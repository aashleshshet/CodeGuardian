"""Durable job state lives in PostgreSQL; the broker carries only opaque job IDs."""
import json
import logging
import subprocess
import threading
from contextlib import contextmanager
from datetime import timedelta, timezone
from celery import Celery
from sqlalchemy import update, delete
from sqlmodel import Session, select
from .config import settings
from .models import (engine, Scan, Repository, User, Notification, UserPreference, WorkerHealth,
                     LoginSession, OAuthState, WebhookDelivery, VulnerabilityReference, now)
from .auth import cipher
from .intake import extract_sources
from .isolation import analyze
from .jobs import persist_results, create_scan, delete_scan, ACTIVE
from .scanner import compare
from . import github

log = logging.getLogger("codeguardian.worker")
celery = Celery("codeguardian", broker=settings().redis_url)
celery.conf.update(task_always_eager=settings().tasks_eager, task_serializer="json", accept_content=["json"], result_serializer="json", task_ignore_result=True,
    task_time_limit=settings().scan_timeout * 2 + 180, task_soft_time_limit=settings().scan_timeout * 2 + 150,
    worker_max_tasks_per_child=10, worker_max_memory_per_child=512_000, worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True, task_send_sent_event=False, worker_send_task_events=False,
    task_publish_retry=False, broker_connection_timeout=3,
    beat_schedule={"maintenance": {"task": "codeguardian.maintenance", "schedule": 60.0}, "heartbeat": {"task": "codeguardian.worker_ping", "schedule": 30.0}})


from celery.signals import worker_init


@worker_init.connect
def validate_worker(**kwargs):
    settings().validate_runtime()


def stop_container(scan_id):
    # API does not possess a Docker socket. Cancellation is DB authoritative; worker heartbeat kills its child.
    return None


def kill_scanner(scan_id):
    try:
        from .isolation import cancel_scan
        cancel_scan(scan_id)
    except (ImportError, OSError, RuntimeError):
        pass


@contextmanager
def heartbeat(scan_id):
    stop = threading.Event()
    def tick():
        while not stop.wait(5):
            try:
                with Session(engine) as db:
                    scan = db.get(Scan, scan_id)
                    if not scan or scan.status == "cancelled":
                        kill_scanner(scan_id)
                        return
                    if scan.status not in ACTIVE: return
                    scan.heartbeat_at = now()
                    health = db.get(WorkerHealth, "celery") or WorkerHealth(id="celery")
                    health.heartbeat_at = now()
                    db.add(health)
                    db.add(scan)
                    db.commit()
            except Exception: pass
    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    try: yield
    finally: stop.set(); thread.join(timeout=6)


def set_stage(db, scan_id, stage):
    db.expire_all()
    scan = db.get(Scan, scan_id)
    if not scan or scan.status not in ACTIVE: return None
    scan.status, scan.heartbeat_at = stage, now()
    db.add(scan)
    db.commit()
    return scan


@celery.task(name="codeguardian.scan", acks_late=True, reject_on_worker_lost=True)
def run_scan(scan_id: str):
    with Session(engine) as db:
        claim = db.exec(update(Scan).where(Scan.id == scan_id, Scan.status == "queued").values(status="preparing", started_at=now(), heartbeat_at=now(), attempts=Scan.attempts + 1))
        db.commit()
        if claim.rowcount != 1: return
        with heartbeat(scan_id):
            try:
                scan = db.get(Scan, scan_id)
                repo = db.get(Repository, scan.repository_id)
                user = db.get(User, repo.owner_id)
                if scan.encrypted_source:
                    files = json.loads(cipher().decrypt(scan.encrypted_source.encode()))
                    intake = scan.coverage
                else:
                    data, scan.commit_sha = github.snapshot(user, repo, scan.commit_sha or scan.branch, db)
                    files, intake = extract_sources(data, strip_root=True)
                db.add(scan)
                db.commit()
                scan = set_stage(db, scan_id, "scanning")
                if not scan: return
                result = analyze(files, scan_id=scan_id)
                # Base comparison uses the same isolated runner and explicit authorized commit.
                if scan.base_commit:
                    db.refresh(scan)
                    if scan.status not in ACTIVE: return
                    base_data, base_sha = github.snapshot(user, repo, scan.base_commit, db)
                    base_files, _ = extract_sources(base_data, strip_root=True)
                    base_result = analyze(base_files, scan_id=scan_id)
                    result["coverage"]["pr_comparison"] = {**compare(result["findings"], base_result["findings"]), "baseline_commit": base_sha, "reliable": bool(result["coverage"]["complete"] and base_result["coverage"]["complete"])}
                    with github.repository_client(user, repo, db) as gh:
                        changes = github.request(gh, "GET", f"/repos/{repo.full_name}/compare/{base_sha}...{scan.commit_sha}")
                    scan.changed_files = [r["filename"] for r in changes.get("files", [])][:300]
                    db.add(scan)
                    db.commit()
                scan = set_stage(db, scan_id, "analyzing")
                if not scan: return
                try:
                    from .intelligence import enrich_findings
                    result["findings"] = enrich_findings(result["findings"], db)
                except ImportError: pass
                scan.coverage = {**scan.coverage, **intake}
                # Atomic final state: late cancellation wins, and stale workers cannot resurrect deleted data.
                db.expire_all()
                scan = db.exec(select(Scan).where(Scan.id == scan_id).with_for_update()).first()
                if not scan or scan.status not in ACTIVE: return
                persist_results(db, scan, result)
                db.commit()
                if scan.publish_check and settings().github_checks_enabled and repo.checks_enabled:
                    try: github.publish_check(repo, scan)
                    except Exception:
                        scan.coverage = {**scan.coverage, "check_error": "GitHub check could not be published"}
                        db.add(scan); db.commit()
            except Exception as exc:
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan and scan.status in ACTIVE:
                    scan.status, scan.completed_at, scan.encrypted_source = "failed", now(), ""
                    scan.error = "Scan failed safely. Check worker health, repository authorization, scanner caches and resource limits."
                    scan.coverage = {**scan.coverage, "complete": False, "error_type": type(exc).__name__}
                    db.add(scan)
                    repo = db.get(Repository, scan.repository_id)
                    if repo:
                        prefs = db.get(UserPreference, repo.owner_id)
                        if not prefs or prefs.notify_scan_failure: db.add(Notification(user_id=repo.owner_id, scan_id=scan.id, message="A security scan failed. Inspect runner health and retry."))
                    db.commit()
                log.warning('{"event":"scan.failed","scan_id":"%s","error_type":"%s"}', scan_id, type(exc).__name__)
            finally:
                kill_scanner(scan_id)


def enqueue(scan: Scan, db: Session):
    try:
        run_scan.apply_async(args=[scan.id], argsrepr="[scan_id]")
        db.refresh(scan)
        scan.queued_at = now()
        db.add(scan)
        db.commit()
        return True
    except Exception:
        db.rollback()
        # The committed queued row is an outbox entry. Beat retries broker delivery.
        return False


@celery.task(name="codeguardian.worker_ping")
def worker_ping():
    with Session(engine) as db:
        record = db.get(WorkerHealth, "celery") or WorkerHealth(id="celery")
        record.heartbeat_at = now()
        db.add(record)
        db.commit()


@celery.task(name="codeguardian.maintenance")
def maintenance():
    worker_ping()
    with Session(engine) as db:
        stamp = now()
        for model, column, cutoff in [(LoginSession, LoginSession.expires_at, stamp), (OAuthState, OAuthState.expires_at, stamp), (WebhookDelivery, WebhookDelivery.received_at, stamp-timedelta(days=30)), (VulnerabilityReference, VulnerabilityReference.expires_at, stamp-timedelta(days=7))]:
            db.exec(delete(model).where(column < cutoff))
        for scan in db.exec(select(Scan).where(Scan.source_expires_at < stamp)).all():
            scan.files, scan.encrypted_source, scan.source_expires_at = {}, "", None
            db.add(scan)
        for scan in db.exec(select(Scan).where(Scan.status.in_(ACTIVE - {"queued"}), Scan.heartbeat_at < stamp-timedelta(seconds=settings().worker_stale_seconds))).all():
            scan.status, scan.error, scan.completed_at, scan.encrypted_source = "failed", "Worker heartbeat expired. Retry after restoring worker health.", stamp, ""
            db.add(scan)
            kill_scanner(scan.id)
        # Preserve the latest retained finding state; historical scans can be safely removed.
        from .models import FindingRecord
        latest_ids = select(FindingRecord.latest_scan_id)
        for scan in db.exec(select(Scan).where(Scan.created_at < stamp-timedelta(days=settings().result_retention_days), Scan.status.not_in(ACTIVE), Scan.id.not_in(latest_ids))).all(): delete_scan(db, scan)
        db.commit()
        for repo in db.exec(select(Repository).where(Repository.schedule_hours > 0, Repository.connection_status == "connected", Repository.next_scan_at <= stamp).with_for_update(skip_locked=True)).all():
            user = db.get(User, repo.owner_id)
            try:
                create_scan(db, repo, user, trigger="schedule", key=f"schedule:{repo.id}:{repo.next_scan_at.isoformat()}")
                repo.next_scan_at = stamp + timedelta(hours=repo.schedule_hours)
                db.add(repo)
                db.commit()
            except Exception: db.rollback()
        pending = db.exec(select(Scan).where(Scan.status == "queued").order_by(Scan.created_at).limit(100)).all()
        for scan in pending:
            if not scan.queued_at or scan.queued_at.replace(tzinfo=timezone.utc) < stamp-timedelta(seconds=120): enqueue(scan, db)
