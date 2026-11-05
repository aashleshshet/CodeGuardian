import json
from celery import Celery
from sqlmodel import Session
from .config import settings, ROOT
from .models import engine, Scan, Repository, User, now
from .auth import cipher
from .intake import extract_sources
from .isolation import analyze
from . import github

celery = Celery("codeguardian", broker=settings().redis_url)
celery.conf.update(task_always_eager=settings().tasks_eager, task_serializer="json", accept_content=["json"], result_serializer="json", task_ignore_result=True, task_time_limit=240, task_soft_time_limit=225, worker_max_tasks_per_child=10, worker_max_memory_per_child=512_000, worker_prefetch_multiplier=1, broker_connection_retry_on_startup=True, task_send_sent_event=False, worker_send_task_events=False)


@celery.task(name="codeguardian.scan", acks_late=False)
def run_scan(scan_id: str, encrypted_source: str | None = None, fixture_version: str = "current", publish_check: bool = False):
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan or scan.status != "queued": return
        repo = db.get(Repository, scan.repository_id)
        if not repo: return
        scan.status = "running"
        db.add(scan)
        db.commit()
        try:
            if repo.is_fixture:
                if fixture_version not in {"baseline", "current"}: raise ValueError("Invalid fixture")
                root = ROOT / "fixtures" / fixture_version
                files = {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*") if p.is_file()}
                import hashlib
                scan.commit_sha = hashlib.sha1(json.dumps(files, sort_keys=True).encode()).hexdigest()
                intake = {"skipped_files": 0}
            elif encrypted_source:
                files = json.loads(cipher().decrypt(encrypted_source.encode()))
                intake = {"skipped_files": 0}
            else:
                user = db.get(User, repo.owner_id)
                data, scan.commit_sha = github.snapshot(user, repo, scan.commit_sha or None)
                files, intake = extract_sources(data, strip_root=True)
            result = analyze(files, fixture=repo.is_fixture)
            scan.findings, scan.files = result["findings"], result["files"]
            scan.coverage = {**result["coverage"], **intake}
            scan.status = "completed" if scan.coverage["complete"] else "partial"
            scan.completed_at = now()
            db.add(scan)
            db.commit()
            if publish_check and settings().github_checks_enabled:
                try: github.publish_check(repo, scan)
                except Exception:
                    scan.coverage = {**scan.coverage, "check_error": "GitHub check could not be published"}
                    db.add(scan)
                    db.commit()
        except Exception as exc:
            # Never log exception text: parsers, GitHub URLs, and repositories may contain credentials.
            scan.status = "failed"
            scan.error = "Scan failed safely. Check scanner availability, repository authorization, and configured resource limits."
            scan.completed_at = now()
            scan.coverage = {"complete": False, "error_type": type(exc).__name__}
            db.add(scan)
            db.commit()


def enqueue(scan: Scan, db: Session, **kwargs):
    try:
        run_scan.apply_async(args=[scan.id], kwargs=kwargs, argsrepr="[scan_id]", kwargsrepr="{redacted}")
    except Exception:
        scan.status = "failed"
        scan.error = "The scan queue is unavailable. Start Redis and the worker, then retry."
        db.add(scan)
        db.commit()
