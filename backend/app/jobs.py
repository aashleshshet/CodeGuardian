"""Transaction-scoped job and finding persistence. Callers own commits."""
import hashlib
from datetime import timedelta
from fastapi import HTTPException
from sqlmodel import select
from sqlalchemy import delete
from .models import (User, Repository, Scan, Review, FindingRecord, AIAnalysis, RepositoryBranch,
                     Notification, UserPreference, AuditEvent, now)
from .config import settings

ACTIVE = {"queued", "preparing", "scanning", "analyzing"}
TERMINAL = {"completed", "partial", "failed", "cancelled"}


def audit(db, user_id, action, resource):
    db.add(AuditEvent(user_id=user_id, action=action, resource_id=resource))


def create_scan(db, repo, user, *, commit="", branch=None, trigger="manual", key=None, base_commit="", publish_check=False):
    # Serialize account job admission in PostgreSQL; atomic claim in the worker prevents redelivery execution.
    db.exec(select(User).where(User.id == user.id).with_for_update()).first()
    branch = branch or repo.branch
    if key:
        existing = db.exec(select(Scan).where(Scan.job_key == key)).first()
        if existing: return existing, False
    active = db.exec(select(Scan).join(Repository).where(Repository.owner_id == user.id, Scan.status.in_(ACTIVE))).all()
    if len(active) >= 3: raise HTTPException(429, "Three scans are active; wait for one to finish")
    for prior in active:
        if prior.repository_id == repo.id and prior.commit_sha == commit and prior.branch == branch:
            return prior, False
    previous = db.exec(select(Scan).where(Scan.repository_id == repo.id, Scan.branch == branch, Scan.status == "completed").order_by(Scan.created_at.desc())).first()
    scan = Scan(repository_id=repo.id, branch=branch, commit_sha=commit, trigger=trigger,
                baseline_id=previous.id if previous else None, job_key=key, base_commit=base_commit,
                publish_check=publish_check)
    db.add(scan)
    db.flush()
    audit(db, user.id, "scan.requested", scan.id)
    return scan, True


def persist_results(db, scan, result):
    db.exec(select(Repository).where(Repository.id == scan.repository_id).with_for_update()).first()
    stamp = now()
    scan.findings, scan.files = result["findings"], result.get("files", {})
    scan.coverage = {**scan.coverage, **result["coverage"]}
    scan.status = "completed" if scan.coverage.get("complete") else "partial"
    scan.completed_at = stamp
    scan.source_expires_at = stamp + timedelta(hours=settings().source_retention_hours)
    scan.encrypted_source = ""
    records = {r.fingerprint: r for r in db.exec(select(FindingRecord).where(FindingRecord.repository_id == scan.repository_id, FindingRecord.branch == scan.branch)).all()}
    current = set()
    for f in scan.findings:
        fingerprint = f["fingerprint"]
        current.add(fingerprint)
        record = records.get(fingerprint) or FindingRecord(repository_id=scan.repository_id, branch=scan.branch, fingerprint=fingerprint, latest_scan_id=scan.id)
        if record.resolved_at: record.status = "open"
        record.last_seen, record.resolved_at, record.latest_scan_id = stamp, None, scan.id
        record.evidence = f
        db.add(record)
    # A partial scan is never evidence that an old finding is resolved.
    if scan.coverage.get("complete"):
        for fingerprint, record in records.items():
            if fingerprint not in current and record.resolved_at is None:
                record.resolved_at = stamp
                db.add(record)
    repo = db.get(Repository, scan.repository_id)
    prefs = db.get(UserPreference, repo.owner_id)
    if any(f["severity"] in {"critical", "high"} for f in scan.findings) and (not prefs or prefs.notify_high_findings):
        db.add(Notification(user_id=repo.owner_id, scan_id=scan.id, message="A security scan reported high-priority findings requiring review."))
    db.add(scan)
    db.flush()


def delete_scan(db, scan):
    db.exec(delete(Notification).where(Notification.scan_id == scan.id))
    db.exec(delete(Review).where(Review.scan_id == scan.id))
    db.exec(delete(AIAnalysis).where(AIAnalysis.scan_id == scan.id))
    db.exec(delete(FindingRecord).where(FindingRecord.latest_scan_id == scan.id))
    for child in db.exec(select(Scan).where(Scan.baseline_id == scan.id)).all():
        child.baseline_id = None
        db.add(child)
    db.flush()
    db.delete(scan)
    db.flush()


def delete_repository(db, repo):
    db.exec(delete(FindingRecord).where(FindingRecord.repository_id == repo.id))
    db.exec(delete(RepositoryBranch).where(RepositoryBranch.repository_id == repo.id))
    scans = db.exec(select(Scan).where(Scan.repository_id == repo.id)).all()
    for scan in scans:
        scan.baseline_id = None
        db.add(scan)
    db.flush()
    for scan in scans: delete_scan(db, scan)
    db.delete(repo)
    db.flush()
