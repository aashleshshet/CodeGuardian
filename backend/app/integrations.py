import hashlib
import json
from collections import Counter
from datetime import timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func
from sqlmodel import Session, select
from .auth import current_user, cipher
from .models import (get_db, User, Repository, Installation, RepositoryBranch, Scan, FindingRecord,
                     LoginSession, UserPreference, Notification, AuditEvent, now)
from .access import owned_repo, owned_scan, scan_view
from .jobs import create_scan, delete_repository, audit, ACTIVE
from .config import settings
from .redaction import redact_tree
from .intake import extract_sources
from . import github

router = APIRouter()


def sync_connection(user, db):
    installs = github.installations(user, db)
    available = github.authorized_repositories(user, db)
    ids = {i["id"] for i in installs}
    existing = {i.github_id: i for i in db.exec(select(Installation).where(Installation.owner_id == user.id)).all()}
    for item in installs:
        row = existing.get(item["id"]) or Installation(owner_id=user.id, github_id=item["id"], account=item["account"])
        row.account, row.account_type, row.permissions, row.status, row.synced_at = item["account"], item["account_type"], item["permissions"], item["status"], now()
        db.add(row)
    for key, row in existing.items():
        if key not in ids:
            row.status = "revoked"
            db.add(row)
    allowed = {(r["installation_id"], r["id"]): r for r in available}
    for repo in db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.github_id != None)).all():
        item = allowed.get((repo.installation_id, repo.github_id))
        repo.connection_status = "connected" if item else "revoked"
        repo.synced_at = now()
        if item:
            repo.full_name, repo.branch, repo.language = item["full_name"], item["branch"], item["language"]
            repo.visibility, repo.github_updated_at = "private" if item["private"] else "public", item["updated_at"]
        else:
            repo.auto_scan = False
            for scan in db.exec(select(Scan).where(Scan.repository_id == repo.id)).all():
                scan.files, scan.encrypted_source = {}, ""
                if scan.status in ACTIVE: scan.status, scan.completed_at = "cancelled", now()
                db.add(scan)
        db.add(repo)
    audit(db, user.id, "github.synced", user.id)
    db.commit()
    return {"repositories": available, "installations": installs}


@router.get("/github/installations")
def installations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.exec(select(Installation).where(Installation.owner_id == user.id)).all()
    return {"installations": [r.model_dump(exclude={"owner_id"}) for r in rows]}


@router.post("/github/sync")
def sync(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return sync_connection(user, db)


@router.get("/github/repositories")
def available_repositories(user: User = Depends(current_user), db: Session = Depends(get_db)):
    repos = github.authorized_repositories(user, db)
    db.commit()
    return {"repositories": repos}


@router.get("/repositories")
def repositories(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.exec(select(Repository).where(Repository.owner_id == user.id).order_by(Repository.created_at.desc()).offset(offset).limit(limit)).all()
    return [{**r.model_dump(exclude={"owner_id"}), "scans": [scan_view(s, db, False) for s in db.exec(select(Scan).where(Scan.repository_id == r.id).order_by(Scan.created_at.desc()).limit(20)).all()]} for r in rows]


class ImportRepository(BaseModel):
    full_name: str = Field(max_length=160)
    installation_id: int = Field(gt=0)


@router.post("/repositories/github", status_code=201)
def import_github(body: ImportRepository, user: User = Depends(current_user), db: Session = Depends(get_db)):
    available = github.verify_repository(user, body.full_name, body.installation_id, db)
    if not available: raise HTTPException(403, "Authorize this repository in the GitHub App first")
    repo = db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.github_id == available["id"])).first()
    if not repo:
        repo = Repository(owner_id=user.id, full_name=available["full_name"], github_id=available["id"])
    repo.installation_id, repo.branch = body.installation_id, available["branch"]
    repo.visibility, repo.language = "private" if available["private"] else "public", available.get("language", "")
    repo.github_updated_at, repo.synced_at, repo.connection_status = available.get("updated_at", ""), now(), "connected"
    db.add(repo)
    db.flush()
    audit(db, user.id, "repository.connected", repo.id)
    db.commit()
    return {"repository_id": repo.id}


@router.get("/repositories/{repo_id}/branches")
def branches(repo_id: str, page: int = Query(1, ge=1, le=100), user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo = owned_repo(repo_id, user, db)
    rows = github.branches(user, repo, db, page)
    for row in rows:
        entry = db.exec(select(RepositoryBranch).where(RepositoryBranch.repository_id == repo.id, RepositoryBranch.name == row["name"])).first() or RepositoryBranch(repository_id=repo.id, **row)
        entry.commit_sha, entry.synced_at = row["commit_sha"], now()
        db.add(entry)
    db.commit()
    return {"branches": rows, "page": page, "has_more": len(rows) == 100}


@router.get("/repositories/{repo_id}/commits")
def commits(repo_id: str, branch: str = Query(max_length=200), page: int = Query(1, ge=1, le=100), user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo = owned_repo(repo_id, user, db)
    rows = github.commits(user, repo, branch, db, page)
    db.commit()
    return redact_tree({"commits": rows, "page": page, "has_more": len(rows) == 30})


@router.get("/repositories/{repo_id}/scans")
def history(repo_id: str, limit: int = Query(30, ge=1, le=100), offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    owned_repo(repo_id, user, db)
    return {"scans": [scan_view(s, db, False) for s in db.exec(select(Scan).where(Scan.repository_id == repo_id).order_by(Scan.created_at.desc()).offset(offset).limit(limit)).all()]}


class ScanRequest(BaseModel):
    ref: str | None = Field(default=None, max_length=200)
    branch: str | None = Field(default=None, max_length=200)


@router.post("/repositories/{repo_id}/scans", status_code=202)
def rescan(repo_id: str, body: ScanRequest = ScanRequest(), user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .tasks import enqueue
    repo = owned_repo(repo_id, user, db)
    if not repo.github_id: raise HTTPException(409, "Upload a new archive to analyze this repository again")
    branch = body.branch or repo.branch
    commit = github.resolve_commit(user, repo, body.ref or branch, db)
    scan, created = create_scan(db, repo, user, commit=commit, branch=branch)
    db.commit()
    if created: enqueue(scan, db)
    return {"scan_id": scan.id}


@router.post("/repositories/upload", status_code=201)
async def upload(file: UploadFile = File(...), authorized: bool = Form(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .tasks import enqueue
    if not authorized: raise HTTPException(422, "Confirm authorization to review this source")
    data = await file.read(settings().max_archive_bytes + 1)
    await file.close()
    try: files, intake = extract_sources(data)
    except ValueError as exc: raise HTTPException(422, str(exc)) from None
    import secrets
    repo = Repository(owner_id=user.id, full_name="uploaded/" + secrets.token_hex(4), branch="snapshot", connection_status="uploaded")
    db.add(repo)
    db.flush()
    scan, _ = create_scan(db, repo, user, commit=hashlib.sha256(data).hexdigest(), branch="snapshot")
    scan.encrypted_source, scan.coverage = cipher().encrypt(json.dumps(files).encode()).decode(), intake
    db.add(scan)
    db.commit()
    enqueue(scan, db)
    return {"repository_id": repo.id, "scan_id": scan.id}


@router.post("/scans/{scan_id}/cancel")
def cancel(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .tasks import stop_container
    scan, _ = owned_scan(scan_id, user, db)
    if scan.status not in ACTIVE: raise HTTPException(409, "Only active jobs can be cancelled")
    scan.status, scan.completed_at, scan.encrypted_source = "cancelled", now(), ""
    db.add(scan)
    audit(db, user.id, "scan.cancelled", scan.id)
    db.commit()
    stop_container(scan.id)
    return {"status": "cancelled"}


@router.post("/scans/{scan_id}/retry", status_code=202)
def retry(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .tasks import enqueue
    scan, repo = owned_scan(scan_id, user, db)
    if scan.status not in {"failed", "partial"}: raise HTTPException(409, "Only failed or partial jobs can be retried")
    if scan.attempts >= settings().max_scan_attempts: raise HTTPException(409, "Retry limit reached; start a new scan after fixing runner health")
    if not repo.github_id: raise HTTPException(409, "Upload the source again to retry; temporary upload data was removed")
    github.resolve_commit(user, repo, scan.commit_sha or scan.branch, db)
    db.exec(select(User).where(User.id == user.id).with_for_update()).first()
    active = db.exec(select(Scan).join(Repository).where(Repository.owner_id == user.id, Scan.status.in_(ACTIVE))).all()
    if len(active) >= 3: raise HTTPException(429, "Three jobs are already active")
    scan.status, scan.error, scan.completed_at, scan.queued_at = "queued", None, None, None
    db.add(scan)
    audit(db, user.id, "scan.retried", scan.id)
    db.commit()
    enqueue(scan, db)
    return {"scan_id": scan.id}


class RepositorySettings(BaseModel):
    auto_scan: bool | None = None
    schedule_hours: int | None = None
    checks_enabled: bool | None = None
    blocking_checks: bool | None = None


@router.patch("/repositories/{repo_id}")
def update_repository(repo_id: str, body: RepositorySettings, user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo = owned_repo(repo_id, user, db)
    if body.schedule_hours is not None and body.schedule_hours not in {0, 6, 12, 24, 168}: raise HTTPException(422, "Schedule must be disabled, 6, 12, 24 or 168 hours")
    if (body.auto_scan or body.schedule_hours or body.checks_enabled) and (not repo.github_id or repo.connection_status != "connected"):
        raise HTTPException(409, "Reconnect GitHub before enabling automation")
    if body.checks_enabled:
        if not settings().github_checks_enabled: raise HTTPException(409, "Check publishing is not enabled on this service")
        install = db.exec(select(Installation).where(Installation.owner_id == user.id, Installation.github_id == repo.installation_id)).first()
        if not install or install.permissions.get("checks") != "write": raise HTTPException(403, "Synchronize an installation with Checks: write before enabling this feature")
    for key, value in body.model_dump(exclude_none=True).items(): setattr(repo, key, value)
    if repo.blocking_checks and not repo.checks_enabled: raise HTTPException(422, "Enable checks before selecting a blocking policy")
    if body.schedule_hours is not None: repo.next_scan_at = now()+timedelta(hours=body.schedule_hours) if body.schedule_hours else None
    db.add(repo)
    audit(db, user.id, "repository.settings", repo.id)
    db.commit()
    db.refresh(repo)
    return repo.model_dump(exclude={"owner_id"})


@router.delete("/repositories/{repo_id}")
def disconnect_repository(repo_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .tasks import stop_container
    repo = owned_repo(repo_id, user, db)
    active_ids = [s.id for s in db.exec(select(Scan).where(Scan.repository_id == repo.id, Scan.status.in_(ACTIVE))).all()]
    delete_repository(db, repo)
    audit(db, user.id, "repository.deleted", repo_id)
    db.commit()
    for scan_id in active_ids: stop_container(scan_id)
    return {"deleted": True}


@router.delete("/github/connection")
def disconnect_github(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.encrypted_token: github.revoke_user(user, db)
    user.encrypted_token, user.encrypted_refresh_token, user.token_expires_at = "", "", None
    db.add(user)
    for repo in db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.github_id != None)).all(): delete_repository(db, repo)
    db.exec(delete(Installation).where(Installation.owner_id == user.id))
    audit(db, user.id, "github.disconnected", user.id)
    db.commit()
    return {"disconnected": True, "installation_management_url": "https://github.com/settings/installations"}


@router.delete("/account")
def delete_account(user: User = Depends(current_user), db: Session = Depends(get_db)):
    revoked = not bool(user.encrypted_token)
    if user.encrypted_token:
        try: github.revoke_user(user, db); revoked = True
        except HTTPException: pass
    for repo in db.exec(select(Repository).where(Repository.owner_id == user.id)).all(): delete_repository(db, repo)
    for model, column in [(Installation, Installation.owner_id), (LoginSession, LoginSession.user_id), (UserPreference, UserPreference.user_id), (AuditEvent, AuditEvent.user_id), (Notification, Notification.user_id)]:
        db.exec(delete(model).where(column == user.id))
    db.delete(user)
    db.commit()
    response = JSONResponse({"deleted": True, "github_grant_revoked": revoked, "installation_management_url": "https://github.com/settings/installations"})
    response.delete_cookie("cg_session", path="/")
    return response


class Preferences(BaseModel):
    notify_scan_failure: bool = True
    notify_high_findings: bool = True


@router.get("/preferences")
def preferences(user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.get(UserPreference, user.id)
    return row.model_dump(exclude={"user_id"}) if row else Preferences().model_dump()


@router.patch("/preferences")
def save_preferences(body: Preferences, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.get(UserPreference, user.id) or UserPreference(user_id=user.id)
    row.sqlmodel_update(body.model_dump())
    db.add(row)
    audit(db, user.id, "preferences.updated", user.id)
    db.commit()
    db.refresh(row)
    return row.model_dump(exclude={"user_id"})


@router.get("/notifications")
def notifications(limit: int = Query(30, ge=1, le=100), user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"notifications": [n.model_dump(exclude={"user_id"}) for n in db.exec(select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(limit)).all()]}


class NotificationUpdate(BaseModel):
    read: bool = True


@router.patch("/notifications/{notification_id}")
def mark_notification(notification_id: str, body: NotificationUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.get(Notification, notification_id)
    if not row or row.user_id != user.id: raise HTTPException(404, "Notification not found")
    row.read = body.read
    db.add(row)
    db.commit()
    return {"read": row.read}


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo_ids = select(Repository.id).where(Repository.owner_id == user.id)
    def number(statement): return db.exec(statement).one()
    total_repos = number(select(func.count()).select_from(Repository).where(Repository.owner_id == user.id))
    base = select(FindingRecord).join(Repository).where(Repository.owner_id == user.id, FindingRecord.branch == Repository.branch)
    rows = db.exec(base).all()
    open_rows = [r for r in rows if r.resolved_at is None and r.status != "dismissed"]
    counts = Counter(r.evidence.get("severity", "info") for r in open_rows)
    completed = number(select(func.count()).select_from(Scan).where(Scan.repository_id.in_(repo_ids), Scan.status == "completed"))
    failed = number(select(func.count()).select_from(Scan).where(Scan.repository_id.in_(repo_ids), Scan.status.in_(["failed", "partial"])))
    finished = completed + failed
    recent = db.exec(select(Scan, Repository.full_name).join(Repository).where(Repository.owner_id == user.id).order_by(Scan.created_at.desc()).limit(15)).all()
    trend = db.exec(select(Scan).where(Scan.repository_id.in_(repo_ids), Scan.status.in_(["completed", "partial"])).order_by(Scan.created_at.desc()).limit(20)).all()
    return {"repositories": total_repos, "scanned_repositories": number(select(func.count(func.distinct(Scan.repository_id))).where(Scan.repository_id.in_(repo_ids), Scan.status.in_(["completed", "partial"]))),
            "open_findings": len(open_rows), "by_severity": {s: counts[s] for s in ["critical", "high", "medium", "low", "info"]},
            "vulnerable_dependencies": sum(r.evidence.get("category") == "dependency" for r in open_rows), "potential_secrets": sum(r.evidence.get("category") == "secret" for r in open_rows),
            "resolved_findings": sum(r.resolved_at is not None for r in rows), "scan_success_rate": round(100*completed/finished, 1) if finished else None,
            "scan_failure_rate": round(100*failed/finished, 1) if finished else None,
            "recent_scans": [{**scan_view(s, db, False), "repository_name": name} for s, name in recent],
            "trend": [{"date": s.created_at.isoformat(), "findings": len(s.findings)} for s in reversed(trend)],
            "notifications_unread": number(select(func.count()).select_from(Notification).where(Notification.user_id == user.id, Notification.read == False))}
