"""Signed, idempotent webhook ingestion with a database-backed scan outbox."""
import hashlib
import hmac
import json
import re
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from .models import get_db, Installation, Repository, Scan, User, WebhookDelivery, now
from .jobs import ACTIVE, create_scan, audit
from .config import settings

router = APIRouter()


def revoke_repository(db, repo):
    repo.connection_status, repo.auto_scan, repo.checks_enabled = "revoked", False, False
    repo.next_scan_at = None
    db.add(repo)
    for scan in db.exec(select(Scan).where(Scan.repository_id == repo.id)).all():
        scan.files, scan.encrypted_source = {}, ""
        if scan.status in ACTIVE: scan.status, scan.completed_at = "cancelled", now()
        db.add(scan)
    audit(db, repo.owner_id, "repository.access_revoked", repo.id)


@router.post("/webhooks/github", status_code=202)
async def webhook(request: Request, db: Session = Depends(get_db)):
    cfg = settings()
    if not cfg.github_webhook_secret: raise HTTPException(404, "Not found")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 1_000_000: raise HTTPException(413, "Webhook body too large")
    signature = "sha256=" + hmac.new(cfg.github_webhook_secret.encode(), data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, request.headers.get("x-hub-signature-256", "")): raise HTTPException(403, "Invalid webhook signature")
    delivery = request.headers.get("x-github-delivery", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{8,100}", delivery): raise HTTPException(422, "Invalid delivery identifier")
    try:
        payload = json.loads(data)
        if not isinstance(payload, dict): raise ValueError()
    except (ValueError, UnicodeDecodeError): raise HTTPException(422, "Invalid webhook payload") from None
    event = request.headers.get("x-github-event", "")
    if event not in {"ping", "push", "pull_request", "installation", "installation_repositories"}: return {"status": "ignored"}
    if db.get(WebhookDelivery, delivery): return {"status": "duplicate"}
    db.add(WebhookDelivery(id=delivery))
    try: db.flush()
    except IntegrityError:
        db.rollback()
        return {"status": "duplicate"}
    installation_id = (payload.get("installation") or {}).get("id")
    action = payload.get("action", "")
    if event == "installation":
        for install in db.exec(select(Installation).where(Installation.github_id == installation_id)).all():
            if action in {"deleted", "suspend"}: install.status = "revoked" if action == "deleted" else "suspended"
            elif action in {"created", "unsuspend", "new_permissions_accepted"}: install.status = "active"
            install.permissions = (payload.get("installation") or {}).get("permissions", install.permissions)
            install.synced_at = now()
            db.add(install)
            audit(db, install.owner_id, "installation." + str(action)[:60], install.id)
        for repo in db.exec(select(Repository).where(Repository.installation_id == installation_id)).all():
            if action in {"deleted", "suspend"}: revoke_repository(db, repo)
            elif (payload.get("installation") or {}).get("permissions", {}).get("contents") not in {"read", "write"}: revoke_repository(db, repo)
        db.commit()
        return {"status": "processed"}
    if event == "installation_repositories":
        removed = {r.get("id") for r in payload.get("repositories_removed", []) if isinstance(r, dict)}
        for repo in db.exec(select(Repository).where(Repository.installation_id == installation_id)).all():
            if repo.github_id in removed: revoke_repository(db, repo)
        db.commit()
        return {"status": "processed", "sync_required": True}
    repository_id = (payload.get("repository") or {}).get("id")
    if not isinstance(repository_id, int) or not isinstance(installation_id, int):
        db.commit()
        return {"status": "ignored"}
    commit, branch, base = "", "", ""
    if event == "push" and not payload.get("deleted") and str(payload.get("ref", "")).startswith("refs/heads/"):
        commit, branch = payload.get("after", ""), payload["ref"][11:]
    elif event == "pull_request" and action in {"opened", "reopened", "synchronize", "ready_for_review"}:
        pr = payload.get("pull_request") or {}
        head, base_data = pr.get("head") or {}, pr.get("base") or {}
        # Fork content is not authorized by an installation on the base repository.
        if (head.get("repo") or {}).get("id") != repository_id:
            db.commit()
            return {"status": "skipped_fork"}
        commit, branch, base = head.get("sha", ""), head.get("ref", ""), base_data.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", str(commit)) or not isinstance(branch, str) or not branch or len(branch) > 200 or (base and not re.fullmatch(r"[0-9a-f]{40}", str(base))):
        db.commit()
        return {"status": "ignored"}
    jobs = []
    for repo in db.exec(select(Repository).where(Repository.github_id == repository_id, Repository.installation_id == installation_id, Repository.connection_status == "connected", Repository.auto_scan == True)).all():
        user = db.get(User, repo.owner_id)
        if not user or not user.encrypted_token: continue
        key = hashlib.sha256(f"{repo.id}:{commit}:{event}:{base}".encode()).hexdigest()
        try:
            scan, created = create_scan(db, repo, user, commit=commit, branch=branch, trigger=event, key=key, base_commit=base, publish_check=event == "pull_request" and repo.checks_enabled and cfg.github_checks_enabled)
            if created: jobs.append(scan)
        except HTTPException as exc:
            if exc.status_code != 429: raise
            # Do not acknowledge a delivery whose scan could not be admitted; GitHub/operator can redeliver.
            db.rollback()
            raise HTTPException(503, "Scan capacity reached; retry this delivery") from None
    db.commit()
    from .tasks import enqueue
    for scan in jobs: enqueue(scan, db)
    return {"status": "queued" if jobs else "ignored", "scan_ids": [s.id for s in jobs]}
