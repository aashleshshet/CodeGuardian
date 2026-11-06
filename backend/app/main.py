import base64
import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta, timezone
from urllib.parse import urlencode
from uuid import uuid4
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, SQLModel, select
from .config import settings
from .models import engine, get_db, User, OAuthState, AIAnalysis, Review, FindingRecord, now
from .auth import current_user, make_session, digest
from .access import retained_source, owned_scan, finding_for, scan_view
from .jobs import audit
from .scanner import compare
from .redaction import redact, redact_tree
from .ai import explain, propose_patch
from . import github
from .middleware import BodyLimitMiddleware
from .limits import check_limit
from .readiness import readiness_checks

logger = logging.getLogger("codeguardian")


@asynccontextmanager
async def lifespan(app):
    settings().validate_runtime()
    if settings().environment != "production": SQLModel.metadata.create_all(engine)
    yield


app = FastAPI(title="CodeGuardian AI", version="0.2.0", lifespan=lifespan,
              docs_url="/docs" if settings().environment != "production" else None,
              redoc_url=None, openapi_url="/openapi.json" if settings().environment != "production" else None)
app.add_middleware(BodyLimitMiddleware)


@app.middleware("http")
async def harden(request: Request, call_next):
    request_id = uuid4().hex
    try: response = await call_next(request)
    except Exception as exc:
        # Do not log URLs, body, exception messages, stack locals, source, or credentials.
        logger.error('{"event":"request.failed","request_id":"%s","error_type":"%s"}', request_id, type(exc).__name__)
        response = JSONResponse({"detail": "An internal error occurred. Retry or contact the operator.", "request_id": request_id}, status_code=500)
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "X-Request-ID": request_id})
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return JSONResponse({"detail": "Invalid request parameters", "fields": [".".join(str(x) for x in e["loc"]) for e in exc.errors()]}, status_code=422)


@app.get("/health")
def health(): return {"status": "ok", "service": "codeguardian-api"}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    checks = readiness_checks(db)
    return JSONResponse({"status": "ready" if all(checks.values()) else "unavailable", "checks": checks}, status_code=200 if all(checks.values()) else 503)


@app.get("/capabilities")
def capabilities():
    cfg = settings()
    configured = all((cfg.github_client_id, cfg.github_client_secret, cfg.github_app_id, cfg.github_private_key, cfg.token_encryption_key, cfg.github_app_slug))
    return {"github": bool(configured), "llm": bool(cfg.llm_enabled and cfg.llm_model), "checks": cfg.github_checks_enabled,
            "repository_writes": False, "scanner_mode": cfg.scanner_mode,
            "install_url": f"https://github.com/apps/{cfg.github_app_slug}/installations/new" if configured else None}


@app.get("/auth/github/start")
def github_start(request: Request, db: Session = Depends(get_db)):
    cfg = settings()
    if not capabilities()["github"]: raise HTTPException(503, "GitHub App credentials are not configured")
    check_limit(request.client.host if request.client else "unknown", "oauth", 30)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    db.add(OAuthState(id=digest(state), verifier=verifier, expires_at=now() + timedelta(minutes=10)))
    db.commit()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    url = "https://github.com/login/oauth/authorize?" + urlencode({"client_id": cfg.github_client_id, "redirect_uri": cfg.public_url + "/api/backend/auth/github/callback", "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "scope": "offline_access"})
    response = RedirectResponse(url)
    response.set_cookie("cg_oauth", state, max_age=600, httponly=True, secure=cfg.public_url.startswith("https://"), samesite="lax", path="/")
    return response


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str, state: str, db: Session = Depends(get_db)):
    cookie = request.cookies.get("cg_oauth", "")
    stored = db.exec(select(OAuthState).where(OAuthState.id == digest(state)).with_for_update()).first()
    if not cookie or not secrets.compare_digest(cookie, state) or not stored or stored.expires_at.replace(tzinfo=timezone.utc) < now():
        raise HTTPException(403, "OAuth state expired or invalid; start sign-in again")
    verifier = stored.verifier
    db.delete(stored)
    db.commit()
    cfg = settings()
    with httpx.Client(timeout=20, follow_redirects=False) as gh:
        response = gh.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": cfg.github_client_id, "client_secret": cfg.github_client_secret, "code": code, "code_verifier": verifier, "redirect_uri": cfg.public_url + "/api/backend/auth/github/callback"})
        payload = github.checked(response)
    token = payload.get("access_token")
    if not token: raise HTTPException(403, "GitHub did not grant access")
    with github.client(token) as gh: identity = github.request(gh, "GET", "/user")
    user = db.exec(select(User).where(User.github_id == identity["id"])).first() or User(github_id=identity["id"], login=identity["login"])
    user.login = identity["login"]
    user.avatar_url = identity.get("avatar_url", "")
    github.store_tokens(user, payload)
    db.add(user)
    db.commit()
    db.refresh(user)
    response = RedirectResponse(cfg.public_url + "/#integrations", status_code=303)
    response.delete_cookie("cg_oauth", path="/")
    # Rotate any prior browser session to prevent accumulating credentials after reconnect.
    old = request.cookies.get("cg_session")
    if old:
        from .models import LoginSession
        existing = db.get(LoginSession, digest(old))
        if existing: db.delete(existing)
    make_session(db, user, response)
    audit(db, user.id, "auth.github", user.id)
    db.commit()
    return response


@app.get("/auth/me")
def me(request: Request, user: User = Depends(current_user)):
    return {"login": user.login, "avatar_url": user.avatar_url, "csrf_token": request.state.login_session.csrf_token}


@app.post("/auth/logout")
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(request.state.login_session)
    audit(db, user.id, "auth.logout", user.id)
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("cg_session", path="/")
    return response


@app.get("/scans/{scan_id}")
def scan_detail(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, repo = owned_scan(scan_id, user, db)
    return {**scan_view(scan, db), "repository": repo.model_dump(exclude={"owner_id"})}


@app.get("/scans/{scan_id}/compare/{baseline_id}")
def compare_scans(scan_id: str, baseline_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, repo = owned_scan(scan_id, user, db)
    baseline, old_repo = owned_scan(baseline_id, user, db)
    if old_repo.id != repo.id: raise HTTPException(422, "Compare scans from the same repository")
    return {**compare(scan.findings, baseline.findings), "reliable": bool(scan.coverage.get("complete") and baseline.coverage.get("complete"))}


class ExplainRequest(BaseModel):
    use_llm: bool = False


@app.post("/scans/{scan_id}/findings/{fingerprint}/explanation")
def explanation(scan_id: str, fingerprint: str, body: ExplainRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.use_llm: check_limit(user.id, "llm", 5)
    scan, _ = owned_scan(scan_id, user, db)
    f = finding_for(scan, fingerprint)
    try: result = explain(f, retained_source(scan).get(f["path"], ""), body.use_llm)
    except (ValueError, httpx.HTTPError): raise HTTPException(502, "AI explanation unavailable. Curated remediation remains available.") from None
    db.add(AIAnalysis(scan_id=scan.id, fingerprint=fingerprint, provider=result["provider"], result=result))
    audit(db, user.id, "finding.explained", fingerprint)
    db.commit()
    return result


def patch_for(scan, fingerprint):
    f = finding_for(scan, fingerprint)
    if f["path"] not in retained_source(scan): raise HTTPException(410, "Source retention expired; rescan this commit before requesting a patch")
    try: return propose_patch(f, scan.files[f["path"]])
    except (ValueError, IndexError) as exc: raise HTTPException(422, str(exc) if isinstance(exc, ValueError) else "Source location unavailable") from None


@app.post("/scans/{scan_id}/findings/{fingerprint}/patch")
def patch(scan_id: str, fingerprint: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    return patch_for(scan, fingerprint)


class ExportPatch(BaseModel):
    digest: str = Field(max_length=128)
    reviewed: bool


@app.post("/scans/{scan_id}/findings/{fingerprint}/patch/export")
def export_patch(scan_id: str, fingerprint: str, body: ExportPatch, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    proposed = patch_for(scan, fingerprint)
    if not body.reviewed or not secrets.compare_digest(body.digest, proposed["digest"]): raise HTTPException(409, "Review the current patch before exporting it")
    audit(db, user.id, "patch.reviewed_export", fingerprint)
    db.commit()
    return Response(proposed["diff"], media_type="text/plain", headers={"Content-Disposition": 'attachment; filename="codeguardian.patch"'})


class ReviewBody(BaseModel):
    status: str
    note: str = Field(default="", max_length=2000)


@app.patch("/scans/{scan_id}/findings/{fingerprint}/review")
def review(scan_id: str, fingerprint: str, body: ReviewBody, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    f = finding_for(scan, fingerprint)
    if body.status not in {"open", "confirmed", "dismissed"}: raise HTTPException(422, "Invalid review status")
    if body.status == "dismissed" and not body.note.strip(): raise HTTPException(422, "A dismissal needs a reason")
    record = db.exec(select(Review).where(Review.scan_id == scan.id, Review.fingerprint == fingerprint, Review.owner_id == user.id)).first() or Review(scan_id=scan.id, fingerprint=fingerprint, owner_id=user.id)
    record.status, record.note, record.updated_at = body.status, redact(body.note), now()
    db.add(record)
    durable = db.exec(select(FindingRecord).where(FindingRecord.repository_id == scan.repository_id, FindingRecord.branch == scan.branch, FindingRecord.fingerprint == fingerprint)).first() or FindingRecord(repository_id=scan.repository_id, branch=scan.branch, fingerprint=fingerprint, latest_scan_id=scan.id, evidence=f)
    durable.status, durable.note = body.status, redact(body.note)
    db.add(durable)
    audit(db, user.id, "finding." + body.status, fingerprint)
    db.commit()
    return {"status": record.status, "note": record.note}


@app.get("/scans/{scan_id}/report")
def report(scan_id: str, format: str = "json", user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = scan_detail(scan_id, user, db)
    if format not in {"json", "sarif", "md"}: raise HTTPException(422, "Supported report formats: json, sarif, md")
    if format == "sarif":
        return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "CodeGuardian AI", "version": "0.2.0"}}, "properties": {"coverage": data["coverage"], "status": data["status"]}, "results": [{"ruleId": f["rule_id"], "level": "error" if f["severity"] in {"critical", "high"} else "warning", "message": {"text": f["message"]}, "partialFingerprints": {"codeguardian/v2": f["fingerprint"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": {"startLine": f["line"]}}}]} for f in data["findings"]]}]}
    data.pop("files", None)
    if format == "md":
        safe = lambda v: str(v).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;")
        body = f"# CodeGuardian security report\n\nRepository: {safe(data['repository']['full_name'])}\nCommit: {safe(data['commit_sha'])}\nScan status: {safe(data['status'])}\nCoverage complete: {bool(data['coverage'].get('complete'))}\n\nStatic evidence requires human review.\n\n| Finding | Severity | Location | Analyzer | Status |\n|---|---|---|---|---|\n"
        body += "\n".join("| " + " | ".join(safe(x) for x in (f["title"], f["severity"], f'{f["path"]}:{f["line"]}', f["engine"], f["status"])) + " |" for f in data["findings"])
        return Response(redact(body), media_type="text/markdown")
    return redact_tree({"schema_version": "2.0", "notice": "Static analyzer evidence is not proof of exploitability. Secrets are redacted on a best-effort basis.", **data})


from .integrations import router as integrations_router
from .webhooks import router as webhook_router
app.include_router(integrations_router)
app.include_router(webhook_router)
