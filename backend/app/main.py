import base64
import hashlib
import hmac
import json
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta, timezone
from urllib.parse import urlencode
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, select
from .config import settings
from .models import engine, get_db, User, Repository, Scan, Review, AuditEvent, OAuthState, WebhookDelivery, now
from .auth import current_user, make_session, cipher, digest
from .scanner import summary, compare
from .intake import extract_sources
from .redaction import redact, redact_tree
from .ai import explain, propose_patch
from .tasks import enqueue
from . import github
from .middleware import BodyLimitMiddleware
from .limits import check_limit


@asynccontextmanager
async def lifespan(app):
    settings().validate_runtime()
    if settings().environment != "production": SQLModel.metadata.create_all(engine)
    yield


app = FastAPI(title="CodeGuardian AI", version="0.1.0", lifespan=lifespan, docs_url="/docs" if settings().environment != "production" else None)
app.add_middleware(BodyLimitMiddleware)


@app.middleware("http")
async def harden(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def audit(db, user, action, resource):
    db.add(AuditEvent(user_id=user.id, action=action, resource_id=resource))
    db.commit()


def owned_repo(repo_id, user, db):
    repo = db.get(Repository, repo_id)
    if not repo or repo.owner_id != user.id: raise HTTPException(404, "Repository not found")
    return repo


def owned_scan(scan_id, user, db):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    return scan, owned_repo(scan.repository_id, user, db)


def finding_for(scan, fingerprint):
    finding = next((f for f in scan.findings if f["fingerprint"] == fingerprint), None)
    if not finding: raise HTTPException(404, "Finding not found")
    return finding


def new_scan(repo, user, db):
    active = db.exec(select(Scan).join(Repository).where(Repository.owner_id == user.id, Scan.status.in_(["queued", "running"]))).all()
    if len(active) >= 3: raise HTTPException(429, "Three scans are already active; wait for one to complete")
    previous = db.exec(select(Scan).where(Scan.repository_id == repo.id, Scan.status == "completed").order_by(Scan.created_at.desc())).first()
    scan = Scan(repository_id=repo.id, baseline_id=previous.id if previous else None)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    audit(db, user, "scan.requested", scan.id)
    return scan


def scan_view(scan, db, with_files=True):
    result = scan.model_dump()
    result["summary"] = summary(scan.findings)
    if not with_files: result.pop("files")
    if scan.baseline_id:
        baseline = db.get(Scan, scan.baseline_id)
        if baseline:
            result["comparison"] = compare(scan.findings, baseline.findings)
            result["comparison"]["baseline_commit"] = baseline.commit_sha
            result["comparison"]["reliable"] = bool(scan.coverage.get("complete") and baseline.coverage.get("complete"))
    return result


@app.get("/health")
def health(): return {"status": "ok", "service": "codeguardian-api"}


@app.get("/capabilities")
def capabilities():
    cfg = settings()
    return {"github": bool(cfg.github_client_id and cfg.github_client_secret and cfg.token_encryption_key), "llm": bool(cfg.llm_enabled and cfg.llm_api_key and cfg.llm_model), "checks": cfg.github_checks_enabled, "demo_login": cfg.allow_demo_login and cfg.environment != "production", "repository_writes": False, "scanner_mode": cfg.scanner_mode}


@app.get("/auth/github/start")
def github_start(request: Request, db: Session = Depends(get_db)):
    cfg = settings()
    if not capabilities()["github"]: raise HTTPException(503, "GitHub App credentials are not configured")
    check_limit(request.client.host if request.client else "unknown", "oauth", 30)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    db.add(OAuthState(id=digest(state), verifier=verifier, expires_at=now() + timedelta(minutes=10)))
    db.commit()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    url = "https://github.com/login/oauth/authorize?" + urlencode({"client_id": cfg.github_client_id, "redirect_uri": cfg.public_url + "/api/backend/auth/github/callback", "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    response = RedirectResponse(url)
    response.set_cookie("cg_oauth", state, max_age=600, httponly=True, secure=cfg.public_url.startswith("https://"), samesite="lax", path="/")
    return response


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str, state: str, db: Session = Depends(get_db)):
    cookie = request.cookies.get("cg_oauth", "")
    stored = db.get(OAuthState, digest(state))
    if not cookie or not secrets.compare_digest(cookie, state) or not stored or stored.expires_at.replace(tzinfo=timezone.utc) < now():
        raise HTTPException(403, "OAuth state expired or invalid; start sign-in again")
    verifier = stored.verifier
    db.delete(stored)
    db.commit()
    cfg = settings()
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        response = client.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": cfg.github_client_id, "client_secret": cfg.github_client_secret, "code": code, "code_verifier": verifier, "redirect_uri": cfg.public_url + "/api/backend/auth/github/callback"})
        if response.status_code != 200: raise HTTPException(502, "GitHub sign-in failed")
        token = response.json().get("access_token")
        if not token: raise HTTPException(403, "GitHub did not grant access")
    with github.client(token) as gh: identity = github.checked(gh.get("/user"))
    user = db.exec(select(User).where(User.github_id == identity["id"])).first() or User(github_id=identity["id"], login=identity["login"])
    user.encrypted_token = cipher().encrypt(token.encode()).decode()
    db.add(user)
    db.commit()
    db.refresh(user)
    response = RedirectResponse(cfg.public_url + "/?connected=github", status_code=303)
    response.delete_cookie("cg_oauth", path="/")
    make_session(db, user, response)
    audit(db, user, "auth.github", user.id)
    return response


@app.post("/auth/demo")
def demo_login(request: Request, db: Session = Depends(get_db)):
    if not capabilities()["demo_login"]: raise HTTPException(404, "Not found")
    if request.headers.get("origin") != settings().public_url: raise HTTPException(403, "Untrusted origin")
    user = db.exec(select(User).where(User.github_id == -1)).first() or User(github_id=-1, login="local-reviewer")
    db.add(user)
    db.commit()
    db.refresh(user)
    response = JSONResponse({"login": user.login})
    make_session(db, user, response)
    return response


@app.get("/auth/me")
def me(request: Request, user: User = Depends(current_user)):
    return {"login": user.login, "csrf_token": request.state.login_session.csrf_token}


@app.post("/auth/logout")
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(request.state.login_session)
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("cg_session", path="/")
    return response


@app.get("/github/repositories")
def available_repos(user: User = Depends(current_user)):
    return {"repositories": github.authorized_repositories(user)}


@app.get("/repositories")
def repositories(user: User = Depends(current_user), db: Session = Depends(get_db)):
    repos = db.exec(select(Repository).where(Repository.owner_id == user.id).order_by(Repository.created_at.desc())).all()
    result = []
    for repo in repos:
        scans = db.exec(select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc())).all()
        result.append({**repo.model_dump(exclude={"owner_id"}), "scans": [scan_view(s, db, False) for s in scans]})
    return result


class ImportRepository(BaseModel):
    full_name: str = Field(max_length=160)
    installation_id: int = Field(gt=0)


@app.post("/repositories/github", status_code=201)
def import_github(body: ImportRepository, user: User = Depends(current_user), db: Session = Depends(get_db)):
    available = github.verify_repository(user, body.full_name, body.installation_id)
    if not available: raise HTTPException(403, "Authorize this repository in the GitHub App first")
    repo = db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.full_name == available["full_name"])).first()
    if not repo:
        repo = Repository(owner_id=user.id, full_name=available["full_name"], github_id=available["id"], installation_id=body.installation_id, branch=available["branch"])
        db.add(repo)
        db.commit()
        db.refresh(repo)
    scan = new_scan(repo, user, db)
    enqueue(scan, db)
    return {"repository_id": repo.id, "scan_id": scan.id}


@app.post("/repositories/fixture", status_code=201)
def import_fixture(user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo = db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.is_fixture == True)).first()
    if not repo:
        repo = Repository(owner_id=user.id, full_name="codeguardian/payment-service", is_fixture=True)
        db.add(repo)
        db.commit()
        db.refresh(repo)
    scan = new_scan(repo, user, db)
    enqueue(scan, db)
    return {"repository_id": repo.id, "scan_id": scan.id}


@app.post("/repositories/upload", status_code=201)
async def upload(file: UploadFile = File(...), authorized: bool = Form(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not authorized: raise HTTPException(422, "Confirm that you are authorized to review this source")
    data = await file.read(settings().max_archive_bytes + 1)
    await file.close()
    try: files, intake = extract_sources(data)
    except ValueError as exc: raise HTTPException(422, str(exc)) from None
    encrypted = cipher().encrypt(json.dumps(files).encode()).decode()
    repo = Repository(owner_id=user.id, full_name="uploaded/" + secrets.token_hex(4), branch="snapshot")
    db.add(repo)
    db.commit()
    db.refresh(repo)
    scan = new_scan(repo, user, db)
    scan.commit_sha = hashlib.sha256(data).hexdigest()
    scan.coverage = intake
    db.add(scan)
    db.commit()
    enqueue(scan, db, encrypted_source=encrypted)
    return {"repository_id": repo.id, "scan_id": scan.id}


@app.post("/repositories/{repo_id}/scans", status_code=202)
def rescan(repo_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    repo = owned_repo(repo_id, user, db)
    if not repo.is_fixture and not repo.github_id: raise HTTPException(409, "Upload a new archive to scan an updated snapshot")
    if repo.github_id and not github.verify_repository(user, repo.full_name, repo.installation_id): raise HTTPException(403, "Repository access was revoked")
    scan = new_scan(repo, user, db)
    enqueue(scan, db)
    return {"scan_id": scan.id}


@app.get("/scans/{scan_id}")
def scan_detail(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, repo = owned_scan(scan_id, user, db)
    result = scan_view(scan, db)
    reviews = {r.fingerprint: r for r in db.exec(select(Review).where(Review.scan_id == scan.id, Review.owner_id == user.id)).all()}
    result["findings"] = [{**f, "status": reviews[f["fingerprint"]].status if f["fingerprint"] in reviews else "open", "review_note": reviews[f["fingerprint"]].note if f["fingerprint"] in reviews else ""} for f in scan.findings]
    return {**result, "repository": repo.model_dump(exclude={"owner_id"})}


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
    try: result = explain(f, scan.files[f["path"]], body.use_llm)
    except (ValueError, httpx.HTTPError): raise HTTPException(502, "AI explanation unavailable. Curated remediation remains available.") from None
    audit(db, user, "finding.explained", fingerprint)
    return result


@app.post("/scans/{scan_id}/findings/{fingerprint}/patch")
def patch(scan_id: str, fingerprint: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    f = finding_for(scan, fingerprint)
    try: result = propose_patch(f, scan.files[f["path"]])
    except ValueError as exc: raise HTTPException(422, str(exc)) from None
    return result


class ExportPatch(BaseModel):
    digest: str
    reviewed: bool


@app.post("/scans/{scan_id}/findings/{fingerprint}/patch/export")
def export_patch(scan_id: str, fingerprint: str, body: ExportPatch, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    f = finding_for(scan, fingerprint)
    try: proposed = propose_patch(f, scan.files[f["path"]])
    except ValueError as exc: raise HTTPException(422, str(exc)) from None
    if not body.reviewed or not secrets.compare_digest(body.digest, proposed["digest"]): raise HTTPException(409, "Review the current patch before exporting it")
    audit(db, user, "patch.reviewed_export", fingerprint)
    return Response(proposed["diff"], media_type="text/plain", headers={"Content-Disposition": 'attachment; filename="codeguardian.patch"'})


class ReviewBody(BaseModel):
    status: str
    note: str = Field(default="", max_length=2000)


@app.patch("/scans/{scan_id}/findings/{fingerprint}/review")
def review(scan_id: str, fingerprint: str, body: ReviewBody, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan, _ = owned_scan(scan_id, user, db)
    finding_for(scan, fingerprint)
    if body.status not in {"open", "confirmed", "dismissed"}: raise HTTPException(422, "Invalid review status")
    if body.status == "dismissed" and not body.note.strip(): raise HTTPException(422, "A dismissal needs a reason")
    record = db.exec(select(Review).where(Review.scan_id == scan.id, Review.fingerprint == fingerprint, Review.owner_id == user.id)).first() or Review(scan_id=scan.id, fingerprint=fingerprint, owner_id=user.id)
    record.status, record.note, record.updated_at = body.status, redact(body.note), now()
    db.add(record)
    db.commit()
    audit(db, user, "finding." + body.status, fingerprint)
    return record


@app.get("/scans/{scan_id}/report")
def report(scan_id: str, format: str = "json", user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = scan_detail(scan_id, user, db)
    if format == "sarif":
        return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "CodeGuardian AI", "version": "0.1.0"}}, "results": [{"ruleId": f["rule_id"], "level": "error" if f["severity"] in {"critical", "high"} else "warning", "message": {"text": f["message"]}, "partialFingerprints": {"codeguardian/v1": f["fingerprint"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": {"startLine": f["line"]}}}]} for f in data["findings"]]}]}
    data.pop("files", None)
    return redact_tree({"schema_version": "1.0", "notice": "Static analyzer evidence is not proof of exploitability. Secrets are redacted on a best-effort basis.", **data})


@app.post("/webhooks/github", status_code=202)
async def webhook(request: Request, db: Session = Depends(get_db)):
    cfg = settings()
    if not cfg.github_webhook_secret or not cfg.github_checks_enabled: raise HTTPException(404, "Not found")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 1_000_000: raise HTTPException(413, "Webhook too large")
    expected = "sha256=" + hmac.new(cfg.github_webhook_secret.encode(), data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(request.headers.get("x-hub-signature-256", ""), expected): raise HTTPException(403, "Invalid webhook signature")
    delivery = request.headers.get("x-github-delivery", "")
    if not delivery or len(delivery) > 100: raise HTTPException(422, "Invalid delivery identifier")
    if db.get(WebhookDelivery, delivery): return {"status": "duplicate"}
    payload = json.loads(data)
    if request.headers.get("x-github-event") != "pull_request" or payload.get("action") not in {"opened", "synchronize", "reopened"}: return {"status": "ignored"}
    repo = db.exec(select(Repository).where(Repository.github_id == payload.get("repository", {}).get("id"), Repository.installation_id == payload.get("installation", {}).get("id"))).first()
    if not repo: return {"status": "unregistered"}
    # MVP only reviews same-repository heads. Forks need a separate authorization policy.
    pr = payload["pull_request"]
    if pr["head"]["repo"]["id"] != repo.github_id: return {"status": "fork_skipped"}
    user = db.get(User, repo.owner_id)
    scan = new_scan(repo, user, db)
    scan.commit_sha = pr["head"]["sha"]
    db.add(scan)
    db.add(WebhookDelivery(id=delivery))
    try: db.commit()
    except IntegrityError:
        db.rollback()
        return {"status": "duplicate"}
    enqueue(scan, db, publish_check=True)
    return {"scan_id": scan.id}
