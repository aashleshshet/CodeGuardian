"""Test-only browser harness. This module refuses to start outside ENVIRONMENT=test.

It performs real scans of the application-owned fixture. There is no test login
route in app.main and production images do not include this package.
"""
import hashlib
import json
import secrets
from fastapi import HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import Session, select
from app.config import settings, ROOT

if settings().environment != "test":
    raise RuntimeError("The E2E harness is exclusively for ENVIRONMENT=test")

from app.main import app
from app.models import User, Repository, Scan, get_db, now
from app.auth import make_session
from app.isolation import analyze


class TestSession(BaseModel):
    scan: bool = False


@app.post("/test/session")
def test_session(body: TestSession, request: Request, db: Session = Depends(get_db)):
    if settings().environment != "test" or request.headers.get("origin") != settings().public_url:
        raise HTTPException(403, "Test session unavailable")
    user = User(github_id=9_000_000_000 + secrets.randbelow(1_000_000_000), login="security-reviewer")
    db.add(user)
    db.commit()
    db.refresh(user)
    scan_id = repository_id = None
    if body.scan:
        from app.jobs import persist_results
        source = ROOT / "fixtures/current"
        files = {p.relative_to(source).as_posix(): p.read_text() for p in source.rglob("*") if p.is_file()}
        evidence = analyze(files, fixture=True)
        if not evidence["coverage"]["complete"]:
            raise RuntimeError("Real fixture scanners did not complete")
        repo = db.exec(select(Repository).where(Repository.owner_id == user.id, Repository.full_name == "tests/security-fixture")).first()
        if not repo:
            repo = Repository(owner_id=user.id, full_name="tests/security-fixture", branch="main", visibility="private", language="TypeScript")
            db.add(repo)
            db.flush()
        scan = Scan(repository_id=repo.id, branch="main", status="analyzing", commit_sha=hashlib.sha1(json.dumps(files, sort_keys=True).encode()).hexdigest(), started_at=now())
        db.add(scan)
        db.flush()
        persist_results(db, scan, evidence)
        db.commit()
        scan_id, repository_id = scan.id, repo.id
    response = JSONResponse({"login": user.login, "scan_id": scan_id, "repository_id": repository_id})
    make_session(db, user, response)
    return response
