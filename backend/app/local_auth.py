"""Explicit single-user device authentication; never enabled by a cloud deployment."""
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from .auth import digest, make_session
from .config import settings
from .jobs import audit
from .limits import check_limit
from .models import LoginSession, User, get_db

router = APIRouter()
LOCAL_USER_ID = -1


class LocalSignIn(BaseModel):
    access_key: SecretStr = Field(min_length=32, max_length=256)


@router.post("/auth/local")
def local_sign_in(body: LocalSignIn, request: Request, db: Session = Depends(get_db)):
    cfg = settings()
    if cfg.environment != "local" or not cfg.local_auth_enabled:
        raise HTTPException(404, "Local authentication is not available")
    # Revalidate the security boundary even if a process mutates configuration
    # after startup. Merely reaching localhost must never create a session.
    try:
        cfg.validate_runtime()
    except (RuntimeError, ValueError):
        raise HTTPException(503, "Local authentication is not configured safely") from None
    if request.headers.get("origin", "").rstrip("/") != cfg.public_url.rstrip("/"):
        raise HTTPException(403, "Request origin is not trusted")
    check_limit(request.client.host if request.client else "unknown", "local-login", 10)
    if not secrets.compare_digest(digest(body.access_key.get_secret_value()), cfg.local_access_key_hash):
        raise HTTPException(401, "Invalid local access key")
    user = db.exec(select(User).where(User.github_id == LOCAL_USER_ID)).first()
    if user is None:
        user = User(github_id=LOCAL_USER_ID, login="local-reviewer")
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            # Concurrent first logins still belong to the same durable account.
            db.rollback()
            user = db.exec(select(User).where(User.github_id == LOCAL_USER_ID)).one()
        db.refresh(user)
    old = request.cookies.get("cg_session")
    if old:
        existing = db.get(LoginSession, digest(old))
        if existing:
            db.delete(existing)
    response = JSONResponse({"ok": True})
    make_session(db, user, response)
    audit(db, user.id, "auth.local", user.id)
    db.commit()
    return response
