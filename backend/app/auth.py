import hashlib
import secrets
from datetime import timedelta, timezone
from fastapi import Depends, HTTPException, Request
from cryptography.fernet import Fernet
from sqlmodel import Session
from .config import settings
from .models import User, LoginSession, get_db, now
from .limits import check_limit


def digest(value: str) -> str: return hashlib.sha256(value.encode()).hexdigest()


def cipher() -> Fernet:
    key = settings().token_encryption_key
    if not key: raise HTTPException(503, "Token encryption is not configured")
    return Fernet(key.encode())


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("cg_session", "")
    session = db.get(LoginSession, digest(token)) if token else None
    if not session or session.expires_at.replace(tzinfo=timezone.utc) <= now():
        raise HTTPException(401, "Sign in to access your repositories")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if request.headers.get("origin", "").rstrip("/") != settings().public_url.rstrip("/"):
            raise HTTPException(403, "Request origin is not trusted")
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf_token):
            raise HTTPException(403, "Invalid CSRF token; reload the session")
    user = db.get(User, session.user_id)
    if not user: raise HTTPException(401, "Session expired")
    if request.method not in {"GET", "HEAD", "OPTIONS"}: check_limit(user.id, "mutation", 30)
    request.state.login_session = session
    return user


def make_session(db: Session, user: User, response):
    token = secrets.token_urlsafe(48)
    session = LoginSession(id=digest(token), user_id=user.id, csrf_token=secrets.token_urlsafe(32), expires_at=now() + timedelta(hours=8))
    db.add(session)
    db.commit()
    response.set_cookie("cg_session", token, max_age=8 * 3600, httponly=True, secure=settings().public_url.startswith("https://"), samesite="lax", path="/")
    return session
