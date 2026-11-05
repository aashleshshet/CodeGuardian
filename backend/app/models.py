from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Column, JSON, UniqueConstraint
from sqlmodel import SQLModel, Field, create_engine, Session
from .config import settings


def uid(): return str(uuid4())
def now(): return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    github_id: int = Field(unique=True, index=True)
    login: str
    encrypted_token: str = ""


class LoginSession(SQLModel, table=True):
    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    csrf_token: str
    expires_at: datetime


class OAuthState(SQLModel, table=True):
    id: str = Field(primary_key=True)
    verifier: str
    expires_at: datetime


class Repository(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("owner_id", "full_name"),)
    id: str = Field(default_factory=uid, primary_key=True)
    owner_id: str = Field(foreign_key="user.id", index=True)
    full_name: str
    github_id: int | None = None
    installation_id: int | None = None
    branch: str = "main"
    is_fixture: bool = False
    created_at: datetime = Field(default_factory=now)


class Scan(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    repository_id: str = Field(foreign_key="repository.id", index=True)
    commit_sha: str = ""
    status: str = "queued"
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    findings: list = Field(default_factory=list, sa_column=Column(JSON))
    files: dict = Field(default_factory=dict, sa_column=Column(JSON))
    coverage: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: str | None = None
    baseline_id: str | None = None


class Review(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", "owner_id"),)
    id: str = Field(default_factory=uid, primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    fingerprint: str
    owner_id: str = Field(foreign_key="user.id")
    status: str = "open"
    note: str = ""
    updated_at: datetime = Field(default_factory=now)


class WebhookDelivery(SQLModel, table=True):
    id: str = Field(primary_key=True)
    received_at: datetime = Field(default_factory=now)


class AuditEvent(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    user_id: str = Field(index=True)
    action: str
    resource_id: str
    created_at: datetime = Field(default_factory=now)


engine = create_engine(settings().database_url, connect_args={"check_same_thread": False} if settings().database_url.startswith("sqlite") else {}, pool_pre_ping=True)


def get_db():
    with Session(engine) as session:
        yield session
