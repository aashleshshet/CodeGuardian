from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Column, JSON, UniqueConstraint, BigInteger
from sqlmodel import SQLModel, Field, create_engine, Session
from .config import settings


def uid(): return str(uuid4())
def now(): return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    github_id: int = Field(sa_column=Column(BigInteger, unique=True, index=True, nullable=False))
    login: str
    encrypted_token: str = ""
    encrypted_refresh_token: str = ""
    token_expires_at: datetime | None = None
    avatar_url: str = ""
    created_at: datetime = Field(default_factory=now)


class LoginSession(SQLModel, table=True):
    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    csrf_token: str
    expires_at: datetime


class OAuthState(SQLModel, table=True):
    id: str = Field(primary_key=True)
    verifier: str
    expires_at: datetime


class Installation(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("owner_id", "github_id"),)
    id: str = Field(default_factory=uid, primary_key=True)
    owner_id: str = Field(foreign_key="user.id", index=True)
    github_id: int = Field(sa_column=Column(BigInteger, index=True, nullable=False))
    account: str
    account_type: str = "User"
    permissions: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = "active"
    synced_at: datetime = Field(default_factory=now)


class Repository(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("owner_id", "full_name"),)
    id: str = Field(default_factory=uid, primary_key=True)
    owner_id: str = Field(foreign_key="user.id", index=True)
    full_name: str
    github_id: int | None = Field(default=None, sa_column=Column(BigInteger))
    installation_id: int | None = Field(default=None, sa_column=Column(BigInteger))
    branch: str = "main"
    visibility: str = "private"
    language: str = ""
    github_updated_at: str = ""
    connection_status: str = "connected"
    synced_at: datetime | None = None
    auto_scan: bool = False
    schedule_hours: int = 0
    next_scan_at: datetime | None = None
    checks_enabled: bool = False
    blocking_checks: bool = False
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
    baseline_id: str | None = Field(default=None, foreign_key="scan.id")
    branch: str = "main"
    trigger: str = "manual"
    job_key: str | None = Field(default=None, unique=True, index=True)
    attempts: int = 0
    queued_at: datetime | None = None
    started_at: datetime | None = None
    heartbeat_at: datetime | None = None
    encrypted_source: str = ""
    source_expires_at: datetime | None = None
    publish_check: bool = False
    base_commit: str = ""
    changed_files: list = Field(default_factory=list, sa_column=Column(JSON))


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


class RepositoryBranch(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("repository_id", "name"),)
    id: str = Field(default_factory=uid, primary_key=True)
    repository_id: str = Field(foreign_key="repository.id", index=True)
    name: str
    commit_sha: str
    synced_at: datetime = Field(default_factory=now)


class FindingRecord(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("repository_id", "branch", "fingerprint"),)
    id: str = Field(default_factory=uid, primary_key=True)
    repository_id: str = Field(foreign_key="repository.id", index=True)
    branch: str
    fingerprint: str = Field(index=True)
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)
    resolved_at: datetime | None = None
    status: str = "open"
    note: str = ""
    latest_scan_id: str = Field(foreign_key="scan.id")
    evidence: dict = Field(default_factory=dict, sa_column=Column(JSON))


class AIAnalysis(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    fingerprint: str
    provider: str
    result: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now)


class VulnerabilityReference(SQLModel, table=True):
    id: str = Field(primary_key=True)
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    expires_at: datetime


class UserPreference(SQLModel, table=True):
    user_id: str = Field(foreign_key="user.id", primary_key=True)
    notify_scan_failure: bool = True
    notify_high_findings: bool = True


class Notification(SQLModel, table=True):
    id: str = Field(default_factory=uid, primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    scan_id: str = Field(foreign_key="scan.id")
    message: str
    read: bool = False
    created_at: datetime = Field(default_factory=now)


class WorkerHealth(SQLModel, table=True):
    id: str = Field(primary_key=True)
    heartbeat_at: datetime = Field(default_factory=now)


engine = create_engine(settings().database_url, connect_args={"check_same_thread": False} if settings().database_url.startswith("sqlite") else {}, pool_pre_ping=True)


def get_db():
    with Session(engine) as session:
        yield session
