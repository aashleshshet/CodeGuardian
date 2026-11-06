"""Read-only readiness probes. Public results contain booleans, never connection details."""
from datetime import timedelta, timezone
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from redis import Redis
from sqlalchemy import inspect, text
from sqlmodel import SQLModel, Session
from .config import ROOT, settings
from .models import WorkerHealth, now


def schema_ready(db: Session) -> bool:
    if settings().environment == "production":
        # A reachable database may still be empty or running an incompatible revision.
        expected = set(ScriptDirectory(str(ROOT / "backend/migrations")).get_heads())
        current = set(MigrationContext.configure(db.connection()).get_current_heads())
        return bool(expected) and current == expected
    # Development/test startup intentionally creates tables directly. Check their
    # shape instead of inventing an Alembic stamp for a database never migrated.
    inspector = inspect(db.connection())
    actual = set(inspector.get_table_names())
    return all(
        table.name in actual
        and {column.name for column in table.columns}
        <= {column["name"] for column in inspector.get_columns(table.name)}
        for table in SQLModel.metadata.sorted_tables
    )


def readiness_checks(db: Session) -> dict[str, bool]:
    checks = {"database": False, "schema": False, "queue": False, "worker": False}
    try:
        db.exec(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        db.rollback()
    if checks["database"]:
        try:
            checks["schema"] = schema_ready(db)
        except Exception:
            db.rollback()
        try:
            worker = db.get(WorkerHealth, "celery")
            checks["worker"] = bool(
                worker and worker.heartbeat_at.replace(tzinfo=timezone.utc)
                > now() - timedelta(seconds=120)
            )
        except Exception:
            db.rollback()
    # A broker failure must not skip database/schema/worker diagnostics.
    try:
        with Redis.from_url(settings().redis_url, socket_timeout=2, socket_connect_timeout=2) as queue:
            checks["queue"] = bool(queue.ping())
    except Exception:
        pass
    return checks
