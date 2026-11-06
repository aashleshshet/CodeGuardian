from datetime import timedelta
from unittest.mock import MagicMock
from sqlalchemy import text
from sqlmodel import Session
from app import tasks
from app.config import settings
from app.models import WorkerHealth, now


def ready_dependencies(monkeypatch):
    queue = MagicMock()
    queue.__enter__.return_value = queue
    queue.ping.return_value = True
    monkeypatch.setattr("app.readiness.Redis.from_url", lambda *a, **kw: queue)
    with Session(tasks.engine) as db:
        db.add(WorkerHealth(id="celery", heartbeat_at=now()))
        db.commit()
    return queue


def test_readiness_requires_current_production_migration(client, monkeypatch):
    ready_dependencies(monkeypatch)
    monkeypatch.setattr(settings(), "environment", "production")
    # Reachability and a fresh worker cannot make an unstamped database ready.
    missing = client.get("/ready")
    assert missing.status_code == 503
    assert missing.json()["checks"] == {"database": True, "schema": False, "queue": True, "worker": True}
    with Session(tasks.engine) as db:
        db.exec(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        db.exec(text("INSERT INTO alembic_version VALUES ('001')"))
        db.commit()
    assert client.get("/ready").status_code == 503
    with Session(tasks.engine) as db:
        db.exec(text("UPDATE alembic_version SET version_num = '002'"))
        db.commit()
    assert client.get("/ready").status_code == 200


def test_broker_failure_preserves_independent_worker_result(client, monkeypatch):
    queue = ready_dependencies(monkeypatch)
    queue.ping.side_effect = RuntimeError("redis://operator:private-password@queue")
    result = client.get("/ready")
    assert result.status_code == 503
    assert result.json()["checks"] == {"database": True, "schema": True, "queue": False, "worker": True}
    assert "private-password" not in result.text


def test_readiness_rejects_stale_worker_even_when_database_and_queue_work(client, monkeypatch):
    ready_dependencies(monkeypatch)
    assert client.get("/ready").status_code == 200
    with Session(tasks.engine) as db:
        worker = db.get(WorkerHealth, "celery")
        worker.heartbeat_at = now() - timedelta(seconds=121)
        db.add(worker)
        db.commit()
    stale = client.get("/ready")
    assert stale.status_code == 503
    assert stale.json()["checks"] == {"database": True, "schema": True, "queue": True, "worker": False}
