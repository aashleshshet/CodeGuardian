import os
import sys
import tempfile
from pathlib import Path
import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.update(DATABASE_URL="sqlite://", ENVIRONMENT="test", ALLOW_DEMO_LOGIN="true", TASKS_EAGER="true", SCANNER_MODE="trusted-fixture", PUBLIC_URL="http://testserver", TOKEN_ENCRYPTION_KEY=Fernet.generate_key().decode())
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, create_engine
from app.main import app
from app.models import get_db


@pytest.fixture
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    def session():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db] = session
    monkeypatch.setattr("app.tasks.engine", engine)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


@pytest.fixture
def authenticated(client):
    assert client.post("/auth/demo", headers={"Origin": "http://testserver"}).status_code == 200
    identity = client.get("/auth/me").json()
    client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": identity["csrf_token"]})
    return client
