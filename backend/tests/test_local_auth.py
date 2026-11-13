import hashlib
import secrets
from unittest.mock import MagicMock
import pytest
from app.config import settings, Settings


def configure_local(monkeypatch):
    key = secrets.token_urlsafe(48)
    cfg = settings()
    for name, value in {
        "environment": "local", "local_auth_enabled": True,
        "local_access_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "public_url": "http://localhost:3000", "tasks_eager": False,
        "scanner_mode": "docker",
    }.items():
        monkeypatch.setattr(cfg, name, value)
    # Only the Redis transport is replaced. Local auth/session/CSRF code is real.
    broker = MagicMock()
    broker.pipeline.return_value.execute.return_value = [1, True]
    monkeypatch.setattr("app.limits.Redis.from_url", lambda *a, **kw: broker)
    return key, broker


def test_local_key_session_origin_and_logout(client, monkeypatch):
    key, broker = configure_local(monkeypatch)
    assert client.get("/capabilities").json()["local_auth"] is True
    assert client.get("/capabilities").json()["github"] is False
    assert client.post("/auth/local", json={"access_key": key}).status_code == 403
    origin = {"Origin": "http://localhost:3000"}
    wrong = client.post("/auth/local", json={"access_key": "x" * 64}, headers=origin)
    assert wrong.status_code == 401
    login = client.post("/auth/local", json={"access_key": key}, headers=origin)
    assert login.status_code == 200 and key not in login.text
    assert "HttpOnly" in login.headers["set-cookie"]
    identity = client.get("/auth/me").json()
    assert identity["auth_method"] == "local"
    assert client.post("/auth/logout", headers=origin).status_code == 403
    headers = {**origin, "X-CSRF-Token": identity["csrf_token"]}
    assert client.patch("/preferences", json={"notify_scan_failure": False}, headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 200
    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/local", json={"access_key": key}, headers=origin).status_code == 200
    assert client.get("/preferences").json()["notify_scan_failure"] is False
    broker.pipeline.return_value.execute.return_value = [11, True]
    assert client.post("/auth/local", json={"access_key": key}, headers=origin).status_code == 429


def test_local_auth_is_unavailable_in_cloud_and_source_never_enriched(client, monkeypatch):
    assert client.post("/auth/local", json={"access_key": "x" * 64}).status_code == 404
    configure_local(monkeypatch)
    def unexpected_network(*a, **kw):
        raise AssertionError("Local mode must not contact a remote advisory API")
    monkeypatch.setattr("app.intelligence.httpx.Client", unexpected_network)
    from app.intelligence import enrich_findings, fetch_advisory
    finding = {"advisory_ids": ["CVE-2025-12345"]}
    assert enrich_findings([finding], None) == [finding]
    assert fetch_advisory("CVE-2025-12345", "nvd", None) is None


@pytest.mark.parametrize("changes", [
    {"environment": "production"}, {"public_url": "https://example.com"},
    {"public_url": "http://localhost:3000@evil.example"}, {"public_url": "http://localhost:3000/path"},
    {"local_access_key_hash": ""}, {"tasks_eager": True}, {"llm_allow_remote": True},
])
def test_local_configuration_rejects_unsafe_modes(changes):
    values = dict(environment="local", local_auth_enabled=True,
                  local_access_key_hash="a" * 64, public_url="http://localhost:3000",
                  token_encryption_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  scanner_mode="docker", tasks_eager=False)
    values.update(changes)
    with pytest.raises(RuntimeError):
        Settings(**values).validate_runtime()
