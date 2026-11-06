import json
from datetime import timedelta
from sqlmodel import Session, select
from app.models import User, Repository, Scan, LoginSession, now, get_db
from app.main import app
from app.auth import digest
from app.config import ROOT


def seed(client):
    db = next(app.dependency_overrides[get_db]())
    user = db.exec(select(User)).first()
    fixture = json.loads((ROOT / "backend/tests/data/scanner_snapshot.json").read_text())
    repo = Repository(owner_id=user.id, full_name="test/repo")
    db.add(repo); db.commit(); db.refresh(repo)
    scan = Scan(repository_id=repo.id, status="completed", findings=fixture["scan"]["findings"], files=fixture["scan"]["files"], coverage=fixture["scan"]["coverage"], commit_sha="a" * 40)
    db.add(scan); db.commit(); db.refresh(scan)
    return scan


def test_requires_auth_and_csrf(client):
    assert client.get("/repositories").status_code == 401
    assert client.post("/auth/demo").status_code == 404
    assert client.post("/repositories/fixture").status_code in {404, 405}
    assert not any(getattr(route, "path", None) == "/repositories/fixture" for route in app.routes)


def test_mutations_require_csrf(authenticated):
    authenticated.headers.pop("X-CSRF-Token")
    assert authenticated.post("/auth/logout").status_code == 403


def test_tenant_isolation(authenticated):
    scan = seed(authenticated)
    assert authenticated.get(f"/scans/{scan.id}").status_code == 200
    db = next(app.dependency_overrides[get_db]())
    stranger = User(github_id=222, login="another-user")
    db.add(stranger); db.commit(); db.refresh(stranger)
    db.add(LoginSession(id=digest("other-session"), user_id=stranger.id, csrf_token="other", expires_at=now()+timedelta(hours=1))); db.commit()
    authenticated.cookies.clear()
    authenticated.cookies.set("cg_session", "other-session")
    assert authenticated.get(f"/scans/{scan.id}").status_code == 404
    assert authenticated.get(f"/scans/{scan.id}/report").status_code == 404


def test_review_patch_and_redacted_reports(authenticated):
    scan = seed(authenticated)
    f = next(f for f in scan.findings if f["rule_id"] == "javascript-html-injection")
    base = f"/scans/{scan.id}/findings/{f['fingerprint']}"
    patch = authenticated.post(base + "/patch").json()
    assert authenticated.post(base + "/patch/export", json={"digest": patch["digest"], "reviewed": False}).status_code == 409
    assert authenticated.post(base + "/patch/export", json={"digest": "tampered", "reviewed": True}).status_code == 409
    exported = authenticated.post(base + "/patch/export", json={"digest": patch["digest"], "reviewed": True})
    assert exported.status_code == 200 and "textContent" in exported.text
    assert authenticated.patch(base + "/review", json={"status": "dismissed"}).status_code == 422
    assert authenticated.patch(base + "/review", json={"status": "confirmed", "note": 'password="synthetic_secret_123456789"'}).status_code == 200
    report = authenticated.get(f"/scans/{scan.id}/report").text
    assert "synthetic_secret_123456789" not in report
    assert "cg_fixture_not_a_real_credential" not in report
    assert "files" not in authenticated.get(f"/scans/{scan.id}/report").json()
    assert authenticated.get(f"/scans/{scan.id}/report?format=sarif").json()["version"] == "2.1.0"


def test_webhook_forgery_rejected(authenticated, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings(), "github_checks_enabled", True)
    monkeypatch.setattr(settings(), "github_webhook_secret", "webhook-test-secret")
    assert authenticated.post("/webhooks/github", json={"action": "opened"}).status_code == 403


def test_logout_invalidates_session(authenticated):
    assert authenticated.post("/auth/logout").status_code == 200
    assert authenticated.get("/auth/me").status_code == 401
