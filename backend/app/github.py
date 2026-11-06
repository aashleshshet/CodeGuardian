"""GitHub App boundary. Fixed API origins, short-lived scoped tokens, no repository code execution."""
import re
import time
from datetime import timedelta, timezone
from urllib.parse import quote
import httpx
import jwt
from fastapi import HTTPException
from .auth import cipher
from .config import settings
from .models import now

API = "https://api.github.com"


def client(token: str):
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, timeout=25, follow_redirects=False)


def checked(response: httpx.Response):
    if response.status_code == 429 or (response.status_code == 403 and (response.headers.get("x-ratelimit-remaining") == "0" or response.headers.get("retry-after"))):
        retry = response.headers.get("retry-after", "60")
        raise HTTPException(429, "GitHub rate limit reached; retry after the indicated delay", headers={"Retry-After": retry if retry.isdigit() else "60"})
    if response.status_code in (401, 403, 404):
        raise HTTPException(403, "GitHub access was denied or revoked; reconnect your account")
    if response.status_code >= 400: raise HTTPException(502, "GitHub could not complete the request")
    try: return response.json()
    except ValueError: raise HTTPException(502, "Invalid response from GitHub") from None


def request(gh, method, path, **kwargs):
    for attempt in range(3):
        try:
            response = gh.request(method, path, **kwargs)
        except (httpx.TimeoutException, httpx.NetworkError):
            if attempt == 2: raise HTTPException(502, "GitHub temporarily unavailable") from None
            time.sleep(.2 * 2 ** attempt)
            continue
        if response.status_code >= 500 and attempt < 2:
            time.sleep(.2 * 2 ** attempt)
            continue
        return checked(response)


def store_tokens(user, payload):
    token = payload.get("access_token")
    if not token: raise HTTPException(403, "GitHub did not grant access")
    user.encrypted_token = cipher().encrypt(token.encode()).decode()
    if payload.get("refresh_token"):
        user.encrypted_refresh_token = cipher().encrypt(payload["refresh_token"].encode()).decode()
    user.token_expires_at = now() + timedelta(seconds=int(payload["expires_in"])) if payload.get("expires_in") else None


def user_token(user, db=None) -> str:
    if not user.encrypted_token: raise HTTPException(409, "Connect your GitHub account first")
    if db is not None and user.token_expires_at and user.token_expires_at.replace(tzinfo=timezone.utc) <= now() + timedelta(seconds=60):
        from sqlmodel import select
        from .models import User
        # Refresh tokens rotate. Serialize refresh so concurrent jobs do not reuse one.
        user = db.exec(select(User).where(User.id == user.id).with_for_update().execution_options(populate_existing=True)).one()
    if user.token_expires_at and user.token_expires_at.replace(tzinfo=timezone.utc) <= now() + timedelta(seconds=60):
        if not user.encrypted_refresh_token or db is None: raise HTTPException(401, "GitHub authorization expired; sign in again")
        cfg = settings()
        with httpx.Client(timeout=20, follow_redirects=False) as gh:
            response = gh.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": cfg.github_client_id, "client_secret": cfg.github_client_secret, "grant_type": "refresh_token", "refresh_token": cipher().decrypt(user.encrypted_refresh_token.encode()).decode()})
        store_tokens(user, checked(response))
        db.add(user)
        db.flush()
    return cipher().decrypt(user.encrypted_token.encode()).decode()


def installations(user, db=None):
    result = []
    with client(user_token(user, db)) as gh:
        for page in range(1, 21):
            batch = request(gh, "GET", f"/user/installations?per_page=100&page={page}")["installations"]
            result.extend({"id": i["id"], "account": i["account"]["login"], "account_type": i["account"]["type"], "permissions": i.get("permissions", {}), "status": "suspended" if i.get("suspended_at") else "active"} for i in batch if str(i["app_id"]) == settings().github_app_id)
            if len(batch) < 100: return result
    raise HTTPException(422, "Installation limit exceeded; narrow the authorized account scope")


def authorized_repositories(user, db=None) -> list[dict]:
    result = []
    for installation in installations(user, db):
        if installation["status"] != "active": continue
        with client(user_token(user, db)) as gh:
            for page in range(1, 21):
                repos = request(gh, "GET", f"/user/installations/{installation['id']}/repositories?per_page=100&page={page}")["repositories"]
                result.extend({"id": r["id"], "full_name": r["full_name"], "branch": r.get("default_branch") or "main", "private": r["private"], "language": r.get("language") or "", "updated_at": r.get("updated_at", ""), "installation_id": installation["id"]} for r in repos)
                if len(repos) < 100: break
            else: raise HTTPException(422, "Repository authorization exceeds the 2,000-repository limit")
    return result


def verify_repository(user, full_name: str, installation_id: int, db=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name): raise HTTPException(422, "Invalid repository name")
    return next((r for r in authorized_repositories(user, db) if r["full_name"].lower() == full_name.lower() and r["installation_id"] == installation_id), None)


def installation_token(installation_id: int, repository_id: int, checks=False) -> str:
    cfg = settings()
    if not cfg.github_app_id or not cfg.github_private_key: raise HTTPException(503, "GitHub App signing is not configured")
    signed = jwt.encode({"iat": int(time.time()) - 30, "exp": int(time.time()) + 300, "iss": cfg.github_app_id}, cfg.github_private_key.replace("\\n", "\n"), algorithm="RS256")
    permissions = {"contents": "read"}
    if checks: permissions["checks"] = "write"
    with client(signed) as gh:
        # A new narrowly scoped token per operation; no stale installation token cache.
        return request(gh, "POST", f"/app/installations/{installation_id}/access_tokens", json={"repository_ids": [repository_id], "permissions": permissions})["token"]


def repository_client(user, repo, db=None):
    if repo.connection_status != "connected" or not verify_repository(user, repo.full_name, repo.installation_id, db):
        raise HTTPException(403, "Repository authorization was revoked")
    return client(installation_token(repo.installation_id, repo.github_id))


def resolve_commit(user, repo, ref, db=None):
    if not ref or len(ref) > 200 or any(ord(c) < 32 for c in ref): raise HTTPException(422, "Invalid branch or commit")
    with repository_client(user, repo, db) as gh:
        sha = request(gh, "GET", f"/repos/{repo.full_name}/commits/{quote(ref, safe='')}")["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha): raise HTTPException(502, "Invalid commit returned by GitHub")
    return sha


def branches(user, repo, db=None, page=1):
    with repository_client(user, repo, db) as gh:
        data = request(gh, "GET", f"/repos/{repo.full_name}/branches", params={"per_page": 100, "page": page})
    return [{"name": b["name"], "commit_sha": b["commit"]["sha"]} for b in data]


def commits(user, repo, branch, db=None, page=1):
    with repository_client(user, repo, db) as gh:
        data = request(gh, "GET", f"/repos/{repo.full_name}/commits", params={"sha": branch, "per_page": 30, "page": page})
    return [{"sha": c["sha"], "message": c["commit"]["message"].split("\n")[0][:300], "date": c["commit"]["committer"]["date"]} for c in data]


def snapshot(user, repo, ref: str | None = None, db=None) -> tuple[bytes, str]:
    with repository_client(user, repo, db) as gh:
        commit = request(gh, "GET", f"/repos/{repo.full_name}/commits/{quote(ref or repo.branch, safe='')}")["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit): raise HTTPException(502, "Invalid commit returned by GitHub")
        response = gh.get(f"/repos/{repo.full_name}/zipball/{commit}")
        location = response.headers.get("location", "")
        parsed = httpx.URL(location)
        if response.status_code != 302 or parsed.scheme != "https" or parsed.host != "codeload.github.com" or parsed.port not in (None, 443):
            raise HTTPException(502, "GitHub archive redirect was rejected")
        with httpx.stream("GET", location, timeout=60, follow_redirects=False) as archive:
            if archive.status_code != 200: raise HTTPException(502, "Could not download repository archive")
            data = bytearray()
            for chunk in archive.iter_bytes():
                data.extend(chunk)
                if len(data) > settings().max_archive_bytes: raise HTTPException(413, "Repository archive exceeds configured limit")
        return bytes(data), commit


def revoke_user(user, db=None):
    token = user_token(user, db)
    cfg = settings()
    with httpx.Client(base_url=API, auth=(cfg.github_client_id, cfg.github_client_secret), timeout=20, follow_redirects=False) as gh:
        response = gh.request("DELETE", f"/applications/{cfg.github_client_id}/grant", json={"access_token": token})
        if response.status_code not in (204, 404): checked(response)


def publish_check(repo, scan):
    token = installation_token(repo.installation_id, repo.github_id, checks=True)
    findings = scan.findings
    high = sum(f["severity"] in {"critical", "high"} for f in findings)
    complete = scan.coverage.get("complete", False)
    conclusion = "neutral"
    if complete: conclusion = "failure" if high and repo.blocking_checks else ("neutral" if high else "success")
    with client(token) as gh:
        request(gh, "POST", f"/repos/{repo.full_name}/check-runs", json={
            "name": "CodeGuardian security review", "head_sha": scan.commit_sha, "status": "completed", "conclusion": conclusion,
            "details_url": settings().public_url + "/#repositories",
            "output": {"title": f"{len(findings)} analyzer findings · {high} high priority", "summary": "Static evidence requires human review. " + ("Configured analyzers completed." if complete else "Incomplete coverage: inspect scanner errors."),
            "annotations": [{"path": f["path"], "start_line": f["line"], "end_line": f["line"], "annotation_level": "warning", "title": f["title"][:255], "message": f"{f['engine']} {f['rule_id']} · {f['cwe']}\n{f['message']}"[:5000]} for f in findings[:50]]}})
