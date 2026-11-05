import base64
import hashlib
import re
import time
from urllib.parse import quote
import httpx
import jwt
from fastapi import HTTPException
from .auth import cipher
from .config import settings

API = "https://api.github.com"


def client(token: str):
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, timeout=25, follow_redirects=False)


def user_token(user) -> str:
    if not user.encrypted_token: raise HTTPException(409, "Connect your GitHub account first")
    return cipher().decrypt(user.encrypted_token.encode()).decode()


def checked(response: httpx.Response):
    if response.status_code in (401, 403, 404):
        raise HTTPException(403, "GitHub access was denied or revoked; reconnect your account")
    if response.status_code >= 400: raise HTTPException(502, "GitHub could not complete the request")
    return response.json()


def authorized_repositories(user) -> list[dict]:
    result = []
    with client(user_token(user)) as gh:
        for ipage in range(1, 6):
            installations = checked(gh.get(f"/user/installations?per_page=100&page={ipage}"))["installations"]
            for installation in installations:
                if settings().github_app_id and str(installation["app_id"]) != settings().github_app_id: continue
                for page in range(1, 11):
                    repos = checked(gh.get(f"/user/installations/{installation['id']}/repositories?per_page=100&page={page}"))["repositories"]
                    result.extend({"id": r["id"], "full_name": r["full_name"], "branch": r["default_branch"], "private": r["private"], "installation_id": installation["id"]} for r in repos)
                    if len(repos) < 100: break
            if len(installations) < 100: break
    return result


def verify_repository(user, full_name: str, installation_id: int):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name): raise HTTPException(422, "Invalid repository name")
    return next((r for r in authorized_repositories(user) if r["full_name"].lower() == full_name.lower() and r["installation_id"] == installation_id), None)


def snapshot(user, repo, ref: str | None = None) -> tuple[bytes, str]:
    if not verify_repository(user, repo.full_name, repo.installation_id): raise HTTPException(403, "Repository authorization was revoked")
    with client(user_token(user)) as gh:
        commit = checked(gh.get(f"/repos/{repo.full_name}/commits/{quote(ref or repo.branch, safe='')}"))["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit): raise HTTPException(502, "Invalid commit returned by GitHub")
        response = gh.get(f"/repos/{repo.full_name}/zipball/{commit}")
        location = response.headers.get("location", "")
        parsed = httpx.URL(location)
        if response.status_code != 302 or parsed.scheme != "https" or parsed.host != "codeload.github.com":
            raise HTTPException(502, "GitHub archive redirect was rejected")
        # The signed archive URL is sufficient. Never forward the user bearer token across hosts.
        with httpx.stream("GET", location, timeout=60, follow_redirects=False) as archive:
            if archive.status_code != 200: raise HTTPException(502, "Could not download repository archive")
            data = bytearray()
            for chunk in archive.iter_bytes():
                data.extend(chunk)
                if len(data) > settings().max_archive_bytes: raise HTTPException(413, "Repository archive exceeds 10 MB")
        return bytes(data), commit


def installation_token(installation_id: int, repository_id: int) -> str:
    cfg = settings()
    if not cfg.github_app_id or not cfg.github_private_key: raise RuntimeError("GitHub App signing is not configured")
    signed = jwt.encode({"iat": int(time.time()) - 30, "exp": int(time.time()) + 300, "iss": cfg.github_app_id}, cfg.github_private_key.replace("\\n", "\n"), algorithm="RS256")
    with client(signed) as gh:
        return checked(gh.post(f"/app/installations/{installation_id}/access_tokens", json={"repository_ids": [repository_id], "permissions": {"contents": "read", "checks": "write"}}))["token"]


def publish_check(repo, scan):
    token = installation_token(repo.installation_id, repo.github_id)
    findings = scan.findings
    high = sum(f["severity"] in {"critical", "high"} for f in findings)
    complete = scan.coverage.get("complete", False)
    with client(token) as gh:
        checked(gh.post(f"/repos/{repo.full_name}/check-runs", json={
            "name": "CodeGuardian security review", "head_sha": scan.commit_sha, "status": "completed",
            "conclusion": "neutral" if not complete else ("action_required" if high else "success"),
            "output": {"title": f"{len(findings)} analyzer findings · {high} high priority", "summary": "Static evidence requires human review. " + ("All configured analyzers completed." if complete else "Coverage incomplete: inspect the scan before merging."),
            "annotations": [{"path": f["path"], "start_line": f["line"], "end_line": f["line"], "annotation_level": "warning", "title": f["title"], "message": f"{f['engine']} {f['rule_id']} · {f['cwe']}\n{f['message']}"} for f in findings[:50]]}}))
