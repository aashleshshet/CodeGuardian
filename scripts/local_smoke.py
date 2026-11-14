"""Exercise the running local stack through its real HTTP/session/worker APIs.

Uses only the owned vulnerable fixture and removes its imported repository after
verification. Never executes fixture code; only the isolated scanners inspect it.
"""
import http.cookiejar
import io
import json
import secrets
import time
import urllib.request
import zipfile
from local_setup import ROOT, KEY_FILE


def smoke():
    base = "http://localhost:3000"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf = ""

    def request(path, method="GET", payload=None, content_type="application/json"):
        headers = {"Origin": base, "Content-Type": content_type}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(base + "/api/backend" + path, data=data, method=method, headers=headers)
        with opener.open(req, timeout=235 if path.endswith(("/explanation", "/agent")) else 60) as response:
            return json.load(response)

    assert request("/ready")["status"] == "ready"
    caps = request("/capabilities")
    assert caps["local_auth"] and not caps["github"]
    request("/auth/local", "POST", {"access_key": KEY_FILE.read_text().strip()})
    identity = request("/auth/me")
    assert identity["auth_method"] == "local"
    csrf = identity["csrf_token"]
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for file in (ROOT / "fixtures/current").rglob("*"):
            if file.is_file():
                target.writestr(file.relative_to(ROOT / "fixtures/current").as_posix(), file.read_bytes())
    boundary = "cg-" + secrets.token_hex(12)
    payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="authorized"\r\n\r\ntrue\r\n'
               f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="local-smoke-{secrets.token_hex(4)}.zip"\r\n'
               'Content-Type: application/zip\r\n\r\n').encode() + archive.getvalue() + f'\r\n--{boundary}--\r\n'.encode()
    uploaded = request("/repositories/upload", "POST", payload, f"multipart/form-data; boundary={boundary}")
    scan_id = uploaded["scan_id"]
    deadline = time.monotonic() + 600
    previous = None
    while time.monotonic() < deadline:
        scan = request(f"/scans/{scan_id}")
        if scan["status"] != previous:
            previous = scan["status"]
            print("Local scan:", previous, flush=True)
        if previous in {"completed", "partial", "failed", "cancelled"}:
            break
        time.sleep(3)
    incomplete = [e["name"] for e in scan.get("coverage", {}).get("engines", []) if e["status"] != "completed"]
    assert scan["status"] == "completed", f"Scan ended {scan['status']}; incomplete analyzers: {incomplete}"
    assert scan["coverage"]["complete"], "Analyzer coverage was incomplete"
    assert scan["findings"], "Expected evidence was not detected"
    assert "cg_fixture_not_a_real_credential" not in json.dumps(scan)
    completed = {e["name"] for e in scan["coverage"]["engines"] if e["status"] == "completed"}
    assert {"Semgrep", "Bandit", "Gitleaks", "OSV-Scanner", "Trivy"} <= completed
    finding = next(f for f in scan["findings"] if f["category"] == "sast" and f["cwe"] == "CWE-89")
    explanation = request(f"/scans/{scan_id}/findings/{finding['fingerprint']}/explanation", "POST", {"use_llm": False})
    assert explanation["explanation"] and explanation["provider"] != "llm"
    model_result = None
    if caps["llm"]:
        print("Requesting local AI explanation for the SQL injection finding.", flush=True)
        generated = request(f"/scans/{scan_id}/findings/{finding['fingerprint']}/explanation", "POST", {"use_llm": True})
        assert generated["provider"] == "llm" and generated["explanation"].strip()
        assert generated["classification"] == finding["classification"] and generated["citations"]
        model_result = {"model": generated["model"], "citations": [c["id"] for c in generated["citations"]]}
    rag_path = f"/scans/{scan_id}/findings/{finding['fingerprint']}/agent"
    retrieval = request(rag_path, "POST", {"question": "How should I fix this?", "use_model": False})
    assert retrieval["provider"] == "curated_retrieval" and retrieval["citations"][0]["id"] == "CWE-89"
    if caps["llm"]:
        print("Requesting a cited answer from the local RAG agent.", flush=True)
        answer = request(rag_path, "POST", {"question": "How should I fix this SQL injection finding?", "use_model": True})
        assert answer["provider"] == "local_llm" and answer["answer"].strip()
        assert answer["classification"] == finding["classification"] and answer["citations"]
        assert "cg_fixture_not_a_real_credential" not in json.dumps(answer)
        model_result["rag_citations"] = [citation["id"] for citation in answer["citations"]]
    # Re-authentication must preserve stored scan results.
    request("/auth/logout", "POST")
    csrf = ""
    request("/auth/local", "POST", {"access_key": KEY_FILE.read_text().strip()})
    csrf = request("/auth/me")["csrf_token"]
    assert request(f"/scans/{scan_id}")["id"] == scan_id
    evidence = {"status": scan["status"], "coverage": scan["coverage"], "finding_count": len(scan["findings"]), "persisted_across_sessions": True, "local_model": model_result}
    (ROOT / ".cache/local/smoke-result.json").write_text(json.dumps(evidence, indent=2))
    request(f"/repositories/{scan['repository_id']}", "DELETE")
    request("/auth/logout", "POST")
    print("Verified local authentication, persisted results, five isolated scanners, redaction, curated explanations and the RAG agent. Test repository removed.")


if __name__ == "__main__":
    smoke()
