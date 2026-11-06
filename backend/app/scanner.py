"""Only this module runs analyzers; their configs are exclusively application-owned."""
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import certifi
from pathlib import Path
from collections import Counter
from .config import ROOT, settings
from .redaction import detect_secrets, redact, redact_tree

RULES = ROOT / "backend/rules/security.yml"
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TITLES = {"B602": "Shell command injection", "B608": "SQL query built with string formatting", "B506": "Unsafe YAML deserialization", "B403": "Unsafe deserialization library", "B301": "Unsafe pickle deserialization", "B324": "Weak cryptographic hash", "B404": "Subprocess module in use", "javascript-sql-injection": "SQL injection", "javascript-command-execution": "Command injection", "javascript-eval": "Dynamic code evaluation", "javascript-tls-disabled": "TLS verification disabled", "javascript-html-injection": "Unescaped HTML assignment", "python-unsafe-yaml": "Unsafe YAML deserialization"}
CWE_OWASP = {"78": "A03:2021 – Injection", "89": "A03:2021 – Injection", "95": "A03:2021 – Injection", "79": "A03:2021 – Injection", "502": "A08:2021 – Software and Data Integrity Failures", "295": "A02:2021 – Cryptographic Failures", "327": "A02:2021 – Cryptographic Failures", "259": "A07:2021 – Identification and Authentication Failures", "798": "A07:2021 – Identification and Authentication Failures", "22": "A01:2021 – Broken Access Control"}


def bounded_run(command: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    # Scanner output can contain raw source. Private temporary files are destroyed before returning.
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": tempfile.gettempdir(), "SSL_CERT_FILE": certifi.where(), "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "PYTHONIOENCODING": "utf-8", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(Path(settings().scanner_cache) / "osv"), "GOMAXPROCS": "1"}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=errors, start_new_session=True)
        try: proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise RuntimeError("Analyzer exceeded its time limit") from None
        output.seek(0, 2)
        if output.tell() > 8_000_000: raise RuntimeError("Analyzer output exceeded its limit")
        output.seek(0)
        return proc.returncode, output.read().decode("utf-8", errors="replace")


def normalize(f: dict, files: dict[str, str]) -> dict | None:
    path = f["path"].removeprefix("/source/").removeprefix("./")
    if path not in files: return None
    lines = files[path].splitlines()
    line = min(max(1, int(f["line"])), max(len(lines), 1))
    snippet = lines[line - 1] if lines else ""
    normalized_line = re.sub(r"\s+", " ", redact(snippet)).strip()
    category = f.get("category", "sast")
    package = f.get("package", "")
    if str(f.get("ecosystem", "")).lower() in {"pypi", "pip"}: package = re.sub(r"[-_.]+", "-", package.lower())
    identity = f"{package}:{f.get('installed_version','')}" if category == "dependency" else normalized_line
    fingerprint = hashlib.sha256(f"{category}:{f['rule_id']}:{path}:{identity}".encode()).hexdigest()[:24]
    return {**f, "category": category, "title": TITLES.get(f["rule_id"], f["title"]), "path": path, "line": line, "end_line": max(line, int(f.get("end_line", line))), "fingerprint": fingerprint,
            "snippet": redact(snippet), "classification": f.get("classification", "verified_analyzer"), "status": "open"}


def scan_directory(directory: Path) -> dict:
    files = {p.relative_to(directory).as_posix(): p.read_text() for p in directory.rglob("*") if p.is_file() and not p.is_symlink()}
    results, engines, errors = [], [], []
    enabled = set(settings().enabled_scanners.lower().split(","))
    unknown = enabled - {"semgrep", "bandit", "gitleaks", "osv", "trivy"}
    if unknown: raise ValueError("Unknown configured analyzer")
    if not enabled: raise ValueError("No analyzers configured")
    from .scanner_adapters import ADAPTERS
    secret_values = []
    for key in ("gitleaks", "osv", "trivy"):
        if key not in enabled: continue
        name, adapter = ADAPTERS[key]
        try:
            entries, values = adapter(directory, bounded_run)
            results.extend(entries)
            secret_values.extend(values)
            engines.append({"name": name, "status": "completed"})
        except (FileNotFoundError, RuntimeError, json.JSONDecodeError, KeyError, ValueError, TypeError):
            errors.append(f"{name}: analyzer unavailable, cache missing, or scan failed; coverage is incomplete")
            engines.append({"name": name, "status": "failed"})
    database_updated_at = None
    if enabled & {"osv", "trivy"}:
        from datetime import datetime, timezone, timedelta
        try:
            manifest = json.loads((Path(settings().scanner_cache)/"manifest.json").read_text())
            database_updated_at = manifest["updated_at"]
            updated = datetime.fromisoformat(database_updated_at).astimezone(timezone.utc)
            if datetime.now(timezone.utc)-updated > timedelta(days=7):
                errors.append("Vulnerability databases are older than seven days; refresh the administrative cache")
        except (OSError, ValueError, KeyError):
            errors.append("Vulnerability database freshness is unknown; refresh the administrative cache")
    def mask(value):
        if isinstance(value, str):
            for secret in sorted(set(secret_values), key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]" + "\n" * secret.count("\n"))
            return redact(value)
        if isinstance(value, list): return [mask(v) for v in value]
        if isinstance(value, dict): return {mask(k): mask(v) for k,v in value.items()}
        return value
    files = {p: mask(v) for p,v in files.items()}
    adapter_results = results
    results = []
    for entry in adapter_results:
        if entry["path"].startswith(str(directory)):
            entry["path"] = Path(entry["path"]).relative_to(directory).as_posix()
        normalized = normalize(mask(entry), files)
        if normalized: results.append(normalized)
    for name, command in [
        ("Semgrep", ["semgrep", "scan", "--config", str(RULES), "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore", "--disable-nosem", "--jobs=1", "--timeout=20", "--max-memory=768", "."]),
        ("Bandit", ["bandit", "-r", ".", "--ini", str(ROOT / "backend/rules/bandit.ini"), "-f", "json", "--ignore-nosec", "-q"]),
    ]:
        if name.lower() not in enabled: continue
        try:
            code, raw = bounded_run(command, directory, 120)
            if code not in (0, 1): raise RuntimeError("Analyzer failed")
            payload = json.loads(raw)
            if payload.get("errors"):
                errors.append(f"{name}: some files could not be analyzed")
            for item in payload.get("results", []):
                if name == "Bandit":
                    cwe = str((item.get("issue_cwe") or {}).get("id", ""))
                    if not cwe: cwe = "unknown"
                    f = {"path": item["filename"], "line": item["line_number"], "end_line": max(item.get("line_range") or [item["line_number"]]), "rule_id": item["test_id"], "title": item["test_name"].replace("_", " ").capitalize(), "message": item["issue_text"], "severity": item["issue_severity"].lower(), "confidence": item["issue_confidence"].lower(), "cwe": "CWE-" + cwe, "owasp": CWE_OWASP.get(cwe, "Unmapped"), "engine": name}
                else:
                    extra = item["extra"]
                    meta = extra.get("metadata", {})
                    f = {"path": item["path"], "line": item["start"]["line"], "end_line": item["end"]["line"], "rule_id": item["check_id"].split(".")[-1], "title": item["check_id"].split(".")[-1].replace("javascript-", "").replace("python-", "").replace("-", " ").capitalize(), "message": extra["message"], "severity": {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(extra["severity"], "medium"), "confidence": meta.get("confidence", "MEDIUM").lower(), "cwe": meta.get("cwe", "Unmapped"), "owasp": meta.get("owasp", "Unmapped"), "engine": name}
                if f["path"].startswith(str(directory)):
                    f["path"] = Path(f["path"]).relative_to(directory).as_posix()
                entry = normalize(mask(f), files)
                if entry: results.append(entry)
            engines.append({"name": name, "status": "partial" if payload.get("errors") else "completed"})
        except (FileNotFoundError, RuntimeError, json.JSONDecodeError, KeyError, ValueError):
            errors.append(f"{name}: analyzer unavailable or failed; coverage is incomplete")
            engines.append({"name": name, "status": "failed"})
    for path, content in {p: pth.read_text() for p, pth in ((p.relative_to(directory).as_posix(), p) for p in directory.rglob("*") if p.is_file() and not p.is_symlink())}.items():
        for secret in detect_secrets(content):
            results.append(normalize({"path": path, "line": secret.line, "rule_id": "CG-SECRET-001", "title": "Potential hardcoded credential", "message": f"{secret.kind} pattern detected. The value has been redacted. Verify ownership, revoke if active, and move it into a secret store.", "severity": "high", "confidence": "medium", "cwe": "CWE-798", "owasp": CWE_OWASP["798"], "engine": "CodeGuardian Secrets", "category": "secret", "classification": "potential_vulnerability"}, files))
    engines.append({"name": "CodeGuardian Secrets", "status": "completed"})
    # A stable fingerprint intentionally collapses repeated identical matches in a file.
    merged = {}
    for finding in results:
        if not finding: continue
        old = merged.get(finding["fingerprint"])
        if old:
            old["sources"] = sorted(set(old.get("sources", [old["engine"]])) | {finding["engine"]})
            old["references"] = sorted(set(old.get("references", [])) | set(finding.get("references", [])))
            old["advisory_ids"] = sorted(set(old.get("advisory_ids", [])) | set(finding.get("advisory_ids", [])))
            if old.get("cwe") == "Unmapped" and finding.get("cwe") != "Unmapped": old["cwe"] = finding["cwe"]
            if ORDER[finding["severity"]] < ORDER[old["severity"]]: old["severity"] = finding["severity"]
        else: merged[finding["fingerprint"]] = finding
    findings = sorted(merged.values(), key=lambda f: (ORDER[f["severity"]], f["path"], f["line"]))
    return mask({"findings": findings, "files": {p: redact(v) for p, v in files.items()}, "coverage": {"files": len(files), "languages": sorted({{ ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript"}.get(Path(p).suffix, "Configuration") for p in files}), "engines": engines, "errors": errors, "complete": not errors, "rule_version": "2026.11.2", "configured_engines": sorted(enabled), "database_updated_at": database_updated_at, "scope": "Static source, supported lockfiles and configuration; no application builds or container image execution"}})


def summary(findings: list[dict]) -> dict:
    counts = Counter(f["severity"] for f in findings)
    return {s: counts[s] for s in ORDER}


def compare(current: list[dict], baseline: list[dict]) -> dict:
    old, new = {f["fingerprint"] for f in baseline}, {f["fingerprint"] for f in current}
    return {"new": sorted(new - old), "resolved": sorted(old - new), "unchanged": sorted(old & new)}


if __name__ == "__main__":
    print(json.dumps(scan_directory(Path("/source"))))
