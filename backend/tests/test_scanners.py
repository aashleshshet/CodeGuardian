import json
from app.config import ROOT
from app.isolation import analyze


def test_real_semgrep_bandit_pipeline():
    root = ROOT / "fixtures/current"
    files = {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*") if p.is_file()}
    result = analyze(files, fixture=True)
    assert result["coverage"]["complete"], result["coverage"]
    rules = {f["rule_id"] for f in result["findings"]}
    assert {"javascript-sql-injection", "javascript-command-execution", "javascript-eval", "javascript-html-injection", "javascript-tls-disabled", "python-unsafe-yaml", "B608", "B602", "CG-SECRET-001"} <= rules
    serialized = json.dumps(result)
    assert "cg_fixture_not_a_real_credential" not in serialized
    assert "[REDACTED]" in serialized
    assert {"Python", "JavaScript", "TypeScript"} <= set(result["coverage"]["languages"])


def test_all_five_real_scanners(monkeypatch):
    import os
    import pytest
    from app.config import settings
    if os.environ.get("RUN_ALL_SCANNERS") != "true":
        pytest.skip("Set RUN_ALL_SCANNERS=true after installing binaries and offline databases")
    monkeypatch.setenv("ENABLED_SCANNERS", "semgrep,bandit,gitleaks,osv,trivy")
    settings.cache_clear()
    try:
        root=ROOT/"fixtures/current"
        files={p.relative_to(root).as_posix():p.read_text() for p in root.rglob('*') if p.is_file()}
        result=analyze(files,fixture=True)
        assert result['coverage']['complete'],result['coverage']
        assert {f['engine'] for f in result['findings']} >= {'Semgrep','Bandit','Gitleaks','OSV-Scanner','Trivy'}
        assert {f['category'] for f in result['findings']} >= {'sast','secret','dependency','configuration'}
        assert any(f.get('package')=='lodash' and f.get('advisory_ids') for f in result['findings'])
        assert any(len(f.get('sources',[]))>1 for f in result['findings'])
        serialized=json.dumps(result)
        assert 'ghp_aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5' not in serialized
        assert 'cg_fixture_not_a_real_credential' not in serialized
    finally:
        monkeypatch.setenv("ENABLED_SCANNERS", "semgrep,bandit")
        settings.cache_clear()
