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
