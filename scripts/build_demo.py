"""Generate the published fixture view from real analyzer executions, never invented counts."""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from importlib.metadata import version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["SCANNER_MODE"] = "trusted-fixture"
from app.isolation import analyze
from app.scanner import summary, compare
from app.ai import explain, propose_patch


def build(version_name):
    directory = ROOT / "fixtures" / version_name
    files = {p.relative_to(directory).as_posix(): p.read_text() for p in directory.rglob("*") if p.is_file()}
    sha = hashlib.sha1(json.dumps(files, sort_keys=True).encode()).hexdigest()
    started = datetime.now(timezone.utc).isoformat()
    result = analyze(files, fixture=True)
    if not result["coverage"]["complete"]:
        raise RuntimeError("Demo build needs complete real scanner coverage: " + str(result["coverage"]["errors"]))
    return {"id": "fixture-" + version_name, "repository_id": "fixture-payment-service", "commit_sha": sha, "status": "completed", "created_at": started, "completed_at": datetime.now(timezone.utc).isoformat(), "summary": summary(result["findings"]), **result}


if __name__ == "__main__":
    baseline, current = build("baseline"), build("current")
    explanations, patches = {}, {}
    for finding in current["findings"]:
        fingerprint = finding["fingerprint"]
        source = current["files"][finding["path"]]
        explanations[fingerprint] = explain(finding, source)
        try: patches[fingerprint] = propose_patch(finding, source)
        except ValueError: pass
    output = {"mode": "fixture", "repository": {"id": "fixture-payment-service", "full_name": "codeguardian/payment-service", "branch": "main", "is_fixture": True}, "scan": current, "history": [{k: v for k, v in s.items() if k not in {"files", "findings"}} for s in [baseline, current]], "comparison": {**compare(current["findings"], baseline["findings"]), "baseline_commit": baseline["commit_sha"], "reliable": True}, "explanations": explanations, "patches": patches, "provenance": {"generated_at": datetime.now(timezone.utc).isoformat(), "semgrep": version("semgrep"), "bandit": version("bandit"), "fixture_hashes_are_git_commits": False}}
    dest = ROOT / "public/demo.json"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"file": str(dest), "findings": len(current["findings"]), "baseline": len(baseline["findings"]), "resolved": len(output["comparison"]["resolved"]), "engines": current["coverage"]["engines"]}))
