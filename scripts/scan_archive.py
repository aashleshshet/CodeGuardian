"""Scan an authorized ZIP in the hardened container, and export redacted JSON or SARIF."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.intake import extract_sources
from app.isolation import analyze

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
with args.archive.open("rb") as source: data = source.read(10_000_001)
files, coverage = extract_sources(data)
result = analyze(files)
result.pop("files", None)
args.output.write_text(json.dumps(result, indent=2))
print(f"{len(result['findings'])} findings; complete coverage: {result['coverage']['complete']}")
if not result["coverage"]["complete"]: print(json.dumps(result["coverage"]))
sys.exit(0 if result["coverage"]["complete"] else 2)
