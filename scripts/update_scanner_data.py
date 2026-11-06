"""Trusted administrative cache update. Never consumes repository-controlled URLs/configuration."""
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def update(cache: Path, ecosystems: list[str], trivy=True):
    cache.mkdir(parents=True, exist_ok=True)
    receipt = {"updated_at": datetime.now(timezone.utc).isoformat(), "ecosystems": {}}
    for ecosystem in ecosystems:
        if ecosystem not in {"npm", "PyPI"}: raise ValueError("Only supported ecosystems may be downloaded")
        dest = cache / "osv" / "osv-scalibr" / ecosystem / "all.zip"
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        digest, size = hashlib.sha256(), 0
        temp = dest.with_suffix(".download")
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temp.open("wb") as out:
                while block := response.read(1024*1024):
                    size += len(block)
                    if size > 500_000_000: raise RuntimeError("Database exceeds administrative download limit")
                    digest.update(block); out.write(block)
            os.replace(temp, dest)
        finally: temp.unlink(missing_ok=True)
        receipt["ecosystems"][ecosystem] = {"bytes": size, "sha256": digest.hexdigest(), "source": url}
        print(f"Updated {ecosystem} vulnerability database ({size} bytes)", flush=True)
    if trivy:
        prefix = ["trivy", "--config", str(ROOT/"backend/rules/trivy.yaml"), "--cache-dir", str(cache/"trivy"), "--quiet", "--timeout", "10m"]
        subprocess.run([*prefix,"fs","--download-db-only","--no-progress"],check=True,timeout=660)
        with tempfile.TemporaryDirectory() as target:
            Path(target,"Dockerfile").write_text("FROM scratch\nUSER 65532\n")
            subprocess.run([*prefix,"fs","--scanners","misconfig","--disable-telemetry","--skip-version-check",target],check=True,timeout=300,stdout=subprocess.DEVNULL)
        receipt["trivy"] = {"database": "trivy/db", "checks": "trivy/policy", "updated": True}
        print("Updated Trivy vulnerability database and checks",flush=True)
    (cache/"manifest.json").write_text(json.dumps(receipt,indent=2))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir",type=Path,default=Path(".cache/scanner-data"))
    parser.add_argument("--ecosystems",nargs="+",choices=["npm","PyPI"],default=["npm","PyPI"])
    parser.add_argument("--skip-trivy",action="store_true")
    args=parser.parse_args()
    update(args.cache_dir.resolve(),args.ecosystems,not args.skip_trivy)
