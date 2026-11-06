"""Install pinned official scanner binaries with release SHA-256 verification.

This trusted administrative command is never run against repository content.
"""
import argparse
import hashlib
import io
import json
import os
import platform
import tarfile
import time
import urllib.request
from pathlib import Path

VERSIONS = {"gitleaks": "8.30.1", "osv-scanner": "2.7.0", "trivy": "0.76.2"}
REPOS = {"gitleaks": "gitleaks/gitleaks", "osv-scanner": "google/osv-scanner", "trivy": "aquasecurity/trivy"}


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "CodeGuardian-scanner-installer", "Accept": "application/vnd.github+json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                data = response.read(250_000_001)
            break
        except (TimeoutError, OSError):
            if attempt == 2: raise
            time.sleep(2 ** attempt)
    if len(data) > 250_000_000:
        raise RuntimeError("Release artifact exceeds size limit")
    return data


def install(destination: Path, selected: list[str]):
    system, arch = platform.system().lower(), platform.machine().lower()
    if system not in {"darwin", "linux"} or arch not in {"arm64", "aarch64", "x86_64", "amd64"}:
        raise RuntimeError("Supported platforms are macOS/Linux ARM64 and x86_64")
    arm = arch in {"arm64", "aarch64"}
    destination.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for tool in selected:
        version = VERSIONS[tool]
        if tool == "gitleaks":
            asset_name = f"gitleaks_{version}_{system}_{'arm64' if arm else 'x64'}.tar.gz"
        elif tool == "osv-scanner":
            asset_name = f"osv-scanner_{system}_{'arm64' if arm else 'amd64'}"
        else:
            machine = ('macOS-ARM64' if arm else 'macOS-64bit') if system == 'darwin' else ('Linux-ARM64' if arm else 'Linux-64bit')
            asset_name = f"trivy_{version}_{machine}.tar.gz"
        release = json.loads(fetch(f"https://api.github.com/repos/{REPOS[tool]}/releases/tags/v{version}"))
        asset = next(item for item in release["assets"] if item["name"] == asset_name)
        digest = asset.get("digest", "")
        if digest.startswith("sha256:"):
            expected = digest.removeprefix("sha256:")
        else:
            checksum = next(item for item in release["assets"] if item["name"].endswith("checksums.txt"))
            lines = fetch(checksum["browser_download_url"]).decode().splitlines()
            expected = next(line.split()[0] for line in lines if line.split()[-1].lstrip("*") == asset_name)
        data = fetch(asset["browser_download_url"])
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Checksum verification failed for {tool}")
        if asset_name.endswith(".tar.gz"):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = next(m for m in archive.getmembers() if m.name == tool or m.name.endswith('/' + tool))
                if not member.isfile() or member.size > 250_000_000:
                    raise RuntimeError("Unexpected binary archive member")
                data = archive.extractfile(member).read()
        target = destination / tool
        temporary = target.with_suffix(".download")
        temporary.write_bytes(data)
        temporary.chmod(0o755)
        os.replace(temporary, target)
        receipts[tool] = {"version": version, "asset": asset_name, "release_sha256": expected}
        (destination / "versions.json").write_text(json.dumps(receipts, indent=2))
        print(f"Installed {tool} {version}; SHA-256 verified", flush=True)
    (destination / "versions.json").write_text(json.dumps(receipts, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path(".cache/tools"))
    parser.add_argument("--tools", nargs="+", choices=VERSIONS, default=list(VERSIONS))
    args = parser.parse_args()
    install(args.destination.resolve(), args.tools)
