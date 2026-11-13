"""Install a project-scoped, open-source Lima/Docker VM on Apple Silicon.

Trusted setup only: downloads an official, checksum-pinned runtime and Linux
image. Does not execute any submitted repository code or create cloud resources.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".cache/local-runtime"
LIMA_HOME = ROOT / ".cache/lima"
VERSION = "2.3.0"
SHA256 = "b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc"


def install():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("This helper targets Apple Silicon. On Linux use Docker Engine and Compose.")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    archive = RUNTIME / "lima.tar.gz"
    if not archive.exists():
        url = f"https://github.com/lima-vm/lima/releases/download/v{VERSION}/lima-{VERSION}-Darwin-arm64.tar.gz"
        with urllib.request.urlopen(url, timeout=180) as response, archive.open("wb") as target:
            import shutil
            shutil.copyfileobj(response, target)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("Lima checksum mismatch. Remove the downloaded archive and retry.")
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(RUNTIME, filter="data")
    print(f"Lima {VERSION} verified and installed in {RUNTIME}")


def runtime_env():
    return {**os.environ, "LIMA_HOME": str(LIMA_HOME)}


def start(memory=6):
    binary = RUNTIME / "bin/limactl"
    if not binary.exists():
        install()
    # Do not share the user's home, SSH credentials or other projects with this VM.
    config = {
        "base": [{"url": "template:_images/ubuntu-lts"}],
        "vmType": "vz", "mountType": "virtiofs", "cpus": 2,
        "memory": f"{memory}GiB", "disk": "40GiB",
        "mounts": [{"location": str(ROOT), "writable": True}],
        "containerd": {"system": False, "user": False},
        "provision": [{"mode": "system", "script": "#!/bin/sh\nset -eu\nif ! command -v docker >/dev/null 2>&1; then\n curl -fsSL https://get.docker.com -o /tmp/install-docker.sh\n sh /tmp/install-docker.sh\n rm /tmp/install-docker.sh\nfi\n"}],
        "probes": [{"script": "#!/bin/sh\nsudo docker info >/dev/null\n"}],
        "portForwards": [
            {"guestPort": 3000, "hostPort": 3000, "hostIP": "127.0.0.1"},
            {"guestIP": "0.0.0.0", "proto": "any", "ignore": True},
        ],
    }
    path = RUNTIME / "cg.yaml"
    path.write_text(json.dumps(config, indent=2))  # JSON is valid YAML.
    env = runtime_env()
    if (LIMA_HOME / "cg/lima.yaml").exists():
        command = [str(binary), "start", "--tty=false", "cg"]
    else:
        command = [str(binary), "start", "--tty=false", "--name=cg", str(path)]
    subprocess.run(command, env=env, check=True)
    subprocess.run([str(binary), "shell", "cg", "sudo", "docker", "compose", "version"], env=env, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "start", "stop"], default="start", nargs="?")
    parser.add_argument("--memory", type=int, choices=range(4, 17), default=6, help="VM RAM in GiB (default 6)")
    args = parser.parse_args()
    if args.action == "install":
        install()
    elif args.action == "start":
        start(args.memory)
    else:
        subprocess.run([str(RUNTIME / "bin/limactl"), "stop", "cg"], env=runtime_env(), check=True)
