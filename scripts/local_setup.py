"""Manage the device-only CodeGuardian stack without exposing generated secrets."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".cache/local"
ENV_FILE = STATE / "compose.env"
KEY_FILE = STATE / "access-key.txt"


def private_write(path, value):
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(value)
    path.chmod(0o600)


def initialize():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    for name in ("jobs", "scanner-data"):
        (STATE / name).mkdir(exist_ok=True)
    if ENV_FILE.exists():
        if not KEY_FILE.exists():
            raise SystemExit("The local access key is missing. Restore it from your backup; setup will not replace existing credentials.")
        return
    if KEY_FILE.exists():
        raise SystemExit("An access key exists without compose.env. Restore the matching configuration before continuing.")
    key = secrets.token_urlsafe(48)
    values = {
        "LOCAL_PORT": "3000", "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "TOKEN_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "LOCAL_ACCESS_KEY_HASH": hashlib.sha256(key.encode()).hexdigest(),
        "SCANNER_JOBS_DIR": str(STATE / "jobs"), "SCANNER_CACHE_DIR": str(STATE / "scanner-data"),
        "WORKER_UID": str(os.getuid()), "DOCKER_GID": "0",
        "DOCKER_DAEMON_SOCKET": "/var/run/docker.sock",
    }
    # Literal single-quoted dotenv values support spaces without interpolation.
    if any("'" in value or "\n" in value for value in values.values()):
        raise SystemExit("The project path cannot contain a single quote or newline.")
    private_write(KEY_FILE, key + "\n")
    private_write(ENV_FILE, "\n".join(f"{k}='{v}'" for k, v in values.items()) + "\n")


def docker_command():
    lima = ROOT / ".cache/local-runtime/bin/limactl"
    # Prefer this project's VM over an unrelated system Docker context.
    if lima.exists() and (ROOT / ".cache/lima/cg/lima.yaml").exists():
        return [str(lima), "shell", "--workdir", str(ROOT), "cg", "sudo", "docker"]
    docker = shutil.which("docker")
    if docker:
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            endpoint = subprocess.check_output(
                [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], text=True
            ).strip()
        if not endpoint.startswith("unix:///"):
            raise SystemExit("Device-only mode requires a local Unix Docker socket. Select a local Docker context.")
        return [docker, "--host", endpoint]
    raise SystemExit("Docker is unavailable. On Apple Silicon run: python3 scripts/install_local_runtime.py start")


def docker(*args, capture=False):
    env = {**os.environ, "LIMA_HOME": str(ROOT / ".cache/lima")}
    return subprocess.run(docker_command() + list(args), cwd=ROOT, env=env, check=True,
                          text=True, capture_output=capture)


def compose(*args, capture=False, ai=None):
    enabled = (STATE / "ai-enabled").is_file() if ai is None else ai
    files = ["-f", "compose.local.yaml"]
    if enabled:
        files.extend(["-f", "compose.local-ai.yaml"])
    return docker("compose", "--env-file", str(ENV_FILE), *files, *args, capture=capture)


def cache_ready(cache):
    from datetime import datetime, timedelta, timezone

    try:
        manifest = json.loads((cache / "manifest.json").read_text())
        updated = datetime.fromisoformat(manifest["updated_at"])
        files = [cache / "trivy/db/trivy.db", cache / "trivy/db/metadata.json"]
        files.extend(cache / "osv/osv-scalibr" / ecosystem / "all.zip" for ecosystem in ("npm", "PyPI"))
        return (timedelta(0) <= datetime.now(timezone.utc) - updated <= timedelta(days=7)
                and all(path.is_file() and path.stat().st_size > 0 for path in files))
    except (KeyError, OSError, ValueError, TypeError):
        return False


def refresh_data():
    cache = STATE / "scanner-data"
    # Trivy can remove its current DB during a failed update. Download into a
    # separate directory and publish only after both tools complete successfully.
    with tempfile.TemporaryDirectory(prefix="db-update-", dir=STATE) as directory:
        stage = Path(directory)
        compose("--profile", "tools", "run", "--rm", "--volume", f"{stage}:/scanner-cache", "scanner-data")
        if not cache_ready(stage):
            raise SystemExit("Database download is incomplete. The previous cache is still available.")
        for subtree in ("osv", "trivy"):
            for path in (stage / subtree).rglob("*"):
                target = cache / path.relative_to(stage)
                if path.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    path.chmod(0o644)
                    os.replace(path, target)
        os.replace(stage / "manifest.json", cache / "manifest.json")


def configure_socket():
    # The daemon's Linux socket group can differ from both macOS and group 0.
    result = compose("run", "--rm", "--no-deps", "--entrypoint", "python", "worker", "-c",
                     "import os; print(os.stat('/var/run/docker.sock').st_gid)", capture=True)
    group = result.stdout.strip()
    if not group.isdecimal():
        raise SystemExit("Unable to determine the scanner daemon socket group.")
    rows = ENV_FILE.read_text().splitlines()
    private_write(ENV_FILE, "\n".join(f"DOCKER_GID='{group}'" if row.startswith("DOCKER_GID=") else row for row in rows) + "\n")


def probe():
    for route in ("health", "ready", "capabilities"):
        try:
            with urllib.request.urlopen(f"http://localhost:3000/api/backend/{route}", timeout=10) as response:
                value = json.load(response)
            print(f"{route}: {json.dumps(value)}")
        except urllib.error.HTTPError as exc:
            print(f"{route}: HTTP {exc.code}")
            return False
        except OSError:
            print(f"{route}: service is not reachable")
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "up", "down", "status", "update-data", "smoke", "enable-ai", "disable-ai"])
    args = parser.parse_args()
    initialize()
    if args.action == "init":
        print(f"Local configuration created or preserved. Access key: {KEY_FILE}")
    elif args.action == "up":
        docker("info", capture=True)
        docker("build", "-f", "backend/Dockerfile", "--target", "scanner", "-t", "codeguardian-scanner:local", ".")
        compose("build")
        configure_socket()
        if not cache_ready(STATE / "scanner-data"):
            refresh_data()
        services = ["frontend", "worker", "scheduler"]
        if (STATE / "ai-enabled").is_file():
            services.append("ollama")
        compose("up", "-d", *services)
        for _ in range(30):
            if probe():
                print(f"Open http://localhost:3000. Read your local access key from {KEY_FILE}")
                return
            time.sleep(4)
        raise SystemExit("Services started but readiness is incomplete. Run local_setup.py status.")
    elif args.action == "down":
        compose("down")  # Keep database and queue volumes; no data destruction.
    elif args.action == "update-data":
        refresh_data()
    elif args.action == "enable-ai":
        compose("--profile", "model-setup", "run", "--rm", "model-download", ai=True)
        compose("up", "-d", "--wait", "--wait-timeout", "120", "ollama", ai=True)
        compose("up", "-d", "--build", "api", "frontend", ai=True)
        (STATE / "ai-enabled").touch(mode=0o600)
        print("Local model enabled. In Code review select a finding and choose Explain with configured AI.")
    elif args.action == "disable-ai":
        compose("up", "-d", "api", "frontend", ai=False)
        compose("stop", "ollama", ai=True)
        (STATE / "ai-enabled").unlink(missing_ok=True)
        print("Local inference stopped. Downloaded weights are retained on this device.")
    elif args.action == "status":
        compose("ps")
        if not probe():
            raise SystemExit(1)
    else:
        from local_smoke import smoke
        smoke()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        raise SystemExit("A local service command failed. Inspect its output; credentials were not printed.") from None
