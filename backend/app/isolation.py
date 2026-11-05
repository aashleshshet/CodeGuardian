import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4
from .config import ROOT, settings
from .intake import validate_path
from .scanner import scan_directory


def analyze(files: dict[str, str], fixture: bool = False) -> dict:
    cfg = settings()
    if cfg.scanner_mode == "trusted-fixture":
        # Development escape hatch is restricted to the exact, application-owned fixture bytes.
        if cfg.environment == "production" or not fixture:
            raise RuntimeError("Untrusted repositories require the isolated Docker runner")
        allowed = [{p.relative_to(ROOT / "fixtures" / version).as_posix(): p.read_text() for p in (ROOT / "fixtures" / version).rglob("*") if p.is_file()} for version in ("baseline", "current")]
        if files not in allowed:
            raise RuntimeError("Only the bundled fixture may use the local scanner")
        with tempfile.TemporaryDirectory(prefix="cg-fixture-") as tmp:
            root = Path(tmp)
            for name, text in files.items():
                dest = root / validate_path(name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text)
            return scan_directory(root)
    if cfg.scanner_mode != "docker": raise RuntimeError("Unknown scanner mode")
    name = "codeguardian-" + uuid4().hex
    with tempfile.TemporaryDirectory(prefix="cg-scan-", dir=cfg.scan_root) as tmp:
        root = Path(tmp)
        for filename, content in files.items():
            dest = root / validate_path(filename)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
            dest.chmod(0o444)
        for directory in [root, *[p for p in root.rglob("*") if p.is_dir()]]: directory.chmod(0o555)
        command = ["docker", "run", "--rm", "--name", name, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=1536m", "--memory-swap=1536m", "--cpus=1", "--ulimit", "nofile=256:256", "--ulimit", "fsize=16777216:16777216", "--user=65532:65532", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m,mode=1777", "--mount", f"type=bind,src={root},dst=/source,readonly", cfg.scanner_image]
        try:
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                proc = subprocess.run(command, stdout=out, stderr=err, timeout=cfg.scan_timeout, check=False)
                if proc.returncode: raise RuntimeError("Isolated scanner failed; inspect runner health")
                out.seek(0, os.SEEK_END)
                if out.tell() > 8_000_000: raise RuntimeError("Scanner output exceeds limit")
                out.seek(0)
                return json.load(out)
        except FileNotFoundError:
            raise RuntimeError("Docker is required for untrusted repository scans") from None
        except subprocess.TimeoutExpired:
            raise RuntimeError("Isolated scan exceeded its time limit") from None
        finally:
            try: subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10, check=False)
            except (FileNotFoundError, subprocess.TimeoutExpired): pass
            for directory in [root, *[p for p in root.rglob("*") if p.is_dir()]]: directory.chmod(0o755)
