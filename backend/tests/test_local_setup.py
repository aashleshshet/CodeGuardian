import hashlib
import importlib.util
from pathlib import Path
import stat
import yaml
import pytest

ROOT = Path(__file__).resolve().parents[2]


def setup_module_at(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("local_setup_under_test", ROOT / "scripts/local_setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name, value in {"STATE": tmp_path / "local", "ENV_FILE": tmp_path / "local/compose.env", "KEY_FILE": tmp_path / "local/access-key.txt"}.items():
        monkeypatch.setattr(module, name, value)
    return module


def test_local_setup_preserves_secrets_and_protects_files(tmp_path, monkeypatch):
    module = setup_module_at(tmp_path, monkeypatch)
    module.initialize()
    key, config = module.KEY_FILE.read_text(), module.ENV_FILE.read_text()
    assert hashlib.sha256(key.strip().encode()).hexdigest() in config
    assert key.strip() not in config
    assert stat.S_IMODE(module.KEY_FILE.stat().st_mode) == 0o600
    assert stat.S_IMODE(module.ENV_FILE.stat().st_mode) == 0o600
    module.initialize()
    assert module.KEY_FILE.read_text() == key and module.ENV_FILE.read_text() == config
    module.KEY_FILE.unlink()
    with pytest.raises(SystemExit, match="Restore"):
        module.initialize()
    assert module.ENV_FILE.read_text() == config


def test_local_stack_exposes_only_loopback_and_no_runtime_egress():
    stack = yaml.safe_load((ROOT / "compose.local.yaml").read_text())
    services = stack["services"]
    assert stack["networks"]["local"]["internal"] is True
    assert services["frontend"]["ports"] == ["127.0.0.1:${LOCAL_PORT:-3000}:3000"]
    for name in ("postgres", "redis", "api", "worker", "scheduler", "migrate"):
        assert not services[name].get("ports")
        assert services[name]["networks"] == ["local"]
    assert not services["api"].get("volumes")
    assert services["api"]["environment"]["LLM_ENABLED"] == "false"
    assert services["api"]["environment"]["ADVISORY_ENRICHMENT_ENABLED"] == "false"


def test_failed_cache_update_preserves_existing_database(tmp_path, monkeypatch):
    module = setup_module_at(tmp_path, monkeypatch)
    module.initialize()
    existing = module.STATE / "scanner-data/trivy/db/trivy.db"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"last successful database")

    def failed_update(*args):
        mount = args[args.index("--volume") + 1]
        stage = Path(mount.removesuffix(":/scanner-cache"))
        assert stage != module.STATE / "scanner-data"
        (stage / "incomplete-download").write_bytes(b"partial")
        raise RuntimeError("simulated update failure")

    monkeypatch.setattr(module, "compose", failed_update)
    with pytest.raises(RuntimeError, match="simulated update failure"):
        module.refresh_data()
    assert existing.read_bytes() == b"last successful database"
    assert not list(module.STATE.glob("db-update-*"))


def test_model_download_is_separate_from_private_inference():
    services = yaml.safe_load((ROOT / "compose.local-ai.yaml").read_text())["services"]
    assert services["ollama"]["networks"] == ["local"]
    assert not services["ollama"].get("ports")
    assert services["ollama"]["environment"]["OLLAMA_NO_CLOUD"] == "1"
    assert services["model-download"]["networks"] == ["updates"]
    assert services["model-download"]["volumes"] == ["model_store:/root/.ollama"]
    assert services["api"]["environment"]["LLM_ALLOW_REMOTE"] == "false"
