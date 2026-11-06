from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_url: str = "sqlite:///./codeguardian.db"
    redis_url: str = "redis://localhost:6379/0"
    public_url: str = "http://localhost:3000"
    token_encryption_key: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    github_app_id: str = ""
    github_private_key: str = ""
    github_webhook_secret: str = ""
    github_app_slug: str = ""
    github_checks_enabled: bool = False
    llm_base_url: str = "http://ollama:11434/v1"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_enabled: bool = False
    scanner_mode: str = "docker"
    scanner_image: str = "codeguardian-scanner:local"
    scan_root: str | None = None
    tasks_eager: bool = False
    max_archive_bytes: int = 10_000_000
    max_source_bytes: int = 20_000_000
    max_files: int = 500
    max_file_bytes: int = 250_000
    scan_timeout: int = 480
    scanner_cache: str = ""
    enabled_scanners: str = "semgrep,bandit,gitleaks,osv,trivy"
    source_retention_hours: int = 24
    result_retention_days: int = 90
    advisory_cache_hours: int = 24
    nvd_api_key: str = ""
    llm_allow_remote: bool = False
    max_scan_attempts: int = 3
    worker_stale_seconds: int = 600

    def validate_runtime(self):
        from cryptography.fernet import Fernet
        from urllib.parse import urlparse
        if self.token_encryption_key:
            Fernet(self.token_encryption_key.encode())
        if self.llm_enabled:
            host = urlparse(self.llm_base_url)
            local = host.hostname in {"localhost", "127.0.0.1", "ollama", "host.docker.internal"}
            if not local and (not self.llm_allow_remote or host.scheme != "https"):
                raise RuntimeError("Remote AI requires explicit opt-in and HTTPS")
        if not 1 <= self.source_retention_hours <= 168 or not 1 <= self.result_retention_days <= 365:
            raise RuntimeError("Retention settings exceed supported bounds")
        if self.environment == "production":
            if not self.token_encryption_key:
                raise RuntimeError("Production requires a Fernet token encryption key")
            if self.scanner_mode != "docker" or self.tasks_eager:
                raise RuntimeError("Production requires isolated scans and asynchronous workers")
            if not self.database_url.startswith("postgresql") or not self.public_url.startswith("https://"):
                raise RuntimeError("Production requires PostgreSQL and an HTTPS public URL")


@lru_cache
def settings() -> Settings:
    return Settings()
