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
    secret_key: str = ""
    token_encryption_key: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    github_app_id: str = ""
    github_private_key: str = ""
    github_webhook_secret: str = ""
    github_app_slug: str = ""
    github_checks_enabled: bool = False
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_enabled: bool = False
    scanner_mode: str = "docker"
    scanner_image: str = "codeguardian-scanner:local"
    scan_root: str | None = None
    tasks_eager: bool = False
    allow_demo_login: bool = False
    max_archive_bytes: int = 10_000_000
    max_source_bytes: int = 20_000_000
    max_files: int = 500
    max_file_bytes: int = 250_000
    scan_timeout: int = 180

    def validate_runtime(self):
        if self.environment == "production":
            if len(self.secret_key) < 32 or not self.token_encryption_key:
                raise RuntimeError("Production requires strong session and token encryption keys")
            if self.allow_demo_login or self.scanner_mode != "docker" or self.tasks_eager:
                raise RuntimeError("Production requires isolated scans and asynchronous workers")
            if not self.database_url.startswith("postgresql") or not self.public_url.startswith("https://"):
                raise RuntimeError("Production requires PostgreSQL and an HTTPS public URL")


@lru_cache
def settings() -> Settings:
    return Settings()
