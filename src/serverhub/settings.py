from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SERVERHUB_", extra="ignore")
    database_url: str = "postgresql+psycopg://serverhub@/serverhub"
    dev_mode: bool = False
    state_dir: Path = Path("/var/lib/serverhub")
    public_url: str = "https://serverhub.local"
    allowed_origins: list[str] = ["https://serverhub.local"]
    secret_key: str = ""
    frontend_dir: Path = Path("/opt/serverhub/current/frontend/dist")
    model_config_path: Path = Path("/etc/serverhub/models.yaml")
    integration_config_path: Path = Path("/etc/serverhub/integrations.yaml")
    session_hours: int = 12
    login_failures: int = 5
    login_lock_seconds: int = 900
    max_concurrent_jobs: int = 4
    max_host_jobs: int = 1
    lease_seconds: int = 45
    worker_poll_seconds: float = 2.0
    offline_seconds: int = 180
    max_request_bytes: int = 8_388_608
    max_inventory_bytes: int = 4_194_304
    enable_openapi: bool = True
    api_bind: str = "127.0.0.1"
    api_port: int = 9080

    @property
    def integrations_config_path(self) -> Path:
        return self.integration_config_path

    @field_validator("session_hours", "login_failures", "login_lock_seconds", "max_concurrent_jobs", "max_host_jobs", "lease_seconds")
    @classmethod
    def positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be positive")
        return value

    @model_validator(mode="after")
    def validate_deployment(self):
        if self.database_url.startswith("sqlite") and not self.dev_mode:
            raise ValueError("SQLite is isolated-development only; production requires PostgreSQL")
        if not self.dev_mode and not self.public_url.startswith("https://"):
            raise ValueError("production public_url must use HTTPS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
