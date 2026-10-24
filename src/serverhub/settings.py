from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
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
    login_ip_limit: int = Field(default=10, ge=1, le=1000)
    login_global_limit: int = Field(default=100, ge=10, le=10000)
    trusted_proxy_cidrs: list[str] = []

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_proxy_networks(cls, values):
        import ipaddress
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError("Trust only the actual reverse proxy, never all clients")
        return values
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
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    health_url: str = "http://127.0.0.1:9080"
    health_ca: Path | None = None

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
        parsed = urlsplit(self.public_url)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or parsed.scheme not in {"http", "https"}):
            raise ValueError("public_url must be a single HTTP(S) origin without credentials or path")
        host = parsed.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        port = parsed.port
        authority = host + (f":{port}" if port and port != {"https": 443, "http": 80}[parsed.scheme] else "")
        self.public_url = f"{parsed.scheme}://{authority}"
        if bool(self.tls_certfile) != bool(self.tls_keyfile):
            raise ValueError("TLS requires both tls_certfile and tls_keyfile")
        if not self.dev_mode and not self.public_url.startswith("https://"):
            raise ValueError("production public_url must use HTTPS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
