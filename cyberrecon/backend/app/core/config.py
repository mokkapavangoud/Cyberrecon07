"""Application settings. All values can be overridden with CYBERRECON_* env vars."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value):
    if value is None or isinstance(value, list):
        return value
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYBERRECON_", env_file=".env", extra="ignore")

    app_name: str = "CyberRecon"
    version: str = "0.1.0"
    environment: str = "development"

    # storage
    data_dir: Path = Path("./data")
    database_url: str | None = None

    # web
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    rate_limit_per_minute: int = 30

    # outbound network controls
    http_connect_timeout: float = 5.0
    http_read_timeout: float = 10.0
    http_total_timeout: float = 25.0
    max_response_bytes: int = 2_000_000
    max_redirects: int = 5
    allowed_ports: Annotated[list[int], NoDecode] = [80, 443, 8080, 8443]
    target_allowlist: Annotated[list[str], NoDecode] = []
    max_concurrent_assessments: int = 3
    user_agent: str = "CyberRecon/0.1 (authorised-assessment; passive-footprinting)"

    # link analysis
    max_links_stored: int = 2000
    link_check_default_limit: int = 25
    link_check_max_limit: int = 100
    link_check_concurrency: int = 4

    # image intelligence
    max_upload_bytes: int = 10 * 1024 * 1024
    max_image_pixels: int = 50_000_000
    persist_image_gps: bool = False

    # serving
    frontend_dist: Path | None = None  # built SPA directory; defaults to ../frontend/dist when present

    # DNS
    dns_resolvers: Annotated[list[str], NoDecode] = []
    dns_timeout: float = 4.0

    # optional providers
    subdomain_provider: str = "crtsh"  # crtsh | securitytrails | none
    securitytrails_api_key: str | None = None
    subdomain_verify_limit: int = 25
    geoip_provider: str = "none"  # none | ipapi | maxmind
    geoip_db_path: str | None = None

    # screenshots
    screenshot_enabled: bool = True
    screenshot_timeout_ms: int = 20_000
    screenshot_proxy: str | None = None
    chromium_path: str | None = None

    @field_validator("cors_origins", "allowed_ports", "target_allowlist", "dns_resolvers", mode="before")
    @classmethod
    def _csv(cls, v):
        return _split_csv(v)

    # derived paths -------------------------------------------------------
    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'cyberrecon.db').resolve()}"

    @property
    def screenshots_dir(self) -> Path:
        return self.data_dir / "screenshots"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.screenshots_dir, self.reports_dir):
            p.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
