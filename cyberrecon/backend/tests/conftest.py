from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CYBERRECON_ENVIRONMENT", "test")

from app.core.config import Settings  # noqa: E402
from app.security.ip_policy import IPPolicy  # noqa: E402

from .fixture_server import FixtureServer  # noqa: E402


class LoopbackOnlyPolicy(IPPolicy):
    """Test policy: behaves like the production policy except 127.0.0.1 is reachable.

    Lets tests exercise real sockets against the fixture server while every other blocked range
    (link-local metadata, RFC1918, ...) is still rejected exactly as in production.
    """

    def reason(self, ip_str: str):
        if ip_str in ("127.0.0.1",):
            return None
        return super().reason(ip_str)


@pytest.fixture(scope="session")
def fixture_server():
    srv = FixtureServer().start()
    yield srv
    srv.stop()


@pytest.fixture
def server(fixture_server):
    fixture_server.requests.clear()
    return fixture_server


@pytest.fixture
def settings(tmp_path, fixture_server):
    return Settings(
        data_dir=tmp_path / "data",
        allowed_ports=[80, 443, 8080, 8443, fixture_server.port],
        http_connect_timeout=2.0,
        http_read_timeout=1.0,
        http_total_timeout=8.0,
        max_response_bytes=500_000,
        rate_limit_per_minute=1000,
        subdomain_provider="none",
        screenshot_enabled=False,
        _env_file=None,
    )


@pytest.fixture
def loopback_policy():
    return LoopbackOnlyPolicy()


# ---------------------------------------------------------------------------- app-level fixtures
from app.database.migrations import migrate  # noqa: E402
from app.database.session import Database  # noqa: E402
from app.security.safe_net import SafeFetcher  # noqa: E402

from .helpers import DEFAULT_MAP, fake_resolver  # noqa: E402


@pytest.fixture
def db(tmp_path):
    d = Database(f"sqlite:///{tmp_path / 'test.db'}")
    migrate(d)
    yield d
    d.dispose()


@pytest.fixture
def fetcher_factory(settings, loopback_policy):
    def make():
        return SafeFetcher(settings, resolver=fake_resolver(DEFAULT_MAP), policy=loopback_policy)

    return make


# ---------------------------------------------------------------------------- API fixtures
import httpx  # noqa: E402

from app.main import create_app  # noqa: E402

from .helpers import make_providers  # noqa: E402


@pytest.fixture
def make_app(settings, fetcher_factory, loopback_policy):
    def build(providers=None, loopback=False, **settings_override):
        s = settings.model_copy(update=settings_override) if settings_override else settings
        return create_app(s, providers=providers or make_providers(), fetcher_factory=fetcher_factory, policy=loopback_policy if loopback else None)

    return build


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        yield c
