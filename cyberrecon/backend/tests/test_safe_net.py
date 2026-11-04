import asyncio

import httpcore
import pytest

from app.security.ip_policy import IPPolicy
from app.security.safe_net import (
    BlockedTargetError,
    FetchError,
    GuardedNetworkBackend,
    ResolutionError,
    SafeFetcher,
    resolve_public,
)
from app.security.target import TargetError

from .helpers import fake_resolver


# ---------------------------------------------------------------- resolution policy
async def test_resolution_rejects_private_answer():
    with pytest.raises(BlockedTargetError):
        await resolve_public("a.example.org", 80, fake_resolver({"a.example.org": ["10.0.0.4"]}), IPPolicy())


async def test_resolution_rejects_mixed_answers():
    r = fake_resolver({"a.example.org": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(BlockedTargetError):
        await resolve_public("a.example.org", 80, r, IPPolicy())


async def test_resolution_accepts_public_answers():
    r = fake_resolver({"a.example.org": ["93.184.216.34", "2606:4700:4700::1111"]})
    assert await resolve_public("a.example.org", 80, r, IPPolicy()) == ["93.184.216.34", "2606:4700:4700::1111"]


async def test_resolution_failure_is_reported():
    with pytest.raises(ResolutionError):
        await resolve_public("nope.example.org", 80, fake_resolver({}), IPPolicy())


# ---------------------------------------------------------------- DNS rebinding
class RecordingInner(httpcore.AsyncNetworkBackend):
    def __init__(self):
        self.calls = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append(host)
        raise httpcore.ConnectError("stub: not actually connecting")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise AssertionError

    async def sleep(self, seconds):
        await asyncio.sleep(0)


async def test_dns_rebinding_cannot_swap_address_between_check_and_connect():
    """Resolver answers public first, then private. Each connect resolves ONCE and connects to that
    validated IP literal – the hostname is never re-resolved by the socket layer."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"], ["93.184.216.34"]])
    resolver = fake_resolver({"rebind.example.org": lambda: next(answers)})
    inner = RecordingInner()
    backend = GuardedNetworkBackend(resolver, IPPolicy(), inner=inner)

    with pytest.raises(httpcore.ConnectError):  # public answer -> connection attempted to the IP literal
        await backend.connect_tcp("rebind.example.org", 80)
    assert inner.calls == ["93.184.216.34"]

    with pytest.raises(BlockedTargetError):  # rebound to loopback -> refused, inner untouched
        await backend.connect_tcp("rebind.example.org", 80)
    assert inner.calls == ["93.184.216.34"]


async def test_backend_refuses_unix_sockets():
    backend = GuardedNetworkBackend(fake_resolver({}), IPPolicy(), inner=RecordingInner())
    with pytest.raises(BlockedTargetError):
        await backend.connect_unix_socket("/var/run/docker.sock")


# ---------------------------------------------------------------- full fetcher against fixtures
def make_fetcher(settings, loopback_policy, mapping=None, **kw):
    mapping = {"site.example.org": ["127.0.0.1"], "internal-host.example.org": ["10.0.0.5"], **(mapping or {})}
    return SafeFetcher(settings, resolver=fake_resolver(mapping), policy=loopback_policy, **kw)


async def test_production_policy_never_touches_loopback_fixture(settings, server):
    async with SafeFetcher(settings) as f:
        with pytest.raises(TargetError) as exc:
            await f.fetch(f"{server.origin}/")
        assert exc.value.code == "blocked_address"
    assert server.requests == []


async def test_hostname_resolving_to_loopback_is_blocked_with_production_policy(settings, server):
    async with SafeFetcher(settings, resolver=fake_resolver({"site.example.org": ["127.0.0.1"]})) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch(f"http://site.example.org:{server.port}/")
        assert exc.value.code == "blocked_target"
    assert server.requests == []


async def test_successful_fetch_connects_to_validated_ip_and_sends_original_host(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/")
        assert res.status == 200
        assert b"Fixture" in res.body
        assert f.backend.connections[0][:2] == ("site.example.org", "127.0.0.1")
    assert server.requests[0][2].startswith("site.example.org")


async def test_redirect_to_metadata_endpoint_not_followed(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/redirect-private")
        assert res.status == 302
        assert res.blocked_redirect and "169.254.169.254" in res.blocked_redirect
        assert "blocked" in (res.hops[-1].note or "")
        assert len(f.backend.connections) == 1  # only the original host was ever contacted


async def test_redirect_to_hostname_resolving_private_is_blocked(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch(f"http://site.example.org:{server.port}/redirect-internal-name")
        assert exc.value.code == "blocked_target"


async def test_redirect_to_file_scheme_not_followed(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/redirect-file")
        assert res.status == 302 and not res.hops[-1].followed


async def test_out_of_scope_redirect_not_followed(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/redirect-offsite", scope_host="site.example.org")
        assert res.status == 302
        assert "out-of-scope" in res.hops[-1].note


async def test_same_site_redirect_is_followed(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/redirect-ok", scope_host="site.example.org")
        assert res.status == 200
        assert res.final_url.endswith("/about")
        assert [h.status for h in res.hops] == [301, 200]


async def test_redirect_loop_is_bounded(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch(f"http://site.example.org:{server.port}/redirect-loop")
        assert exc.value.code == "too_many_redirects"


async def test_response_size_limit_truncates(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/big", max_bytes=100_000)
        assert res.truncated and len(res.body) == 100_000


async def test_decompression_bomb_is_capped(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/gzip-bomb", max_bytes=200_000)
        assert res.truncated and len(res.body) == 200_000


async def test_read_timeout(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch(f"http://site.example.org:{server.port}/slow")
        assert exc.value.code in ("read_timeout", "timeout")


async def test_unresolvable_host_gives_dns_failure(settings, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch("https://does-not-exist.example.org/")
        assert exc.value.code == "dns_failure"


async def test_connection_refused_reported(settings, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        with pytest.raises(FetchError) as exc:
            await f.fetch("http://site.example.org:8080/")
        assert exc.value.code in ("unreachable", "connect_timeout")


async def test_allowlist_applies_to_every_hop(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy, allowlist=["site.example.org"]) as f:
        res = await f.fetch(f"http://site.example.org:{server.port}/redirect-offsite")
        assert "blocked" in res.hops[-1].note and "allowlist" in res.hops[-1].note


async def test_http_status_codes_are_returned_not_raised(settings, server, loopback_policy):
    async with make_fetcher(settings, loopback_policy) as f:
        r403 = await f.fetch(f"http://site.example.org:{server.port}/forbidden")
        r429 = await f.fetch(f"http://site.example.org:{server.port}/ratelimited")
        assert (r403.status, r429.status) == (403, 429)
        assert r429.headers["retry-after"] == "30"


def test_transport_uses_guarded_backend(settings):
    """Guards against an httpx upgrade silently bypassing the guarded network backend."""
    f = SafeFetcher(settings)
    pool = f._client._transport._pool
    assert pool._network_backend is f.backend
