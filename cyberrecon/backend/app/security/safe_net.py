"""Guarded outbound networking.

Design notes
------------
* DNS is resolved *inside* the network backend that opens the socket. The addresses are validated
  and the connection is made to one of those validated addresses in the same step, so there is no
  window between "check" and "use" in which a DNS rebinding answer could be swapped in.
* If ANY address in a DNS answer is non-public the whole lookup is rejected (mixed answers are a
  classic bypass).
* Redirects are followed manually; every hop is re-parsed by ``parse_target`` and re-resolved.
* This is application-level defence in depth. It does not replace network-level egress controls
  (see docs/SECURITY.md).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urljoin

import httpcore
import httpx

from app.core.config import Settings

from .ip_policy import IPPolicy, parse_ip
from .target import Target, TargetError, parse_target, same_site

Resolver = Callable[[str, int], Awaitable[list[str]]]


class BlockedTargetError(Exception):
    code = "blocked_target"


class ResolutionError(Exception):
    code = "dns_failure"


class FetchError(Exception):
    """Network-level failure with a stable, user-presentable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolutionError(f"DNS lookup failed for {host}: {exc.strerror or exc}") from exc
    seen: list[str] = []
    for _fam, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0].split("%", 1)[0]
        if ip not in seen:
            seen.append(ip)
    return seen


async def resolve_public(host: str, port: int, resolver: Resolver, policy: IPPolicy) -> list[str]:
    """Resolve ``host`` and return addresses only if ALL of them satisfy the policy."""
    if parse_ip(host) is not None:
        ips = [host.strip("[]")]
    else:
        ips = await resolver(host, port)
    if not ips:
        raise ResolutionError(f"No addresses found for {host}.")
    for ip in ips:
        reason = policy.reason(ip)
        if reason:
            raise BlockedTargetError(f"{host} resolves to {ip}, which is blocked ({reason}).")
    return ips


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """httpcore backend that resolves + validates + connects atomically."""

    def __init__(self, resolver: Resolver, policy: IPPolicy, *, inner: httpcore.AsyncNetworkBackend | None = None):
        self._resolver = resolver
        self._policy = policy
        self._inner = inner or httpcore.AnyIOBackend()
        self.connections: list[tuple[str, str, int]] = []  # (host, ip, port) – useful for tests/audit

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ips = await resolve_public(host, port, self._resolver, self._policy)
        last_exc: Exception | None = None
        for ip in ips:
            try:
                stream = await self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
                self.connections.append((host, ip, port))
                return stream
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise BlockedTargetError("Unix sockets are not permitted.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def build_transport(backend: GuardedNetworkBackend, *, max_connections: int = 10) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connection pool uses the guarded backend.

    httpx does not expose ``network_backend`` publicly, so the pool is swapped after construction.
    ``tests/test_safe_net.py`` asserts this wiring so a future httpx upgrade cannot silently break it.
    """
    ctx = httpx.create_ssl_context(verify=True, trust_env=False)
    transport = httpx.AsyncHTTPTransport(verify=ctx, retries=0)
    old_pool = transport._pool
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ctx,
        max_connections=max_connections,
        max_keepalive_connections=max_connections,
        keepalive_expiry=5.0,
        http1=True,
        http2=False,
        retries=0,
        network_backend=backend,
    )
    # old pool never opened a connection; nothing to close
    del old_pool
    return transport


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None = None
    followed: bool = False
    note: str | None = None


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    reason: str
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    elapsed_ms: int
    hops: list[Hop] = field(default_factory=list)
    remote_ip: str | None = None
    blocked_redirect: str | None = None  # set if a redirect was not followed (scope/validation)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


class SafeFetcher:
    """The only component that makes outbound HTTP requests on behalf of a user target."""

    def __init__(
        self,
        settings: Settings,
        *,
        resolver: Resolver | None = None,
        policy: IPPolicy | None = None,
        allowlist: list[str] | None = None,
    ):
        self.settings = settings
        self.policy = policy or IPPolicy()
        self.allowlist = settings.target_allowlist if allowlist is None else allowlist
        self.backend = GuardedNetworkBackend(resolver or system_resolver, self.policy)
        timeout = httpx.Timeout(
            connect=settings.http_connect_timeout,
            read=settings.http_read_timeout,
            write=settings.http_connect_timeout,
            pool=settings.http_connect_timeout,
        )
        self._client = httpx.AsyncClient(
            transport=build_transport(self.backend),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": settings.user_agent, "Accept-Language": "en"},
        )
        self.request_count = 0

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    def parse(self, url: str) -> Target:
        return parse_target(url, allowed_ports=self.settings.allowed_ports, allowlist=self.allowlist, policy=self.policy)

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        max_bytes: int | None = None,
        scope_host: str | None = None,
        follow_redirects: bool = True,
        max_redirects: int | None = None,
        accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
        extra_headers: dict[str, str] | None = None,
    ) -> FetchResult:
        """Fetch ``url`` safely. Raises :class:`FetchError` / :class:`TargetError`."""
        try:
            return await asyncio.wait_for(
                self._fetch(url, method, max_bytes, scope_host, follow_redirects, max_redirects, accept, extra_headers),
                timeout=self.settings.http_total_timeout,
            )
        except asyncio.TimeoutError:
            raise FetchError("timeout", "The request exceeded the total time limit.")

    async def _fetch(self, url, method, max_bytes, scope_host, follow_redirects, max_redirects, accept, extra_headers):
        max_bytes = max_bytes if max_bytes is not None else self.settings.max_response_bytes
        max_redirects = self.settings.max_redirects if max_redirects is None else min(max_redirects, self.settings.max_redirects)
        hops: list[Hop] = []
        current = self.parse(url).url
        started = time.perf_counter()
        blocked_redirect: str | None = None

        for _ in range(max_redirects + 1):
            target = self.parse(current)  # re-validate EVERY hop
            headers = {"Accept": accept}
            if extra_headers:
                headers.update(extra_headers)
            self.request_count += 1
            try:
                async with self._client.stream(method, target.url, headers=headers) as resp:
                    status = resp.status_code
                    location = resp.headers.get("location")
                    remote_ip = None
                    try:
                        ns = resp.extensions.get("network_stream")
                        info = ns.get_extra_info("server_addr") if ns else None
                        if info:
                            remote_ip = info[0]
                    except Exception:  # pragma: no cover
                        pass

                    is_redirect = status in (301, 302, 303, 307, 308) and location
                    if is_redirect:
                        nxt = urljoin(str(resp.url), location)
                        hop = Hop(url=target.url, status=status, location=nxt)
                        if not follow_redirects:
                            hop.note = "redirect not followed (disabled)"
                            hops.append(hop)
                            return self._result(url, target.url, resp, b"", False, started, hops, remote_ip, nxt)
                        try:
                            nxt_target = self.parse(nxt)
                        except TargetError as exc:
                            hop.note = f"redirect blocked: {exc.message}"
                            hops.append(hop)
                            return self._result(url, target.url, resp, b"", False, started, hops, remote_ip, nxt)
                        if scope_host and not same_site(scope_host, nxt_target.hostname):
                            hop.note = f"redirect to out-of-scope host {nxt_target.hostname} was not followed"
                            hops.append(hop)
                            return self._result(url, target.url, resp, b"", False, started, hops, remote_ip, nxt)
                        hop.followed = True
                        hops.append(hop)
                        current = nxt_target.url
                        continue

                    body = bytearray()
                    truncated = False
                    if method != "HEAD":
                        async for chunk in resp.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > max_bytes:
                                del body[max_bytes:]
                                truncated = True
                                break
                    hops.append(Hop(url=target.url, status=status))
                    return self._result(url, target.url, resp, bytes(body), truncated, started, hops, remote_ip, None)
            except BlockedTargetError as exc:
                raise FetchError("blocked_target", str(exc)) from exc
            except ResolutionError as exc:
                raise FetchError("dns_failure", str(exc)) from exc
            except httpx.ConnectTimeout:
                raise FetchError("connect_timeout", "Timed out while connecting to the target.")
            except httpx.ReadTimeout:
                raise FetchError("read_timeout", "The target took too long to respond.")
            except httpx.ConnectError as exc:
                cause = str(exc.__cause__ or exc)
                if isinstance(exc.__cause__, ssl.SSLError) or "CERTIFICATE" in cause.upper():
                    raise FetchError("tls_error", f"TLS error: {cause}")
                raise FetchError("unreachable", f"Could not connect to the target: {cause or 'connection failed'}")
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as exc:
                raise FetchError("protocol_error", f"The connection was interrupted: {exc}")
            except httpx.TooManyRedirects:  # pragma: no cover
                raise FetchError("too_many_redirects", "Too many redirects.")
        raise FetchError("too_many_redirects", f"Stopped after {max_redirects} redirects.")

    @staticmethod
    def _result(url, final_url, resp, body, truncated, started, hops, remote_ip, blocked_redirect) -> FetchResult:
        raw = [(k, v) for k, v in resp.headers.multi_items()]
        headers: dict[str, str] = {}
        for k, v in raw:
            k = k.lower()
            if k == "set-cookie":
                headers.setdefault(k, v)  # raw_headers keeps every cookie header
            elif k in headers:
                headers[k] = f"{headers[k]}, {v}"
            else:
                headers[k] = v
        return FetchResult(
            url=url,
            final_url=final_url,
            status=resp.status_code,
            reason=resp.reason_phrase,
            headers=headers,
            raw_headers=raw,
            body=body,
            truncated=truncated,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            hops=hops,
            remote_ip=remote_ip,
            blocked_redirect=blocked_redirect,
        )


async def open_guarded_tls(
    host: str,
    port: int,
    *,
    resolver: Resolver,
    policy: IPPolicy,
    verify: bool,
    timeout: float,
    server_hostname: str | None = None,
):
    """Open a TLS connection to a validated address. Returns (reader, writer, ip)."""
    ips = await resolve_public(host, port, resolver, policy)
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    last: Exception | None = None
    for ip in ips:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_hostname or host),
                timeout=timeout,
            )
            return reader, writer, ip
        except (OSError, asyncio.TimeoutError) as exc:
            last = exc
            if isinstance(exc, ssl.SSLCertVerificationError):
                raise
    assert last is not None
    raise last
