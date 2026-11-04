"""Target parsing and normalisation. Every user-supplied (or redirect-supplied) URL passes here."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .ip_policy import IPPolicy, parse_ip

MAX_URL_LENGTH = 2048
_UNSUPPORTED_SCHEMES = re.compile(
    r"^(javascript|data|file|vbscript|ftp|ftps|gopher|ws|wss|mailto|tel|about|blob|jar|dict|ldap|sftp|ssh|telnet)\s*:",
    re.I,
)
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_NUMERIC_LABEL = re.compile(r"^(0[xX][0-9a-fA-F]*|\d+)$")
_NON_PUBLIC_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home", "corp", "intranet", "private",
    "home.arpa", "arpa", "invalid", "test", "example", "onion",
)
DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetError(ValueError):
    """Raised when a target is syntactically invalid or prohibited. ``code`` is machine readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Target:
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    is_ip_literal: bool

    @property
    def url(self) -> str:
        netloc = self.hostname
        if self.is_ip_literal and ":" in self.hostname:
            netloc = f"[{self.hostname}]"
        if self.port != DEFAULT_PORTS[self.scheme]:
            netloc = f"{netloc}:{self.port}"
        return urlunsplit((self.scheme, netloc, self.path or "/", self.query, ""))

    @property
    def origin(self) -> str:
        netloc = f"[{self.hostname}]" if self.is_ip_literal and ":" in self.hostname else self.hostname
        if self.port != DEFAULT_PORTS[self.scheme]:
            netloc = f"{netloc}:{self.port}"
        return f"{self.scheme}://{netloc}"


def host_in_allowlist(hostname: str, allowlist: list[str] | tuple[str, ...]) -> bool:
    if not allowlist:
        return True
    h = hostname.lower().rstrip(".")
    for entry in allowlist:
        e = entry.lower().strip().lstrip("*.").rstrip(".")
        if h == e or h.endswith("." + e):
            return True
    return False


def same_site(a: str, b: str) -> bool:
    """Scope check used for redirects: same host, www-variant, or parent/child domain."""
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    strip = lambda h: h[4:] if h.startswith("www.") else h  # noqa: E731
    a, b = strip(a), strip(b)
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def normalise_hostname(host: str, *, allow_single_label: bool = False) -> tuple[str, bool]:
    """Validate and normalise a hostname or IP literal. Returns (hostname, is_ip_literal)."""
    if not host:
        raise TargetError("invalid_host", "The target has no hostname.")
    raw = host.strip().strip("[]")
    ip = parse_ip(raw)
    if ip is not None:
        return str(ip), True

    host = host.strip().rstrip(".").lower()
    if len(host) > 253:
        raise TargetError("invalid_host", "Hostname is too long.")

    labels = host.split(".")
    # Reject ambiguous numeric forms (2130706433, 0x7f.1, 127.1, 0177.0.0.1) – some stacks read them as IPv4.
    if all(_NUMERIC_LABEL.match(lab) for lab in labels if lab != ""):
        raise TargetError("ambiguous_ip", "Numeric host forms other than a standard dotted IPv4 address are not accepted.")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetError("invalid_host", "Hostname contains invalid characters.")
    labels = ascii_host.split(".")
    if any(not _LABEL_RE.match(lab) for lab in labels):
        raise TargetError("invalid_host", "Hostname contains invalid characters.")
    if len(labels) < 2 and not allow_single_label:
        raise TargetError("non_public_name", "Single-label hostnames are not publicly resolvable and are not accepted.")
    for suffix in _NON_PUBLIC_SUFFIXES:
        if ascii_host == suffix or ascii_host.endswith("." + suffix):
            raise TargetError("non_public_name", f"Names under '.{suffix}' are not public internet targets.")
    return ascii_host, False


def parse_target(
    raw: str,
    *,
    allowed_ports: list[int] | tuple[int, ...] = (80, 443, 8080, 8443),
    allowlist: list[str] | tuple[str, ...] = (),
    policy: IPPolicy | None = None,
) -> Target:
    """Parse a URL, domain or hostname into a validated :class:`Target`.

    This performs *syntactic* validation and literal-IP checks. DNS answers are validated
    separately, at connection time, by the guarded network backend.
    """
    policy = policy or IPPolicy()
    if raw is None:
        raise TargetError("empty_target", "Enter a URL, domain or hostname.")
    value = raw.strip()
    if not value:
        raise TargetError("empty_target", "Enter a URL, domain or hostname.")
    if len(value) > MAX_URL_LENGTH:
        raise TargetError("too_long", "The target is too long.")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) or re.search(r"\s", value):
        raise TargetError("invalid_characters", "The target contains whitespace or control characters.")
    if "\\" in value:
        raise TargetError("invalid_characters", "Backslashes are not allowed in targets.")

    if "://" not in value:
        if _UNSUPPORTED_SCHEMES.match(value):
            raise TargetError("unsupported_scheme", "Only http and https targets are supported.")
        value = "https://" + value

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise TargetError("invalid_url", "The URL could not be parsed.")

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetError("unsupported_scheme", "Only http and https targets are supported.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetError("credentials_in_url", "URLs containing credentials are not accepted.")
    if not parts.hostname:
        raise TargetError("invalid_host", "The target has no hostname.")

    hostname, is_ip = normalise_hostname(parts.hostname)
    if is_ip:
        reason = policy.reason(hostname)
        if reason:
            raise TargetError("blocked_address", f"{hostname} is not allowed: {reason}.")

    port = port or DEFAULT_PORTS[scheme]
    if port not in allowed_ports:
        raise TargetError("port_not_allowed", f"Port {port} is not permitted. Allowed ports: {', '.join(map(str, allowed_ports))}.")

    if not host_in_allowlist(hostname, allowlist):
        raise TargetError("out_of_scope", f"{hostname} is not in the configured assessment allowlist.")

    path = parts.path or "/"
    return Target(scheme=scheme, hostname=hostname, port=port, path=path, query=parts.query, is_ip_literal=is_ip)


def parse_domain_target(
    raw: str,
    *,
    allowlist: list[str] | tuple[str, ...] = (),
    policy: IPPolicy | None = None,
    allow_ip: bool = True,
) -> tuple[str, bool]:
    """Parse input for the infrastructure module. Accepts a domain, hostname, URL or IP.

    Returns ``(hostname, is_ip_literal)``.
    """
    t = parse_target(raw, allowed_ports=(80, 443, 8080, 8443), allowlist=allowlist, policy=policy)
    if t.is_ip_literal and not allow_ip:
        raise TargetError("ip_not_supported", "A domain name is required for this module.")
    return t.hostname, t.is_ip_literal


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False
