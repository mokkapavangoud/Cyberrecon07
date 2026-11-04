"""IP address policy: only globally routable, public unicast addresses are allowed.

The deny-list is explicit (rather than relying only on ``ipaddress.is_global``) so the
behaviour is documented, testable and stable across Python versions.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

_V4_BLOCKED = [
    "0.0.0.0/8",  # "this network"
    "10.0.0.0/8",  # RFC1918
    "100.64.0.0/10",  # CGNAT
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local, includes cloud metadata 169.254.169.254
    "172.16.0.0/12",  # RFC1918
    "192.0.0.0/24",  # IETF protocol assignments
    "192.0.2.0/24",  # TEST-NET-1
    "192.88.99.0/24",  # 6to4 relay (deprecated)
    "192.168.0.0/16",  # RFC1918
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",  # TEST-NET-3
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved
    "255.255.255.255/32",  # broadcast
]
_V6_BLOCKED = [
    "::/128",  # unspecified
    "::1/128",  # loopback
    "64:ff9b::/96",  # NAT64 (embeds IPv4)
    "64:ff9b:1::/48",  # local-use NAT64
    "100::/64",  # discard-only
    "2001::/32",  # Teredo
    "2001:10::/28",  # deprecated ORCHID
    "2001:db8::/32",  # documentation
    "2002::/16",  # 6to4 (embeds IPv4)
    "fc00::/7",  # unique local
    "fe80::/10",  # link-local
    "fec0::/10",  # deprecated site-local
    "ff00::/12",  # multicast
]

BLOCKED_V4 = [ipaddress.ip_network(n) for n in _V4_BLOCKED]
BLOCKED_V6 = [ipaddress.ip_network(n) for n in _V6_BLOCKED]

METADATA_ADDRESSES = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal, dropping any IPv6 zone id. Returns None if not an IP."""
    value = value.strip().strip("[]")
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def block_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a human-readable reason if the address is not allowed, else None."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
    if str(ip) in METADATA_ADDRESSES:
        return "cloud metadata endpoint"
    networks = BLOCKED_V4 if ip.version == 4 else BLOCKED_V6
    for net in networks:
        if ip in net:
            return f"reserved or non-public range ({net})"
    if not ip.is_global:
        return "not a globally routable address"
    return None


@dataclass(frozen=True)
class IPPolicy:
    """Policy object. ``allow_private`` exists ONLY so tests can talk to local fixtures."""

    allow_private: bool = False

    def reason(self, ip_str: str) -> str | None:
        ip = parse_ip(ip_str)
        if ip is None:
            return "not a valid IP address"
        if self.allow_private:
            return None
        return block_reason(ip)

    def is_allowed(self, ip_str: str) -> bool:
        return self.reason(ip_str) is None
