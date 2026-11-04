"""Provider registry: every external data source sits behind an interface so it can be swapped or mocked."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.config import Settings


class ProviderUnavailable(Exception):
    """Raised when a provider cannot be used (missing key, library or file). Shown as 'unavailable', never faked."""


@dataclass
class Providers:
    dns: Any
    rdap: Any
    asn: Any
    geoip: Any
    subdomains: Any
    tls: Any
    screenshots: Any
    extra: dict = field(default_factory=dict)


def build_default_providers(settings: Settings, *, fetcher_factory) -> Providers:
    from .dns_provider import DnsPythonProvider
    from .geoip import build_geoip_provider
    from .rdap import RdapProvider
    from .asn import CymruAsnProvider
    from .screenshots import PlaywrightScreenshotProvider
    from .subdomains import build_subdomain_provider
    from .tls import TlsProbe

    dns = DnsPythonProvider(settings)
    return Providers(
        dns=dns,
        rdap=RdapProvider(settings, fetcher_factory=fetcher_factory),
        asn=CymruAsnProvider(settings, dns=dns),
        geoip=build_geoip_provider(settings, fetcher_factory=fetcher_factory),
        subdomains=build_subdomain_provider(settings, fetcher_factory=fetcher_factory),
        tls=TlsProbe(settings),
        screenshots=PlaywrightScreenshotProvider(settings),
    )
