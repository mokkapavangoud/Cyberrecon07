"""Passive subdomain intelligence providers. No brute forcing, no active scanning: data is only what a
third-party source *reports*. API keys stay on the backend."""
from __future__ import annotations

import json

from app.security.safe_net import FetchError
from app.security.target import TargetError

from .registry import ProviderUnavailable

MAX_ITEMS = 500


def _normalise(names, domain: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for n in names:
        n = n.strip().lower().lstrip("*.").rstrip(".")
        if not n or " " in n or not (n == domain or n.endswith("." + domain)):
            continue
        out.setdefault(n, {"name": n})
    return out


class DisabledSubdomains:
    name = "disabled"

    def __init__(self, reason="Passive subdomain lookup is disabled (CYBERRECON_SUBDOMAIN_PROVIDER=none)."):
        self.reason = reason

    async def fetch(self, domain: str) -> dict:
        raise ProviderUnavailable(self.reason)


class CrtShProvider:
    name = "crt.sh (Certificate Transparency logs)"
    reference = "https://crt.sh/"
    basis = "Hostnames that appeared in publicly logged TLS certificates. A name being logged does not prove it currently exists."

    def __init__(self, settings, fetcher_factory):
        self.fetcher_factory = fetcher_factory

    async def fetch(self, domain: str) -> dict:
        fetcher = self.fetcher_factory()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            res = await fetcher.fetch(url, max_bytes=3_000_000, accept="application/json")
        except (FetchError, TargetError) as exc:
            raise ProviderUnavailable(f"crt.sh request failed: {getattr(exc, 'message', exc)}")
        finally:
            await fetcher.aclose()
        if res.status != 200:
            raise ProviderUnavailable(f"crt.sh returned HTTP {res.status}.")
        text = res.body.decode("utf-8", "replace")
        try:
            rows = json.loads(text)
        except ValueError:
            if not res.truncated:
                raise ProviderUnavailable("crt.sh returned an unreadable response.")
            head = text.rsplit("},", 1)[0]  # response was cut at the size limit: salvage whole objects
            try:
                rows = json.loads(head + "}]")
            except ValueError:
                raise ProviderUnavailable("crt.sh response was too large to read within limits.")
        names: list[str] = []
        for r in rows:
            names.extend(str(r.get("name_value", "")).split("\n"))
        items = _normalise(names, domain)
        return {"provider": self.name, "reference": self.reference, "basis": self.basis, "items": list(items.values())[:MAX_ITEMS],
                "total_reported": len(items), "truncated": res.truncated or len(items) > MAX_ITEMS}


class SecurityTrailsProvider:
    name = "SecurityTrails"
    reference = "https://docs.securitytrails.com/reference/list-subdomains"
    basis = "Subdomains reported by SecurityTrails' passive DNS dataset."

    def __init__(self, settings, fetcher_factory):
        if not settings.securitytrails_api_key:
            raise ProviderUnavailable("SecurityTrails selected but CYBERRECON_SECURITYTRAILS_API_KEY is not set.")
        self._key = settings.securitytrails_api_key
        self.fetcher_factory = fetcher_factory

    async def fetch(self, domain: str) -> dict:
        fetcher = self.fetcher_factory()
        try:
            res = await fetcher.fetch(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=false",
                                      max_bytes=2_000_000, accept="application/json", extra_headers={"APIKEY": self._key})
        except (FetchError, TargetError) as exc:
            raise ProviderUnavailable(f"SecurityTrails request failed: {getattr(exc, 'message', exc)}")
        finally:
            await fetcher.aclose()
        if res.status in (401, 403):
            raise ProviderUnavailable("SecurityTrails rejected the API key.")
        if res.status == 429:
            raise ProviderUnavailable("SecurityTrails rate limit or quota reached.")
        if res.status != 200:
            raise ProviderUnavailable(f"SecurityTrails returned HTTP {res.status}.")
        try:
            labels = json.loads(res.body).get("subdomains", [])
        except ValueError:
            raise ProviderUnavailable("SecurityTrails returned invalid JSON.")
        items = _normalise([f"{l}.{domain}" for l in labels], domain)
        return {"provider": self.name, "reference": self.reference, "basis": self.basis, "items": list(items.values())[:MAX_ITEMS],
                "total_reported": len(items), "truncated": len(items) > MAX_ITEMS}


def build_subdomain_provider(settings, fetcher_factory):
    choice = (settings.subdomain_provider or "none").lower()
    if choice == "crtsh":
        return CrtShProvider(settings, fetcher_factory)
    if choice == "securitytrails":
        try:
            return SecurityTrailsProvider(settings, fetcher_factory)
        except ProviderUnavailable as exc:
            return DisabledSubdomains(str(exc))
    return DisabledSubdomains()
