"""Approximate IP geolocation. Always an ESTIMATE; never evidence of a person's physical location."""
from __future__ import annotations

import json

from app.security.safe_net import FetchError
from app.security.target import TargetError

from .registry import ProviderUnavailable

DISCLAIMER = ("IP geolocation is a statistical estimate, usually accurate to country or region level only. "
              "It reflects where an address is registered or routed, not where any person is.")


class NullGeoProvider:
    name = "GeoIP (not configured)"

    def __init__(self, reason: str):
        self.reason = reason

    async def lookup(self, ip: str) -> dict:
        raise ProviderUnavailable(self.reason)


class IpapiCoProvider:
    name = "ipapi.co"
    reference = "https://ipapi.co/api/"

    def __init__(self, settings, fetcher_factory):
        self.fetcher_factory = fetcher_factory

    async def lookup(self, ip: str) -> dict:
        fetcher = self.fetcher_factory()
        try:
            res = await fetcher.fetch(f"https://ipapi.co/{ip}/json/", max_bytes=100_000, accept="application/json")
        except (FetchError, TargetError) as exc:
            raise ProviderUnavailable(f"ipapi.co request failed: {getattr(exc, 'message', exc)}")
        finally:
            await fetcher.aclose()
        if res.status == 429:
            raise ProviderUnavailable("ipapi.co rate limit reached.")
        if res.status != 200:
            raise ProviderUnavailable(f"ipapi.co returned HTTP {res.status}.")
        try:
            d = json.loads(res.body)
        except ValueError:
            raise ProviderUnavailable("ipapi.co returned invalid JSON.")
        if d.get("error"):
            raise ProviderUnavailable(f"ipapi.co: {d.get('reason', 'error')}")
        return {"country": d.get("country_name"), "country_code": d.get("country_code"), "region": d.get("region"), "city": d.get("city"),
                "latitude": d.get("latitude"), "longitude": d.get("longitude"), "organization": d.get("org"), "provider": self.name,
                "estimate": True, "note": DISCLAIMER}


class MaxMindProvider:
    name = "MaxMind GeoLite2 (local database)"
    reference = "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"

    def __init__(self, path: str):
        try:
            import maxminddb  # optional dependency
        except ImportError:
            raise ProviderUnavailable("The 'maxminddb' package is not installed.")
        try:
            self.reader = maxminddb.open_database(path)
        except Exception as exc:
            raise ProviderUnavailable(f"Could not open GeoIP database: {exc}")

    async def lookup(self, ip: str) -> dict:
        rec = self.reader.get(ip)
        if not rec:
            raise ProviderUnavailable("The address is not present in the GeoIP database.")
        loc = rec.get("location", {})
        return {"country": rec.get("country", {}).get("names", {}).get("en"), "country_code": rec.get("country", {}).get("iso_code"),
                "region": (rec.get("subdivisions") or [{}])[0].get("names", {}).get("en"), "city": rec.get("city", {}).get("names", {}).get("en"),
                "latitude": loc.get("latitude"), "longitude": loc.get("longitude"), "accuracy_radius_km": loc.get("accuracy_radius"),
                "provider": self.name, "estimate": True, "note": DISCLAIMER}


def build_geoip_provider(settings, fetcher_factory):
    choice = (settings.geoip_provider or "none").lower()
    if choice == "ipapi":
        return IpapiCoProvider(settings, fetcher_factory)
    if choice == "maxmind":
        if not settings.geoip_db_path:
            return NullGeoProvider("GeoIP provider 'maxmind' selected but CYBERRECON_GEOIP_DB_PATH is not set.")
        try:
            return MaxMindProvider(settings.geoip_db_path)
        except ProviderUnavailable as exc:
            return NullGeoProvider(str(exc))
    return NullGeoProvider("No GeoIP provider is configured. Set CYBERRECON_GEOIP_PROVIDER to 'ipapi' or 'maxmind' (see docs/INTEGRATIONS.md).")
