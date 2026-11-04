"""RDAP (the structured successor to WHOIS) via the IANA bootstrap registry. No API key."""
from __future__ import annotations

import json
import time

import tldextract

from app.security.safe_net import FetchError
from app.security.target import TargetError

from .registry import ProviderUnavailable

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled suffix list, no network
_REDACTED = ("redacted", "privacy", "withheld", "not disclosed", "data protected")


def registrable_domain(host: str) -> str | None:
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None


def _vcard_value(entity: dict, key: str) -> str | None:
    arr = entity.get("vcardArray")
    if not arr or len(arr) < 2:
        return None
    for item in arr[1]:
        if item and item[0] == key and len(item) >= 4:
            v = item[3]
            return v if isinstance(v, str) else None
    return None


def _is_redacted(v: str | None) -> bool:
    return bool(v) and any(w in v.lower() for w in _REDACTED)


def parse_rdap_domain(doc: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events", []) if e.get("eventAction")}
    registrar, iana_id, registrant_org = None, None, None
    redacted = False
    for ent in doc.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            registrar = _vcard_value(ent, "fn") or _vcard_value(ent, "org")
            for pid in ent.get("publicIds", []):
                if "iana" in pid.get("type", "").lower():
                    iana_id = pid.get("identifier")
        if "registrant" in roles:
            org = _vcard_value(ent, "org") or _vcard_value(ent, "fn")
            if _is_redacted(org) or not org:
                redacted = True
            else:
                registrant_org = org
    if not registrant_org and doc.get("remarks"):
        redacted = redacted or any(_is_redacted(json.dumps(r)) for r in doc["remarks"])
    ns = sorted({(n.get("ldhName") or "").lower() for n in doc.get("nameservers", []) if n.get("ldhName")})
    return {
        "domain": (doc.get("ldhName") or "").lower() or None,
        "registrar": registrar, "registrar_iana_id": iana_id,
        "created": events.get("registration"), "expires": events.get("expiration"),
        "updated": events.get("last changed"), "rdap_updated": events.get("last update of RDAP database"),
        "domain_status": doc.get("status", []), "nameservers": ns,
        "registrant_org": registrant_org, "registrant_redacted": redacted or registrant_org is None,
    }


class RdapProvider:
    name = "RDAP"
    reference = "https://about.rdap.org/"

    def __init__(self, settings, fetcher_factory):
        self.settings = settings
        self.fetcher_factory = fetcher_factory
        self._bootstrap: tuple[float, dict] | None = None

    async def _get_json(self, fetcher, url: str):
        try:
            res = await fetcher.fetch(url, max_bytes=800_000, accept="application/rdap+json, application/json;q=0.9")
        except (FetchError, TargetError) as exc:
            raise ProviderUnavailable(f"RDAP request failed: {getattr(exc, 'message', exc)}")
        return res

    async def _base_for_tld(self, fetcher, tld: str) -> str:
        if not self._bootstrap or time.time() - self._bootstrap[0] > 86_400:
            res = await self._get_json(fetcher, BOOTSTRAP_URL)
            if res.status != 200:
                raise ProviderUnavailable(f"IANA RDAP bootstrap returned HTTP {res.status}.")
            self._bootstrap = (time.time(), json.loads(res.body))
        for tlds, urls in self._bootstrap[1].get("services", []):
            if tld.lower() in tlds and urls:
                return next((u for u in urls if u.startswith("https://")), urls[0]).rstrip("/") + "/"
        raise ProviderUnavailable(f"No RDAP service is registered for .{tld}.")

    async def lookup_domain(self, hostname: str) -> dict:
        domain = registrable_domain(hostname)
        if not domain:
            raise ProviderUnavailable("Could not determine a registrable domain for this name.")
        fetcher = self.fetcher_factory()
        try:
            base = await self._base_for_tld(fetcher, domain.rsplit(".", 1)[-1])
            url = f"{base}domain/{domain}"
            res = await self._get_json(fetcher, url)
            if res.status == 404:
                return {"status": "not_found", "source": url, "domain": domain, "message": "The registry reports no registration for this domain."}
            if res.status != 200:
                raise ProviderUnavailable(f"RDAP server returned HTTP {res.status}.")
            try:
                doc = json.loads(res.body)
            except ValueError:
                raise ProviderUnavailable("RDAP server returned invalid JSON.")
            return {"status": "found", "source": url, "queried_domain": domain, **parse_rdap_domain(doc)}
        finally:
            await fetcher.aclose()

    async def lookup_ip(self, ip: str) -> dict:
        fetcher = self.fetcher_factory()
        try:
            url = f"https://rdap.org/ip/{ip}"
            res = await self._get_json(fetcher, url)
            if res.status == 404:
                return {"status": "not_found", "source": url}
            if res.status != 200:
                raise ProviderUnavailable(f"RDAP returned HTTP {res.status}.")
            doc = json.loads(res.body)
            orgs = []
            for ent in doc.get("entities", []):
                fn = _vcard_value(ent, "fn") or _vcard_value(ent, "org")
                if fn and not _is_redacted(fn):
                    orgs.append(fn)
            return {"status": "found", "source": url, "name": doc.get("name"), "handle": doc.get("handle"), "country": doc.get("country"),
                    "start": doc.get("startAddress"), "end": doc.get("endAddress"), "type": doc.get("type"), "organizations": orgs[:5]}
        finally:
            await fetcher.aclose()
