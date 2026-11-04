"""DNS lookups through dnspython. Every answer records status, TTL, time and the resolver used."""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import dns.reversename

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
MAX_VALUES = 50


def _fmt(rtype: str, rdata) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype in ("NS", "CNAME", "PTR"):
        return rdata.target.to_text().rstrip(".")
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")[:1000]
    if rtype == "SOA":
        return f"{rdata.mname.to_text().rstrip('.')} {rdata.rname.to_text().rstrip('.')} serial={rdata.serial}"
    if rtype == "CAA":
        return f"{rdata.flags} {rdata.tag.decode()} {rdata.value.decode('utf-8', 'replace')}"
    return rdata.to_text()


class DnsPythonProvider:
    name = "dnspython"

    def __init__(self, settings):
        self.timeout = settings.dns_timeout
        self.nameservers = list(settings.dns_resolvers)

    def _resolver(self) -> dns.asyncresolver.Resolver:
        try:
            r = dns.asyncresolver.Resolver(configure=not self.nameservers)
        except dns.resolver.NoResolverConfiguration:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = ["1.1.1.1", "9.9.9.9"]
        if self.nameservers:
            r.nameservers = self.nameservers
        r.timeout = self.timeout
        r.lifetime = self.timeout * 1.5
        return r

    @property
    def resolver_label(self) -> str:
        if self.nameservers:
            return ", ".join(self.nameservers)
        try:
            return "system resolver (" + ", ".join(dns.asyncresolver.Resolver().nameservers[:2]) + ")"
        except Exception:
            return "system resolver"

    async def lookup(self, name: str, rtype: str) -> dict:
        queried = datetime.now(timezone.utc).isoformat(timespec="seconds")
        base = {"type": rtype, "name": name, "queried_at": queried, "values": [], "error": None}
        try:
            ans = await self._resolver().resolve(name, rtype, raise_on_no_answer=True)
            values = [{"value": _fmt(rtype, r), "ttl": ans.rrset.ttl} for r in ans][:MAX_VALUES]
            return {**base, "status": "ok", "values": values}
        except dns.resolver.NoAnswer:
            return {**base, "status": "no_answer"}
        except dns.resolver.NXDOMAIN:
            return {**base, "status": "nxdomain", "error": "The domain name does not exist (NXDOMAIN)."}
        except dns.resolver.NoNameservers:
            return {**base, "status": "error", "error": "All nameservers failed (SERVFAIL/refused)."}
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return {**base, "status": "timeout", "error": "The DNS query timed out."}
        except dns.name.LabelTooLong:
            return {**base, "status": "error", "error": "Invalid DNS label."}
        except Exception as exc:  # network unreachable, etc.
            return {**base, "status": "error", "error": f"{type(exc).__name__}: {str(exc)[:160]}"}

    async def lookup_many(self, name: str, types: list[str] | None = None) -> list[dict]:
        return list(await asyncio.gather(*(self.lookup(name, t) for t in (types or RECORD_TYPES))))

    async def reverse(self, ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"type": "PTR", "name": ip, "status": "error", "error": "Invalid IP", "values": [], "queried_at": None}
        return await self.lookup(dns.reversename.from_address(ip).to_text(), "PTR")
