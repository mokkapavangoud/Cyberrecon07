"""ASN / prefix lookups using Team Cymru's public IP-to-ASN DNS service (no API key)."""
from __future__ import annotations

import ipaddress

from .registry import ProviderUnavailable


def _origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _fields(txt: str) -> list[str]:
    return [p.strip() for p in txt.strip('"').split("|")]


class CymruAsnProvider:
    name = "Team Cymru IP-to-ASN (DNS)"
    reference = "https://www.team-cymru.com/ip-asn-mapping"

    def __init__(self, settings, dns):
        self.dns = dns

    async def lookup(self, ip: str) -> dict:
        ans = await self.dns.lookup(_origin_name(ip), "TXT")
        if ans["status"] != "ok" or not ans["values"]:
            if ans["status"] in ("timeout", "error"):
                raise ProviderUnavailable(f"ASN lookup failed: {ans['error']}")
            return {"asn": None, "note": "No origin ASN was announced for this address."}
        f = _fields(ans["values"][0]["value"])
        if len(f) < 3:
            raise ProviderUnavailable("Unexpected ASN service response.")
        asns = [a for a in f[0].split() if a.isdigit()]
        out = {"asn": int(asns[0]) if asns else None, "all_asns": [int(a) for a in asns], "prefix": f[1], "country": f[2] or None,
               "registry": f[3] if len(f) > 3 else None, "allocated": f[4] if len(f) > 4 else None, "name": None}
        if asns:
            name_ans = await self.dns.lookup(f"AS{asns[0]}.asn.cymru.com", "TXT")
            if name_ans["status"] == "ok" and name_ans["values"]:
                nf = _fields(name_ans["values"][0]["value"])
                out["name"] = nf[-1] if nf else None
        return out
