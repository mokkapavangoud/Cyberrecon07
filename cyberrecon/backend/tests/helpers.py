from app.security.safe_net import ResolutionError


def fake_resolver(mapping):
    async def _r(host, port):
        if host not in mapping:
            raise ResolutionError(f"DNS lookup failed for {host}: Name or service not known")
        value = mapping[host]
        return list(value() if callable(value) else value)

    return _r


DEFAULT_MAP = {
    "site.example.org": ["127.0.0.1"],
    "blog.site.example.org": ["127.0.0.1"],
    "internal-host.example.org": ["10.0.0.5"],
}


# ------------------------------------------------------------------ fake providers for the infrastructure module
from datetime import datetime, timedelta, timezone  # noqa: E402

from app.integrations.registry import ProviderUnavailable, Providers  # noqa: E402

NOW = "2026-10-25T08:00:00+00:00"


def dns_rec(name, rtype, values=None, status="ok", error=None):
    vals = [{"value": v, "ttl": 300} for v in (values or [])]
    if values and status == "ok":
        pass
    elif not values and status == "ok":
        status = "no_answer"
    return {"type": rtype, "name": name, "status": status, "values": vals, "error": error, "queried_at": NOW}


class FakeDns:
    resolver_label = "fake-resolver (10.255.255.1)"
    name = "fake"

    def __init__(self, zone=None, default_status="no_answer", fail_all=None):
        self.zone = zone or {}
        self.default_status = default_status
        self.fail_all = fail_all  # "timeout" | "error"
        self.calls = []

    async def lookup(self, name, rtype):
        self.calls.append((name, rtype))
        if self.fail_all:
            return dns_rec(name, rtype, status=self.fail_all, error="simulated network failure")
        if (name, rtype) in self.zone:
            v = self.zone[(name, rtype)]
            if isinstance(v, dict):
                return dns_rec(name, rtype, **v)
            return dns_rec(name, rtype, v)
        if any(n == name for n, _ in self.zone) or name.endswith("example-corp.org"):
            return dns_rec(name, rtype, status="no_answer")
        return dns_rec(name, rtype, status="nxdomain", error="The domain name does not exist (NXDOMAIN).")

    async def lookup_many(self, name, types=None):
        return [await self.lookup(name, t) for t in (types or ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"])]

    async def reverse(self, ip):
        return await self.lookup(f"rev.{ip}", "PTR")


class FakeRdap:
    name = "fake-rdap"

    def __init__(self, domain=None, ip=None, fail=None):
        self.domain, self.ip, self.fail = domain, ip, fail
        self.ip_calls = []

    async def lookup_domain(self, host):
        if self.fail:
            raise ProviderUnavailable(self.fail)
        return self.domain

    async def lookup_ip(self, ip):
        self.ip_calls.append(ip)
        if self.fail:
            raise ProviderUnavailable(self.fail)
        return self.ip or {"status": "not_found"}


class FakeAsn:
    name = "fake-asn"
    reference = "https://example.invalid/asn"

    def __init__(self, table=None, fail=None):
        self.table, self.fail = table or {}, fail
        self.calls = []

    async def lookup(self, ip):
        self.calls.append(ip)
        if self.fail:
            raise ProviderUnavailable(self.fail)
        return self.table.get(ip, {"asn": None})


class FakeGeo:
    name = "fake-geo"

    def __init__(self, result=None, reason="No GeoIP provider is configured."):
        self.result, self.reason = result, reason

    async def lookup(self, ip):
        if self.result is None:
            raise ProviderUnavailable(self.reason)
        return self.result


class FakeTls:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def probe(self, host, port=443):
        self.calls.append((host, port))
        return self.result


class FakeSubs:
    def __init__(self, names=None, fail=None, provider="fake-ct"):
        self.names, self.fail, self.provider = names or [], fail, provider

    async def fetch(self, domain):
        if self.fail:
            raise ProviderUnavailable(self.fail)
        return {"provider": self.provider, "reference": "https://example.invalid/ct", "basis": "Reported names.",
                "items": [{"name": n} for n in self.names], "total_reported": len(self.names), "truncated": False}


def good_tls(host="www.example-corp.org", **over):
    base = {
        "status": "ok", "port": 443, "connected_ip": "93.184.216.34", "verification": {"ok": True, "error": None}, "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384", "subject_cn": host, "subject_org": None, "issuer_cn": "R11", "issuer_org": "Let's Encrypt",
        "issuer_country": "US", "not_before": "2026-09-01T00:00:00+00:00", "not_after": "2026-12-01T00:00:00+00:00", "days_remaining": 37,
        "expired": False, "not_yet_valid": False, "san": [host, "example-corp.org", "api.example-corp.org"], "san_count": 3, "serial": "abc123",
        "signature_hash": "sha256", "public_key": {"type": "RSA", "bits": 2048}, "fingerprint_sha256": "ab" * 32, "self_signed": False, "hostname_match": True,
    }
    base.update(over)
    return base


ZONE = {
    ("www.example-corp.org", "A"): ["93.184.216.34"],
    ("www.example-corp.org", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
    ("www.example-corp.org", "CNAME"): ["edge.cdn-provider.net"],
    ("example-corp.org", "NS"): ["ns1.example-corp.org", "ns2.example-corp.org"],
    ("example-corp.org", "MX"): ["10 mail.example-corp.org"],
    ("example-corp.org", "TXT"): ["v=spf1 include:_spf.example-corp.org ~all", "site-verification=abc"],
    ("_dmarc.example-corp.org", "TXT"): ["v=DMARC1; p=none"],
}
ASN_TABLE = {
    "93.184.216.34": {"asn": 64496, "all_asns": [64496], "prefix": "93.184.216.0/24", "country": "US", "registry": "arin", "allocated": "2008-06-02", "name": "EXAMPLE-NET, US"},
    "2606:2800:220:1:248:1893:25c8:1946": {"asn": 64496, "all_asns": [64496], "prefix": "2606:2800::/32", "country": "US", "registry": "arin", "allocated": "2008-06-02", "name": "EXAMPLE-NET, US"},
}
REG = {"status": "found", "source": "https://rdap.example.invalid/domain/example-corp.org", "queried_domain": "example-corp.org", "domain": "example-corp.org",
       "registrar": "Example Registrar, Inc.", "registrar_iana_id": "9999", "created": "2015-03-01T00:00:00Z",
       "expires": (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ"), "updated": "2026-01-01T00:00:00Z",
       "domain_status": ["client transfer prohibited"], "nameservers": ["ns1.example-corp.org", "ns2.example-corp.org"], "registrant_org": None, "registrant_redacted": True}


def make_providers(**over):
    p = dict(
        dns=FakeDns(ZONE), rdap=FakeRdap(REG, {"status": "found", "name": "EXAMPLE-NET", "handle": "NET-93-184-216-0-1", "country": "US", "organizations": ["Example Hosting"]}),
        asn=FakeAsn(ASN_TABLE), geoip=FakeGeo(), subdomains=FakeSubs(), tls=FakeTls(good_tls()), screenshots=None,
    )
    p.update(over)
    return Providers(**p)
