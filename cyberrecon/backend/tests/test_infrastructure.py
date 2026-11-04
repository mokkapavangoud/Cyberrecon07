import datetime as dt
import ipaddress
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.integrations.asn import CymruAsnProvider
from app.integrations.geoip import NullGeoProvider, build_geoip_provider
from app.integrations.rdap import RdapProvider, parse_rdap_domain, registrable_domain
from app.integrations.registry import ProviderUnavailable
from app.integrations.subdomains import CrtShProvider, DisabledSubdomains, SecurityTrailsProvider, build_subdomain_provider
from app.integrations.tls import TlsProbe, hostname_matches, parse_certificate
from app.security.safe_net import FetchError
from app.services.common import RunContext, StepTracker
from app.services.infrastructure import analyzer

from .helpers import ZONE, FakeAsn, FakeDns, FakeGeo, FakeRdap, FakeSubs, FakeTls, dns_rec, fake_resolver, good_tls, make_providers


def ctx(settings, fetcher_factory, providers):
    t = StepTracker(analyzer.STEPS, lambda s: None)
    return RunContext("i1", settings, t, fetcher_factory, providers), t


async def run(settings, fetcher_factory, providers, target="www.example-corp.org", options=None):
    c, t = ctx(settings, fetcher_factory, providers)
    out = await analyzer.run(c, {"target": target, "options": options or {"include_http": False}})
    return out, t


# ------------------------------------------------------------------ happy path + graph integrity
async def test_full_assessment_produces_evidence_backed_graph(settings, fetcher_factory):
    prov = make_providers(subdomains=FakeSubs(["api.example-corp.org", "old.example-corp.org"]))
    prov.dns.zone[("api.example-corp.org", "A")] = ["93.184.216.35"]
    out, t = await run(settings, fetcher_factory, prov)
    d = out.data
    assert out.status == "partial"  # geoip provider is unconfigured -> an unavailable source is reported, not hidden
    assert d["apex_domain"] == "example-corp.org" and d["hostname"] == "www.example-corp.org"
    g = d["graph"]
    ids = {n["id"] for n in g["nodes"]}
    assert {"domain:example-corp.org", "host:www.example-corp.org", "ip:93.184.216.34", "asn:64496", "sub:api.example-corp.org"} <= ids
    assert any(n["type"] == "certificate" for n in g["nodes"])
    # integrity: every edge has endpoints, evidence and a source – nothing invented
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids
        assert e["evidence"] and e["source_ref"]
    rel = {(e["source"], e["relation"], e["target"]) for e in g["edges"]}
    assert ("host:www.example-corp.org", "A", "ip:93.184.216.34") in rel
    assert ("ip:93.184.216.34", "announced_by", "asn:64496") in rel
    assert ("domain:example-corp.org", "NS", "dns:NS:ns1.example-corp.org") in rel
    assert any(r[1] == "serves_certificate" for r in rel)
    # subdomain verification state is explicit
    subs = {i["name"]: i for i in d["subdomains"]["items"]}
    assert subs["api.example-corp.org"]["verification"] == "dns_resolved" and subs["api.example-corp.org"]["resolves_to"] == ["93.184.216.35"]
    assert subs["old.example-corp.org"]["verification"] == "dns_unresolved"
    assert ("sub:api.example-corp.org", "A/AAAA", "ip:93.184.216.35") in rel
    assert [e for e in g["edges"] if e["target"] == "sub:old.example-corp.org"][0]["kind"] == "third_party"
    # step tracking reflects work performed
    assert {s["key"]: s["status"] for s in t.steps}["http"] == "skipped"
    assert all(s["status"] in ("done", "skipped") for s in t.steps)


async def test_findings_distinguish_observed_third_party_and_estimates(settings, fetcher_factory):
    geo = FakeGeo({"country": "United States", "country_code": "US", "region": "California", "city": "Los Angeles", "provider": "fake-geo", "estimate": True,
                   "note": "IP geolocation is a statistical estimate"})
    out, _ = await run(settings, fetcher_factory, make_providers(geoip=geo, subdomains=FakeSubs()))
    by_cat = {}
    for f in out.findings:
        by_cat.setdefault(f["category"], set()).add(f["evidence_type"])
    assert by_cat["dns"] == {"observed"} and by_cat["tls"] == {"observed"}
    assert by_cat["registration"] == {"third_party"}
    assert by_cat["geolocation"] == {"estimate"}
    assert any(f["category"] == "ip" and f["evidence_type"] == "third_party" and "AS64496" in f["title"] for f in out.findings)
    assert out.status == "completed"


async def test_email_security_findings(settings, fetcher_factory):
    zone = dict(ZONE)
    del zone[("_dmarc.example-corp.org", "TXT")]
    zone[("example-corp.org", "TXT")] = ["site-verification=abc"]
    out, _ = await run(settings, fetcher_factory, make_providers(dns=FakeDns(zone)))
    titles = [f["title"] for f in out.findings]
    assert "No SPF record observed" in titles and "No DMARC record observed" in titles


# ------------------------------------------------------------------ failure & unavailable states never fabricate data
async def test_nxdomain_is_a_clean_result(settings, fetcher_factory):
    out, _ = await run(settings, fetcher_factory, make_providers(dns=FakeDns({})), target="ghost.nonexistent-domain.org")
    assert any("NXDOMAIN" in f["title"] for f in out.findings)
    assert out.data["ips"] == []
    assert not [n for n in out.data["graph"]["nodes"] if n["type"] == "ip"]


async def test_total_dns_failure_fails_honestly_and_skips_dependents(settings, fetcher_factory):
    out, t = await run(settings, fetcher_factory, make_providers(dns=FakeDns(fail_all="timeout")))
    assert out.status == "failed" and out.errors[0]["code"] == "dns_unavailable"
    assert {s["key"]: s["status"] for s in t.steps}["tls"] == "skipped"
    assert out.data["ips"] == []


async def test_unavailable_providers_are_reported_with_reasons(settings, fetcher_factory):
    prov = make_providers(rdap=FakeRdap(fail="RDAP request failed: timeout"), asn=FakeAsn(fail="ASN lookup failed"),
                          subdomains=FakeSubs(fail="no API key"), tls=FakeTls({"status": "error", "port": 443, "error": "Could not connect on port 443: TimeoutError"}))
    out, _ = await run(settings, fetcher_factory, prov)
    assert out.status == "partial"
    d = out.data
    assert d["registration"] == {"status": "unavailable", "message": "RDAP request failed: timeout"}
    assert d["subdomains"]["status"] == "unavailable" and d["subdomains"]["items"] == []
    assert d["tls"]["status"] == "error"
    assert d["ips"][0]["asn"] is None and d["ips"][0]["asn_status"] == "unavailable"
    assert not [n for n in d["graph"]["nodes"] if n["type"] in ("asn", "certificate", "subdomain")]
    st = {s["name"]: s for s in out.sources}
    assert st["RDAP"]["status"] == "unavailable" and "timeout" in st["RDAP"]["detail"]
    assert st["Passive subdomain provider"]["detail"] == "no API key"


async def test_non_public_dns_answers_are_not_contacted(settings, fetcher_factory):
    zone = dict(ZONE)
    zone[("www.example-corp.org", "A")] = ["10.1.2.3", "93.184.216.34"]
    asn = FakeAsn({"93.184.216.34": {"asn": 64496, "prefix": "x", "name": "N"}})
    rdap = FakeRdap({"status": "found", "registrar": "R", "expires": None, "created": None, "domain_status": []}, {"status": "found"})
    out, _ = await run(settings, fetcher_factory, make_providers(dns=FakeDns(zone), asn=asn, rdap=rdap))
    assert "10.1.2.3" not in asn.calls and "10.1.2.3" not in rdap.ip_calls
    private = next(i for i in out.data["ips"] if i["ip"] == "10.1.2.3")
    assert private["public"] is False and "no lookups were made" in private["messages"]["skipped"]
    assert any("non-public address" in f["title"] for f in out.findings)


async def test_tls_findings_for_bad_certificates(settings, fetcher_factory):
    bad = good_tls(verification={"ok": False, "error": "self-signed certificate"}, expired=True, days_remaining=-3, self_signed=True, hostname_match=False,
                   public_key={"type": "RSA", "bits": 1024}, signature_hash="sha1")
    out, _ = await run(settings, fetcher_factory, make_providers(tls=FakeTls(bad)))
    titles = " | ".join(f["title"] for f in out.findings if f["category"] == "tls")
    for needle in ("failed verification", "has expired", "does not cover", "Self-signed", "Weak RSA", "SHA1"):
        assert needle in titles
    assert next(f for f in out.findings if f["title"] == "Certificate has expired")["severity"] == "high"


async def test_ip_target_skips_domain_only_steps(settings, fetcher_factory):
    zone = {("rev.93.184.216.34", "PTR"): ["host.example-corp.org"]}
    out, t = await run(settings, fetcher_factory, make_providers(dns=FakeDns(zone)), target="93.184.216.34")
    st = {s["key"]: s["status"] for s in t.steps}
    assert st["registration"] == st["tls"] == st["subdomains"] == "skipped"
    assert out.data["ips"][0]["ptr"] == "host.example-corp.org"
    assert out.data["graph"]["nodes"][0]["id"] == "ip:93.184.216.34"


async def test_loopback_and_metadata_targets_rejected_before_any_lookup(settings, fetcher_factory):
    from app.security.target import TargetError
    dns = FakeDns(ZONE)
    for bad in ("127.0.0.1", "169.254.169.254", "http://localhost", "10.0.0.1"):
        with pytest.raises(TargetError):
            await run(settings, lambda: __import__("app.security.safe_net", fromlist=["SafeFetcher"]).SafeFetcher(settings), make_providers(dns=dns), target=bad)
    assert dns.calls == []


async def test_subdomain_dns_verification_is_capped(settings, fetcher_factory):
    settings.subdomain_verify_limit = 3
    names = [f"s{i}.example-corp.org" for i in range(8)]
    out, _ = await run(settings, fetcher_factory, make_providers(subdomains=FakeSubs(names)))
    verifs = [i["verification"] for i in out.data["subdomains"]["items"]]
    assert verifs.count("reported") == 5 and out.data["subdomains"]["dns_checked"] == 3


async def test_http_indicators_via_single_request(settings, server, fetcher_factory):
    prov = make_providers(dns=FakeDns({("site.example.org", "A"): ["93.184.216.34"]}))
    c, _ = ctx(settings, fetcher_factory, prov)
    out = await analyzer.run(c, {"target": f"http://site.example.org:{server.port}/", "options": {"include_http": True, "include_subdomains": False}})
    names = {t["name"] for t in out.data["technologies"]}
    assert {"nginx", "PHP", "WordPress"} <= names
    assert out.data["http"]["http_status"] == 200
    assert len([r for r in server.requests if r[1] == "/"]) == 1


# ------------------------------------------------------------------ provider unit tests
def test_hostname_matching_rules():
    assert hostname_matches("www.example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])
    assert not hostname_matches("example.com", ["*.example.com"])
    assert hostname_matches("EXAMPLE.com.", ["example.com"])


def test_registrable_domain_uses_public_suffix_list():
    assert registrable_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("localhost") is None


def test_rdap_parsing_never_invents_registrant_details():
    doc = {"ldhName": "EXAMPLE.ORG", "status": ["active"], "nameservers": [{"ldhName": "NS1.EXAMPLE.ORG"}],
           "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
           "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]], "publicIds": [{"type": "IANA Registrar ID", "identifier": "123"}]},
                        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}]}
    r = parse_rdap_domain(doc)
    assert (r["registrar"], r["registrar_iana_id"], r["created"], r["expires"]) == ("Reg Inc", "123", "2000-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
    assert r["domain_status"] == ["active"]
    assert r["registrant_org"] is None and r["registrant_redacted"] is True and r["nameservers"] == ["ns1.example.org"]
    doc["entities"][1]["vcardArray"] = ["vcard", [["org", {}, "text", "Acme Corp"]]]
    assert parse_rdap_domain(doc)["registrant_org"] == "Acme Corp"


class FakeFetchResult:
    def __init__(self, body, status=200, truncated=False):
        self.body, self.status, self.truncated, self.headers = body, status, truncated, {}


class FakeFetcher:
    def __init__(self, routes):
        self.routes, self.requested = routes, []

    async def fetch(self, url, **kw):
        self.requested.append((url, kw))
        for prefix, res in self.routes.items():
            if url.startswith(prefix):
                if isinstance(res, Exception):
                    raise res
                return res
        return FakeFetchResult(b"", 404)

    async def aclose(self):
        pass


async def test_rdap_provider_uses_iana_bootstrap(settings):
    import json
    boot = json.dumps({"services": [[["com", "net"], ["https://rdap.verisign.example/com/v1/"]], [["org"], ["https://rdap.pir.example/"]]]}).encode()
    doc = json.dumps({"ldhName": "example.org", "status": ["active"], "events": [], "entities": []}).encode()
    f = FakeFetcher({"https://data.iana.org/rdap/dns.json": FakeFetchResult(boot), "https://rdap.pir.example/domain/example.org": FakeFetchResult(doc)})
    p = RdapProvider(settings, lambda: f)
    res = await p.lookup_domain("www.example.org")
    assert res["status"] == "found" and res["source"] == "https://rdap.pir.example/domain/example.org"
    assert await p.lookup_domain("www.example.org") and sum(1 for u, _ in f.requested if "dns.json" in u) == 1  # bootstrap cached


async def test_rdap_not_found_and_unsupported_tld(settings):
    import json
    boot = json.dumps({"services": [[["org"], ["https://rdap.pir.example/"]]]}).encode()
    f = FakeFetcher({"https://data.iana.org/rdap/dns.json": FakeFetchResult(boot), "https://rdap.pir.example/domain/": FakeFetchResult(b"{}", 404)})
    p = RdapProvider(settings, lambda: f)
    assert (await p.lookup_domain("nope.org"))["status"] == "not_found"
    with pytest.raises(ProviderUnavailable, match="No RDAP service"):
        await p.lookup_domain("thing.dev")  # a real TLD that this (fake) bootstrap does not list
    with pytest.raises(ProviderUnavailable, match="registrable domain"):
        await p.lookup_domain("thing.notatld")
    f2 = FakeFetcher({"https://data.iana.org/": FetchError("dns_failure", "DNS lookup failed")})
    with pytest.raises(ProviderUnavailable, match="RDAP request failed"):
        await RdapProvider(settings, lambda: f2).lookup_domain("x.org")


async def test_cymru_asn_provider_parses_dns_txt():
    dns = FakeDns({("34.216.184.93.origin.asn.cymru.com", "TXT"): ['"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'],
                   ("AS15133.asn.cymru.com", "TXT"): ['"15133 | US | arin | 2008-06-02 | EDGECAST, US"']})
    r = await CymruAsnProvider(None, dns=dns).lookup("93.184.216.34")
    assert (r["asn"], r["prefix"], r["country"], r["name"]) == (15133, "93.184.216.0/24", "US", "EDGECAST, US")
    dns2 = FakeDns(fail_all="timeout")
    with pytest.raises(ProviderUnavailable):
        await CymruAsnProvider(None, dns=dns2).lookup("93.184.216.34")


async def test_crtsh_provider_normalises_filters_and_labels(settings):
    import json
    rows = [{"name_value": "www.example.org\n*.example.org\napi.example.org"}, {"name_value": "evil.com\nexample.org.evil.com\nmail.example.org"}]
    f = FakeFetcher({"https://crt.sh/": FakeFetchResult(json.dumps(rows).encode())})
    r = await CrtShProvider(settings, lambda: f).fetch("example.org")
    assert sorted(i["name"] for i in r["items"]) == ["api.example.org", "example.org", "mail.example.org", "www.example.org"]
    assert "does not prove" in r["basis"]


async def test_crtsh_truncated_response_is_salvaged(settings):
    import json
    rows = [{"name_value": f"h{i}.example.org"} for i in range(50)]
    raw = json.dumps(rows).encode()
    f = FakeFetcher({"https://crt.sh/": FakeFetchResult(raw[: len(raw) - 40], truncated=True)})
    r = await CrtShProvider(settings, lambda: f).fetch("example.org")
    assert r["truncated"] and 40 <= r["total_reported"] < 50


async def test_subdomain_provider_selection_and_missing_key(settings):
    settings.subdomain_provider = "securitytrails"
    settings.securitytrails_api_key = None
    p = build_subdomain_provider(settings, lambda: None)
    assert isinstance(p, DisabledSubdomains)
    with pytest.raises(ProviderUnavailable, match="SECURITYTRAILS_API_KEY"):
        await p.fetch("example.org")
    settings.securitytrails_api_key = "sekret"
    st = build_subdomain_provider(settings, lambda: FakeFetcher({"https://api.securitytrails.com/": FakeFetchResult(b'{"subdomains":["www","mail"]}')}))
    assert isinstance(st, SecurityTrailsProvider)
    r = await st.fetch("example.org")
    assert [i["name"] for i in r["items"]] == ["www.example.org", "mail.example.org"]
    assert "sekret" not in str(r)  # key never appears in results
    settings.subdomain_provider = "none"
    assert isinstance(build_subdomain_provider(settings, lambda: None), DisabledSubdomains)


def test_geoip_unconfigured_is_unavailable_not_empty(settings):
    p = build_geoip_provider(settings, lambda: None)
    assert isinstance(p, NullGeoProvider) and "No GeoIP provider" in p.reason
    settings.geoip_provider = "maxmind"
    assert "CYBERRECON_GEOIP_DB_PATH" in build_geoip_provider(settings, lambda: None).reason


# ------------------------------------------------------------------ TLS against a real local TLS server
def _make_cert(cn, sans, *, days=30, self_issue=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False).sign(key, hashes.SHA256()))
    return key, cert


@pytest.fixture
def tls_server(tmp_path):
    key, cert = _make_cert("site.example.org", ["site.example.org", "*.site.example.org"], days=10)
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ctx_ = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with ctx_.wrap_socket(conn, server_side=True) as s:
                    s.recv(10)
            except Exception:
                pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield sock.getsockname()[1], cert
    stop.set()
    th.join(1)
    sock.close()


async def test_tls_probe_reads_untrusted_certificate_and_reports_verification_failure(settings, tls_server, loopback_policy):
    port, cert = tls_server
    probe = TlsProbe(settings, resolver=fake_resolver({"site.example.org": ["127.0.0.1"]}), policy=loopback_policy)
    r = await probe.probe("site.example.org", port)
    assert r["status"] == "ok"
    assert r["verification"]["ok"] is False and "self-signed" in r["verification"]["error"].lower()
    assert r["subject_cn"] == "site.example.org" and r["self_signed"] is True and r["hostname_match"] is True
    assert r["san"] == ["*.site.example.org", "site.example.org"] and 8 <= r["days_remaining"] <= 10
    assert r["public_key"] == {"type": "RSA", "bits": 2048} and r["protocol"].startswith("TLS")
    assert len(r["fingerprint_sha256"]) == 64


async def test_tls_probe_refuses_private_resolution(settings, tls_server):
    port, _ = tls_server
    probe = TlsProbe(settings, resolver=fake_resolver({"evil.example.org": ["127.0.0.1"]}))  # production policy
    r = await probe.probe("evil.example.org", port)
    assert r["status"] == "unavailable" and "blocked" in r["error"]


async def test_tls_probe_connection_refused_is_reported(settings, loopback_policy):
    probe = TlsProbe(settings, resolver=fake_resolver({"site.example.org": ["127.0.0.1"]}), policy=loopback_policy)
    r = await probe.probe("site.example.org", 1)
    assert r["status"] == "error"


def test_parse_certificate_fields():
    key, cert = _make_cert("shop.example.org", ["shop.example.org", "pay.example.org"], days=90)
    p = parse_certificate(cert.public_bytes(serialization.Encoding.DER), "shop.example.org")
    assert p["hostname_match"] and p["san_count"] == 2 and 88 <= p["days_remaining"] <= 90 and not p["expired"]
    assert not parse_certificate(cert.public_bytes(serialization.Encoding.DER), "other.example.org")["hostname_match"]
