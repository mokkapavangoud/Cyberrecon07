#!/usr/bin/env python
"""Regenerate demo/aurora-demo.json.

The demo dataset is produced by running CyberRecon's REAL analysers against a local, controlled fixture
(a throwaway HTTP server + scripted DNS/RDAP/ASN/TLS answers for a FICTIONAL organisation), so the demo has exactly
the same data shapes as live results. Nothing here touches the internet. Everything is labelled simulated.

Reserved/fictional identifiers only: aurora-demo.example.org (IANA-reserved example.org), TEST-NET documentation
addresses (203.0.113.0/24, 198.51.100.0/24, 2001:db8::/32), private-use AS numbers (64496-64511, RFC 5398).

Usage:  cd backend && .venv/bin/python ../scripts/build_demo.py
"""
from __future__ import annotations

import asyncio
import io
import json
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import piexif  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.database.migrations import migrate  # noqa: E402
from app.database.session import Database  # noqa: E402
from app.integrations.registry import Providers  # noqa: E402
from app.models.entities import Assessment  # noqa: E402
from app.security.ip_policy import IPPolicy  # noqa: E402
from app.security.safe_net import SafeFetcher  # noqa: E402
from app.services.image_intelligence import analyzer as image_analyzer  # noqa: E402
from app.services.infrastructure import analyzer as infra_analyzer  # noqa: E402
from app.services.jobs import JobRunner  # noqa: E402
from app.services.link_analysis import analyzer as link_analyzer  # noqa: E402
from app.services.reporting.serialize import assessment_to_dict  # noqa: E402
from tests.helpers import FakeAsn, FakeDns, FakeGeo, FakeRdap, FakeSubs, FakeTls, fake_resolver  # noqa: E402

DOMAIN = "aurora-demo.example.org"
HOST = f"www.{DOMAIN}"
PORT_PLACEHOLDER = "{PORT}"
IP4, IP4B, IP6 = "203.0.113.10", "203.0.113.11", "2001:db8:a0:1::10"

PAGES = {
    "/": f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Aurora Labs — Demo Company (simulated)</title>
<meta name="description" content="Simulated demo site for CyberRecon. Aurora Labs is a fictional company.">
<meta name="generator" content="Hugo 0.121">
<meta property="og:title" content="Aurora Labs (simulated)"><link rel="canonical" href="/"><link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/assets/site.css"></head><body>
<nav><a href="/products">Products</a> <a href="/about">About</a> <a href="/careers">Careers</a> <a href="/blog/">Blog</a> <a href="/contact">Contact</a></nav>
<a href="/products/beacon">Beacon</a> <a href="/legacy/pricing-2019">Old pricing</a> <a href="/press">Press</a> <a href="/admin/">Staff</a>
<a href="http://docs.{DOMAIN}:{PORT_PLACEHOLDER}/guide">Docs</a>
<a href="https://partner-one.example.net/aurora">Partner One</a> <a href="https://status.example.com/aurora">Status</a>
<a href="https://social.example.com/aurora-labs">Social</a> <a href="mailto:hello@{DOMAIN}">Email us</a> <a href="tel:+15550100">Call</a>
<img src="/assets/logo.png"><script src="/assets/app.js"></script><script src="https://cdn.example.net/analytics.js"></script>
</body></html>""",
    "/products": "<html><head><title>Products</title></head><body>Products</body></html>",
    "/about": "<html><head><title>About</title></head><body>About</body></html>",
    "/careers": "<html><head><title>Careers</title></head><body>Careers</body></html>",
    "/blog/": "<html><head><title>Blog</title></head><body>Blog</body></html>",
    "/contact": "<html><head><title>Contact</title></head><body>Contact</body></html>",
    "/products/beacon": "<html><head><title>Beacon</title></head><body>Beacon</body></html>",
    "/press": "<html><head><title>Press</title></head><body>Press</body></html>",
}
ROBOTS = f"User-agent: *\nDisallow: /admin/\nAllow: /\nSitemap: http://{HOST}:{PORT_PLACEHOLDER}/sitemap.xml\n"
SITEMAP = ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           + "".join(f"<url><loc>http://{HOST}:{PORT_PLACEHOLDER}{p}</loc></url>" for p in ("/", "/products", "/about", "/careers", "/blog/", "/contact")) + "</urlset>")


class H(BaseHTTPRequestHandler):
    server_version, sys_version = "nginx/1.24.0", ""

    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_GET(self, head=False):
        port = self.server.server_address[1]
        p = self.path.split("?")[0]
        if p == "/robots.txt":
            body, ctype, status = ROBOTS.replace(PORT_PLACEHOLDER, str(port)), "text/plain", 200
        elif p == "/sitemap.xml":
            body, ctype, status = SITEMAP.replace(PORT_PLACEHOLDER, str(port)), "application/xml", 200
        elif p in PAGES:
            body, ctype, status = PAGES[p].replace(PORT_PLACEHOLDER, str(port)), "text/html; charset=utf-8", 200
        else:
            body, ctype, status = "Not found", "text/plain", 404
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "session_demo=SIMULATED; Path=/; HttpOnly")
        self.send_header("Set-Cookie", "prefs=1; Path=/")
        self.end_headers()
        if not head:
            self.wfile.write(data)


class DemoPolicy(IPPolicy):
    """Generation-time policy: loopback (local fixture) and documentation ranges are treated as public so the demo exercises full code paths."""
    def reason(self, ip):
        if ip == "127.0.0.1" or ip.startswith(("203.0.113.", "198.51.100.", "2001:db8")):
            return None
        return super().reason(ip)


def demo_image() -> bytes:
    img = Image.new("RGB", (640, 420))
    d = ImageDraw.Draw(img)
    for y in range(420):
        d.line([(0, y), (640, y)], fill=(20 + y // 4, 60 + y // 5, 90 + y // 4))
    d.ellipse((430, 50, 540, 160), fill=(240, 220, 150))
    d.polygon([(0, 420), (200, 230), (360, 420)], fill=(15, 40, 45))
    d.polygon([(220, 420), (420, 260), (640, 420)], fill=(10, 30, 35))
    exif = piexif.dump({
        "0th": {piexif.ImageIFD.Make: b"AuroraDemo", piexif.ImageIFD.Model: b"Simulated Camera S1", piexif.ImageIFD.Software: b"DemoEdit 1.0",
                piexif.ImageIFD.Artist: b"Demo Photographer (fictional)", piexif.ImageIFD.Orientation: 1},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:03:14 17:42:09", piexif.ExifIFD.BodySerialNumber: b"DEMO-0000-FAKE", piexif.ExifIFD.ISOSpeedRatings: 200,
                 piexif.ExifIFD.FNumber: (28, 10), piexif.ExifIFD.ExposureTime: (1, 250), piexif.ExifIFD.FocalLength: (35, 1)},
        "GPS": {piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((0, 1), (0, 1), (0, 1)), piexif.GPSIFD.GPSLongitudeRef: b"E",
                piexif.GPSIFD.GPSLongitude: ((0, 1), (0, 1), (0, 1)), piexif.GPSIFD.GPSAltitudeRef: 0, piexif.GPSIFD.GPSAltitude: (10, 1)},
        "1st": {}, "thumbnail": None,
    })
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88, exif=exif)
    return buf.getvalue()


def infra_providers() -> Providers:
    zone = {
        (HOST, "A"): [IP4, IP4B], (HOST, "AAAA"): [IP6], (DOMAIN, "A"): [IP4],
        ("example.org", "NS"): [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"], ("example.org", "MX"): [f"10 mail.{DOMAIN}", f"20 mail2.{DOMAIN}"],
        ("example.org", "TXT"): ["v=spf1 include:_spf.aurora-demo.example.org ~all", "aurora-demo-site-verification=SIMULATED"],
        ("example.org", "CAA"): ['0 issue "letsencrypt.example"'],
        (f"_dmarc.example.org", "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@aurora-demo.example.org"],
        (f"api.{DOMAIN}", "A"): [IP4B], (f"staging.{DOMAIN}", "A"): ["198.51.100.77"],
    }
    asn = {
        IP4: {"asn": 64500, "all_asns": [64500], "prefix": "203.0.113.0/24", "country": "ZZ", "registry": "simulated", "allocated": "2015-01-01", "name": "AURORA-HOSTING-DEMO, ZZ"},
        IP4B: {"asn": 64500, "all_asns": [64500], "prefix": "203.0.113.0/24", "country": "ZZ", "registry": "simulated", "allocated": "2015-01-01", "name": "AURORA-HOSTING-DEMO, ZZ"},
        IP6: {"asn": 64500, "all_asns": [64500], "prefix": "2001:db8:a0::/48", "country": "ZZ", "registry": "simulated", "allocated": "2015-01-01", "name": "AURORA-HOSTING-DEMO, ZZ"},
        "198.51.100.77": {"asn": 64501, "all_asns": [64501], "prefix": "198.51.100.0/24", "country": "ZZ", "registry": "simulated", "allocated": "2018-06-01", "name": "STAGING-CLOUD-DEMO, ZZ"},
    }
    reg = {"status": "found", "source": "simulated://rdap/example.org", "queried_domain": "example.org", "domain": "example.org", "registrar": "Demo Registrar Ltd (simulated)",
           "registrar_iana_id": "0000", "created": "2016-02-11T00:00:00Z", "expires": (datetime.now(timezone.utc) + timedelta(days=41)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "updated": "2026-02-01T00:00:00Z", "domain_status": ["client transfer prohibited"], "nameservers": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"], "registrant_org": None, "registrant_redacted": True}
    ipreg = {"status": "found", "source": "simulated://rdap/ip", "name": "AURORA-HOSTING-DEMO-NET", "handle": "DEMO-NET-1", "country": "ZZ", "organizations": ["Aurora Hosting Demo (fictional)"]}
    tls = {
        "status": "ok", "port": 443, "connected_ip": IP4, "verification": {"ok": True, "error": None}, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        "subject_cn": HOST, "subject_org": None, "issuer_cn": "Demo Intermediate CA", "issuer_org": "Demo Certificate Authority (simulated)", "issuer_country": "ZZ",
        "not_before": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(), "not_after": (datetime.now(timezone.utc) + timedelta(days=24)).isoformat(),
        "days_remaining": 24, "expired": False, "not_yet_valid": False, "san": [HOST, DOMAIN, f"api.{DOMAIN}"], "san_count": 3, "serial": "00DEMO",
        "signature_hash": "sha256", "public_key": {"type": "EC", "bits": 256}, "fingerprint_sha256": "de" * 32, "self_signed": False, "hostname_match": True,
    }
    geo = {"country": "Zedland (fictional)", "city": "Demo City", "region": None, "latitude": None, "longitude": None, "provider": "simulated-geoip", "estimate": True, "note": "SIMULATED. IP geolocation is an approximate estimate and does not identify a precise or physical location."}
    dns, asn_p, geo_p = FakeDns(zone), FakeAsn(asn), FakeGeo(geo)
    dns.resolver_label, dns.name = "simulated resolver", "simulated-dns"
    asn_p.name, asn_p.reference = "Team Cymru IP-to-ASN (simulated)", "simulated://asn"
    geo_p.name = "simulated-geoip"
    return Providers(dns=dns, rdap=FakeRdap(reg, ipreg), asn=asn_p, geoip=geo_p, subdomains=FakeSubs([f"api.{DOMAIN}", f"staging.{DOMAIN}", f"old-portal.{DOMAIN}"], provider="simulated-ct-index"),
                     tls=FakeTls(tls), screenshots=None)


async def main():
    tmp = Path(tempfile.mkdtemp(prefix="cr-demo-"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    settings = Settings(data_dir=tmp / "data", allowed_ports=[80, 443, port], http_read_timeout=3.0, http_total_timeout=10.0, rate_limit_per_minute=1000, subdomain_provider="none", screenshot_enabled=False, _env_file=None)
    db = Database(f"sqlite:///{tmp / 'demo.db'}")
    migrate(db)
    mapping = {HOST: ["127.0.0.1"], DOMAIN: ["127.0.0.1"], f"docs.{DOMAIN}": ["127.0.0.1"]}

    def fetcher_factory():
        return SafeFetcher(settings, resolver=fake_resolver(mapping), policy=DemoPolicy())

    runner = JobRunner(db, settings, infra_providers(), fetcher_factory)
    out: list[dict] = []

    url = f"http://{HOST}:{port}/"
    a = runner.create(module="link", target=url, label=HOST, steps_def=link_analyzer.STEPS, authorized=True, options={"check_links": True, "check_external": False, "max_links_to_check": 25},
                      scope={"hosts": [HOST], "note": "Simulated demo scope"})
    await runner.execute(a, link_analyzer.run, {"target": url, "options": {"check_links": True, "check_external": False, "max_links_to_check": 25}}, link_analyzer.STEPS)
    out.append(("link", a, None))

    a = runner.create(module="infrastructure", target=HOST, label=HOST, steps_def=infra_analyzer.STEPS, authorized=True, options={"include_http": False}, scope={"hosts": [HOST]})
    await runner.execute(a, infra_analyzer.run, {"target": HOST, "options": {"include_http": False}}, infra_analyzer.STEPS)
    out.append(("infrastructure", a, None))

    a = runner.create(module="image", target="aurora-demo-photo.jpg", label="aurora-demo-photo.jpg", steps_def=image_analyzer.STEPS)
    o = await runner.execute(a, image_analyzer.run, {"bytes": demo_image(), "filename": "aurora-demo-photo.jpg"}, image_analyzer.STEPS)
    out.append(("image", a, o.transient))
    httpd.shutdown()

    assessments = []
    with db.session() as s:
        for i, (module, aid, transient) in enumerate(out):
            d = assessment_to_dict(s.get(Assessment, aid))
            if transient is not None:  # demo shows the full simulated metadata, including the fictional GPS panel
                d["result"] = transient
            assessments.append((module, d))
    text = json.dumps([d for _m, d in assessments], ensure_ascii=False)
    text = text.replace(f":{port}", "").replace("127.0.0.1", IP4)
    text = text.replace('"http://aurora-demo', '"http://aurora-demo')
    items = json.loads(text)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for i, d in enumerate(items):
        new_id = f"demo-{d['module']}-aurora"
        text = None
        d["_old_id"] = d["id"]
        d.update(id=new_id, mode="demo", simulated=True)
        for k, off in (("created_at", 0), ("started_at", 0), ("finished_at", 1)):
            d[k] = (now - timedelta(days=3 - i, minutes=-off)).isoformat(timespec="seconds")
        d["authorization"]["confirmed_at"] = d["created_at"] if d["authorization"]["confirmed"] else None
        d["reports"] = []
    raw = json.dumps(items, ensure_ascii=False)
    for d in items:
        raw = raw.replace(d["_old_id"], d["id"])
    items = json.loads(raw)
    for d in items:
        d.pop("_old_id", None)
        for src in d["sources"]:
            if "simulated" not in src["name"].lower():
                src["name"] += " (simulated)"
    bundle = {
        "simulated": True,
        "notice": "SIMULATED DEMO DATA. Aurora Labs is a fictional organisation. Domains use the IANA-reserved example.org; addresses are documentation ranges (RFC 5737/3849); AS numbers are reserved for documentation (RFC 5398). Nothing here was retrieved from the internet.",
        "generated_by": "scripts/build_demo.py (real analysers run against a local scripted fixture)",
        "assessments": items,
    }
    dest = ROOT / "demo" / "aurora-demo.json"
    dest.write_text(json.dumps(bundle, indent=1, ensure_ascii=False))
    print("wrote", dest, dest.stat().st_size, "bytes;", [(d["module"], d["status"], len(d["findings"])) for d in items])


if __name__ == "__main__":
    asyncio.run(main())
