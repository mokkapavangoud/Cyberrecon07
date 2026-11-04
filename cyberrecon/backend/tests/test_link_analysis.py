import pytest

from app.services.common import RunContext, StepTracker
from app.services.link_analysis import analyzer
from app.services.link_analysis.parser import classify_link, parse_html
from app.services.link_analysis.robots import parse_robots
from app.services.link_analysis.sitemap import parse_sitemap

from .fixture_server import HOME_HTML


def make_ctx(settings, fetcher_factory):
    tracker = StepTracker(analyzer.STEPS, lambda s: None)
    return RunContext("t1", settings, tracker, fetcher_factory, providers=None), tracker


# ------------------------------------------------------------------ pure parsing
def test_link_extraction_and_classification():
    page = parse_html(HOME_HTML.encode(), "http://site.example.org:8080/")
    by_url = {l.url: l for l in page.links}
    assert by_url["http://site.example.org:8080/about"].kind == "internal"
    assert by_url["http://site.example.org:8080/about"].count == 2  # "/about" and "about" resolve identically via <base href="/">
    assert by_url["https://other-site.example.org/page"].kind == "external"
    assert by_url["https://blog.site.example.org/post"].kind == "subdomain"
    assert by_url["mailto:hi@site.example.org"].kind == "mailto"
    assert by_url["tel:+100"].kind == "tel"
    assert by_url["javascript:alert(1)"].kind == "javascript"
    assert by_url["#"].kind == "fragment"
    assert by_url["https://widgets.example.net/embed"].sources == ["iframe"]
    assert "form" in by_url["http://site.example.org:8080/search"].sources
    assert page.title == "Fixture & Co <Home>"
    assert page.meta["generator"] == "WordPress 6.4"
    assert page.meta["open_graph"]["title"] == "Fixture OG"
    assert page.favicon == "http://site.example.org:8080/favicon.ico"


def test_title_is_kept_as_literal_text_not_parsed_markup():
    page = parse_html(b"<html><head><title><img src=x onerror=alert(1)></title></head><body><img src=y></body></html>", "https://a.example.org/")
    # stored verbatim as a string; escaping is the job of every output path (React, PDF and CSV are tested separately)
    assert page.title == "<img src=x onerror=alert(1)>"
    assert [l.url for l in page.links if "img" in l.sources] == ["https://a.example.org/y"]  # the title's <img> is NOT a link


def test_classify_www_is_internal():
    assert classify_link("https://www.example.org/x", "example.org") == "internal"
    assert classify_link("https://example.org.evil.net/", "example.org") == "external"


def test_link_cap_applied():
    html = "".join(f'<a href="/p{i}">x</a>' for i in range(50)).encode()
    page = parse_html(html, "https://a.example.org/", max_links=10)
    assert len(page.links) == 10 and page.discarded_links == 40


def test_robots_longest_match_and_allow_wins_ties():
    info = parse_robots("User-agent: *\nDisallow: /private/\nAllow: /private/public\nDisallow: /*.pdf$\nSitemap: https://x.example.org/s.xml")
    assert not info.allowed("/private/secret")
    assert info.allowed("/private/public/page")
    assert not info.allowed("/docs/a.pdf")
    assert info.allowed("/docs/a.pdf.html")
    assert info.sitemaps == ["https://x.example.org/s.xml"]


def test_robots_specific_agent_overrides_wildcard():
    info = parse_robots("User-agent: *\nDisallow: /\n\nUser-agent: CyberRecon\nDisallow: /admin")
    assert info.allowed("/home") and not info.allowed("/admin/x")


def test_sitemap_parse_and_xxe_rejected():
    ok = parse_sitemap(b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://a/1</loc></url><url><loc>https://a/2</loc></url></urlset>')
    assert ok["status"] == "parsed" and ok["url_count"] == 2
    bad = parse_sitemap(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><urlset><url><loc>&e;</loc></url></urlset>')
    assert bad["status"] == "rejected" and "root:" not in str(bad)
    assert parse_sitemap(b"not xml")["status"] == "invalid"


# ------------------------------------------------------------------ end to end against the fixture
async def test_full_analysis_without_link_checking(settings, server, fetcher_factory):
    ctx, tracker = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/", "options": {}})
    d = out.data
    assert out.status == "completed"
    assert d["http"]["status"] == 200 and d["http"]["remote_ip"] == "127.0.0.1"
    assert d["page"]["title"] == "Fixture & Co <Home>"
    assert d["robots"]["status"] == "found" and d["sitemap"]["status"] == "parsed" and d["sitemap"]["url_count"] == 2
    # discovered != checked
    assert d["link_summary"]["discovered"] >= 10 and d["link_summary"]["checked"] == 0
    assert all(l["check"]["state"] == "not_checked" for l in d["links"])
    techs = {t["name"] for t in d["technologies"]}
    assert {"nginx", "PHP", "WordPress"} <= techs
    hsts = next(h for h in d["headers"]["security"] if h["name"] == "strict-transport-security")
    assert hsts["applicable"] is False  # plain http fixture
    assert d["headers"]["cookies"][0] == {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax", "path": "/"}
    assert "abc123" not in str(out.data)  # cookie VALUES are never stored
    assert d["requests_made"] == 3  # page + robots + sitemap, nothing else
    assert [s["status"] for s in tracker.steps if s["key"] == "link_check"] == ["skipped"]
    kinds = {s["name"]: s["status"] for s in out.sources}
    assert kinds["robots.txt"] == "ok" and kinds["sitemap.xml"] == "ok"


async def test_link_checking_honours_robots_and_blocks_internal_addresses(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    html_server = server
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{html_server.port}/", "options": {"check_links": True, "max_links_to_check": 50}})
    links = {l["url"].replace(f":{server.port}", ""): l["check"] for l in out.data["links"]}
    assert links["http://site.example.org/about"]["state"] == "checked" and links["http://site.example.org/about"]["status"] == 200
    assert links["http://site.example.org/missing"]["status"] == 404
    assert links["http://site.example.org/private/area"]["state"] == "skipped"
    assert links["http://site.example.org/private/area"]["reason"] == "robots_disallow"
    assert links["https://other-site.example.org/page"]["reason"] == "external_disabled"
    # the disallowed URL was genuinely never requested
    assert not any(p == "/private/area" for _m, p, _h in server.requests)
    assert any(f["category"] == "broken_link" for f in out.findings)
    s = out.data["link_summary"]
    assert s["checked"] >= 3 and s["broken"] >= 1 and s["skipped"] >= 1


async def test_link_check_limit_is_enforced(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/", "options": {"check_links": True, "max_links_to_check": 2}})
    s = out.data["link_summary"]
    assert s["checked"] + s["skipped"] <= 2
    assert any(l["check"].get("reason") == "limit" for l in out.data["links"])


async def test_external_check_unresolvable_host_reported_as_failed(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/", "options": {"check_links": True, "check_external": True, "max_links_to_check": 50}})
    ext = next(l for l in out.data["links"] if l["url"] == "https://other-site.example.org/page")
    assert ext["check"]["state"] == "failed" and ext["check"]["reason"] == "dns_failure"


async def test_forbidden_target_is_partial_with_clear_message(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/forbidden", "options": {}})
    assert out.status == "partial" and out.data["http"]["status"] == 403
    assert "does not bypass" in out.errors[0]["message"]
    assert out.data["links"] == []


async def test_rate_limited_target_message(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/ratelimited", "options": {}})
    assert out.status == "partial" and "rate limiting" in out.errors[0]["message"] and "30" in out.errors[0]["message"]


async def test_unreachable_target_fails_cleanly(settings, fetcher_factory):
    ctx, tracker = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": "https://no-such-host.example.org/", "options": {}})
    assert out.status == "failed" and out.data["fetch_error"]["code"] == "dns_failure"
    assert out.findings[0]["category"] == "reachability"
    assert {s["status"] for s in tracker.steps if s["key"] in ("parse", "robots")} == {"skipped"}


async def test_redirect_to_metadata_is_reported_not_followed(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/redirect-private", "options": {}})
    assert out.data["http"]["status"] == 302
    assert any("blocked" in (h["note"] or "") for h in out.data["redirect_chain"])
    assert not any("169.254" in host for _m, _p, host in server.requests)


async def test_malicious_markup_is_stored_as_inert_text(settings, server, fetcher_factory):
    ctx, _ = make_ctx(settings, fetcher_factory)
    out = await analyzer.run(ctx, {"target": f"http://site.example.org:{server.port}/evil-title", "options": {}})
    link = next(l for l in out.data["links"] if l["url"].endswith("/x"))
    assert link["text"] == "<script>alert(1)</script>"  # preserved as text; React escapes on render, PDF/CSV escape on export
