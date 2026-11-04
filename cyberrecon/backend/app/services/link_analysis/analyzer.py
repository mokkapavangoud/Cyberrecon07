"""Module A: website footprinting and link intelligence.

Active requests are limited to: the target page, /robots.txt, one sitemap, and (only if enabled)
HEAD requests to a capped number of discovered links. Everything goes through ``SafeFetcher``.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from urllib.parse import urlsplit

from app.security.safe_net import FetchError, SafeFetcher
from app.security.target import TargetError, same_site
from app.services.common import ModuleOutput, RunContext, finding, source
from app.services.fingerprint import (
    INTERESTING_HEADERS,
    analyse_security_headers,
    detect_technologies,
    parse_set_cookies,
)

from .parser import parse_html, summarise_links
from .robots import RobotsCache, parse_robots, robots_summary
from .sitemap import parse_sitemap

MODULE = "link"
STEPS = [
    ("validate", "Validate target and scope"),
    ("fetch", "Fetch the target page"),
    ("parse", "Parse metadata, headers and links"),
    ("robots", "Read robots.txt"),
    ("sitemap", "Read sitemap.xml"),
    ("link_check", "Check discovered links"),
    ("finalise", "Assemble results"),
]

FETCH_ERROR_HELP = {
    "dns_failure": "The hostname could not be resolved.",
    "blocked_target": "The hostname resolves to a non-public address and was not contacted.",
    "connect_timeout": "The target did not accept a connection in time.",
    "read_timeout": "The target accepted the connection but did not respond in time.",
    "timeout": "The overall time limit for the request was reached.",
    "unreachable": "The target could not be reached.",
    "tls_error": "A TLS/certificate error prevented a secure connection.",
    "protocol_error": "The connection was interrupted or the response was malformed.",
    "too_many_redirects": "The target redirected too many times.",
}


def _status_message(status: int, headers: dict[str, str]) -> str | None:
    if status in (401, 403):
        return (f"The target responded with HTTP {status}: access is restricted or automated requests are refused. "
                "CyberRecon does not bypass authentication, CAPTCHAs or access controls.")
    if status == 429:
        retry = headers.get("retry-after")
        return "The target is rate limiting requests (HTTP 429)" + (f"; it asked clients to retry after {retry}." if retry else ".")
    if status == 451:
        return "The target is unavailable for legal reasons (HTTP 451)."
    if status >= 500:
        return f"The target reported a server error (HTTP {status})."
    if status == 404:
        return "The page was not found (HTTP 404)."
    return None


async def _check_links(fetcher: SafeFetcher, robots: RobotsCache, links: list[dict], *, limit: int, include_external: bool,
                       concurrency: int, on_progress) -> None:
    candidates = []
    for l in links:
        if not l["url"].startswith(("http://", "https://")):
            l["check"] = {"state": "not_checked", "reason": "not_http", "detail": "Only http(s) links can be checked."}
            continue
        if l["kind"] == "external" and not include_external:
            l["check"] = {"state": "not_checked", "reason": "external_disabled", "detail": "External link checking is off."}
            continue
        candidates.append(l)
    # internal first (they are in scope), then others, in discovery order
    candidates.sort(key=lambda l: 0 if l["kind"] in ("internal", "subdomain") else 1)
    selected, rest = candidates[:limit], candidates[limit:]
    for l in rest:
        l["check"] = {"state": "not_checked", "reason": "limit", "detail": f"Beyond the per-assessment limit of {limit} checks."}

    sem = asyncio.Semaphore(concurrency)
    host_sems: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(2))
    done = 0

    async def one(l: dict):
        nonlocal done
        host = (urlsplit(l["url"]).hostname or "").lower()
        async with sem, host_sems[host]:
            l["check"] = await _check_one(fetcher, robots, l["url"], host)
        done += 1
        on_progress(done, len(selected))

    if selected:
        await asyncio.gather(*(one(l) for l in selected))


async def _check_one(fetcher: SafeFetcher, robots: RobotsCache, url: str, host: str) -> dict:
    try:
        if not await robots.allowed(url):
            return {"state": "skipped", "reason": "robots_disallow", "detail": "Disallowed by robots.txt for this crawler; not requested."}
        res = await fetcher.fetch(url, method="HEAD", scope_host=host, max_redirects=3, accept="*/*")
        method = "HEAD"
        if res.status in (405, 501):
            res = await fetcher.fetch(url, method="GET", max_bytes=2048, scope_host=host, max_redirects=3, accept="*/*")
            method = "GET"
        out = {"state": "checked", "status": res.status, "method": method, "time_ms": res.elapsed_ms,
               "redirects": max(0, len(res.hops) - 1)}
        if res.final_url.rstrip("/") != url.rstrip("/"):
            out["final_url"] = res.final_url
        if res.blocked_redirect:
            out["detail"] = f"Redirect to {res.blocked_redirect[:200]} was not followed."
        return out
    except TargetError as exc:
        return {"state": "blocked", "reason": exc.code, "detail": exc.message}
    except FetchError as exc:
        state = "blocked" if exc.code == "blocked_target" else "failed"
        return {"state": state, "reason": exc.code, "detail": exc.message}


def _build_findings(d: dict) -> list[dict]:
    f: list[dict] = []
    http = d["http"]
    if d["page"].get("title"):
        f.append(finding(MODULE, "metadata", "Page title observed", d["page"]["title"], source="HTTP response body"))
    if d["page"]["meta"].get("description"):
        f.append(finding(MODULE, "metadata", "Meta description present", d["page"]["meta"]["description"][:300], source="HTTP response body"))
    if len(d["redirect_chain"]) > 1:
        f.append(finding(MODULE, "http", f"Request redirected {len(d['redirect_chain']) - 1} time(s)",
                         " → ".join(h["url"] for h in d["redirect_chain"][:6]), source="HTTP response"))
    if http["response_time_ms"] and http["response_time_ms"] > 3000:
        f.append(finding(MODULE, "performance", "Slow response", f"The page took {http['response_time_ms']} ms to respond.", severity="info", source="HTTP response"))
    if http.get("truncated"):
        f.append(finding(MODULE, "limits", "Response body truncated", "The page exceeded the response-size limit; links beyond it were not discovered.", severity="info", source="CyberRecon limits"))
    for h in d["headers"]["security"]:
        if h["applicable"] and not h["present"]:
            f.append(finding(MODULE, "headers", f"{h['label']} header not observed",
                             f"The {h['label']} response header was absent from the response to this single request.",
                             severity=h["severity"], source="HTTP response headers"))
        elif h["present"] and h.get("note"):
            f.append(finding(MODULE, "headers", f"{h['label']} configuration note", h["note"], severity="low", source="HTTP response headers"))
    if d["page"]["server_disclosure"]:
        f.append(finding(MODULE, "headers", "Server software disclosed in headers", d["page"]["server_disclosure"], severity="info", source="HTTP response headers"))
    scheme_https = d["scheme"] == "https"
    for c in d["headers"]["cookies"]:
        problems = []
        if scheme_https and not c["secure"]:
            problems.append("Secure")
        if not c["httponly"]:
            problems.append("HttpOnly")
        if problems:
            f.append(finding(MODULE, "cookies", f"Cookie '{c['name']}' without {'/'.join(problems)} attribute",
                             "Cookie attributes were read from the Set-Cookie header; values are never stored.", severity="low", source="HTTP response headers"))
    for t in d["technologies"]:
        f.append(finding(MODULE, "technology", f"Technology indicator: {t['name']}" + (f" {t['version']}" if t.get("version") else ""),
                         "; ".join(t["evidence"]) + ". Indicators are hints, not definitive identification.", severity="info", source="Headers and page markup"))
    r = d["robots"]
    if r["status"] == "found":
        n = sum(g["disallow"] for g in r["groups"])
        f.append(finding(MODULE, "robots", "robots.txt found", f"{len(r['groups'])} user-agent group(s), {n} disallow rule(s), {len(r['sitemaps'])} sitemap reference(s).", source="robots.txt"))
    elif r["status"] == "not_found":
        f.append(finding(MODULE, "robots", "robots.txt not found", "The server returned a non-200 response for /robots.txt.", source="robots.txt"))
    s = d["sitemap"]
    if s["status"] == "parsed":
        f.append(finding(MODULE, "sitemap", "Sitemap found", f"{s['type']} with {s.get('url_count') or s.get('child_sitemaps')} entries.", source="sitemap.xml"))
    ls = d["link_summary"]
    k = ls["by_kind"]
    f.append(finding(MODULE, "links", f"{ls['discovered']} unique links discovered",
                     f"{k.get('internal', 0)} internal, {k.get('subdomain', 0)} subdomain, {k.get('external', 0)} external, "
                     f"{sum(v for kk, v in k.items() if kk not in ('internal', 'subdomain', 'external'))} other. "
                     f"{ls['checked']} were actively checked; the rest were discovered only.", source="HTTP response body"))
    for l in d["links"]:
        if l["check"]["state"] == "checked" and (l["check"].get("status") or 0) >= 400 and sum(1 for x in f if x["category"] == "broken_link") < 20:
            f.append(finding(MODULE, "broken_link", f"Link returned HTTP {l['check']['status']}", l["url"], severity="low", source="Link check (HEAD)"))
    return f


async def run(ctx: RunContext, params: dict) -> ModuleOutput:
    settings, steps = ctx.settings, ctx.steps
    opts = params.get("options", {})
    check_links = bool(opts.get("check_links", False))
    include_external = bool(opts.get("check_external", False))
    limit = max(1, min(int(opts.get("max_links_to_check", settings.link_check_default_limit)), settings.link_check_max_limit))

    sources: list[dict] = []
    errors: list[dict] = []
    fetcher: SafeFetcher = ctx.fetcher_factory()
    try:
        async with steps.step("validate"):
            target = fetcher.parse(params["target"])
            steps.detail("validate", f"Normalised to {target.url}")

        # ------------------------------------------------------------------ fetch
        try:
            async with steps.step("fetch"):
                res = await fetcher.fetch(target.url, scope_host=target.hostname)
        except FetchError as exc:
            msg = f"{FETCH_ERROR_HELP.get(exc.code, 'The request failed.')} ({exc.message})"
            errors.append({"step": "fetch", "code": exc.code, "message": msg})
            sources.append(source("Target website", "http", "failed", target.url, msg))
            for k in ("parse", "robots", "sitemap", "link_check"):
                steps.skip(k, "Target could not be fetched")
            data = {"normalized_url": target.url, "scheme": target.scheme, "hostname": target.hostname, "fetch_error": {"code": exc.code, "message": msg}}
            return ModuleOutput(data=data, sources=sources, errors=errors, status="failed",
                                findings=[finding(MODULE, "reachability", "Target could not be analysed", msg, severity="info", source="HTTP request")],
                                summary={"headline": "Target unreachable", "error": exc.code})

        final = fetcher.parse(res.final_url)
        ctype = res.headers.get("content-type", "")
        status_note = _status_message(res.status, res.headers)
        if status_note:
            errors.append({"step": "fetch", "code": f"http_{res.status}", "message": status_note})
        sources.append(source("Target website", "http", "ok" if res.status < 400 else "failed", res.final_url,
                              status_note or f"HTTP {res.status} in {res.elapsed_ms} ms"))

        # ------------------------------------------------------------------ parse
        async with steps.step("parse"):
            is_html = "html" in ctype.lower() or (not ctype and res.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html")))
            if res.status < 400 and res.body and is_html:
                page = parse_html(res.body, res.final_url, max_links=settings.max_links_stored)
                title, meta, parsed_links, assets, favicon = page.title, page.meta, page.links, page.asset_urls, page.favicon
                discarded = page.discarded_links
            else:
                title, meta, parsed_links, assets, favicon, discarded = None, {"open_graph": {}, "twitter": {}}, [], [], None, 0
                if res.status < 400 and not is_html:
                    errors.append({"step": "parse", "code": "non_html", "message": f"Response content type is '{ctype or 'unknown'}', so no links were extracted."})
            steps.detail("parse", f"{len(parsed_links)} unique links found")
            html_sample = res.body[:200_000].decode("utf-8", "replace") if is_html else ""
            technologies = detect_technologies(res.headers, generator=meta.get("generator"), html_sample=html_sample, asset_urls=assets)
            headers_selected = {k: res.headers[k][:500] for k in INTERESTING_HEADERS if k in res.headers}
            sec = analyse_security_headers(res.headers, https=final.scheme == "https")
            cookies = parse_set_cookies(res.raw_headers)
            links = [{"url": l.url, "kind": l.kind, "sources": l.sources, "count": l.count, "text": l.text,
                      "check": {"state": "not_checked", "reason": "disabled", "detail": "Link checking was not enabled."}}
                     for l in parsed_links]

        # ------------------------------------------------------------------ robots
        robots_cache = RobotsCache(fetcher)
        robots_data: dict = {"status": "unavailable", "url": final.origin + "/robots.txt"}
        robots_info = None
        async with steps.step("robots"):
            try:
                rr = await fetcher.fetch(robots_data["url"], max_bytes=200_000, scope_host=final.hostname, accept="text/plain,*/*;q=0.5")
                robots_data["http_status"] = rr.status
                if rr.status == 200:
                    text = rr.body.decode("utf-8", "replace")
                    robots_info = parse_robots(text)
                    robots_data.update({"status": "found", "size_bytes": len(rr.body), **robots_summary(robots_info), "excerpt": text[:2000]})
                    sources.append(source("robots.txt", "http", "ok", robots_data["url"], f"HTTP 200, {len(rr.body)} bytes"))
                else:
                    robots_data.update({"status": "not_found", "groups": [], "sitemaps": []})
                    sources.append(source("robots.txt", "http", "unavailable", robots_data["url"], f"HTTP {rr.status}"))
            except (FetchError, TargetError) as exc:
                robots_data.update({"status": "error", "error": getattr(exc, "message", str(exc)), "groups": [], "sitemaps": []})
                sources.append(source("robots.txt", "http", "failed", robots_data["url"], robots_data["error"]))
        robots_cache.seed(final.origin, robots_info)

        # ------------------------------------------------------------------ sitemap
        sitemap_data: dict = {"status": "unavailable"}
        async with steps.step("sitemap"):
            sm_url = final.origin + "/sitemap.xml"
            for cand in robots_data.get("sitemaps", []):
                try:
                    if same_site(final.hostname, urlsplit(cand).hostname or ""):
                        sm_url = fetcher.parse(cand).url
                        break
                except TargetError:
                    continue
            sitemap_data["url"] = sm_url
            if robots_info is not None and not robots_info.allowed(urlsplit(sm_url).path or "/"):
                sitemap_data.update({"status": "skipped", "error": "Sitemap path is disallowed by robots.txt; not requested."})
                sources.append(source("sitemap.xml", "http", "skipped", sm_url, sitemap_data["error"]))
            else:
                try:
                    sr = await fetcher.fetch(sm_url, max_bytes=1_000_000, scope_host=final.hostname, accept="application/xml,text/xml,*/*;q=0.5")
                    sitemap_data["http_status"] = sr.status
                    if sr.status == 200:
                        sitemap_data.update(parse_sitemap(sr.body))
                        sitemap_data["truncated"] = sr.truncated
                        sources.append(source("sitemap.xml", "http", "ok" if sitemap_data["status"] == "parsed" else "failed", sm_url,
                                              sitemap_data.get("error") or f"{sitemap_data.get('url_count', 0)} URLs"))
                    else:
                        sitemap_data["status"] = "not_found"
                        sources.append(source("sitemap.xml", "http", "unavailable", sm_url, f"HTTP {sr.status}"))
                except (FetchError, TargetError) as exc:
                    sitemap_data.update({"status": "error", "error": getattr(exc, "message", str(exc))})
                    sources.append(source("sitemap.xml", "http", "failed", sm_url, sitemap_data["error"]))

        # ------------------------------------------------------------------ link check
        if check_links and links:
            async with steps.step("link_check"):
                def progress(done, total):
                    steps.detail("link_check", f"{done}/{total} links checked")
                await _check_links(fetcher, robots_cache, links, limit=limit, include_external=include_external,
                                   concurrency=settings.link_check_concurrency, on_progress=progress)
            sources.append(source("Link checks (HEAD)", "http", "ok", None,
                                  f"Up to {limit} links, external {'included' if include_external else 'excluded'}; robots.txt honoured."))
        else:
            for l in links:
                l["check"] = {"state": "not_checked", "reason": "disabled", "detail": "Link checking was not enabled."}
            steps.skip("link_check", "Link checking not enabled" if not check_links else "No links to check")

        # ------------------------------------------------------------------ assemble
        async with steps.step("finalise"):
            server_disclosure = None
            if res.headers.get("server") and any(ch.isdigit() for ch in res.headers["server"]):
                server_disclosure = f"Server: {res.headers['server'][:80]}"
            if res.headers.get("x-powered-by"):
                server_disclosure = (server_disclosure + "; " if server_disclosure else "") + f"X-Powered-By: {res.headers['x-powered-by'][:80]}"
            data = {
                "normalized_url": target.url,
                "scheme": final.scheme,
                "hostname": final.hostname,
                "final_url": res.final_url,
                "redirect_chain": [{"url": h.url, "status": h.status, "location": h.location, "followed": h.followed, "note": h.note} for h in res.hops],
                "http": {
                    "status": res.status, "reason": res.reason, "response_time_ms": res.elapsed_ms, "content_type": ctype or None,
                    "bytes_read": len(res.body), "truncated": res.truncated, "remote_ip": res.remote_ip,
                    "message": status_note,
                },
                "page": {"title": title, "meta": meta, "favicon": favicon, "server_disclosure": server_disclosure},
                "headers": {"selected": headers_selected, "security": sec, "cookies": cookies},
                "technologies": technologies,
                "links": links,
                "link_summary": summarise_links(links),
                "link_check": {"enabled": check_links, "external_included": include_external, "limit": limit},
                "links_discarded_over_cap": discarded,
                "robots": robots_data,
                "sitemap": sitemap_data,
                "requests_made": fetcher.request_count,
            }
            findings = _build_findings(data)
            if status_note:
                findings.insert(0, finding(MODULE, "reachability", f"HTTP {res.status}: access not fully available", status_note, severity="info", source="HTTP response"))
            status = "completed" if res.status < 400 else "partial"
            summary = {
                "headline": f"HTTP {res.status} · {data['link_summary']['discovered']} links · {len(technologies)} tech indicators",
                "http_status": res.status, "links": data["link_summary"]["discovered"], "requests_made": fetcher.request_count,
            }
        return ModuleOutput(data=data, findings=findings, sources=sources, errors=errors, status=status, summary=summary)
    finally:
        await fetcher.aclose()
