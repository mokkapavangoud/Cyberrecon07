"""Module C: domain, DNS, IP, TLS and infrastructure intelligence (passive-first)."""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timezone

from app.integrations.registry import ProviderUnavailable
from app.integrations.rdap import registrable_domain
from app.security.safe_net import FetchError
from app.security.target import TargetError
from app.services.common import ModuleOutput, RunContext, finding, iso_now, source
from app.services.fingerprint import detect_technologies
from app.services.link_analysis.parser import parse_html

from .graph import build_graph

MODULE = "infrastructure"
STEPS = [
    ("validate", "Validate target"),
    ("dns", "Query DNS records"),
    ("registration", "Look up registration (RDAP)"),
    ("ip_intel", "Resolve IP ownership and network"),
    ("tls", "Inspect TLS certificate"),
    ("http", "Observe HTTP technology indicators"),
    ("subdomains", "Passive subdomain lookup"),
    ("graph", "Build relationship graph"),
]


def _days_until(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except ValueError:
        return None


async def _ip_intel(ip: str, fetcher_policy, prov, *, want_geo: bool) -> tuple[dict, list[dict]]:
    addr = ipaddress.ip_address(ip)
    entry: dict = {"ip": ip, "version": addr.version, "public": fetcher_policy.is_allowed(ip), "ptr": None, "asn": None, "network": None, "geo": None,
                   "asn_status": None, "network_status": None, "geo_status": None, "messages": {}}
    srcs: list[dict] = []
    if not entry["public"]:
        entry["messages"]["skipped"] = "Non-public address returned in DNS; no lookups were made against it."
        return entry, srcs

    async def asn():
        try:
            entry["asn"] = await prov.asn.lookup(ip)
            entry["asn_status"] = "ok"
        except ProviderUnavailable as exc:
            entry["asn_status"] = "unavailable"
            entry["messages"]["asn"] = str(exc)

    async def net():
        try:
            entry["network"] = await prov.rdap.lookup_ip(ip)
            entry["network_status"] = "ok"
        except ProviderUnavailable as exc:
            entry["network_status"] = "unavailable"
            entry["messages"]["network"] = str(exc)

    async def geo():
        if not want_geo:
            entry["geo_status"] = "skipped"
            return
        try:
            entry["geo"] = await prov.geoip.lookup(ip)
            entry["geo_status"] = "ok"
        except ProviderUnavailable as exc:
            entry["geo_status"] = "unavailable"
            entry["messages"]["geo"] = str(exc)

    async def ptr():
        r = await prov.dns.reverse(ip)
        if r["status"] == "ok" and r["values"]:
            entry["ptr"] = r["values"][0]["value"]

    await asyncio.gather(asn(), net(), geo(), ptr())
    return entry, srcs


async def _verify_subdomains(items: list[dict], dns, limit: int) -> None:
    sem = asyncio.Semaphore(8)

    async def one(item):
        async with sem:
            a = await dns.lookup(item["name"], "A")
            aaaa = await dns.lookup(item["name"], "AAAA") if a["status"] != "ok" else None
            addrs = [v["value"] for r in (a, aaaa) if r and r["status"] == "ok" for v in r["values"]]
            if addrs:
                item["verification"], item["resolves_to"] = "dns_resolved", addrs[:6]
            elif a["status"] in ("timeout", "error"):
                item["verification"] = "reported"
                item["verification_note"] = "DNS check failed; treated as unverified."
            else:
                item["verification"] = "dns_unresolved"

    await asyncio.gather(*(one(i) for i in items[:limit]))


def _dns_findings(d: dict) -> list[dict]:
    f: list[dict] = []
    recs = {(r["name"], r["type"]): r for r in d["dns"]["records"]}
    host, apex = d["hostname"], d.get("apex_domain") or d["hostname"]
    a, aaaa = recs.get((host, "A")), recs.get((host, "AAAA"))
    if a and a["status"] == "nxdomain":
        f.append(finding(MODULE, "dns", "Domain does not exist (NXDOMAIN)", f"The resolver reports no DNS records for {host}.", severity="low", source="DNS"))
        return f
    n_a = len(a["values"]) if a and a["status"] == "ok" else 0
    n_aaaa = len(aaaa["values"]) if aaaa and aaaa["status"] == "ok" else 0
    f.append(finding(MODULE, "dns", f"{n_a} IPv4 and {n_aaaa} IPv6 address record(s)", ", ".join(v["value"] for r in (a, aaaa) if r and r["status"] == "ok" for v in r["values"]) or "None returned.", source="DNS A/AAAA lookup"))
    if n_a and not n_aaaa:
        f.append(finding(MODULE, "dns", "No IPv6 (AAAA) records observed", "Only IPv4 addresses were returned.", source="DNS AAAA lookup"))
    ns = recs.get((apex, "NS"))
    if ns and ns["status"] == "ok":
        f.append(finding(MODULE, "dns", f"{len(ns['values'])} nameserver(s)", ", ".join(v["value"] for v in ns["values"]), severity="low" if len(ns["values"]) < 2 else "info", source="DNS NS lookup"))
    mx = recs.get((apex, "MX"))
    if mx and mx["status"] == "ok":
        f.append(finding(MODULE, "email", f"{len(mx['values'])} mail exchanger(s)", ", ".join(v["value"] for v in mx["values"][:6]), source="DNS MX lookup"))
    elif mx and mx["status"] == "no_answer":
        f.append(finding(MODULE, "email", "No MX records observed", f"{apex} does not publish mail exchangers.", source="DNS MX lookup"))
    txt = recs.get((apex, "TXT"))
    spf = [v["value"] for v in (txt["values"] if txt and txt["status"] == "ok" else []) if v["value"].lower().startswith("v=spf1")]
    if spf:
        f.append(finding(MODULE, "email", "SPF record published", spf[0][:300], source="DNS TXT lookup"))
    elif txt and txt["status"] in ("ok", "no_answer") and (mx and mx["status"] == "ok"):
        f.append(finding(MODULE, "email", "No SPF record observed", f"{apex} accepts mail (MX present) but no 'v=spf1' TXT record was returned.", severity="low", source="DNS TXT lookup"))
    dm = recs.get((f"_dmarc.{apex}", "TXT"))
    dmarc = [v["value"] for v in (dm["values"] if dm and dm["status"] == "ok" else []) if v["value"].upper().startswith("V=DMARC1")]
    if dmarc:
        f.append(finding(MODULE, "email", "DMARC record published", dmarc[0][:300], source="DNS TXT lookup (_dmarc)"))
    elif dm and dm["status"] in ("no_answer", "nxdomain") and (mx and mx["status"] == "ok"):
        f.append(finding(MODULE, "email", "No DMARC record observed", f"No 'v=DMARC1' record at _dmarc.{apex}.", severity="low", source="DNS TXT lookup (_dmarc)"))
    caa = recs.get((apex, "CAA"))
    if caa and caa["status"] == "no_answer":
        f.append(finding(MODULE, "dns", "No CAA records observed", "Any certificate authority may issue certificates unless CAA restricts it.", source="DNS CAA lookup"))
    return f


def _reg_findings(reg: dict) -> list[dict]:
    f: list[dict] = []
    if reg.get("status") == "found":
        f.append(finding(MODULE, "registration", f"Registrar: {reg.get('registrar') or 'not stated'}",
                         f"Created {reg.get('created') or 'n/a'}; expires {reg.get('expires') or 'n/a'}; status: {', '.join(reg.get('domain_status', [])) or 'n/a'}.",
                         evidence="third_party", source="RDAP"))
        days = _days_until(reg.get("expires"))
        if days is not None and days < 0:
            f.append(finding(MODULE, "registration", "Domain registration appears expired", f"Expiry date {reg['expires']} is in the past.", severity="medium", evidence="third_party", source="RDAP"))
        elif days is not None and days < 30:
            f.append(finding(MODULE, "registration", f"Domain registration expires in {days} days", reg["expires"], severity="medium", evidence="third_party", source="RDAP"))
        elif days is not None and days < 90:
            f.append(finding(MODULE, "registration", f"Domain registration expires in {days} days", reg["expires"], severity="low", evidence="third_party", source="RDAP"))
        if reg.get("registrant_redacted"):
            f.append(finding(MODULE, "registration", "Registrant details redacted", "Registrant contact data is not published (common under privacy regulation); none is shown.", evidence="third_party", source="RDAP"))
    return f


def _tls_findings(t: dict) -> list[dict]:
    f: list[dict] = []
    if t.get("status") != "ok":
        return f
    v = t["verification"]
    f.append(finding(MODULE, "tls", f"Certificate issued by {t.get('issuer_org') or t.get('issuer_cn') or 'unknown issuer'}",
                     f"Subject {t.get('subject_cn')}; valid {t['not_before'][:10]} → {t['not_after'][:10]}; {t['protocol']}.", source="TLS handshake"))
    if not v["ok"]:
        f.append(finding(MODULE, "tls", "Certificate failed verification", f"{v['error']}. Details below were read without trusting the certificate.", severity="medium", source="TLS handshake"))
    if t["expired"]:
        f.append(finding(MODULE, "tls", "Certificate has expired", f"Expired {t['not_after'][:10]}.", severity="high", source="TLS handshake"))
    elif t["days_remaining"] < 14:
        f.append(finding(MODULE, "tls", f"Certificate expires in {t['days_remaining']} days", t["not_after"], severity="medium", source="TLS handshake"))
    elif t["days_remaining"] < 30:
        f.append(finding(MODULE, "tls", f"Certificate expires in {t['days_remaining']} days", t["not_after"], severity="low", source="TLS handshake"))
    if not t["hostname_match"]:
        f.append(finding(MODULE, "tls", "Certificate does not cover the hostname", f"SANs: {', '.join(t['san'][:6]) or 'none'}.", severity="medium", source="TLS handshake"))
    if t["self_signed"]:
        f.append(finding(MODULE, "tls", "Self-signed certificate", "Issuer and subject are identical.", severity="medium", source="TLS handshake"))
    pk = t["public_key"]
    if pk["type"] == "RSA" and pk["bits"] and pk["bits"] < 2048:
        f.append(finding(MODULE, "tls", f"Weak RSA key ({pk['bits']} bits)", "RSA keys under 2048 bits are considered weak.", severity="medium", source="TLS handshake"))
    if t.get("signature_hash") in ("sha1", "md5"):
        f.append(finding(MODULE, "tls", f"Certificate signed with {t['signature_hash'].upper()}", "Deprecated signature hash.", severity="medium", source="TLS handshake"))
    return f


async def run(ctx: RunContext, params: dict) -> ModuleOutput:
    settings, steps, prov = ctx.settings, ctx.steps, ctx.providers
    opts = params.get("options", {})
    want_sub, want_http, want_geo = opts.get("include_subdomains", True), opts.get("include_http", True), opts.get("include_geoip", True)
    sources: list[dict] = []
    errors: list[dict] = []
    findings: list[dict] = []
    fetcher = ctx.fetcher_factory()
    statuses: list[str] = []

    try:
        async with steps.step("validate"):
            target = fetcher.parse(params["target"])
            host, is_ip = target.hostname, target.is_ip_literal
            apex = None if is_ip else registrable_domain(host)
            steps.detail("validate", f"{'IP address' if is_ip else 'Hostname'} {host}" + (f" · registrable domain {apex}" if apex and apex != host else ""))

        d: dict = {"hostname": host, "apex_domain": apex, "is_ip_target": is_ip, "scheme": target.scheme,
                   "dns": {"resolver": prov.dns.resolver_label, "queried_at": iso_now(), "records": []},
                   "registration": {"status": "skipped"}, "ips": [], "tls": {"status": "skipped"}, "http": {"status": "skipped"},
                   "technologies": [], "subdomains": {"status": "skipped", "items": []}}

        # ---------------------------------------------------------------- DNS
        ips_found: list[str] = []
        async with steps.step("dns"):
            if is_ip:
                ptr = await prov.dns.reverse(host)
                d["dns"]["records"] = [ptr]
                ips_found = [host]
                sources.append(source("DNS (PTR)", "dns", "ok" if ptr["status"] in ("ok", "no_answer", "nxdomain") else "failed", None, ptr.get("error") or f"PTR lookup: {ptr['status']}"))
            else:
                queries = [prov.dns.lookup_many(host, ["A", "AAAA", "CNAME"] if host != apex else ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"])]
                if apex:
                    base = apex
                    if host != apex:
                        queries.append(prov.dns.lookup_many(apex, ["MX", "NS", "TXT", "SOA", "CAA"]))
                    queries.append(prov.dns.lookup_many(f"_dmarc.{base}", ["TXT"]))
                results = await asyncio.gather(*queries)
                d["dns"]["records"] = [r for group in results for r in group]
                recs = d["dns"]["records"]
                if all(r["status"] in ("timeout", "error") for r in recs):
                    msg = recs[0].get("error") or "DNS lookups did not complete."
                    steps.fail_step("dns", msg)
                    errors.append({"step": "dns", "code": "dns_unavailable", "message": msg})
                    sources.append(source("DNS", "dns", "failed", None, msg))
                    statuses.append("dns_failed")
                else:
                    sources.append(source(f"DNS via {d['dns']['resolver']}", "dns", "ok", None, f"{len(recs)} queries"))
                for r in recs:
                    if r["name"] == host and r["type"] in ("A", "AAAA") and r["status"] == "ok":
                        ips_found += [v["value"] for v in r["values"]]
                ips_found = list(dict.fromkeys(ips_found))
            steps.detail("dns", f"{len(d['dns']['records'])} queries; {len(ips_found)} address(es)")
        if "dns_failed" in statuses:
            for k in ("registration", "ip_intel", "tls", "http", "subdomains"):
                steps.skip(k, "DNS was unavailable")
            d["graph"] = build_graph({**d, "ips": []})
            return ModuleOutput(data=d, sources=sources, errors=errors, status="failed",
                                findings=[finding(MODULE, "dns", "DNS lookups could not be completed", errors[0]["message"], source="DNS")],
                                summary={"headline": "DNS unavailable", "error": "dns_unavailable"})
        findings += _dns_findings(d) if not is_ip else []

        # ---------------------------------------------------------------- registration
        if is_ip:
            steps.skip("registration", "Not applicable to IP targets")
        else:
            async with steps.step("registration"):
                try:
                    d["registration"] = await prov.rdap.lookup_domain(host)
                    sources.append(source("RDAP", "rdap", "ok" if d["registration"]["status"] == "found" else "unavailable", d["registration"].get("source"),
                                          d["registration"].get("message") or "Registration data retrieved."))
                except ProviderUnavailable as exc:
                    d["registration"] = {"status": "unavailable", "message": str(exc)}
                    sources.append(source("RDAP", "rdap", "unavailable", None, str(exc)))
                    steps.detail("registration", str(exc))
                findings += _reg_findings(d["registration"])

        # ---------------------------------------------------------------- IP intelligence
        async with steps.step("ip_intel"):
            entries = await asyncio.gather(*(_ip_intel(ip, fetcher.policy, prov, want_geo=want_geo) for ip in ips_found[:8]))
            d["ips"] = [e for e, _ in entries]
            if len(ips_found) > 8:
                d["ips_truncated"] = len(ips_found) - 8
            asn_ok = any(e["asn_status"] == "ok" for e in d["ips"])
            sources.append(source(prov.asn.name, "asn", "ok" if asn_ok else ("unavailable" if d["ips"] else "skipped"), getattr(prov.asn, "reference", None),
                                  next((e["messages"]["asn"] for e in d["ips"] if "asn" in e["messages"]), None)))
            net_ok = any(e["network_status"] == "ok" for e in d["ips"])
            sources.append(source("RDAP (IP network)", "rdap", "ok" if net_ok else ("unavailable" if d["ips"] else "skipped"), "https://rdap.org/",
                                  next((e["messages"]["network"] for e in d["ips"] if "network" in e["messages"]), None)))
            geo_ok = any(e["geo_status"] == "ok" for e in d["ips"])
            sources.append(source(getattr(prov.geoip, "name", "GeoIP"), "geoip", "ok" if geo_ok else ("skipped" if not want_geo else "unavailable"), getattr(prov.geoip, "reference", None),
                                  next((e["messages"]["geo"] for e in d["ips"] if "geo" in e["messages"]), None)))
            for e in d["ips"]:
                if not e["public"]:
                    findings.append(finding(MODULE, "ip", f"DNS returned a non-public address: {e['ip']}", "This address was not contacted. Public DNS pointing at private ranges can expose internal addressing.", severity="low", source="DNS"))
                    continue
                a = e["asn"] or {}
                if a.get("asn"):
                    findings.append(finding(MODULE, "ip", f"{e['ip']} is announced by AS{a['asn']}" + (f" ({a['name']})" if a.get("name") else ""),
                                            f"Prefix {a.get('prefix')}; registry {a.get('registry') or 'n/a'}. Reported by Team Cymru's public IP-to-ASN service.", evidence="third_party", source="Team Cymru IP-to-ASN"))
                n = e["network"] or {}
                if n.get("status") == "found" and (n.get("name") or n.get("organizations")):
                    findings.append(finding(MODULE, "ip", f"Network {n.get('name') or n.get('handle')} for {e['ip']}",
                                            f"{', '.join(n.get('organizations', [])) or 'No organisation published'}; country {n.get('country') or 'n/a'}.", evidence="third_party", source="RDAP (IP)"))
                g = e["geo"]
                if g:
                    findings.append(finding(MODULE, "geolocation", f"Estimated location for {e['ip']}: {', '.join(x for x in (g.get('city'), g.get('region'), g.get('country')) if x) or 'unknown'}",
                                            g["note"], evidence="estimate", source=g["provider"]))

        # ---------------------------------------------------------------- TLS
        if is_ip:
            steps.skip("tls", "Not performed for IP targets (no hostname to validate against)")
        else:
            async with steps.step("tls"):
                d["tls"] = await prov.tls.probe(host, 443)
                st = "ok" if d["tls"]["status"] == "ok" else ("unavailable" if d["tls"]["status"] == "unavailable" else "failed")
                sources.append(source("TLS handshake (port 443)", "http", st, f"{host}:443", d["tls"].get("error")))
                if d["tls"]["status"] != "ok":
                    steps.detail("tls", d["tls"].get("error", "TLS not available"))
                findings += _tls_findings(d["tls"])

        # ---------------------------------------------------------------- HTTP indicators
        if not want_http or is_ip:
            steps.skip("http", "Disabled" if not want_http else "Not performed for IP targets")
        else:
            async with steps.step("http"):
                candidates = [target.origin + "/"] if target.port not in (80, 443) or "://" in params["target"] else [f"https://{host}/", f"http://{host}/"]
                last_err = None
                for url in candidates:
                    try:
                        res = await fetcher.fetch(url, scope_host=host, max_bytes=300_000)
                    except (FetchError, TargetError) as exc:
                        last_err = getattr(exc, "message", str(exc))
                        continue
                    html = res.body.decode("utf-8", "replace") if "html" in res.headers.get("content-type", "") else ""
                    page = parse_html(res.body, res.final_url, max_links=300) if html else None
                    techs = detect_technologies(res.headers, generator=(page.meta.get("generator") if page else None), html_sample=html, asset_urls=page.asset_urls if page else [])
                    d["http"] = {"status": "ok", "url": url, "final_url": res.final_url, "http_status": res.status, "server": res.headers.get("server"), "remote_ip": res.remote_ip,
                                 "response_time_ms": res.elapsed_ms}
                    d["technologies"] = techs
                    sources.append(source("HTTP request (single GET /)", "http", "ok", url, f"HTTP {res.status}"))
                    for t in techs:
                        findings.append(finding(MODULE, "technology", f"Technology indicator: {t['name']}" + (f" {t['version']}" if t.get("version") else ""),
                                                "; ".join(t["evidence"]) + ". Indicators are hints, not definitive.", source="Headers and page markup"))
                    break
                else:
                    d["http"] = {"status": "unavailable", "message": last_err or "No HTTP response."}
                    sources.append(source("HTTP request (single GET /)", "http", "failed", candidates[0], d["http"]["message"]))
                    steps.detail("http", d["http"]["message"])

        # ---------------------------------------------------------------- subdomains
        if is_ip or not want_sub:
            steps.skip("subdomains", "Not applicable to IP targets" if is_ip else "Disabled for this assessment")
        else:
            async with steps.step("subdomains"):
                try:
                    res = await prov.subdomains.fetch(apex or host)
                    items = [{"name": i["name"], "sources": [res["provider"]], "verification": "reported"} for i in res["items"]]
                    await _verify_subdomains(items, prov.dns, settings.subdomain_verify_limit)
                    checked = min(len(items), settings.subdomain_verify_limit)
                    d["subdomains"] = {"status": "ok", "provider": res["provider"], "reference": res["reference"], "basis": res["basis"], "items": items,
                                       "total_reported": res["total_reported"], "truncated": res["truncated"], "dns_checked": checked,
                                       "dns_resolved": len([i for i in items if i["verification"] == "dns_resolved"])}
                    sources.append(source(res["provider"], "ct", "ok", res["reference"], f"{res['total_reported']} names reported; {checked} checked via DNS"))
                    findings.append(finding(MODULE, "subdomains", f"{res['total_reported']} subdomain(s) reported by {res['provider']}",
                                            f"{d['subdomains']['dns_resolved']} of the first {checked} resolved in DNS during this assessment. {res['basis']}", evidence="third_party", source=res["provider"]))
                except ProviderUnavailable as exc:
                    d["subdomains"] = {"status": "unavailable", "message": str(exc), "items": []}
                    sources.append(source("Passive subdomain provider", "ct", "unavailable", None, str(exc)))
                    steps.detail("subdomains", str(exc))

        # ---------------------------------------------------------------- graph
        async with steps.step("graph"):
            d["graph"] = build_graph(d)
            steps.detail("graph", f"{len(d['graph']['nodes'])} nodes, {len(d['graph']['edges'])} edges")

        failed_sources = [s for s in sources if s["status"] in ("failed", "unavailable")]
        status = "partial" if failed_sources else "completed"
        d["limitations"] = [
            "DNS answers can differ by resolver, location and time (CDNs, load balancing).",
            "RDAP/WHOIS data is reported by registries and may be redacted. ASN data comes from Team Cymru's public service.",
            "IP geolocation is an estimate and does not identify a person's physical location.",
            "Technology indicators are inferred from headers and markup and are not definitive.",
            "Subdomains from passive sources are reported, not guaranteed to exist; only those marked 'dns_resolved' resolved when checked.",
        ]
        summary = {"headline": f"{len(ips_found)} IP(s) · {len(d['graph']['nodes'])} graph nodes" + (f" · cert {d['tls']['days_remaining']}d left" if d["tls"].get("status") == "ok" else ""),
                   "ips": len(ips_found), "nodes": len(d["graph"]["nodes"]), "unavailable_sources": len(failed_sources)}
        return ModuleOutput(data=d, findings=findings, sources=sources, errors=errors, status=status, summary=summary)
    finally:
        await fetcher.aclose()
