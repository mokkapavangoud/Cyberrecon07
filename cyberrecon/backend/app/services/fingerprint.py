"""Passive technology indicators. These are hints from headers and page markup, never definitive."""
from __future__ import annotations

import re

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "low", True),
    ("content-security-policy", "Content-Security-Policy", "low", False),
    ("x-frame-options", "X-Frame-Options", "info", False),
    ("x-content-type-options", "X-Content-Type-Options", "info", False),
    ("referrer-policy", "Referrer-Policy", "info", False),
    ("permissions-policy", "Permissions-Policy", "info", False),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "info", False),
]

INTERESTING_HEADERS = [
    "server", "x-powered-by", "content-type", "content-length", "content-encoding", "cache-control", "etag",
    "last-modified", "date", "expires", "vary", "via", "location", "x-generator", "x-aspnet-version",
    "x-request-id", "alt-svc", "retry-after", "x-frame-options", "x-content-type-options",
    "strict-transport-security", "content-security-policy", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy",
    "access-control-allow-origin", "x-xss-protection", "report-to", "nel",
]

_HEADER_RULES = [
    ("cf-ray", "Cloudflare", "CDN / edge", "medium"),
    ("x-amz-cf-id", "Amazon CloudFront", "CDN / edge", "medium"),
    ("x-amz-cf-pop", "Amazon CloudFront", "CDN / edge", "medium"),
    ("x-vercel-id", "Vercel", "Hosting platform", "medium"),
    ("x-nf-request-id", "Netlify", "Hosting platform", "medium"),
    ("fly-request-id", "Fly.io", "Hosting platform", "medium"),
    ("x-github-request-id", "GitHub Pages", "Hosting platform", "medium"),
    ("x-shopify-stage", "Shopify", "E-commerce platform", "medium"),
    ("x-drupal-cache", "Drupal", "CMS", "medium"),
    ("x-aspnet-version", "ASP.NET", "Framework", "medium"),
    ("x-aspnetmvc-version", "ASP.NET MVC", "Framework", "medium"),
    ("x-akamai-transformed", "Akamai", "CDN / edge", "low"),
    ("x-served-by", "Fastly (possible)", "CDN / edge", "low"),
]

_HTML_RULES = [
    (r"/wp-content/|/wp-includes/", "WordPress", "CMS", "medium"),
    (r"/_next/static/", "Next.js", "Framework", "medium"),
    (r"/_nuxt/", "Nuxt", "Framework", "medium"),
    (r"cdn\.shopify\.com", "Shopify", "E-commerce platform", "medium"),
    (r"static\.squarespace\.com", "Squarespace", "Website builder", "medium"),
    (r"static\.wixstatic\.com|static\.parastorage\.com", "Wix", "Website builder", "medium"),
    (r"ajax\.googleapis\.com/ajax/libs/jquery|/jquery[.-][\d.]*(min\.)?js", "jQuery", "JavaScript library", "low"),
    (r"googletagmanager\.com", "Google Tag Manager", "Tag management", "medium"),
    (r"google-analytics\.com|gtag/js", "Google Analytics", "Analytics", "medium"),
    (r"fonts\.googleapis\.com", "Google Fonts", "Font service", "medium"),
    (r"cdn\.jsdelivr\.net", "jsDelivr CDN", "CDN / edge", "low"),
    (r"cdnjs\.cloudflare\.com", "cdnjs", "CDN / edge", "low"),
    (r"bootstrap[.-][\d.]*(min\.)?(css|js)|/bootstrap/", "Bootstrap", "UI framework", "low"),
    (r"reactroot|data-reactroot|react-dom", "React", "JavaScript library", "low"),
    (r"ng-version=|ng-app", "Angular", "JavaScript framework", "low"),
    (r"data-v-[0-9a-f]{6,}|__vue__", "Vue.js", "JavaScript framework", "low"),
]

_VERSION_RE = re.compile(r"^([A-Za-z][\w .\-]*?)[/ ]([\d][\w.\-]*)")


def detect_technologies(headers: dict[str, str], *, generator: str | None, html_sample: str, asset_urls: list[str]) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name, category, confidence, evidence, version=None):
        key = f"{name}|{category}"
        entry = found.get(key)
        if entry:
            entry["evidence"].append(evidence)
            if version and not entry.get("version"):
                entry["version"] = version
            return
        found[key] = {"name": name, "category": category, "confidence": confidence, "evidence": [evidence], "version": version}

    server = headers.get("server")
    if server:
        m = _VERSION_RE.match(server)
        name, version = (m.group(1).strip(), m.group(2)) if m else (server.split("/")[0], None)
        add(name or server, "Web server / edge", "medium", f"Server header: {server[:80]}", version)
        if server.lower().startswith("cloudflare"):
            add("Cloudflare", "CDN / edge", "medium", "Server header: cloudflare")
    xpb = headers.get("x-powered-by")
    if xpb:
        m = _VERSION_RE.match(xpb)
        add(m.group(1).strip() if m else xpb[:40], "Language / runtime", "medium", f"X-Powered-By header: {xpb[:80]}", m.group(2) if m else None)
    xgen = headers.get("x-generator")
    if xgen:
        add(xgen.split()[0][:40], "CMS / generator", "medium", f"X-Generator header: {xgen[:80]}")
    for hname, tech, cat, conf in _HEADER_RULES:
        if hname in headers:
            add(tech, cat, conf, f"Response header present: {hname}")
    if generator:
        m = _VERSION_RE.match(generator)
        add(m.group(1).strip() if m else generator[:40], "CMS / generator", "medium", f"<meta name=generator>: {generator[:80]}", m.group(2) if m else None)

    haystack = html_sample[:200_000] + "\n" + "\n".join(asset_urls[:400])
    for pattern, tech, cat, conf in _HTML_RULES:
        m = re.search(pattern, haystack, re.I)
        if m:
            add(tech, cat, conf, f"Page markup/assets reference: {m.group(0)[:60]}")

    out = list(found.values())
    for t in out:
        t["evidence"] = t["evidence"][:4]
    return sorted(out, key=lambda t: (t["category"], t["name"]))


def analyse_security_headers(headers: dict[str, str], *, https: bool) -> list[dict]:
    out = []
    for key, label, severity, https_only in SECURITY_HEADERS:
        if https_only and not https:
            out.append({"name": key, "label": label, "present": key in headers, "value": headers.get(key), "applicable": False,
                        "severity": "info", "note": "Only meaningful over HTTPS."})
            continue
        present = key in headers
        note = None
        if key == "strict-transport-security" and present:
            m = re.search(r"max-age=(\d+)", headers[key], re.I)
            if m and int(m.group(1)) < 15_552_000:
                note = "max-age is shorter than 180 days."
        out.append({"name": key, "label": label, "present": present, "value": (headers.get(key) or None) and headers[key][:300],
                    "applicable": True, "severity": severity if not present else "info", "note": note})
    return out


def parse_set_cookies(raw_headers: list[tuple[str, str]]) -> list[dict]:
    """Return cookie names and attribute flags only. Values are never stored."""
    cookies = []
    for k, v in raw_headers:
        if k.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in v.split(";")]
        name = parts[0].split("=", 1)[0][:80]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": str(attrs.get("samesite")) if "samesite" in attrs else None,
            "path": str(attrs.get("path")) if "path" in attrs else None,
        })
    return cookies[:50]
