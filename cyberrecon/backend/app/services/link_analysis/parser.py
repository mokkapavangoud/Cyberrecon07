from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from app.security.target import same_site

_WS = re.compile(r"\s+")
LINK_ATTRS = [
    ("a", "href"), ("area", "href"), ("link", "href"), ("script", "src"), ("img", "src"),
    ("iframe", "src"), ("form", "action"), ("source", "src"), ("video", "src"), ("audio", "src"), ("embed", "src"),
]
_NON_HTTP = {"mailto": "mailto", "tel": "tel", "sms": "tel", "javascript": "javascript", "data": "data", "blob": "data"}


def clean_text(value: str | None, limit: int = 300) -> str | None:
    if value is None:
        return None
    v = _WS.sub(" ", value).strip()
    return v[:limit] if v else None


@dataclass
class ParsedLink:
    url: str
    kind: str
    sources: list[str] = field(default_factory=list)
    count: int = 0
    text: str | None = None


@dataclass
class ParsedPage:
    title: str | None
    meta: dict
    links: list[ParsedLink]
    asset_urls: list[str]
    favicon: str | None
    discarded_links: int = 0


def classify_link(url: str, page_host: str) -> str:
    sp = urlsplit(url)
    scheme = sp.scheme.lower()
    if scheme in ("http", "https"):
        host = (sp.hostname or "").lower()
        if not host:
            return "other"
        if same_site(page_host, host):
            h, p = host.removeprefix("www."), page_host.lower().removeprefix("www.")
            return "internal" if h == p else "subdomain"
        return "external"
    return _NON_HTTP.get(scheme, "other")


def parse_html(body: bytes, base_url: str, *, max_links: int = 2000) -> ParsedPage:
    soup = BeautifulSoup(body, "lxml")
    page_host = (urlsplit(base_url).hostname or "").lower()

    # <base href> is honoured only for http(s) results
    base = base_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        cand = urljoin(base_url, base_tag["href"].strip())
        if urlsplit(cand).scheme in ("http", "https"):
            base = cand

    title = clean_text(soup.title.get_text() if soup.title else None)

    def meta_content(**attrs):
        tag = soup.find("meta", attrs=attrs)
        return clean_text(tag.get("content")) if tag and tag.get("content") else None

    og, twitter = {}, {}
    for tag in soup.find_all("meta"):
        prop = (tag.get("property") or tag.get("name") or "").lower()
        content = clean_text(tag.get("content"), 300)
        if not content:
            continue
        if prop.startswith("og:") and len(og) < 20:
            og[prop[3:]] = content
        elif prop.startswith("twitter:") and len(twitter) < 20:
            twitter[prop[8:]] = content

    canonical = soup.find("link", rel=lambda r: r and "canonical" in (r if isinstance(r, list) else [r]))
    html_tag = soup.find("html")
    charset_tag = soup.find("meta", charset=True)
    meta = {
        "description": meta_content(name="description"),
        "keywords": meta_content(name="keywords"),
        "robots": meta_content(name="robots"),
        "generator": meta_content(name="generator"),
        "viewport": meta_content(name="viewport"),
        "author": meta_content(name="author"),
        "theme_color": meta_content(name="theme-color"),
        "canonical": urljoin(base, canonical["href"]) if canonical and canonical.get("href") else None,
        "lang": clean_text(html_tag.get("lang"), 20) if html_tag else None,
        "charset": clean_text(charset_tag.get("charset"), 30) if charset_tag else None,
        "open_graph": og,
        "twitter": twitter,
    }

    favicon = None
    icon = soup.find("link", rel=lambda r: r and any("icon" in x.lower() for x in (r if isinstance(r, list) else [r])))
    if icon and icon.get("href"):
        favicon = urljoin(base, icon["href"].strip())

    links: dict[str, ParsedLink] = {}
    asset_urls: list[str] = []
    discarded = 0
    for tag_name, attr in LINK_ATTRS:
        for el in soup.find_all(tag_name):
            raw = el.get(attr)
            if not raw or not isinstance(raw, str):
                continue
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("#"):
                kind, absolute = "fragment", "#"
            else:
                try:
                    absolute = urljoin(base, raw)
                except ValueError:
                    discarded += 1
                    continue
                sp = urlsplit(absolute)
                if sp.scheme in ("http", "https"):
                    absolute = urlunsplit((sp.scheme, sp.netloc, sp.path or "/", sp.query, ""))  # drop fragment
                else:
                    absolute = absolute[:300]
                kind = classify_link(absolute, page_host)
            if tag_name in ("script", "img", "link", "source", "video", "audio", "embed"):
                asset_urls.append(absolute)
            entry = links.get(absolute)
            if entry is None:
                if len(links) >= max_links:
                    discarded += 1
                    continue
                entry = links[absolute] = ParsedLink(url=absolute, kind=kind)
            entry.count += 1
            if tag_name not in entry.sources:
                entry.sources.append(tag_name)
            if tag_name == "a" and not entry.text:
                entry.text = clean_text(el.get_text(), 120)
    return ParsedPage(title=title, meta=meta, links=list(links.values()), asset_urls=asset_urls, favicon=favicon, discarded_links=discarded)


def summarise_links(links: list[dict]) -> dict:
    kinds: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for l in links:
        kinds[l["kind"]] = kinds.get(l["kind"], 0) + 1
        for s in l["sources"]:
            by_source[s] = by_source.get(s, 0) + 1
    checked = [l for l in links if l["check"]["state"] == "checked"]
    broken = [l for l in checked if (l["check"].get("status") or 0) >= 400]
    return {
        "discovered": len(links),
        "by_kind": kinds,
        "by_source": by_source,
        "checked": len(checked),
        "ok": len([l for l in checked if (l["check"].get("status") or 0) < 400]),
        "broken": len(broken),
        "blocked": len([l for l in links if l["check"]["state"] == "blocked"]),
        "skipped": len([l for l in links if l["check"]["state"] == "skipped"]),
        "failed": len([l for l in links if l["check"]["state"] == "failed"]),
        "not_checked": len([l for l in links if l["check"]["state"] == "not_checked"]),
    }
