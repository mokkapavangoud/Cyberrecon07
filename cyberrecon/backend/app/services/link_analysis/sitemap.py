"""Sitemap parsing with XXE hardening: DTDs/entities are rejected outright and never resolved."""
from __future__ import annotations

from lxml import etree

MAX_SAMPLE = 25


def parse_sitemap(body: bytes, *, max_urls: int = 50_000) -> dict:
    head = body[:4096].lower()
    if b"<!entity" in body[:20_000].lower() or b"<!doctype" in head:
        return {"status": "rejected", "error": "Document declares a DTD or entities; not parsed for safety."}
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False, recover=False)
    try:
        root = etree.fromstring(body, parser=parser)
    except etree.XMLSyntaxError as exc:
        return {"status": "invalid", "error": f"Not valid XML: {str(exc)[:160]}"}
    tag = etree.QName(root).localname.lower()
    locs = []
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        if etree.QName(el).localname == "loc" and el.text:
            locs.append(el.text.strip()[:500])
            if len(locs) >= max_urls:
                break
    if tag == "sitemapindex":
        return {"status": "parsed", "type": "sitemapindex", "url_count": 0, "child_sitemaps": len(locs), "sample": locs[:MAX_SAMPLE],
                "note": "Child sitemaps were listed but not fetched."}
    if tag == "urlset":
        return {"status": "parsed", "type": "urlset", "url_count": len(locs), "child_sitemaps": 0, "sample": locs[:MAX_SAMPLE], "note": None}
    return {"status": "invalid", "error": f"Unexpected root element <{tag}>."}
