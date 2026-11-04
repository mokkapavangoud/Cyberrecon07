"""PDF report generation (reportlab).

Security: reportlab's Paragraph parses a mini-HTML dialect (including <img src=...> and <font>), so EVERY
piece of data that did not originate from this file goes through ``esc`` before it reaches a Paragraph.
"""
from __future__ import annotations

import io
import re
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

FONT_DIR = Path(__file__).resolve().parents[2] / "assets" / "fonts"
INK, MUTED, EMERALD, CYAN, LINE, PANEL = (colors.HexColor(c) for c in ("#0b1210", "#5b6b66", "#0f9d74", "#0891b2", "#d5dedb", "#f2f6f5"))
SEV_COLOR = {"info": colors.HexColor("#5b6b66"), "low": colors.HexColor("#a16207"), "medium": colors.HexColor("#c2410c"), "high": colors.HexColor("#b91c1c")}
EVIDENCE_LABEL = {"observed": "Observed facts", "third_party": "Third-party reports", "estimate": "Estimates"}
EVIDENCE_NOTE = {
    "observed": "Directly retrieved or measured by CyberRecon during this assessment.",
    "third_party": "Reported by an external source (registry, DNS-based data service, certificate-transparency index). Not independently verified.",
    "estimate": "Approximations (for example IP geolocation). Not reliable evidence of a physical location.",
}
MODULE_TITLE = {"link": "Website footprint & link intelligence", "image": "Image intelligence", "infrastructure": "Domain, DNS & infrastructure intelligence", "screenshot": "Website screenshot"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")
_fonts = {"ok": False}


def register_fonts() -> tuple[str, str, str]:
    if not _fonts["ok"]:
        try:
            pdfmetrics.registerFont(TTFont("DejaVu", str(FONT_DIR / "DejaVuSans.ttf")))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))
            pdfmetrics.registerFont(TTFont("DejaVu-Mono", str(FONT_DIR / "DejaVuSansMono.ttf")))
            pdfmetrics.registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold", italic="DejaVu", boldItalic="DejaVu-Bold")
            _fonts["ok"] = True
        except Exception:
            _fonts["ok"] = False
    return ("DejaVu", "DejaVu-Bold", "DejaVu-Mono") if _fonts["ok"] else ("Helvetica", "Helvetica-Bold", "Courier")


def esc(value, limit: int = 600) -> str:
    """Escape untrusted text for use inside a reportlab Paragraph."""
    if value is None:
        return "—"
    s = _CTRL.sub("", str(value))
    if len(s) > limit:
        s = s[:limit] + "…"
    return escape(s)


def make_styles():
    regular, bold, mono = register_fonts()
    base = dict(fontName=regular, textColor=INK, leading=13, fontSize=9, alignment=TA_LEFT, wordWrap="CJK")
    return {
        "title": ParagraphStyle("title", **{**base, "fontName": bold, "fontSize": 20, "leading": 25}),
        "h1": ParagraphStyle("h1", **{**base, "fontName": bold, "fontSize": 13, "leading": 17, "spaceBefore": 14, "spaceAfter": 6, "textColor": EMERALD}),
        "h2": ParagraphStyle("h2", **{**base, "fontName": bold, "fontSize": 10, "leading": 14, "spaceBefore": 8, "spaceAfter": 3}),
        "body": ParagraphStyle("body", **{**base, "spaceAfter": 4}),
        "small": ParagraphStyle("small", **{**base, "fontSize": 7.5, "leading": 10, "textColor": MUTED}),
        "cell": ParagraphStyle("cell", **{**base, "fontSize": 7.8, "leading": 10}),
        "cellb": ParagraphStyle("cellb", **{**base, "fontName": bold, "fontSize": 7.8, "leading": 10}),
        "mono": ParagraphStyle("mono", **{**base, "fontName": mono, "fontSize": 7.3, "leading": 9.5}),
        "head": ParagraphStyle("head", **{**base, "fontName": bold, "fontSize": 7.8, "leading": 10, "textColor": colors.white}),
    }


class Builder:
    def __init__(self, a: dict, *, demo: bool, screenshot_path: Path | None):
        self.a, self.demo, self.shot = a, demo, screenshot_path
        self.s = make_styles()
        self.story: list = []

    # -- primitives
    def P(self, text, style="body", limit=600):
        return Paragraph(esc(text, limit), self.s[style])

    def h1(self, text):
        self.story.append(self.P(text, "h1"))

    def h2(self, text):
        self.story.append(self.P(text, "h2"))

    def para(self, text, style="body"):
        self.story.append(self.P(text, style, 2000))

    def table(self, header, rows, widths, *, mono_cols=(), limit=300, repeat=1):
        data = [[Paragraph(esc(h), self.s["head"]) for h in header]]
        for r in rows:
            data.append([Paragraph(esc(c, limit), self.s["mono" if i in mono_cols else "cell"]) for i, c in enumerate(r)])
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=repeat)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INK), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        self.story.append(t)
        self.story.append(Spacer(1, 4))

    def kv(self, rows, widths=(48, 122)):
        data = [[Paragraph(esc(k), self.s["cellb"]), Paragraph(esc(v, 800), self.s["cell"])] for k, v in rows if v not in (None, "")]
        if not data:
            return
        t = Table(data, colWidths=[w * mm for w in widths])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE), ("BACKGROUND", (0, 0), (0, -1), PANEL),
                               ("LEFTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        self.story.append(t)
        self.story.append(Spacer(1, 4))

    # -- sections
    def cover(self):
        a = self.a
        self.story.append(self.P("CYBERRECON", "small"))
        self.story.append(self.P("Assessment report", "title"))
        self.story.append(self.P(MODULE_TITLE.get(a["module"], a["module"]), "h2"))
        if self.demo:
            self.story.append(Spacer(1, 4))
            t = Table([[Paragraph(esc("SIMULATED DEMO DATA — this report describes a fictional target and does not reflect any real assessment."), self.s["cellb"])]], colWidths=[170 * mm])
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")), ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#b45309")), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
            self.story.append(t)
        self.story.append(Spacer(1, 6))
        auth = a["authorization"]
        self.kv([
            ("Assessment ID", a["id"]), ("Target" if a["module"] != "image" else "Uploaded file", a["target"]), ("Module", MODULE_TITLE.get(a["module"], a["module"])),
            ("Status", a["status"]), ("Assessment date (UTC)", a.get("started_at") or a.get("created_at")), ("Finished (UTC)", a.get("finished_at")),
            ("Duration", f"{a['duration_ms']} ms" if a.get("duration_ms") is not None else None),
            ("Authorisation", ("Confirmed at " + (auth.get("confirmed_at") or "n/a") + ". " + (auth.get("statement") or "")) if auth["confirmed"] else
             ("Not applicable: local analysis of a file supplied by the user." if a["module"] == "image" else "Not recorded")),
            ("Scope", self._scope_text()),
        ])

    def _scope_text(self):
        sc = self.a.get("scope") or {}
        if not sc:
            return None
        return "; ".join(f"{k}: {v}" for k, v in sc.items())

    def summary(self):
        a = self.a
        self.h1("1. Summary")
        c = Counter(f["severity"] for f in a["findings"])
        self.para(a["summary"].get("headline") or "No headline recorded.")
        self.para(f"{len(a['findings'])} finding(s) recorded — high: {c['high']}, medium: {c['medium']}, low: {c['low']}, informational: {c['info']}. "
                  "Severity reflects how much attention an item may deserve, not a confirmed vulnerability.")
        if a.get("error"):
            self.para("Assessment error: " + a["error"])

    def methods(self):
        self.h1("2. Methods used")
        m = self.a["module"]
        text = {
            "link": ["One HTTP GET to the target page, one GET to /robots.txt and one to a sitemap, all through a request guard that validates every resolved address and redirect.",
                     "Metadata, links, headers and technology indicators were parsed from the response. Links were only requested if link checking was enabled, and then only a capped number via HEAD, honouring robots.txt.",
                     "Links listed as 'not checked' were discovered in the page source but never requested."],
            "image": ["The file was analysed locally in memory: content sniffing, structural validation and metadata extraction (EXIF, GPS, XMP, IPTC, ICC, text chunks).",
                      "The image was not uploaded to any third party. Reverse-image-search links are plain links; the user chooses whether to upload."],
            "infrastructure": ["Public DNS queries (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA), RDAP registration lookup, Team Cymru ASN lookup, RDAP network lookup, an optional GeoIP provider, one TLS handshake and at most two HTTP GET requests for technology indicators.",
                               "Subdomains come only from a passive third-party source; reported names were checked with DNS lookups only. No brute forcing or port scanning was performed."],
            "screenshot": ["A single page load in an isolated headless Chromium instance with every request filtered through the CyberRecon network policy."],
        }[m]
        for t in text:
            self.para("• " + t)
        if self.a["options"]:
            self.para("Options: " + ", ".join(f"{k}={v}" for k, v in self.a["options"].items()), "small")

    def findings(self):
        self.h1("3. Findings")
        if not self.a["findings"]:
            self.para("No findings were recorded.")
            return
        for ev in ("observed", "third_party", "estimate"):
            items = [f for f in self.a["findings"] if f["evidence_type"] == ev]
            if not items:
                continue
            self.h2(f"{EVIDENCE_LABEL[ev]} ({len(items)})")
            self.para(EVIDENCE_NOTE[ev], "small")
            rows = [[f["severity"].upper(), f["title"], f["detail"], f["source"]] for f in items[:200]]
            self.table(["Severity", "Finding", "Detail", "Source"], rows, [17, 55, 68, 30])

    def details(self):
        self.h1("4. Detailed results")
        r = self.a.get("result") or {}
        {"link": self._link, "image": self._image, "infrastructure": self._infra, "screenshot": self._shot}[self.a["module"]](r)

    def _link(self, r):
        if not r or r.get("fetch_error"):
            self.para("The target could not be fetched: " + ((r or {}).get("fetch_error") or {}).get("message", "unknown error"))
            return
        h = r["http"]
        self.h2("HTTP response")
        self.kv([("Normalised URL", r["normalized_url"]), ("Final URL", r["final_url"]), ("Status", f"{h['status']} {h['reason']}"), ("Response time", f"{h['response_time_ms']} ms"),
                 ("Content type", h.get("content_type")), ("Bytes read", f"{h['bytes_read']:,}" + (" (truncated at limit)" if h["truncated"] else "")), ("Connected IP", h.get("remote_ip")),
                 ("Page title", r["page"].get("title")), ("Meta description", r["page"]["meta"].get("description")), ("HTTP requests made", r.get("requests_made"))])
        if len(r["redirect_chain"]) > 1 or any(x.get("note") for x in r["redirect_chain"]):
            self.h2("Redirect chain")
            self.table(["URL", "Status", "Followed", "Note"], [[x["url"], x["status"], "yes" if x["followed"] else "no", x.get("note")] for x in r["redirect_chain"]], [78, 14, 16, 62], mono_cols=(0,))
        self.h2("Security-relevant response headers")
        self.table(["Header", "Present", "Value / note"], [[x["label"], "yes" if x["present"] else ("n/a" if not x["applicable"] else "no"), x.get("value") or x.get("note")] for x in r["headers"]["security"]], [50, 18, 102])
        if r["headers"]["cookies"]:
            self.h2("Cookies (names and attributes only; values are never stored)")
            self.table(["Name", "Secure", "HttpOnly", "SameSite"], [[c["name"], c["secure"], c["httponly"], c.get("samesite")] for c in r["headers"]["cookies"]], [70, 30, 30, 40])
        if r["technologies"]:
            self.h2("Technology indicators (hints only, not definitive)")
            self.table(["Technology", "Category", "Confidence", "Evidence"], [[t["name"] + (f" {t['version']}" if t.get("version") else ""), t["category"], t["confidence"], "; ".join(t["evidence"])] for t in r["technologies"]], [38, 32, 20, 80])
        self.h2("robots.txt and sitemap")
        rb, sm = r["robots"], r["sitemap"]
        self.kv([("robots.txt", f"{rb['status']} ({rb.get('url')})"), ("robots.txt groups", len(rb.get("groups", []))), ("Sitemap references", ", ".join(rb.get("sitemaps", [])) or None),
                 ("sitemap.xml", f"{sm['status']} ({sm.get('url')})"), ("Sitemap URLs", sm.get("url_count")), ("Sitemap note", sm.get("error") or sm.get("note"))])
        ls = r["link_summary"]
        self.h2("Links: discovered vs checked")
        self.para(f"{ls['discovered']} unique links were discovered in the page source. {ls['checked']} were actively checked (HTTP request sent); "
                  f"{ls['not_checked']} were not checked; {ls['skipped']} skipped (robots.txt); {ls['blocked']} blocked by network policy; {ls['failed']} failed to check.")
        self.para("Discovered by type: " + ", ".join(f"{k}={v}" for k, v in sorted(ls["by_kind"].items())), "small")
        rows = [[l["url"], l["kind"], l["check"]["state"].replace("_", " "), l["check"].get("status") or l["check"].get("reason") or ""] for l in r["links"][:80]]
        self.table(["URL", "Type", "Check state", "Status / reason"], rows, [96, 20, 28, 26], mono_cols=(0,), limit=220)
        if len(r["links"]) > 80:
            self.para(f"{len(r['links']) - 80} further links are in the CSV/JSON export.", "small")

    def _image(self, r):
        if r.get("rejected"):
            self.para("The upload was rejected: " + r["rejected"]["message"])
            return
        f, md = r["file"], r["metadata"]
        self.h2("File")
        self.kv([("Filename (display only)", f["display_name"]), ("Size", f"{f['size_bytes']:,} bytes"), ("Detected format", f"{f['detected_format']} ({f['mime_type']}) — from file content"),
                 ("Dimensions", f"{f['width']} × {f['height']} px ({f['megapixels']} MP)"), ("Colour mode", f["color_mode"]), ("Frames", f["frames"]), ("SHA-256", f["sha256"]),
                 ("Extension matches content", {True: "yes", False: "NO", None: "no extension"}[f["extension_matches_content"]])])
        gps = md["gps"]
        self.h2("GPS")
        if not gps["present"]:
            self.para("No GPS metadata is present in this file.")
        elif gps.get("redacted"):
            self.para("GPS metadata is present. Coordinates were shown to the user at analysis time but are not retained in this record (privacy by default).")
        else:
            self.kv([("Latitude", gps.get("latitude")), ("Longitude", gps.get("longitude")), ("Altitude (m)", gps.get("altitude_m")), ("GPS date", gps.get("timestamp"))])
        ex = md["exif"]
        self.h2("EXIF")
        if not ex["present"]:
            self.para("No EXIF data found. Missing metadata is common (messaging apps and social networks strip it) and is not evidence of anything on its own.")
        else:
            self.kv([(k, v) for grp in ("camera", "capture", "exposure") for k, v in ex[grp].items()])
        self.h2("Other metadata containers")
        self.kv([("XMP", "present" if md["xmp"]["present"] else "absent"), ("IPTC", "present" if md["iptc"]["present"] else "absent"),
                 ("ICC profile", (md["icc_profile"].get("description") or "present") if md["icc_profile"]["present"] else "absent"), ("Text chunks", ", ".join(md["text_chunks"].get("entries", {})) or "absent"),
                 ("Comment", "present" if md["comment"]["present"] else "absent")])
        self.h2("Privacy summary")
        self.para(("Potentially sensitive items: " + ", ".join(r["privacy_summary"]["sensitive_present"])) if r["privacy_summary"]["sensitive_present"] else "No potentially sensitive embedded fields were found.")
        for n in r["privacy_summary"]["notes"]:
            self.para(n, "small")
        self.h2("Reverse image search (third-party services; nothing was uploaded by CyberRecon)")
        self.table(["Service", "Link"], [[x["name"], x["url"]] for x in r.get("reverse_search", [])], [50, 120], mono_cols=(1,))

    def _infra(self, r):
        if not r:
            self.para("No result data.")
            return
        self.kv([("Hostname / IP", r["hostname"]), ("Registrable domain", r.get("apex_domain")), ("DNS resolver", r["dns"].get("resolver")), ("DNS queried at", r["dns"].get("queried_at"))])
        self.h2("DNS records")
        rows = []
        for rec in r["dns"]["records"]:
            if rec["values"]:
                rows += [[rec["name"], rec["type"], rec["status"], v["value"], v["ttl"]] for v in rec["values"]]
            else:
                rows.append([rec["name"], rec["type"], rec["status"] + (f" — {rec['error']}" if rec.get("error") else ""), "", ""])
        self.table(["Name", "Type", "Status", "Value", "TTL"], rows, [42, 13, 28, 75, 12], mono_cols=(0, 3))
        reg = r.get("registration", {})
        self.h2("Registration (RDAP) — third-party report")
        if reg.get("status") == "found":
            self.kv([("Registrar", reg.get("registrar")), ("Registrar IANA ID", reg.get("registrar_iana_id")), ("Created", reg.get("created")), ("Expires", reg.get("expires")),
                     ("Last changed", reg.get("updated")), ("Status", ", ".join(reg.get("domain_status", []))), ("Nameservers", ", ".join(reg.get("nameservers", []))),
                     ("Registrant organisation", reg.get("registrant_org") or "Not published / redacted"), ("Source", reg.get("source"))])
        else:
            self.para(f"Registration data: {reg.get('status')}. {reg.get('message') or ''}")
        self.h2("IP addresses and network ownership")
        rows = []
        for ip in r.get("ips", []):
            asn, geo = ip.get("asn") or {}, ip.get("geo") or {}
            rows.append([ip["ip"], ("AS%s %s" % (asn.get("asn"), asn.get("name") or "")) if asn.get("asn") else (ip.get("messages", {}).get("asn") or ip.get("messages", {}).get("skipped") or "no origin AS"),
                         (ip.get("network") or {}).get("name") or "", (", ".join(x for x in (geo.get("city"), geo.get("country")) if x) + " (estimate)") if geo else (ip.get("messages", {}).get("geo") or "")])
        self.table(["Address", "ASN (third-party)", "Network (RDAP)", "Geolocation (ESTIMATE)"], rows or [["—", "", "", ""]], [42, 50, 38, 40], mono_cols=(0,))
        self.para("IP geolocation is an estimate and does not reliably identify a person's physical location.", "small")
        tls = r.get("tls", {})
        self.h2("TLS certificate")
        if tls.get("status") == "ok":
            v = tls["verification"]
            self.kv([("Verification", "passed" if v["ok"] else "FAILED: " + str(v["error"])), ("Subject", tls.get("subject_cn")), ("Issuer", tls.get("issuer_org") or tls.get("issuer_cn")),
                     ("Valid from", tls["not_before"]), ("Valid until", f"{tls['not_after']} ({tls['days_remaining']} days remaining)"), ("Covers hostname", "yes" if tls["hostname_match"] else "NO"),
                     ("Subject alternative names", ", ".join(tls["san"][:12])), ("Key", f"{tls['public_key']['type']} {tls['public_key']['bits']}"), ("Protocol / cipher", f"{tls['protocol']} / {tls['cipher']}"),
                     ("SHA-256 fingerprint", tls["fingerprint_sha256"])])
        else:
            self.para(f"TLS inspection: {tls.get('status')}. {tls.get('error') or ''}")
        subs = r.get("subdomains", {})
        self.h2("Passive subdomains — reported by a third-party source")
        if subs.get("status") == "ok":
            self.para(f"Provider: {subs['provider']}. {subs['basis']} {subs['total_reported']} name(s) reported; the first {subs['dns_checked']} were checked with DNS lookups ({subs['dns_resolved']} resolved).")
            self.table(["Name", "Status", "Resolved addresses"], [[i["name"], i["verification"].replace("_", " "), ", ".join(i.get("resolves_to", []))] for i in subs["items"][:80]], [80, 30, 60], mono_cols=(0, 2))
        else:
            self.para(f"Subdomain lookup: {subs.get('status')}. {subs.get('message') or ''}")
        g = r.get("graph", {})
        self.h2("Relationship graph")
        self.para(f"{len(g.get('nodes', []))} nodes and {len(g.get('edges', []))} edges were derived from the lookups above. Each edge records the evidence and source that produced it (see JSON export).")
        self.table(["From", "Relation", "To", "Evidence"], [[e["source"], e["relation"], e["target"], e["evidence"]] for e in g.get("edges", [])[:60]], [45, 25, 45, 55], mono_cols=(0, 2))

    def _shot(self, r):
        if not r or r.get("failure") or r.get("unavailable"):
            self.para("Screenshot capture failed: " + ((r or {}).get("failure", {}).get("message") or (r or {}).get("unavailable") or "unknown"))
            return
        self.kv([("Requested URL", r["requested_url"]), ("Final URL", r["final_url"]), ("HTTP status", r["http_status"]), ("Page title", r.get("title")), ("Captured at (UTC)", r["captured_at"]),
                 ("Viewport", f"{r['viewport']['width']}×{r['viewport']['height']}"), ("Mode", r["capture_mode"]), ("Browser", f"{r['browser']['name']} {r['browser']['version']}"),
                 ("Image", f"PNG {r['image']['width']}×{r['image']['height']}, {r['image']['size_bytes']:,} bytes"), ("Image SHA-256", r["image"]["sha256"]), ("Requests blocked by policy", len(r.get("blocked_requests", [])))])
        if self.shot and self.shot.exists():
            from PIL import Image as PILImage
            w, h = PILImage.open(self.shot).size
            width = 170 * mm
            self.story.append(Image(str(self.shot), width=width, height=width * h / w))

    def sources(self):
        self.h1("5. Data sources, failed and unavailable lookups")
        if not self.a["sources"]:
            self.para("No external data sources were consulted.")
            return
        self.table(["Source", "Kind", "Status", "Detail / reason"], [[s["name"], s["kind"], s["status"].upper(), s["detail"] or s["reference"]] for s in self.a["sources"]], [50, 16, 24, 80])
        bad = [s for s in self.a["sources"] if s["status"] in ("failed", "unavailable")]
        if bad:
            self.para(f"{len(bad)} source(s) were unavailable or failed. Related sections are marked accordingly; no values were substituted for them.")
        if self.a["errors"]:
            self.h2("Errors")
            self.table(["Step", "Code", "Message"], [[e.get("step"), e.get("code"), e.get("message")] for e in self.a["errors"]], [25, 35, 110])

    def limitations(self):
        self.h1("6. Limitations")
        common = [
            "This report is a point-in-time, passive observation. Results can differ by network location, resolver, time and user agent.",
            "Absence of a finding is not proof of absence. Technology and header observations come from a single request.",
            "Severity labels indicate where attention may be warranted; they are not a vulnerability assessment or a compliance statement.",
            "Findings should be validated with the asset owner before action is taken.",
        ]
        specific = {
            "image": ["Embedded metadata is self-reported and can be edited or fabricated; it does not establish authenticity or the identity of any person."],
            "infrastructure": (self.a.get("result") or {}).get("limitations", []),
            "link": ["Links marked as not checked were discovered only. Dynamic, script-generated content may not appear in a static page parse."],
            "screenshot": (self.a.get("result") or {}).get("limitations", []),
        }[self.a["module"]]
        for t in common + specific:
            self.para("• " + t)

    def conclusion(self):
        self.h1("7. Conclusion and recommended next steps")
        a = self.a
        c = Counter(f["severity"] for f in a["findings"])
        self.para(f"The assessment finished with status '{a['status']}' and recorded {len(a['findings'])} finding(s) ({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} informational).")
        for s in next_steps(a):
            self.para("• " + s)

    def build(self) -> bytes:
        self.cover()
        self.summary()
        self.methods()
        self.findings()
        self.details()
        self.sources()
        self.limitations()
        self.conclusion()
        buf = io.BytesIO()
        regular, bold, _ = register_fonts()
        demo, a = self.demo, self.a

        def deco(canvas, doc):
            canvas.saveState()
            w, h = A4
            canvas.setFillColor(INK)
            canvas.rect(0, h - 14 * mm, w, 14 * mm, stroke=0, fill=1)
            canvas.setFillColor(EMERALD)
            canvas.circle(18 * mm, h - 7 * mm, 2 * mm, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont(bold, 10)
            canvas.drawString(23 * mm, h - 8.3 * mm, "CYBERRECON")
            canvas.setFont(regular, 7.5)
            canvas.drawRightString(w - 20 * mm, h - 8.3 * mm, ("DEMO — SIMULATED DATA · " if demo else "") + "Assessment " + a["id"][:12])
            canvas.setFillColor(MUTED)
            canvas.setFont(regular, 7)
            canvas.drawString(20 * mm, 10 * mm, "Generated by CyberRecon v0.1.0 · passive footprinting only · results reflect public information at the time of assessment")
            canvas.drawRightString(w - 20 * mm, 10 * mm, f"Page {doc.page}")
            if demo:
                canvas.saveState()
                canvas.setFillColor(colors.Color(0.7, 0.35, 0.03, alpha=0.08))
                canvas.setFont(bold, 62)
                canvas.translate(w / 2, h / 2)
                canvas.rotate(35)
                canvas.drawCentredString(0, 0, "SIMULATED DEMO")
                canvas.restoreState()
            canvas.restoreState()

        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=22 * mm, bottomMargin=18 * mm,
                                title=f"CyberRecon assessment {a['id']}", author="CyberRecon", subject=MODULE_TITLE.get(a["module"], ""))
        doc.build(self.story, onFirstPage=deco, onLaterPages=deco)
        return buf.getvalue()


def next_steps(a: dict) -> list[str]:
    titles = " | ".join(f["title"] for f in a["findings"]).lower()
    steps = []
    rules = [
        ("hsts header not observed", "Review HSTS and Content-Security-Policy headers with the site owner and enable them where appropriate."),
        ("content-security-policy header not observed", "Consider a Content-Security-Policy to reduce cross-site scripting impact."),
        ("without secure", "Review cookie attributes (Secure, HttpOnly, SameSite) for session-related cookies."),
        ("without httponly", "Review cookie attributes (Secure, HttpOnly, SameSite) for session-related cookies."),
        ("server software disclosed", "Consider removing version details from Server / X-Powered-By headers (low value, but reduces fingerprinting)."),
        ("link returned http", "Fix or remove the broken links listed in the findings."),
        ("failed verification", "Investigate the TLS certificate chain; clients will warn on unverifiable certificates."),
        ("has expired", "Renew the expired TLS certificate immediately."),
        ("certificate expires in", "Schedule renewal of the TLS certificate and consider automated renewal."),
        ("does not cover the hostname", "Re-issue the certificate so it covers every hostname served."),
        ("no spf record", "Publish an SPF record for domains that send or receive mail."),
        ("no dmarc record", "Publish a DMARC policy to protect the domain from spoofing."),
        ("registration expires in", "Renew the domain registration or enable auto-renew."),
        ("non-public address", "Review public DNS records that point to private address space."),
        ("gps location embedded", "Sanitise the image (remove metadata) before sharing it publicly."),
        ("embedded device serial", "Sanitise the image before sharing; it carries a device identifier."),
        ("screenshot could not be captured", "Retry later or check whether the site blocks automated browsers."),
    ]
    seen = set()
    for key, text in rules:
        if key in titles and text not in seen:
            steps.append(text)
            seen.add(text)
    steps.append("Validate these observations with the asset owner; passive data can be incomplete or out of date.")
    steps.append("Re-run the assessment periodically to track changes over time.")
    return steps


def build_pdf(a: dict, *, demo: bool = False, screenshot_path: Path | None = None) -> bytes:
    return Builder(a, demo=demo, screenshot_path=screenshot_path).build()
