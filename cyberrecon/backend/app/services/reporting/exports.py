"""JSON and CSV exports. CSV cells are neutralised against spreadsheet formula injection."""
from __future__ import annotations

import csv
import io
import json

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_safe(value) -> str:
    """Prefix risky cells with an apostrophe so Excel/Sheets never evaluate them as formulas."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(v) for v in value)
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False)
    s = str(value).replace("\x00", "")
    if s.startswith(_FORMULA_PREFIXES):
        s = "'" + s
    return s


def _write(rows: list[list], header: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow([csv_safe(c) for c in r])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so Excel detects UTF-8


def available_tables(a: dict) -> list[str]:
    tables = ["findings", "sources"]
    r = a.get("result") or {}
    if a["module"] == "link" and r.get("links") is not None:
        tables.insert(0, "links")
    if a["module"] == "infrastructure" and r.get("dns"):
        tables = ["dns_records", "ip_addresses", "subdomains"] + tables
    if a["module"] == "image" and r.get("file"):
        tables.insert(0, "metadata")
    return tables


def to_csv(a: dict, table: str) -> bytes:
    r = a.get("result") or {}
    if table == "findings":
        return _write([[f["severity"], f["evidence_type"], f["module"], f["category"], f["title"], f["detail"], f["source"]] for f in a["findings"]],
                      ["severity", "evidence_type", "module", "category", "title", "detail", "source"])
    if table == "sources":
        return _write([[s["name"], s["kind"], s["status"], s["reference"], s["detail"], s["retrieved_at"]] for s in a["sources"]],
                      ["name", "kind", "status", "reference", "detail", "retrieved_at"])
    if table == "links" and a["module"] == "link":
        rows = []
        for l in r.get("links", []):
            c = l["check"]
            rows.append([l["url"], l["kind"], l["sources"], l["count"], l.get("text"), c["state"], c.get("status"), c.get("final_url"), c.get("time_ms"), c.get("reason"), c.get("detail")])
        return _write(rows, ["url", "kind", "found_in", "occurrences", "anchor_text", "check_state", "http_status", "final_url", "time_ms", "reason", "detail"])
    if table == "dns_records" and a["module"] == "infrastructure":
        rows = []
        for rec in r.get("dns", {}).get("records", []):
            if rec["values"]:
                rows += [[rec["name"], rec["type"], rec["status"], v["value"], v["ttl"], rec["queried_at"]] for v in rec["values"]]
            else:
                rows.append([rec["name"], rec["type"], rec["status"], "", "", rec["queried_at"]])
        return _write(rows, ["name", "type", "status", "value", "ttl", "queried_at"])
    if table == "ip_addresses" and a["module"] == "infrastructure":
        rows = []
        for ip in r.get("ips", []):
            asn, geo, net = ip.get("asn") or {}, ip.get("geo") or {}, ip.get("network") or {}
            rows.append([ip["ip"], ip["public"], ip.get("ptr"), asn.get("asn"), asn.get("name"), asn.get("prefix"), net.get("name"), geo.get("country"), geo.get("city"), "estimate" if geo else ""])
        return _write(rows, ["ip", "public", "reverse_dns", "asn", "asn_name", "prefix", "network_name", "geo_country_estimate", "geo_city_estimate", "geo_note"])
    if table == "subdomains" and a["module"] == "infrastructure":
        items = (r.get("subdomains") or {}).get("items", [])
        return _write([[i["name"], i["verification"], i.get("sources"), i.get("resolves_to")] for i in items], ["name", "verification", "reported_by", "resolved_addresses"])
    if table == "metadata" and a["module"] == "image":
        rows = [[f"file.{k}", v] for k, v in r.get("file", {}).items()]
        md = r.get("metadata", {})
        rows += [[f"exif.{k}", v] for k, v in md.get("exif", {}).get("fields", {}).items()]
        gps = md.get("gps", {})
        rows += [[f"gps.{k}", v] for k, v in gps.items() if k != "fields"]
        return _write(rows, ["field", "value"])
    raise KeyError(table)


def to_json(a: dict) -> bytes:
    payload = {"generated_by": "CyberRecon", "format_version": 1, "assessment": a}
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
