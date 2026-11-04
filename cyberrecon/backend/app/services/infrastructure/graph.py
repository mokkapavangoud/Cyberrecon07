"""Builds the infrastructure relationship graph strictly from collected data.

Every edge carries the evidence string and the source that produced it. Nothing is inferred beyond what a
lookup returned (the single exception, name-hierarchy edges, is labelled ``kind: naming``).
"""
from __future__ import annotations

MAX_NODES = 160
LAYER = {"domain": 0, "hostname": 1, "dns_record": 2, "subdomain": 2, "ip": 3, "asn": 4, "certificate": 4}


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}

    def node(self, nid: str, ntype: str, label: str, **data) -> str:
        if nid not in self.nodes and len(self.nodes) < MAX_NODES:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label[:60], "layer": LAYER[ntype], "data": {k: v for k, v in data.items() if v not in (None, [], {})}}
        elif nid in self.nodes:
            self.nodes[nid]["data"].update({k: v for k, v in data.items() if v not in (None, [], {})})
        return nid

    def edge(self, a: str, b: str, relation: str, evidence: str, source: str, *, kind: str = "observed", **data) -> None:
        if a not in self.nodes or b not in self.nodes:
            return
        eid = f"{a}|{relation}|{b}"
        if eid not in self.edges:
            self.edges[eid] = {"id": eid, "source": a, "target": b, "relation": relation, "evidence": evidence, "source_ref": source, "kind": kind, "data": data}

    def to_dict(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values()),
                "truncated": len(self.nodes) >= MAX_NODES,
                "note": "Edges represent relationships returned by the listed lookups at assessment time. Absence of an edge means nothing was observed, not that no relationship exists."}


def build_graph(d: dict) -> dict:
    g = Graph()
    host, apex = d["hostname"], d.get("apex_domain")
    is_ip = d.get("is_ip_target")
    dns_by_key = {(r["name"], r["type"]): r for r in d["dns"]["records"]}

    if is_ip:
        root = g.node(f"ip:{host}", "ip", host, role="assessed target")
    else:
        if apex and apex != host:
            g.node(f"domain:{apex}", "domain", apex, role="registrable domain", registration=d.get("registration"))
        root = g.node(f"host:{host}", "hostname", host, role="assessed hostname")
        if apex and apex != host:
            g.edge(f"domain:{apex}", root, "parent_of", f"{host} is within {apex} (name hierarchy)", "Name structure", kind="naming")
        domain_id = f"domain:{apex}" if apex and apex != host else root
        if domain_id == root:
            g.nodes[root]["type"] = "domain"
            g.nodes[root]["layer"] = 0
            g.nodes[root]["data"].update({"registration": d.get("registration")})

        # A / AAAA / CNAME for the hostname
        for rtype in ("A", "AAAA"):
            rec = dns_by_key.get((host, rtype))
            if rec and rec["status"] == "ok":
                for v in rec["values"]:
                    ip = g.node(f"ip:{v['value']}", "ip", v["value"], version=6 if ":" in v["value"] else 4)
                    g.edge(root, ip, rtype, f"{rtype} record {v['value']} (TTL {v['ttl']})", f"DNS {rtype} lookup", queried_at=rec["queried_at"])
        cn = dns_by_key.get((host, "CNAME"))
        if cn and cn["status"] == "ok":
            for v in cn["values"]:
                t = g.node(f"dns:CNAME:{v['value']}", "dns_record", f"CNAME → {v['value']}", record_type="CNAME", value=v["value"], ttl=v["ttl"])
                g.edge(root, t, "CNAME", f"CNAME record {v['value']} (TTL {v['ttl']})", "DNS CNAME lookup", queried_at=cn["queried_at"])

        # delegation / mail / text records belong to the registrable domain
        base_name = apex or host
        base_id = f"domain:{apex}" if apex and apex != host else root
        for rtype, prefix in (("NS", "ns"), ("MX", "mx")):
            rec = dns_by_key.get((base_name, rtype))
            if rec and rec["status"] == "ok":
                for v in rec["values"]:
                    n = g.node(f"dns:{rtype}:{v['value']}", "dns_record", f"{rtype} {v['value']}", record_type=rtype, value=v["value"], ttl=v["ttl"])
                    g.edge(base_id, n, rtype, f"{rtype} record {v['value']} (TTL {v['ttl']})", f"DNS {rtype} lookup", queried_at=rec["queried_at"])
        rec = dns_by_key.get((base_name, "TXT"))
        if rec and rec["status"] == "ok":
            for i, v in enumerate(rec["values"][:8]):
                n = g.node(f"dns:TXT:{i}:{v['value'][:24]}", "dns_record", f"TXT {v['value'][:34]}", record_type="TXT", value=v["value"], ttl=v["ttl"])
                g.edge(base_id, n, "TXT", f"TXT record (TTL {v['ttl']})", "DNS TXT lookup", queried_at=rec["queried_at"])

    # IP -> ASN / network
    for ip in d.get("ips", []):
        ipn = g.node(f"ip:{ip['ip']}", "ip", ip["ip"], public=ip["public"], ptr=ip.get("ptr"), network=ip.get("network"), geolocation=ip.get("geo"),
                     version=ip["version"])
        if is_ip and ip["ip"] == host:
            ipn = f"ip:{host}"
        asn = ip.get("asn") or {}
        if asn.get("asn"):
            an = g.node(f"asn:{asn['asn']}", "asn", f"AS{asn['asn']}" + (f" · {asn['name']}" if asn.get("name") else ""), **{k: v for k, v in asn.items() if k != "all_asns"})
            g.edge(ipn, an, "announced_by", f"Origin AS{asn['asn']} for prefix {asn.get('prefix')}", "Team Cymru IP-to-ASN (DNS)")

    # TLS certificate
    tls = d.get("tls") or {}
    if tls.get("status") == "ok":
        cert_id = g.node(f"cert:{tls['fingerprint_sha256'][:16]}", "certificate", tls.get("subject_cn") or "certificate",
                         issuer=tls.get("issuer_cn"), not_before=tls["not_before"], not_after=tls["not_after"], san_count=tls["san_count"],
                         verification=tls["verification"], fingerprint_sha256=tls["fingerprint_sha256"], hostname_match=tls["hostname_match"])
        connected = tls.get("connected_ip")
        if connected and f"ip:{connected}" in g.nodes:
            g.edge(f"ip:{connected}", cert_id, "serves_certificate", f"Certificate observed in a TLS handshake with {connected}:{tls['port']}", "TLS handshake")
        elif root in g.nodes:
            g.edge(root, cert_id, "serves_certificate", f"Certificate observed in a TLS handshake on port {tls['port']}", "TLS handshake")

    # passive subdomains (+ their DNS verification, when it happened)
    subs = d.get("subdomains") or {}
    base_id = (f"domain:{apex}" if apex and f"domain:{apex}" in g.nodes else root) if not is_ip else None
    for item in subs.get("items", [])[:60]:
        if item["name"] == host:
            continue
        sn = g.node(f"sub:{item['name']}", "subdomain", item["name"], verification=item["verification"], sources=item.get("sources"), resolves_to=item.get("resolves_to"))
        if base_id:
            g.edge(base_id, sn, "reported_subdomain", f"Reported by {subs.get('provider')} ({item['verification'].replace('_', ' ')})", subs.get("provider", "passive source"), kind="third_party",
                   verification=item["verification"])
        for ipaddr in item.get("resolves_to", [])[:4]:
            ipn = g.node(f"ip:{ipaddr}", "ip", ipaddr, version=6 if ":" in ipaddr else 4)
            g.edge(sn, ipn, "A/AAAA", f"{item['name']} resolved to {ipaddr} during this assessment", "DNS lookup")
        if tls.get("status") == "ok" and any(s.lstrip("*.") == item["name"] for s in tls.get("san", [])):
            g.edge(f"cert:{tls['fingerprint_sha256'][:16]}", sn, "covers", f"{item['name']} appears in the certificate's SAN list", "TLS handshake")
    if tls.get("status") == "ok" and not is_ip:
        for s in tls.get("san", []):
            if s == host and root in g.nodes:
                g.edge(f"cert:{tls['fingerprint_sha256'][:16]}", root, "covers", f"{host} appears in the certificate's SAN list", "TLS handshake")
    return g.to_dict()
