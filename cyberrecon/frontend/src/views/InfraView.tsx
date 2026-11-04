import { lazy, Suspense, useState } from "react";
import { DataTable, type Column } from "../components/DataTable";
import { ErrorState, EvidenceTag, KV, LoadingBlock, Mono, Notice, Panel, Stat, Tabs } from "../components/ui";
import type { Assessment, Mode } from "../lib/api";
import { ExportMenu, FindingsPanel, Limitations, SourcesPanel } from "./common";
const InfraGraph = lazy(() => import("./InfraGraph").then((m) => ({ default: m.InfraGraph })));

type Tab = "overview" | "dns" | "network" | "tls" | "subdomains" | "graph" | "findings" | "sources";

export function InfraView({ a, mode }: { a: Assessment; mode: Mode }) {
  const [tab, setTab] = useState<Tab>("overview");
  const r = a.result;
  if (!r || !r.dns) return <ErrorState title="No result data" message={a.error ?? "This assessment did not produce infrastructure data."} />;
  const records = r.dns.records.flatMap((rec: any) => rec.values.length ? rec.values.map((v: any, i: number) => ({ ...rec, value: v.value, ttl: v.ttl, k: `${rec.name}${rec.type}${i}` })) : [{ ...rec, value: null, ttl: null, k: `${rec.name}${rec.type}` }]);
  const dnsCols: Column<any>[] = [
    { key: "name", header: "Name", mono: true, sortValue: (x) => x.name }, { key: "type", header: "Type", sortValue: (x) => x.type },
    { key: "status", header: "Result", sortValue: (x) => x.status, render: (x) => <span className={x.status === "ok" ? "text-emerald" : x.status === "no_answer" ? "text-muted" : "text-amber"} title={x.error ?? ""}>{x.status.replace("_", " ")}</span> },
    { key: "value", header: "Value", mono: true, sortValue: (x) => x.value, className: "max-w-[30rem] break-all", render: (x) => <span>{x.value ?? "—"}</span> }, { key: "ttl", header: "TTL", sortValue: (x) => x.ttl, className: "tabular-nums" },
  ];
  const reg = r.registration ?? {};
  const tls = r.tls ?? {};
  const subs = r.subdomains ?? {};
  const subCols: Column<any>[] = [
    { key: "name", header: "Name", mono: true, sortValue: (s) => s.name },
    { key: "v", header: "Verification", sortValue: (s) => s.verification, render: (s) => <span className={s.verification === "dns_resolved" ? "text-emerald" : "text-muted"}>{{ dns_resolved: "Resolved in DNS", dns_unresolved: "Reported, did not resolve", reported: "Reported, not checked" }[s.verification as string] ?? s.verification}</span> },
    { key: "ips", header: "Addresses", mono: true, sortValue: (s) => (s.resolves_to ?? []).join(","), render: (s) => <span>{(s.resolves_to ?? []).join(", ") || "—"}</span> },
    { key: "src", header: "Reported by", sortValue: (s) => (s.sources ?? []).join(","), render: (s) => <span className="text-muted">{(s.sources ?? []).join(", ")}</span> },
  ];
  return (
    <div className="space-y-5">
      <ExportMenu a={a} mode={mode} tables={a.available_exports ?? []} />
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "dns", label: "DNS", count: records.length }, { id: "network", label: "Registration & network" }, { id: "tls", label: "TLS" },
        { id: "subdomains", label: "Subdomains", count: subs.items?.length }, { id: "graph", label: "Graph", count: r.graph?.nodes?.length }, { id: "findings", label: "Findings", count: a.findings.length }, { id: "sources", label: "Sources", count: a.sources.length }]} />
      {tab === "overview" && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="IP addresses" value={r.ips.length} hint={`${r.ips.filter((i: any) => i.public).length} public`} />
            <Stat label="Registration" value={reg.status === "found" ? "Found" : reg.status === "not_found" ? "Not found" : "Unavailable"} tone={reg.status === "found" ? "good" : "warn"} hint="RDAP" />
            <Stat label="Certificate" value={tls.status === "ok" ? `${tls.days_remaining} days` : "—"} hint={tls.status === "ok" ? "until expiry" : tls.status === "skipped" ? "Not checked" : "Not available"} tone={tls.status === "ok" ? (tls.days_remaining < 14 ? "bad" : tls.days_remaining < 30 ? "warn" : "good") : undefined} />
            <Stat label="Subdomains reported" value={subs.total_reported ?? "—"} hint={subs.status === "ok" ? `${subs.dns_resolved} resolved when checked` : "Provider unavailable"} />
          </div>
          <Panel title="Target"><KV rows={[["Hostname / address", <Mono key="h">{r.hostname}</Mono>], ["Registrable domain", r.apex_domain && <Mono key="a">{r.apex_domain}</Mono>], ["DNS resolver", r.dns.resolver], ["Queried at", r.dns.queried_at]]} /></Panel>
          {r.technologies?.length > 0 && <Panel title="Technology indicators">{r.technologies.map((t: any) => <p key={t.name} className="text-sm">{t.name} <span className="text-muted">— {t.category}, {t.confidence} confidence</span></p>)}</Panel>}
          <Limitations items={r.limitations} />
        </div>
      )}
      {tab === "dns" && <DataTable rows={records} columns={dnsCols} rowKey={(x) => x.k} caption="DNS records" searchPlaceholder="Search DNS records" filters={[{ id: "type", label: "Type", options: [...new Set<string>(records.map((x: any) => x.type))].map((t) => ({ value: t, label: t })), test: (x, v) => x.type === v }]} />}
      {tab === "network" && (
        <div className="space-y-5">
          <Panel title="Registration (RDAP)" action={<EvidenceTag type="third_party" />}>
            {reg.status === "found" ? <KV rows={[["Registrar", reg.registrar], ["Created", reg.created], ["Expires", reg.expires], ["Last changed", reg.updated], ["Status", (reg.domain_status ?? []).join(", ")], ["Nameservers", (reg.nameservers ?? []).join(", ")], ["Registrant", reg.registrant_org ?? "Redacted or not published"], ["Source", reg.source && <Mono key="s">{reg.source}</Mono>]]} />
              : <Notice tone="warn" title={reg.status === "not_found" ? "No registration found" : "Registration data unavailable"}>{reg.message ?? "The registry lookup did not return data."}</Notice>}
          </Panel>
          <Panel title="IP ownership and location">
            {r.ips.length === 0 ? <p className="text-sm text-muted">No IP addresses were returned by DNS.</p> : (
              <div className="space-y-3">{r.ips.map((ip: any) => (
                <div key={ip.ip} className="rounded-lg border border-line bg-canvas p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2"><Mono className="text-base">{ip.ip}</Mono>{!ip.public && <span className="text-xs text-amber">Non-public address — not contacted</span>}</div>
                  <div className="mt-2"><KV rows={[["Origin AS", ip.asn?.asn ? `AS${ip.asn.asn} · ${ip.asn.name} · ${ip.asn.prefix}` : ip.messages?.asn ?? ip.messages?.skipped], ["Network (RDAP)", ip.network?.name && `${ip.network.name} · ${(ip.network.organizations ?? []).join(", ")}`],
                    ["Location estimate", ip.geo ? `${[ip.geo.city, ip.geo.country].filter(Boolean).join(", ")} (estimate)` : ip.messages?.geo], ["Reverse DNS", ip.ptr]]} /></div>
                </div>))}</div>)}
            <p className="mt-3 text-xs text-muted">ASN data is third-party. Geolocation is an estimate and does not identify a precise or physical location.</p>
          </Panel>
        </div>
      )}
      {tab === "tls" && (tls.status === "ok" ? (
        <Panel title="Certificate" action={<EvidenceTag type="observed" />}>
          {!tls.verification.ok && <div className="mb-3"><Notice tone="warn" title="Certificate verification failed">{tls.verification.error}. Details below were read from the unverified certificate.</Notice></div>}
          <KV rows={[["Verification", tls.verification.ok ? "Passed" : "Failed"], ["Subject", tls.subject_cn], ["Issuer", tls.issuer_org ?? tls.issuer_cn], ["Valid from", tls.not_before], ["Valid until", `${tls.not_after} (${tls.days_remaining} days left)`], ["Covers hostname", tls.hostname_match ? "Yes" : "No"],
            ["Alternative names", (tls.san ?? []).join(", ")], ["Key", `${tls.public_key.type} ${tls.public_key.bits}`], ["Protocol", `${tls.protocol} · ${tls.cipher}`], ["SHA-256 fingerprint", <Mono key="f">{tls.fingerprint_sha256}</Mono>]]} />
        </Panel>
      ) : <Notice tone="warn" title={tls.status === "skipped" ? "TLS was not checked" : "TLS inspection unavailable"}>{tls.error ?? "No certificate details were collected."}</Notice>)}
      {tab === "subdomains" && (subs.status === "ok" ? (
        <div className="space-y-3">
          <Notice tone="info" title={`Reported by ${subs.provider}`}>{subs.basis} “Resolved” means a DNS lookup returned an address when checked; it does not prove the host is reachable or owned by the same party. Names were never guessed or brute-forced.</Notice>
          <DataTable rows={subs.items} columns={subCols} rowKey={(s) => s.name} caption="Passively reported subdomains" searchPlaceholder="Search subdomains" />
        </div>
      ) : <Notice tone="warn" title="Passive subdomain data unavailable">{subs.message ?? "The subdomain provider is not configured or did not respond."}</Notice>)}
      {tab === "graph" && <Suspense fallback={<LoadingBlock label="Loading the graph" rows={4} />}><InfraGraph graph={r.graph} /></Suspense>}
      {tab === "findings" && <FindingsPanel findings={a.findings} />}
      {tab === "sources" && <SourcesPanel a={a} />}
    </div>
  );
}
