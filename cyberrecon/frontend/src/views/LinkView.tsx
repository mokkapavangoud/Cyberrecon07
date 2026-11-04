import { useState } from "react";
import { DataTable, type Column, type FilterDef } from "../components/DataTable";
import { EmptyState, ErrorState, KV, Mono, Notice, Panel, Stat, Tabs } from "../components/ui";
import type { Assessment, Mode } from "../lib/api";
import { fmtBytes, fmtMs } from "../lib/format";
import { ExportMenu, FindingsPanel, SourcesPanel } from "./common";

type Tab = "overview" | "links" | "headers" | "robots" | "findings" | "sources";
const SOURCE_LABEL: Record<string, string> = { a: "link", link: "<link> tag", script: "script", img: "image", iframe: "iframe", form: "form", source: "media", area: "image map" };
const CHECK_LABEL: Record<string, string> = { checked: "Checked", not_checked: "Not checked", skipped: "Skipped (robots.txt)", blocked: "Blocked by policy", failed: "Check failed" };

export function LinkView({ a, mode }: { a: Assessment; mode: Mode }) {
  const [tab, setTab] = useState<Tab>("overview");
  const r = a.result;
  if (!r) return <ErrorState title="No result data" message="This assessment did not store any result data." />;
  if (r.fetch_error) {
    return (
      <div className="space-y-4">
        <ErrorState title="The target could not be analysed" message={r.fetch_error.message} />
        <Tabs tabs={[{ id: "findings", label: "Findings", count: a.findings.length }, { id: "sources", label: "Sources" }]} value={tab === "sources" ? "sources" : "findings"} onChange={(t) => setTab(t as Tab)} />
        {tab === "sources" ? <SourcesPanel a={a} /> : <FindingsPanel findings={a.findings} />}
      </div>
    );
  }
  const ls = r.link_summary, h = r.http;
  const links: any[] = r.links;
  const cols: Column<any>[] = [
    { key: "url", header: "URL", mono: true, sortValue: (l) => l.url, className: "max-w-[28rem] break-all", render: (l) => <span>{l.url}</span> },
    { key: "kind", header: "Type", sortValue: (l) => l.kind },
    { key: "count", header: "Seen", sortValue: (l) => l.count, className: "tabular-nums" },
    { key: "found", header: "Found in", sortValue: (l) => l.sources.join(","), render: (l) => <span className="text-muted">{l.sources.map((x: string) => SOURCE_LABEL[x] ?? x).join(", ")}</span> },
    { key: "state", header: "Check", sortValue: (l) => l.check.state, render: (l) => <span className={l.check.state === "checked" ? "text-text" : "text-muted"}>{CHECK_LABEL[l.check.state] ?? l.check.state}</span> },
    { key: "status", header: "Status", sortValue: (l) => l.check.status ?? -1, className: "tabular-nums", render: (l) => <StatusCell c={l.check} /> },
  ];
  const filters: FilterDef<any>[] = [
    { id: "kind", label: "Type", options: Object.keys(ls.by_kind).map((k) => ({ value: k, label: `${k} (${ls.by_kind[k]})` })), test: (l, v) => l.kind === v },
    { id: "state", label: "Check", options: Object.entries(CHECK_LABEL).map(([value, label]) => ({ value, label })), test: (l, v) => l.check.state === v },
  ];
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><ExportMenu a={a} mode={mode} tables={a.available_exports ?? ["links"]} /></div>
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[
        { id: "overview", label: "Overview" }, { id: "links", label: "Links", count: ls.discovered }, { id: "headers", label: "Headers & cookies" },
        { id: "robots", label: "robots.txt & sitemap" }, { id: "findings", label: "Findings", count: a.findings.length }, { id: "sources", label: "Sources", count: a.sources.length },
      ]} />
      {tab === "overview" && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="HTTP status" value={h.status} hint={h.reason} tone={h.status < 400 ? "good" : "bad"} />
            <Stat label="Response time" value={fmtMs(h.response_time_ms)} hint="single request" />
            <Stat label="Links discovered" value={ls.discovered} hint={`${ls.by_kind.internal ?? 0} internal · ${(ls.by_kind.external ?? 0) + (ls.by_kind.subdomain ?? 0)} external`} />
            <Stat label="Links checked" value={ls.checked} hint={ls.checked ? `${ls.ok} ok · ${ls.broken} broken` : "Link checking was not run"} tone={ls.broken ? "warn" : undefined} />
          </div>
          <Panel title="Page">
            <KV rows={[["Final URL", <Mono key="u">{r.final_url}</Mono>], ["Title", r.page.title], ["Description", r.page.meta?.description], ["Content type", h.content_type], ["Size read", `${fmtBytes(h.bytes_read)}${h.truncated ? " (truncated at the size limit)" : ""}`],
              ["Connected IP", h.remote_ip && <Mono key="i">{h.remote_ip}</Mono>], ["Server disclosure", r.page.server_disclosure], ["Requests made", r.requests_made]]} />
          </Panel>
          {r.redirect_chain?.length > 1 && (
            <Panel title="Redirect chain"><ol className="space-y-1.5 text-sm">{r.redirect_chain.map((x: any, i: number) => (
              <li key={i} className="flex flex-wrap gap-2"><span className="tabular-nums text-muted">{x.status}</span><Mono>{x.url}</Mono>{!x.followed && x.note && <span className="text-amber">{x.note}</span>}</li>))}</ol></Panel>
          )}
          <Panel title="Technology indicators" action={<span className="text-xs text-muted">Hints from headers and markup, not proof</span>}>
            {r.technologies.length === 0 ? <p className="text-sm text-muted">No technology indicators were found in the response.</p> : (
              <ul className="grid gap-2 sm:grid-cols-2">{r.technologies.map((t: any) => (
                <li key={t.name} className="rounded-lg border border-line bg-canvas px-3 py-2 text-sm"><div className="flex justify-between gap-2"><span className="font-medium">{t.name}{t.version ? ` ${t.version}` : ""}</span><span className="text-xs text-muted">{t.confidence} confidence</span></div>
                  <p className="text-xs text-muted">{t.category} · {t.evidence.join("; ")}</p></li>))}</ul>
            )}
          </Panel>
        </div>
      )}
      {tab === "links" && (
        <div className="space-y-3">
          <Notice tone="info" title="Discovered is not the same as checked">
            {ls.discovered} links were found in the page source. Only {ls.checked} were requested{ls.not_checked ? `; ${ls.not_checked} were not checked` : ""}{ls.skipped ? `; ${ls.skipped} skipped because robots.txt disallows them` : ""}. External links are never crawled.
          </Notice>
          <DataTable rows={links} columns={cols} filters={filters} rowKey={(l) => l.url} caption="Links discovered on the page" searchPlaceholder="Search URLs" />
        </div>
      )}
      {tab === "headers" && (
        <div className="space-y-5">
          <Panel title="Security-relevant headers" action={<span className="text-xs text-muted">From this single response</span>}>
            <div className="overflow-x-auto"><table className="w-full min-w-[520px] text-left text-sm"><thead className="text-xs text-muted"><tr><th className="py-2 pr-3 font-medium">Header</th><th className="py-2 pr-3 font-medium">Observed</th><th className="py-2 font-medium">Value / note</th></tr></thead>
              <tbody>{r.headers.security.map((s: any) => (
                <tr key={s.name} className="border-t border-line align-top"><td className="py-2 pr-3 font-medium">{s.label}</td><td className="py-2 pr-3">{s.present ? <span className="text-emerald">Present</span> : s.applicable ? <span className="text-amber">Not observed</span> : <span className="text-muted">Not applicable</span>}</td>
                  <td className="py-2 text-muted">{s.value ? <Mono>{s.value}</Mono> : s.note}</td></tr>))}</tbody></table></div>
          </Panel>
          <Panel title="Cookies" action={<span className="text-xs text-muted">Names and flags only. Values are never stored.</span>}>
            {r.headers.cookies.length === 0 ? <p className="text-sm text-muted">No cookies were set by this response.</p> : (
              <ul className="divide-y divide-line">{r.headers.cookies.map((c: any) => (<li key={c.name} className="flex flex-wrap justify-between gap-2 py-2 text-sm"><Mono>{c.name}</Mono>
                <span className="text-muted">Secure: {c.secure ? "yes" : "no"} · HttpOnly: {c.httponly ? "yes" : "no"} · SameSite: {c.samesite ?? "not set"}</span></li>))}</ul>)}
          </Panel>
          <Panel title="Other response headers"><KV rows={Object.entries(r.headers.selected ?? {}).map(([k, v]) => [k, <Mono key={k}>{String(v)}</Mono>] as [string, React.ReactNode])} /></Panel>
        </div>
      )}
      {tab === "robots" && (
        <div className="space-y-5">
          <Panel title="robots.txt"><KV rows={[["Status", r.robots.status.replace("_", " ")], ["URL", <Mono key="u">{r.robots.url}</Mono>], ["HTTP status", r.robots.http_status], ["Rule groups", r.robots.groups?.length],
            ["Sitemaps declared", (r.robots.sitemaps ?? []).join(", ")]]} />
            {r.robots.excerpt && <pre className="mt-3 max-h-64 overflow-auto rounded-lg border border-line bg-canvas p-3 font-mono text-xs text-muted">{r.robots.excerpt}</pre>}
            <p className="mt-3 text-xs text-muted">CyberRecon obeys these rules when checking links. It never bypasses them.</p></Panel>
          <Panel title="Sitemap"><KV rows={[["Status", r.sitemap.status.replace("_", " ")], ["URL", r.sitemap.url && <Mono key="u">{r.sitemap.url}</Mono>], ["Type", r.sitemap.type], ["URLs listed", r.sitemap.url_count], ["Note", r.sitemap.note ?? r.sitemap.error]]} />
            {r.sitemap.sample?.length > 0 && <ul className="mt-3 space-y-1">{r.sitemap.sample.map((u: string) => <li key={u}><Mono>{u}</Mono></li>)}</ul>}</Panel>
        </div>
      )}
      {tab === "findings" && <FindingsPanel findings={a.findings} />}
      {tab === "sources" && <SourcesPanel a={a} />}
      {links.length === 0 && tab === "overview" && <EmptyState title="No links were found">The response had no HTML links to extract.</EmptyState>}
    </div>
  );
}

function StatusCell({ c }: { c: any }) {
  if (c.state === "checked") {
    const ok = c.status >= 200 && c.status < 400;
    return <span className={ok ? "text-emerald" : "text-rose"}>{c.status}{c.time_ms != null && <span className="ml-1.5 text-xs text-faint">{c.time_ms} ms</span>}</span>;
  }
  return <span className="text-xs text-muted" title={c.detail ?? ""}>{c.reason ? String(c.reason).replace(/_/g, " ") : "—"}</span>;
}
