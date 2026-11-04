import { CheckCircle2, CircleDashed, Download, Loader2, MinusCircle, XCircle } from "lucide-react";
import { useState } from "react";
import { api, type Assessment, type Evidence, type Finding, type Mode, type Step } from "../lib/api";
import { download, errMsg, EVIDENCE_HELP, EVIDENCE_LABEL, fileSafe } from "../lib/format";
import { DataTable, type Column } from "../components/DataTable";
import { Button, cx, EmptyState, EvidenceTag, Notice, SeverityBadge, SourceStatus, SEV_LABEL } from "../components/ui";

const ORDER: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };

/** Shows the real, persisted step statuses from the backend. There is no timer-driven fake progress anywhere. */
export function StepList({ steps, percent }: { steps: Step[]; percent?: number }) {
  const icon = (s: Step["status"]) => ({
    done: <CheckCircle2 className="size-4 text-emerald" />, running: <Loader2 className="size-4 animate-spin text-cyan" />, failed: <XCircle className="size-4 text-rose" />,
    skipped: <MinusCircle className="size-4 text-faint" />, pending: <CircleDashed className="size-4 text-faint" />,
  }[s]);
  return (
    <div>
      {percent != null && (
        <div className="mb-3 flex items-center gap-3">
          <div role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100} aria-label="Assessment progress" className="h-1.5 flex-1 overflow-hidden rounded-full bg-raised">
            <div className="h-full bg-emerald transition-[width] duration-300" style={{ width: `${percent}%` }} />
          </div>
          <span className="w-10 text-right text-xs tabular-nums text-muted">{percent}%</span>
        </div>
      )}
      <ol className="space-y-2">
        {steps.map((s) => (
          <li key={s.key} className="flex items-start gap-2.5 text-sm">
            <span className="mt-0.5 shrink-0" aria-hidden>{icon(s.status)}</span>
            <div className="min-w-0">
              <span className={cx(s.status === "pending" && "text-faint", s.status === "skipped" && "text-muted")}>{s.label}</span>
              <span className="sr-only"> — {s.status}</span>
              {s.detail && <p className="text-xs text-muted">{s.detail}</p>}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <EmptyState title="No findings recorded">This assessment finished without any item worth flagging, or the data source was unavailable. Check the Sources tab.</EmptyState>;
  const groups: Evidence[] = ["observed", "third_party", "estimate"];
  return (
    <div className="space-y-6">
      {groups.map((g) => {
        const items = findings.filter((f) => f.evidence_type === g).sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
        if (!items.length) return null;
        const cols: Column<Finding>[] = [
          { key: "severity", header: "Severity", sortValue: (f) => ORDER[f.severity], render: (f) => <SeverityBadge severity={f.severity} />, searchText: (f) => SEV_LABEL[f.severity] },
          { key: "title", header: "Finding", sortValue: (f) => f.title, className: "font-medium", render: (f) => <span>{f.title}</span> },
          { key: "detail", header: "Detail", sortValue: (f) => f.detail, className: "text-muted max-w-[34rem]", render: (f) => <span>{f.detail}</span> },
          { key: "source", header: "Source", sortValue: (f) => f.source, className: "text-muted" },
        ];
        return (
          <section key={g} aria-label={EVIDENCE_LABEL[g]}>
            <div className="mb-2 flex flex-wrap items-baseline gap-x-3">
              <h3 className="font-display text-base"><EvidenceTag type={g} /></h3>
              <p className="text-xs text-muted">{EVIDENCE_HELP[g]}</p>
            </div>
            <DataTable rows={items} columns={cols} rowKey={(f) => f.id} caption={`${EVIDENCE_LABEL[g]} findings`} searchPlaceholder="Search findings" pageSize={15} />
          </section>
        );
      })}
    </div>
  );
}

export function SourcesPanel({ a }: { a: Assessment }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">Every lookup that contributed to this assessment, including the ones that failed or were not available. Nothing is filled in for a lookup that did not succeed.</p>
      {a.sources.length === 0 ? <EmptyState title="No external sources">This assessment did not consult any external data source.</EmptyState> : (
        <ul className="divide-y divide-line rounded-lg border border-line">
          {a.sources.map((s) => (
            <li key={s.id} className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1 px-3.5 py-3">
              <div className="min-w-0"><p className="text-sm font-medium">{s.name}</p>{s.reference && <p className="break-all font-mono text-xs text-faint">{s.reference}</p>}{s.detail && <p className="mt-0.5 text-xs text-muted">{s.detail}</p>}</div>
              <SourceStatus status={s.status} />
            </li>
          ))}
        </ul>
      )}
      {a.errors.length > 0 && (
        <Notice tone="warn" title="Errors recorded">
          <ul className="list-disc pl-4">{a.errors.map((e, i) => <li key={i}>{e.step ? `${e.step}: ` : ""}{e.message}</li>)}</ul>
        </Notice>
      )}
    </div>
  );
}

export function ExportMenu({ a, mode, tables }: { a: Assessment; mode: Mode; tables: string[] }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async (key: string, format: "pdf" | "json" | "csv", table?: string) => {
    setBusy(key); setError(null);
    try {
      const res = await fetch(api.exportUrl(mode, a.id, format, table));
      if (!res.ok) { const b = await res.json().catch(() => null); throw new Error(b?.error?.message ?? `Export failed (HTTP ${res.status}).`); }
      const cd = res.headers.get("content-disposition") ?? "";
      const name = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/.exec(cd)?.[1] ?? `cyberrecon-${fileSafe(a.id)}.${format}`;
      download(await res.blob(), decodeURIComponent(name));
    } catch (e) { setError(errMsg(e)); } finally { setBusy(null); }
  };
  if (mode === "demo") {
    return <Button size="sm" loading={busy === "pdf"} onClick={() => run("pdf", "pdf")}><Download className="size-4" />Sample report (PDF)</Button>;
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="primary" loading={busy === "pdf"} onClick={() => run("pdf", "pdf")}><Download className="size-4" />PDF report</Button>
      <Button size="sm" loading={busy === "json"} onClick={() => run("json", "json")}>JSON</Button>
      {tables.filter((t) => t !== "findings" && t !== "sources").concat(["findings"]).map((t) => (
        <Button key={t} size="sm" loading={busy === t} onClick={() => run(t, "csv", t)}>CSV: {t.replace("_", " ")}</Button>
      ))}
      {error && <span role="alert" className="text-xs text-rose">{error}</span>}
    </div>
  );
}

export const Limitations = ({ items }: { items?: string[] }) => !items?.length ? null : (
  <Notice tone="info" title="Limitations"><ul className="list-disc pl-4">{items.map((l) => <li key={l}>{l}</li>)}</ul></Notice>
);
