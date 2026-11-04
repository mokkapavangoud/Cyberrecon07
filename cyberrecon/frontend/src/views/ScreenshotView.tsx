import { useState } from "react";
import { ErrorState, KV, Mono, Panel, Tabs } from "../components/ui";
import { api, type Assessment, type Mode } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { ExportMenu, FindingsPanel, Limitations, SourcesPanel } from "./common";

export function ScreenshotView({ a, mode }: { a: Assessment; mode: Mode }) {
  const [tab, setTab] = useState<"capture" | "findings" | "sources">("capture");
  const r = a.result;
  if (!r) return <ErrorState title="No result data" message="This assessment did not store any result data." />;
  const failed = r.failure || r.unavailable;
  return (
    <div className="space-y-5">
      <ExportMenu a={a} mode={mode} tables={[]} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "capture", label: "Capture" }, { id: "findings", label: "Findings", count: a.findings.length }, { id: "sources", label: "Sources" }]} />
      {tab === "capture" && (failed ? (
        <ErrorState title={r.unavailable ? "Screenshots are not available" : "The screenshot could not be captured"} message={r.failure?.message ?? r.unavailable} />
      ) : (
        <div className="space-y-5">
          <Panel title="Captured page" pad={false}>
            <img src={api.screenshotUrl(a.id)} alt={`Screenshot of ${r.final_url}`} className="w-full rounded-b-xl bg-canvas" width={r.image.width} height={r.image.height} />
          </Panel>
          <Panel title="Capture details"><KV rows={[["Requested URL", <Mono key="a">{r.requested_url}</Mono>], ["Final URL", <Mono key="b">{r.final_url}</Mono>], ["HTTP status", r.http_status], ["Page title", r.title],
            ["Captured at", r.captured_at], ["Mode", r.capture_mode], ["Browser", `${r.browser.name} ${r.browser.version}`], ["Image", `PNG · ${r.image.width}×${r.image.height} · ${fmtBytes(r.image.size_bytes)}`],
            ["SHA-256", <Mono key="h">{r.image.sha256}</Mono>], ["Requests blocked by policy", r.blocked_requests?.length]]} />
            {r.blocked_requests?.length > 0 && <ul className="mt-3 space-y-1 text-xs text-muted">{r.blocked_requests.slice(0, 8).map((b: any, i: number) => <li key={i}><Mono>{b.url}</Mono> — {b.reason}</li>)}</ul>}</Panel>
          <Limitations items={r.limitations} />
        </div>
      ))}
      {tab === "findings" && <FindingsPanel findings={a.findings} />}
      {tab === "sources" && <SourcesPanel a={a} />}
    </div>
  );
}
