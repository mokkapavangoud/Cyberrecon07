import { ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, Notice, Panel, StatusBadge } from "../components/ui";
import { TERMINAL, type Assessment, type Mode } from "../lib/api";
import { fmtDate, fmtMs, MODULE_LABEL } from "../lib/format";
import { StepList } from "./common";
import { ImageView } from "./ImageView";
import { InfraView } from "./InfraView";
import { LinkView } from "./LinkView";
import { ScreenshotView } from "./ScreenshotView";

/** One component renders any persisted (or demo) assessment: header, real progress while running, then the module's result. */
export function AssessmentView({ a, mode, liveResult, file }: { a: Assessment; mode: Mode; liveResult?: any; file?: File | null }) {
  const active = !TERMINAL.includes(a.status);
  return (
    <div className="space-y-5">
      <header className="rounded-xl border border-line bg-panel p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs text-muted">{MODULE_LABEL[a.module]} assessment · <span className="font-mono">{a.id}</span></p>
            <h1 className="mt-1 break-all font-display text-2xl">{a.target}</h1>
          </div>
          <StatusBadge status={a.status} />
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <div><dt className="text-xs text-muted">Started</dt><dd>{fmtDate(a.started_at ?? a.created_at)}</dd></div>
          <div><dt className="text-xs text-muted">Duration</dt><dd>{fmtMs(a.duration_ms)}</dd></div>
          <div><dt className="text-xs text-muted">Findings</dt><dd>{a.findings.length}</dd></div>
          <div><dt className="text-xs text-muted">Authorisation</dt><dd className="inline-flex items-center gap-1.5">{a.authorization.confirmed ? <><ShieldCheck className="size-4 text-emerald" aria-hidden />Confirmed</> : a.module === "image" ? "Not needed (local file)" : "Not recorded"}</dd></div>
        </dl>
        {a.authorization.confirmed && a.authorization.confirmed_at && <p className="mt-2 text-xs text-muted">{a.authorization.statement} ({fmtDate(a.authorization.confirmed_at)})</p>}
      </header>
      {mode === "demo" && <Notice tone="demo" title="Simulated example">{a.notice ?? "This record is simulated demo data for a fictional organisation. Nothing was retrieved from the internet."}</Notice>}
      {a.error && !active && a.status === "failed" && !(a.result && (a.result.fetch_error || a.result.rejected || a.result.failure || a.result.unavailable)) && <ErrorState title="The assessment failed" message={a.error} />}
      {active ? (
        <Panel title="Assessment in progress"><StepList steps={a.steps} percent={a.progress.percent} /><p className="mt-3 text-xs text-muted">Progress shows the backend's real step status. You can leave this page; the assessment keeps running and is saved to history.</p></Panel>
      ) : (
        <>
          {a.status !== "failed" || a.result ? (
            <>
              {a.module === "link" && <LinkView a={a} mode={mode} />}
              {a.module === "infrastructure" && <InfraView a={a} mode={mode} />}
              {a.module === "image" && <ImageView a={a} mode={mode} liveResult={liveResult} file={file} />}
              {a.module === "screenshot" && <ScreenshotView a={a} mode={mode} />}
            </>
          ) : null}
          <details className="rounded-xl border border-line bg-panel">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium">How this ran ({a.steps.length} steps)</summary>
            <div className="border-t border-line p-4"><StepList steps={a.steps} /></div>
          </details>
        </>
      )}
      <p className="text-xs text-faint">Back to <Link className="text-muted underline" to="/app/history">history</Link>.</p>
    </div>
  );
}
