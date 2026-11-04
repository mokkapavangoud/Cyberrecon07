import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, ConfirmDialog, EmptyState, ErrorState, inputCls, LoadingBlock, Notice, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { errMsg, fmtDate, fmtMs, MODULE_LABEL } from "../lib/format";
import { useAssessments } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { PageHead } from "./ModulePage";

const PAGE = 20;

export function History() {
  const { mode, setMode } = useMode();
  const qc = useQueryClient();
  const [q, setQ] = useState(""); const [module, setModule] = useState(""); const [status, setStatus] = useState(""); const [page, setPage] = useState(0);
  const list = useAssessments(mode, { q, module, status, limit: PAGE, offset: page * PAGE });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["assessments"] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); qc.invalidateQueries({ queryKey: ["reports"] }); };
  const del = useMutation({ mutationFn: (id: string) => api.deleteAssessment(id), onSuccess: refresh });
  const delAll = useMutation({ mutationFn: api.deleteAll, onSuccess: refresh });

  const items = mode === "demo" ? (list.data?.items ?? []).filter((i) => (!module || i.module === module) && (!status || i.status === status) && (!q || i.target.toLowerCase().includes(q.toLowerCase()))) : list.data?.items ?? [];
  const total = mode === "demo" ? items.length : list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));
  return (
    <div className="space-y-5">
      <PageHead title="History" lede="Every saved assessment. Open one to see its full results again, or delete what you no longer need." action={mode === "live" && total > 0 ? (
        <ConfirmDialog trigger={<Button variant="danger" size="sm"><Trash2 className="size-4" />Delete all</Button>} title="Delete all saved data?" confirmLabel="Delete everything" busy={delAll.isPending} onConfirm={() => delAll.mutateAsync().then(() => undefined)}
          description="This permanently removes every assessment, finding, report and screenshot from this server. It cannot be undone." />) : undefined} />
      {mode === "demo" && <Notice tone="demo" title="Showing simulated records">Switch back to live mode to see your own saved assessments.</Notice>}
      <div className="flex flex-wrap gap-2">
        <input aria-label="Search by target" placeholder="Search targets" className={`${inputCls} min-w-52 flex-1`} value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
        <select aria-label="Module" className={`${inputCls} w-auto!`} value={module} onChange={(e) => { setModule(e.target.value); setPage(0); }}><option value="">All modules</option>{Object.entries(MODULE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select aria-label="Status" className={`${inputCls} w-auto!`} value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}><option value="">Any status</option>{["completed", "partial", "failed", "running", "queued"].map((s) => <option key={s} value={s}>{s}</option>)}</select>
      </div>
      {(del.isError || delAll.isError) && <p role="alert" className="text-sm text-rose">{errMsg(del.error ?? delAll.error)}</p>}
      {list.isLoading ? <LoadingBlock rows={5} label="Loading history" /> : list.isError ? <ErrorState title="History could not be loaded" message={(list.error as Error).message} onRetry={() => list.refetch()} /> : items.length === 0 ? (
        (q || module || status) ? <EmptyState title="No assessments match">Clear the search or filters to see everything.</EmptyState> :
          <EmptyState title="Nothing saved yet" action={<><Link to="/app/website"><Button variant="primary">Start an assessment</Button></Link><Button onClick={() => setMode("demo")}>Explore demo data</Button></>}>Completed assessments appear here so you can reopen and export them later.</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-line bg-panel">
          <table className="w-full min-w-[640px] text-left text-sm">
            <caption className="sr-only">Saved assessments</caption>
            <thead className="text-xs text-muted"><tr><th className="px-4 py-2.5 font-medium">Target</th><th className="px-3 py-2.5 font-medium">Module</th><th className="px-3 py-2.5 font-medium">Status</th><th className="px-3 py-2.5 font-medium">Findings</th><th className="px-3 py-2.5 font-medium">Started</th><th className="px-3 py-2.5 font-medium">Took</th><th className="px-3 py-2.5" /></tr></thead>
            <tbody>{items.map((i) => (
              <tr key={i.id} className="border-t border-line hover:bg-raised/40">
                <td className="max-w-[18rem] px-4 py-3"><Link className="block truncate font-mono text-[0.82rem] text-cyan hover:underline" to={`/app/assessments/${i.id}`}>{i.target}</Link></td>
                <td className="px-3 py-3">{MODULE_LABEL[i.module]}</td><td className="px-3 py-3"><StatusBadge status={i.status} /></td><td className="px-3 py-3 tabular-nums">{i.findings}</td>
                <td className="px-3 py-3 text-muted">{fmtDate(i.created_at)}</td><td className="px-3 py-3 text-muted">{fmtMs(i.duration_ms)}</td>
                <td className="px-3 py-3 text-right">{mode === "live" && <ConfirmDialog trigger={<button className="rounded p-1.5 text-muted hover:bg-rose/10 hover:text-rose" aria-label={`Delete assessment of ${i.target}`}><Trash2 className="size-4" /></button>} title="Delete this assessment?" confirmLabel="Delete" busy={del.isPending}
                  description={<>The saved results, findings and reports for <span className="font-mono">{i.target}</span> will be removed permanently.</>} onConfirm={() => del.mutateAsync(i.id).then(() => undefined)} />}</td>
              </tr>))}</tbody>
          </table>
        </div>
      )}
      {pages > 1 && <div className="flex items-center justify-between text-sm text-muted"><Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button><span>Page {page + 1} of {pages}</span><Button size="sm" variant="ghost" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</Button></div>}
    </div>
  );
}
