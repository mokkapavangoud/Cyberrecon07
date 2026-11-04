import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { Link } from "react-router-dom";
import { Button, EmptyState, ErrorState, LoadingBlock, Notice } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtDate, MODULE_LABEL } from "../lib/format";
import { useAssessments } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { PageHead } from "./ModulePage";

export function Reports() {
  const { mode } = useMode();
  const live = useQuery({ queryKey: ["reports"], queryFn: api.listReports, enabled: mode === "live" });
  const demo = useAssessments("demo", {});
  return (
    <div className="space-y-5">
      <PageHead title="Reports" lede="Reports are generated from saved assessment data. Open an assessment and choose PDF, JSON or CSV to create one." />
      {mode === "demo" ? (
        <>
          <Notice tone="demo" title="Sample reports">These PDFs are built from the simulated data and carry a watermark.</Notice>
          {demo.isLoading ? <LoadingBlock rows={3} /> : (
            <ul className="divide-y divide-line rounded-xl border border-line bg-panel">{(demo.data?.items ?? []).map((i) => (
              <li key={i.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"><span><span className="block font-mono text-sm">{i.target}</span><span className="text-xs text-muted">{MODULE_LABEL[i.module]} · simulated</span></span>
                <a href={api.exportUrl("demo", i.id, "pdf")} download><Button size="sm"><Download className="size-4" />Sample PDF</Button></a></li>))}</ul>)}
        </>
      ) : live.isLoading ? <LoadingBlock rows={4} label="Loading reports" /> : live.isError ? <ErrorState message={(live.error as Error).message} onRetry={() => live.refetch()} /> : live.data!.items.length === 0 ? (
        <EmptyState title="No reports generated yet" action={<Link to="/app/history"><Button variant="primary">Open an assessment</Button></Link>}>Open any finished assessment and choose “PDF report”. It will be listed here.</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-line bg-panel"><table className="w-full min-w-[600px] text-left text-sm"><caption className="sr-only">Generated reports</caption>
          <thead className="text-xs text-muted"><tr><th className="px-4 py-2.5 font-medium">Report</th><th className="px-3 py-2.5 font-medium">Target</th><th className="px-3 py-2.5 font-medium">Created</th><th className="px-3 py-2.5 font-medium">Size</th><th /></tr></thead>
          <tbody>{live.data!.items.map((r) => (<tr key={r.id} className="border-t border-line"><td className="px-4 py-3"><span className="block">{r.format.toUpperCase()}{r.variant ? ` · ${r.variant.replace("_", " ")}` : ""}</span><span className="font-mono text-xs text-muted">{r.filename}</span></td>
            <td className="px-3 py-3"><Link className="font-mono text-[0.82rem] text-cyan hover:underline" to={`/app/assessments/${r.assessment_id}`}>{r.target}</Link><span className="block text-xs text-muted">{MODULE_LABEL[r.module]}</span></td>
            <td className="px-3 py-3 text-muted">{fmtDate(r.created_at)}</td><td className="px-3 py-3 text-muted">{fmtBytes(r.size_bytes)}</td><td className="px-3 py-3 text-right"><a href={r.download_url} download><Button size="sm"><Download className="size-4" />Download</Button></a></td></tr>))}</tbody></table></div>
      )}
    </div>
  );
}
