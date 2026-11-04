import { Camera, Globe, Image as ImageIcon, Network, PlayCircle } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Link, useNavigate } from "react-router-dom";
import { Button, EmptyState, ErrorState, LoadingBlock, Notice, Panel, SeverityBadge, Skeleton, Stat, StatusBadge } from "../components/ui";
import { fmtDate, fmtDay, fmtMs, MODULE_LABEL } from "../lib/format";
import { useDashboard } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { PageHead } from "./ModulePage";

const SEV_COLOR = { high: "#e0685f", medium: "#d6a64b", low: "#3db8d4", info: "#5d6e67" } as const;
const tip = { contentStyle: { background: "#1a2420", border: "1px solid #34443d", borderRadius: 8, fontSize: 12 }, itemStyle: { color: "#e4ebe8" }, labelStyle: { color: "#8a9b94" }, cursor: { fill: "rgba(255,255,255,.04)" } };

export function Dashboard() {
  const { mode, setMode } = useMode();
  const q = useDashboard(mode);
  const nav = useNavigate();
  if (q.isLoading) return <div className="space-y-5"><Skeleton className="h-10 w-72" /><div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-24" />)}</div><LoadingBlock label="Loading the dashboard" rows={4} /></div>;
  if (q.isError) return <ErrorState title="The dashboard could not be loaded" message={(q.error as Error).message} onRetry={() => q.refetch()} />;
  const d = q.data!;
  const empty = d.totals.assessments === 0;
  const sevData = (Object.keys(SEV_COLOR) as (keyof typeof SEV_COLOR)[]).map((k) => ({ name: k, count: d.findings_by_severity[k] ?? 0 }));
  const modData = Object.entries(d.module_usage).map(([k, v]) => ({ name: MODULE_LABEL[k], count: v }));

  return (
    <div className="space-y-6">
      <PageHead title={mode === "demo" ? "Demo workspace" : "Workspace"} lede={mode === "demo" ? "Simulated assessments for a fictional organisation." : "Everything here is computed from assessments saved on this server."} action={
        <div className="flex flex-wrap gap-2"><Button variant="primary" onClick={() => nav("/app/website")}><Globe className="size-4" />Website</Button><Button onClick={() => nav("/app/infrastructure")}><Network className="size-4" />Infrastructure</Button>
          <Button onClick={() => nav("/app/images")}><ImageIcon className="size-4" />Image</Button><Button onClick={() => nav("/app/screenshots")}><Camera className="size-4" />Screenshot</Button></div>} />
      {mode === "demo" && d.notice && <Notice tone="demo" title="Simulated data">{d.notice}</Notice>}
      {empty ? (
        <EmptyState icon={<PlayCircle className="size-9" />} title="No assessments yet" action={<><Button variant="primary" onClick={() => nav("/app/website")}>Start an assessment</Button><Button onClick={() => { setMode("demo"); }}>Explore with demo data</Button></>}>
          Your dashboard fills in as you run assessments. Want to see how it looks first? Demo data is simulated, clearly labelled and kept separate from your real results.
        </EmptyState>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Assessments" value={d.totals.assessments} hint={`${d.totals.completed} completed · ${d.totals.partial} partial · ${d.totals.failed} failed`} />
            <Stat label="Targets" value={d.totals.targets} hint="distinct" />
            <Stat label="Findings" value={d.totals.findings} hint={`${d.findings_by_severity.high} high · ${d.findings_by_severity.medium} medium`} tone={d.findings_by_severity.high ? "bad" : undefined} />
            <Stat label="Reports" value={d.totals.reports} hint="generated" />
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Module usage">
              <div className="h-52" role="img" aria-label={`Assessments per module: ${modData.map((m) => `${m.name} ${m.count}`).join(", ")}`}>
                <ResponsiveContainer width="100%" height="100%"><BarChart data={modData} margin={{ left: -20, top: 4 }}><CartesianGrid stroke="#26332e" vertical={false} /><XAxis dataKey="name" stroke="#8a9b94" fontSize={12} tickLine={false} /><YAxis allowDecimals={false} stroke="#8a9b94" fontSize={12} tickLine={false} axisLine={false} /><Tooltip {...tip} /><Bar dataKey="count" name="Assessments" fill="#2fbf8f" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer>
              </div>
              {Object.keys(d.avg_duration_ms).length > 0 && <p className="mt-2 text-xs text-muted">Average duration: {Object.entries(d.avg_duration_ms).map(([m, v]) => `${MODULE_LABEL[m]} ${fmtMs(v)}`).join(" · ")}</p>}
            </Panel>
            <Panel title="Findings by severity">
              <div className="h-52" role="img" aria-label={`Findings by severity: ${sevData.map((s) => `${s.name} ${s.count}`).join(", ")}`}>
                <ResponsiveContainer width="100%" height="100%"><BarChart data={sevData} layout="vertical" margin={{ left: 10, right: 20 }}><CartesianGrid stroke="#26332e" horizontal={false} /><XAxis type="number" allowDecimals={false} stroke="#8a9b94" fontSize={12} tickLine={false} /><YAxis type="category" dataKey="name" stroke="#8a9b94" fontSize={12} width={60} tickLine={false} axisLine={false} /><Tooltip {...tip} />
                  <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} shape={(p: any) => <rect x={p.x} y={p.y} width={Math.max(p.width, 0)} height={p.height} rx={4} fill={SEV_COLOR[p.payload.name as keyof typeof SEV_COLOR]} />} /></BarChart></ResponsiveContainer>
              </div>
            </Panel>
          </div>
          <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
            <Panel title="Recent assessments" action={<Link to="/app/history" className="text-sm text-cyan hover:underline">View all</Link>} pad={false}>
              <ul className="divide-y divide-line">{d.recent.map((r) => (
                <li key={r.id}><Link to={`/app/assessments/${r.id}`} className="flex items-center justify-between gap-3 px-4 py-3 hover:bg-raised/50">
                  <span className="min-w-0"><span className="block truncate font-mono text-sm">{r.target}</span><span className="text-xs text-muted">{MODULE_LABEL[r.module]} · {fmtDate(r.created_at)} · {r.findings} findings</span></span><StatusBadge status={r.status} /></Link></li>))}</ul>
            </Panel>
            <Panel title="Trend">
              {d.trend.sufficient ? (
                <div className="h-44" role="img" aria-label="Assessments per day"><ResponsiveContainer width="100%" height="100%"><LineChart data={d.trend.days.map((x) => ({ ...x, label: fmtDay(x.date) }))} margin={{ left: -20 }}><CartesianGrid stroke="#26332e" vertical={false} /><XAxis dataKey="label" stroke="#8a9b94" fontSize={11} tickLine={false} /><YAxis allowDecimals={false} stroke="#8a9b94" fontSize={11} tickLine={false} axisLine={false} /><Tooltip {...tip} /><Line dataKey="count" name="Assessments" stroke="#3db8d4" strokeWidth={2} dot={{ r: 3 }} /></LineChart></ResponsiveContainer></div>
              ) : <p className="text-sm text-muted">A trend appears after at least {d.trend.min_assessments} assessments across {d.trend.min_days} different days. Until then a line would show noise, not a pattern.</p>}
            </Panel>
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Top findings" pad={false}>
              {d.top_findings.length === 0 ? <p className="p-4 text-sm text-muted">No high or medium findings. Low and informational ones are listed inside each assessment.</p> : (
                <ul className="divide-y divide-line">{d.top_findings.map((f) => (<li key={f.id}><Link to={`/app/assessments/${f.assessment_id}`} className="flex items-start gap-3 px-4 py-3 hover:bg-raised/50"><SeverityBadge severity={f.severity} /><span className="min-w-0 text-sm"><span className="block">{f.title}</span><span className="font-mono text-xs text-muted">{f.target}</span></span></Link></li>))}</ul>)}
            </Panel>
            <Panel title="Target history" pad={false}>
              <ul className="divide-y divide-line">{d.target_history.map((t) => (<li key={t.target} className="flex items-center justify-between gap-3 px-4 py-3 text-sm"><span className="min-w-0"><span className="block truncate font-mono">{t.target}</span><span className="text-xs text-muted">{t.modules.map((m) => MODULE_LABEL[m]).join(", ")} · last {fmtDate(t.last_at)}</span></span><span className="shrink-0 text-xs text-muted tabular-nums">{t.assessments}×</span></li>))}</ul>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
