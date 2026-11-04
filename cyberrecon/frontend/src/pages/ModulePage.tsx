import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Button, Check, ErrorState, Field, inputCls, LoadingBlock, Notice, Panel, StatusBadge } from "../components/ui";
import { api, ApiError, type Module } from "../lib/api";
import { fmtDate } from "../lib/format";
import { useAssessment, useAssessments, useConfig } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { AssessmentView } from "../views/AssessmentView";

type M = Exclude<Module, "image">;
const COPY: Record<M, { title: string; lede: string; placeholder: string; what: string[]; demoId: string }> = {
  link: { title: "Website and link intelligence", lede: "Fetch one page and map what it exposes: status, headers, metadata, links, robots.txt and sitemap.", placeholder: "https://example.org", demoId: "demo-link-aurora",
    what: ["One page request, plus robots.txt and a sitemap lookup", "Links are discovered from the page source; checking them is optional and capped", "robots.txt is always obeyed and external sites are never crawled"] },
  infrastructure: { title: "Domain and infrastructure intelligence", lede: "Collect DNS, registration, network ownership, TLS and passive subdomain data, then see how it connects.", placeholder: "example.org", demoId: "demo-infrastructure-aurora",
    what: ["Public DNS queries, RDAP registration and ASN lookups", "One TLS handshake on port 443 to read the certificate", "Subdomains only from a passive source. No guessing, no port scanning"] },
  screenshot: { title: "Website screenshot", lede: "Capture how a page renders in an isolated headless browser.", placeholder: "https://example.org", demoId: "",
    what: ["Runs in a fresh, isolated Chromium profile", "Every request the page makes is checked against the same network rules", "A failed capture is reported as a failure. No placeholder image is ever shown"] },
};

export function ModulePage({ module }: { module: M }) {
  const c = COPY[module];
  const { mode } = useMode();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const cfg = useConfig();
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [authorized, setAuthorized] = useState(false);
  const [checkLinks, setCheckLinks] = useState(false);
  const [checkExternal, setCheckExternal] = useState(false);
  const [maxLinks, setMaxLinks] = useState(25);
  const [includeHttp, setIncludeHttp] = useState(true);
  useEffect(() => { const t = params.get("target"); if (t) setTarget(t); }, [params]);

  const recent = useAssessments("live", { module, limit: 5 }, mode === "live");
  const demo = useAssessment("demo", mode === "demo" && c.demoId ? c.demoId : undefined);
  const shots = cfg.data?.capabilities.screenshots;
  const blocked = module === "screenshot" && cfg.data && !shots?.available;

  const start = useMutation({
    mutationFn: () => api.createAssessment(module, { target, authorized, options: module === "link" ? { check_links: checkLinks, check_external: checkLinks && checkExternal, max_links_to_check: maxLinks } : module === "infrastructure" ? { include_http: includeHttp } : {} }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["assessments"] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); nav(`/app/assessments/${r.id}`); },
  });
  const err = start.error as ApiError | null;

  if (mode === "demo") {
    return (
      <div className="space-y-5">
        <PageHead title={c.title} lede="Demo mode is on. New assessments are disabled so simulated and real data never mix. Below is a simulated example." />
        {!c.demoId ? <Notice tone="demo" title="No simulated screenshot">CyberRecon never fabricates screenshots, so the demo has none. Exit demo mode and capture a real page, or read the other modules' examples.</Notice> :
          demo.isLoading ? <LoadingBlock label="Loading the simulated example" rows={4} /> : demo.isError ? <ErrorState message={(demo.error as Error).message} onRetry={() => demo.refetch()} /> : demo.data && <AssessmentView a={demo.data} mode="demo" />}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHead title={c.title} lede={c.lede} />
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <Panel title="New assessment">
          <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); start.mutate(); }} noValidate>
            <Field label={module === "infrastructure" ? "Domain, hostname or URL" : "Website address"} hint="Only public targets are accepted. Private, loopback, link-local and cloud-metadata addresses are rejected before anything is requested.">
              {(id) => <input id={id} className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)} placeholder={c.placeholder} autoComplete="off" spellCheck={false} aria-invalid={!!err?.extra?.error?.field} aria-describedby={err ? "form-error" : undefined} />}
            </Field>
            {module === "link" && (
              <fieldset className="space-y-2.5 rounded-lg border border-line p-3.5">
                <legend className="px-1 text-sm font-medium">Link checking</legend>
                <Check checked={checkLinks} onChange={setCheckLinks}>Check discovered links <span className="text-muted">(one HEAD request each, up to the limit)</span></Check>
                {checkLinks && <>
                  <Check checked={checkExternal} onChange={setCheckExternal}>Include links to other websites <span className="text-muted">(single requests only, never crawled)</span></Check>
                  <Field label="Maximum links to check">{(id) => <input id={id} type="number" min={1} max={cfg.data?.limits.link_check_max_limit ?? 100} className={`${inputCls} w-28!`} value={maxLinks} onChange={(e) => setMaxLinks(Math.max(1, Math.min(Number(e.target.value) || 1, cfg.data?.limits.link_check_max_limit ?? 100)))} />}</Field></>}
                {!checkLinks && <p className="text-xs text-muted">Off by default. Links are listed as “not checked” unless you turn this on.</p>}
              </fieldset>
            )}
            {module === "infrastructure" && <Check checked={includeHttp} onChange={setIncludeHttp}>Also read response headers for technology hints <span className="text-muted">(up to two page requests)</span></Check>}
            <div className="rounded-lg border border-emerald/30 bg-emerald/5 p-3.5">
              <Check checked={authorized} onChange={setAuthorized}><span className="font-medium">I own this target or have permission to assess it.</span> <span className="text-muted">CyberRecon runs passive, non-intrusive requests only. It does not exploit, brute-force or bypass anything, and the confirmation is saved with the report.</span></Check>
            </div>
            {err && (
              <div id="form-error" role="alert" className="rounded-lg border border-rose/40 bg-rose/5 px-3.5 py-3 text-sm">
                <p className="font-medium text-rose">{err.code === "authorization_required" ? "Confirm authorisation first" : err.code === "rate_limited" ? "Too many requests" : "This assessment could not start"}</p>
                <p className="text-muted">{err.message}</p>
              </div>
            )}
            {blocked && <Notice tone="warn" title="Screenshots are not available">{shots?.reason}</Notice>}
            <Button type="submit" variant="primary" loading={start.isPending} disabled={!target.trim() || !authorized || !!blocked}><ShieldCheck className="size-4" />Start assessment</Button>
            {(!authorized || !target.trim()) && <p className="text-xs text-muted">{!target.trim() ? "Enter a target to continue." : "Confirm authorisation to enable the button."}</p>}
          </form>
        </Panel>
        <div className="space-y-5">
          <Panel title="What it does"><ul className="list-disc space-y-2 pl-4 text-sm text-muted">{c.what.map((w) => <li key={w}>{w}</li>)}</ul></Panel>
          {module === "infrastructure" && cfg.data && (
            <Panel title="Data providers">
              <ul className="space-y-2 text-sm">
                <li><span className="font-medium">Subdomains</span><br /><span className="text-muted">{cfg.data.capabilities.subdomains.available ? `Passive source: ${cfg.data.capabilities.subdomains.provider}` : `Not configured. ${cfg.data.capabilities.subdomains.reason ?? ""}`}</span></li>
                <li><span className="font-medium">IP geolocation</span><br /><span className="text-muted">{cfg.data.capabilities.geoip.available ? `Provider: ${cfg.data.capabilities.geoip.provider} (estimates)` : "Not configured. Location will show as unavailable."}</span></li>
              </ul>
            </Panel>
          )}
          <Panel title="Recent">
            {recent.isLoading ? <LoadingBlock rows={2} /> : recent.isError ? <p className="text-sm text-muted">History could not be loaded.</p> : recent.data!.items.length === 0 ? <p className="text-sm text-muted">Nothing yet. Your assessments will be listed here.</p> : (
              <ul className="space-y-2">{recent.data!.items.map((i) => (
                <li key={i.id}><Link to={`/app/assessments/${i.id}`} className="block rounded-lg border border-line bg-canvas px-3 py-2 hover:border-muted"><span className="block truncate font-mono text-xs">{i.target}</span><span className="mt-1 flex items-center justify-between text-xs text-muted"><span>{fmtDate(i.created_at)}</span><StatusBadge status={i.status} /></span></Link></li>))}</ul>)}
          </Panel>
        </div>
      </div>
    </div>
  );
}

export function PageHead({ title, lede, action }: { title: string; lede?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="max-w-2xl"><h1 className="font-display text-3xl">{title}</h1>{lede && <p className="mt-1.5 text-muted">{lede}</p>}</div>{action}
    </div>
  );
}
