import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Check, ConfirmDialog, ErrorState, KV, LoadingBlock, Notice, Panel, SourceStatus } from "../components/ui";
import { api } from "../lib/api";
import { errMsg, fmtBytes } from "../lib/format";
import { useConfig, useHealth } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { PageHead } from "./ModulePage";

export function SettingsPage() {
  const cfg = useConfig();
  const health = useHealth();
  const { mode, setMode } = useMode();
  const qc = useQueryClient();
  const wipe = useMutation({ mutationFn: api.deleteAll, onSuccess: () => qc.invalidateQueries() });
  return (
    <div className="space-y-5">
      <PageHead title="Settings" lede="Server capabilities and privacy settings. Secrets such as API keys stay on the server and are never shown here." />
      <Panel title="Demo mode"><Check checked={mode === "demo"} onChange={(v) => setMode(v ? "demo" : "live")}>Show simulated demo data <span className="text-muted">— a fictional organisation, kept apart from your real results. Assessments cannot be started while it is on.</span></Check></Panel>
      {cfg.isLoading ? <LoadingBlock rows={4} /> : cfg.isError ? <ErrorState title="Server settings are unavailable" message={(cfg.error as Error).message} onRetry={() => cfg.refetch()} /> : (
        <>
          <Panel title="Capabilities"><ul className="space-y-3 text-sm">
            <li className="flex flex-wrap justify-between gap-2"><span><span className="font-medium">Website screenshots</span><span className="block text-muted">{cfg.data!.capabilities.screenshots.reason ?? "Isolated headless Chromium is ready."}</span></span><SourceStatus status={cfg.data!.capabilities.screenshots.available ? "ok" : "unavailable"} /></li>
            <li className="flex flex-wrap justify-between gap-2"><span><span className="font-medium">Passive subdomains ({cfg.data!.capabilities.subdomains.provider})</span><span className="block text-muted">{cfg.data!.capabilities.subdomains.reason ?? "Reported names come from a public certificate-transparency index."}</span></span><SourceStatus status={cfg.data!.capabilities.subdomains.available ? "ok" : "unavailable"} /></li>
            <li className="flex flex-wrap justify-between gap-2"><span><span className="font-medium">IP geolocation ({cfg.data!.capabilities.geoip.provider})</span><span className="block text-muted">{cfg.data!.capabilities.geoip.reason ?? "Estimates only."}</span></span><SourceStatus status={cfg.data!.capabilities.geoip.available ? "ok" : "unavailable"} /></li>
          </ul></Panel>
          <Panel title="Limits and privacy"><KV rows={[["Upload limit", fmtBytes(cfg.data!.limits.max_upload_bytes)], ["Link checks per assessment", `up to ${cfg.data!.limits.link_check_max_limit}`], ["Ports", cfg.data!.limits.allowed_ports.join(", ")], ["Redirects followed", `up to ${cfg.data!.limits.max_redirects}, each re-validated`],
            ["Page size limit", fmtBytes(cfg.data!.limits.max_response_bytes)], ["Requests per minute", cfg.data!.limits.rate_limit_per_minute], ["Uploaded images stored", cfg.data!.privacy.uploaded_images_stored ? "Yes" : "Never"], ["GPS coordinates kept in history", cfg.data!.privacy.image_gps_persisted ? "Yes (server setting)" : "No — redacted by default"], ["Target allowlist", cfg.data!.target_allowlist_active ? "Active" : "Not configured"]]} /></Panel>
          <Panel title="About"><KV rows={[["Version", cfg.data!.version], ["Environment", cfg.data!.environment], ["API", health.isError ? "Unreachable" : health.data ? `${health.data.status} · database ${health.data.database}` : "Checking"]]} /></Panel>
        </>
      )}
      <Panel title="Delete saved data">
        <p className="mb-3 text-sm text-muted">Permanently removes every assessment, finding, report and screenshot stored on this server.</p>
        <ConfirmDialog trigger={<Button variant="danger" disabled={mode === "demo"}>Delete all saved data</Button>} title="Delete all saved data?" confirmLabel="Delete everything" busy={wipe.isPending} onConfirm={() => wipe.mutateAsync().then(() => undefined)} description="This cannot be undone." />
        {mode === "demo" && <p className="mt-2 text-xs text-muted">Turn off demo mode to manage real data.</p>}
        {wipe.isSuccess && <div className="mt-3"><Notice tone="ok">Deleted {wipe.data.deleted} assessment(s).</Notice></div>}
        {wipe.isError && <p role="alert" className="mt-2 text-sm text-rose">{errMsg(wipe.error)}</p>}
      </Panel>
    </div>
  );
}
