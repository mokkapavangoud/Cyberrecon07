import { Download, ExternalLink, EyeOff, MapPin } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button, ErrorState, KV, Mono, Notice, Panel, Stat, Tabs } from "../components/ui";
import { api, type Assessment, type Mode } from "../lib/api";
import { download, errMsg, fmtBytes } from "../lib/format";
import { ExportMenu, FindingsPanel, Limitations, SourcesPanel } from "./common";

type Tab = "metadata" | "privacy" | "findings" | "sources";

/** `liveResult` carries GPS coordinates for the one-time response; stored assessments redact them by default. `file` is the in-browser original. */
export function ImageView({ a, mode, liveResult, file }: { a: Assessment; mode: Mode; liveResult?: any; file?: File | null }) {
  const [tab, setTab] = useState<Tab>("metadata");
  const r = liveResult ?? a.result;
  const preview = useObjectUrl(file);
  if (!r) return <ErrorState title="No result data" message="This assessment did not store any result data." />;
  if (r.rejected) {
    return <div className="space-y-4"><ErrorState title="The upload was rejected" message={r.rejected.message} /><FindingsPanel findings={a.findings} /></div>;
  }
  const f = r.file, md = r.metadata, gps = md.gps, ex = md.exif;
  const sensitive: string[] = r.privacy_summary.sensitive_present;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {file && mode === "live" && <SanitizeButton file={file} />}
        {mode === "live" && <ExportMenu a={a} mode={mode} tables={a.available_exports ?? []} />}
        {mode === "demo" && <ExportMenu a={a} mode={mode} tables={[]} />}
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[{ id: "metadata", label: "Metadata" }, { id: "privacy", label: "Privacy & reverse search" }, { id: "findings", label: "Findings", count: a.findings.length }, { id: "sources", label: "Sources" }]} />
      {tab === "metadata" && (
        <div className="space-y-5">
          <div className="grid gap-5 lg:grid-cols-[minmax(0,320px)_1fr]">
            <Panel title="Preview" className="self-start">
              {preview ? <img src={preview} alt={`Preview of ${f.display_name}`} className="max-h-72 w-full rounded-lg bg-canvas object-contain" /> :
                <p className="text-sm text-muted">{mode === "demo" ? "No image is bundled with the simulated example." : "The preview is only shown right after upload. CyberRecon never stores the image."}</p>}
            </Panel>
            <Panel title="File">
              <KV rows={[["Name (display only)", f.display_name], ["Detected format", `${f.detected_format} — identified from file content`], ["Extension check", f.extension_matches_content === false ? <span key="x" className="text-amber">Extension does not match the content</span> : f.extension_matches_content ? "Matches content" : "No extension"],
                ["Size", fmtBytes(f.size_bytes)], ["Dimensions", `${f.width} × ${f.height} px (${f.megapixels} MP)`], ["Colour mode", f.color_mode], ["Frames", f.frames], ["SHA-256", <Mono key="h">{f.sha256}</Mono>]]} />
            </Panel>
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Location (GPS)">
              {!gps.present ? <p className="text-sm text-muted">No GPS metadata is embedded in this file.</p> : gps.redacted ? (
                <Notice tone="info" title="GPS data present — coordinates withheld">The file contains location data. Stored records keep only the fact that it exists, so coordinates are not available here.</Notice>
              ) : (
                <div className="space-y-3">
                  <KV rows={[["Latitude", <Mono key="a">{gps.latitude}</Mono>], ["Longitude", <Mono key="b">{gps.longitude}</Mono>], ["Altitude", gps.altitude_m != null && `${gps.altitude_m} m`], ["GPS timestamp", gps.timestamp]]} />
                  <a className="inline-flex items-center gap-1.5 text-sm text-cyan hover:underline" target="_blank" rel="noopener noreferrer" href={`https://www.openstreetmap.org/?mlat=${gps.latitude}&mlon=${gps.longitude}#map=14/${gps.latitude}/${gps.longitude}`}>
                    <MapPin className="size-4" aria-hidden />Open in OpenStreetMap<ExternalLink className="size-3.5" aria-hidden /></a>
                  <p className="text-xs text-muted">Opening the map sends these coordinates to a third party. CyberRecon does not load any map itself.</p>
                </div>
              )}
            </Panel>
            <Panel title="Camera, capture and software">
              {!ex.present ? <p className="text-sm text-muted">No EXIF data was found. Messaging apps and social networks often strip it, so its absence says nothing on its own.</p> :
                <KV rows={[...Object.entries({ ...ex.camera, ...ex.capture, ...ex.exposure }).map(([k, v]) => [k, String(v)] as [string, string])]} />}
            </Panel>
          </div>
          <Panel title="Other metadata containers">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              {[["XMP", md.xmp?.present], ["IPTC", md.iptc?.present], ["ICC profile", md.icc_profile?.present], ["Text chunks", md.text_chunks?.present], ["Comment", md.comment?.present]].map(([k, v]) => <Stat key={k as string} label={k as string} value={v ? "Present" : "None"} />)}
            </div>
          </Panel>
          <Limitations items={r.limitations} />
        </div>
      )}
      {tab === "privacy" && (
        <div className="space-y-5">
          <Panel title="What this file could reveal">
            {sensitive.length ? <ul className="list-disc space-y-1 pl-5 text-sm">{sensitive.map((s) => <li key={s}>{s}</li>)}</ul> : <p className="text-sm text-muted">No potentially sensitive embedded fields were found.</p>}
            <ul className="mt-3 space-y-1 text-xs text-muted">{r.privacy_summary.notes.map((n: string) => <li key={n}>{n}</li>)}</ul>
          </Panel>
          <Panel title="Reverse image search" action={<span className="inline-flex items-center gap-1.5 text-xs text-muted"><EyeOff className="size-3.5" aria-hidden />Nothing is uploaded by CyberRecon</span>}>
            <p className="mb-3 text-sm text-muted">These links open third-party search services. You choose whether to upload the image there. CyberRecon does not send your image anywhere and does not identify people.</p>
            <ul className="grid gap-2 sm:grid-cols-2">{(r.reverse_search ?? []).map((s: any) => (
              <li key={s.name}><a href={s.url} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between gap-2 rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm hover:border-cyan">
                <span><span className="font-medium">{s.name}</span><span className="block text-xs text-muted">{s.note}</span></span><ExternalLink className="size-4 shrink-0 text-muted" aria-hidden /></a></li>))}</ul>
          </Panel>
        </div>
      )}
      {tab === "findings" && <FindingsPanel findings={a.findings} />}
      {tab === "sources" && <SourcesPanel a={a} />}
    </div>
  );
}

function SanitizeButton({ file }: { file: File }) {
  const [state, setState] = useState<{ busy: boolean; info?: any; error?: string }>({ busy: false });
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="primary" size="sm" loading={state.busy} onClick={async () => {
        setState({ busy: true });
        try { const { blob, filename, info } = await api.sanitizeImage(file); download(blob, filename); setState({ busy: false, info }); }
        catch (e) { setState({ busy: false, error: errMsg(e) }); }
      }}><Download className="size-4" />Download sanitised copy</Button>
      {state.info && <span role="status" className="text-xs text-emerald">Removed {state.info.removed.length} metadata item(s); {fmtBytes(state.info.bytes_before)} → {fmtBytes(state.info.bytes_after)}. Method: {state.info.method}.</span>}
      {state.error && <span role="alert" className="text-xs text-rose">{state.error}</span>}
    </div>
  );
}

function useObjectUrl(file?: File | null) {
  const url = useMemo(() => (file ? URL.createObjectURL(file) : null), [file]);
  useEffect(() => () => { if (url) URL.revokeObjectURL(url); }, [url]);
  return url;
}
