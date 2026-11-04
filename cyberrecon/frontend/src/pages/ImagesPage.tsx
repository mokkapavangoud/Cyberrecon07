import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ImageUp } from "lucide-react";
import { useRef, useState } from "react";
import { Button, EmptyState, ErrorState, LoadingBlock, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { useAssessment, useConfig } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { AssessmentView } from "../views/AssessmentView";
import { PageHead } from "./ModulePage";

const ACCEPT = "image/jpeg,image/png,image/webp,image/gif,image/bmp,image/tiff";

export function ImagesPage() {
  const { mode } = useMode();
  const qc = useQueryClient();
  const cfg = useConfig();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const demo = useAssessment("demo", mode === "demo" ? "demo-image-aurora" : undefined);
  const max = cfg.data?.limits.max_upload_bytes ?? 10 * 1024 * 1024;

  const analyze = useMutation({ mutationFn: (f: File) => api.analyzeImage(f), onSuccess: () => { qc.invalidateQueries({ queryKey: ["assessments"] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); } });
  const pick = (f?: File | null) => {
    analyze.reset(); setLocalError(null);
    if (!f) return;
    if (f.size > max) { setFile(null); setLocalError(`That file is ${fmtBytes(f.size)}. The limit is ${fmtBytes(max)}.`); return; }
    setFile(f);
  };

  if (mode === "demo") {
    return (
      <div className="space-y-5">
        <PageHead title="Image metadata" lede="Demo mode is on. Uploads are disabled. Below is a simulated analysis of a fictional photo." />
        {demo.isLoading ? <LoadingBlock rows={4} label="Loading the simulated example" /> : demo.isError ? <ErrorState message={(demo.error as Error).message} onRetry={() => demo.refetch()} /> : demo.data && <AssessmentView a={demo.data} mode="demo" liveResult={demo.data.result} />}
      </div>
    );
  }
  const apiErr = analyze.error as ApiError | null;
  return (
    <div className="space-y-6">
      <PageHead title="Image metadata" lede="See what a photo reveals before you share it: camera, timestamps, location and software. Analysis happens on the server in memory and the image is never stored." />
      <Panel>
        <div className="space-y-4">
          <div role="button" tabIndex={0} aria-label="Choose an image to analyse" onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
            className={`flex cursor-pointer flex-col items-center rounded-xl border border-dashed px-6 py-10 text-center ${drag ? "border-emerald bg-emerald/5" : "border-line-strong hover:border-muted"}`}>
            <ImageUp className="mb-3 size-8 text-muted" aria-hidden />
            <p className="font-medium">{file ? file.name : "Drop an image here, or choose a file"}</p>
            <p className="mt-1 text-sm text-muted">{file ? `${fmtBytes(file.size)} · ${file.type || "unknown type"}` : `JPEG, PNG, WebP, GIF, BMP or TIFF · up to ${fmtBytes(max)}`}</p>
            <input ref={input} type="file" accept={ACCEPT} className="sr-only" tabIndex={-1} aria-hidden onChange={(e) => pick(e.target.files?.[0])} />
          </div>
          {localError && <p role="alert" className="text-sm text-rose">{localError}</p>}
          <Notice tone="info" title="Privacy">The file is checked by its content, not its name. Coordinates are shown to you once and are not kept in history unless the server is configured to keep them. Nothing is sent to third parties.</Notice>
          <div className="flex flex-wrap gap-2"><Button variant="primary" disabled={!file} loading={analyze.isPending} onClick={() => file && analyze.mutate(file)}>Analyse image</Button>
            {file && <Button variant="ghost" onClick={() => { pick(null); setFile(null); if (input.current) input.current.value = ""; }}>Clear</Button>}</div>
        </div>
      </Panel>
      {analyze.isPending && <LoadingBlock label="Analysing the image" rows={3} />}
      {apiErr && <ErrorState title={apiErr.code === "file_too_large" ? "The file is too large" : "The image could not be analysed"} message={apiErr.message} />}
      {analyze.data && <AssessmentView a={analyze.data.assessment} mode="live" liveResult={analyze.data.live_result} file={file} />}
      {!analyze.data && !analyze.isPending && !apiErr && <EmptyState title="No image analysed yet">Choose a file above. Results appear here and are saved to history without the image itself.</EmptyState>}
    </div>
  );
}
