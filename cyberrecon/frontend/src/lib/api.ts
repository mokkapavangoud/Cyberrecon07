/* Typed-enough client for the CyberRecon API. Module results are deliberately `any`: their shape is owned by the backend analysers. */
export type Module = "link" | "image" | "infrastructure" | "screenshot";
export type Status = "queued" | "running" | "completed" | "partial" | "failed";
export type Severity = "high" | "medium" | "low" | "info";
export type Evidence = "observed" | "third_party" | "estimate";
export type Mode = "live" | "demo";

export interface Step { key: string; label: string; status: "pending" | "running" | "done" | "skipped" | "failed"; detail?: string | null }
export interface Finding { id: string; module: string; category: string; title: string; detail: string; severity: Severity; evidence_type: Evidence; source: string }
export interface SourceRef { id: string; name: string; kind: string; reference: string | null; status: "ok" | "failed" | "unavailable" | "skipped"; detail: string | null; retrieved_at: string | null }
export interface Progress { finished: number; total: number; percent: number; current: string | null }
export interface Summary { id: string; module: Module; target: string; status: Status; mode: Mode; simulated?: boolean; created_at: string; finished_at: string | null; duration_ms: number | null; summary: Record<string, any>; findings: number; progress: Progress }
export interface Assessment extends Omit<Summary, "findings"> {
  target_input: string; authorization: { confirmed: boolean; confirmed_at: string | null; statement: string | null };
  scope: Record<string, any>; options: Record<string, any>; steps: Step[]; error: string | null; started_at: string | null;
  result_status: string | null; result: any; errors: { step?: string; code?: string; message: string }[];
  findings: Finding[]; sources: SourceRef[]; reports: any[]; available_exports?: string[]; notice?: string;
}
export interface Config {
  app: string; version: string; environment: string;
  capabilities: { screenshots: { available: boolean; reason: string | null }; subdomains: { provider: string; available: boolean; reason?: string }; geoip: { provider: string; available: boolean; reason?: string }; pdf_reports: boolean };
  limits: { max_upload_bytes: number; max_image_pixels: number; link_check_max_limit: number; allowed_ports: number[]; max_redirects: number; max_response_bytes: number; rate_limit_per_minute: number };
  privacy: { image_gps_persisted: boolean; uploaded_images_stored: boolean }; target_allowlist_active: boolean;
}
export interface Dashboard {
  mode: Mode; simulated: boolean; notice?: string;
  totals: { assessments: number; completed: number; partial: number; failed: number; in_progress: number; targets: number; findings: number; reports: number };
  findings_by_severity: Record<Severity, number>; module_usage: Record<Module, number>; avg_duration_ms: Record<string, number>;
  recent: { id: string; module: Module; target: string; status: Status; created_at: string; duration_ms: number | null; findings: number }[];
  target_history: { target: string; assessments: number; last_at: string; modules: string[]; findings: number }[];
  top_findings: (Finding & { assessment_id: string; target: string })[];
  trend: { sufficient: boolean; min_assessments: number; min_days: number; days: { date: string; count: number }[] };
}

export class ApiError extends Error {
  constructor(public code: string, message: string, public status = 0, public retryAfter?: number, public extra?: any) { super(message); }
}

async function parse(res: Response): Promise<any> {
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON error pages */ }
  if (!res.ok) {
    const e = body?.error;
    throw new ApiError(e?.code ?? "http_error", e?.message ?? `The server answered with HTTP ${res.status}.`, res.status, e?.retry_after, body);
  }
  return body;
}

async function call(path: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(path, init);
  } catch {
    throw new ApiError("network", "The CyberRecon API cannot be reached. Check that the backend is running and try again.");
  }
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await call(path, init);
  return parse(res);
}

const post = (body: unknown): RequestInit => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const qs = (p: Record<string, string | number | undefined | null>) => {
  const u = new URLSearchParams();
  Object.entries(p).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") u.set(k, String(v)); });
  const s = u.toString();
  return s ? `?${s}` : "";
};

export interface SanitizeInfo { method: string; sha256: string; removed: string[]; retained: string[]; notes: string[]; bytes_before: number; bytes_after: number }

export const api = {
  health: () => json<{ status: string; version: string; database: string }>("/api/health"),
  config: () => json<Config>("/api/config"),
  createAssessment: (module: Exclude<Module, "image">, body: { target: string; authorized: boolean; options?: Record<string, unknown> }) =>
    json<{ id: string }>(`/api/assessments/${module}`, post(body)),
  listAssessments: (mode: Mode, p: { module?: string; status?: string; q?: string; limit?: number; offset?: number }) =>
    json<{ items: Summary[]; total: number }>(`/api/${mode === "demo" ? "demo/" : ""}assessments${mode === "demo" ? "" : qs(p)}`),
  getAssessment: (mode: Mode, id: string) => json<Assessment>(`/api/${mode === "demo" ? "demo/" : ""}assessments/${encodeURIComponent(id)}`),
  deleteAssessment: async (id: string) => { const r = await call(`/api/assessments/${id}`, { method: "DELETE" }); if (!r.ok) await parse(r); },
  deleteAll: () => json<{ deleted: number }>("/api/assessments?confirm=true", { method: "DELETE" }),
  dashboard: (mode: Mode) => json<Dashboard>(`/api/${mode === "demo" ? "demo/" : ""}dashboard`),
  analyzeImage: (file: File) => { const f = new FormData(); f.append("file", file); return json<{ assessment: Assessment; live_result: any; live_result_note: string }>("/api/images/analyze", { method: "POST", body: f }); },
  sanitizeImage: async (file: File): Promise<{ blob: Blob; filename: string; info: SanitizeInfo }> => {
    const f = new FormData(); f.append("file", file);
    const res = await call("/api/images/sanitize", { method: "POST", body: f });
    if (!res.ok) await parse(res);
    const cd = res.headers.get("content-disposition") ?? "";
    const filename = /filename="([^"]+)"/.exec(cd)?.[1] ?? "sanitised-image";
    const info = JSON.parse(res.headers.get("x-cyberrecon-sanitize") ?? "{}");
    return { blob: await res.blob(), filename, info };
  },
  listReports: () => json<{ items: { id: string; assessment_id: string; target: string; module: Module; format: string; variant: string | null; filename: string; size_bytes: number; created_at: string; download_url: string }[] }>("/api/reports"),
  exportUrl: (mode: Mode, id: string, format: "pdf" | "json" | "csv", table?: string) =>
    mode === "demo" ? `/api/demo/assessments/${id}/report.pdf` : `/api/assessments/${id}/export${qs({ format, table })}`,
  screenshotUrl: (id: string) => `/api/assessments/${id}/screenshot`,
};

export const TERMINAL: Status[] = ["completed", "partial", "failed"];
