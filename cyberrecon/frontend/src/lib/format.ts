export const fmtDate = (iso?: string | null) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};
export const fmtDay = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
export const fmtMs = (ms?: number | null) => (ms == null ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
export const fmtBytes = (n?: number | null) => {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
};
export const MODULE_LABEL: Record<string, string> = { link: "Website", image: "Image", infrastructure: "Infrastructure", screenshot: "Screenshot" };
export const MODULE_PATH: Record<string, string> = { link: "website", image: "images", infrastructure: "infrastructure", screenshot: "screenshots" };
export const EVIDENCE_LABEL: Record<string, string> = { observed: "Observed", third_party: "Third-party report", estimate: "Estimate" };
export const EVIDENCE_HELP: Record<string, string> = {
  observed: "Directly retrieved or measured by CyberRecon during this assessment.",
  third_party: "Reported by an outside source (registry, DNS-based service, certificate-transparency index). Not independently verified.",
  estimate: "An approximation, such as IP geolocation. Not reliable evidence of a physical location.",
};
export const fileSafe = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
export function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.rel = "noopener";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
export const errMsg = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong.");
