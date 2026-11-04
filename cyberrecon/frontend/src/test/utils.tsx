import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import type { Mode } from "../lib/api";
import { ModeProvider } from "../lib/mode";

export function renderApp(ui: ReactElement, { route = "/app", mode = "live" as Mode } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={client}><ModeProvider initial={mode}><MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter></ModeProvider></QueryClientProvider>,
  );
}

type Handler = (url: string, init?: RequestInit) => { status?: number; body?: unknown } | Promise<{ status?: number; body?: unknown }>;
/** Replaces fetch with a router of path -> handler. Unmatched requests fail loudly so tests never rely on a real network. */
export function mockApi(routes: Record<string, Handler | { status?: number; body?: unknown }>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const key = Object.keys(routes).find((k) => url.split("?")[0] === k || url.startsWith(k + "?"));
    if (!key) throw new Error(`Unmocked request: ${url}`);
    const h = routes[key];
    const r = typeof h === "function" ? await h(url, init) : h;
    if (r.status === 204) return new Response(null, { status: 204 });
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status ?? 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { calls, fn };
}

export const emptyDash = {
  mode: "live", simulated: false, totals: { assessments: 0, completed: 0, partial: 0, failed: 0, in_progress: 0, targets: 0, findings: 0, reports: 0 },
  findings_by_severity: { high: 0, medium: 0, low: 0, info: 0 }, module_usage: { link: 0, image: 0, infrastructure: 0, screenshot: 0 }, avg_duration_ms: {}, recent: [], target_history: [], top_findings: [],
  trend: { sufficient: false, min_assessments: 5, min_days: 3, days: [] },
};

export const baseAssessment = (over: Record<string, unknown> = {}) => ({
  id: "a".repeat(32), module: "link", target: "https://site.example.org/", status: "completed", mode: "live", created_at: "2026-10-25T08:00:00+00:00", finished_at: "2026-10-25T08:00:02+00:00", duration_ms: 2000,
  summary: {}, findings: [], progress: { finished: 7, total: 7, percent: 100, current: null }, target_input: "", authorization: { confirmed: true, confirmed_at: "2026-10-25T08:00:00+00:00", statement: "The user confirmed they are authorised." },
  scope: {}, options: {}, steps: [], error: null, started_at: "2026-10-25T08:00:00+00:00", result_status: "completed", result: null, errors: [], sources: [], reports: [], available_exports: [], ...over,
});
