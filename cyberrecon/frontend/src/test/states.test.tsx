import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, api } from "../lib/api";
import { Dashboard } from "../pages/Dashboard";
import { History } from "../pages/History";
import { ModulePage } from "../pages/ModulePage";
import { AssessmentPage } from "../pages/AssessmentPage";
import { AssessmentView } from "../views/AssessmentView";
import { Routes, Route } from "react-router-dom";
import { baseAssessment, emptyDash, mockApi, renderApp } from "./utils";

const cfg = { app: "CyberRecon", version: "0.1.0", environment: "test", capabilities: { screenshots: { available: false, reason: "No Chromium" }, subdomains: { provider: "crtsh", available: true }, geoip: { provider: "none", available: false, reason: "none" }, pdf_reports: true },
  limits: { max_upload_bytes: 10485760, max_image_pixels: 5e7, link_check_max_limit: 100, allowed_ports: [80, 443], max_redirects: 5, max_response_bytes: 2e6, rate_limit_per_minute: 30 }, privacy: { image_gps_persisted: false, uploaded_images_stored: false }, target_allowlist_active: false };

describe("api client", () => {
  it("maps backend error bodies to ApiError with code and message", async () => {
    mockApi({ "/api/assessments/link": { status: 422, body: { error: { code: "blocked_address", message: "169.254.169.254 is not allowed" } } } });
    await expect(api.createAssessment("link", { target: "x", authorized: true })).rejects.toMatchObject({ code: "blocked_address", status: 422, message: "169.254.169.254 is not allowed" });
  });
  it("turns a network failure into a clear message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    const e = await api.health().catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.code).toBe("network");
    expect(e.message).toMatch(/cannot be reached/i);
  });
  it("routes demo mode to /api/demo and never to live endpoints", async () => {
    const m = mockApi({ "/api/demo/dashboard": { body: emptyDash }, "/api/demo/assessments": { body: { items: [], total: 0 } }, "/api/demo/assessments/demo-link-aurora": { body: {} } });
    await api.dashboard("demo"); await api.listAssessments("demo", {}); await api.getAssessment("demo", "demo-link-aurora");
    expect(m.calls.every((c) => c.url.startsWith("/api/demo/"))).toBe(true);
  });
});

describe("dashboard states", () => {
  it("shows a loading skeleton first", () => {
    mockApi({ "/api/dashboard": () => new Promise(() => {}) as never });
    renderApp(<Dashboard />);
    expect(screen.getByRole("status")).toHaveTextContent(/loading the dashboard/i);
  });
  it("shows the empty state with a demo-data offer and no fake numbers", async () => {
    mockApi({ "/api/dashboard": { body: emptyDash } });
    renderApp(<Dashboard />);
    expect(await screen.findByText("No assessments yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /explore with demo data/i })).toBeInTheDocument();
    expect(screen.queryByText("Module usage")).not.toBeInTheDocument();
  });
  it("shows an error with retry when the API fails", async () => {
    mockApi({ "/api/dashboard": { status: 500, body: { error: { code: "internal_error", message: "An unexpected internal error occurred." } } } });
    renderApp(<Dashboard />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/unexpected internal error/i);
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
  });
  it("explains why there is no trend instead of drawing one from too little data", async () => {
    mockApi({ "/api/dashboard": { body: { ...emptyDash, totals: { ...emptyDash.totals, assessments: 1, completed: 1, targets: 1 }, recent: [{ id: "a".repeat(32), module: "link", target: "x.example.org", status: "completed", created_at: "2026-10-25T08:00:00+00:00", duration_ms: 5, findings: 0 }], target_history: [] } } });
    renderApp(<Dashboard />);
    expect(await screen.findByText(/a trend appears after at least 5 assessments/i)).toBeInTheDocument();
  });
  it("labels demo mode and calls only demo endpoints", async () => {
    const m = mockApi({ "/api/demo/dashboard": { body: { ...emptyDash, mode: "demo", simulated: true, notice: "SIMULATED DEMO DATA. Fictional.", totals: { ...emptyDash.totals, assessments: 3 } } } });
    renderApp(<Dashboard />, { mode: "demo" });
    expect(await screen.findByText(/simulated demo data/i)).toBeInTheDocument();
    expect(m.calls.map((c) => c.url)).toEqual(["/api/demo/dashboard"]);
  });
});

describe("history", () => {
  it("shows an empty state for no saved assessments", async () => {
    mockApi({ "/api/assessments": { body: { items: [], total: 0 } } });
    renderApp(<History />);
    expect(await screen.findByText("Nothing saved yet")).toBeInTheDocument();
  });
  it("asks for confirmation before deleting and then deletes", async () => {
    const item = { id: "b".repeat(32), module: "link", target: "https://site.example.org/", status: "completed", mode: "live", created_at: "2026-10-25T08:00:00+00:00", duration_ms: 10, findings: 2, summary: {}, finished_at: null, progress: {} };
    let deleted = false;
    const m = mockApi({ [`/api/assessments/${item.id}`]: (_u, init) => { if (init?.method === "DELETE") { deleted = true; return { status: 204 }; } return { body: {} }; }, "/api/assessments": () => ({ body: { items: deleted ? [] : [item], total: deleted ? 0 : 1 } }) });
    renderApp(<History />);
    await userEvent.click(await screen.findByRole("button", { name: /delete assessment of/i }));
    expect(m.calls.some((c) => c.init?.method === "DELETE")).toBe(false);
    const dlg = await screen.findByRole("dialog");
    await userEvent.click(within(dlg).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(m.calls.some((c) => c.init?.method === "DELETE")).toBe(true));
    expect(await screen.findByText("Nothing saved yet")).toBeInTheDocument();
  });
});

describe("assessment view", () => {
  it("shows the backend's real step status while running and no result", () => {
    const a = baseAssessment({ status: "running", progress: { finished: 2, total: 4, percent: 50, current: "Fetch" }, steps: [
      { key: "validate", label: "Validate", status: "done" }, { key: "fetch", label: "Fetch", status: "running" }, { key: "parse", label: "Parse", status: "pending" }, { key: "robots", label: "Robots", status: "pending" }] });
    renderApp(<AssessmentView a={a as never} mode="live" />);
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "50");
    expect(screen.getByText("Fetch")).toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });
  it("distinguishes discovered links from checked links", async () => {
    const link = (url: string, state: string, status?: number) => ({ url, kind: "internal", sources: ["a"], count: 1, text: "x", check: { state, status, reason: state === "not_checked" ? "disabled" : undefined } });
    const a = baseAssessment({ result: { final_url: "https://site.example.org/", http: { status: 200, reason: "OK", response_time_ms: 12, content_type: "text/html", bytes_read: 100, truncated: false }, page: { title: "T", meta: {} }, technologies: [], redirect_chain: [],
      links: [link("https://site.example.org/a", "checked", 200), link("https://site.example.org/b", "not_checked")], link_summary: { discovered: 2, by_kind: { internal: 2 }, checked: 1, ok: 1, broken: 0, not_checked: 1, skipped: 0, blocked: 0, failed: 0 },
      headers: { security: [], cookies: [], selected: {} }, robots: { status: "not_found", groups: [], sitemaps: [] }, sitemap: { status: "not_found" }, requests_made: 3 }, available_exports: ["links", "findings", "sources"] });
    renderApp(<AssessmentView a={a as never} mode="live" />);
    await userEvent.click(screen.getByRole("tab", { name: /links/i }));
    expect(screen.getByText(/discovered is not the same as checked/i)).toBeInTheDocument();
    expect(screen.getByText(/2 links were found in the page source. Only 1 were requested/i)).toBeInTheDocument();
    const rows = screen.getAllByRole("row");
    expect(within(rows.find((r) => r.textContent?.includes("/b"))!).getByText("Not checked")).toBeInTheDocument();
  });
  it("renders an unreachable target as a failure with sources, not as data", () => {
    const a = baseAssessment({ status: "failed", result: { fetch_error: { code: "dns_failure", message: "The hostname could not be resolved." } }, error: "x", findings: [] });
    renderApp(<AssessmentView a={a as never} mode="live" />);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByText(/could not be resolved/)).toBeInTheDocument();
  });
  it("marks demo records as simulated", () => {
    renderApp(<AssessmentView a={baseAssessment({ status: "failed", result: { fetch_error: { message: "m" } } }) as never} mode="demo" />);
    expect(screen.getByText("Simulated example")).toBeInTheDocument();
  });
  it("assessment page shows not found for a missing id", async () => {
    mockApi({ [`/api/assessments/${"c".repeat(32)}`]: { status: 404, body: { error: { code: "not_found", message: "Assessment not found." } } } });
    renderApp(<Routes><Route path="/app/assessments/:id" element={<AssessmentPage />} /></Routes>, { route: `/app/assessments/${"c".repeat(32)}` });
    expect(await screen.findByText("Assessment not found")).toBeInTheDocument();
  });
});

describe("assessment form", () => {
  it("keeps Start disabled until a target is entered and authorisation is confirmed", async () => {
    mockApi({ "/api/config": { body: cfg }, "/api/assessments": { body: { items: [], total: 0 } } });
    renderApp(<ModulePage module="link" />, { route: "/app/website" });
    const start = screen.getByRole("button", { name: /start assessment/i });
    expect(start).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/website address/i), "example.org");
    expect(start).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox", { name: /i own this target/i }));
    expect(start).toBeEnabled();
  });
  it("shows the backend's validation message when a target is rejected", async () => {
    mockApi({ "/api/config": { body: cfg }, "/api/assessments": { body: { items: [], total: 0 } }, "/api/assessments/link": { status: 422, body: { error: { code: "blocked_address", message: "169.254.169.254 is not allowed: cloud metadata endpoint.", field: "target" } } } });
    renderApp(<ModulePage module="link" />, { route: "/app/website" });
    await userEvent.type(screen.getByLabelText(/website address/i), "http://169.254.169.254/");
    await userEvent.click(screen.getByRole("checkbox", { name: /i own this target/i }));
    await userEvent.click(screen.getByRole("button", { name: /start assessment/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/cloud metadata endpoint/);
  });
  it("sends authorisation and options, and disables screenshots when unavailable", async () => {
    const m = mockApi({ "/api/config": { body: cfg }, "/api/assessments": { body: { items: [], total: 0 } } });
    renderApp(<ModulePage module="screenshot" />, { route: "/app/screenshots" });
    expect(await screen.findByText(/screenshots are not available/i)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/website address/i), "example.org");
    await userEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: /start assessment/i })).toBeDisabled();
    expect(m.calls.some((c) => c.init?.method === "POST")).toBe(false);
  });
  it("in demo mode disables new assessments and never calls live endpoints", async () => {
    const m = mockApi({ "/api/demo/assessments/demo-link-aurora": { body: baseAssessment({ id: "demo-link-aurora", mode: "demo", status: "failed", result: { fetch_error: { message: "m" } } }) } });
    renderApp(<ModulePage module="link" />, { route: "/app/website", mode: "demo" });
    expect(await screen.findByText("Simulated example")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start assessment/i })).not.toBeInTheDocument();
    expect(m.calls.filter((c) => c.url !== "/api/config").every((c) => c.url.includes("/api/demo/"))).toBe(true);
    expect(m.calls.some((c) => c.url.startsWith("/api/assessments"))).toBe(false);
  });
});
