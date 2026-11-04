import * as Dialog from "@radix-ui/react-dialog";
import { Activity, BarChart3, Camera, ChevronLeft, ChevronRight, FileText, Globe, History, Image as ImageIcon, Menu, Network, Presentation, Settings, X } from "lucide-react";
import { useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useHealth } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { Logo } from "./Logo";
import { Button, cx, inputCls } from "./ui";

const NAV = [
  { to: "/app", label: "Dashboard", icon: BarChart3, end: true },
  { to: "/app/website", label: "Website & links", icon: Globe },
  { to: "/app/images", label: "Image metadata", icon: ImageIcon },
  { to: "/app/infrastructure", label: "Infrastructure", icon: Network },
  { to: "/app/screenshots", label: "Screenshots", icon: Camera },
  { to: "/app/history", label: "History", icon: History },
  { to: "/app/reports", label: "Reports", icon: FileText },
  { to: "/app/settings", label: "Settings", icon: Settings },
];
const CRUMB: Record<string, string> = { website: "Website & links", images: "Image metadata", infrastructure: "Infrastructure", screenshots: "Screenshots", history: "History", reports: "Reports", settings: "Settings", assessments: "Assessment" };

function readCollapsed() { try { return localStorage.getItem("cyberrecon.nav") === "1"; } catch { return false; } }

function NavList({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-0.5 px-2">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink key={to} to={to} end={end} onClick={onNavigate} title={collapsed ? label : undefined}
          className={({ isActive }) => cx("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", isActive ? "bg-raised text-text" : "text-muted hover:bg-raised/60 hover:text-text", collapsed && "justify-center px-0")}>
          {({ isActive }) => (<><Icon className={cx("size-[18px] shrink-0", isActive && "text-emerald")} aria-hidden /><span className={collapsed ? "sr-only" : ""}>{label}</span></>)}
        </NavLink>
      ))}
    </nav>
  );
}

export function Shell() {
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [mobile, setMobile] = useState(false);
  const { mode, setMode } = useMode();
  const health = useHealth();
  const loc = useLocation();
  const nav = useNavigate();
  const [target, setTarget] = useState("");
  const [kind, setKind] = useState("website");
  const running = useQuery({ queryKey: ["running", mode], enabled: mode === "live", refetchInterval: 4000, queryFn: () => api.listAssessments("live", { status: "running", limit: 1 }) });
  const crumbs = loc.pathname.split("/").filter(Boolean).slice(1);
  const toggle = () => setCollapsed((c) => { try { localStorage.setItem("cyberrecon.nav", c ? "0" : "1"); } catch { /* ignore */ } return !c; });
  const apiState = health.isError ? "unreachable" : health.data?.status === "ok" ? "online" : health.isLoading ? "checking" : "degraded";

  return (
    <div className="flex min-h-full bg-canvas">
      <aside className={cx("sticky top-0 hidden h-screen shrink-0 flex-col border-r border-line bg-ink md:flex", collapsed ? "w-[68px]" : "w-60")}>
        <div className={cx("flex h-14 items-center border-b border-line", collapsed ? "justify-center" : "px-4")}><Link to="/" aria-label="CyberRecon home"><Logo showText={!collapsed} /></Link></div>
        <div className="flex-1 overflow-y-auto py-3"><NavList collapsed={collapsed} /></div>
        <div className="border-t border-line p-2">
          <Link to="/present" className={cx("mb-1 flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-muted hover:bg-raised/60 hover:text-text", collapsed && "justify-center px-0")} title="Presentation mode"><Presentation className="size-[18px]" aria-hidden /><span className={collapsed ? "sr-only" : ""}>Presentation mode</span></Link>
          <button onClick={toggle} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!collapsed} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-muted hover:bg-raised/60 hover:text-text">
            {collapsed ? <ChevronRight className="mx-auto size-[18px]" /> : <><ChevronLeft className="size-[18px]" />Collapse</>}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-ink/90 px-3 backdrop-blur sm:px-5">
          <Dialog.Root open={mobile} onOpenChange={setMobile}>
            <Dialog.Trigger asChild><button className="rounded-lg p-2 text-muted hover:bg-raised md:hidden" aria-label="Open navigation"><Menu className="size-5" /></button></Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 md:hidden" />
              <Dialog.Content className="fixed inset-y-0 left-0 z-50 w-72 border-r border-line bg-ink py-3 md:hidden" aria-describedby={undefined}>
                <div className="mb-3 flex items-center justify-between px-4"><Dialog.Title asChild><Logo /></Dialog.Title><Dialog.Close className="rounded p-1.5 text-muted hover:bg-raised" aria-label="Close navigation"><X className="size-5" /></Dialog.Close></div>
                <NavList collapsed={false} onNavigate={() => setMobile(false)} />
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          <form className="flex min-w-0 flex-1 items-center gap-2 sm:max-w-xl" onSubmit={(e) => { e.preventDefault(); if (target.trim()) nav(`/app/${kind}?target=${encodeURIComponent(target.trim())}`); }} role="search" aria-label="Start an assessment">
            <select aria-label="Assessment type" value={kind} onChange={(e) => setKind(e.target.value)} className={cx(inputCls, "hidden w-auto! py-2 sm:block")}>
              <option value="website">Website</option><option value="infrastructure">Infrastructure</option><option value="screenshots">Screenshot</option>
            </select>
            <input aria-label="Target domain or URL" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.org or https://example.org" className={cx(inputCls, "min-w-0 py-2")} />
            <Button type="submit" size="sm" variant="primary" disabled={!target.trim()}>Set up</Button>
          </form>

          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            {mode === "live" && (running.data?.total ?? 0) > 0 && (
              <Link to="/app/history" className="inline-flex items-center gap-1.5 rounded-full border border-cyan/40 bg-cyan/10 px-2.5 py-1 text-xs text-cyan"><Activity className="size-3.5" aria-hidden />{running.data!.total} running</Link>
            )}
            <span className="hidden items-center gap-1.5 text-xs text-muted sm:inline-flex" role="status" title={health.isError ? "The backend API cannot be reached" : "Backend API status"}>
              <span className={cx("size-2 rounded-full", apiState === "online" ? "bg-emerald" : apiState === "checking" ? "bg-faint" : "bg-rose")} aria-hidden />API {apiState}
            </span>
          </div>
        </header>

        {mode === "demo" && (
          <div role="status" className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 border-b border-amber/50 bg-amber/15 px-4 py-2 text-sm">
            <strong className="font-semibold text-amber">DEMO DATA</strong>
            <span className="text-text/90">You are viewing simulated results for a fictional organisation. Nothing here was collected from the internet and none of it is saved.</span>
            <button className="underline underline-offset-2 hover:text-amber" onClick={() => { setMode("live"); nav("/app"); }}>Exit demo mode</button>
          </div>
        )}

        <nav aria-label="Breadcrumb" className="px-4 pt-4 text-xs text-muted sm:px-6">
          <ol className="flex flex-wrap items-center gap-1.5">
            <li><Link to="/app" className="hover:text-text">Workspace</Link></li>
            {crumbs.map((c, i) => (
              <li key={i} className="flex items-center gap-1.5"><span aria-hidden>/</span>{i === crumbs.length - 1 ? <span aria-current="page" className="text-text">{CRUMB[c] ?? <span className="font-mono">{c.slice(0, 14)}</span>}</span> : <span>{CRUMB[c] ?? c}</span>}</li>
            ))}
          </ol>
        </nav>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 pb-16 pt-3 sm:px-6"><Outlet /></main>
      </div>
    </div>
  );
}
