import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, CheckCircle2, CircleDashed, Info, Loader2, XCircle } from "lucide-react";
import { useId, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import type { Evidence, Severity, Status } from "../lib/api";
import { EVIDENCE_HELP, EVIDENCE_LABEL } from "../lib/format";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

// ------------------------------------------------------------------ buttons
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md"; loading?: boolean };
export function Button({ variant = "secondary", size = "md", loading, className, children, disabled, ...rest }: BtnProps) {
  const v = {
    primary: "bg-emerald text-ink font-semibold hover:bg-[#45d1a0] disabled:bg-emerald-dim disabled:text-[#9fd8c3]",
    secondary: "bg-raised border border-line-strong text-text hover:border-muted hover:bg-[#202c27]",
    ghost: "text-muted hover:text-text hover:bg-raised",
    danger: "bg-rose/10 border border-rose/50 text-rose hover:bg-rose/20",
  }[variant];
  return (
    <button {...rest} disabled={disabled || loading} className={cx("inline-flex items-center justify-center gap-2 rounded-lg whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-60", size === "sm" ? "px-2.5 py-1.5 text-sm" : "px-4 py-2.5 text-sm", v, className)}>
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

// ------------------------------------------------------------------ surfaces
export function Panel({ title, action, children, className, pad = true }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={cx("rounded-xl border border-line bg-panel", className)}>
      {(title || action) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
          <h2 className="font-display text-[15px] font-semibold tracking-tight">{title}</h2>
          {action}
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function Skeleton({ className }: { className?: string }) { return <div className={cx("skeleton", className)} aria-hidden />; }

export function LoadingBlock({ label = "Loading", rows = 3 }: { label?: string; rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">{label}…</span>
      {Array.from({ length: rows }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center rounded-xl border border-dashed border-line-strong px-6 py-12 text-center">
      {icon && <div className="mb-3 text-muted">{icon}</div>}
      <h3 className="font-display text-lg">{title}</h3>
      {children && <p className="mt-1.5 max-w-md text-sm text-muted">{children}</p>}
      {action && <div className="mt-5 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ title = "This could not be loaded", message, onRetry }: { title?: string; message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-rose/40 bg-rose/5 p-5">
      <div className="flex items-start gap-3">
        <XCircle className="mt-0.5 size-5 shrink-0 text-rose" aria-hidden />
        <div className="min-w-0">
          <h3 className="font-display text-base">{title}</h3>
          <p className="mt-1 text-sm text-muted">{message}</p>
          {onRetry && <Button size="sm" className="mt-3" onClick={onRetry}>Try again</Button>}
        </div>
      </div>
    </div>
  );
}

export function Notice({ tone = "info", title, children }: { tone?: "info" | "warn" | "demo" | "ok"; title?: string; children: ReactNode }) {
  const t = { info: ["border-cyan/30 bg-cyan/5", <Info key="i" className="size-4 text-cyan" />], warn: ["border-amber/40 bg-amber/5", <AlertTriangle key="w" className="size-4 text-amber" />],
    demo: ["border-amber/50 bg-amber/10", <AlertTriangle key="d" className="size-4 text-amber" />], ok: ["border-emerald/30 bg-emerald/5", <CheckCircle2 key="o" className="size-4 text-emerald" />] }[tone];
  return (
    <div className={cx("flex gap-3 rounded-lg border px-3.5 py-3 text-sm", t[0] as string)}>
      <span className="mt-0.5 shrink-0" aria-hidden>{t[1]}</span>
      <div className="min-w-0">{title && <p className="font-medium">{title}</p>}<div className="text-muted">{children}</div></div>
    </div>
  );
}

// ------------------------------------------------------------------ badges
const STATUS: Record<string, [string, string]> = {
  completed: ["Completed", "text-emerald border-emerald/40 bg-emerald/10"], partial: ["Partial", "text-amber border-amber/40 bg-amber/10"],
  failed: ["Failed", "text-rose border-rose/40 bg-rose/10"], running: ["Running", "text-cyan border-cyan/40 bg-cyan/10"], queued: ["Queued", "text-muted border-line-strong bg-raised"],
};
export function StatusBadge({ status }: { status: Status | string }) {
  const [label, cls] = STATUS[status] ?? [status, "text-muted border-line-strong"];
  return <span className={cx("inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium", cls)}>{label}</span>;
}
const SEV: Record<Severity, string> = { high: "text-rose border-rose/50 bg-rose/10", medium: "text-amber border-amber/50 bg-amber/10", low: "text-cyan border-cyan/40 bg-cyan/10", info: "text-muted border-line-strong bg-raised" };
export const SEV_LABEL: Record<Severity, string> = { high: "High", medium: "Medium", low: "Low", info: "Info" };
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cx("inline-flex min-w-14 justify-center rounded-md border px-1.5 py-0.5 text-xs font-medium", SEV[severity])}>{SEV_LABEL[severity]}</span>;
}
const EV: Record<Evidence, string> = { observed: "text-emerald", third_party: "text-violet", estimate: "text-amber" };
export function EvidenceTag({ type }: { type: Evidence }) {
  return <span title={EVIDENCE_HELP[type]} className={cx("inline-flex items-center gap-1.5 text-xs", EV[type])}><span className="size-1.5 rounded-full bg-current" aria-hidden />{EVIDENCE_LABEL[type]}</span>;
}
export function SourceStatus({ status }: { status: string }) {
  const m: Record<string, [string, string, ReactNode]> = {
    ok: ["Retrieved", "text-emerald", <CheckCircle2 key="a" className="size-3.5" />], failed: ["Failed", "text-rose", <XCircle key="b" className="size-3.5" />],
    unavailable: ["Unavailable", "text-amber", <AlertTriangle key="c" className="size-3.5" />], skipped: ["Skipped", "text-muted", <CircleDashed key="d" className="size-3.5" />],
  };
  const [label, cls, icon] = m[status] ?? [status, "text-muted", null];
  return <span className={cx("inline-flex items-center gap-1.5 text-xs", cls)}>{icon}{label}</span>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) { return <code className={cx("break-all text-[0.82rem] text-text/90", className)}>{children}</code>; }

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "good" | "warn" | "bad" }) {
  return (
    <div className="rounded-lg border border-line bg-canvas px-3.5 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={cx("mt-1 font-display text-2xl leading-none tabular-nums", tone === "bad" && "text-rose", tone === "warn" && "text-amber", tone === "good" && "text-emerald")}>{value}</div>
      {hint && <div className="mt-1.5 text-xs text-faint">{hint}</div>}
    </div>
  );
}

export function KV({ rows, stacked }: { rows: [string, ReactNode][]; stacked?: boolean }) {
  const shown = rows.filter(([, v]) => v !== null && v !== undefined && v !== "");
  return (
    <dl className={cx("grid grid-cols-1 gap-x-6", stacked ? "gap-y-1" : "gap-y-2.5 sm:grid-cols-[minmax(130px,200px)_1fr]")}>
      {shown.map(([k, v]) => (<div key={k} className={stacked ? "mb-1.5" : "contents"}><dt className="text-xs text-muted sm:text-sm">{k}</dt><dd className="min-w-0 break-words text-sm">{v}</dd></div>))}
    </dl>
  );
}

// ------------------------------------------------------------------ form bits
export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: (id: string) => ReactNode }) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium">{label}</label>
      {children(id)}
      {hint && <p className="mt-1.5 text-xs text-muted">{hint}</p>}
    </div>
  );
}
export const inputCls = "w-full rounded-lg border border-line-strong bg-canvas px-3 py-2.5 text-sm placeholder:text-faint hover:border-muted focus:border-cyan";
export function Check({ checked, onChange, children, disabled }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; disabled?: boolean }) {
  return (
    <label className={cx("flex items-start gap-2.5 text-sm", disabled ? "opacity-60" : "cursor-pointer")}>
      <input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-emerald" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}

// ------------------------------------------------------------------ dialog
export function ConfirmDialog({ trigger, title, description, confirmLabel, onConfirm, danger = true, busy }: { trigger: ReactNode; title: string; description: ReactNode; confirmLabel: string; onConfirm: () => void | Promise<void>; danger?: boolean; busy?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>{trigger}</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/70" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(92vw,440px)] rounded-xl border border-line-strong bg-panel p-5 shadow-2xl" style={{ animation: "dialog-in .15s ease-out" }}>
          <Dialog.Title className="font-display text-lg">{title}</Dialog.Title>
          <Dialog.Description asChild><div className="mt-2 text-sm text-muted">{description}</div></Dialog.Description>
          <div className="mt-5 flex justify-end gap-2">
            <Dialog.Close asChild><Button variant="ghost">Cancel</Button></Dialog.Close>
            <Button variant={danger ? "danger" : "primary"} loading={busy} onClick={async () => { await onConfirm(); setOpen(false); }}>{confirmLabel}</Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("-mb-px whitespace-nowrap border-b-2 px-3 py-2.5 text-sm", value === t.id ? "border-emerald text-text" : "border-transparent text-muted hover:text-text")}>
          {t.label}{t.count != null && <span className="ml-1.5 text-xs text-faint tabular-nums">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}
