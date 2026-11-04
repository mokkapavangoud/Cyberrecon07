import { ArrowDown, ArrowUp, ChevronsUpDown, Search } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { cx, EmptyState, inputCls } from "./ui";

export interface Column<T> {
  key: string; header: string; render?: (row: T) => ReactNode; sortValue?: (row: T) => string | number | null | undefined;
  searchText?: (row: T) => string; className?: string; mono?: boolean;
}
export interface FilterDef<T> { id: string; label: string; options: { value: string; label: string }[]; test: (row: T, value: string) => boolean }

/** Client-side searchable / sortable / filterable table. Page size keeps large link sets responsive. */
export function DataTable<T>({ rows, columns, rowKey, filters = [], searchPlaceholder = "Search", pageSize = 25, empty, caption }: {
  rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string; filters?: FilterDef<T>[]; searchPlaceholder?: string; pageSize?: number; empty?: string; caption: string;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [fv, setFv] = useState<Record<string, string>>({});
  const [page, setPage] = useState(0);

  const view = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let out = rows.filter((r) => filters.every((f) => !fv[f.id] || f.test(r, fv[f.id])));
    if (needle) out = out.filter((r) => columns.some((c) => (c.searchText ? c.searchText(r) : String(c.sortValue?.(r) ?? "")).toLowerCase().includes(needle)));
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      const sv = col?.sortValue;
      if (sv) out = [...out].sort((a, b) => {
        const x = sv(a), y = sv(b);
        if (x == null && y == null) return 0;
        if (x == null) return 1;
        if (y == null) return -1;
        return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) * sort.dir;
      });
    }
    return out;
  }, [rows, q, sort, fv, columns, filters]);

  const pages = Math.max(1, Math.ceil(view.length / pageSize));
  const cur = Math.min(page, pages - 1);
  const slice = view.slice(cur * pageSize, cur * pageSize + pageSize);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-52 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" aria-hidden />
          <input aria-label={searchPlaceholder} className={cx(inputCls, "pl-9")} placeholder={searchPlaceholder} value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
        </div>
        {filters.map((f) => (
          <select key={f.id} aria-label={f.label} className={cx(inputCls, "w-auto!")} value={fv[f.id] ?? ""} onChange={(e) => { setFv({ ...fv, [f.id]: e.target.value }); setPage(0); }}>
            <option value="">{f.label}: all</option>
            {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        ))}
        <span className="text-xs text-muted tabular-nums" aria-live="polite">{view.length} of {rows.length}</span>
      </div>
      {view.length === 0 ? (
        <EmptyState title="No matching rows">{empty ?? "Adjust the search or filters to see more."}</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-[640px] border-collapse text-left text-sm">
            <caption className="sr-only">{caption}</caption>
            <thead className="bg-canvas text-xs text-muted">
              <tr>
                {columns.map((c) => {
                  const active = sort?.key === c.key;
                  return (
                    <th key={c.key} scope="col" aria-sort={active ? (sort!.dir === 1 ? "ascending" : "descending") : undefined} className="whitespace-nowrap px-3 py-2.5 font-medium">
                      {c.sortValue ? (
                        <button className="inline-flex items-center gap-1 hover:text-text" onClick={() => setSort(active && sort!.dir === -1 ? null : { key: c.key, dir: active ? -1 : 1 })}>
                          {c.header}{active ? (sort!.dir === 1 ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />) : <ChevronsUpDown className="size-3 opacity-50" />}
                        </button>
                      ) : c.header}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {slice.map((r) => (
                <tr key={rowKey(r)} className="border-t border-line align-top hover:bg-raised/50">
                  {columns.map((c) => <td key={c.key} className={cx("px-3 py-2.5", c.mono && "font-mono text-[0.8rem]", c.className)}>{c.render ? c.render(r) : String(c.sortValue?.(r) ?? "—")}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages > 1 && (
        <div className="mt-3 flex items-center justify-between text-sm text-muted">
          <button className="rounded px-2 py-1 hover:text-text disabled:opacity-40" disabled={cur === 0} onClick={() => setPage(cur - 1)}>Previous</button>
          <span className="tabular-nums">Page {cur + 1} of {pages}</span>
          <button className="rounded px-2 py-1 hover:text-text disabled:opacity-40" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>Next</button>
        </div>
      )}
    </div>
  );
}
