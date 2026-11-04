import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState, Notice } from "../components/ui";
import { MODULE_LABEL, fileSafe, fmtBytes } from "../lib/format";

interface Row { name: string; n: number; kind: string }
const rows: Row[] = [{ name: "beta", n: 2, kind: "x" }, { name: "alpha", n: 10, kind: "y" }, { name: "gamma", n: 1, kind: "x" }];
const cols: Column<Row>[] = [{ key: "name", header: "Name", sortValue: (r) => r.name }, { key: "n", header: "Count", sortValue: (r) => r.n }];

const names = () => screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0].textContent);

describe("DataTable", () => {
  it("sorts text and numbers, toggling direction", async () => {
    render(<DataTable rows={rows} columns={cols} rowKey={(r) => r.name} caption="t" />);
    await userEvent.click(screen.getByRole("button", { name: /count/i }));
    expect(names()).toEqual(["gamma", "beta", "alpha"]);
    await userEvent.click(screen.getByRole("button", { name: /count/i }));
    expect(names()).toEqual(["alpha", "beta", "gamma"]);
    expect(screen.getByRole("columnheader", { name: /count/i })).toHaveAttribute("aria-sort", "descending");
  });
  it("searches and filters, and shows an empty state when nothing matches", async () => {
    render(<DataTable rows={rows} columns={cols} rowKey={(r) => r.name} caption="t" filters={[{ id: "k", label: "Kind", options: [{ value: "x", label: "x" }], test: (r, v) => r.kind === v }]} />);
    await userEvent.selectOptions(screen.getByLabelText("Kind"), "x");
    expect(names()).toEqual(["beta", "gamma"]);
    await userEvent.type(screen.getByLabelText("Search"), "zzz");
    expect(screen.getByText("No matching rows")).toBeInTheDocument();
  });
  it("paginates large sets", async () => {
    const many = Array.from({ length: 60 }, (_, i) => ({ name: `r${i}`, n: i, kind: "x" }));
    render(<DataTable rows={many} columns={cols} rowKey={(r) => r.name} caption="t" pageSize={25} />);
    expect(names()).toHaveLength(25);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Page 2 of 3")).toBeInTheDocument();
  });
  it("renders untrusted text as text, never as markup", () => {
    const evil = [{ name: "<img src=x onerror=alert(1)>", n: 1, kind: "x" }];
    const { container } = render(<DataTable rows={evil} columns={cols} rowKey={(r) => r.name} caption="t" />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });
});

describe("ui + format helpers", () => {
  it("renders empty states and notices", () => {
    render(<><EmptyState title="Nothing">Hint text</EmptyState><Notice tone="warn" title="Careful">Body</Notice></>);
    expect(screen.getByText("Hint text")).toBeInTheDocument();
    expect(screen.getByText("Careful")).toBeInTheDocument();
  });
  it("formats sizes and makes filenames safe", () => {
    expect(fmtBytes(1536)).toBe("1.5 KB");
    expect(fileSafe("../../etc/passwd x")).not.toMatch(/[\/ ]/);
    expect(MODULE_LABEL.infrastructure).toBe("Infrastructure");
  });
});
