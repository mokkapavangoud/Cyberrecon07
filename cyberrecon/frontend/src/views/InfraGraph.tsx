import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Globe, KeyRound, Network, Server, Shield, Waypoints, FileText } from "lucide-react";
import { memo, useMemo, useState, type ReactNode } from "react";
import { EmptyState, KV, Mono, Panel } from "../components/ui";

export const NODE_TYPES: Record<string, { label: string; color: string; icon: ReactNode; help: string }> = {
  domain: { label: "Registrable domain", color: "#2fbf8f", icon: <Globe className="size-3.5" />, help: "The domain a registry records." },
  hostname: { label: "Hostname", color: "#3db8d4", icon: <Server className="size-3.5" />, help: "A name that was assessed or resolved." },
  dns_record: { label: "DNS record target", color: "#8a9b94", icon: <FileText className="size-3.5" />, help: "A name returned by NS, MX or CNAME records." },
  subdomain: { label: "Subdomain (passive)", color: "#9b8cd9", icon: <Waypoints className="size-3.5" />, help: "Reported by a third-party source; DNS state shown when checked." },
  ip: { label: "IP address", color: "#d6a64b", icon: <Network className="size-3.5" />, help: "An address returned by DNS." },
  asn: { label: "Network (ASN)", color: "#e0875f", icon: <Shield className="size-3.5" />, help: "Autonomous system that announces the address (third-party data)." },
  certificate: { label: "TLS certificate", color: "#6fd0b4", icon: <KeyRound className="size-3.5" />, help: "Certificate presented on port 443." },
};

type GNode = { id: string; type: string; label: string; layer: number; data: Record<string, any> };
type GEdge = { id: string; source: string; target: string; relation: string; evidence: string; source_ref: string; kind: string; data?: Record<string, any> };

const NodeCard = memo(function NodeCard({ data, selected }: NodeProps) {
  const t = NODE_TYPES[(data as any).type] ?? NODE_TYPES.dns_record;
  const unresolved = (data as any).verification === "dns_unresolved";
  return (
    <div className="flex max-w-[210px] items-center gap-2 rounded-lg border bg-panel px-2.5 py-1.5 text-xs shadow-lg" style={{ borderColor: selected ? "#e4ebe8" : t.color + "99", borderStyle: unresolved ? "dashed" : "solid" }}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-line-strong" />
      <span style={{ color: t.color }} aria-hidden>{t.icon}</span>
      <span className="truncate font-mono">{(data as any).label}</span>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-line-strong" />
    </div>
  );
});
const nodeTypes = { card: NodeCard };

function layout(nodes: GNode[]): Node[] {
  const byLayer = new Map<number, GNode[]>();
  nodes.forEach((n) => byLayer.set(n.layer, [...(byLayer.get(n.layer) ?? []), n]));
  const out: Node[] = [];
  [...byLayer.keys()].sort().forEach((layer) => {
    const col = byLayer.get(layer)!;
    col.forEach((n, i) => out.push({ id: n.id, type: "card", position: { x: layer * 250, y: (i - (col.length - 1) / 2) * 50 }, data: { type: n.type, label: n.label, verification: n.data?.verification } }));
  });
  return out;
}

export function InfraGraph({ graph }: { graph: { nodes: GNode[]; edges: GEdge[]; note?: string; truncated?: boolean } }) {
  const [sel, setSel] = useState<{ kind: "node" | "edge"; id: string } | null>(null);
  const nodes = useMemo(() => layout(graph.nodes), [graph.nodes]);
  const edges: Edge[] = useMemo(() => graph.edges.map((e) => ({
    id: e.id, source: e.source, target: e.target, label: e.relation, markerEnd: { type: MarkerType.ArrowClosed, color: "#4a5f56" },
    style: { strokeDasharray: e.kind === "naming" ? "5 4" : undefined, stroke: "#4a5f56" }, labelStyle: { fill: "#8a9b94", fontSize: 10 }, labelBgStyle: { fill: "#0e1412" },
  })), [graph.edges]);
  const present = [...new Set(graph.nodes.map((n) => n.type))];
  const node = sel?.kind === "node" ? graph.nodes.find((n) => n.id === sel.id) : null;
  const edge = sel?.kind === "edge" ? graph.edges.find((e) => e.id === sel.id) : null;
  const touching = node ? graph.edges.filter((e) => e.source === node.id || e.target === node.id) : [];
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;

  if (!graph.nodes.length) return <EmptyState title="Nothing to graph">No relationships were returned by the lookups.</EmptyState>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-x-4 gap-y-1.5" aria-label="Legend">
        {present.map((t) => <span key={t} className="inline-flex items-center gap-1.5 text-xs text-muted" title={NODE_TYPES[t]?.help}><span style={{ color: NODE_TYPES[t]?.color }}>{NODE_TYPES[t]?.icon}</span>{NODE_TYPES[t]?.label ?? t}</span>)}
        <span className="inline-flex items-center gap-1.5 text-xs text-muted"><svg width="22" height="6" aria-hidden><line x1="0" y1="3" x2="22" y2="3" stroke="#4a5f56" strokeWidth="2" /></svg>Observed in a lookup</span>
        <span className="inline-flex items-center gap-1.5 text-xs text-muted"><svg width="22" height="6" aria-hidden><line x1="0" y1="3" x2="22" y2="3" stroke="#4a5f56" strokeWidth="2" strokeDasharray="5 4" /></svg>Name hierarchy only</span>
        <span className="inline-flex items-center gap-1.5 text-xs text-muted"><span className="inline-block h-3 w-5 rounded border border-dashed border-muted" aria-hidden />Reported name that did not resolve</span>
      </div>
      <div className="grid gap-3">
        <div className="h-[560px] overflow-hidden rounded-xl border border-line bg-canvas" data-testid="infra-graph">
          <ReactFlow colorMode="dark" nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08, maxZoom: 1.1 }} minZoom={0.2} maxZoom={2} nodesConnectable={false} proOptions={{ hideAttribution: true }}
            onNodeClick={(_, n) => setSel({ kind: "node", id: n.id })} onEdgeClick={(_, e) => setSel({ kind: "edge", id: e.id })} onPaneClick={() => setSel(null)}>
            <Background color="#1c2824" gap={24} />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(n) => NODE_TYPES[(n.data as any).type]?.color ?? "#555"} maskColor="rgba(10,14,13,.7)" />
          </ReactFlow>
        </div>
        <Panel title="Details" className="self-start">
          {!sel && <p className="text-sm text-muted">Select a node or a line. Every line shows the lookup that produced it. Scroll to zoom, drag to pan.</p>}
          {node && (
            <div className="grid gap-5 md:grid-cols-2">
              <div className="space-y-3"><div><p className="text-xs text-muted">{NODE_TYPES[node.type]?.label}</p><p className="break-all font-mono text-sm">{node.label}</p></div>
              <KV stacked rows={flatten(node.data)} /></div>
              <div><p className="mb-1.5 text-xs font-medium text-muted">Evidence ({touching.length})</p>
                <ul className="space-y-2">{touching.map((e) => <li key={e.id} className="rounded-md border border-line bg-canvas p-2 text-xs"><p><span className="text-muted">{label(e.source)}</span> <span className="text-cyan">{e.relation}</span> <span className="text-muted">{label(e.target)}</span></p><p className="mt-1">{e.evidence}</p><p className="mt-0.5 text-faint">Source: {e.source_ref}</p></li>)}</ul></div>
            </div>
          )}
          {edge && (
            <div className="space-y-2 text-sm">
              <p><span className="font-mono">{label(edge.source)}</span> <span className="text-cyan">{edge.relation}</span> <span className="font-mono">{label(edge.target)}</span></p>
              <KV stacked rows={[["Evidence", edge.evidence], ["Source", edge.source_ref], ["Kind", edge.kind === "naming" ? "Name hierarchy (no lookup)" : "Observed in a lookup"], ["Queried", edge.data?.queried_at && <Mono key="q">{String(edge.data.queried_at)}</Mono>]]} />
            </div>
          )}
        </Panel>
      </div>
      <p className="text-xs text-muted">{graph.note}{graph.truncated ? " The graph was truncated at the node limit." : ""}</p>
    </div>
  );
}

function flatten(d: Record<string, any>): [string, ReactNode][] {
  const rows: [string, ReactNode][] = [];
  const walk = (o: any, prefix = "") => Object.entries(o ?? {}).forEach(([k, v]) => {
    if (v === null || v === undefined || v === "") return;
    const key = (prefix + k).replace(/_/g, " ");
    if (Array.isArray(v)) rows.push([key, v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ")]);
    else if (typeof v === "object") walk(v, key + " · ");
    else rows.push([key, String(v)]);
  });
  walk(d);
  return rows.slice(0, 24);
}
