import { ArrowRight, Eye, FileCheck2, Gavel, Lock, ScanSearch, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Logo } from "../components/Logo";
import { Button } from "../components/ui";
import { useMode } from "../lib/mode";

/** The hero diagram is drawn once on load and then stays still. It is labelled illustrative: it never imitates a running scan. */
function FootprintDiagram() {
  const cx = 260, cy = 230;
  const rings = [88, 150, 212];
  const nodes: { a: number; r: number; label: string; color: string; kind: string }[] = [
    { a: -100, r: 88, label: "A  203.0.113.10", color: "#d6a64b", kind: "ip" }, { a: 5, r: 88, label: "NS  ns1", color: "#8a9b94", kind: "dns" }, { a: 95, r: 88, label: "MX  mail", color: "#8a9b94", kind: "dns" }, { a: 185, r: 88, label: "TLS certificate", color: "#6fd0b4", kind: "cert" },
    { a: -35, r: 150, label: "AS64500", color: "#e0875f", kind: "asn" }, { a: 55, r: 150, label: "api.", color: "#9b8cd9", kind: "sub" }, { a: 145, r: 150, label: "staging.", color: "#9b8cd9", kind: "sub" }, { a: 230, r: 150, label: "registrar", color: "#2fbf8f", kind: "reg" },
    { a: -110, r: 212, label: "linked sites", color: "#3db8d4", kind: "link" }, { a: 20, r: 212, label: "partner.", color: "#3db8d4", kind: "link" }, { a: 120, r: 212, label: "robots.txt", color: "#8a9b94", kind: "file" }, { a: 205, r: 212, label: "sitemap", color: "#8a9b94", kind: "file" },
  ];
  const pos = (a: number, r: number) => [cx + r * Math.cos((a * Math.PI) / 180), cy + r * Math.sin((a * Math.PI) / 180)] as const;
  return (
    <figure className="relative">
      <svg viewBox="0 0 520 460" className="mx-auto w-full max-w-[560px]" role="img" aria-label="Illustration of a domain at the centre with DNS records, certificates, networks, subdomains and linked sites arranged around it in rings">
        {rings.map((r, i) => <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="#26332e" strokeWidth="1" strokeDasharray={i === 2 ? "2 6" : undefined} />)}
        {nodes.map((n, i) => { const [x, y] = pos(n.a, n.r); const len = Math.hypot(x - cx, y - cy); return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke={n.color} strokeOpacity=".5" strokeWidth="1.2" className="draw-in" style={{ ["--len" as any]: len, ["--delay" as any]: `${0.2 + i * 0.07}s` }} />; })}
        {nodes.map((n, i) => {
          const [x, y] = pos(n.a, n.r); const left = x < cx - 20;
          return (
            <g key={i} className="fade-in" style={{ ["--delay" as any]: `${0.7 + i * 0.07}s` }}>
              <circle cx={x} cy={y} r="5" fill="#0a0e0d" stroke={n.color} strokeWidth="1.8" />
              <text x={x + (left ? -11 : 11)} y={y + 4} textAnchor={left ? "end" : "start"} fontSize="11" fill="#b4c2bc" fontFamily="JetBrains Mono, monospace">{n.label}</text>
            </g>
          );
        })}
        <g className="fade-in" style={{ ["--delay" as any]: "0s" }}>
          <circle cx={cx} cy={cy} r="30" fill="#141c19" stroke="#2fbf8f" strokeWidth="2" />
          <circle cx={cx} cy={cy} r="8" fill="#2fbf8f" />
          <text x={cx} y={cy + 52} textAnchor="middle" fontSize="12" fill="#e4ebe8" fontFamily="JetBrains Mono, monospace">aurora-demo.example.org</text>
        </g>
      </svg>
      <figcaption className="mt-1 text-center text-xs text-muted">Illustration of a footprint, not a live scan. The workspace shows only data that was actually collected.</figcaption>
    </figure>
  );
}

const FEATURES = [
  { icon: ScanSearch, title: "Website and link intelligence", body: "Status, headers, metadata, technology hints, robots.txt, sitemap and every link on the page. Links you did not check are labelled as not checked." },
  { icon: Eye, title: "Image metadata", body: "See what a photo gives away before you post it: camera, time, software, location. Download a sanitised copy. Nothing is uploaded to third parties." },
  { icon: FileCheck2, title: "Infrastructure map", body: "DNS, registration, network ownership, certificates and passively reported subdomains, joined into a graph where every line cites the lookup behind it." },
  { icon: Lock, title: "Built against misuse", body: "Every request passes address validation, DNS-rebinding defence and redirect re-checks. It cannot be turned into an open proxy for internal networks." },
];

export function Landing() {
  const nav = useNavigate();
  const { setMode } = useMode();
  return (
    <div className="min-h-full bg-ink">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-5 py-5">
        <Logo />
        <nav aria-label="Site" className="flex items-center gap-1 text-sm text-muted">
          <a href="#how" className="hidden rounded px-3 py-2 hover:text-text sm:block">How it works</a>
          <a href="#responsible" className="hidden rounded px-3 py-2 hover:text-text sm:block">Responsible use</a>
          <Link to="/present" className="hidden rounded px-3 py-2 hover:text-text sm:block">Presentation</Link>
          <Link to="/app"><Button size="sm" variant="secondary">Open workspace</Button></Link>
        </nav>
      </header>

      <main>
        <section className="mx-auto grid max-w-6xl items-center gap-10 px-5 pb-16 pt-8 lg:grid-cols-[1.05fr_1fr] lg:pt-14">
          <div>
            <h1 className="max-w-xl text-[2.6rem] leading-[1.04] sm:text-6xl">Know what your domain shows the world.</h1>
            <p className="mt-5 max-w-lg text-lg text-muted">CyberRecon maps the public footprint of websites, domains and images you are authorised to assess, and labels every fact as observed, reported by a third party, or estimated.</p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button variant="primary" className="px-5 py-3 text-base" onClick={() => { setMode("live"); nav("/app"); }}>Launch workspace<ArrowRight className="size-4" /></Button>
              <Button className="px-5 py-3 text-base" onClick={() => { setMode("demo"); nav("/app"); }}>Explore demo</Button>
            </div>
            <p className="mt-4 max-w-md text-sm text-muted">The demo needs no API keys or internet access and uses a fictional company. It is always labelled as simulated.</p>
          </div>
          <FootprintDiagram />
        </section>

        <section aria-label="Product preview" className="mx-auto max-w-6xl px-5 pb-20">
          <div className="overflow-hidden rounded-2xl border border-line-strong bg-canvas shadow-[0_30px_80px_-30px_rgba(47,191,143,.18)]">
            <div className="flex items-center gap-2 border-b border-line bg-ink px-4 py-2.5"><span className="size-2.5 rounded-full bg-line-strong" /><span className="size-2.5 rounded-full bg-line-strong" /><span className="size-2.5 rounded-full bg-line-strong" />
              <span className="ml-3 rounded bg-amber/15 px-2 py-0.5 text-xs text-amber">DEMO DATA · simulated preview</span></div>
            <div className="grid gap-px bg-line md:grid-cols-[1.3fr_1fr]">
              <div className="space-y-3 bg-canvas p-5">
                <p className="font-display text-lg">aurora-demo.example.org</p>
                <div className="grid grid-cols-3 gap-2 text-sm">{[["IP addresses", "3"], ["Certificate", "24 days"], ["Subdomains reported", "3"]].map(([k, v]) => <div key={k} className="rounded-lg border border-line bg-panel p-3"><p className="text-xs text-muted">{k}</p><p className="font-display text-xl">{v}</p></div>)}</div>
                <ul className="divide-y divide-line rounded-lg border border-line text-sm">
                  {[["Medium", "Certificate expires in 24 days", "Observed", "text-amber"], ["Low", "No DMARC enforcement (p=none)", "Observed", "text-cyan"], ["Info", "Network AS64500 announces 203.0.113.0/24", "Third-party", "text-violet"]].map(([s, t, e, c]) => (
                    <li key={t} className="flex items-center gap-3 px-3 py-2.5"><span className={`w-14 text-xs font-medium ${c}`}>{s}</span><span className="flex-1">{t}</span><span className="text-xs text-muted">{e}</span></li>))}
                </ul>
              </div>
              <div className="bg-canvas p-5">
                <p className="mb-3 text-sm text-muted">Where each statement comes from</p>
                <ul className="space-y-2.5 text-sm">{[["DNS via resolver", "Retrieved", "text-emerald"], ["RDAP registration", "Retrieved", "text-emerald"], ["GeoIP provider", "Not configured", "text-amber"], ["Subdomain source", "Retrieved", "text-emerald"]].map(([n, s, c]) => <li key={n} className="flex justify-between gap-3 rounded-lg border border-line bg-panel px-3 py-2"><span>{n}</span><span className={`text-xs ${c}`}>{s}</span></li>)}</ul>
                <p className="mt-4 text-xs text-muted">Unavailable sources are shown as unavailable. They are never filled in.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-5 pb-20" aria-labelledby="features">
          <h2 id="features" className="max-w-xl text-3xl sm:text-4xl">Four things it does well, and one it refuses to do.</h2>
          <div className="mt-10 grid gap-x-12 gap-y-9 md:grid-cols-2">
            {FEATURES.map(({ icon: Icon, title, body }) => (
              <div key={title} className="flex gap-4 border-t border-line pt-5"><Icon className="mt-1 size-5 shrink-0 text-emerald" aria-hidden /><div><h3 className="text-lg">{title}</h3><p className="mt-1.5 text-muted">{body}</p></div></div>
            ))}
          </div>
        </section>

        <section id="how" className="border-y border-line bg-canvas py-20" aria-labelledby="how-h">
          <div className="mx-auto max-w-6xl px-5">
            <h2 id="how-h" className="text-3xl sm:text-4xl">From target to evidence in three steps.</h2>
            <ol className="mt-10 grid gap-8 md:grid-cols-3">
              {[["Confirm you may assess it", "Enter a domain or URL and confirm authorisation. CyberRecon checks the target against its network rules before sending a single request."], ["Watch the real progress", "Each step reports what the backend is actually doing, including steps that fail or are skipped. There is no animated fake scan."], ["Review, export, share", "Open findings grouped by how they were obtained, then export a PDF, JSON or CSV with sources, limitations and next steps."]].map(([t, b], i) => (
                <li key={t} className="relative border-l-2 border-emerald/60 pl-5"><span className="font-mono text-sm text-emerald">Step {i + 1}</span><h3 className="mt-1 text-xl">{t}</h3><p className="mt-2 text-muted">{b}</p></li>))}
            </ol>
          </div>
        </section>

        <section id="responsible" className="mx-auto max-w-6xl px-5 py-20" aria-labelledby="resp">
          <div className="grid gap-10 lg:grid-cols-[1fr_1.2fr]">
            <div><Gavel className="mb-4 size-6 text-amber" aria-hidden /><h2 id="resp" className="text-3xl sm:text-4xl">Responsible use is part of the product.</h2>
              <p className="mt-4 max-w-md text-muted">Footprinting helps defenders see what attackers see. It can also be misused, so CyberRecon is deliberately limited.</p></div>
            <ul className="space-y-4">
              {[["Authorisation first", "You confirm permission before every live assessment, and the confirmation is stored with the result and printed in the report."], ["Passive only", "No exploitation, credential attacks, brute-forcing, port scanning or bypassing of CAPTCHAs, logins or robots.txt."], ["No people-finding", "Image analysis reads embedded metadata. It never identifies a person, never claims a photo is authentic, and never uploads to third parties without your action."], ["Honest limits", "Estimates are labelled as estimates. Technology detection is a hint. Application-level checks reduce SSRF risk but are not a substitute for network egress controls, and the docs say so."]].map(([t, b]) => (
                <li key={t} className="flex gap-3"><ShieldCheck className="mt-1 size-5 shrink-0 text-emerald" aria-hidden /><div><p className="font-medium">{t}</p><p className="text-muted">{b}</p></div></li>))}
            </ul>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-5 py-8 text-sm text-muted">
          <Logo size={22} /><p>For authorised assessments only. Not a legal, compliance or penetration-testing service.</p>
          <nav aria-label="Footer" className="flex gap-4"><Link className="hover:text-text" to="/app">Workspace</Link><Link className="hover:text-text" to="/present">Presentation</Link></nav>
        </div>
      </footer>
    </div>
  );
}
