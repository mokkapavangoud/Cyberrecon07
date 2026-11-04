# CyberRecon

A digital-footprint intelligence workspace for **authorised** security assessments. It looks at the public surface of a website, an image, or a domain, keeps the results, and produces evidence-labelled reports. It is passive by design: no exploitation, no credential testing, no bypassing of robots.txt, CAPTCHAs or access controls.

> **Status:** a working prototype / portfolio-grade MVP. It is *not* enterprise-grade or production-hardened, and nothing here is a substitute for a security review before exposing it to others. See [docs/SECURITY.md](docs/SECURITY.md) for exactly what is and isn't protected.

## What it does

| Module | What you get |
|---|---|
| **Website & links** | Status, timing, title, metadata, security-relevant headers, robots.txt, sitemap, every link with category and count. Optional link checking (capped, same-site by default) — *discovered* and *checked* links are shown separately. |
| **Image metadata** | Upload an image → file facts, EXIF, GPS, timestamps, camera. Missing metadata is labelled as missing. Download a **sanitised copy**, a report, and get reverse-image-search links (nothing is uploaded to third parties). The app never identifies people or judges authenticity. |
| **Infrastructure** | DNS (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA), RDAP registration, ASN/network ownership, optional geolocation (labelled an *estimate*), TLS certificate, technology fingerprints (labelled non-definitive), optional passive subdomain discovery (*reported* vs *verified*), and an interactive graph whose edges come only from collected data. |
| **Screenshots** | A page screenshot taken in an isolated headless Chromium with its own request guard. Failures are shown as failures. |
| **Dashboard / history** | Built only from saved assessments. Reopen, search, export, or delete anything. |
| **Reports** | PDF / JSON / CSV generated from the persisted record: authorisation, scope, methods, findings grouped as *observed / third-party / estimate*, sources including failed lookups, limitations, next steps. |
| **Demo mode** | A fictional organisation ("Aurora Labs") with simulated data, a sample report and a presentation walkthrough. Works fully offline, is watermarked, and never touches the database. |

## Stack and why

- **FastAPI + SQLAlchemy 2 + SQLite (WAL)** — typed, async, small. SQLite keeps setup to zero services; SQLAlchemy lets you swap to Postgres via `CYBERRECON_DATABASE_URL`.
- **httpx/httpcore with a custom network backend** — the only way to resolve, validate and *connect to the validated IP* in one step (the basis of the SSRF defence).
- **dnspython, cryptography, Pillow/piexif, BeautifulSoup/lxml, reportlab** — each does one job; reportlab ships with bundled DejaVu fonts so PDFs render non-Latin text offline.
- **Playwright Chromium** (optional) — real rendering for screenshots, driven through the CDP `Fetch` domain so every request, including redirect hops, is vetted.
- **React 19 + TypeScript + Vite + Tailwind v4** — TanStack Query for polling real job status, `@xyflow/react` for the infrastructure graph, Recharts for the dashboard.
- **Tests:** pytest (+ a local fixture HTTP/TLS server and fake providers) and Vitest/Testing Library.

## Quick start

Requirements: Python 3.13 (what it was developed on), Node 22+, ~500 MB for optional Chromium.

```bash
scripts/dev.sh setup          # venv + pip install + npm install
scripts/dev.sh api            # terminal 1: API on http://127.0.0.1:8000  (docs at /api/docs)
scripts/dev.sh web            # terminal 2: UI on  http://localhost:5173  (proxies /api)
```

Optional screenshots: `backend/.venv/bin/playwright install chromium` (Linux may also need `--with-deps`).

Single-process mode (API serves the built UI):

```bash
scripts/dev.sh build && scripts/dev.sh serve     # http://127.0.0.1:8000
```

Configuration is by `CYBERRECON_*` environment variables or `backend/.env`; see [.env.example](.env.example).

### Commands

| Task | Command |
|---|---|
| Backend tests | `cd backend && .venv/bin/pytest -q` |
| Frontend tests | `cd frontend && npm test` |
| Typecheck | `cd frontend && npm run typecheck` |
| Production build | `cd frontend && npm run build` |
| Everything | `scripts/dev.sh test` |
| Rebuild demo data | `cd backend && .venv/bin/python ../scripts/build_demo.py` |

## Try it without any network

1. Open the app → **Explore Demo** (or the *Demo* switch in the top bar).
2. A banner states the data is simulated. Browse the dashboard, open the infrastructure graph, download the sample PDF.
3. Open **Presentation mode** (`/present`) for a talk-ready walkthrough: problem, workflow, architecture, ethics, future work.

Demo mode serves a static bundle from `demo/aurora-demo.json`, uses reserved documentation domains and IP ranges, and is flagged `simulated: true` in every payload. See [docs/PRESENTATION.md](docs/PRESENTATION.md).

## Live assessments

Enter a domain/URL in the top bar (or a module page), tick the authorisation confirmation, and start. Progress shown in the UI is the real step status stored by the job runner (polled every second). If DNS, TLS, RDAP or an external provider is unreachable, the affected section shows **unavailable** with the reason — nothing is fabricated.

Targets resolving to private, loopback, link-local, metadata or other non-public addresses are rejected, including after redirects.

## What was verified (and what wasn't)

Run in the build environment, which had **no direct internet or DNS**:

- ✅ Backend: **215 tests passed** (SSRF/rebinding, redirects, limits, link extraction, EXIF, sanitiser, uploads, persistence, reports incl. PDF text, API errors, demo isolation, real-Chromium screenshot guard against a local server).
- ✅ Frontend: typecheck clean, **30 Vitest tests passed**, production build succeeds.
- ✅ Browser checks with Playwright on desktop and mobile widths: landing, demo dashboard, graph, link table, image upload → sanitise, validation failure, unreachable-target failure, delete confirmation.
- ❌ **Not executed:** live DNS, RDAP, ASN, crt.sh and GeoIP lookups, and a *successful* live website assessment against a real public host. Those paths are covered only by fakes and local fixtures, plus the failure paths above. The first run on a networked machine is the real integration test.
- ❌ **Not executed:** Docker image build, container deployment, egress-firewall behaviour.

## Known limitations

- Application-level validation does **not** by itself eliminate SSRF or DNS-rebinding risk; production needs network egress controls ([docs/SECURITY.md](docs/SECURITY.md)).
- Chromium resolves DNS itself, so screenshots keep a residual time-of-check/time-of-use gap unless you use `CYBERRECON_SCREENSHOT_PROXY` or a firewall.
- No user accounts: single-tenant, intended for local or trusted-network use. Rate limiting is in-memory and per process.
- Technology fingerprints and geolocation are heuristics; they are labelled as such.

## Docs

- [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Security design & limits](docs/SECURITY.md)
- [Integrations & providers](docs/INTEGRATIONS.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [Presentation guide](docs/PRESENTATION.md)

## Responsible use

Only assess systems you own or have written permission to assess. CyberRecon requires an authorisation confirmation before any live assessment and records it with the assessment. It is not a tool for reconnaissance against third parties, and it must not be deployed as a public, unauthenticated service.
