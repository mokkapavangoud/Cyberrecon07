# Architecture

```
Browser (React SPA)
   │  /api/*  (JSON, multipart upload, file downloads)
   ▼
FastAPI app ── rate limiter ── security headers ── error envelope
   │
   ├── routes.py ─────────────► JobRunner (semaphore, StepTracker, recover_interrupted)
   │                               │
   │                               ├─ link_analysis      ─┐
   │                               ├─ infrastructure      ├─► SafeFetcher / providers
   │                               ├─ screenshot          │     (GuardedNetworkBackend)
   │                               └─ image_intelligence ─┘     (in-memory only)
   │
   ├── history / dashboard ───► SQLAlchemy ► SQLite (assessments, results, findings, sources, reports)
   ├── reporting (PDF/JSON/CSV) ◄── persisted record only
   └── demo ──► demo/aurora-demo.json   (static, never touches the DB)
```

## Backend layout (`backend/app`)

| Path | Responsibility |
|---|---|
| `core/` | `config.py` (pydantic-settings, `CYBERRECON_*`), `ratelimit.py` (sliding window) |
| `security/` | `ip_policy.py` (deny-list), `target.py` (URL/host normalisation and scope), `safe_net.py` (`GuardedNetworkBackend`, `SafeFetcher`, guarded TLS dial) |
| `integrations/` | One adapter per external source behind a small interface: `dns_provider`, `rdap`, `asn` (Team Cymru over DNS), `geoip`, `subdomains` (crt.sh / SecurityTrails), `tls`, `screenshots`; `registry.py` bundles them as `Providers` |
| `services/link_analysis/` | HTML parsing, link classification, robots.txt, sitemap, optional bounded link checking |
| `services/infrastructure/` | Orchestrates DNS → RDAP → ASN → geo → TLS → fingerprints → subdomains → graph; `screenshot.py` is the screenshot module |
| `services/image_intelligence/` | Validation (`inspector`), EXIF/GPS extraction and findings (`analyzer`), metadata removal (`sanitizer`) |
| `services/jobs.py` | `JobRunner`, `StepTracker`, `ModuleOutput` |
| `services/reporting/` | `serialize` (one dict shape used everywhere), `exports` (CSV/JSON), `pdf`, `store` (files + DB rows) |
| `services/history.py`, `dashboard.py`, `demo.py` | Queries, aggregates, static demo bundle |
| `database/` | Engine/session (WAL + foreign keys pragmas), versioned migrations |
| `api/` | Routes, error envelope, shared state |

## Job model and real progress

1. `POST /api/assessments/{module}` validates the target and authorisation, inserts an `assessments` row with a list of **steps** (`pending`), and returns `202` + id.
2. `JobRunner` runs the module under a semaphore. Each module calls `StepTracker.start/finish/skip/fail`, which write the step status to the database.
3. The UI polls `GET /api/assessments/{id}` every second while status is `queued`/`running`; the progress bar is `finished steps / total steps` — never a timer.
4. On finish the runner stores the result JSON, findings and sources, sets the status (`completed`, `partial` when some lookups failed, `failed`), and marks any remaining pending steps `skipped`.
5. On start-up `recover_interrupted` marks anything left `running` by a previous crash as `failed` with an explanatory error.

Images run synchronously in the request (they are fast and the bytes are never stored). `ModuleOutput.transient` carries the full GPS result back once; the persisted copy is redacted.

## Evidence model

Every finding carries `evidence_type`:

- `observed` — CyberRecon retrieved or measured it directly (headers, DNS answer, certificate, EXIF in the file).
- `third_party` — reported by an external dataset (RDAP, crt.sh, ASN registry).
- `estimate` — inferred (geolocation, technology fingerprint, subdomain *reported but not verified*).

Sources are stored with a status (`ok`, `unavailable`, `failed`, `skipped`) so failed lookups appear in the UI and in reports. Reports and the UI group findings by evidence type.

## Persistence

SQLite via SQLAlchemy: `assessments` (target, module, options, scope, authorisation flag + timestamp, steps, status, summary, error, timings), `results` (module JSON), `findings`, `sources`, `reports` (file metadata + sha256). Cascading deletes; `delete_assessment` also removes the report and screenshot files. Migrations are an ordered list applied at start-up and recorded in a version table. Uploaded images are never stored.

## Frontend (`frontend/src`)

- `lib/` — typed API client (`api.ts`), demo-vs-live routing via `ModeProvider`, React Query hooks (`useAssessment` polls while non-terminal).
- `components/` — design system (`ui.tsx`: Button, Panel, Skeleton, EmptyState, ErrorState, ConfirmDialog, …), `DataTable` (search/sort/filter/export), `Shell` (collapsible sidebar, top bar, breadcrumbs, mobile nav).
- `views/` — pure presentational views of an assessment object (`LinkView`, `InfraView`, `ImageView`, `ScreenshotView`, `InfraGraph`), shared by live and demo data.
- `pages/` — routes: landing, presentation, dashboard, module pages, history, assessment, reports, settings.
- Visual language: charcoal canvas, emerald/cyan accents, self-hosted fonts, a landing-page illustration of a domain with its related records in rings, which is explicitly an illustration (it is not shown as a scan); `prefers-reduced-motion` removes animation.

## Decisions worth knowing

- **Why custom network backend, not a URL checker:** validating a hostname then letting the HTTP client re-resolve is the classic rebinding bug. Connecting to the validated IP removes that gap for the HTTP/TLS clients.
- **Why one serialised assessment shape:** API, CSV/JSON export, PDF and the demo bundle all use `assessment_to_dict`, so reports cannot drift from what the UI shows.
- **Why demo is separate code, not a flag in the DB:** it makes "demo data never reaches real history" a structural property that tests can assert.
- **Why SQLite:** zero-ops for a single-tenant tool. Concurrency is bounded by the semaphore.

## Future enhancements

Scheduled re-assessments with change detection; authentication, roles and per-project scopes; Postgres + a durable queue (RQ/Celery/Arq); distributed rate limiting; signed/immutable report archives; more passive providers (Shodan/Censys-style, behind the same interfaces); an egress proxy service shipped with the compose file; i18n; accessibility audit with assistive-tech testing; OpenAPI-generated client types.
