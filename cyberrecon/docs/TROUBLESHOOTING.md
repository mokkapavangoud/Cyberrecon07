# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| UI shows "API offline" | API not running, or Vite proxy target wrong | Start `scripts/dev.sh api`; the dev proxy expects `127.0.0.1:8000` (`frontend/vite.config.ts`) |
| Browser console: CORS error | UI served from an origin not in the allow-list | Add it to `CYBERRECON_CORS_ORIGINS` |
| `The hostname could not be resolved` | No DNS from the server, or the name doesn't exist | Check `dig <host>` from the same machine; set `CYBERRECON_DNS_RESOLVERS`; the assessment is correctly saved as *failed* |
| `blocked_address` / `non_public_name` | Target resolves to (or is) a private/reserved address, or uses a reserved suffix such as `.local`/`.example` | Expected. Use a public name. For local testing use the fixtures in `backend/tests` rather than loosening the policy |
| `out_of_scope` | `CYBERRECON_TARGET_ALLOWLIST` is set and doesn't include the host | Add the domain or clear the setting |
| Infrastructure sections say *unavailable* | RDAP/crt.sh/Cymru unreachable from the server (firewall, no internet) | Open the *Sources* tab for the exact reason. Egress allow-list must permit DNS and HTTPS to those hosts |
| Geolocation unavailable | No provider configured (default) | See [INTEGRATIONS.md](INTEGRATIONS.md) |
| Screenshots disabled / `screenshots_unavailable` | Chromium not installed | `backend/.venv/bin/playwright install chromium` (Linux: add `--with-deps`) or set `CYBERRECON_CHROMIUM_PATH` |
| Screenshot fails with blocked request | The page redirected or loaded a resource from a non-public address or other site | Expected guard behaviour; the blocked URLs are listed in the result |
| `429 rate_limited` | More than `CYBERRECON_RATE_LIMIT_PER_MINUTE` requests from your IP | Wait for `Retry-After` or raise the limit |
| Upload rejected | Not a decodable image, > 10 MB, > 50 MP, or animated | Limits come from `/api/config`; adjust `CYBERRECON_MAX_UPLOAD_BYTES` / `MAX_IMAGE_PIXELS` |
| GPS missing from a *saved* image assessment | By design: redacted before storage | Re-upload to see it once, or set `CYBERRECON_PERSIST_IMAGE_GPS=true` (not recommended) |
| Assessment stuck "running" after a crash | Process died mid-job | Restart the API; interrupted jobs are marked *failed* at start-up |
| `database is locked` | Another process holds the SQLite file | Run one API process per data dir, or move to Postgres |
| PDF has missing glyphs | Unusual script not in DejaVu | Fonts live in `backend/app/assets/fonts`; add a font and register it in `reporting/pdf.py` |
| `Demo data unavailable` | `demo/aurora-demo.json` missing | `cd backend && .venv/bin/python ../scripts/build_demo.py` |
| Blank page when serving the built UI | `frontend/dist` missing | `scripts/dev.sh build`, or set `CYBERRECON_FRONTEND_DIST` |
| `pytest` skips screenshot tests | Chromium not installed | Install it to run them; they are reported as skipped, not passed |

Logs go to stderr from uvicorn; unexpected errors are logged with a traceback and returned to the client only as a generic `internal_error`.
