# API

Base path `/api`. Interactive docs: `/api/docs` (Swagger UI) and `/api/openapi.json`.

## Conventions

- JSON in/out unless noted. Timestamps are ISO-8601.
- **Errors** always look like:
  ```json
  { "error": { "code": "blocked_address", "message": "…", "field": "target" } }
  ```
  Common codes: `invalid_request` (422, with `fields`), `authorization_required` (422), `not_found` (404), `rate_limited` (429 + `Retry-After`), `file_too_large` (413), `screenshots_unavailable` (503), `internal_error` (500). Target-validation codes (422): `blocked_address`, `port_not_allowed`, `out_of_scope`, `unsupported_scheme`, `invalid_host`, `invalid_url`, `non_public_name`, `ambiguous_ip`, `ip_not_supported`, `credentials_in_url`, `empty_target`, `too_long`, `invalid_characters`.
- Assessment IDs are 32-char lowercase hex. Demo IDs are `demo-<module>-aurora`.
- Rate limit: `CYBERRECON_RATE_LIMIT_PER_MINUTE` per client IP on endpoints that start work or generate files.

## Meta

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | `{status, version, database, time}`; 503 if the DB is unavailable |
| GET | `/config` | Capabilities (screenshots, subdomain provider, geoip, PDF), limits, privacy flags. Never includes secrets |

## Live assessments

`POST /api/assessments/{module}` — `module` ∈ `link`, `infrastructure`, `screenshot`

```json
{
  "target": "example.org",
  "authorized": true,
  "options": { "check_links": true, "check_external": false, "max_links_to_check": 25, "include_http": true }
}
```
`authorized` must be `true` or the call returns 422 `authorization_required`. Options not relevant to the module are ignored. Response `202`:
```json
{ "id": "…32 hex…", "module": "link", "status": "queued", "location": "/api/assessments/…" }
```

`GET /api/assessments/{id}` — full assessment: `status` (`queued|running|completed|partial|failed`), `progress {finished,total,percent,current}`, `steps[]`, `authorization`, `scope`, `options`, `result` (module-specific), `findings[]`, `sources[]`, `errors[]`, `reports[]`, `available_exports[]`. Poll while status is `queued`/`running`.

`GET /api/assessments?module=&status=&q=&limit=&offset=` — `{items, total, …}` summaries.

`DELETE /api/assessments/{id}` → 204 (also deletes reports and screenshot). `DELETE /api/assessments?confirm=true` deletes everything (`confirm` missing → 400).

`GET /api/assessments/{id}/screenshot` → `image/png` (404 when none was captured).

## Images

`POST /api/images/analyze` — multipart field `file`. Runs synchronously. Response:
```json
{ "assessment": { … persisted record, GPS redacted … },
  "live_result": { … includes GPS if present, returned once … },
  "live_result_note": "…" }
```
Invalid/unsupported/oversized files → 422/413 with an error code (`unsupported_type`, `corrupt_image`, `image_too_large` (pixel cap), `animated_unsupported`, `file_too_large`, `empty_file`). The upload is not stored.

`POST /api/images/sanitize` — multipart `file`. Returns the sanitised image bytes. Header `X-CyberRecon-Sanitize` is JSON: `{method, sha256, removed[], retained[], notes[], bytes_before, bytes_after}`.

## Reports and exports

| Method | Path | Notes |
|---|---|---|
| POST | `/assessments/{id}/reports` | body `{format: pdf|json|csv, table?}` → 201 with report metadata + `download_url`. 409 `not_ready` if the assessment is still running |
| GET | `/assessments/{id}/export?format=&table=` | generates and streams a file directly |
| GET | `/reports` | previously generated reports |
| GET | `/reports/{id}/download` | file download |

CSV `table` values depend on the module (`links`, `dns_records`, `ip_addresses`, `subdomains`, `metadata`, `findings`, `sources`); see `available_exports` on the assessment. Unknown table → 422 `unknown_table`.

## Dashboard

`GET /api/dashboard` — aggregates computed from saved assessments only (totals, severity counts, module usage, durations, recent, top findings, trend with `sufficient` flag). Empty database → zeros and `sufficient: false`, never sample data.

## Demo (static, simulated, never persisted)

`GET /api/demo/dashboard`, `/api/demo/assessments`, `/api/demo/assessments/{demo-id}`, `/api/demo/bundle`, `/api/demo/assessments/{demo-id}/report.pdf`. Every payload has `mode: "demo"` and `simulated: true`. `503 demo_unavailable` if the bundle file is missing.

## Example

```bash
curl -s -X POST localhost:8000/api/assessments/link \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.org","authorized":true}'
# → {"id":"…","status":"queued",…}
curl -s localhost:8000/api/assessments/<id> | jq '.status,.progress'
curl -sOJ "localhost:8000/api/assessments/<id>/export?format=pdf"
```
