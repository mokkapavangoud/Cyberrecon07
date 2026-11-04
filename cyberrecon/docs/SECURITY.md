# Security design and limitations

CyberRecon makes outbound requests to user-supplied targets. That is the definition of an SSRF-shaped feature, so the design goal is: *requests only go to the public internet, only for an authorised purpose, in bounded amounts, and the service cannot be turned into an open proxy.*

**Application-level validation alone does not eliminate SSRF or DNS-rebinding risk.** The controls below reduce it substantially; the deployment controls at the end are what make it robust.

## 1. Outbound request controls (application layer)

| Threat | Control | Where |
|---|---|---|
| Private / internal targets | Explicit deny-list: RFC1918, loopback, link-local (incl. 169.254.169.254, `fd00:ec2::254`, `100.100.100.200`), CGNAT, multicast, reserved, documentation, 6to4/Teredo/NAT64, ULA, IPv4-mapped IPv6 judged as IPv4. Anything not `is_global` is also blocked. | `security/ip_policy.py` |
| Hostname tricks | `parse_target` rejects userinfo (`user@host`), non-HTTP(S) schemes, IP literals in private ranges, decimal/hex/octal IP forms, reserved suffixes (`.local`, `.internal`, `.example`, `.test`, …), non-allowed ports, over-long input. IDNs are punycode-normalised. | `security/target.py` |
| DNS rebinding / TOCTOU | `GuardedNetworkBackend` resolves the name, validates **every** returned address, and connects to the *validated IP* in the same step. The connection never re-resolves. TLS SNI/Host still use the original hostname. | `security/safe_net.py` |
| Redirect to internal host | Redirects are followed manually; every hop is re-parsed and re-validated (scheme, port, resolved IPs). Limit: `max_redirects`. Cross-site hops can be refused by scope. | `SafeFetcher` |
| Resource exhaustion | Connect/read/total timeouts, response byte cap (body is streamed and truncated, flagged `truncated`), redirect cap, concurrency semaphore, link-check cap (default 25, max 100), per-IP rate limit (429 + `Retry-After`). | `core/config.py`, `jobs.py`, `core/ratelimit.py` |
| Open proxy / arbitrary fetcher | The API never returns fetched bodies. It returns structured, parsed results. Link checking is HEAD/limited GET against *discovered same-site links by default*; external checking is opt-in and capped. No recursive external crawling. | `link_analysis/` |
| Scope abuse | Optional `CYBERRECON_TARGET_ALLOWLIST` restricts assessable domains. | `security/target.py` |
| Misuse | Live assessments return 422 `authorization_required` unless `authorized: true`; confirmation + timestamp are stored and printed in the report. | `api/routes.py` |
| Robots / access controls | robots.txt is read and reported, never used to discover hidden paths, and no CAPTCHA/auth bypass exists. The tool does not send credentials. | `link_analysis/robots.py` |

### Screenshots

Chromium does its own networking, so a Python-level guard cannot protect it. The provider:

- launches an isolated, throw-away browser context with downloads, permissions, service workers and extensions disabled and a hardened argument list;
- intercepts **every** request (including redirect hops, which Playwright's `page.route` misses) through the CDP `Fetch` domain, validates scheme/port/host/resolved IPs, and answers `failRequest BlockedByClient` for anything not allowed;
- blocks main-frame navigation outside the target's registrable site, caps the number of requests (200), and fails **closed** if the guard errors;
- reports a failed screenshot as a failure. No placeholder image is ever produced.

**Residual risk:** the guard resolves and validates a hostname, then Chromium resolves it again to connect. A hostile DNS server could answer differently the second time (DNS rebinding). The guard narrows but cannot close this window. Mitigate with `CYBERRECON_SCREENSHOT_PROXY` (an egress proxy that enforces the IP policy at connect time) and/or the network controls below. If neither is possible, set `CYBERRECON_SCREENSHOT_ENABLED=false`.

## 2. Network egress restriction (required for any shared deployment)

Run the service where the *network* forbids what the code forbids:

1. Put the container/VM in a subnet whose outbound rules **deny** RFC1918, loopback, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`, and cloud metadata addresses; allow only 80/443/53 to the internet.
2. Enforce IMDSv2 (hop limit 1) or disable the metadata service for the workload. Never grant the workload cloud credentials.
3. Use a dedicated resolver (`CYBERRECON_DNS_RESOLVERS`) that cannot reach internal zones.
4. For screenshots, force Chromium through an egress proxy (`CYBERRECON_SCREENSHOT_PROXY`) that re-checks the destination IP at connect time.
5. Run as non-root, read-only filesystem apart from the data volume, no extra capabilities (the sample `docker-compose.yml` does the last three — untested here).

## 3. Application security

- **Uploads:** size cap enforced while streaming (and by Content-Length precheck), pixel cap, real format detection by decoding with Pillow (extension and client MIME are ignored), only JPEG/PNG/WebP/GIF/BMP/TIFF accepted, decompression-bomb protection. Uploaded files are processed in memory and **never written to disk**. Display names are sanitised.
- **Image privacy:** GPS coordinates are returned once in the response to the uploader and are **redacted from the stored record** unless `CYBERRECON_PERSIST_IMAGE_GPS=true`. The sanitiser strips EXIF/XMP/IPTC/comment segments (lossless for JPEG/PNG/WebP, re-encode fallback) and reports exactly what was removed and kept. No image is sent to a third party; reverse-search links just open the provider's site and the user uploads manually if they choose.
- **No identification:** the app extracts metadata only. It performs no face recognition or authenticity judgement and says so in the UI and reports.
- **XSS/injection:** React escapes by default and no `dangerouslySetInnerHTML` is used. All SQL goes through SQLAlchemy with bound parameters; history search escapes LIKE wildcards. Untrusted strings in PDFs are XML-escaped, stripped of control/bidi characters and truncated before reportlab sees them. CSV exports neutralise formula injection (`= + - @` prefixes).
- **HTTP hardening:** `/api` responses carry `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Cache-Control: no-store` on API responses, and `frame-ancestors 'none'`. CORS allows only configured origins. IDs are validated hex before any lookup; report download paths are checked to stay inside `reports_dir`.
- **Secrets:** provider keys are read from server environment only, never serialised to `/api/config` or the frontend bundle. `.env.example` has no real values.
- **Errors:** uniform `{"error": {...}}` bodies; unexpected exceptions return a generic 500 and are logged server-side.

## 4. Demo isolation

`/api/demo/*` serves a static JSON bundle that refuses to load unless marked `simulated`. It never reads or writes the database. Every payload has `mode: "demo"`; demo PDFs are watermarked; the UI shows a persistent banner; demo IDs (`demo-*`) cannot resolve to live records and live IDs cannot resolve to demo data. Demo data is built from reserved documentation domains, IPs and AS numbers.

## 5. Known limitations — please read

- **No authentication or multi-tenancy.** Anyone who can reach the API can start assessments and read all history. Bind to localhost or put it behind an authenticating reverse proxy. Do **not** expose it publicly.
- Rate limiting is per process and in memory (resets on restart; not shared across workers; trusts the direct client IP, so behind a proxy you need to handle forwarded headers deliberately).
- Chromium DNS gap (above).
- The IP deny-list is maintained by hand; new special-use ranges would need adding. The `is_global` fallback covers most.
- Geolocation and technology fingerprints are estimates. RDAP/crt.sh/ASN data is third-party and may be incomplete or wrong; reports label it that way.
- TLS probing validates against the system trust store; corporate MITM roots would change results.
- SQLite is fine for a single user; use Postgres and a real job queue for concurrency at scale.
- This project has had no independent security audit or penetration test.

## 6. Reporting a problem

If you find a bypass of the target guard, open a private issue with a reproduction against a **local fixture**, not a third party's systems.
