# Integrations and providers

Every external data source sits behind a small interface in `backend/app/integrations/` and is bundled in `registry.Providers`. A provider that cannot work (missing key, library, network, rate limit) raises `ProviderUnavailable`; the module records a source with status `unavailable` and the reason, and the UI/report shows it. **No provider ever returns made-up data on failure.**

| Capability | Default | Alternatives | Needs | Data leaves the server? |
|---|---|---|---|---|
| DNS | `dnspython` against the system resolver | `CYBERRECON_DNS_RESOLVERS=ip,ip` | – | Queries go to the resolver |
| Registration | RDAP via IANA bootstrap (`data.iana.org`) and `rdap.org` for IPs | – | outbound HTTPS | Domain / IP sent to the RDAP server |
| ASN / network | Team Cymru IP→ASN over DNS | – | DNS | IP sent as a DNS query |
| Geolocation | **none** (reported as unavailable) | `ipapi` (ipapi.co, no key, rate-limited), `maxmind` (local `.mmdb`) | `maxminddb` + licensed DB for maxmind | `ipapi`: the IP is sent to ipapi.co. `maxmind`: local only |
| Subdomains | `crtsh` (Certificate Transparency search) | `securitytrails` (key), `none` | key for SecurityTrails | Domain sent to the provider |
| TLS | direct handshake through the guarded dialer | – | – | Connects to the target only |
| Screenshots | Playwright Chromium | – | `playwright install chromium` | Connects to the target only |

Geolocation is always labelled an **estimate**. Subdomains from a provider are **reported**; the tool resolves a bounded number of them (`CYBERRECON_SUBDOMAIN_VERIFY_LIMIT`) and marks them **verified** only if they resolved to a public address. No brute-forcing or wordlists are used.

## Configure

Set the variables in [.env.example](../.env.example). Check `GET /api/config` (or the Settings page) to see what the server considers available and why something isn't.

```bash
# MaxMind (local, no third-party calls)
pip install maxminddb            # already in requirements.txt
CYBERRECON_GEOIP_PROVIDER=maxmind
CYBERRECON_GEOIP_DB_PATH=/data/GeoLite2-City.mmdb

# SecurityTrails
CYBERRECON_SUBDOMAIN_PROVIDER=securitytrails
CYBERRECON_SECURITYTRAILS_API_KEY=…   # server-side only
```

## Adding a provider

1. Write a class with the async method(s) used by the module (see `FakeGeo`, `FakeSubs` in `backend/tests/helpers.py` for the minimal shape).
2. Raise `ProviderUnavailable("human-readable reason")` for anything that stops it working.
3. Return plain dicts; include a `reference` URL so the report can cite the source.
4. Register it in `build_default_providers` (or the relevant `build_*_provider`) behind a setting.
5. Write tests with a fake that returns success and one that raises `ProviderUnavailable`.

Providers that make HTTP calls must use the `fetcher_factory` (the guarded `SafeFetcher`), not raw `httpx`.

## Reverse image search

The image view offers links to Google Lens, TinEye, Bing and Yandex. They are plain links; **CyberRecon does not upload the image**. The user must upload it themselves on the provider's site, which the UI says before they leave.

## Not integrated (by design)

Active scanners, port scanners, credential/leak databases, people-search and face-recognition services are out of scope.
