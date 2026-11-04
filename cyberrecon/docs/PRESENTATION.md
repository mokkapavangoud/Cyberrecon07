# Presentation and demo guide

Works with no internet and no API keys.

## Setup (2 minutes)

```bash
scripts/dev.sh build && scripts/dev.sh serve        # http://127.0.0.1:8000
```
Open `/present` for the built-in slide walkthrough (arrow keys / on-screen buttons), or click **Explore Demo** on the landing page to go straight to the workspace in demo mode. Every demo screen carries a *DEMO DATA* banner and the PDFs are watermarked *SIMULATED DEMO*.

## Suggested 8-minute flow

1. **Problem (1 min)** — slide *The problem*: organisations don't know what strangers can see from their domain, site and photos; tools blur what was observed vs guessed.
2. **How it works (1 min)** — *Confirm → Collect → Explain*. Point out the authorisation checkbox.
3. **Demo workspace (3 min)** — *Live walkthrough* slide → opens demo mode.
   - Dashboard: totals, severity, module usage (all from the fictional bundle).
   - **Infrastructure** → Aurora Labs: open the graph, click a node, show the *observed / third-party / estimate* tags and the *Sources* tab (including a lookup that failed and is shown as failed).
   - **Image** → metadata with GPS labelled, "missing" fields labelled missing, reverse-search links that don't upload.
   - **Website** → links table: search, sort, filter, export CSV.
4. **Sample report (1 min)** — *Sample report* slide: download the PDF; show authorisation, scope, methods, limitations.
5. **Architecture & security (1 min)** — resolve-validate-connect in one step, per-hop redirect checks, egress controls, honest limits.
6. **Ethics and next steps (1 min)** — no exploitation or bypass; what comes next.

## Optional live moment (needs network on the demo machine)

Turn demo mode **off** (top bar), enter a domain **you own**, tick the authorisation box, run the website assessment and watch the step list advance — it is real job progress. Then show a refusal: enter `http://127.0.0.1` or `http://169.254.169.254` and show the validation error. Do not run it against anyone else's domain.

## Talking points to be straight about

- Demo data is simulated and says so everywhere; the dashboard in live mode is empty until real assessments exist.
- Geolocation and technology fingerprints are estimates.
- App-level SSRF checks are one layer; deployment needs egress restriction ([SECURITY.md](SECURITY.md)).
- Prototype: no authentication, single tenant, not independently audited.
