"""Website screenshots with an isolated, headless Chromium (Playwright).

Isolation measures: fresh incognito context per capture, no persistent profile, downloads/permissions/service
workers/WebSockets disabled, and EVERY request the page makes (including sub-resources) is intercepted and run
through the same target + address policy as the rest of CyberRecon.

Known limitation (documented in docs/SECURITY.md): Chromium performs its own DNS resolution after our check, so
a hostile DNS server could still rebind between the interception check and the browser's connection. For
production use, run the browser in a container whose egress is restricted by a firewall or a controlled egress
proxy (``CYBERRECON_SCREENSHOT_PROXY``).
"""
from __future__ import annotations

import asyncio
import glob
import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from app.security.ip_policy import IPPolicy
from app.security.safe_net import BlockedTargetError, ResolutionError, resolve_public, system_resolver
from app.security.target import TargetError, parse_target, same_site

MAX_REQUESTS = 200
VIEWPORT = {"width": 1366, "height": 768}
CHROME_ARGS = [
    "--disable-dev-shm-usage", "--disable-gpu", "--no-first-run", "--disable-extensions", "--disable-background-networking",
    "--disable-sync", "--disable-default-apps", "--mute-audio", "--deny-permission-prompts", "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication",
    "--disable-component-update", "--disable-domain-reliability", "--disable-breakpad", "--no-pings", "--metrics-recording-only", "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update",
]


class ScreenshotError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ScreenshotUnavailable(Exception):
    pass


def find_chromium(configured: str | None = None) -> str | None:
    if configured and os.path.exists(configured):
        return configured
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), str(Path.home() / ".cache" / "ms-playwright"), "/opt/pw-browsers"]
    patterns = ["chromium-*/chrome-linux*/chrome", "chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell",
                "chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium", "chromium-*/chrome-win*/chrome.exe"]
    for root in filter(None, roots):
        for pat in patterns:
            hits = sorted(glob.glob(os.path.join(root, pat)))
            if hits:
                return hits[-1]
    return None


class PlaywrightScreenshotProvider:
    name = "Playwright / Chromium"

    def __init__(self, settings, *, resolver=None, policy: IPPolicy | None = None):
        self.settings = settings
        self.resolver = resolver or system_resolver
        self.policy = policy or IPPolicy()

    def availability(self) -> dict:
        if not self.settings.screenshot_enabled:
            return {"available": False, "reason": "Screenshots are disabled by configuration (CYBERRECON_SCREENSHOT_ENABLED=false)."}
        try:
            import playwright  # noqa: F401
        except ImportError:
            return {"available": False, "reason": "The 'playwright' Python package is not installed (pip install playwright)."}
        path = find_chromium(getattr(self.settings, "chromium_path", None))
        if not path:
            return {"available": False, "reason": "No Chromium executable was found. Run 'playwright install chromium' or set CYBERRECON_CHROMIUM_PATH."}
        return {"available": True, "reason": None, "browser_path": path}

    async def capture(self, url: str, out_path: Path, *, scope_host: str) -> dict:
        avail = self.availability()
        if not avail["available"]:
            raise ScreenshotUnavailable(avail["reason"])
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright

        started = time.perf_counter()
        blocked: list[dict] = []
        seen_hosts: dict[str, str | None] = {}
        counter = {"n": 0}
        timeout = self.settings.screenshot_timeout_ms

        async with async_playwright() as p:
            launch_kwargs = {"executable_path": avail["browser_path"], "headless": True, "args": CHROME_ARGS}
            if self.settings.screenshot_proxy:
                launch_kwargs["proxy"] = {"server": self.settings.screenshot_proxy}
            try:
                browser = await p.chromium.launch(**launch_kwargs)
            except PlaywrightError as exc:
                raise ScreenshotUnavailable(f"Chromium could not be started: {str(exc).splitlines()[0][:160]}")
            try:
                context = await browser.new_context(
                    viewport=VIEWPORT, accept_downloads=False, service_workers="block", permissions=[], java_script_enabled=True,
                    ignore_https_errors=False, user_agent=self.settings.user_agent + " Chromium", locale="en-US",
                )
                page = await context.new_page()

                async def decide(u: str, is_main_navigation: bool) -> str | None:
                    """Returns a reason string when the request must be blocked."""
                    counter["n"] += 1
                    try:
                        if counter["n"] > MAX_REQUESTS:
                            raise TargetError("request_limit", f"More than {MAX_REQUESTS} requests; remaining requests were blocked.")
                        t = parse_target(u, allowed_ports=self.settings.allowed_ports, policy=self.policy)
                        if t.hostname not in seen_hosts:
                            try:
                                await resolve_public(t.hostname, t.port, self.resolver, self.policy)
                                seen_hosts[t.hostname] = None
                            except (BlockedTargetError, ResolutionError) as exc:
                                seen_hosts[t.hostname] = str(exc)
                        if seen_hosts[t.hostname]:
                            raise TargetError("blocked_address", seen_hosts[t.hostname])
                        if is_main_navigation and not same_site(scope_host, t.hostname):
                            raise TargetError("out_of_scope", f"Navigation to out-of-scope host {t.hostname} was blocked.")
                    except TargetError as exc:
                        return exc.message[:200]
                    return None

                # Requests are intercepted with the DevTools Fetch domain rather than Playwright's page.route(): Playwright's
                # route handler is NOT invoked for redirect hops, so a 302 to http://169.254.169.254/ would have been followed
                # by the browser unchecked. CDP re-pauses every redirected request, so each hop is validated.
                cdp = await context.new_cdp_session(page)
                main_frame_id = (await cdp.send("Page.getFrameTree"))["frameTree"]["frame"]["id"]

                async def on_paused(ev: dict) -> None:
                    rid, u = ev["requestId"], ev["request"]["url"]
                    try:
                        if u.startswith(("data:", "blob:", "about:")):
                            return await cdp.send("Fetch.continueRequest", {"requestId": rid})
                        is_nav = ev.get("resourceType") == "Document" and ev.get("frameId") == main_frame_id
                        reason = await decide(u, is_nav)
                        if reason:
                            blocked.append({"url": u[:200], "reason": reason})
                            return await cdp.send("Fetch.failRequest", {"requestId": rid, "errorReason": "BlockedByClient"})
                        await cdp.send("Fetch.continueRequest", {"requestId": rid})
                    except Exception:  # fail closed: if the guard itself errors, the request does not go out
                        try:
                            blocked.append({"url": u[:200], "reason": "Blocked: the request could not be validated."})
                            await cdp.send("Fetch.failRequest", {"requestId": rid, "errorReason": "BlockedByClient"})
                        except Exception:
                            pass

                cdp.on("Fetch.requestPaused", lambda ev: asyncio.ensure_future(on_paused(ev)))
                await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
                try:
                    await context.route_web_socket("**/*", lambda ws: asyncio.ensure_future(ws.close()))
                except Exception:  # older Playwright
                    pass

                try:
                    resp = await asyncio.wait_for(page.goto(url, wait_until="load", timeout=timeout), timeout=timeout / 1000 + 10)
                except asyncio.TimeoutError:
                    raise ScreenshotError("timeout", "The page did not finish loading in time.")
                except PlaywrightError as exc:
                    msg = str(exc).splitlines()[0]
                    if "ERR_NAME_NOT_RESOLVED" in msg:
                        raise ScreenshotError("dns_failure", "The hostname could not be resolved.")
                    if "blockedbyclient" in msg.lower() or "ERR_BLOCKED_BY_CLIENT" in msg:
                        raise ScreenshotError("blocked_target", (blocked[0]["reason"] if blocked else "The request was blocked by CyberRecon's network policy."))
                    if "CERT" in msg or "SSL" in msg:
                        raise ScreenshotError("tls_error", "A TLS/certificate error prevented the page from loading.")
                    if "Timeout" in msg:
                        raise ScreenshotError("timeout", "The page did not finish loading in time.")
                    raise ScreenshotError("navigation_failed", f"The page could not be loaded: {msg[:160]}")
                if resp is None:
                    raise ScreenshotError("navigation_failed", "The browser did not receive a response.")
                await page.wait_for_timeout(600)  # let late paints settle
                title = (await page.title())[:300]
                png = await page.screenshot(type="png", full_page=False, timeout=timeout)
                final_url = page.url
                version = browser.version
            finally:
                await browser.close()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(png)
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(png))
        return {
            "requested_url": url, "final_url": final_url, "http_status": resp.status, "title": title,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "viewport": VIEWPORT, "capture_mode": "viewport only (above the fold)",
            "image": {"format": "PNG", "width": im.width, "height": im.height, "size_bytes": len(png), "sha256": hashlib.sha256(png).hexdigest()},
            "browser": {"name": "Chromium", "version": version}, "requests_total": counter["n"], "blocked_requests": blocked[:50],
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
