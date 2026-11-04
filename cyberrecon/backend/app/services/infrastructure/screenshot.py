"""Website screenshot module. A failed capture is reported as a failure; no placeholder image is ever produced."""
from __future__ import annotations

from app.integrations.screenshots import ScreenshotError, ScreenshotUnavailable
from app.security.target import TargetError
from app.services.common import ModuleOutput, RunContext, finding, source

MODULE = "screenshot"
STEPS = [
    ("validate", "Validate target and scope"),
    ("capture", "Capture screenshot in isolated browser"),
    ("finalise", "Record screenshot metadata"),
]


async def run(ctx: RunContext, params: dict) -> ModuleOutput:
    steps, prov, settings = ctx.steps, ctx.providers.screenshots, ctx.settings
    fetcher = ctx.fetcher_factory()
    try:
        async with steps.step("validate"):
            target = fetcher.parse(params["target"])
    except TargetError as exc:
        await fetcher.aclose()
        steps.skip("capture", "Invalid target")
        steps.skip("finalise", "Invalid target")
        return ModuleOutput(data={"error": {"code": exc.code, "message": exc.message}}, status="failed", errors=[{"step": "validate", "code": exc.code, "message": exc.message}])
    await fetcher.aclose()

    out_path = settings.screenshots_dir / f"{ctx.assessment_id}.png"
    try:
        async with steps.step("capture"):
            meta = await prov.capture(target.url, out_path, scope_host=target.hostname)
    except ScreenshotUnavailable as exc:
        steps.skip("finalise", "Screenshots unavailable")
        return ModuleOutput(
            data={"requested_url": target.url, "unavailable": str(exc)}, status="failed",
            errors=[{"step": "capture", "code": "screenshots_unavailable", "message": str(exc)}],
            sources=[source(prov.name, "browser", "unavailable", None, str(exc))],
            findings=[finding(MODULE, "screenshot", "Screenshot capture is not available", str(exc), source=prov.name)],
            summary={"headline": "Screenshots unavailable", "error": "screenshots_unavailable"},
        )
    except ScreenshotError as exc:
        steps.skip("finalise", "Capture failed")
        return ModuleOutput(
            data={"requested_url": target.url, "failure": {"code": exc.code, "message": exc.message}}, status="failed",
            errors=[{"step": "capture", "code": exc.code, "message": exc.message}],
            sources=[source(prov.name, "browser", "failed", target.url, exc.message)],
            findings=[finding(MODULE, "screenshot", "Screenshot could not be captured", exc.message, source=prov.name)],
            summary={"headline": "Capture failed", "error": exc.code},
        )
    async with steps.step("finalise"):
        findings = [finding(MODULE, "screenshot", f"Screenshot captured (HTTP {meta['http_status']})",
                            f"{meta['image']['width']}×{meta['image']['height']} PNG, {meta['image']['size_bytes']:,} bytes, {meta['capture_mode']}. Shows what a headless browser received at {meta['captured_at']}.",
                            source=prov.name)]
        if meta["http_status"] >= 400:
            findings.append(finding(MODULE, "screenshot", f"Server answered HTTP {meta['http_status']}", "The image shows the error or blocked page the server returned, not the intended content.", source="HTTP response"))
        if meta["blocked_requests"]:
            findings.append(finding(MODULE, "screenshot", f"{len(meta['blocked_requests'])} request(s) blocked by network policy",
                                    "; ".join(b["reason"] for b in meta["blocked_requests"][:3]), source="CyberRecon network policy"))
    data = {**meta, "file_available": True, "limitations": [
        "The capture covers the first viewport only and reflects one moment in time.",
        "Pages may render differently for bots, other regions, logged-in users or other devices.",
        "Content that is blocked, gated by CAPTCHAs/consent walls or loaded after interaction may be missing.",
    ]}
    return ModuleOutput(data=data, findings=findings, sources=[source(prov.name, "browser", "ok", meta["final_url"], f"Chromium {meta['browser']['version']}")],
                        status="completed", summary={"headline": f"HTTP {meta['http_status']} · {meta['image']['width']}×{meta['image']['height']}", "http_status": meta["http_status"]})
