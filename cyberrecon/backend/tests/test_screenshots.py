"""Screenshot provider against the LOCAL fixture server using real headless Chromium. Skipped (and reported as skipped) if Chromium is absent."""
import io

import pytest
from PIL import Image

from app.integrations.screenshots import PlaywrightScreenshotProvider, ScreenshotError, ScreenshotUnavailable, find_chromium

from .helpers import DEFAULT_MAP, fake_resolver

needs_chromium = pytest.mark.skipif(find_chromium() is None, reason="Chromium is not installed (playwright install chromium)")


def provider(settings, loopback_policy, **over):
    s = settings.model_copy(update={"screenshot_enabled": True, "screenshot_timeout_ms": 15000, **over})
    return PlaywrightScreenshotProvider(s, resolver=fake_resolver(DEFAULT_MAP), policy=loopback_policy)


@needs_chromium
async def test_captures_real_png_with_metadata(settings, loopback_policy, server, tmp_path):
    p = provider(settings, loopback_policy)
    out = tmp_path / "shot.png"
    meta = await p.capture(f"http://127.0.0.1:{server.port}/", out, scope_host="127.0.0.1")
    im = Image.open(out)
    assert im.format == "PNG" and im.size == (1366, 768)
    assert len({im.getpixel((x, y)) for x in range(0, 1366, 97) for y in range(0, 768, 89)}) >= 1  # decodes to real pixels
    assert meta["http_status"] == 200 and meta["image"]["size_bytes"] == out.stat().st_size and meta["browser"]["version"]
    assert meta["capture_mode"].startswith("viewport")
    assert "Fixture" in meta["title"]


@needs_chromium
async def test_subresources_to_private_addresses_are_blocked_and_reported(settings, loopback_policy, server, tmp_path):
    p = provider(settings, loopback_policy)
    meta = await p.capture(f"http://127.0.0.1:{server.port}/page-with-assets", tmp_path / "a.png", scope_host="127.0.0.1")
    reasons = " ".join(b["reason"] for b in meta["blocked_requests"])
    urls = " ".join(b["url"] for b in meta["blocked_requests"])
    assert "169.254.169.254" in urls and "internal-host.example.org" in urls
    assert "non-public" in reasons.lower() or "blocked" in reasons.lower()
    hit_paths = [path for _m, path, _h in server.requests]
    assert "/pixel.png" not in hit_paths  # the internal-host request never reached the network
    assert "/ok.png" in hit_paths  # allowed sub-resources still load


@needs_chromium
async def test_redirect_hops_of_subresources_are_validated_too(settings, loopback_policy, server, tmp_path):
    """Regression: Playwright's page.route() is not invoked for redirect hops, which let the browser follow a 302 to the metadata IP."""
    p = provider(settings, loopback_policy)
    meta = await p.capture(f"http://127.0.0.1:{server.port}/page-with-redirecting-asset", tmp_path / "r.png", scope_host="127.0.0.1")
    assert any("169.254.169.254" in b["url"] and "metadata" in b["reason"] for b in meta["blocked_requests"]), meta["blocked_requests"]
    assert meta["requests_total"] >= 3  # page, the asset, and the redirect hop were each inspected


@needs_chromium
async def test_navigation_redirect_to_private_target_fails_as_failure_not_image(settings, loopback_policy, server, tmp_path):
    p = provider(settings, loopback_policy)
    out = tmp_path / "b.png"
    with pytest.raises(ScreenshotError) as e:
        await p.capture(f"http://127.0.0.1:{server.port}/redirect-private", out, scope_host="127.0.0.1")
    assert e.value.code in ("blocked_target", "navigation_failed")
    assert not out.exists()  # no placeholder image is ever created


@needs_chromium
async def test_offsite_navigation_is_out_of_scope(settings, loopback_policy, server, tmp_path):
    p = provider(settings, loopback_policy)
    with pytest.raises(ScreenshotError):
        await p.capture(f"http://127.0.0.1:{server.port}/redirect-offsite", tmp_path / "c.png", scope_host="127.0.0.1")
    assert not (tmp_path / "c.png").exists()


@needs_chromium
async def test_unresolvable_host_reports_blocked_not_success(settings, loopback_policy, tmp_path):
    p = provider(settings, loopback_policy)
    with pytest.raises(ScreenshotError):
        await p.capture("http://does-not-exist.example.org:8080/", tmp_path / "d.png", scope_host="does-not-exist.example.org")
    assert not (tmp_path / "d.png").exists()


async def test_unavailable_states_are_explicit(settings, loopback_policy, tmp_path):
    p = provider(settings, loopback_policy, screenshot_enabled=False)
    assert p.availability()["available"] is False and "disabled" in p.availability()["reason"]
    with pytest.raises(ScreenshotUnavailable):
        await p.capture("http://site.example.org/", tmp_path / "e.png", scope_host="site.example.org")
    p2 = provider(settings, loopback_policy, chromium_path="/nonexistent/chrome")
    # falls back to discovery; when nothing is found the reason says how to fix it
    if find_chromium("/nonexistent/chrome") is None:
        assert "Chromium" in p2.availability()["reason"]


@needs_chromium
async def test_screenshot_api_flow_end_to_end(make_app, settings, loopback_policy, server):
    import httpx
    from .helpers import make_providers
    shots = provider(settings, loopback_policy)
    app = make_app(providers=make_providers(screenshots=shots), loopback=True, screenshot_enabled=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/config")).json()["capabilities"]["screenshots"]["available"] is True
        r = await c.post("/api/assessments/screenshot", json={"target": f"http://127.0.0.1:{server.port}/", "authorized": True})
        assert r.status_code == 202
        aid = r.json()["id"]
        await app.state.cr.runner.wait(aid)
        d = (await c.get(f"/api/assessments/{aid}")).json()
        assert d["status"] == "completed" and d["result"]["image"]["width"] == 1366 and d["result"]["file_available"]
        img = await c.get(f"/api/assessments/{aid}/screenshot")
        assert img.status_code == 200 and img.headers["content-type"] == "image/png" and img.content[:4] == b"\x89PNG"
        assert Image.open(io.BytesIO(img.content)).size == (1366, 768)
        pdf = await c.get(f"/api/assessments/{aid}/export", params={"format": "pdf"})
        assert pdf.content.startswith(b"%PDF")
        failed = await c.post("/api/assessments/screenshot", json={"target": f"http://127.0.0.1:{server.port}/redirect-private", "authorized": True})
        fid = failed.json()["id"]
        await app.state.cr.runner.wait(fid)
        fd = (await c.get(f"/api/assessments/{fid}")).json()
        assert fd["status"] == "failed" and fd["result"]["failure"]["code"] in ("blocked_target", "navigation_failed")
        assert (await c.get(f"/api/assessments/{fid}/screenshot")).status_code == 404  # no fake image for a failed capture
        assert (await c.delete(f"/api/assessments/{aid}")).status_code == 204
        assert not (settings.screenshots_dir / f"{aid}.png").exists()
