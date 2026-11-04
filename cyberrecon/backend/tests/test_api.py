import io
import json

import httpx
import pytest
from PIL import Image

from app.services.image_intelligence.inspector import inspect_image

from .test_image_intelligence import make_jpeg


def site(server):
    return f"http://site.example.org:{server.port}/"


async def finish(app, aid):
    await app.state.cr.runner.wait(aid)


async def start(client, app, module, body):
    r = await client.post(f"/api/assessments/{module}", json=body)
    assert r.status_code == 202, r.text
    aid = r.json()["id"]
    await finish(app, aid)
    return aid


# ------------------------------------------------------------------ meta / hardening
async def test_health_and_config_do_not_leak_secrets(make_app):
    app = make_app(securitytrails_api_key="SECRET-KEY-123", subdomain_provider="securitytrails")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = (await c.get("/api/health")).json()
        assert h["status"] == "ok" and h["database"] == "ok"
        cfg = await c.get("/api/config")
        assert "SECRET-KEY-123" not in cfg.text
        body = cfg.json()
        assert body["capabilities"]["subdomains"]["available"] is True
        assert body["capabilities"]["screenshots"]["available"] is False and body["capabilities"]["screenshots"]["reason"]
        assert body["privacy"]["uploaded_images_stored"] is False


async def test_security_headers_and_cors(client):
    r = await client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    evil = await client.get("/api/health", headers={"Origin": "https://evil.example.net"})
    assert "access-control-allow-origin" not in evil.headers


async def test_consistent_error_shape(client):
    for path, status in (("/api/nope", 404), ("/api/assessments/not-an-id", 404), ("/api/assessments/" + "0" * 32, 404), ("/api/reports/zzz/download", 404)):
        r = await client.get(path)
        assert r.status_code == status and r.json()["error"]["code"] == "not_found"
    r = await client.put("/api/health")
    assert r.status_code == 405 and "error" in r.json()


# ------------------------------------------------------------------ validation + authorisation
async def test_authorisation_is_mandatory(client):
    r = await client.post("/api/assessments/link", json={"target": "https://site.example.org/"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "authorization_required"
    r = await client.post("/api/assessments/link", json={"target": "https://site.example.org/", "authorized": False})
    assert r.json()["error"]["code"] == "authorization_required"
    assert (await client.get("/api/assessments")).json()["total"] == 0  # nothing was created


@pytest.mark.parametrize("target,code", [
    ("http://127.0.0.1/", None), ("http://localhost/", None), ("http://169.254.169.254/latest/meta-data/", None), ("http://2130706433/", None),
    ("ftp://site.example.org/", None), ("http://user:pw@site.example.org/", None), ("http://site.example.org:22/", None), ("file:///etc/passwd", None),
    ("http://[::1]/", None), ("http://10.0.0.5/", None), ("", None),
])
async def test_dangerous_targets_rejected_before_any_job_exists(client, target, code):
    r = await client.post("/api/assessments/link", json={"target": target or " ", "authorized": True})
    assert r.status_code == 422, (target, r.text)
    assert r.json()["error"]["code"]
    r2 = await client.post("/api/assessments/infrastructure", json={"target": target or " ", "authorized": True})
    assert r2.status_code == 422
    assert (await client.get("/api/assessments")).json()["total"] == 0


async def test_unknown_fields_and_bad_options_rejected(client):
    r = await client.post("/api/assessments/link", json={"target": "site.example.org", "authorized": True, "options": {"max_links_to_check": 5000}})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"
    r = await client.post("/api/assessments/link", json={"target": "site.example.org", "authorized": True, "evil": 1})
    assert r.status_code == 422
    r = await client.post("/api/assessments/bogus", json={"target": "site.example.org", "authorized": True})
    assert r.status_code == 422


async def test_screenshot_unavailable_is_an_explicit_error(client):
    r = await client.post("/api/assessments/screenshot", json={"target": "site.example.org", "authorized": True})
    assert r.status_code == 503 and r.json()["error"]["code"] == "screenshots_unavailable"


async def test_rate_limit(make_app):
    app = make_app(rate_limit_per_minute=3)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        codes = [(await c.post("/api/assessments/link", json={"target": "x", "authorized": False})).status_code for _ in range(5)]
        assert codes[:3] == [422] * 3 and codes[3:] == [429, 429]
        r = await c.post("/api/assessments/link", json={"target": "x", "authorized": False})
        assert r.headers["retry-after"].isdigit() and r.json()["error"]["code"] == "rate_limited"
        assert (await c.get("/api/health")).status_code == 200  # read-only endpoints are not limited


# ------------------------------------------------------------------ full website flow
async def test_link_flow_progress_history_exports_delete(client, app, server, settings):
    aid = await start(client, app, "link", {"target": site(server), "authorized": True, "options": {"check_links": True, "max_links_to_check": 10}})
    d = (await client.get(f"/api/assessments/{aid}")).json()
    assert d["status"] in ("completed", "partial") and d["result"]["http"]["status"] == 200
    assert d["progress"]["percent"] == 100 and all(s["status"] in ("done", "skipped", "failed") for s in d["steps"])
    assert d["authorization"]["confirmed"] is True and d["authorization"]["confirmed_at"]
    assert "links" in d["available_exports"] and "findings" in d["available_exports"]
    ls = d["result"]["link_summary"]
    assert ls["checked"] > 0 and ls["discovered"] > ls["checked"]  # discovered vs checked stays distinct

    lst = (await client.get("/api/assessments", params={"module": "link", "q": "SITE.EXAMPLE"})).json()
    assert lst["total"] == 1 and lst["items"][0]["id"] == aid and "result" not in lst["items"][0]
    assert (await client.get("/api/assessments", params={"module": "image"})).json()["total"] == 0
    assert (await client.get("/api/assessments", params={"q": "%"})).json()["total"] == 0  # LIKE wildcards are literal
    assert (await client.get("/api/assessments", params={"module": "evil"})).status_code == 422

    csvr = await client.get(f"/api/assessments/{aid}/export", params={"format": "csv", "table": "links"})
    assert csvr.status_code == 200 and csvr.headers["content-type"].startswith("text/csv") and "attachment" in csvr.headers["content-disposition"]
    assert csvr.content.startswith(b"\xef\xbb\xbf")
    js = await client.get(f"/api/assessments/{aid}/export", params={"format": "json"})
    assert js.json()["assessment"]["id"] == aid
    pdf = await client.get(f"/api/assessments/{aid}/export", params={"format": "pdf"})
    assert pdf.content.startswith(b"%PDF")
    bad = await client.get(f"/api/assessments/{aid}/export", params={"format": "csv", "table": "nope"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "unknown_table"
    assert (await client.get(f"/api/assessments/{aid}/export", params={"format": "xml"})).status_code == 422

    rep = await client.post(f"/api/assessments/{aid}/reports", json={"format": "pdf"})
    assert rep.status_code == 201
    dl = await client.get(rep.json()["download_url"])
    assert dl.content.startswith(b"%PDF") and dl.headers["x-content-type-options"] == "nosniff"
    assert (await client.get("/api/reports")).json()["items"]
    dash = (await client.get("/api/dashboard")).json()
    assert dash["totals"]["assessments"] == 1 and dash["totals"]["reports"] >= 1 and dash["module_usage"]["link"] == 1 and dash["trend"]["sufficient"] is False

    files = list(settings.reports_dir.glob("*"))
    assert files
    assert (await client.delete(f"/api/assessments/{aid}")).status_code == 204
    assert (await client.get(f"/api/assessments/{aid}")).status_code == 404
    assert (await client.delete(f"/api/assessments/{aid}")).status_code == 404
    assert not list(settings.reports_dir.glob("*"))  # files removed with the assessment
    assert (await client.get("/api/reports")).json()["items"] == []


async def test_unreachable_target_is_persisted_as_failed_with_explanation(client, app):
    aid = await start(client, app, "link", {"target": "http://unknown-host.example.org/", "authorized": True})
    d = (await client.get(f"/api/assessments/{aid}")).json()
    assert d["status"] == "failed" and d["errors"] and d["result"]["fetch_error"]["message"]
    # a report of a failed assessment is still available and honest
    assert (await client.get(f"/api/assessments/{aid}/export", params={"format": "pdf"})).status_code == 200


async def test_infrastructure_flow(client, app):
    aid = await start(client, app, "infrastructure", {"target": "https://www.example-corp.org/some/path", "authorized": True, "options": {"include_http": False}})
    d = (await client.get(f"/api/assessments/{aid}")).json()
    assert d["result"]["hostname"] == "www.example-corp.org" and d["result"]["graph"]["edges"]
    assert {"dns_records", "ip_addresses", "subdomains"} <= set(d["available_exports"])
    assert any(s["status"] == "unavailable" for s in d["sources"])  # GeoIP not configured -> reported, not hidden


async def test_delete_all_requires_confirmation(client, app, server):
    await start(client, app, "link", {"target": site(server), "authorized": True})
    r = await client.delete("/api/assessments")
    assert r.status_code == 400 and r.json()["error"]["code"] == "confirmation_required"
    assert (await client.get("/api/assessments")).json()["total"] == 1
    assert (await client.delete("/api/assessments", params={"confirm": "true"})).json()["deleted"] == 1
    assert (await client.get("/api/assessments")).json()["total"] == 0


async def test_report_for_unfinished_assessment_is_refused(client, app):
    st = app.state.cr
    from app.services.link_analysis import analyzer
    aid = st.runner.create(module="link", target="x", label="x", steps_def=analyzer.STEPS, authorized=True)
    r = await client.post(f"/api/assessments/{aid}/reports", json={"format": "json"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_ready"
    d = (await client.get(f"/api/assessments/{aid}")).json()
    assert d["status"] == "queued" and d["progress"]["percent"] == 0 and d["available_exports"] == []


# ------------------------------------------------------------------ images
def upload(data, name="photo.jpg", ctype="image/jpeg"):
    return {"file": (name, data, ctype)}


async def test_image_analyze_privacy_defaults(client, settings):
    r = await client.post("/api/images/analyze", files=upload(make_jpeg()))
    assert r.status_code == 200, r.text
    body = r.json()
    live, stored = body["live_result"], body["assessment"]["result"]
    assert live["metadata"]["gps"]["latitude"] and not stored["metadata"]["gps"].get("latitude")  # coordinates only in the one-time response
    assert stored["metadata"]["gps"]["present"] and stored["metadata"]["gps"]["redacted"] is True
    assert "12.58" not in json.dumps(body["assessment"])
    assert body["assessment"]["authorization"]["confirmed"] is False  # local analysis needs no target authorisation
    assert not any(p.suffix in (".jpg", ".jpeg") for p in settings.data_dir.rglob("*"))  # the upload is never written to disk
    assert any(link["name"] for link in stored["reverse_search"])


@pytest.mark.parametrize("payload,name,code", [
    (b"", "e.jpg", "empty_file"), (b"<svg onload=alert(1)>", "x.svg", None), (b"not an image", "a.png", None), (b"MZ\x90\x00" + b"\x00" * 200, "evil.jpg", None),
])
async def test_image_rejections(client, payload, name, code):
    r = await client.post("/api/images/analyze", files=upload(payload, name))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == (code or r.json()["error"]["code"])
    if code is None:
        assert r.json()["assessment"]["status"] == "failed"


async def test_upload_size_limit(make_app):
    app = make_app(max_upload_bytes=50_000)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/images/analyze", files=upload(b"\xff\xd8" + b"0" * 200_000))
        assert r.status_code == 413 and r.json()["error"]["code"] == "file_too_large"
        r = await c.post("/api/images/sanitize", files=upload(b"\xff\xd8" + b"0" * 200_000))
        assert r.status_code == 413
        assert (await c.get("/api/assessments")).json()["total"] == 0


async def test_image_sanitize_endpoint_returns_clean_copy(client):
    original = make_jpeg()
    r = await client.post("/api/images/sanitize", files=upload(original, "../../etc/My Photo.jpg"))
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
    cd = r.headers["content-disposition"]
    assert "attachment" in cd and ".." not in cd and "/" not in cd
    info = json.loads(r.headers["x-cyberrecon-sanitize"])
    assert info["bytes_after"] == len(r.content) < len(original) and info["removed"]
    after = inspect_image(r.content, "x.jpg", max_bytes=5_000_000, max_pixels=20_000_000)
    assert not after["metadata"]["gps"]["present"] and not after["metadata"]["exif"].get("serial_number")
    assert Image.open(io.BytesIO(r.content)).size == Image.open(io.BytesIO(original)).size
    bad = await client.post("/api/images/sanitize", files=upload(b"nope", "a.jpg"))
    assert bad.status_code == 422
    assert (await client.get("/api/assessments")).json()["total"] == 0  # sanitising stores nothing


# ------------------------------------------------------------------ demo mode isolation
async def test_demo_mode_is_isolated_and_labelled(client, app):
    d = (await client.get("/api/demo/dashboard")).json()
    assert d["simulated"] and d["mode"] == "demo" and d["totals"]["assessments"] == 3 and "SIMULATED" in d["notice"]
    lst = (await client.get("/api/demo/assessments")).json()
    assert lst["simulated"] and all(i["mode"] == "demo" and i["simulated"] for i in lst["items"])
    bundle = (await client.get("/api/demo/bundle")).json()
    assert all(a["mode"] == "demo" and a["simulated"] for a in bundle["assessments"])
    pdf = await client.get("/api/demo/assessments/demo-infrastructure-aurora/report.pdf")
    assert pdf.content.startswith(b"%PDF")
    from pypdf import PdfReader
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "SIMULATED" in text
    # live side stays untouched and cannot see demo records
    assert (await client.get("/api/assessments")).json()["total"] == 0
    assert (await client.get("/api/dashboard")).json()["totals"]["assessments"] == 0
    assert (await client.get("/api/assessments/demo-link-aurora")).status_code == 404
    assert (await client.get("/api/demo/assessments/..%2f..%2fetc")).status_code == 404
    assert (await client.get("/api/demo/assessments/demo-link-aurora")).json()["id"] == "demo-link-aurora"
    assert (await client.get("/api/reports")).json()["items"] == []


async def test_demo_dataset_uses_only_reserved_identifiers():
    import ipaddress
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "demo" / "aurora-demo.json").read_text()
    for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
        assert ipaddress.ip_address(ip) in ipaddress.ip_network("203.0.113.0/24") or ipaddress.ip_address(ip) in ipaddress.ip_network("198.51.100.0/24"), ip
    for a in (m for m in re.findall(r"\bAS(\d+)\b", text)):
        assert 64496 <= int(a) <= 64511, a
    assert "fake-" not in text.lower() and "10.255.255.1" not in text  # no test-double labels leak into the demo


async def test_empty_dashboard(client):
    d = (await client.get("/api/dashboard")).json()
    assert d["totals"]["assessments"] == 0 and d["recent"] == [] and d["trend"] == {**d["trend"], "sufficient": False, "days": []}
    assert d["mode"] == "live" and d["simulated"] is False
