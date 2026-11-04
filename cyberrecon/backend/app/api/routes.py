from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.database.migrations import database_ok
from app.security.target import TargetError, parse_target
from app.services import dashboard as dashboard_svc
from app.services import history
from app.services.demo import DemoUnavailable
from app.services.image_intelligence import analyzer as image_analyzer
from app.services.image_intelligence.inspector import ImageValidationError, safe_display_name
from app.services.image_intelligence.sanitizer import sanitize_image
from app.services.infrastructure import analyzer as infra_analyzer
from app.services.infrastructure import screenshot as screenshot_module
from app.services.link_analysis import analyzer as link_analyzer
from app.services.reporting.exports import available_tables
from app.services.reporting.store import ReportError

from .errors import ApiError
from .state import AppState

router = APIRouter(prefix="/api")
HEX = re.compile(r"^[0-9a-f]{32}$")
DEMO_ID = re.compile(r"^demo-[a-z]+-[a-z]+$")
MEDIA = {"pdf": "application/pdf", "json": "application/json", "csv": "text/csv; charset=utf-8"}


def state(request: Request) -> AppState:
    return request.app.state.cr


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def rate_limited(request: Request, st: AppState = Depends(state)) -> None:
    ok, retry = st.limiter.check(client_key(request))
    if not ok:
        raise ApiError(429, "rate_limited", f"Too many requests. Try again in {retry} seconds.", headers={"Retry-After": str(retry)}, retry_after=retry)


def require_id(assessment_id: str) -> str:
    if not HEX.match(assessment_id):
        raise ApiError(404, "not_found", "Assessment not found.")
    return assessment_id


# ------------------------------------------------------------------------------------------------ models
class Options(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_links: bool = False
    check_external: bool = False
    max_links_to_check: int = Field(25, ge=1, le=100)
    include_http: bool = True


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(..., min_length=1, max_length=2048)
    authorized: bool = False
    options: Options = Options()


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["pdf", "json", "csv"] = "pdf"
    table: str | None = Field(None, max_length=40)


MODULES = {
    "link": (link_analyzer.run, link_analyzer.STEPS),
    "infrastructure": (infra_analyzer.run, infra_analyzer.STEPS),
    "screenshot": (screenshot_module.run, screenshot_module.STEPS),
}


# ------------------------------------------------------------------------------------------------ meta
@router.get("/health")
def health(st: AppState = Depends(state)):
    db_ok = database_ok(st.db)
    body = {"status": "ok" if db_ok else "degraded", "version": st.settings.version, "database": "ok" if db_ok else "unavailable",
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return JSONResponse(body, status_code=200 if db_ok else 503)


@router.get("/config")
def config(st: AppState = Depends(state)):
    s = st.settings
    shots = st.providers.screenshots.availability() if getattr(st.providers, "screenshots", None) else {"available": False, "reason": "No screenshot provider is configured."}
    sub = {"provider": s.subdomain_provider, "available": s.subdomain_provider == "crtsh" or (s.subdomain_provider == "securitytrails" and bool(s.securitytrails_api_key))}
    if s.subdomain_provider == "securitytrails" and not s.securitytrails_api_key:
        sub["reason"] = "SecurityTrails is selected but no API key is configured on the server."
    if s.subdomain_provider == "none":
        sub["reason"] = "Passive subdomain discovery is disabled."
    geo = {"provider": s.geoip_provider, "available": s.geoip_provider != "none"}
    if not geo["available"]:
        geo["reason"] = "No GeoIP provider is configured. IP geolocation will be shown as unavailable."
    return {
        "app": s.app_name, "version": s.version, "environment": s.environment,
        "capabilities": {"screenshots": {"available": shots["available"], "reason": shots.get("reason")}, "subdomains": sub, "geoip": geo, "pdf_reports": True},
        "limits": {"max_upload_bytes": s.max_upload_bytes, "max_image_pixels": s.max_image_pixels, "link_check_max_limit": s.link_check_max_limit,
                   "allowed_ports": s.allowed_ports, "max_redirects": s.max_redirects, "max_response_bytes": s.max_response_bytes, "rate_limit_per_minute": s.rate_limit_per_minute},
        "privacy": {"image_gps_persisted": s.persist_image_gps, "uploaded_images_stored": False},
        "target_allowlist_active": bool(s.target_allowlist),
    }


# ------------------------------------------------------------------------------------------------ assessments
def _validate(st: AppState, raw: str):
    try:
        return parse_target(raw, allowed_ports=st.settings.allowed_ports, allowlist=st.settings.target_allowlist, policy=st.policy)
    except TargetError as exc:
        raise ApiError(422, exc.code, exc.message, field="target")


@router.post("/assessments/{module}", status_code=202, dependencies=[Depends(rate_limited)])
async def create_assessment(module: Literal["link", "infrastructure", "screenshot"], body: AssessmentRequest, st: AppState = Depends(state)):
    if not body.authorized:
        raise ApiError(422, "authorization_required", "You must confirm you are authorised to assess this target before a live assessment can start.", field="authorized")
    if module == "screenshot" and not (getattr(st.providers, "screenshots", None) and st.providers.screenshots.availability()["available"]):
        reason = st.providers.screenshots.availability()["reason"] if getattr(st.providers, "screenshots", None) else "No screenshot provider is configured."
        raise ApiError(503, "screenshots_unavailable", reason)
    target = _validate(st, body.target)
    fn, steps = MODULES[module]
    opts = body.options.model_dump() if module != "screenshot" else {}
    if module == "link":
        opts = {k: opts[k] for k in ("check_links", "check_external", "max_links_to_check")}
    elif module == "infrastructure":
        opts = {"include_http": opts["include_http"]}
    label = target.hostname if module != "link" else target.url
    aid = st.runner.create(module=module, target=target.url if module != "infrastructure" else target.hostname, label=label[:512], steps_def=steps,
                           options=opts, scope={"host": target.hostname, "same_site_only": True}, authorized=True)
    st.runner.launch(aid, fn, {"target": target.url if module != "infrastructure" else target.hostname, "options": opts}, steps)
    return {"id": aid, "module": module, "status": "queued", "location": f"/api/assessments/{aid}"}


@router.get("/assessments")
def list_assessments(module: str | None = Query(None, pattern="^(link|image|infrastructure|screenshot)$"),
                     status: str | None = Query(None, pattern="^(queued|running|completed|partial|failed)$"),
                     q: str | None = Query(None, max_length=200), limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100_000),
                     st: AppState = Depends(state)):
    return {**history.list_assessments(st.db, module=module, status=status, q=q, limit=limit, offset=offset), "mode": "live"}


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str = Depends(require_id), st: AppState = Depends(state)):
    a = history.get_assessment(st.db, assessment_id)
    if a is None:
        raise ApiError(404, "not_found", "Assessment not found.")
    a["available_exports"] = available_tables(a) if a["status"] not in ("queued", "running") else []
    return a


@router.delete("/assessments/{assessment_id}", status_code=204)
def delete_assessment(assessment_id: str = Depends(require_id), st: AppState = Depends(state)):
    if not history.delete_assessment(st.db, st.settings, assessment_id):
        raise ApiError(404, "not_found", "Assessment not found.")
    return Response(status_code=204)


@router.delete("/assessments")
def delete_all(confirm: bool = Query(False), st: AppState = Depends(state)):
    if not confirm:
        raise ApiError(400, "confirmation_required", "Pass confirm=true to delete ALL saved assessments, reports and screenshots. This cannot be undone.")
    return {"deleted": history.delete_all(st.db, st.settings)}


@router.get("/assessments/{assessment_id}/screenshot")
def get_screenshot(assessment_id: str = Depends(require_id), st: AppState = Depends(state)):
    a = history.get_assessment(st.db, assessment_id, include_result=False)
    path = st.settings.screenshots_dir / f"{assessment_id}.png"
    if a is None or a["module"] != "screenshot" or not path.is_file():
        raise ApiError(404, "not_found", "No screenshot is stored for this assessment.")
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "private, max-age=300", "Content-Disposition": f'inline; filename="screenshot-{assessment_id[:10]}.png"'})


# ------------------------------------------------------------------------------------------------ images
async def _read_upload(file: UploadFile, limit: int) -> bytes:
    chunks, size = [], 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ApiError(413, "file_too_large", f"The file exceeds the {limit // (1024 * 1024)} MB upload limit.")
        chunks.append(chunk)
    if not size:
        raise ApiError(422, "empty_file", "The uploaded file is empty.")
    return b"".join(chunks)


def _check_content_length(request: Request, limit: int) -> None:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit + 64 * 1024:
        raise ApiError(413, "file_too_large", f"The upload exceeds the {limit // (1024 * 1024)} MB limit.")


@router.post("/images/analyze", dependencies=[Depends(rate_limited)])
async def analyze_image(request: Request, file: UploadFile = File(...), st: AppState = Depends(state)):
    _check_content_length(request, st.settings.max_upload_bytes)
    data = await _read_upload(file, st.settings.max_upload_bytes)
    name = safe_display_name(file.filename)
    aid = st.runner.create(module="image", target=name, label=name, steps_def=image_analyzer.STEPS, options={}, scope={}, authorized=False)
    out = await st.runner.execute(aid, image_analyzer.run, {"bytes": data, "filename": file.filename or name}, image_analyzer.STEPS)
    detail = history.get_assessment(st.db, aid)
    detail["available_exports"] = available_tables(detail)
    if out.status == "failed" and out.data.get("rejected"):
        rej = out.data["rejected"]
        return JSONResponse({"error": {"code": rej["code"], "message": rej["message"], "assessment_id": aid}, "assessment": detail}, status_code=422)
    # the one-time live result includes GPS coordinates even when the stored copy has them redacted
    return {"assessment": detail, "live_result": out.transient, "live_result_note": "Returned once for this response. Stored data redacts GPS coordinates unless the server is configured otherwise; the image itself is never stored."}


@router.post("/images/sanitize", dependencies=[Depends(rate_limited)])
async def sanitize(request: Request, file: UploadFile = File(...), st: AppState = Depends(state)):
    _check_content_length(request, st.settings.max_upload_bytes)
    data = await _read_upload(file, st.settings.max_upload_bytes)
    try:
        res = sanitize_image(data, file.filename or "image", max_bytes=st.settings.max_upload_bytes, max_pixels=st.settings.max_image_pixels)
    except ImageValidationError as exc:
        raise ApiError(422, exc.code, exc.message)
    import json
    headers = {
        "Content-Disposition": f'attachment; filename="{res.filename}"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "X-CyberRecon-Sanitize": json.dumps({"method": res.method, "sha256": res.sha256, "removed": res.removed[:40], "retained": res.retained[:20], "notes": res.notes[:10],
                                             "bytes_before": len(data), "bytes_after": len(res.data)}, ensure_ascii=True),
    }
    return Response(content=res.data, media_type=res.mime_type, headers=headers)


# ------------------------------------------------------------------------------------------------ reports
def _report_http(exc: ReportError) -> ApiError:
    status = {"not_found": 404, "not_ready": 409, "file_missing": 410}.get(exc.code, 422)
    return ApiError(status, exc.code, exc.message)


@router.post("/assessments/{assessment_id}/reports", status_code=201, dependencies=[Depends(rate_limited)])
def create_report(body: ReportRequest, assessment_id: str = Depends(require_id), st: AppState = Depends(state)):
    try:
        r = st.reports.generate(assessment_id, body.format, body.table)
    except ReportError as exc:
        raise _report_http(exc)
    return {**r, "download_url": f"/api/reports/{r['id']}/download"}


@router.get("/assessments/{assessment_id}/export", dependencies=[Depends(rate_limited)])
def export(format: Literal["pdf", "json", "csv"] = "json", table: str | None = Query(None, max_length=40), assessment_id: str = Depends(require_id), st: AppState = Depends(state)):
    try:
        r = st.reports.generate(assessment_id, format, table)
        meta, path = st.reports.open(r["id"])
    except ReportError as exc:
        raise _report_http(exc)
    return FileResponse(path, media_type=MEDIA[format], filename=meta["filename"], headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@router.get("/reports")
def list_reports(limit: int = Query(50, ge=1, le=200), st: AppState = Depends(state)):
    from sqlalchemy import select

    from app.models.entities import Assessment, Report
    with st.db.session() as s:
        rows = s.execute(select(Report, Assessment.target_label, Assessment.module).join(Assessment, Assessment.id == Report.assessment_id).order_by(Report.created_at.desc()).limit(limit)).all()
        return {"items": [{"id": r.id, "assessment_id": r.assessment_id, "target": t, "module": m, "format": r.format, "variant": r.variant, "filename": r.filename, "size_bytes": r.size_bytes,
                           "sha256": r.sha256, "created_at": r.created_at.isoformat(timespec="seconds"), "download_url": f"/api/reports/{r.id}/download"} for r, t, m in rows]}


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, st: AppState = Depends(state)):
    if not HEX.match(report_id):
        raise ApiError(404, "not_found", "Report not found.")
    try:
        meta, path = st.reports.open(report_id)
    except ReportError as exc:
        raise _report_http(exc)
    return FileResponse(path, media_type=MEDIA[meta["format"]], filename=meta["filename"], headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


# ------------------------------------------------------------------------------------------------ dashboard
@router.get("/dashboard")
def dashboard(st: AppState = Depends(state)):
    return dashboard_svc.compute(history.all_for_dashboard(st.db), mode="live")


# ------------------------------------------------------------------------------------------------ demo (static, never persisted)
def _demo(st: AppState):
    try:
        st.demo.notice()
    except DemoUnavailable as exc:
        raise ApiError(503, "demo_unavailable", str(exc))
    return st.demo


@router.get("/demo/dashboard")
def demo_dashboard(st: AppState = Depends(state)):
    return _demo(st).dashboard()


@router.get("/demo/assessments")
def demo_list(st: AppState = Depends(state)):
    d = _demo(st)
    return {"items": d.summaries(), "total": len(d.summaries()), "mode": "demo", "simulated": True, "notice": d.notice()}


@router.get("/demo/assessments/{assessment_id}")
def demo_get(assessment_id: str, st: AppState = Depends(state)):
    a = _demo(st).get(assessment_id) if DEMO_ID.match(assessment_id) else None
    if a is None:
        raise ApiError(404, "not_found", "Demo assessment not found.")
    a["available_exports"] = available_tables(a)
    a["notice"] = st.demo.notice()
    return a


@router.get("/demo/bundle")
def demo_bundle(st: AppState = Depends(state)):
    return _demo(st).bundle()


@router.get("/demo/assessments/{assessment_id}/report.pdf")
def demo_report(assessment_id: str, st: AppState = Depends(state)):
    body = _demo(st).report_pdf(assessment_id) if DEMO_ID.match(assessment_id) else None
    if body is None:
        raise ApiError(404, "not_found", "Demo assessment not found.")
    return Response(body, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cyberrecon-DEMO-{assessment_id}.pdf"', "X-Content-Type-Options": "nosniff"})
