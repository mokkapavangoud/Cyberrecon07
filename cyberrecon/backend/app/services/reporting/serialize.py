"""Single serialisation path for assessments: used by the API, exports and reports."""
from __future__ import annotations

from app.models.entities import Assessment

AUTH_STATEMENT = "The user confirmed they are authorised to assess this target before the assessment started."
DONE_STATES = ("done", "skipped", "failed")


def iso(dt) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def progress(steps: list[dict]) -> dict:
    total = len(steps)
    finished = len([s for s in steps if s["status"] in DONE_STATES])
    return {"finished": finished, "total": total, "percent": int(100 * finished / total) if total else 0,
            "current": next((s["label"] for s in steps if s["status"] == "running"), None)}


def summary_row(a: Assessment) -> dict:
    return {
        "id": a.id, "module": a.module, "target": a.target_label, "status": a.status, "mode": "live",
        "created_at": iso(a.created_at), "finished_at": iso(a.finished_at), "duration_ms": a.duration_ms,
        "summary": a.summary or {}, "findings": (a.summary or {}).get("findings", 0), "progress": progress(a.steps or []),
    }


def assessment_to_dict(a: Assessment, *, include_result: bool = True) -> dict:
    result = a.results[0] if a.results else None
    return {
        **summary_row(a),
        "target_input": a.target,
        "authorization": {"confirmed": a.authorization_confirmed, "confirmed_at": iso(a.authorization_at), "statement": AUTH_STATEMENT if a.authorization_confirmed else None},
        "scope": a.scope or {}, "options": a.options or {}, "steps": a.steps or [], "error": a.error,
        "started_at": iso(a.started_at),
        "result_status": result.status if result else None,
        "result": (result.data if result else None) if include_result else None,
        "errors": result.errors if result else [],
        "findings": [
            {"id": f.id, "module": f.module, "category": f.category, "title": f.title, "detail": f.detail, "severity": f.severity,
             "evidence_type": f.evidence_type, "source": f.source}
            for f in sorted(a.findings, key=lambda f: (f.created_at, f.id))
        ],
        "sources": [
            {"id": s.id, "name": s.name, "kind": s.kind, "reference": s.reference, "status": s.status, "detail": s.detail, "retrieved_at": iso(s.retrieved_at)}
            for s in sorted(a.sources, key=lambda s: (s.retrieved_at, s.id))
        ],
        "reports": [
            {"id": r.id, "format": r.format, "variant": r.variant, "filename": r.filename, "size_bytes": r.size_bytes, "sha256": r.sha256, "created_at": iso(r.created_at)}
            for r in sorted(a.reports, key=lambda r: r.created_at, reverse=True)
        ],
    }
