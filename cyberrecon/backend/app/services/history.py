"""Query / delete persisted assessments (and the files that belong to them)."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, or_, select

from app.core.config import Settings
from app.database.session import Database
from app.models.entities import Assessment, Report
from app.services.reporting.serialize import assessment_to_dict, summary_row

MODULES = ("link", "image", "infrastructure", "screenshot")
STATUSES = ("queued", "running", "completed", "partial", "failed")


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_assessments(db: Database, *, module: str | None, status: str | None, q: str | None, limit: int, offset: int) -> dict:
    with db.session() as s:
        stmt = select(Assessment)
        if module:
            stmt = stmt.where(Assessment.module == module)
        if status:
            stmt = stmt.where(Assessment.status == status)
        if q:
            like = f"%{_escape_like(q.strip().lower())}%"
            stmt = stmt.where(or_(func.lower(Assessment.target_label).like(like, escape="\\"), Assessment.id.like(like, escape="\\")))
        total = s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = s.scalars(stmt.order_by(Assessment.created_at.desc(), Assessment.id).limit(limit).offset(offset)).all()
        return {"items": [summary_row(a) for a in rows], "total": total, "limit": limit, "offset": offset}


def get_assessment(db: Database, assessment_id: str, *, include_result: bool = True) -> dict | None:
    with db.session() as s:
        a = s.get(Assessment, assessment_id)
        return assessment_to_dict(a, include_result=include_result) if a else None


def all_for_dashboard(db: Database, limit: int = 1000) -> list[dict]:
    with db.session() as s:
        rows = s.scalars(select(Assessment).order_by(Assessment.created_at.desc()).limit(limit)).all()
        return [assessment_to_dict(a, include_result=False) for a in rows]


def _unlink(path: Path, base: Path) -> None:
    try:
        p = path.resolve()
        if base.resolve() in p.parents and p.is_file():
            p.unlink()
    except OSError:
        pass


def delete_assessment(db: Database, settings: Settings, assessment_id: str) -> bool:
    with db.session() as s:
        a = s.get(Assessment, assessment_id)
        if a is None:
            return False
        files = [Path(r.path) for r in a.reports]
        s.delete(a)
    for f in files:
        _unlink(f, settings.reports_dir)
    _unlink(settings.screenshots_dir / f"{assessment_id}.png", settings.screenshots_dir)
    return True


def delete_all(db: Database, settings: Settings) -> int:
    with db.session() as s:
        ids = list(s.scalars(select(Assessment.id)))
    return sum(1 for i in ids if delete_assessment(db, settings, i))
