"""Generate report files from PERSISTED assessment data and register them. Nothing is built from client-supplied data."""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

from app.core.config import Settings
from app.database.session import Database
from app.models.entities import Assessment, Report

from . import exports, pdf
from .serialize import assessment_to_dict

FORMATS = ("pdf", "json", "csv")
_SAFE = re.compile(r"[^A-Za-z0-9._-]")


class ReportError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class ReportStore:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings

    def generate(self, assessment_id: str, fmt: str, table: str | None = None) -> dict:
        if fmt not in FORMATS:
            raise ReportError("unsupported_format", f"Unsupported report format. Choose one of: {', '.join(FORMATS)}.")
        with self.db.session() as s:
            a = s.get(Assessment, assessment_id)
            if a is None:
                raise ReportError("not_found", "Assessment not found.")
            if a.status in ("queued", "running"):
                raise ReportError("not_ready", "The assessment has not finished yet.")
            data = assessment_to_dict(a)
            shot = self.settings.screenshots_dir / f"{a.id}.png" if a.module == "screenshot" else None
            if fmt == "pdf":
                body, ext, variant = pdf.build_pdf(data, screenshot_path=shot), "pdf", None
            elif fmt == "json":
                body, ext, variant = exports.to_json(data), "json", None
            else:
                tables = exports.available_tables(data)
                table = table or tables[0]
                if table not in tables:
                    raise ReportError("unknown_table", f"Unknown table '{table}'. Available: {', '.join(tables)}.")
                body, ext, variant = exports.to_csv(data, table), "csv", table
            self.settings.ensure_dirs()
            name = f"cyberrecon-{a.module}-{a.id[:10]}{'-' + variant if variant else ''}.{ext}"
            name = _SAFE.sub("_", name)
            path = self.settings.reports_dir / f"{a.id}-{uuid.uuid4().hex[:10]}.{ext}"
            path.write_bytes(body)
            r = Report(assessment_id=a.id, format=fmt, variant=variant, filename=name, path=str(path), size_bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            s.add(r)
            s.flush()
            return {"id": r.id, "assessment_id": a.id, "format": fmt, "variant": variant, "filename": name, "size_bytes": len(body), "sha256": r.sha256}

    def open(self, report_id: str) -> tuple[dict, Path]:
        with self.db.session() as s:
            r = s.get(Report, report_id)
            if r is None:
                raise ReportError("not_found", "Report not found.")
            p = Path(r.path).resolve()
            base = self.settings.reports_dir.resolve()
            if base not in p.parents or not p.exists():  # defence in depth against a tampered DB row
                raise ReportError("file_missing", "The report file is no longer available. Generate it again.")
            return {"filename": r.filename, "format": r.format}, p
