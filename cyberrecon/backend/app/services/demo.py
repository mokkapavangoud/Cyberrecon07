"""Demo mode: a static, clearly simulated dataset. It is read from a file, NEVER written to the database,
and every payload carries ``mode: "demo"`` / ``simulated: true`` so it cannot be mistaken for real results."""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path

from . import dashboard
from .reporting import pdf

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "demo" / "aurora-demo.json"
NOTICE_FALLBACK = "SIMULATED DEMO DATA"


class DemoUnavailable(Exception):
    pass


class DemoData:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or DEFAULT_PATH)

    @lru_cache(maxsize=1)
    def _load(self) -> dict:
        try:
            bundle = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise DemoUnavailable(f"Demo dataset could not be loaded from {self.path.name}: {exc.__class__.__name__}.")
        if not bundle.get("simulated"):
            raise DemoUnavailable("Demo dataset is not marked as simulated and was refused.")
        return bundle

    def notice(self) -> str:
        return self._load().get("notice", NOTICE_FALLBACK)

    def assessments(self) -> list[dict]:
        out = copy.deepcopy(self._load()["assessments"])
        for a in out:
            a.update(mode="demo", simulated=True)
        return out

    def get(self, assessment_id: str) -> dict | None:
        return next((a for a in self.assessments() if a["id"] == assessment_id), None)

    def summaries(self) -> list[dict]:
        keys = ("id", "module", "target", "status", "mode", "simulated", "created_at", "finished_at", "duration_ms", "summary", "progress")
        return [{k: a.get(k) for k in keys} | {"findings": len(a["findings"])} for a in self.assessments()]

    def dashboard(self) -> dict:
        d = dashboard.compute(self.assessments(), mode="demo")
        d["notice"] = self.notice()
        return d

    def bundle(self) -> dict:
        return {"mode": "demo", "simulated": True, "notice": self.notice(), "assessments": self.assessments()}

    def report_pdf(self, assessment_id: str) -> bytes | None:
        a = self.get(assessment_id)
        return pdf.build_pdf(a, demo=True) if a else None
