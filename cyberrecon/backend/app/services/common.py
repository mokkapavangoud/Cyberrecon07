from __future__ import annotations

import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

SEVERITIES = ("info", "low", "medium", "high")
EVIDENCE_TYPES = ("observed", "third_party", "estimate")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def finding(
    module: str,
    category: str,
    title: str,
    detail: str = "",
    *,
    severity: str = "info",
    evidence: str = "observed",
    source: str | None = None,
    data: dict | None = None,
) -> dict:
    assert severity in SEVERITIES and evidence in EVIDENCE_TYPES
    return {
        "module": module,
        "category": category,
        "title": title[:300],
        "detail": detail,
        "severity": severity,
        "evidence_type": evidence,
        "source": source,
        "data": data or {},
    }


def source(name: str, kind: str, status: str, reference: str | None = None, detail: str | None = None) -> dict:
    assert status in ("ok", "unavailable", "failed", "skipped")
    return {"name": name, "kind": kind, "status": status, "reference": reference, "detail": detail, "retrieved_at": iso_now()}


@dataclass
class ModuleOutput:
    data: dict[str, Any]
    findings: list[dict] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"  # completed | partial | failed
    transient: dict[str, Any] | None = None  # returned to the caller once, never persisted


class StepTracker:
    """Persists *real* step status. The UI progress bar is derived from these records only."""

    def __init__(self, steps_def: list[tuple[str, str]], persist: Callable[[list[dict]], None]):
        self.steps = [
            {"key": k, "label": label, "status": "pending", "started_at": None, "finished_at": None, "detail": None}
            for k, label in steps_def
        ]
        self._persist = persist
        self._t0: dict[str, float] = {}

    def _get(self, key: str) -> dict:
        for s in self.steps:
            if s["key"] == key:
                return s
        raise KeyError(key)

    def flush(self) -> None:
        self._persist([dict(s) for s in self.steps])

    @asynccontextmanager
    async def step(self, key: str):
        s = self._get(key)
        s["status"], s["started_at"] = "running", iso_now()
        self._t0[key] = time.perf_counter()
        self.flush()
        try:
            yield s
        except BaseException as exc:
            s["status"], s["finished_at"] = "failed", iso_now()
            s["detail"] = s["detail"] or type(exc).__name__
            self.flush()
            raise
        else:
            if s["status"] == "running":
                s["status"] = "done"
            s["finished_at"] = iso_now()
            self.flush()

    def detail(self, key: str, text: str) -> None:
        self._get(key)["detail"] = text
        self.flush()

    def mark(self, key: str, status: str, detail: str | None = None) -> None:
        s = self._get(key)
        s["status"] = status
        if detail is not None:
            s["detail"] = detail
        if status in ("done", "failed", "skipped"):
            s["finished_at"] = iso_now()
        self.flush()

    def fail_step(self, key: str, detail: str) -> None:
        """Mark a step failed without raising (module continues in 'partial' mode)."""
        self.mark(key, "failed", detail)

    def skip(self, key: str, reason: str) -> None:
        self.mark(key, "skipped", reason)


ModuleFn = Callable[["RunContext", dict], Awaitable[ModuleOutput]]


@dataclass
class RunContext:
    assessment_id: str
    settings: Any
    steps: StepTracker
    fetcher_factory: Callable[[], Any]
    providers: Any
