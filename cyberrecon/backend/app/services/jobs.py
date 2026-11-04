"""Assessment lifecycle: create -> run (tracked steps) -> persist. Progress shown to users is real state."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select

from app.core.config import Settings
from app.database.session import Database
from app.models.entities import Assessment, DataSource, Finding, ModuleResult
from app.services.common import ModuleFn, ModuleOutput, RunContext, StepTracker

log = logging.getLogger("cyberrecon.jobs")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class JobRunner:
    def __init__(self, db: Database, settings: Settings, providers, fetcher_factory: Callable):
        self.db = db
        self.settings = settings
        self.providers = providers
        self.fetcher_factory = fetcher_factory
        self._sem = asyncio.Semaphore(settings.max_concurrent_assessments)
        self._tasks: dict[str, asyncio.Task] = {}

    # ------------------------------------------------------------------ creation
    def create(self, *, module: str, target: str, label: str, steps_def: list[tuple[str, str]], options: dict | None = None,
               scope: dict | None = None, authorized: bool = False) -> str:
        tracker = StepTracker(steps_def, lambda s: None)
        with self.db.session() as s:
            a = Assessment(
                module=module, target=target[:2048], target_label=label[:512], status="queued",
                authorization_confirmed=authorized, authorization_at=_now() if authorized else None,
                scope=scope or {}, options=options or {}, steps=tracker.steps,
            )
            s.add(a)
            s.flush()
            return a.id

    def launch(self, assessment_id: str, module_fn: ModuleFn, params: dict, steps_def: list[tuple[str, str]]) -> None:
        task = asyncio.create_task(self.execute(assessment_id, module_fn, params, steps_def))
        self._tasks[assessment_id] = task
        task.add_done_callback(lambda _t, aid=assessment_id: self._tasks.pop(aid, None))

    async def wait(self, assessment_id: str) -> None:
        task = self._tasks.get(assessment_id)
        if task:
            await asyncio.shield(task)

    # ------------------------------------------------------------------ execution
    def _persist_steps(self, assessment_id: str):
        def persist(steps: list[dict]) -> None:
            with self.db.session() as s:
                a = s.get(Assessment, assessment_id)
                if a:
                    a.steps = steps
        return persist

    async def execute(self, assessment_id: str, module_fn: ModuleFn, params: dict, steps_def: list[tuple[str, str]]) -> ModuleOutput:
        tracker = StepTracker(steps_def, self._persist_steps(assessment_id))
        async with self._sem:
            t0 = time.perf_counter()
            with self.db.session() as s:
                a = s.get(Assessment, assessment_id)
                a.status, a.started_at = "running", _now()
            tracker.flush()
            ctx = RunContext(assessment_id, self.settings, tracker, self.fetcher_factory, self.providers)
            try:
                out: ModuleOutput = await module_fn(ctx, params)
                error = None
            except Exception as exc:  # unexpected: never leak internals to the client
                log.exception("assessment %s crashed", assessment_id)
                out = ModuleOutput(data={}, status="failed", errors=[{"step": "internal", "code": "internal_error", "message": "An unexpected internal error occurred."}])
                error = "An unexpected internal error occurred. The failure has been logged."
                for st in tracker.steps:
                    if st["status"] == "running":
                        st["status"] = "failed"
                    elif st["status"] == "pending":
                        st["status"] = "skipped"
                tracker.flush()
            for st in tracker.steps:  # a finished assessment never leaves steps pending
                if st["status"] == "pending":
                    st["status"], st["detail"] = "skipped", st.get("detail") or "Not reached"
            tracker.flush()
            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._persist_output(assessment_id, out, duration_ms, error)
            return out

    def _persist_output(self, assessment_id: str, out: ModuleOutput, duration_ms: int, error: str | None) -> None:
        with self.db.session() as s:
            a = s.get(Assessment, assessment_id)
            if a is None:  # deleted while running
                return
            s.add(ModuleResult(assessment_id=a.id, module=a.module, status=out.status, data=out.data, errors=out.errors))
            for f in out.findings:
                s.add(Finding(assessment_id=a.id, **f))
            for src in out.sources:
                retrieved = src.get("retrieved_at")
                s.add(DataSource(
                    assessment_id=a.id, name=src["name"], kind=src["kind"], reference=src.get("reference"),
                    status=src["status"], detail=src.get("detail"),
                    retrieved_at=datetime.fromisoformat(retrieved) if retrieved else _now(),
                ))
            a.status = out.status
            a.summary = {**out.summary, "findings": len(out.findings)}
            a.error = error or (out.errors[0]["message"] if out.status == "failed" and out.errors else None)
            a.finished_at = _now()
            a.duration_ms = duration_ms

    # ------------------------------------------------------------------ housekeeping
    def recover_interrupted(self) -> int:
        """Assessments left queued/running by a previous process cannot be resumed; mark them failed honestly."""
        n = 0
        with self.db.session() as s:
            for a in s.scalars(select(Assessment).where(Assessment.status.in_(("queued", "running")))):
                a.status = "failed"
                a.error = "The server restarted before this assessment finished."
                a.finished_at = _now()
                # build NEW dicts: mutating the stored ones in place would not be detected as a change
                a.steps = [{**st, "status": ("skipped" if st["status"] == "pending" else "failed")} if st["status"] in ("running", "pending") else dict(st) for st in a.steps]
                n += 1
        return n
