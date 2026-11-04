import pytest
from sqlalchemy import text

from app.database.migrations import current_version, database_ok, migrate
from app.database.session import Database
from app.models.entities import Assessment, DataSource, Finding, ModuleResult
from app.services.common import ModuleOutput, finding, source
from app.services.jobs import JobRunner
from app.services.link_analysis import analyzer as link_analyzer
from app.services.reporting.serialize import assessment_to_dict

from .helpers import make_providers

STEPS = [("a", "Step A"), ("b", "Step B")]


@pytest.fixture
def runner(db, settings, fetcher_factory):
    return JobRunner(db, settings, make_providers(), fetcher_factory)


def test_migrations_are_idempotent_and_versioned(tmp_path):
    d = Database(f"sqlite:///{tmp_path / 'm.db'}")
    migrate(d)
    v = current_version(d)
    migrate(d)
    assert current_version(d) == v >= 1 and database_ok(d)
    with d.engine.connect() as c:
        assert c.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert c.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"
    d.dispose()


async def test_module_output_is_persisted_in_full(runner, db):
    async def fn(ctx, params):
        async with ctx.steps.step("a"):
            pass
        async with ctx.steps.step("b"):
            ctx.steps.detail("b", "detail text")
        return ModuleOutput(data={"k": "v"}, findings=[finding("link", "cat", "Title", "Detail", severity="medium", evidence="third_party", source="src")],
                            sources=[source("Src", "http", "failed", "http://x", "why it failed")], errors=[{"step": "b", "code": "c", "message": "m"}],
                            status="partial", summary={"headline": "H"})

    aid = runner.create(module="link", target="t", label="t", steps_def=STEPS, authorized=True, options={"o": 1}, scope={"s": 2})
    await runner.execute(aid, fn, {}, STEPS)
    with db.session() as s:
        d = assessment_to_dict(s.get(Assessment, aid))
    assert d["status"] == "partial" and d["result"] == {"k": "v"} and d["options"] == {"o": 1} and d["scope"] == {"s": 2}
    assert d["findings"][0]["severity"] == "medium" and d["findings"][0]["evidence_type"] == "third_party"
    assert d["sources"][0]["status"] == "failed" and d["sources"][0]["detail"] == "why it failed"
    assert d["errors"][0]["code"] == "c" and d["duration_ms"] is not None and d["finished_at"]
    assert [x["status"] for x in d["steps"]] == ["done", "done"] and d["steps"][1]["detail"] == "detail text"
    assert d["progress"]["percent"] == 100


async def test_crashing_module_is_a_generic_failure_without_internals(runner, db):
    async def boom(ctx, params):
        async with ctx.steps.step("a"):
            raise RuntimeError("secret internal path /srv/app/x.py password=hunter2")

    aid = runner.create(module="link", target="t", label="t", steps_def=STEPS)
    await runner.execute(aid, boom, {}, STEPS)
    with db.session() as s:
        d = assessment_to_dict(s.get(Assessment, aid))
    assert d["status"] == "failed" and "hunter2" not in str(d) and "/srv/app" not in str(d)
    assert [x["status"] for x in d["steps"]] == ["failed", "skipped"]


def test_interrupted_assessments_are_marked_failed_on_restart(runner, db):
    aid = runner.create(module="link", target="t", label="t", steps_def=STEPS)
    with db.session() as s:
        a = s.get(Assessment, aid)
        a.status = "running"
        a.steps = [{**a.steps[0], "status": "running"}, {**a.steps[1], "status": "pending"}]
    assert runner.recover_interrupted() == 1
    with db.session() as s:
        a = s.get(Assessment, aid)
        assert a.status == "failed" and "restarted" in a.error and [x["status"] for x in a.steps] == ["failed", "skipped"]
    assert runner.recover_interrupted() == 0


async def test_deleting_an_assessment_removes_all_children(runner, db):
    async def fn(ctx, params):
        return ModuleOutput(data={}, findings=[finding("link", "c", "t", "d")], sources=[source("s", "http", "ok")], status="completed")

    aid = runner.create(module="link", target="t", label="t", steps_def=STEPS)
    await runner.execute(aid, fn, {}, STEPS)
    from app.services import history
    assert history.delete_assessment(db, runner.settings, aid)
    with db.session() as s:
        for model in (Assessment, ModuleResult, Finding, DataSource):
            assert s.query(model).count() == 0


async def test_deleted_while_running_does_not_crash(runner, db):
    from app.services import history

    async def fn(ctx, params):
        history.delete_assessment(db, ctx.settings, ctx.assessment_id)
        return ModuleOutput(data={}, status="completed")

    aid = runner.create(module="link", target="t", label="t", steps_def=STEPS)
    await runner.execute(aid, fn, {}, STEPS)
    with db.session() as s:
        assert s.query(Assessment).count() == 0


async def test_concurrency_limit_is_enforced(db, settings, fetcher_factory):
    import asyncio
    s = settings.model_copy(update={"max_concurrent_assessments": 2})
    r = JobRunner(db, s, make_providers(), fetcher_factory)
    active = {"now": 0, "max": 0}

    async def fn(ctx, params):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        await asyncio.sleep(0.05)
        active["now"] -= 1
        return ModuleOutput(data={}, status="completed")

    ids = [r.create(module="link", target=str(i), label=str(i), steps_def=STEPS) for i in range(6)]
    await asyncio.gather(*(r.execute(i, fn, {}, STEPS) for i in ids))
    assert active["max"] == 2
