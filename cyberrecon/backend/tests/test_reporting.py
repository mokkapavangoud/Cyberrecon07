import csv
import io
import json

import pytest
from pypdf import PdfReader

from app.models.entities import Assessment, Report
from app.services.image_intelligence import analyzer as image_analyzer
from app.services.infrastructure import analyzer as infra_analyzer
from app.services.jobs import JobRunner
from app.services.link_analysis import analyzer as link_analyzer
from app.services.reporting import exports, pdf
from app.services.reporting.serialize import assessment_to_dict
from app.services.reporting.store import ReportError, ReportStore

from .helpers import make_providers
from .test_image_intelligence import make_jpeg

EVIL = '<img src="file:///etc/passwd"/><font color="red">x</font><a href="javascript:alert(1)">z</a>&amp;'


def pdf_text(data: bytes) -> str:
    return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


@pytest.fixture
def runner(db, settings, fetcher_factory):
    return JobRunner(db, settings, make_providers(), fetcher_factory)


async def run_link(runner, server, **opts):
    url = f"http://site.example.org:{server.port}/"
    aid = runner.create(module="link", target=url, label="site.example.org", steps_def=link_analyzer.STEPS, authorized=True, options=opts)
    await runner.execute(aid, link_analyzer.run, {"target": url, "options": opts}, link_analyzer.STEPS)
    return aid


# ------------------------------------------------------------------ csv
def test_csv_neutralises_formulas():
    for v in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(1)", "\tTAB", "\rCR"):
        assert exports.csv_safe(v).startswith("'")
    assert exports.csv_safe("normal") == "normal" and exports.csv_safe(None) == ""


# ------------------------------------------------------------------ persistence + reports from stored data
async def test_link_report_pdf_json_csv_from_persisted_data(runner, db, settings, server):
    aid = await run_link(runner, server, check_links=False)
    with db.session() as s:
        d = assessment_to_dict(s.get(Assessment, aid))
    assert d["status"] in ("completed", "partial") and d["result"]["http"]["status"] == 200
    store = ReportStore(db, settings)
    rp = store.generate(aid, "pdf")
    meta, path = store.open(rp["id"])
    body = path.read_bytes()
    assert body.startswith(b"%PDF") and meta["format"] == "pdf"
    text = pdf_text(body)
    for needle in ("Assessment report", aid, "Methods used", "Limitations", "Authorisation", "Data sources", "discovered"):
        assert needle in text, needle
    assert "SIMULATED" not in text  # real report is never watermarked as demo
    rj = store.generate(aid, "json")
    parsed = json.loads(store.open(rj["id"])[1].read_bytes())
    assert parsed["assessment"]["id"] == aid and parsed["assessment"]["authorization"]["confirmed"] is True
    rc = store.generate(aid, "csv", "links")
    rows = list(csv.reader(io.StringIO(store.open(rc["id"])[1].read_text("utf-8-sig"))))
    assert rows[0][0] == "url" and len(rows) > 3
    with db.session() as s:
        assert s.query(Report).filter_by(assessment_id=aid).count() == 3
        assert all(r.sha256 and r.size_bytes for r in s.query(Report))


async def test_pdf_escapes_untrusted_content(runner, db, settings, server):
    aid = await run_link(runner, server, check_links=False)
    with db.session() as s:
        d = assessment_to_dict(s.get(Assessment, aid))
    d["result"]["page"]["title"] = EVIL
    d["target"] = EVIL
    d["findings"].append({"id": "x", "module": "link", "category": "c", "title": EVIL, "detail": EVIL, "severity": "high", "evidence_type": "observed", "source": EVIL})
    d["sources"].append({"id": "y", "name": EVIL, "kind": "x", "reference": EVIL, "status": "failed", "detail": EVIL, "retrieved_at": None})
    d["result"]["links"][0]["url"] = EVIL
    body = pdf.build_pdf(d)  # must not raise or fetch file:// resources
    text = pdf_text(body)
    assert "<img" in text and "file:///etc/passwd" in text  # rendered as literal text, not interpreted


def test_esc_handles_markup_control_chars_and_length():
    assert pdf.esc("<b>x</b>&") == "&lt;b&gt;x&lt;/b&gt;&amp;"
    assert pdf.esc("a\x00b‮c") == "abc"
    assert len(pdf.esc("x" * 5000, 100)) <= 101 and pdf.esc(None) == "—"


async def test_report_for_failed_assessment_states_the_failure(runner, db, settings, server):
    aid = runner.create(module="link", target="http://127.0.0.1:1/", label="nothing", steps_def=link_analyzer.STEPS, authorized=True)
    await runner.execute(aid, link_analyzer.run, {"target": "http://127.0.0.1:1/", "options": {}}, link_analyzer.STEPS)
    rp = ReportStore(db, settings).generate(aid, "pdf")
    text = pdf_text(ReportStore(db, settings).open(rp["id"])[1].read_bytes())
    assert "could not be fetched" in text or "error" in text.lower()


async def test_infrastructure_report_labels_evidence_types(runner, db, settings, fetcher_factory):
    aid = runner.create(module="infrastructure", target="www.example-corp.org", label="www.example-corp.org", steps_def=infra_analyzer.STEPS, authorized=True)
    await runner.execute(aid, infra_analyzer.run, {"target": "www.example-corp.org", "options": {"include_http": False}}, infra_analyzer.STEPS)
    store = ReportStore(db, settings)
    text = pdf_text(store.open(store.generate(aid, "pdf")["id"])[1].read_bytes())
    for needle in ("DNS records", "Registration (RDAP)", "third-party", "ESTIMATE", "Relationship graph", "TLS certificate"):
        assert needle in text, needle
    for table in ("dns_records", "ip_addresses", "subdomains", "findings", "sources"):
        assert store.generate(aid, "csv", table)["variant"] == table


async def test_image_report_never_contains_redacted_gps(runner, db, settings):
    jpeg = make_jpeg()
    aid = runner.create(module="image", target="me.jpg", label="me.jpg", steps_def=image_analyzer.STEPS)
    out = await runner.execute(aid, image_analyzer.run, {"bytes": jpeg, "filename": "me.jpg"}, image_analyzer.STEPS)
    assert out.transient  # live result had the coordinates
    store = ReportStore(db, settings)
    body = store.open(store.generate(aid, "pdf")["id"])[1].read_bytes()
    text = pdf_text(body)
    assert "GPS" in text and "not retained" in text
    assert "12.58" not in text and "77.58" not in text
    assert "12.58" not in store.open(store.generate(aid, "json")["id"])[1].read_text()


def test_report_errors(db, settings):
    store = ReportStore(db, settings)
    with pytest.raises(ReportError) as e:
        store.generate("nope", "pdf")
    assert e.value.code == "not_found"
    with pytest.raises(ReportError) as e:
        store.generate("nope", "docx")
    assert e.value.code == "unsupported_format"


async def test_report_path_traversal_in_db_row_is_refused(runner, db, settings, server):
    aid = await run_link(runner, server, check_links=False)
    store = ReportStore(db, settings)
    rid = store.generate(aid, "json")["id"]
    with db.session() as s:
        s.get(Report, rid).path = "/etc/passwd"
    with pytest.raises(ReportError) as e:
        store.open(rid)
    assert e.value.code == "file_missing"


async def test_unfinished_assessment_cannot_be_reported(runner, db, settings):
    aid = runner.create(module="link", target="x", label="x", steps_def=link_analyzer.STEPS, authorized=True)
    with pytest.raises(ReportError) as e:
        ReportStore(db, settings).generate(aid, "pdf")
    assert e.value.code == "not_ready"
