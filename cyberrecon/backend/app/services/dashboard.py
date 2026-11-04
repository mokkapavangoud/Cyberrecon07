"""Dashboard statistics computed ONLY from assessment dictionaries (persisted data, or the demo bundle in demo mode)."""
from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

MODULES = ("link", "image", "infrastructure", "screenshot")
SEVERITIES = ("high", "medium", "low", "info")
MIN_TREND_ASSESSMENTS = 5
MIN_TREND_DAYS = 3


def compute(items: list[dict], *, mode: str = "live") -> dict:
    """``items`` are assessment dicts (as produced by ``assessment_to_dict``), newest first."""
    ordered = sorted(items, key=lambda a: a.get("created_at") or "", reverse=True)
    by_status = Counter(a["status"] for a in ordered)
    by_module = Counter(a["module"] for a in ordered)
    sev = Counter()
    for a in ordered:
        for f in a.get("findings", []):
            sev[f["severity"]] += 1
    durations: dict[str, list[int]] = defaultdict(list)
    for a in ordered:
        if a.get("duration_ms") is not None and a["status"] in ("completed", "partial"):
            durations[a["module"]].append(a["duration_ms"])
    targets: dict[str, dict] = {}
    for a in ordered:
        t = targets.setdefault(a["target"], {"target": a["target"], "assessments": 0, "last_at": a.get("created_at"), "modules": set(), "findings": 0})
        t["assessments"] += 1
        t["modules"].add(a["module"])
        t["findings"] += len(a.get("findings", []))
    days = Counter((a.get("created_at") or "")[:10] for a in ordered if a.get("created_at"))
    sufficient = len(ordered) >= MIN_TREND_ASSESSMENTS and len(days) >= MIN_TREND_DAYS
    top = [f | {"assessment_id": a["id"], "target": a["target"]} for a in ordered for f in a.get("findings", []) if f["severity"] in ("high", "medium")][:8]
    return {
        "mode": mode, "simulated": mode == "demo",
        "totals": {
            "assessments": len(ordered), "completed": by_status.get("completed", 0), "partial": by_status.get("partial", 0), "failed": by_status.get("failed", 0),
            "in_progress": by_status.get("running", 0) + by_status.get("queued", 0), "targets": len(targets),
            "findings": sum(sev.values()), "reports": sum(len(a.get("reports", [])) for a in ordered),
        },
        "findings_by_severity": {k: sev.get(k, 0) for k in SEVERITIES},
        "module_usage": {m: by_module.get(m, 0) for m in MODULES},
        "avg_duration_ms": {m: int(mean(v)) for m, v in durations.items()},
        "recent": [{k: a[k] for k in ("id", "module", "target", "status", "created_at", "duration_ms", "mode") if k in a} | {"findings": len(a.get("findings", []))} for a in ordered[:8]],
        "target_history": sorted(({**t, "modules": sorted(t["modules"])} for t in targets.values()), key=lambda t: t["last_at"] or "", reverse=True)[:8],
        "top_findings": top,
        "trend": {"sufficient": sufficient, "min_assessments": MIN_TREND_ASSESSMENTS, "min_days": MIN_TREND_DAYS,
                  "days": [{"date": d, "count": c} for d, c in sorted(days.items())] if sufficient else []},
    }
