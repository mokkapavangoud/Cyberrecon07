from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.core.config import Settings
from app.core.ratelimit import RateLimiter
from app.database.session import Database
from app.security.ip_policy import IPPolicy
from app.services.demo import DemoData
from app.services.jobs import JobRunner
from app.services.reporting.store import ReportStore


@dataclass
class AppState:
    settings: Settings
    db: Database
    runner: JobRunner
    providers: object
    reports: ReportStore
    demo: DemoData
    limiter: RateLimiter
    policy: IPPolicy
    target_fetcher_factory: Callable
