"""Application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api import errors
from app.api.errors import ApiError
from app.api.routes import router
from app.api.state import AppState
from app.core.config import Settings, get_settings
from app.core.ratelimit import RateLimiter
from app.database.migrations import migrate
from app.database.session import Database
from app.integrations.registry import Providers, build_default_providers
from app.security.ip_policy import IPPolicy
from app.security.safe_net import SafeFetcher
from app.services.demo import DemoData
from app.services.jobs import JobRunner
from app.services.reporting.store import ReportStore

log = logging.getLogger("cyberrecon")
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


def create_app(settings: Settings | None = None, *, providers: Providers | None = None, fetcher_factory: Callable | None = None,
               policy: IPPolicy | None = None, demo_path: Path | None = None) -> FastAPI:
    """``providers`` / ``fetcher_factory`` / ``policy`` are injection points used by tests; production uses the defaults."""
    settings = settings or get_settings()
    settings.ensure_dirs()
    policy = policy or IPPolicy()
    db = Database(settings.db_url)
    migrate(db)

    # Two fetcher flavours. Targets: restricted by the optional target allowlist. Providers (RDAP, CT, GeoIP): fixed public
    # services chosen by the server, so the user's allowlist must not block them — but they still pass through the same IP guard.
    target_factory = fetcher_factory or (lambda: SafeFetcher(settings, policy=policy))
    provider_factory = (lambda: SafeFetcher(settings, policy=policy, allowlist=[])) if fetcher_factory is None else fetcher_factory
    providers = providers or build_default_providers(settings, fetcher_factory=provider_factory)
    runner = JobRunner(db, settings, providers, target_factory)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        n = runner.recover_interrupted()
        if n:
            log.warning("marked %d interrupted assessment(s) as failed", n)
        yield
        db.dispose()

    app = FastAPI(title=f"{settings.app_name} API", version=settings.version, lifespan=lifespan, docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.cr = AppState(settings=settings, db=db, runner=runner, providers=providers, reports=ReportStore(db, settings), demo=DemoData(demo_path),
                            limiter=RateLimiter(settings.rate_limit_per_minute), policy=policy, target_fetcher_factory=target_factory)
    errors.install(app)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"],
                       allow_headers=["Content-Type"], expose_headers=["Content-Disposition", "X-CyberRecon-Sanitize", "Retry-After"], max_age=600)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            if not request.url.path.startswith("/api/docs"):
                resp.headers.setdefault("Content-Security-Policy", API_CSP)
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    app.include_router(router)

    dist = settings.frontend_dist or Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if (dist / "index.html").is_file():
        root = dist.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path == "api" or path.startswith("api/"):
                raise ApiError(404, "not_found", "Resource not found.")
            candidate = (root / path).resolve()
            if path and root in candidate.parents and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})

    return app


def app_factory() -> FastAPI:  # for `uvicorn app.main:app_factory --factory`
    return create_app()
