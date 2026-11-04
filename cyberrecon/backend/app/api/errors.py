from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("cyberrecon.api")


class ApiError(HTTPException):
    """HTTPException with a stable machine-readable ``code``."""

    def __init__(self, status: int, code: str, message: str, headers: dict | None = None, **extra):
        super().__init__(status_code=status, detail={"code": code, "message": message, **extra}, headers=headers)


def _body(code: str, message: str, **extra) -> dict:
    return {"error": {"code": code, "message": message, **extra}}


def install(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exc(_req: Request, exc: StarletteHTTPException):
        d = exc.detail
        if isinstance(d, dict) and "code" in d:
            return JSONResponse(_body(**d), status_code=exc.status_code, headers=getattr(exc, "headers", None))
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        return JSONResponse(_body(codes.get(exc.status_code, "http_error"), str(d) if exc.status_code != 404 else "Resource not found."), status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation(_req: Request, exc: RequestValidationError):
        fields = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]} for e in exc.errors()[:10]]
        return JSONResponse(_body("invalid_request", "The request is invalid: " + "; ".join(f"{f['field'] or 'body'}: {f['message']}" for f in fields), fields=fields), status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(_req: Request, exc: Exception):
        log.exception("unhandled error")
        return JSONResponse(_body("internal_error", "An unexpected internal error occurred."), status_code=500)
