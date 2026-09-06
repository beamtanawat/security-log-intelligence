"""Minimal FastAPI application factory for the Stage 1.6B readiness boundary."""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import Response

from .bridge import ApiStartupError, ReadinessSnapshot, require_current_store, verify_startup_store
from .settings import ApiSettings


API_VERSION = "1.0"


def _json_response(payload: dict[str, object], status_code: int = 200) -> Response:
    """Publish compact, deterministic UTF-8 JSON without exposing local paths."""

    return Response(
        content=json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        media_type="application/json",
        status_code=status_code,
    )


def create_app(settings: ApiSettings) -> FastAPI:
    """Create an unstarted application for one explicitly configured store."""

    if not isinstance(settings, ApiSettings):
        raise TypeError("settings must be an ApiSettings")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        snapshot = verify_startup_store(settings)
        app.state.readiness_snapshot = snapshot
        try:
            yield
        finally:
            del app.state.readiness_snapshot

    app = FastAPI(
        title="Security Log Intelligence Read-Only API",
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/healthz")
    def healthz() -> Response:
        snapshot: ReadinessSnapshot = app.state.readiness_snapshot
        try:
            require_current_store(settings, snapshot)
        except ApiStartupError:
            return _json_response(
                {
                    "error": {
                        "code": "STORE_UNAVAILABLE",
                        "fields": [],
                        "message": "The verified store is unavailable.",
                    }
                },
                status_code=503,
            )
        return _json_response(
            {
                "api_version": API_VERSION,
                "status": "ready",
                "storage_schema_version": snapshot.storage_schema_version,
            }
        )

    return app
