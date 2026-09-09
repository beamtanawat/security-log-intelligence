"""Read-only FastAPI factory for the Stage 1.6C readiness and findings boundary."""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
import re
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import Response
from storage import (
    MAX_QUERY_LIMIT,
    FindingQuery,
    StorageContractError,
    StorageQueryError,
    StoredFinding,
    get_finding,
    list_findings,
)

from .bridge import ApiStartupError, ReadinessSnapshot, require_current_store, verify_startup_store
from .settings import ApiSettings


API_VERSION = "1.0"
_IDENTIFIER_PATTERN = re.compile(r"[0-9a-f]{64}")
_RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_RULE_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
_REASON_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
_MAX_TEXT_FILTER_LENGTH = 256
_MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
_QUERY_FIELDS = frozenset(
    {
        "finding_id",
        "rule_id",
        "rule_version",
        "severity",
        "reason_code",
        "source_type",
        "source_record_number",
        "evidence_path",
        "limit",
    }
)
_TEXT_FILTER_FIELDS = frozenset({"source_type", "evidence_path"})


class _InvalidRequest(ValueError):
    """Raised internally for one deterministic API request-validation failure."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        self.fields = fields
        super().__init__("Request parameters are invalid.")


class _UnavailableStoredFinding(RuntimeError):
    """Raised when a public storage result cannot be safely published."""


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


def _error_response(
    status_code: int,
    code: str,
    fields: tuple[str, ...],
    message: str,
) -> Response:
    """Return the approved compact application-error envelope."""

    return _json_response(
        {"error": {"code": code, "fields": list(fields), "message": message}},
        status_code=status_code,
    )


def _invalid_request_response(fields: tuple[str, ...]) -> Response:
    return _error_response(
        422,
        "INVALID_REQUEST",
        fields,
        "Request parameters are invalid.",
    )


def _validate_identifier(value: str, field: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise _InvalidRequest((field,))


def _validate_text_filter(value: str, field: str) -> str:
    if not value.strip() or len(value) > _MAX_TEXT_FILTER_LENGTH:
        raise _InvalidRequest((field,))
    return value


def _parse_positive_decimal(value: str, field: str, maximum: int) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise _InvalidRequest((field,))
    parsed = int(value)
    if not 1 <= parsed <= maximum:
        raise _InvalidRequest((field,))
    return parsed


def _validate_filter_value(name: str, value: str) -> str | int:
    field = f"query.{name}"
    if name == "finding_id":
        _validate_identifier(value, field)
        return value
    if name == "rule_id":
        if len(value) > _MAX_TEXT_FILTER_LENGTH or _RULE_ID_PATTERN.fullmatch(value) is None:
            raise _InvalidRequest((field,))
        return value
    if name == "rule_version":
        if len(value) > _MAX_TEXT_FILTER_LENGTH or _RULE_VERSION_PATTERN.fullmatch(value) is None:
            raise _InvalidRequest((field,))
        return value
    if name == "severity":
        if not value or len(value) > _MAX_TEXT_FILTER_LENGTH:
            raise _InvalidRequest((field,))
        return value
    if name == "reason_code":
        if len(value) > _MAX_TEXT_FILTER_LENGTH or _REASON_CODE_PATTERN.fullmatch(value) is None:
            raise _InvalidRequest((field,))
        return value
    if name in _TEXT_FILTER_FIELDS:
        return _validate_text_filter(value, field)
    if name == "source_record_number":
        return _parse_positive_decimal(value, field, _MAX_SQLITE_INTEGER)
    if name == "limit":
        return _parse_positive_decimal(value, field, MAX_QUERY_LIMIT)
    raise _InvalidRequest(("query",))


def _validated_finding_query(request: Request, run_id: str) -> FindingQuery:
    """Translate exact allowlisted filters into a query fixed to one audited run."""

    values: dict[str, str | int] = {}
    for name, value in request.query_params.multi_items():
        if name not in _QUERY_FIELDS or name in values:
            raise _InvalidRequest(("query",))
        values[name] = _validate_filter_value(name, value)
    try:
        return FindingQuery(run_id=run_id, **values)
    except StorageContractError as error:
        raise _InvalidRequest(("query",)) from error


def _validate_detail_query(request: Request) -> None:
    if request.query_params.multi_items():
        raise _InvalidRequest(("query",))


def _complete_finding_payload(
    stored_finding: StoredFinding,
    snapshot: ReadinessSnapshot,
) -> dict[str, object]:
    """Decode already reconciled canonical JSON without rebuilding projections."""

    if stored_finding.run_id != snapshot.audited_run_id:
        raise _UnavailableStoredFinding("Stored finding run identity is inconsistent.")
    try:
        payload = json.loads(stored_finding.canonical_finding_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise _UnavailableStoredFinding("Stored finding cannot be published safely.") from error
    if not isinstance(payload, dict):
        raise _UnavailableStoredFinding("Stored finding cannot be published safely.")
    return payload


def _configured_snapshot(app: FastAPI) -> ReadinessSnapshot:
    return app.state.readiness_snapshot


def _store_unavailable_response() -> Response:
    return _error_response(
        503,
        "STORE_UNAVAILABLE",
        (),
        "The verified store is unavailable.",
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
    app.router.redirect_slashes = False

    @app.get("/healthz")
    def healthz() -> Response:
        snapshot = _configured_snapshot(app)
        try:
            require_current_store(settings, snapshot)
        except ApiStartupError:
            return _store_unavailable_response()
        return _json_response(
            {
                "api_version": API_VERSION,
                "status": "ready",
                "storage_schema_version": snapshot.storage_schema_version,
            }
        )

    @app.get("/api/v1/runs/{run_id}/findings")
    def findings(run_id: str, request: Request) -> Response:
        try:
            _validate_identifier(run_id, "path.run_id")
            snapshot = _configured_snapshot(app)
            if run_id != snapshot.audited_run_id:
                return _error_response(
                    404,
                    "RUN_NOT_FOUND",
                    (),
                    "The requested run is not available.",
                )
            query = _validated_finding_query(request, snapshot.audited_run_id)
        except _InvalidRequest as error:
            return _invalid_request_response(error.fields)

        try:
            require_current_store(settings, snapshot)
            stored_findings = list_findings(settings.database_path, query)
            items = [
                _complete_finding_payload(stored_finding, snapshot)
                for stored_finding in stored_findings
            ]
        except (
            ApiStartupError,
            StorageContractError,
            StorageQueryError,
            _UnavailableStoredFinding,
        ):
            return _store_unavailable_response()

        return _json_response(
            {
                "api_version": API_VERSION,
                "run_id": snapshot.audited_run_id,
                "limit": query.limit,
                "returned_count": len(items),
                "items": items,
            }
        )

    @app.get("/api/v1/runs/{run_id}/findings/{finding_id}")
    def finding_detail(run_id: str, finding_id: str, request: Request) -> Response:
        try:
            _validate_identifier(run_id, "path.run_id")
            _validate_identifier(finding_id, "path.finding_id")
            _validate_detail_query(request)
            snapshot = _configured_snapshot(app)
            if run_id != snapshot.audited_run_id:
                return _error_response(
                    404,
                    "RUN_NOT_FOUND",
                    (),
                    "The requested run is not available.",
                )
        except _InvalidRequest as error:
            return _invalid_request_response(error.fields)

        try:
            require_current_store(settings, snapshot)
            stored_finding = get_finding(settings.database_path, finding_id)
            if stored_finding is None:
                return _error_response(
                    404,
                    "FINDING_NOT_FOUND",
                    (),
                    "The requested finding is not available.",
                )
            finding = _complete_finding_payload(stored_finding, snapshot)
        except (
            ApiStartupError,
            StorageContractError,
            StorageQueryError,
            _UnavailableStoredFinding,
        ):
            return _store_unavailable_response()

        return _json_response(
            {
                "api_version": API_VERSION,
                "run_id": snapshot.audited_run_id,
                "finding": finding,
            }
        )

    return app
