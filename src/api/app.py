"""Read-only FastAPI factory for the Stage 1.6D bounded findings boundary."""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
import re
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from starlette.datastructures import QueryParams
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send
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
MAX_REQUEST_TARGET_BYTES = 4_096
MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024
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
_LOCAL_HOSTS = ("127.0.0.1", "localhost")
_NO_QUERY_PARAMETER_PATHS = frozenset({"/healthz", "/openapi.json"})
_APPLICATION_RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


class _InvalidRequest(ValueError):
    """Raised internally for one deterministic API request-validation failure."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        self.fields = fields
        super().__init__("Request parameters are invalid.")


class _UnavailableStoredFinding(RuntimeError):
    """Raised when a public storage result cannot be safely published."""


class _ResponseTooLarge(RuntimeError):
    """Raised before a complete response body would exceed the fixed budget."""


def _json_bytes(payload: object) -> bytes:
    """Serialize one application value using the fixed public JSON contract."""

    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _response_from_bytes(
    content: bytes,
    status_code: int = 200,
    *,
    headers: dict[str, str] | None = None,
) -> Response:
    """Publish already bounded application JSON with fixed safety headers."""

    response_headers = dict(headers or {})
    response_headers.update(_APPLICATION_RESPONSE_HEADERS)
    return Response(
        content=content,
        headers=response_headers,
        media_type="application/json",
        status_code=status_code,
    )


def _json_response(
    payload: object,
    status_code: int = 200,
    *,
    headers: dict[str, str] | None = None,
    enforce_response_budget: bool = True,
) -> Response:
    """Publish compact deterministic JSON without exposing local paths."""

    content = _json_bytes(payload)
    if enforce_response_budget and len(content) > MAX_RESPONSE_BODY_BYTES:
        return _result_too_large_response()
    return _response_from_bytes(content, status_code, headers=headers)


def _append_response_part(content: bytearray, part: bytes) -> None:
    """Append a serialized response part only when the whole body stays bounded."""

    if len(content) + len(part) > MAX_RESPONSE_BODY_BYTES:
        raise _ResponseTooLarge()
    content.extend(part)


def _list_response(
    snapshot: ReadinessSnapshot,
    query: FindingQuery,
    stored_findings: tuple[StoredFinding, ...],
) -> Response:
    """Build one complete bounded list response without creating an items list."""

    content = bytearray()
    _append_response_part(content, b'{"api_version":')
    _append_response_part(content, _json_bytes(API_VERSION))
    _append_response_part(content, b',"items":[')
    for index, stored_finding in enumerate(stored_findings):
        if index:
            _append_response_part(content, b",")
        item = _complete_finding_payload(stored_finding, snapshot)
        _append_response_part(content, _json_bytes(item))
    _append_response_part(content, b'],"limit":')
    _append_response_part(content, _json_bytes(query.limit))
    _append_response_part(content, b',"returned_count":')
    _append_response_part(content, _json_bytes(len(stored_findings)))
    _append_response_part(content, b',"run_id":')
    _append_response_part(content, _json_bytes(snapshot.audited_run_id))
    _append_response_part(content, b"}")
    return _response_from_bytes(bytes(content))


def _error_response(
    status_code: int,
    code: str,
    fields: tuple[str, ...],
    message: str,
    *,
    headers: dict[str, str] | None = None,
) -> Response:
    """Return the approved compact application-error envelope."""

    return _json_response(
        {"error": {"code": code, "fields": list(fields), "message": message}},
        status_code=status_code,
        headers=headers,
    )


def _invalid_request_response(fields: tuple[str, ...]) -> Response:
    return _error_response(
        422,
        "INVALID_REQUEST",
        fields,
        "Request parameters are invalid.",
    )


def _result_too_large_response() -> Response:
    return _json_response(
        {
            "error": {
                "code": "RESULT_TOO_LARGE",
                "fields": [],
                "message": "The response exceeds the allowed size.",
            }
        },
        status_code=422,
        enforce_response_budget=False,
    )


def _request_target_too_long_response() -> Response:
    return _error_response(
        414,
        "REQUEST_TARGET_TOO_LONG",
        (),
        "The request target is too long.",
    )


def _origin_not_allowed_response() -> Response:
    return _error_response(
        403,
        "ORIGIN_NOT_ALLOWED",
        (),
        "The request origin is not allowed.",
    )


def _not_found_response() -> Response:
    return _error_response(
        404,
        "NOT_FOUND",
        (),
        "The requested route is not available.",
    )


def _method_not_allowed_response(allow: str | None) -> Response:
    headers = {"Allow": allow} if allow else None
    return _error_response(
        405,
        "METHOD_NOT_ALLOWED",
        (),
        "The requested method is not allowed.",
        headers=headers,
    )


def _internal_error_response() -> Response:
    return _error_response(
        500,
        "INTERNAL_ERROR",
        (),
        "The request could not be completed.",
    )


def _request_target_bytes(scope: Scope) -> bytes:
    """Return the raw path and query bytes that form the HTTP request target."""

    raw_path = scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        raw_path = str(scope.get("path", "")).encode("utf-8")
    query_string = scope.get("query_string", b"")
    if not isinstance(query_string, bytes):
        query_string = b""
    if query_string:
        return raw_path + b"?" + query_string
    return raw_path


def _scope_has_header(scope: Scope, expected_name: bytes) -> bool:
    """Check header presence without interpreting client-controlled values."""

    return any(
        isinstance(name, bytes) and name.lower() == expected_name
        for name, _ in scope.get("headers", [])
    )


class _HttpSafetyMiddleware:
    """Reject unsafe HTTP input and sanitize unexpected application failures."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if len(_request_target_bytes(scope)) > MAX_REQUEST_TARGET_BYTES:
            await _request_target_too_long_response()(scope, receive, send)
            return
        if _scope_has_header(scope, b"origin"):
            await _origin_not_allowed_response()(scope, receive, send)
            return

        query_string = scope.get("query_string", b"")
        if (
            scope.get("path") in _NO_QUERY_PARAMETER_PATHS
            and isinstance(query_string, bytes)
            and QueryParams(query_string).multi_items()
        ):
            await _invalid_request_response(("query",))(scope, receive, send)
            return

        response_started = False

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, guarded_send)
        except Exception:
            if response_started:
                raise
            await _internal_error_response()(scope, receive, send)


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
        debug=False,
        docs_url=None,
        openapi_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.router.redirect_slashes = False
    app.add_middleware(_HttpSafetyMiddleware)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(_LOCAL_HOSTS),
        www_redirect=False,
    )

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(
        _request: Request,
        _error: RequestValidationError,
    ) -> Response:
        return _invalid_request_response(())

    @app.exception_handler(StarletteHTTPException)
    async def http_exception(
        _request: Request,
        error: StarletteHTTPException,
    ) -> Response:
        if error.status_code == 404:
            return _not_found_response()
        if error.status_code == 405:
            allow = None
            if error.headers:
                for name, value in error.headers.items():
                    if name.lower() == "allow":
                        allow = value
                        break
            return _method_not_allowed_response(allow)
        if error.status_code in {400, 422}:
            return _invalid_request_response(())
        return _internal_error_response()

    @app.api_route(
        "/openapi.json",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    def openapi_schema() -> Response:
        return _json_response(app.openapi())

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
            return _list_response(snapshot, query, stored_findings)
        except _ResponseTooLarge:
            return _result_too_large_response()
        except (
            ApiStartupError,
            StorageContractError,
            StorageQueryError,
            _UnavailableStoredFinding,
            OSError,
        ):
            return _store_unavailable_response()

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
            OSError,
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
