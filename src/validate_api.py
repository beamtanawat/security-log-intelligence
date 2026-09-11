"""Controlled Stage 1.6F validation for one existing local findings store.

The validator is deliberately separate from the API server.  It reads only the
configured Stage 1.5 database and its approved Stage 1.4 finding/summary
artifacts, starts one owned loopback launcher process, and verifies that all
observed inputs remain byte-for-byte unchanged afterwards.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from urllib.parse import urlencode

from fastapi.testclient import TestClient
from storage import (
    ApprovedArtifactIdentity,
    FindingQuery,
    StorageAuditError,
    StorageContractError,
    StorageInputValidationError,
    StorageQueryError,
    audit_detection_store,
    list_findings,
    validate_detection_artifacts,
)

from api import ApiSettings, ApiSettingsError, create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"
LAUNCHER_PATH = PROJECT_ROOT / "src" / "serve_api.py"
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
MAX_VALIDATION_FINDINGS = 500
MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024
_PROCESS_TIMEOUT_SECONDS = 5.0


class ValidationError(RuntimeError):
    """A bounded reason why final API validation cannot safely pass."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ValidationOptions:
    """Explicit operator inputs for one local Stage 1.6F validation run."""

    settings: ApiSettings
    summary_output: Path | None


@dataclass(frozen=True)
class FileIntegrity:
    """The size and SHA-256 of one immutable validation input."""

    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, int | str]:
        return {"file_size_bytes": self.size_bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class HttpResponse:
    """A minimal transport-neutral HTTP response used by both validation paths."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class ApiContractResult:
    """Bounded aggregate results from one complete API contract check."""

    finding_count: int
    evidence_count: int
    unique_source_record_count: int
    endpoint_checks: Mapping[str, str]
    http_safety_checks: Mapping[str, str]
    body_sha256: Mapping[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_count": self.finding_count,
            "evidence_count": self.evidence_count,
            "unique_source_record_count": self.unique_source_record_count,
            "endpoint_checks": dict(self.endpoint_checks),
            "http_safety_checks": dict(self.http_safety_checks),
            "body_sha256": dict(self.body_sha256),
        }


HttpRequester = Callable[[str, str, Mapping[str, str] | None], HttpResponse]


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the local read-only findings API against one existing store."
    )
    parser.add_argument("--database", required=True, type=Path, metavar="PATH")
    parser.add_argument("--findings", required=True, type=Path, metavar="PATH")
    parser.add_argument("--summary", required=True, type=Path, metavar="PATH")
    parser.add_argument("--expected-run-id", required=True, metavar="SHA256")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, metavar="PORT")
    parser.add_argument("--summary-output", type=Path, metavar="PATH")
    return parser


def parse_options(argv: Sequence[str] | None = None) -> ValidationOptions:
    """Parse explicit, side-effect-free validator configuration."""

    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = ApiSettings(
            database_path=arguments.database,
            findings_path=arguments.findings,
            summary_path=arguments.summary,
            expected_run_id=arguments.expected_run_id,
            port=arguments.port,
        )
    except ApiSettingsError as error:
        parser.error(str(error))
        raise AssertionError("argparse.error must exit") from error
    return ValidationOptions(settings=settings, summary_output=arguments.summary_output)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: object, *, newline: bool = False) -> bytes:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encoded + (b"\n" if newline else b"")


def _relative_processed_path(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as error:
        raise ValidationError(
            "INVALID_STORAGE_PATH", "Validation inputs must remain under the repository."
        ) from error


def _resolve_input_path(path: Path, label: str) -> Path:
    """Resolve one existing regular input without following it outside processed data."""

    try:
        processed_directory = PROCESSED_DATA_DIRECTORY.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValidationError("MISSING_INPUT", f"The configured {label} is unavailable.") from error
    if not processed_directory.is_dir() or not resolved_path.is_relative_to(processed_directory):
        raise ValidationError(
            "INVALID_STORAGE_PATH", "Validation inputs must be existing processed-data files."
        )
    if not resolved_path.is_file():
        raise ValidationError("MISSING_INPUT", f"The configured {label} is unavailable.")
    return resolved_path


def _resolve_inputs(settings: ApiSettings) -> tuple[Path, Path, Path]:
    database_path = _resolve_input_path(settings.database_path, "database")
    findings_path = _resolve_input_path(settings.findings_path, "findings artifact")
    summary_path = _resolve_input_path(settings.summary_path, "summary artifact")
    if len({database_path, findings_path, summary_path}) != 3:
        raise ValidationError("INPUT_PATH_ALIAS", "Database and artifact inputs must be distinct.")
    return database_path, findings_path, summary_path


def _file_integrity(path: Path) -> FileIntegrity:
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size_bytes += len(chunk)
                digest.update(chunk)
    except OSError as error:
        raise ValidationError("INPUT_UNREADABLE", "A configured validation input is unreadable.") from error
    return FileIntegrity(size_bytes=size_bytes, sha256=digest.hexdigest())


def _sidecar_paths(database_path: Path) -> tuple[Path, ...]:
    return tuple(
        database_path.with_name(database_path.name + suffix)
        for suffix in ("-journal", "-wal", "-shm")
    )


def _require_no_sidecars(database_path: Path) -> None:
    if any(path.exists() or path.is_symlink() for path in _sidecar_paths(database_path)):
        raise ValidationError(
            "SQLITE_SIDECAR_PRESENT", "SQLite sidecar files are not permitted for this validation."
        )


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ValidationError(code, message)


def _json_body(response: HttpResponse, *, label: str) -> object:
    _require(
        len(response.body) <= MAX_RESPONSE_BODY_BYTES,
        "RESPONSE_BUDGET_FAILURE",
        f"The {label} response exceeded the approved body budget.",
    )
    try:
        return json.loads(response.body)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValidationError("INVALID_API_JSON", f"The {label} response was not valid JSON.") from error


def _require_application_headers(response: HttpResponse, *, label: str) -> None:
    headers = {name.lower(): value for name, value in response.headers.items()}
    _require(
        headers.get("cache-control") == "no-store",
        "MISSING_SECURITY_HEADER",
        f"The {label} response did not preserve Cache-Control.",
    )
    _require(
        headers.get("x-content-type-options") == "nosniff",
        "MISSING_SECURITY_HEADER",
        f"The {label} response did not preserve X-Content-Type-Options.",
    )


def _require_error(
    request: HttpRequester,
    method: str,
    target: str,
    *,
    status_code: int,
    code: str,
    headers: Mapping[str, str] | None = None,
) -> None:
    response = request(method, target, headers)
    _require(
        response.status_code == status_code,
        "HTTP_STATUS_MISMATCH",
        "A required negative HTTP result did not have the expected status.",
    )
    _require_application_headers(response, label="error")
    payload = _json_body(response, label="error")
    _require(
        isinstance(payload, dict)
        and isinstance(payload.get("error"), dict)
        and payload["error"].get("code") == code,
        "HTTP_ERROR_CONTRACT_MISMATCH",
        "A required negative HTTP result did not have the expected stable code.",
    )


def _request_target(path: str, query: Mapping[str, str] | None = None) -> str:
    if not query:
        return path
    return path + "?" + urlencode(query)


def _as_finding_payloads(expected_findings: Sequence[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
    payloads: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for finding in expected_findings:
        payload = dict(finding)
        finding_id = payload.get("finding_id")
        _require(
            isinstance(finding_id, str) and finding_id not in seen_ids,
            "SOURCE_FINDING_IDENTITY_FAILURE",
            "Validated source findings did not have unique identifiers.",
        )
        seen_ids.add(finding_id)
        payloads.append(payload)
    return tuple(payloads)


def _payload_values(payloads: Sequence[Mapping[str, object]], name: str) -> tuple[str, ...]:
    values: list[str] = []
    for payload in payloads:
        if name == "finding_id":
            value = payload.get("finding_id")
            candidates = (value,)
        elif name in {"rule_id", "rule_version", "severity"}:
            rule = payload.get("rule")
            _require(isinstance(rule, dict), "FINDING_SHAPE_FAILURE", "Finding rule data is invalid.")
            candidates = (rule.get({"rule_id": "rule_id", "rule_version": "version", "severity": "severity"}[name]),)
        elif name in {"source_type", "source_record_number"}:
            source_event = payload.get("source_event")
            _require(
                isinstance(source_event, dict),
                "FINDING_SHAPE_FAILURE",
                "Finding source-event data is invalid.",
            )
            candidates = (source_event.get(name),)
        elif name == "reason_code":
            candidates = (payload.get("reason_code"),)
        elif name == "evidence_path":
            evidence = payload.get("evidence")
            _require(isinstance(evidence, list), "FINDING_SHAPE_FAILURE", "Finding evidence is invalid.")
            candidates = tuple(
                item.get("canonical_path")
                for item in evidence
                if isinstance(item, dict)
            )
        else:
            raise AssertionError(f"Unsupported filter: {name}")
        for candidate in candidates:
            _require(
                isinstance(candidate, (str, int)),
                "FINDING_SHAPE_FAILURE",
                "A supported filter value was missing from a source finding.",
            )
            text = str(candidate)
            if text not in values:
                values.append(text)
    return tuple(values)


def _matches_filter(payload: Mapping[str, object], name: str, value: str) -> bool:
    if name == "finding_id":
        return payload.get("finding_id") == value
    if name in {"rule_id", "rule_version", "severity"}:
        rule = payload.get("rule")
        if not isinstance(rule, dict):
            return False
        key = {"rule_id": "rule_id", "rule_version": "version", "severity": "severity"}[name]
        return rule.get(key) == value
    if name in {"source_type", "source_record_number"}:
        source_event = payload.get("source_event")
        if not isinstance(source_event, dict):
            return False
        return str(source_event.get(name)) == value
    if name == "reason_code":
        return payload.get("reason_code") == value
    if name == "evidence_path":
        evidence = payload.get("evidence")
        return isinstance(evidence, list) and any(
            isinstance(item, dict) and item.get("canonical_path") == value
            for item in evidence
        )
    raise AssertionError(f"Unsupported filter: {name}")


def _unknown_identifier(existing: set[str]) -> str:
    for character in "fedcba9876543210":
        candidate = character * 64
        if candidate not in existing:
            return candidate
    raise ValidationError("IDENTIFIER_TEST_SETUP_FAILURE", "No synthetic unknown identifier was available.")


def _check_list_payload(
    response: HttpResponse,
    *,
    run_id: str,
    limit: int,
    expected_items: Sequence[Mapping[str, object]],
    label: str,
) -> dict[str, object]:
    _require(response.status_code == 200, "HTTP_STATUS_MISMATCH", f"The {label} list did not succeed.")
    _require_application_headers(response, label=label)
    payload = _json_body(response, label=label)
    _require(isinstance(payload, dict), "LIST_SHAPE_FAILURE", "A list response was not an object.")
    _require(
        set(payload) == {"api_version", "run_id", "limit", "returned_count", "items"},
        "LIST_SHAPE_FAILURE",
        "A list response did not preserve its exact envelope.",
    )
    _require(
        payload.get("api_version") == "1.0"
        and payload.get("run_id") == run_id
        and payload.get("limit") == limit
        and payload.get("returned_count") == len(expected_items)
        and payload.get("items") == list(expected_items),
        "LIST_RECONCILIATION_FAILURE",
        "A list response did not preserve the approved finding payloads.",
    )
    return payload


def validate_http_contract(
    request: HttpRequester,
    *,
    run_id: str,
    expected_findings: Sequence[Mapping[str, object]],
    audit_result: object,
) -> ApiContractResult:
    """Validate every supported read-only API behavior using one transport.

    The caller supplies either TestClient transport or an actual loopback HTTP
    transport.  This keeps the exact reconciliation and safety assertions shared
    while ensuring the final validation exercises both paths.
    """

    payloads = _as_finding_payloads(expected_findings)
    finding_count = getattr(audit_result, "finding_count", None)
    evidence_count = getattr(audit_result, "evidence_count", None)
    source_hash = getattr(audit_result, "findings_sha256", None)
    _require(
        isinstance(finding_count, int)
        and isinstance(evidence_count, int)
        and isinstance(source_hash, str),
        "AUDIT_RESULT_FAILURE",
        "The storage audit result was not usable for API validation.",
    )
    _require(
        len(payloads) == finding_count <= MAX_VALIDATION_FINDINGS,
        "VALIDATION_RESULT_LIMIT",
        "The configured run exceeds the approved bounded final-validation limit.",
    )
    base_path = f"/api/v1/runs/{run_id}/findings"

    health = request("GET", "/healthz", None)
    _require(health.status_code == 200, "HTTP_STATUS_MISMATCH", "Health did not report ready.")
    _require_application_headers(health, label="health")
    health_payload = _json_body(health, label="health")
    _require(
        isinstance(health_payload, dict)
        and health_payload.get("api_version") == "1.0"
        and health_payload.get("status") == "ready"
        and isinstance(health_payload.get("storage_schema_version"), str),
        "HEALTH_CONTRACT_MISMATCH",
        "Health did not preserve the approved readiness shape.",
    )

    default_response = request("GET", base_path, None)
    default_expected = payloads[:50]
    _check_list_payload(
        default_response,
        run_id=run_id,
        limit=50,
        expected_items=default_expected,
        label="default",
    )
    repeated_default = request("GET", base_path, None)
    _require(
        repeated_default.status_code == 200 and repeated_default.body == default_response.body,
        "RESPONSE_DETERMINISM_FAILURE",
        "Repeated list responses were not byte-stable.",
    )

    full_response = request("GET", _request_target(base_path, {"limit": "500"}), None)
    full_payload = _check_list_payload(
        full_response,
        run_id=run_id,
        limit=500,
        expected_items=payloads,
        label="full",
    )
    reconstructed_bytes = b"".join(
        _canonical_json_bytes(item, newline=True) for item in full_payload["items"]
    )
    _require(
        _sha256_bytes(reconstructed_bytes) == source_hash,
        "FINDING_SERIALIZATION_FAILURE",
        "API findings did not reconstruct the approved finding artifact identity.",
    )

    source_numbers: set[int] = set()
    evidence_total = 0
    for payload in payloads:
        source_event = payload.get("source_event")
        evidence = payload.get("evidence")
        _require(
            isinstance(source_event, dict)
            and isinstance(source_event.get("source_record_number"), int)
            and isinstance(evidence, list),
            "FINDING_SHAPE_FAILURE",
            "A finding did not preserve source provenance or evidence.",
        )
        source_numbers.add(source_event["source_record_number"])
        evidence_total += len(evidence)
    _require(
        evidence_total == evidence_count,
        "EVIDENCE_RECONCILIATION_FAILURE",
        "API findings did not preserve the audited evidence count.",
    )

    for payload in payloads:
        finding_id = payload["finding_id"]
        assert isinstance(finding_id, str)
        response = request("GET", f"{base_path}/{finding_id}", None)
        _require(response.status_code == 200, "HTTP_STATUS_MISMATCH", "Finding detail did not succeed.")
        _require_application_headers(response, label="detail")
        detail_payload = _json_body(response, label="detail")
        _require(
            isinstance(detail_payload, dict)
            and set(detail_payload) == {"api_version", "run_id", "finding"}
            and detail_payload.get("api_version") == "1.0"
            and detail_payload.get("run_id") == run_id
            and detail_payload.get("finding") == payload,
            "DETAIL_RECONCILIATION_FAILURE",
            "A finding detail response did not preserve its canonical finding.",
        )

    for filter_name in (
        "finding_id",
        "rule_id",
        "rule_version",
        "severity",
        "reason_code",
        "source_type",
        "source_record_number",
        "evidence_path",
    ):
        for value in _payload_values(payloads, filter_name):
            expected = tuple(
                payload for payload in payloads if _matches_filter(payload, filter_name, value)
            )
            response = request(
                "GET",
                _request_target(base_path, {filter_name: value, "limit": "500"}),
                None,
            )
            _check_list_payload(
                response,
                run_id=run_id,
                limit=500,
                expected_items=expected,
                label="filtered",
            )

    limited_response = request("GET", _request_target(base_path, {"limit": "1"}), None)
    _check_list_payload(
        limited_response,
        run_id=run_id,
        limit=1,
        expected_items=payloads[:1],
        label="limited",
    )
    no_match_response = request(
        "GET",
        _request_target(base_path, {"rule_id": "fortigate.unmatched_observation", "limit": "500"}),
        None,
    )
    _check_list_payload(
        no_match_response,
        run_id=run_id,
        limit=500,
        expected_items=(),
        label="no-match",
    )

    openapi_response = request("GET", "/openapi.json", None)
    _require(openapi_response.status_code == 200, "HTTP_STATUS_MISMATCH", "OpenAPI did not succeed.")
    _require_application_headers(openapi_response, label="openapi")
    openapi_payload = _json_body(openapi_response, label="openapi")
    _require(
        isinstance(openapi_payload, dict)
        and isinstance(openapi_payload.get("paths"), dict)
        and set(openapi_payload["paths"])
        == {
            "/healthz",
            "/api/v1/runs/{run_id}/findings",
            "/api/v1/runs/{run_id}/findings/{finding_id}",
        },
        "OPENAPI_SCOPE_FAILURE",
        "OpenAPI exposed a route outside the approved API surface.",
    )

    existing_ids = {payload["finding_id"] for payload in payloads if isinstance(payload.get("finding_id"), str)}
    unknown_identifier = _unknown_identifier(existing_ids | {run_id})
    _require_error(request, "GET", f"/api/v1/runs/{unknown_identifier}/findings", status_code=404, code="RUN_NOT_FOUND")
    _require_error(request, "GET", f"{base_path}/{unknown_identifier}", status_code=404, code="FINDING_NOT_FOUND")
    _require_error(request, "GET", _request_target(base_path, {"limit": "0"}), status_code=422, code="INVALID_REQUEST")
    _require_error(request, "GET", _request_target(base_path, {"unknown": "value"}), status_code=422, code="INVALID_REQUEST")
    _require_error(request, "GET", base_path + "?limit=1&limit=2", status_code=422, code="INVALID_REQUEST")
    _require_error(request, "GET", "/healthz", status_code=403, code="ORIGIN_NOT_ALLOWED", headers={"Origin": ""})
    _require_error(request, "POST", "/healthz", status_code=405, code="METHOD_NOT_ALLOWED")
    _require_error(request, "GET", "/" + ("x" * 4_096), status_code=414, code="REQUEST_TARGET_TOO_LONG")

    hostile_host = request("GET", "/healthz", {"Host": "hostile.invalid"})
    _require(
        hostile_host.status_code == 400,
        "HOST_POLICY_FAILURE",
        "The API did not reject a hostile Host header.",
    )

    return ApiContractResult(
        finding_count=len(payloads),
        evidence_count=evidence_total,
        unique_source_record_count=len(source_numbers),
        endpoint_checks={
            "health": "PASS",
            "findings": "PASS",
            "detail": "PASS",
            "openapi": "PASS",
        },
        http_safety_checks={
            "invalid_request": "PASS",
            "origin_rejection": "PASS",
            "method_rejection": "PASS",
            "request_target_limit": "PASS",
            "host_rejection": "PASS",
        },
        body_sha256={
            "health": _sha256_bytes(health.body),
            "default_findings": _sha256_bytes(default_response.body),
            "full_findings": _sha256_bytes(full_response.body),
            "openapi": _sha256_bytes(openapi_response.body),
        },
    )


def _testclient_requester(client: TestClient) -> HttpRequester:
    def request(
        method: str,
        target: str,
        headers: Mapping[str, str] | None,
    ) -> HttpResponse:
        response = client.request(method, target, headers=dict(headers or {}))
        return HttpResponse(
            status_code=response.status_code,
            headers={name.lower(): value for name, value in response.headers.items()},
            body=response.content,
        )

    return request


def _loopback_requester(port: int) -> HttpRequester:
    def request(
        method: str,
        target: str,
        headers: Mapping[str, str] | None,
    ) -> HttpResponse:
        connection = HTTPConnection(LOOPBACK_HOST, port, timeout=2)
        try:
            request_headers = {"Host": LOOPBACK_HOST}
            request_headers.update(headers or {})
            connection.request(method, target, headers=request_headers)
            response = connection.getresponse()
            return HttpResponse(
                status_code=response.status,
                headers={name.lower(): value for name, value in response.getheaders()},
                body=response.read(MAX_RESPONSE_BODY_BYTES + 1),
            )
        except OSError as error:
            raise ValidationError("LOOPBACK_REQUEST_FAILED", "The owned local API was unavailable.") from error
        finally:
            connection.close()

    return request


def _validated_source_findings(
    findings_path: Path,
    summary_path: Path,
    audit_result: object,
) -> tuple[dict[str, object], ...]:
    findings_sha256 = getattr(audit_result, "findings_sha256", None)
    summary_sha256 = getattr(audit_result, "summary_sha256", None)
    _require(
        isinstance(findings_sha256, str) and isinstance(summary_sha256, str),
        "AUDIT_RESULT_FAILURE",
        "The storage audit did not provide approved artifact identities.",
    )
    payloads: list[dict[str, object]] = []

    def collect(finding: object) -> None:
        to_dict = getattr(finding, "to_dict", None)
        _require(callable(to_dict), "SOURCE_FINDING_SHAPE_FAILURE", "A source finding was invalid.")
        payload = to_dict()
        _require(isinstance(payload, dict), "SOURCE_FINDING_SHAPE_FAILURE", "A source finding was invalid.")
        payloads.append(payload)

    try:
        validated = validate_detection_artifacts(
            findings_path,
            summary_path,
            ApprovedArtifactIdentity(findings_sha256, summary_sha256),
            on_finding=collect,
        )
    except (StorageInputValidationError, StorageContractError, OSError) as error:
        raise ValidationError("ARTIFACT_VALIDATION_FAILED", "Approved finding artifacts could not be validated.") from error
    for name in ("run_id", "findings_sha256", "summary_sha256", "finding_count", "evidence_count", "rule_count"):
        _require(
            getattr(validated, name) == getattr(audit_result, name),
            "ARTIFACT_RECONCILIATION_FAILURE",
            "Approved artifacts did not reconcile to the read-only store audit.",
        )
    return _as_finding_payloads(payloads)


def _validate_storage_projection(
    database_path: Path,
    *,
    run_id: str,
    expected_findings: Sequence[Mapping[str, object]],
) -> None:
    """Confirm the public read-only query result equals the source payloads."""

    try:
        stored = list_findings(database_path, FindingQuery(run_id=run_id, limit=500))
    except (StorageContractError, StorageQueryError, OSError) as error:
        raise ValidationError("STORAGE_QUERY_FAILED", "The validated storage query was unavailable.") from error
    _require(
        len(stored) == len(expected_findings),
        "STORAGE_FINDING_COUNT_MISMATCH",
        "The storage query did not return every approved finding.",
    )
    payloads: list[dict[str, object]] = []
    for stored_finding in stored:
        try:
            payload = json.loads(stored_finding.canonical_finding_json)
        except (TypeError, json.JSONDecodeError) as error:
            raise ValidationError("STORAGE_CANONICAL_JSON_FAILURE", "A stored finding could not be decoded.") from error
        _require(isinstance(payload, dict), "STORAGE_CANONICAL_JSON_FAILURE", "A stored finding was not an object.")
        payloads.append(payload)
    _require(
        tuple(payloads) == tuple(expected_findings),
        "STORAGE_SOURCE_RECONCILIATION_FAILURE",
        "The read-only storage projection differed from approved source findings.",
    )


def _start_launcher(settings: ApiSettings) -> subprocess.Popen[bytes]:
    command = [
        str(Path(sys.executable)),
        str(LAUNCHER_PATH),
        "--database",
        str(settings.database_path),
        "--findings",
        str(settings.findings_path),
        "--summary",
        str(settings.summary_path),
        "--expected-run-id",
        settings.expected_run_id,
        "--port",
        str(settings.port),
    ]
    try:
        return subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as error:
        raise ValidationError("LAUNCHER_START_FAILED", "The owned local API launcher could not start.") from error


def _wait_for_ready(process: subprocess.Popen[bytes], port: int) -> None:
    request = _loopback_requester(port)
    deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValidationError("LAUNCHER_STARTUP_FAILED", "The owned local API exited before readiness.")
        try:
            response = request("GET", "/healthz", None)
        except ValidationError:
            time.sleep(0.05)
            continue
        if response.status_code == 200:
            return
        raise ValidationError("LAUNCHER_STARTUP_FAILED", "The owned local API did not become ready.")
    raise ValidationError("LAUNCHER_STARTUP_TIMEOUT", "The owned local API did not start before the deadline.")


def _require_port_closed(port: int) -> None:
    deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((LOOPBACK_HOST, port), timeout=0.2):
                pass
        except OSError:
            return
        time.sleep(0.05)
    raise ValidationError("LOOPBACK_PORT_REMAINS_OPEN", "The owned local API port remained open after cleanup.")


def _stop_owned_launcher(process: subprocess.Popen[bytes], port: int) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise ValidationError("LAUNCHER_CLEANUP_FAILED", "The owned local API process did not stop.") from error
    _require_port_closed(port)


def _validate_loopback(
    settings: ApiSettings,
    expected_findings: Sequence[Mapping[str, object]],
    audit_result: object,
) -> ApiContractResult:
    process = _start_launcher(settings)
    validation_error: BaseException | None = None
    try:
        _wait_for_ready(process, settings.port)
        return validate_http_contract(
            _loopback_requester(settings.port),
            run_id=settings.expected_run_id,
            expected_findings=expected_findings,
            audit_result=audit_result,
        )
    except BaseException as error:
        validation_error = error
        raise
    finally:
        try:
            _stop_owned_launcher(process, settings.port)
        except ValidationError:
            if validation_error is None:
                raise


def _validate_in_process(
    settings: ApiSettings,
    expected_findings: Sequence[Mapping[str, object]],
    audit_result: object,
) -> ApiContractResult:
    application = create_app(settings)
    with TestClient(application, base_url=f"http://{LOOPBACK_HOST}") as client:
        return validate_http_contract(
            _testclient_requester(client),
            run_id=settings.expected_run_id,
            expected_findings=expected_findings,
            audit_result=audit_result,
        )


def _require_matching_transport_hashes(
    in_process: ApiContractResult,
    loopback: ApiContractResult,
) -> None:
    """Require identical final response identities from both validation transports."""

    _require(
        in_process.body_sha256 == loopback.body_sha256,
        "TRANSPORT_RESPONSE_HASH_MISMATCH",
        "In-process and real-loopback response identities did not match.",
    )


def _require_integrity_unchanged(
    before: Mapping[str, FileIntegrity],
    after: Mapping[str, FileIntegrity],
) -> None:
    _require(
        before == after,
        "READ_ONLY_INTEGRITY_FAILURE",
        "An approved validation input changed during API validation.",
    )


def _audit_store(database_path: Path) -> object:
    try:
        return audit_detection_store(database_path)
    except (StorageAuditError, StorageContractError, StorageQueryError, OSError) as error:
        raise ValidationError("STORE_AUDIT_FAILED", "The configured storage audit did not pass.") from error


def run_validation(options: ValidationOptions) -> dict[str, object]:
    """Run the complete Stage 1.6F validation without mutating source inputs."""

    database_path, findings_path, summary_path = _resolve_inputs(options.settings)
    _require_no_sidecars(database_path)
    before = {
        "database": _file_integrity(database_path),
        "findings": _file_integrity(findings_path),
        "summary": _file_integrity(summary_path),
    }
    before_audit = _audit_store(database_path)
    _require(
        getattr(before_audit, "run_id", None) == options.settings.expected_run_id,
        "RUN_ID_MISMATCH",
        "The configured run ID did not match the audited store.",
    )
    expected_findings = _validated_source_findings(findings_path, summary_path, before_audit)
    _validate_storage_projection(
        database_path,
        run_id=options.settings.expected_run_id,
        expected_findings=expected_findings,
    )

    in_process = _validate_in_process(options.settings, expected_findings, before_audit)
    loopback = _validate_loopback(options.settings, expected_findings, before_audit)
    _require_matching_transport_hashes(in_process, loopback)

    after_audit = _audit_store(database_path)
    after = {
        "database": _file_integrity(database_path),
        "findings": _file_integrity(findings_path),
        "summary": _file_integrity(summary_path),
    }
    _require_no_sidecars(database_path)
    _require_integrity_unchanged(before, after)
    _require(
        before_audit == after_audit,
        "STORE_AUDIT_CHANGED",
        "The read-only store audit changed during API validation.",
    )

    return {
        "validation_stage": "1.6F",
        "verdict": "PASS",
        "run_identity": {
            "run_id": options.settings.expected_run_id,
            "findings_sha256": getattr(before_audit, "findings_sha256"),
            "summary_sha256": getattr(before_audit, "summary_sha256"),
            "logical_export_sha256": getattr(before_audit, "logical_export_sha256"),
        },
        "inputs": {
            "database": {"path": _relative_processed_path(database_path), **before["database"].to_dict()},
            "findings": {"path": _relative_processed_path(findings_path), **before["findings"].to_dict()},
            "summary": {"path": _relative_processed_path(summary_path), **before["summary"].to_dict()},
        },
        "reconciliation": {
            "finding_count": in_process.finding_count,
            "evidence_count": in_process.evidence_count,
            "unique_source_record_count": in_process.unique_source_record_count,
            "rule_count": getattr(before_audit, "rule_count"),
        },
        "in_process": in_process.to_dict(),
        "real_loopback": {"host": LOOPBACK_HOST, "port": options.settings.port, **loopback.to_dict()},
        "read_only_integrity": {
            "database": "UNCHANGED",
            "findings": "UNCHANGED",
            "summary": "UNCHANGED",
            "sqlite_sidecars": "ABSENT",
        },
        "cleanup": "PASS",
        "security_interpretation": (
            "Findings are informational deterministic rule observations, not confirmed attacks, "
            "malicious activity, compromise, or incidents."
        ),
    }


def publish_validation_summary(
    summary_path: Path,
    report: Mapping[str, object],
    *,
    processed_directory: Path = PROCESSED_DATA_DIRECTORY,
) -> None:
    """Publish one new optional report without overwriting an earlier result."""

    try:
        resolved_directory = processed_directory.resolve(strict=True)
        resolved_path = summary_path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ValidationError("SUMMARY_OUTPUT_INVALID", "The requested summary output is invalid.") from error
    _require(
        resolved_directory.is_dir() and resolved_path.is_relative_to(resolved_directory),
        "SUMMARY_OUTPUT_INVALID",
        "The optional summary output must be under processed data.",
    )
    _require(
        resolved_path.parent.is_dir(),
        "SUMMARY_OUTPUT_INVALID",
        "The optional summary output directory is unavailable.",
    )
    _require(
        not resolved_path.exists() and not resolved_path.is_symlink(),
        "SUMMARY_OUTPUT_EXISTS",
        "The optional summary output already exists and will not be overwritten.",
    )
    content = _canonical_json_bytes(dict(report), newline=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".stage_1_6f_",
        suffix=".tmp",
        dir=resolved_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        try:
            os.link(temporary_path, resolved_path)
        except FileExistsError as error:
            raise ValidationError(
                "SUMMARY_OUTPUT_EXISTS",
                "The optional summary output already exists and will not be overwritten.",
            ) from error
        except OSError as error:
            raise ValidationError(
                "SUMMARY_OUTPUT_PUBLICATION_FAILED",
                "The optional summary output could not be published safely.",
            ) from error
    finally:
        if temporary_path.exists() or temporary_path.is_symlink():
            temporary_path.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    """Run validation and emit only a bounded aggregate report or stable failure code."""

    options = parse_options(argv)
    try:
        report = run_validation(options)
        if options.summary_output is not None:
            publish_validation_summary(options.summary_output, report)
    except ValidationError as error:
        print(f"API_VALIDATION_FAILED:{error.code}", file=sys.stderr)
        return 1
    except Exception:
        print("API_VALIDATION_FAILED:VALIDATOR_INTERNAL_ERROR", file=sys.stderr)
        return 1
    print(_canonical_json_bytes(report).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
