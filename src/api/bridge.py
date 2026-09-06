"""Fail-closed lifecycle bridge to the approved public Stage 1.5 surface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from storage import (
    ApprovedArtifactIdentity,
    StorageAuditError,
    StorageContractError,
    StorageInputValidationError,
    StorageQueryError,
    audit_detection_store,
    get_detection_run,
    validate_detection_artifacts,
)

from .settings import ApiSettings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"
_NORMALIZED_EVENT_FILE_NAME = "stage_1_3f_normalized_events.jsonl"


class ApiStartupError(RuntimeError):
    """A sanitized reason why the configured local store is not usable."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class DatabaseFileIdentity:
    """Non-public local change-guard metadata for the verified database file."""

    device: int
    inode: int
    size_bytes: int
    modified_time_ns: int


@dataclass(frozen=True)
class ReadinessSnapshot:
    """Bounded metadata retained after a successful startup verification."""

    storage_schema_version: str
    finding_schema_version: str
    configured_run_id: str
    audited_run_id: str
    findings_sha256: str
    summary_sha256: str
    finding_count: int
    evidence_count: int
    rule_count: int
    logical_export_sha256: str
    reconstructed_findings_sha256: str
    database_identity: DatabaseFileIdentity


def _resolve_processed_file(path: Path, field_name: str) -> Path:
    """Resolve one operator path without allowing aliases outside processed data."""

    if str(path).lower().startswith("file:"):
        raise ApiStartupError(
            "INVALID_STORAGE_PATH", "Configured storage paths must not be SQLite URIs."
        )
    try:
        processed_directory = PROCESSED_DATA_DIRECTORY.resolve()
        resolved_path = path.resolve()
    except (OSError, RuntimeError) as error:
        raise ApiStartupError(
            "INVALID_STORAGE_PATH", "Configured storage paths cannot be resolved."
        ) from error

    if not processed_directory.is_dir():
        raise ApiStartupError(
            "PROCESSED_DIRECTORY_UNAVAILABLE",
            "The processed-data directory is unavailable.",
        )
    if not resolved_path.is_relative_to(processed_directory):
        raise ApiStartupError(
            "INVALID_STORAGE_PATH", "Configured storage paths must be in processed data."
        )
    if resolved_path.name == _NORMALIZED_EVENT_FILE_NAME:
        raise ApiStartupError(
            "UPSTREAM_ARTIFACT_FORBIDDEN",
            "Configured storage paths cannot refer to normalized-event input."
        )
    if not resolved_path.is_file():
        raise ApiStartupError(
            "MISSING_STORAGE_FILE", f"Configured {field_name} is not an existing file."
        )
    return resolved_path


def _resolve_startup_paths(settings: ApiSettings) -> tuple[Path, Path, Path]:
    database_path = _resolve_processed_file(settings.database_path, "database")
    findings_path = _resolve_processed_file(settings.findings_path, "findings")
    summary_path = _resolve_processed_file(settings.summary_path, "summary")
    if len({database_path, findings_path, summary_path}) != 3:
        raise ApiStartupError(
            "STORAGE_PATH_ALIAS", "Database and artifact paths must be distinct."
        )
    return database_path, findings_path, summary_path


def _database_file_identity(database_path: Path) -> DatabaseFileIdentity:
    """Capture a small identity without opening SQLite outside its public API."""

    try:
        metadata = database_path.stat()
    except OSError as error:
        raise ApiStartupError(
            "STORE_UNAVAILABLE", "The configured storage database is unavailable."
        ) from error
    return DatabaseFileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size_bytes=metadata.st_size,
        modified_time_ns=metadata.st_mtime_ns,
    )


def _raise_reconciliation_failure() -> None:
    raise ApiStartupError(
        "STORE_RECONCILIATION_FAILED",
        "Configured storage identities and bounded metadata do not reconcile.",
    )


def verify_startup_store(settings: ApiSettings) -> ReadinessSnapshot:
    """Audit and reconcile the configured store before any request is served."""

    database_path, findings_path, summary_path = _resolve_startup_paths(settings)
    database_identity = _database_file_identity(database_path)
    try:
        audit_result = audit_detection_store(database_path)
        artifact_identity = ApprovedArtifactIdentity(
            findings_sha256=audit_result.findings_sha256,
            summary_sha256=audit_result.summary_sha256,
        )
        validated_artifacts = validate_detection_artifacts(
            findings_path,
            summary_path,
            artifact_identity,
        )
        stored_run = get_detection_run(database_path, audit_result.run_id)
    except (
        StorageAuditError,
        StorageContractError,
        StorageInputValidationError,
        StorageQueryError,
        OSError,
    ) as error:
        raise ApiStartupError(
            "STORE_VALIDATION_FAILED", "Configured storage could not be verified."
        ) from error

    if stored_run is None:
        _raise_reconciliation_failure()
    if (
        settings.expected_run_id != audit_result.run_id
        or audit_result.run_id != validated_artifacts.run_id
        or audit_result.run_id != stored_run.run_id
        or audit_result.findings_sha256 != validated_artifacts.findings_sha256
        or audit_result.summary_sha256 != validated_artifacts.summary_sha256
        or audit_result.findings_sha256 != stored_run.findings_sha256
        or audit_result.summary_sha256 != stored_run.summary_sha256
        or audit_result.finding_count != validated_artifacts.finding_count
        or audit_result.evidence_count != validated_artifacts.evidence_count
        or audit_result.rule_count != validated_artifacts.rule_count
        or audit_result.finding_count != stored_run.total_finding_count
        or stored_run.finding_schema_version
        != validated_artifacts.summary.finding_schema_version
    ):
        _raise_reconciliation_failure()
    if _database_file_identity(database_path) != database_identity:
        raise ApiStartupError(
            "STORE_UNAVAILABLE", "The configured storage database changed during checks."
        )

    return ReadinessSnapshot(
        storage_schema_version=audit_result.storage_schema_version,
        finding_schema_version=stored_run.finding_schema_version,
        configured_run_id=settings.expected_run_id,
        audited_run_id=audit_result.run_id,
        findings_sha256=audit_result.findings_sha256,
        summary_sha256=audit_result.summary_sha256,
        finding_count=audit_result.finding_count,
        evidence_count=audit_result.evidence_count,
        rule_count=audit_result.rule_count,
        logical_export_sha256=audit_result.logical_export_sha256,
        reconstructed_findings_sha256=audit_result.reconstructed_findings_sha256,
        database_identity=database_identity,
    )


def require_current_store(settings: ApiSettings, snapshot: ReadinessSnapshot) -> None:
    """Fail closed if the configured database changed after startup.

    This guard intentionally does not reread artifacts or rerun the audit.  A
    changed database requires a fresh process startup and independent audit.
    """

    try:
        database_path = _resolve_processed_file(settings.database_path, "database")
        current_identity = _database_file_identity(database_path)
    except ApiStartupError as error:
        raise ApiStartupError(
            "STORE_UNAVAILABLE", "The verified storage database is unavailable."
        ) from error
    if current_identity != snapshot.database_identity:
        raise ApiStartupError(
            "STORE_UNAVAILABLE", "The verified storage database has changed."
        )
    try:
        if get_detection_run(database_path, snapshot.audited_run_id) is None:
            raise ApiStartupError(
                "STORE_UNAVAILABLE", "The verified storage database is unavailable."
            )
    except (StorageContractError, StorageQueryError, OSError) as error:
        raise ApiStartupError(
            "STORE_UNAVAILABLE", "The verified storage database is unavailable."
        ) from error
