"""Transactional single-run import for already validated detection artifacts.

This module creates one new SQLite database from approved Stage 1.4 finding
artifacts. It does not read raw CSV or normalized-event JSONL, append to an
existing database, query a database, audit a database independently, or make a
security decision.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from detection.models import DetectionEvidence, DetectionFinding

from .input import (
    StorageInputValidationError,
    ValidatedDetectionArtifacts,
    calculate_artifact_identity,
    validate_detection_artifacts,
)
from .models import StorageImportSummary
from .schema import StorageSchemaError, configure_connection, create_storage_schema


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"


class StorageImportError(RuntimeError):
    """Raised when a single-run import cannot complete or publish safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _canonical_json(value: object) -> str:
    """Return the compact deterministic JSON representation used by Stage 1.4."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _resolve_database_path(
    findings_path: str | Path,
    summary_path: str | Path,
    database_path: str | Path,
) -> Path:
    """Require a new final database path beneath the configured processed directory."""

    try:
        resolved_findings_path = Path(findings_path).resolve()
        resolved_summary_path = Path(summary_path).resolve()
        resolved_database_path = Path(database_path).resolve()
        processed_directory = PROCESSED_DATA_DIRECTORY.resolve()
    except (OSError, TypeError) as error:
        raise StorageImportError(
            "INVALID_DATABASE_PATH", "Database output path cannot be resolved."
        ) from error

    if resolved_database_path in (resolved_findings_path, resolved_summary_path):
        raise StorageImportError(
            "DATABASE_INPUT_PATH_EQUAL",
            "Database output must differ from finding and summary artifacts.",
        )
    if not processed_directory.is_dir():
        raise StorageImportError(
            "PROCESSED_DIRECTORY_UNAVAILABLE",
            "The processed-data directory is unavailable.",
        )
    if not resolved_database_path.is_relative_to(processed_directory):
        raise StorageImportError(
            "DATABASE_OUTSIDE_PROCESSED",
            "Database output must resolve beneath data/processed.",
        )
    if not resolved_database_path.parent.is_dir():
        raise StorageImportError(
            "DATABASE_PARENT_UNAVAILABLE",
            "Database output parent directory does not exist.",
        )
    if resolved_database_path.exists():
        raise StorageImportError(
            "DATABASE_EXISTS", "Final database already exists; overwrite is not supported."
        )
    return resolved_database_path


def _artifact_reference(path: str | Path) -> str:
    """Return a repository-relative path when available, otherwise a safe basename."""

    resolved_path = Path(path).resolve()
    try:
        return resolved_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return resolved_path.name


def _create_temporary_database(destination: Path) -> Path:
    """Create a unique empty temporary database file beside its final destination."""

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.stem}.",
            suffix=".sqlite3.tmp",
            delete=False,
        ) as temporary_file:
            return Path(temporary_file.name)
    except OSError as error:
        raise StorageImportError(
            "TEMPORARY_DATABASE_CREATE_FAILED",
            "Temporary database file could not be created.",
        ) from error


def _remove_temporary_database(temporary_path: Path) -> None:
    """Remove only the known temporary database and its possible SQLite sidecars."""

    candidates = (
        temporary_path,
        Path(f"{temporary_path}-journal"),
        Path(f"{temporary_path}-wal"),
        Path(f"{temporary_path}-shm"),
    )
    for candidate in candidates:
        try:
            candidate.unlink(missing_ok=True)
        except OSError as error:
            raise StorageImportError(
                "TEMPORARY_DATABASE_CLEANUP_FAILED",
                "Temporary database cleanup could not complete safely.",
            ) from error


def _publish_temporary_database(temporary_path: Path, destination: Path) -> None:
    """Publish a complete database by linking without replacing an existing file."""

    try:
        os.link(temporary_path, destination)
    except FileExistsError as error:
        raise StorageImportError(
            "DATABASE_EXISTS", "Final database already exists; overwrite is not supported."
        ) from error
    except OSError as error:
        raise StorageImportError(
            "DATABASE_PUBLISH_FAILED", "Final database could not be published safely."
        ) from error
    try:
        temporary_path.unlink()
    except OSError as error:
        raise StorageImportError(
            "TEMPORARY_DATABASE_CLEANUP_FAILED",
            "Published database temporary file could not be removed.",
        ) from error


def _insert_run(
    connection: sqlite3.Connection,
    validated: ValidatedDetectionArtifacts,
    findings_path: str | Path,
    summary_path: str | Path,
) -> None:
    """Insert one bounded detection-run row and its artifact rule snapshot."""

    summary = validated.summary
    connection.execute(
        """
        INSERT INTO detection_runs (
            run_id, findings_sha256, summary_sha256, finding_artifact_path,
            summary_artifact_path, finding_schema_version,
            normalized_input_schema_version, normalized_input_record_count,
            evaluated_record_count, invalid_input_count, total_finding_count,
            unique_matched_source_record_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            validated.run_id,
            validated.findings_sha256,
            validated.summary_sha256,
            _artifact_reference(findings_path),
            _artifact_reference(summary_path),
            summary.finding_schema_version,
            summary.normalized_input_schema_version,
            summary.normalized_input_record_count,
            summary.evaluated_record_count,
            summary.invalid_input_count,
            summary.total_finding_count,
            summary.unique_matched_source_record_count,
        ),
    )
    for ordinal, rule in enumerate(summary.active_rules):
        connection.execute(
            """
            INSERT INTO run_rules (run_id, ordinal, rule_id, rule_version)
            VALUES (?, ?, ?, ?)
            """,
            (validated.run_id, ordinal, rule.rule_id, rule.version),
        )


def _insert_evidence(
    connection: sqlite3.Connection,
    run_id: str,
    finding_id: str,
    ordinal: int,
    evidence: DetectionEvidence,
) -> None:
    """Insert one evidence/provenance projection without changing its value."""

    connection.execute(
        """
        INSERT INTO finding_evidence (
            run_id, finding_id, ordinal, canonical_path, observed_value_json,
            source_fields_json, mapping_operation, interpretation_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            finding_id,
            ordinal,
            evidence.canonical_path,
            _canonical_json(evidence.observed_value),
            _canonical_json(list(evidence.source_fields)),
            evidence.mapping_operation,
            evidence.interpretation_status,
        ),
    )


def _insert_finding(
    connection: sqlite3.Connection,
    run_id: str,
    finding: DetectionFinding,
) -> None:
    """Insert one canonical finding and all ordered evidence projections."""

    connection.execute(
        """
        INSERT INTO findings (
            run_id, finding_id, finding_schema_version, rule_id, rule_version,
            rule_name, rule_category, rule_severity, source_type,
            normalized_schema_version, source_record_number, source_record_id,
            reason_code, summary, time_basis, uncertainties_json,
            false_positive_note, deterministic, canonical_finding_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            finding.finding_id,
            finding.finding_schema_version,
            finding.rule.rule_id,
            finding.rule.version,
            finding.rule.name,
            finding.rule.category,
            finding.rule.severity,
            finding.source_event.source_type,
            finding.source_event.normalized_schema_version,
            finding.source_event.source_record_number,
            finding.source_event.source_record_id,
            finding.reason_code,
            finding.summary,
            finding.time_basis,
            _canonical_json(list(finding.uncertainties)),
            finding.false_positive_note,
            1,
            _canonical_json(finding.to_dict()),
        ),
    )
    for ordinal, evidence in enumerate(finding.evidence):
        _insert_evidence(connection, run_id, finding.finding_id, ordinal, evidence)


def _verify_imported_counts(
    connection: sqlite3.Connection,
    validated: ValidatedDetectionArtifacts,
) -> None:
    """Check bounded row counts and SQLite integrity before publication."""

    foreign_keys_enabled = connection.execute("PRAGMA foreign_keys").fetchone()
    if foreign_keys_enabled is None or foreign_keys_enabled[0] != 1:
        raise StorageImportError(
            "FOREIGN_KEYS_DISABLED", "SQLite foreign-key enforcement is not active."
        )
    expected_counts = {
        "detection_runs": 1,
        "run_rules": validated.rule_count,
        "findings": validated.finding_count,
        "finding_evidence": validated.evidence_count,
    }
    for table_name, expected_count in expected_counts.items():
        actual_count = connection.execute(
            f"SELECT COUNT(*) FROM {table_name}"
        ).fetchone()[0]
        if actual_count != expected_count:
            raise StorageImportError(
                "IMPORTED_COUNT_MISMATCH",
                f"Imported {table_name} row count did not reconcile.",
            )
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise StorageImportError(
            "FOREIGN_KEY_CHECK_FAILED", "Imported database has foreign-key violations."
        )
    integrity_result = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity_result is None or integrity_result[0] != "ok":
        raise StorageImportError(
            "INTEGRITY_CHECK_FAILED", "Imported database failed SQLite integrity_check."
        )


def import_detection_run(
    findings_path: str | Path,
    summary_path: str | Path,
    database_path: str | Path,
) -> StorageImportSummary:
    """Create and safely publish one new database from validated finding artifacts.

    Both artifacts are hashed and fully validated before any database is created.
    They are then validated again while their findings stream into a single SQLite
    transaction, so a changed or malformed artifact rolls back and publishes nothing.
    """

    destination = _resolve_database_path(findings_path, summary_path, database_path)
    expected_identity = calculate_artifact_identity(findings_path, summary_path)
    validated = validate_detection_artifacts(
        findings_path,
        summary_path,
        expected_identity,
    )

    temporary_path: Path | None = None
    connection: sqlite3.Connection | None = None
    transaction_started = False
    try:
        temporary_path = _create_temporary_database(destination)
        connection = sqlite3.connect(temporary_path)
        configure_connection(connection)
        create_storage_schema(connection)
        connection.commit()

        connection.execute("BEGIN")
        transaction_started = True
        _insert_run(connection, validated, findings_path, summary_path)
        imported = validate_detection_artifacts(
            findings_path,
            summary_path,
            expected_identity,
            on_finding=lambda finding: _insert_finding(
                connection,
                validated.run_id,
                finding,
            ),
        )
        if imported != validated:
            raise StorageImportError(
                "ARTIFACT_CHANGED_DURING_IMPORT",
                "Validated artifacts changed before transactional import completed.",
            )
        _verify_imported_counts(connection, validated)
        connection.commit()
        transaction_started = False
        connection.close()
        connection = None

        _publish_temporary_database(temporary_path, destination)
        temporary_path = None
    except (sqlite3.DatabaseError, StorageSchemaError) as error:
        if transaction_started and connection is not None:
            connection.rollback()
            transaction_started = False
        raise StorageImportError(
            "DATABASE_IMPORT_FAILED", "SQLite import could not complete safely."
        ) from error
    finally:
        if connection is not None:
            if transaction_started:
                connection.rollback()
            connection.close()
        if temporary_path is not None:
            _remove_temporary_database(temporary_path)

    return StorageImportSummary(
        run_id=validated.run_id,
        findings_sha256=validated.findings_sha256,
        summary_sha256=validated.summary_sha256,
        finding_count=validated.finding_count,
        evidence_count=validated.evidence_count,
        rule_count=validated.rule_count,
    )
