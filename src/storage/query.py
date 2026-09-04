"""Bounded, typed, read-only SQLite queries for one detection store.

This module queries only a completed Stage 1.5 SQLite database. It never opens
raw CSV, normalized JSONL, or Stage 1.4 artifacts; imports data; executes caller
SQL; mutates SQLite; or makes a security decision.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import (
    EvidenceQuery,
    FindingQuery,
    STORAGE_SCHEMA_VERSION,
    STORAGE_USER_VERSION,
    StoredDetectionRun,
    StoredFinding,
    StoredFindingEvidence,
    StorageContractError,
)
from .input import (
    StorageInputValidationError,
    _as_detection_finding,
    _canonical_finding_line,
)
from .schema import STORAGE_METADATA_VALUES, StorageSchemaError, configure_connection


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"


class StorageQueryError(RuntimeError):
    """Raised when a completed storage database cannot be queried safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _path_is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _resolve_database_path(value: str | Path) -> Path:
    """Allow only an existing Stage 1.5 database below data/processed."""

    try:
        resolved_path = Path(value).resolve()
        processed_directory = PROCESSED_DATA_DIRECTORY.resolve()
        raw_directory = (PROJECT_ROOT / "data" / "raw").resolve()
        normalized_event_path = (
            PROJECT_ROOT / "data" / "processed" / "stage_1_3f_normalized_events.jsonl"
        ).resolve()
    except (OSError, TypeError) as error:
        raise StorageQueryError(
            "INVALID_DATABASE_PATH", "Database path cannot be resolved."
        ) from error

    if _path_is_within(resolved_path, raw_directory) or resolved_path == normalized_event_path:
        raise StorageQueryError(
            "UPSTREAM_ARTIFACT_FORBIDDEN",
            "Storage queries must not open raw or normalized artifacts.",
        )
    if not processed_directory.is_dir():
        raise StorageQueryError(
            "PROCESSED_DIRECTORY_UNAVAILABLE",
            "The processed-data directory is unavailable.",
        )
    if not _path_is_within(resolved_path, processed_directory):
        raise StorageQueryError(
            "DATABASE_OUTSIDE_PROCESSED",
            "Database path must resolve beneath data/processed.",
        )
    if not resolved_path.is_file():
        raise StorageQueryError(
            "DATABASE_NOT_FOUND", "Database path must be an existing regular file."
        )
    return resolved_path


def _validate_database_contract(connection: sqlite3.Connection) -> None:
    """Perform the minimum bounded version checks before exposing stored values."""

    user_version = connection.execute("PRAGMA user_version").fetchone()
    if user_version is None or user_version[0] != STORAGE_USER_VERSION:
        raise StorageQueryError(
            "DATABASE_CONTRACT_MISMATCH", "Database user_version is not supported."
        )
    metadata_rows = connection.execute(
        "SELECT key, value FROM storage_metadata WHERE key IN (?, ?) ORDER BY key",
        tuple(key for key, _ in STORAGE_METADATA_VALUES),
    ).fetchall()
    metadata = {row["key"]: row["value"] for row in metadata_rows}
    expected_metadata = dict(STORAGE_METADATA_VALUES)
    if metadata != expected_metadata or (
        metadata.get("storage_schema_version") != STORAGE_SCHEMA_VERSION
    ):
        raise StorageQueryError(
            "DATABASE_CONTRACT_MISMATCH", "Database storage metadata is not supported."
        )


@contextmanager
def _open_read_only_connection(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Open one SQLite connection in both OS-level and SQLite read-only modes."""

    resolved_path = _resolve_database_path(database_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"{resolved_path.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        configure_connection(connection, read_only=True)
        _validate_database_contract(connection)
        yield connection
    except StorageQueryError:
        raise
    except (sqlite3.DatabaseError, StorageSchemaError, OSError) as error:
        raise StorageQueryError(
            "DATABASE_READ_FAILED", "Database cannot be opened for read-only querying."
        ) from error
    finally:
        if connection is not None:
            connection.close()


def _stored_run(row: sqlite3.Row) -> StoredDetectionRun:
    return StoredDetectionRun(
        run_id=row["run_id"],
        findings_sha256=row["findings_sha256"],
        summary_sha256=row["summary_sha256"],
        finding_artifact_path=row["finding_artifact_path"],
        summary_artifact_path=row["summary_artifact_path"],
        finding_schema_version=row["finding_schema_version"],
        normalized_input_schema_version=row["normalized_input_schema_version"],
        normalized_input_record_count=row["normalized_input_record_count"],
        evaluated_record_count=row["evaluated_record_count"],
        invalid_input_count=row["invalid_input_count"],
        total_finding_count=row["total_finding_count"],
        unique_matched_source_record_count=row["unique_matched_source_record_count"],
    )


def _stored_finding(row: sqlite3.Row) -> StoredFinding:
    return StoredFinding(
        run_id=row["run_id"],
        finding_id=row["finding_id"],
        finding_schema_version=row["finding_schema_version"],
        rule_id=row["rule_id"],
        rule_version=row["rule_version"],
        rule_name=row["rule_name"],
        rule_category=row["rule_category"],
        rule_severity=row["rule_severity"],
        source_type=row["source_type"],
        normalized_schema_version=row["normalized_schema_version"],
        source_record_number=row["source_record_number"],
        source_record_id=row["source_record_id"],
        reason_code=row["reason_code"],
        summary=row["summary"],
        time_basis=row["time_basis"],
        uncertainties_json=row["uncertainties_json"],
        false_positive_note=row["false_positive_note"],
        deterministic=bool(row["deterministic"]),
        canonical_finding_json=row["canonical_finding_json"],
    )


def _stored_evidence(row: sqlite3.Row) -> StoredFindingEvidence:
    return StoredFindingEvidence(
        run_id=row["run_id"],
        finding_id=row["finding_id"],
        ordinal=row["ordinal"],
        canonical_path=row["canonical_path"],
        observed_value_json=row["observed_value_json"],
        source_fields_json=row["source_fields_json"],
        mapping_operation=row["mapping_operation"],
        interpretation_status=row["interpretation_status"],
    )


def _canonical_json(value: object) -> str:
    """Return the compact JSON representation required by the stored projection."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _reconstruct_and_reconcile_finding(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> StoredFinding:
    """Fail closed unless canonical and relational finding projections agree."""

    stored_canonical_json = row["canonical_finding_json"]
    try:
        payload = json.loads(stored_canonical_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise StorageQueryError(
            "CANONICAL_FINDING_INVALID",
            "Stored canonical finding JSON cannot be parsed.",
        ) from error
    try:
        finding = _as_detection_finding(payload, line_number=1)
    except StorageInputValidationError as error:
        raise StorageQueryError(
            "CANONICAL_FINDING_INVALID",
            "Stored canonical finding does not satisfy the Stage 1.4 contract.",
        ) from error

    canonical_text = _canonical_finding_line(finding)[:-1].decode("utf-8")
    if stored_canonical_json != canonical_text:
        raise StorageQueryError(
            "CANONICAL_FINDING_NONCANONICAL",
            "Stored canonical finding JSON is not the required canonical representation.",
        )

    expected_projection = (
        finding.finding_schema_version,
        finding.finding_id,
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
    )
    stored_projection = (
        row["finding_schema_version"],
        row["finding_id"],
        row["rule_id"],
        row["rule_version"],
        row["rule_name"],
        row["rule_category"],
        row["rule_severity"],
        row["source_type"],
        row["normalized_schema_version"],
        row["source_record_number"],
        row["source_record_id"],
        row["reason_code"],
        row["summary"],
        row["time_basis"],
        row["uncertainties_json"],
        row["false_positive_note"],
        row["deterministic"],
    )
    if stored_projection != expected_projection:
        raise StorageQueryError(
            "FINDING_PROJECTION_MISMATCH",
            "Stored finding projection does not match canonical Stage 1.4 evidence.",
        )

    expected_evidence = tuple(
        (
            ordinal,
            evidence.canonical_path,
            _canonical_json(evidence.observed_value),
            _canonical_json(list(evidence.source_fields)),
            evidence.mapping_operation,
            evidence.interpretation_status,
        )
        for ordinal, evidence in enumerate(finding.evidence)
    )
    evidence_rows = connection.execute(
        f"SELECT {_EVIDENCE_COLUMNS} FROM finding_evidence "
        "WHERE run_id = ? AND finding_id = ? ORDER BY ordinal LIMIT ?",
        (row["run_id"], row["finding_id"], len(expected_evidence) + 1),
    ).fetchall()
    stored_evidence = tuple(
        (
            evidence_row["ordinal"],
            evidence_row["canonical_path"],
            evidence_row["observed_value_json"],
            evidence_row["source_fields_json"],
            evidence_row["mapping_operation"],
            evidence_row["interpretation_status"],
        )
        for evidence_row in evidence_rows
    )
    if stored_evidence != expected_evidence:
        raise StorageQueryError(
            "EVIDENCE_PROJECTION_MISMATCH",
            "Stored evidence projection does not match canonical Stage 1.4 evidence.",
        )
    return _stored_finding(row)


_RUN_COLUMNS = """
    run_id, findings_sha256, summary_sha256, finding_artifact_path,
    summary_artifact_path, finding_schema_version,
    normalized_input_schema_version, normalized_input_record_count,
    evaluated_record_count, invalid_input_count, total_finding_count,
    unique_matched_source_record_count
"""

_FINDING_COLUMNS = """
    run_id, finding_id, finding_schema_version, rule_id, rule_version,
    rule_name, rule_category, rule_severity, source_type,
    normalized_schema_version, source_record_number, source_record_id,
    reason_code, summary, time_basis, uncertainties_json, false_positive_note,
    deterministic, canonical_finding_json
"""

_EVIDENCE_COLUMNS = """
    run_id, finding_id, ordinal, canonical_path, observed_value_json,
    source_fields_json, mapping_operation, interpretation_status
"""


def get_detection_run(
    database_path: str | Path, run_id: str
) -> StoredDetectionRun | None:
    """Return one stored run, or ``None`` when that run is absent."""

    FindingQuery(run_id=run_id)
    with _open_read_only_connection(database_path) as connection:
        row = connection.execute(
            f"SELECT {_RUN_COLUMNS} FROM detection_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return None if row is None else _stored_run(row)


def get_finding(database_path: str | Path, finding_id: str) -> StoredFinding | None:
    """Return one stored finding, or ``None`` when the ID is absent."""

    findings = list_findings(
        database_path,
        FindingQuery(finding_id=finding_id, limit=1),
    )
    return findings[0] if findings else None


def list_findings(
    database_path: str | Path, query: FindingQuery
) -> tuple[StoredFinding, ...]:
    """Return a deterministically ordered, explicitly bounded finding projection."""

    if not isinstance(query, FindingQuery):
        raise StorageContractError("query must be a FindingQuery")

    clauses: list[str] = []
    parameters: list[str | int] = []
    for column, value in (
        ("run_id", query.run_id),
        ("finding_id", query.finding_id),
        ("rule_id", query.rule_id),
        ("rule_version", query.rule_version),
        ("rule_severity", query.severity),
        ("reason_code", query.reason_code),
        ("source_type", query.source_type),
        ("source_record_number", query.source_record_number),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    if query.evidence_path is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding_evidence AS evidence "
            "WHERE evidence.run_id = findings.run_id "
            "AND evidence.finding_id = findings.finding_id "
            "AND evidence.canonical_path = ?)"
        )
        parameters.append(query.evidence_path)

    where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    statement = (
        f"SELECT {_FINDING_COLUMNS} FROM findings{where_clause} "
        "ORDER BY source_record_number, rule_id, rule_version, finding_id LIMIT ?"
    )
    parameters.append(query.limit)
    with _open_read_only_connection(database_path) as connection:
        rows = connection.execute(statement, parameters).fetchall()
        return tuple(_reconstruct_and_reconcile_finding(connection, row) for row in rows)


def get_finding_evidence(
    database_path: str | Path, query: EvidenceQuery
) -> tuple[StoredFindingEvidence, ...]:
    """Return explicitly bounded evidence for one finding in stored ordinal order."""

    if not isinstance(query, EvidenceQuery):
        raise StorageContractError("query must be an EvidenceQuery")
    with _open_read_only_connection(database_path) as connection:
        rows = connection.execute(
            f"SELECT {_EVIDENCE_COLUMNS} FROM finding_evidence "
            "WHERE run_id = ? AND finding_id = ? ORDER BY ordinal LIMIT ?",
            (query.run_id, query.finding_id, query.limit),
        ).fetchall()
    return tuple(_stored_evidence(row) for row in rows)
