"""Independent, streaming, read-only audit for one Stage 1.5 detection store."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path

from .input import StorageInputValidationError, _as_detection_finding, _canonical_finding_line
from .models import (
    STORAGE_SCHEMA_VERSION,
    STORAGE_USER_VERSION,
    StorageAuditResult,
    StorageContractError,
)
from .schema import (
    REQUIRED_INDEX_NAMES,
    STORAGE_SCHEMA_DDL,
    STORAGE_METADATA_VALUES,
    STORAGE_TABLE_NAMES,
    StorageSchemaError,
    configure_connection,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"


class StorageAuditError(RuntimeError):
    """Raised when a storage audit finds an unsupported or inconsistent store."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _resolve_database_path(value: str | Path) -> Path:
    try:
        path = Path(value).resolve()
        processed_directory = PROCESSED_DATA_DIRECTORY.resolve()
        raw_directory = (PROJECT_ROOT / "data" / "raw").resolve()
        normalized_path = (
            PROJECT_ROOT / "data" / "processed" / "stage_1_3f_normalized_events.jsonl"
        ).resolve()
    except (OSError, TypeError) as error:
        raise StorageAuditError("INVALID_DATABASE_PATH", "Database path cannot be resolved.") from error
    if path.is_relative_to(raw_directory) or path == normalized_path:
        raise StorageAuditError(
            "UPSTREAM_ARTIFACT_FORBIDDEN", "Storage audit must not open upstream artifacts."
        )
    if not processed_directory.is_dir() or not path.is_relative_to(processed_directory):
        raise StorageAuditError(
            "DATABASE_OUTSIDE_PROCESSED", "Database path must be below data/processed."
        )
    if not path.is_file():
        raise StorageAuditError("DATABASE_NOT_FOUND", "Database path must be an existing file.")
    return path


@contextmanager
def _open_audit_connection(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Open an audit-owned read-only connection without reusing query code."""

    path = _resolve_database_path(database_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        configure_connection(connection, read_only=True)
        yield connection
    except StorageAuditError:
        raise
    except (sqlite3.DatabaseError, StorageSchemaError, OSError) as error:
        raise StorageAuditError("DATABASE_READ_FAILED", "Storage database cannot be audited.") from error
    finally:
        if connection is not None:
            connection.close()


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise StorageAuditError(code, message)


def _update_logical_hash(digest: object, entity: str, row: sqlite3.Row) -> None:
    digest.update(_canonical_json({"entity": entity, "row": dict(row)}).encode("utf-8"))
    digest.update(b"\n")


def _normalized_schema_sql(statement: str) -> str:
    """Return a whitespace-stable representation of contract DDL."""

    return " ".join(statement.split())


def _contract_schema_signature() -> str:
    """Hash the Stage 1.5A table, index, and constraint DDL contract."""

    digest = sha256()
    for statement in STORAGE_SCHEMA_DDL:
        digest.update(_normalized_schema_sql(statement).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _stored_schema_signature(connection: sqlite3.Connection) -> str:
    """Hash stored table, index, and constraint definitions in contract order."""

    stored_sql = {
        row["name"]: row["sql"]
        for row in connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE (type = ? OR type = ?) AND sql IS NOT NULL",
            ("table", "index"),
        )
    }
    expected_names = tuple(STORAGE_TABLE_NAMES) + tuple(REQUIRED_INDEX_NAMES)
    _require(
        set(stored_sql) == set(expected_names),
        "SCHEMA_SIGNATURE_MISMATCH",
        "Storage schema objects differ from the contract.",
    )
    digest = sha256()
    for name in expected_names:
        digest.update(_normalized_schema_sql(stored_sql[name]).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _audit_schema(connection: sqlite3.Connection, logical_hash: object) -> None:
    user_version = connection.execute("PRAGMA user_version").fetchone()
    _require(
        user_version is not None and user_version[0] == STORAGE_USER_VERSION,
        "SCHEMA_VERSION_MISMATCH",
        "SQLite user_version is unsupported.",
    )
    tables = tuple(
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ? ORDER BY name", ("table",)
        )
    )
    _require(tables == tuple(sorted(STORAGE_TABLE_NAMES)), "SCHEMA_TABLE_MISMATCH", "Storage tables differ from the contract.")
    indexes = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ? AND sql IS NOT NULL", ("index",)
        )
    }
    _require(set(REQUIRED_INDEX_NAMES) == indexes, "SCHEMA_INDEX_MISMATCH", "Storage indexes differ from the contract.")
    _require(
        _stored_schema_signature(connection) == _contract_schema_signature(),
        "SCHEMA_SIGNATURE_MISMATCH",
        "Storage table, index, or constraint definitions differ from the contract.",
    )
    metadata_rows = tuple(
        connection.execute("SELECT key, value FROM storage_metadata ORDER BY key")
    )
    _require(
        tuple((row["key"], row["value"]) for row in metadata_rows)
        == tuple(sorted(STORAGE_METADATA_VALUES)),
        "STORAGE_METADATA_MISMATCH",
        "Storage metadata differs from the contract.",
    )
    _require(
        connection.execute("PRAGMA foreign_key_check").fetchone() is None,
        "FOREIGN_KEY_CHECK_FAILED",
        "Storage database has foreign-key violations.",
    )
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    _require(integrity is not None and integrity[0] == "ok", "INTEGRITY_CHECK_FAILED", "Storage database failed integrity_check.")
    for row in metadata_rows:
        _update_logical_hash(logical_hash, "storage_metadata", row)


def _reconstruct_finding(connection: sqlite3.Connection, row: sqlite3.Row) -> int:
    try:
        payload = json.loads(row["canonical_finding_json"])
        finding = _as_detection_finding(payload, line_number=1)
    except (TypeError, json.JSONDecodeError, StorageInputValidationError) as error:
        raise StorageAuditError("CANONICAL_FINDING_INVALID", "Stored canonical finding is invalid.") from error
    _require(
        row["canonical_finding_json"] == _canonical_finding_line(finding)[:-1].decode("utf-8"),
        "CANONICAL_FINDING_NONCANONICAL",
        "Stored canonical finding JSON is not canonical.",
    )
    expected = (
        finding.finding_schema_version, finding.finding_id, finding.rule.rule_id,
        finding.rule.version, finding.rule.name, finding.rule.category, finding.rule.severity,
        finding.source_event.source_type, finding.source_event.normalized_schema_version,
        finding.source_event.source_record_number, finding.source_event.source_record_id,
        finding.reason_code, finding.summary, finding.time_basis,
        _canonical_json(list(finding.uncertainties)), finding.false_positive_note, 1,
    )
    actual = tuple(
        row[name] for name in (
            "finding_schema_version", "finding_id", "rule_id", "rule_version", "rule_name",
            "rule_category", "rule_severity", "source_type", "normalized_schema_version",
            "source_record_number", "source_record_id", "reason_code", "summary", "time_basis",
            "uncertainties_json", "false_positive_note", "deterministic",
        )
    )
    _require(actual == expected, "FINDING_PROJECTION_MISMATCH", "Finding projection differs from canonical evidence.")
    evidence_rows = tuple(connection.execute(
        "SELECT run_id, finding_id, ordinal, canonical_path, observed_value_json, "
        "source_fields_json, mapping_operation, interpretation_status FROM finding_evidence "
        "WHERE run_id = ? AND finding_id = ? ORDER BY ordinal LIMIT ?",
        (row["run_id"], row["finding_id"], len(finding.evidence) + 1),
    ))
    expected_evidence = tuple(
        (ordinal, evidence.canonical_path, _canonical_json(evidence.observed_value),
         _canonical_json(list(evidence.source_fields)), evidence.mapping_operation,
         evidence.interpretation_status)
        for ordinal, evidence in enumerate(finding.evidence)
    )
    actual_evidence = tuple(
        (item["ordinal"], item["canonical_path"], item["observed_value_json"],
         item["source_fields_json"], item["mapping_operation"], item["interpretation_status"])
        for item in evidence_rows
    )
    _require(actual_evidence == expected_evidence, "EVIDENCE_PROJECTION_MISMATCH", "Evidence projection differs from canonical evidence.")
    return len(evidence_rows)


def audit_detection_store(database_path: str | Path) -> StorageAuditResult:
    """Independently stream-audit one complete Stage 1.5 database."""

    logical_hash = sha256()
    reconstructed_hash = sha256()
    with _open_audit_connection(database_path) as connection:
        _audit_schema(connection, logical_hash)
        runs = tuple(connection.execute(
            "SELECT run_id, findings_sha256, summary_sha256, finding_artifact_path, "
            "summary_artifact_path, finding_schema_version, normalized_input_schema_version, "
            "normalized_input_record_count, evaluated_record_count, invalid_input_count, "
            "total_finding_count, unique_matched_source_record_count FROM detection_runs LIMIT 2"
        ))
        _require(len(runs) == 1, "RUN_COUNT_MISMATCH", "Storage database must contain exactly one run.")
        run = runs[0]
        _require(run["run_id"] == run["findings_sha256"], "RUN_IDENTITY_MISMATCH", "run_id must equal findings_sha256.")
        _require(
            run["invalid_input_count"] == 0,
            "RUN_INVALID_INPUT_COUNT",
            "A completed detection run cannot report invalid input records.",
        )
        _require(
            run["normalized_input_record_count"] == run["evaluated_record_count"],
            "RUN_RECORD_COUNT_MISMATCH",
            "Completed-run input and evaluated-record counts must match.",
        )
        _update_logical_hash(logical_hash, "detection_runs", run)
        rule_count = 0
        expected_rule_ordinal = 0
        for rule in connection.execute(
            "SELECT run_id, ordinal, rule_id, rule_version FROM run_rules WHERE run_id = ? ORDER BY ordinal",
            (run["run_id"],),
        ):
            _require(
                rule["ordinal"] == expected_rule_ordinal,
                "RULE_ORDINAL_MISMATCH",
                "Rule snapshot ordinals are invalid.",
            )
            _update_logical_hash(logical_hash, "run_rules", rule)
            rule_count += 1
            expected_rule_ordinal += 1
        finding_count = 0
        evidence_count = 0
        unique_matched_source_record_count = 0
        previous_source_record_number: int | None = None
        findings = connection.execute(
            "SELECT run_id, finding_id, finding_schema_version, rule_id, rule_version, rule_name, "
            "rule_category, rule_severity, source_type, normalized_schema_version, "
            "source_record_number, source_record_id, reason_code, summary, time_basis, "
            "uncertainties_json, false_positive_note, deterministic, canonical_finding_json "
            "FROM findings WHERE run_id = ? "
            "ORDER BY source_record_number, rule_id, rule_version, finding_id",
            (run["run_id"],),
        )
        for finding_row in findings:
            rule_reference = connection.execute(
                "SELECT 1 FROM run_rules WHERE run_id = ? AND rule_id = ? "
                "AND rule_version = ? LIMIT 1",
                (
                    run["run_id"],
                    finding_row["rule_id"],
                    finding_row["rule_version"],
                ),
            ).fetchone()
            _require(
                rule_reference is not None,
                "RULE_REFERENCE_MISMATCH",
                "Finding references a rule absent from the snapshot.",
            )
            evidence_count += _reconstruct_finding(connection, finding_row)
            finding_count += 1
            if finding_row["source_record_number"] != previous_source_record_number:
                unique_matched_source_record_count += 1
            previous_source_record_number = finding_row["source_record_number"]
            _update_logical_hash(logical_hash, "findings", finding_row)
            reconstructed_hash.update(finding_row["canonical_finding_json"].encode("utf-8"))
            reconstructed_hash.update(b"\n")
        _require(finding_count == run["total_finding_count"], "FINDING_COUNT_MISMATCH", "Finding count differs from run metadata.")
        _require(
            unique_matched_source_record_count
            == run["unique_matched_source_record_count"],
            "MATCHED_SOURCE_RECORD_COUNT_MISMATCH",
            "Unique matched source-record count differs from run metadata.",
        )
        _require(evidence_count == connection.execute("SELECT COUNT(*) FROM finding_evidence").fetchone()[0], "EVIDENCE_COUNT_MISMATCH", "Evidence count differs from stored rows.")
        for evidence_row in connection.execute(
            "SELECT run_id, finding_id, ordinal, canonical_path, observed_value_json, source_fields_json, "
            "mapping_operation, interpretation_status FROM finding_evidence "
            "ORDER BY run_id, finding_id, ordinal"
        ):
            _update_logical_hash(logical_hash, "finding_evidence", evidence_row)
    try:
        return StorageAuditResult(
            run_id=run["run_id"],
            findings_sha256=run["findings_sha256"],
            summary_sha256=run["summary_sha256"],
            logical_export_sha256=logical_hash.hexdigest(),
            reconstructed_findings_sha256=reconstructed_hash.hexdigest(),
            finding_count=finding_count,
            evidence_count=evidence_count,
            rule_count=rule_count,
        )
    except StorageContractError as error:
        raise StorageAuditError(
            "AUDIT_RESULT_CONTRACT_INVALID",
            "Storage identity or reconstructed finding hash is invalid.",
        ) from error
