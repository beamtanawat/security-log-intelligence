"""Deterministic SQLite schema primitives for Stage 1.5A.

This module creates only the empty storage schema. It does not open finding
artifacts, import a run, publish a database, execute a query, or audit data.
"""

from __future__ import annotations

import sqlite3

from detection.models import (
    DETECTION_FINDING_SCHEMA_VERSION,
    RULE_CATEGORIES,
    RULE_SEVERITIES,
)
from normalization.models import (
    INTERPRETATION_STATUSES,
    MAPPING_OPERATIONS,
    SCHEMA_VERSION,
)

from .models import STORAGE_SCHEMA_VERSION, STORAGE_USER_VERSION


STORAGE_TABLE_NAMES = (
    "storage_metadata",
    "detection_runs",
    "run_rules",
    "findings",
    "finding_evidence",
)

STORAGE_METADATA_VALUES = (
    ("storage_schema_version", STORAGE_SCHEMA_VERSION),
    ("source_finding_contract_version", DETECTION_FINDING_SCHEMA_VERSION),
)

REQUIRED_INDEX_NAMES = (
    "findings_by_source_record",
    "findings_by_rule",
    "findings_by_severity",
    "findings_by_reason_code",
    "findings_by_source_type",
    "finding_evidence_by_path",
)

_RULE_SEVERITY_VALUES = ", ".join(f"'{value}'" for value in sorted(RULE_SEVERITIES))
_RULE_CATEGORY_VALUES = ", ".join(f"'{value}'" for value in sorted(RULE_CATEGORIES))
_MAPPING_OPERATION_VALUES = ", ".join(
    f"'{value}'" for value in sorted(MAPPING_OPERATIONS)
)
_INTERPRETATION_STATUS_VALUES = ", ".join(
    f"'{value}'" for value in sorted(INTERPRETATION_STATUSES)
)


class StorageSchemaError(RuntimeError):
    """Raised when an SQLite connection cannot satisfy the storage schema contract."""


def _sha256_check(column_name: str) -> str:
    """Return SQLite constraints for a lowercase SHA-256 hexadecimal value."""

    return (
        f"length({column_name}) = 64 AND "
        f"{column_name} NOT GLOB '*[^0-9a-f]*'"
    )


STORAGE_SCHEMA_DDL = (
    """
    CREATE TABLE storage_metadata (
        key TEXT PRIMARY KEY CHECK (length(trim(key)) > 0),
        value TEXT NOT NULL CHECK (length(value) > 0)
    )
    """,
    f"""
    CREATE TABLE detection_runs (
        run_id TEXT PRIMARY KEY CHECK ({_sha256_check("run_id")} ),
        findings_sha256 TEXT NOT NULL UNIQUE
            CHECK ({_sha256_check("findings_sha256")})
            CHECK (findings_sha256 = run_id),
        summary_sha256 TEXT NOT NULL CHECK ({_sha256_check("summary_sha256")} ),
        finding_artifact_path TEXT NOT NULL
            CHECK (length(trim(finding_artifact_path)) > 0),
        summary_artifact_path TEXT NOT NULL
            CHECK (length(trim(summary_artifact_path)) > 0),
        finding_schema_version TEXT NOT NULL
            CHECK (finding_schema_version = '{DETECTION_FINDING_SCHEMA_VERSION}'),
        normalized_input_schema_version TEXT NOT NULL
            CHECK (normalized_input_schema_version = '{SCHEMA_VERSION}'),
        normalized_input_record_count INTEGER NOT NULL
            CHECK (normalized_input_record_count >= 0),
        evaluated_record_count INTEGER NOT NULL
            CHECK (evaluated_record_count >= 0),
        invalid_input_count INTEGER NOT NULL
            CHECK (invalid_input_count >= 0),
        total_finding_count INTEGER NOT NULL
            CHECK (total_finding_count >= 0),
        unique_matched_source_record_count INTEGER NOT NULL
            CHECK (unique_matched_source_record_count >= 0)
    )
    """,
    """
    CREATE TABLE run_rules (
        run_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        rule_id TEXT NOT NULL CHECK (length(trim(rule_id)) > 0),
        rule_version TEXT NOT NULL CHECK (length(trim(rule_version)) > 0),
        PRIMARY KEY (run_id, ordinal),
        UNIQUE (run_id, rule_id, rule_version),
        FOREIGN KEY (run_id) REFERENCES detection_runs(run_id)
    )
    """,
    f"""
    CREATE TABLE findings (
        run_id TEXT NOT NULL,
        finding_id TEXT NOT NULL CHECK ({_sha256_check("finding_id")} ),
        finding_schema_version TEXT NOT NULL
            CHECK (finding_schema_version = '{DETECTION_FINDING_SCHEMA_VERSION}'),
        rule_id TEXT NOT NULL CHECK (length(trim(rule_id)) > 0),
        rule_version TEXT NOT NULL CHECK (length(trim(rule_version)) > 0),
        rule_name TEXT NOT NULL CHECK (length(trim(rule_name)) > 0),
        rule_category TEXT NOT NULL CHECK (rule_category IN ({_RULE_CATEGORY_VALUES})),
        rule_severity TEXT NOT NULL CHECK (rule_severity IN ({_RULE_SEVERITY_VALUES})),
        source_type TEXT NOT NULL CHECK (length(trim(source_type)) > 0),
        normalized_schema_version TEXT NOT NULL
            CHECK (normalized_schema_version = '{SCHEMA_VERSION}'),
        source_record_number INTEGER NOT NULL CHECK (source_record_number >= 1),
        source_record_id TEXT
            CHECK (source_record_id IS NULL OR length(trim(source_record_id)) > 0),
        reason_code TEXT NOT NULL CHECK (length(trim(reason_code)) > 0),
        summary TEXT NOT NULL CHECK (length(trim(summary)) > 0),
        time_basis TEXT NOT NULL CHECK (time_basis = 'NOT_USED'),
        uncertainties_json TEXT NOT NULL CHECK (length(uncertainties_json) > 0),
        false_positive_note TEXT NOT NULL CHECK (length(trim(false_positive_note)) > 0),
        deterministic INTEGER NOT NULL CHECK (deterministic = 1),
        canonical_finding_json TEXT NOT NULL CHECK (length(canonical_finding_json) > 0),
        PRIMARY KEY (run_id, finding_id),
        FOREIGN KEY (run_id) REFERENCES detection_runs(run_id),
        FOREIGN KEY (run_id, rule_id, rule_version)
            REFERENCES run_rules(run_id, rule_id, rule_version)
    )
    """,
    f"""
    CREATE TABLE finding_evidence (
        run_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        canonical_path TEXT NOT NULL CHECK (length(trim(canonical_path)) > 0),
        observed_value_json TEXT NOT NULL CHECK (length(observed_value_json) > 0),
        source_fields_json TEXT NOT NULL CHECK (length(source_fields_json) > 0),
        mapping_operation TEXT NOT NULL
            CHECK (mapping_operation IN ({_MAPPING_OPERATION_VALUES})),
        interpretation_status TEXT NOT NULL
            CHECK (interpretation_status IN ({_INTERPRETATION_STATUS_VALUES})),
        PRIMARY KEY (run_id, finding_id, ordinal),
        UNIQUE (run_id, finding_id, canonical_path),
        FOREIGN KEY (run_id, finding_id)
            REFERENCES findings(run_id, finding_id)
    )
    """,
    """
    CREATE INDEX findings_by_source_record
        ON findings(run_id, source_record_number, rule_id, finding_id)
    """,
    """
    CREATE INDEX findings_by_rule
        ON findings(run_id, rule_id, source_record_number, finding_id)
    """,
    """
    CREATE INDEX findings_by_severity
        ON findings(run_id, rule_severity, source_record_number, finding_id)
    """,
    """
    CREATE INDEX findings_by_reason_code
        ON findings(run_id, reason_code, source_record_number, finding_id)
    """,
    """
    CREATE INDEX findings_by_source_type
        ON findings(run_id, source_type, source_record_number, finding_id)
    """,
    """
    CREATE INDEX finding_evidence_by_path
        ON finding_evidence(run_id, canonical_path, finding_id)
    """,
)


def configure_connection(connection: sqlite3.Connection, *, read_only: bool = False) -> None:
    """Enable and verify the required SQLite connection pragmas.

    The helper does not open a path, create a database, execute a query, or retain
    global connection state. Callers own the supplied connection and its lifetime.
    """

    if not isinstance(connection, sqlite3.Connection):
        raise StorageSchemaError("connection must be an sqlite3.Connection")

    try:
        connection.execute("PRAGMA foreign_keys = ON")
        foreign_keys_enabled = connection.execute("PRAGMA foreign_keys").fetchone()
        if foreign_keys_enabled is None or foreign_keys_enabled[0] != 1:
            raise StorageSchemaError("SQLite foreign-key enforcement could not be enabled")

        if read_only:
            connection.execute("PRAGMA query_only = ON")
            query_only_enabled = connection.execute("PRAGMA query_only").fetchone()
            if query_only_enabled is None or query_only_enabled[0] != 1:
                raise StorageSchemaError("SQLite query-only mode could not be enabled")
    except sqlite3.DatabaseError as error:
        raise StorageSchemaError("unable to configure SQLite connection") from error


def create_storage_schema(connection: sqlite3.Connection) -> None:
    """Create the exact Stage 1.5 v1 schema on a caller-owned new connection.

    This function intentionally does not begin, commit, or roll back a transaction.
    A later importer owns those operations. It also does not read any finding or
    summary artifact.
    """

    configure_connection(connection)
    try:
        for statement in STORAGE_SCHEMA_DDL:
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {STORAGE_USER_VERSION}")
        for key, value in STORAGE_METADATA_VALUES:
            connection.execute(
                "INSERT INTO storage_metadata (key, value) VALUES (?, ?)",
                (key, value),
            )
    except sqlite3.DatabaseError as error:
        raise StorageSchemaError("unable to create the Stage 1.5 storage schema") from error
