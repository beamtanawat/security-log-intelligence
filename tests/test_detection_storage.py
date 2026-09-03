"""Synthetic SQLite schema tests for Stage 1.5A storage contracts."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from storage.models import (  # noqa: E402
    FindingQuery,
    StorageAuditResult,
    StorageContractError,
    StorageImportSummary,
)
from storage.schema import (  # noqa: E402
    REQUIRED_INDEX_NAMES,
    STORAGE_METADATA_VALUES,
    STORAGE_TABLE_NAMES,
    configure_connection,
    create_storage_schema,
)


RUN_ID = "a" * 64
SUMMARY_SHA256 = "b" * 64
FINDING_ID = "c" * 64
LOGICAL_EXPORT_SHA256 = "d" * 64


def insert_valid_run(connection: sqlite3.Connection) -> None:
    """Insert minimal synthetic run metadata after schema creation."""

    connection.execute(
        """
        INSERT INTO detection_runs (
            run_id,
            findings_sha256,
            summary_sha256,
            finding_artifact_path,
            summary_artifact_path,
            finding_schema_version,
            normalized_input_schema_version,
            normalized_input_record_count,
            evaluated_record_count,
            invalid_input_count,
            total_finding_count,
            unique_matched_source_record_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            RUN_ID,
            RUN_ID,
            SUMMARY_SHA256,
            "data/processed/synthetic_findings.jsonl",
            "data/processed/synthetic_summary.json",
            "1.0",
            "1.0",
            1,
            1,
            0,
            1,
            1,
        ),
    )


def insert_valid_rule(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO run_rules (run_id, ordinal, rule_id, rule_version)
        VALUES (?, ?, ?, ?)
        """,
        (RUN_ID, 0, "fortigate.example_observation", "1.0"),
    )


def insert_valid_finding(
    connection: sqlite3.Connection,
    *,
    rule_version: str = "1.0",
) -> None:
    connection.execute(
        """
        INSERT INTO findings (
            run_id,
            finding_id,
            finding_schema_version,
            rule_id,
            rule_version,
            rule_name,
            rule_category,
            rule_severity,
            source_type,
            normalized_schema_version,
            source_record_number,
            source_record_id,
            reason_code,
            summary,
            time_basis,
            uncertainties_json,
            false_positive_note,
            deterministic,
            canonical_finding_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            RUN_ID,
            FINDING_ID,
            "1.0",
            "fortigate.example_observation",
            rule_version,
            "Synthetic source observation",
            "SOURCE_PRODUCT_OBSERVATION",
            "INFORMATIONAL",
            "fortigate",
            "1.0",
            1,
            "LOGUID_OPAQUE_1",
            "SYNTHETIC_SOURCE_OBSERVATION",
            "A synthetic source-product observation is present.",
            "NOT_USED",
            '["Synthetic source observations are not attack truth."]',
            "Synthetic inputs can model legitimate activity.",
            1,
            "{}",
        ),
    )


def insert_valid_evidence(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO finding_evidence (
            run_id,
            finding_id,
            ordinal,
            canonical_path,
            observed_value_json,
            source_fields_json,
            mapping_operation,
            interpretation_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            RUN_ID,
            FINDING_ID,
            0,
            "event.subtype_source",
            '"synthetic"',
            '["event_subtype"]',
            "COPIED",
            "VERIFIED",
        ),
    )


class StorageSchemaTests(unittest.TestCase):
    def make_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        create_storage_schema(connection)
        return connection

    def test_schema_creation_defines_metadata_tables_indexes_and_constraints(self) -> None:
        connection = self.make_connection()

        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertEqual(tables, set(STORAGE_TABLE_NAMES))
        self.assertEqual(
            connection.execute("PRAGMA user_version").fetchone()[0],
            1,
        )
        self.assertEqual(
            dict(connection.execute("SELECT key, value FROM storage_metadata")),
            dict(STORAGE_METADATA_VALUES),
        )

        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        self.assertTrue(set(REQUIRED_INDEX_NAMES).issubset(indexes))

        finding_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(findings)")
        }
        prohibited_columns = {
            "is_attack",
            "is_malicious",
            "compromised",
            "confirmed_incident",
            "risk_score",
            "confidence_score",
            "attack_probability",
        }
        self.assertFalse(finding_columns & prohibited_columns)

        primary_key_columns = tuple(
            row[1]
            for row in sorted(
                connection.execute("PRAGMA table_info(findings)"),
                key=lambda row: row[5],
            )
            if row[5] > 0
        )
        self.assertEqual(primary_key_columns, ("run_id", "finding_id"))

        run_rule_unique_indexes = [
            row[1]
            for row in connection.execute("PRAGMA index_list(run_rules)")
            if row[2] == 1
        ]
        unique_column_sets = {
            tuple(
                row[2]
                for row in connection.execute(f"PRAGMA index_info({index_name})")
            )
            for index_name in run_rule_unique_indexes
        }
        self.assertIn(
            ("run_id", "rule_id", "rule_version"),
            unique_column_sets,
        )

        finding_foreign_keys = list(connection.execute("PRAGMA foreign_key_list(findings)"))
        composite_rule_reference = {
            (row[3], row[4])
            for row in finding_foreign_keys
            if row[2] == "run_rules"
        }
        self.assertEqual(
            composite_rule_reference,
            {
                ("run_id", "run_id"),
                ("rule_id", "rule_id"),
                ("rule_version", "rule_version"),
            },
        )

    def test_connection_configuration_enables_foreign_keys_and_query_only_mode(self) -> None:
        connection = self.make_connection()
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)

        connection.commit()
        configure_connection(connection, read_only=True)
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)
        with self.assertRaises(sqlite3.OperationalError):
            connection.execute(
                "INSERT INTO storage_metadata (key, value) VALUES ('other', 'value')"
            )

    def test_valid_run_rule_finding_and_evidence_relationships_succeed(self) -> None:
        connection = self.make_connection()
        insert_valid_run(connection)
        insert_valid_rule(connection)
        insert_valid_finding(connection)
        insert_valid_evidence(connection)

        self.assertEqual(
            connection.execute("SELECT count(*) FROM findings").fetchone()[0],
            1,
        )
        self.assertEqual(
            connection.execute("SELECT count(*) FROM finding_evidence").fetchone()[0],
            1,
        )
        self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_missing_parent_and_undeclared_rule_version_are_rejected(self) -> None:
        connection = self.make_connection()

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO run_rules (run_id, ordinal, rule_id, rule_version)
                VALUES (?, ?, ?, ?)
                """,
                (RUN_ID, 0, "fortigate.example_observation", "1.0"),
            )

        insert_valid_run(connection)
        insert_valid_rule(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            insert_valid_finding(connection, rule_version="2.0")

    def test_duplicate_primary_identities_and_invalid_checks_are_rejected(self) -> None:
        connection = self.make_connection()
        insert_valid_run(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            insert_valid_run(connection)

        insert_valid_rule(connection)
        insert_valid_finding(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            insert_valid_finding(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO finding_evidence (
                    run_id, finding_id, ordinal, canonical_path, observed_value_json,
                    source_fields_json, mapping_operation, interpretation_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    RUN_ID,
                    FINDING_ID,
                    -1,
                    "event.invalid",
                    '"value"',
                    '["event_type"]',
                    "COPIED",
                    "VERIFIED",
                ),
            )

    def test_immutable_storage_models_validate_bounded_contract_values(self) -> None:
        import_summary = StorageImportSummary(
            run_id=RUN_ID,
            findings_sha256=RUN_ID,
            summary_sha256=SUMMARY_SHA256,
            finding_count=1,
            evidence_count=1,
            rule_count=1,
        )
        self.assertEqual(import_summary.to_dict()["run_id"], RUN_ID)

        audit_result = StorageAuditResult(
            run_id=RUN_ID,
            findings_sha256=RUN_ID,
            summary_sha256=SUMMARY_SHA256,
            logical_export_sha256=LOGICAL_EXPORT_SHA256,
            reconstructed_findings_sha256=RUN_ID,
            finding_count=1,
            evidence_count=1,
            rule_count=1,
        )
        self.assertEqual(audit_result.to_dict()["finding_count"], 1)
        self.assertEqual(FindingQuery(rule_id="fortigate.example_observation").limit, 50)

        with self.assertRaises(StorageContractError):
            StorageImportSummary(
                run_id=RUN_ID,
                findings_sha256=SUMMARY_SHA256,
                summary_sha256=SUMMARY_SHA256,
                finding_count=1,
                evidence_count=1,
                rule_count=1,
            )
        with self.assertRaises(StorageContractError):
            FindingQuery(limit=0)
        with self.assertRaises(StorageContractError):
            FindingQuery(limit=True)

    def test_temporary_synthetic_database_is_cleaned_up(self) -> None:
        temporary_path: Path
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory) / "synthetic.sqlite3"
            connection = sqlite3.connect(temporary_path)
            try:
                create_storage_schema(connection)
                connection.commit()
            finally:
                connection.close()
            self.assertTrue(temporary_path.is_file())

        self.assertFalse(temporary_path.exists())
