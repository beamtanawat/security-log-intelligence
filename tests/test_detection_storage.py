"""Synthetic SQLite schema tests for Stage 1.5A storage contracts."""

from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from hashlib import sha256
from io import StringIO
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from storage.models import (  # noqa: E402
    FindingQuery,
    StorageAuditResult,
    StorageContractError,
    StorageImportSummary,
)
from storage import input as storage_input  # noqa: E402
from storage import importer as storage_importer  # noqa: E402
from storage.input import (  # noqa: E402
    ApprovedArtifactIdentity,
    StorageInputValidationError,
    validate_detection_artifacts,
)
from storage.importer import (  # noqa: E402
    StorageImportError,
    import_detection_run,
)
from storage.schema import (  # noqa: E402
    REQUIRED_INDEX_NAMES,
    STORAGE_METADATA_VALUES,
    STORAGE_TABLE_NAMES,
    configure_connection,
    create_storage_schema,
)
from detection.models import (  # noqa: E402
    ActiveRuleVersion,
    DetectionEvidence,
    DetectionFinding,
    DetectionRunSummary,
    FindingRuleReference,
    FindingSample,
    SourceEventReference,
    build_finding_id,
)
from detection.rules import ACTIVE_RULES  # noqa: E402
from load_detection_store import main as load_detection_store_main  # noqa: E402


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


def build_stage_1_4_finding(
    record_number: int,
    *,
    rule_index: int = 0,
) -> DetectionFinding:
    """Build a public-contract finding using one reviewed Stage 1.4 rule."""

    metadata = ACTIVE_RULES[rule_index].metadata
    rule = FindingRuleReference.from_metadata(metadata)
    source_event = SourceEventReference(
        source_type="fortigate",
        normalized_schema_version="1.0",
        source_record_number=record_number,
        source_record_id=f"LOGUID_OPAQUE_{record_number}",
    )
    evidence = DetectionEvidence(
        canonical_path=metadata.evidence_paths[0],
        observed_value="synthetic-source-observation",
        source_fields=("event_subtype",),
        mapping_operation="COPIED",
        interpretation_status="VERIFIED",
    )
    return DetectionFinding(
        finding_id=build_finding_id(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            source_type=source_event.source_type,
            normalized_schema_version=source_event.normalized_schema_version,
            source_record_number=source_event.source_record_number,
            source_record_id=source_event.source_record_id,
        ),
        rule=rule,
        source_event=source_event,
        reason_code=metadata.reason_code,
        summary="A synthetic source-product observation is present.",
        evidence=(evidence,),
        time_basis="NOT_USED",
        uncertainties=("Synthetic findings do not establish attack truth.",),
        false_positive_note="Synthetic source observations can model legitimate activity.",
    )


def build_stage_1_4_summary(
    findings_path: Path,
    findings: tuple[DetectionFinding, ...],
) -> DetectionRunSummary:
    """Build bounded Stage 1.4 summary metadata for synthetic finding bytes."""

    findings_by_rule_id: Counter[str] = Counter()
    findings_by_rule_severity: Counter[str] = Counter()
    samples_by_rule: dict[str, list[FindingSample]] = {}
    for finding in findings:
        findings_by_rule_id[finding.rule.rule_id] += 1
        findings_by_rule_severity[finding.rule.severity] += 1
        samples = samples_by_rule.setdefault(finding.rule.rule_id, [])
        if len(samples) < 5:
            samples.append(
                FindingSample(
                    finding_id=finding.finding_id,
                    source_record_number=finding.source_event.source_record_number,
                )
            )

    return DetectionRunSummary(
        input_path=str(findings_path.parent / "synthetic_normalized_events.jsonl"),
        output_path=str(findings_path.resolve()),
        normalized_input_schema_version="1.0",
        normalized_input_record_count=len(findings),
        evaluated_record_count=len(findings),
        invalid_input_count=0,
        total_finding_count=len(findings),
        findings_by_rule_id=dict(findings_by_rule_id),
        findings_by_rule_severity=dict(findings_by_rule_severity),
        unique_matched_source_record_count=len(
            {finding.source_event.source_record_number for finding in findings}
        ),
        sample_findings_by_rule={
            rule_id: tuple(samples) for rule_id, samples in samples_by_rule.items()
        },
        active_rules=tuple(
            ActiveRuleVersion(rule.metadata.rule_id, rule.metadata.version)
            for rule in ACTIVE_RULES
        ),
    )


def canonical_payload_bytes(payload: object) -> bytes:
    """Return compact sorted JSON bytes for a deliberately synthetic payload."""

    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def canonical_finding_bytes(findings: tuple[DetectionFinding, ...]) -> bytes:
    """Return the exact compact Stage 1.4 JSONL bytes for synthetic findings."""

    return b"".join(canonical_payload_bytes(finding.to_dict()) for finding in findings)


def write_summary(path: Path, summary: DetectionRunSummary) -> bytes:
    """Write bounded synthetic summary bytes and return the exact content."""

    content = canonical_payload_bytes(summary.to_dict())
    path.write_bytes(content)
    return content


def write_synthetic_artifacts(
    directory: Path,
    findings: tuple[DetectionFinding, ...],
) -> tuple[Path, Path, ApprovedArtifactIdentity, DetectionRunSummary]:
    """Create a synthetic approved finding/summary pair without database access."""

    findings_path = directory / "synthetic_findings.jsonl"
    findings_bytes = canonical_finding_bytes(findings)
    findings_path.write_bytes(findings_bytes)
    summary = build_stage_1_4_summary(findings_path, findings)
    summary_path = directory / "synthetic_summary.json"
    summary_bytes = write_summary(summary_path, summary)
    return (
        findings_path,
        summary_path,
        ApprovedArtifactIdentity(
            findings_sha256=sha256(findings_bytes).hexdigest(),
            summary_sha256=sha256(summary_bytes).hexdigest(),
        ),
        summary,
    )


def temporary_processed_directory(directory: Path) -> Path:
    """Create an isolated synthetic data/processed directory for import tests."""

    processed_directory = directory / "project" / "data" / "processed"
    processed_directory.mkdir(parents=True)
    return processed_directory


def finding_with_two_evidence_entries(record_number: int) -> DetectionFinding:
    """Build one valid finding with two ordered evidence projections."""

    finding = build_stage_1_4_finding(record_number)
    additional_evidence = DetectionEvidence(
        canonical_path="threat_observations.threat_name",
        observed_value="synthetic-threat-observation",
        source_fields=("threat_name",),
        mapping_operation="COPIED",
        interpretation_status="VERIFIED",
    )
    return replace(
        finding,
        evidence=tuple(
            sorted(
                (*finding.evidence, additional_evidence),
                key=lambda evidence: evidence.canonical_path,
            )
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


class StorageInputValidationTests(unittest.TestCase):
    """Synthetic tests for the Stage 1.5B strict input boundary."""

    def test_empty_valid_run_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                (),
            )

            validated = validate_detection_artifacts(
                findings_path,
                summary_path,
                identity,
            )

        self.assertEqual(validated.run_id, sha256(b"").hexdigest())
        self.assertEqual(validated.finding_count, 0)
        self.assertEqual(validated.evidence_count, 0)
        self.assertEqual(validated.rule_count, len(ACTIVE_RULES))

    def test_valid_artifacts_reconcile_exact_hashes_and_separate_summary_identity(self) -> None:
        findings = (
            build_stage_1_4_finding(1),
            build_stage_1_4_finding(2, rule_index=1),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                findings,
            )

            validated = validate_detection_artifacts(
                findings_path,
                summary_path,
                identity,
            )

            self.assertEqual(
                validated.findings_sha256,
                sha256(findings_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                validated.summary_sha256,
                sha256(summary_path.read_bytes()).hexdigest(),
            )
        self.assertEqual(validated.run_id, validated.findings_sha256)
        self.assertNotEqual(validated.run_id, validated.summary_sha256)
        self.assertEqual(validated.finding_count, 2)
        self.assertEqual(validated.evidence_count, 2)

    def test_summary_declared_future_rule_version_is_accepted(self) -> None:
        future_rule = FindingRuleReference(
            rule_id="fortigate.future_product_observation",
            version="2.0",
            name="Future product observation",
            category="SOURCE_PRODUCT_OBSERVATION",
            severity="LOW",
        )
        self.assertNotIn(
            (future_rule.rule_id, future_rule.version),
            {
                (rule.metadata.rule_id, rule.metadata.version)
                for rule in ACTIVE_RULES
            },
        )
        source_event = SourceEventReference(
            source_type="fortigate",
            normalized_schema_version="1.0",
            source_record_number=1,
            source_record_id="LOGUID_OPAQUE_1",
        )
        future_finding = DetectionFinding(
            finding_id=build_finding_id(
                rule_id=future_rule.rule_id,
                rule_version=future_rule.version,
                source_type=source_event.source_type,
                normalized_schema_version=source_event.normalized_schema_version,
                source_record_number=source_event.source_record_number,
                source_record_id=source_event.source_record_id,
            ),
            rule=future_rule,
            source_event=source_event,
            reason_code="FUTURE_PRODUCT_OBSERVATION",
            summary="A synthetic future source-product observation is present.",
            evidence=(
                DetectionEvidence(
                    canonical_path="event.future_product_observation",
                    observed_value="synthetic-source-observation",
                    source_fields=("event_subtype",),
                    mapping_operation="COPIED",
                    interpretation_status="VERIFIED",
                ),
            ),
            time_basis="NOT_USED",
            uncertainties=("Synthetic findings do not establish attack truth.",),
            false_positive_note="Synthetic source observations can model legitimate activity.",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, summary = write_synthetic_artifacts(
                directory,
                (future_finding,),
            )
            future_summary = replace(
                summary,
                active_rules=(
                    ActiveRuleVersion(future_rule.rule_id, future_rule.version),
                ),
            )
            summary_bytes = write_summary(summary_path, future_summary)
            identity = ApprovedArtifactIdentity(
                findings_sha256=sha256(findings_path.read_bytes()).hexdigest(),
                summary_sha256=sha256(summary_bytes).hexdigest(),
            )

            validated = validate_detection_artifacts(
                findings_path,
                summary_path,
                identity,
            )

        self.assertEqual(validated.finding_count, 1)
        self.assertEqual(validated.rule_count, 1)
        self.assertEqual(validated.summary.active_rules, future_summary.active_rules)

    def test_blank_or_malformed_finding_jsonl_fails_explicitly(self) -> None:
        for content, expected_code in (
            (b"\n", "BLANK_JSONL_LINE"),
            (b"{not-json}\n", "INVALID_JSONL"),
        ):
            with self.subTest(expected_code=expected_code):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    directory = Path(temporary_directory)
                    findings_path, summary_path, _, _ = write_synthetic_artifacts(
                        directory,
                        (build_stage_1_4_finding(1),),
                    )
                    findings_path.write_bytes(content)
                    identity = ApprovedArtifactIdentity(
                        findings_sha256=sha256(content).hexdigest(),
                        summary_sha256=sha256(summary_path.read_bytes()).hexdigest(),
                    )

                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(findings_path, summary_path, identity)

                self.assertEqual(context.exception.code, expected_code)
                self.assertEqual(context.exception.line_number, 1)

    def test_noncanonical_or_invalid_finding_contract_fails(self) -> None:
        finding = build_stage_1_4_finding(1)
        invalid_cases = {
            "noncanonical": lambda payload: json.dumps(
                payload,
                ensure_ascii=False,
                separators=(", ", ": "),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
            "wrong_schema": lambda payload: canonical_payload_bytes(
                {**payload, "finding_schema_version": "2.0"}
            ),
            "wrong_id": lambda payload: canonical_payload_bytes(
                {**payload, "finding_id": "0" * 64}
            ),
            "invalid_evidence": lambda payload: canonical_payload_bytes(
                {**payload, "evidence": []}
            ),
        }
        expected_codes = {
            "noncanonical": "NONCANONICAL_FINDING",
            "wrong_schema": "FINDING_CONTRACT_INVALID",
            "wrong_id": "FINDING_CONTRACT_INVALID",
            "invalid_evidence": "FINDING_CONTRACT_INVALID",
        }
        for name, build_content in invalid_cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    directory = Path(temporary_directory)
                    findings_path, summary_path, _, _ = write_synthetic_artifacts(
                        directory,
                        (finding,),
                    )
                    content = build_content(finding.to_dict())
                    findings_path.write_bytes(content)
                    identity = ApprovedArtifactIdentity(
                        findings_sha256=sha256(content).hexdigest(),
                        summary_sha256=sha256(summary_path.read_bytes()).hexdigest(),
                    )

                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(findings_path, summary_path, identity)

                self.assertEqual(context.exception.code, expected_codes[name])

    def test_duplicate_finding_id_and_wrong_order_are_rejected(self) -> None:
        duplicate = build_stage_1_4_finding(1)
        ordered = (build_stage_1_4_finding(1), build_stage_1_4_finding(2))
        cases = {
            "duplicate": (duplicate, duplicate),
            "wrong_order": (ordered[1], ordered[0]),
        }
        expected_codes = {
            "duplicate": "DUPLICATE_FINDING_ID",
            "wrong_order": "FINDING_ORDER_INVALID",
        }
        for name, findings in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    directory = Path(temporary_directory)
                    findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                        directory,
                        findings,
                    )

                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(findings_path, summary_path, identity)

                self.assertEqual(context.exception.code, expected_codes[name])

    def test_undeclared_rule_version_and_prohibited_decision_fields_fail(self) -> None:
        finding = build_stage_1_4_finding(1)
        modified_rule = FindingRuleReference(
            rule_id=finding.rule.rule_id,
            version="2.0",
            name=finding.rule.name,
            category=finding.rule.category,
            severity=finding.rule.severity,
        )
        undeclared = DetectionFinding(
            finding_id=build_finding_id(
                rule_id=modified_rule.rule_id,
                rule_version=modified_rule.version,
                source_type=finding.source_event.source_type,
                normalized_schema_version=finding.source_event.normalized_schema_version,
                source_record_number=finding.source_event.source_record_number,
                source_record_id=finding.source_event.source_record_id,
            ),
            rule=modified_rule,
            source_event=finding.source_event,
            reason_code=finding.reason_code,
            summary=finding.summary,
            evidence=finding.evidence,
            time_basis=finding.time_basis,
            uncertainties=finding.uncertainties,
            false_positive_note=finding.false_positive_note,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                (undeclared,),
            )
            with self.assertRaises(StorageInputValidationError) as context:
                validate_detection_artifacts(findings_path, summary_path, identity)
            self.assertEqual(context.exception.code, "UNDECLARED_RULE_VERSION")

            payload = finding.to_dict()
            payload["is_attack"] = True
            prohibited_content = canonical_payload_bytes(payload)
            findings_path.write_bytes(prohibited_content)
            prohibited_identity = ApprovedArtifactIdentity(
                findings_sha256=sha256(prohibited_content).hexdigest(),
                summary_sha256=sha256(summary_path.read_bytes()).hexdigest(),
            )
            with self.assertRaises(StorageInputValidationError) as context:
                validate_detection_artifacts(
                    findings_path,
                    summary_path,
                    prohibited_identity,
                )
            self.assertEqual(context.exception.code, "PROHIBITED_DECISION_FIELD")

    def test_malformed_summary_and_missing_summary_field_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, summary = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            duplicate_active_rules = summary.to_dict()
            duplicate_active_rules["active_rules"].append(
                duplicate_active_rules["active_rules"][0]
            )
            for content, expected_code in (
                (b"{not-json}", "INVALID_SUMMARY_JSON"),
                (
                    canonical_payload_bytes(
                        {
                            key: value
                            for key, value in summary.to_dict().items()
                            if key != "active_rules"
                        }
                    ),
                    "SUMMARY_SCHEMA_MISMATCH",
                ),
                (
                    canonical_payload_bytes(duplicate_active_rules),
                    "SUMMARY_CONTRACT_INVALID",
                ),
                (
                    canonical_payload_bytes(
                        replace(
                            summary,
                            output_path=str(directory / "different_findings.jsonl"),
                        ).to_dict()
                    ),
                    "SUMMARY_OUTPUT_PATH_MISMATCH",
                ),
            ):
                with self.subTest(expected_code=expected_code):
                    summary_path.write_bytes(content)
                    identity = ApprovedArtifactIdentity(
                        findings_sha256=sha256(findings_path.read_bytes()).hexdigest(),
                        summary_sha256=sha256(content).hexdigest(),
                    )
                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(findings_path, summary_path, identity)
                    self.assertEqual(context.exception.code, expected_code)

    def test_summary_count_reconciliation_mismatches_fail(self) -> None:
        finding = build_stage_1_4_finding(1)
        other_rule_id = ACTIVE_RULES[1].metadata.rule_id
        original_sample = FindingSample(
            finding_id=finding.finding_id,
            source_record_number=finding.source_event.source_record_number,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, summary = write_synthetic_artifacts(
                directory,
                (finding,),
            )
            mismatches = {
                "finding_count": (
                    replace(
                        summary,
                        total_finding_count=2,
                        findings_by_rule_id={finding.rule.rule_id: 2},
                        findings_by_rule_severity={finding.rule.severity: 2},
                    ),
                    "SUMMARY_FINDING_COUNT_MISMATCH",
                ),
                "rule_count": (
                    replace(
                        summary,
                        findings_by_rule_id={other_rule_id: 1},
                        sample_findings_by_rule={other_rule_id: (original_sample,)},
                    ),
                    "SUMMARY_RULE_COUNT_MISMATCH",
                ),
                "severity_count": (
                    replace(summary, findings_by_rule_severity={"LOW": 1}),
                    "SUMMARY_SEVERITY_COUNT_MISMATCH",
                ),
                "matched_record_count": (
                    replace(summary, unique_matched_source_record_count=2),
                    "SUMMARY_MATCHED_RECORD_COUNT_MISMATCH",
                ),
                "evaluated_record_count": (
                    replace(summary, evaluated_record_count=2),
                    "SUMMARY_RECORD_COUNT_MISMATCH",
                ),
                "invalid_input_count": (
                    replace(summary, invalid_input_count=1),
                    "SUMMARY_INVALID_INPUT_COUNT",
                ),
                "samples": (
                    replace(summary, sample_findings_by_rule={}),
                    "SUMMARY_SAMPLE_MISMATCH",
                ),
            }
            for name, (mismatched_summary, expected_code) in mismatches.items():
                with self.subTest(name=name):
                    summary_bytes = write_summary(summary_path, mismatched_summary)
                    identity = ApprovedArtifactIdentity(
                        findings_sha256=sha256(findings_path.read_bytes()).hexdigest(),
                        summary_sha256=sha256(summary_bytes).hexdigest(),
                    )
                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(findings_path, summary_path, identity)
                    self.assertEqual(context.exception.code, expected_code)

    def test_expected_artifact_hash_mismatches_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            mismatches = (
                (
                    ApprovedArtifactIdentity("0" * 64, identity.summary_sha256),
                    "FINDINGS_HASH_MISMATCH",
                ),
                (
                    ApprovedArtifactIdentity(identity.findings_sha256, "1" * 64),
                    "SUMMARY_HASH_MISMATCH",
                ),
            )
            for mismatched_identity, expected_code in mismatches:
                with self.subTest(expected_code=expected_code):
                    with self.assertRaises(StorageInputValidationError) as context:
                        validate_detection_artifacts(
                            findings_path,
                            summary_path,
                            mismatched_identity,
                        )
                    self.assertEqual(context.exception.code, expected_code)

    def test_raw_and_normalized_artifacts_are_rejected_before_opening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            _, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            fake_project_root = directory / "project"
            raw_path = fake_project_root / "data" / "raw" / "blocked.csv"
            normalized_path = (
                fake_project_root
                / "data"
                / "processed"
                / "stage_1_3f_normalized_events.jsonl"
            )
            raw_path.parent.mkdir(parents=True)
            normalized_path.parent.mkdir(parents=True)
            raw_path.write_text("not-opened", encoding="utf-8")
            normalized_path.write_text("not-opened", encoding="utf-8")

            with patch.object(storage_input, "PROJECT_ROOT", fake_project_root):
                for blocked_path in (raw_path, normalized_path):
                    with self.subTest(blocked_path=blocked_path.name):
                        with patch.object(
                            Path,
                            "open",
                            side_effect=AssertionError("blocked path was opened"),
                        ) as open_mock:
                            with self.assertRaises(StorageInputValidationError) as context:
                                validate_detection_artifacts(
                                    blocked_path,
                                    summary_path,
                                    identity,
                                )
                        self.assertEqual(
                            context.exception.code,
                            "UPSTREAM_ARTIFACT_FORBIDDEN",
                        )
                        open_mock.assert_not_called()

    def test_finding_jsonl_streaming_does_not_use_whole_file_read_helpers(self) -> None:
        findings = tuple(build_stage_1_4_finding(number) for number in range(1, 8))
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, identity, _ = write_synthetic_artifacts(
                directory,
                findings,
            )
            original_read_bytes = Path.read_bytes

            def guarded_read_bytes(path: Path) -> bytes:
                if path.resolve() == findings_path.resolve():
                    raise AssertionError("finding JSONL must be streamed, not read at once")
                return original_read_bytes(path)

            def blocked_read_text(path: Path, *args: object, **kwargs: object) -> str:
                raise AssertionError("finding JSONL must not use read_text")

            with patch.object(Path, "read_bytes", new=guarded_read_bytes), patch.object(
                Path,
                "read_text",
                new=blocked_read_text,
            ):
                validated = validate_detection_artifacts(
                    findings_path,
                    summary_path,
                    identity,
                )

        self.assertEqual(validated.finding_count, len(findings))


class StorageImportTests(unittest.TestCase):
    """Synthetic Stage 1.5C tests for transactional single-run database import."""

    def test_import_creates_new_database_and_preserves_finding_projections(self) -> None:
        findings = (
            finding_with_two_evidence_entries(1),
            build_stage_1_4_finding(2, rule_index=1),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, summary = write_synthetic_artifacts(
                directory,
                findings,
            )
            processed_directory = temporary_processed_directory(directory)
            database_path = processed_directory / "synthetic_store.sqlite3"

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                imported = import_detection_run(
                    findings_path,
                    summary_path,
                    database_path,
                )

            self.assertTrue(database_path.is_file())
            self.assertEqual(imported.run_id, imported.findings_sha256)
            self.assertEqual(imported.finding_count, len(findings))
            self.assertEqual(imported.evidence_count, 3)
            self.assertEqual(imported.rule_count, len(summary.active_rules))
            self.assertFalse(list(processed_directory.glob(".synthetic_store.*")))

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT run_id, findings_sha256, summary_sha256, total_finding_count "
                        "FROM detection_runs"
                    ).fetchone(),
                    (
                        imported.run_id,
                        imported.findings_sha256,
                        imported.summary_sha256,
                        len(findings),
                    ),
                )
                self.assertEqual(
                    tuple(
                        connection.execute(
                            "SELECT rule_id, rule_version FROM run_rules ORDER BY ordinal"
                        )
                    ),
                    tuple((rule.rule_id, rule.version) for rule in summary.active_rules),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                    len(findings),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM finding_evidence").fetchone()[0],
                    3,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT canonical_finding_json FROM findings "
                        "WHERE finding_id = ?",
                        (findings[0].finding_id,),
                    ).fetchone()[0],
                    canonical_payload_bytes(findings[0].to_dict())[:-1].decode("utf-8"),
                )
                self.assertEqual(
                    tuple(
                        connection.execute(
                            "SELECT canonical_path, observed_value_json, source_fields_json, "
                            "mapping_operation, interpretation_status "
                            "FROM finding_evidence WHERE finding_id = ? ORDER BY ordinal",
                            (findings[0].finding_id,),
                        )
                    ),
                    tuple(
                        (
                            evidence.canonical_path,
                            canonical_payload_bytes(evidence.observed_value)[:-1].decode(
                                "utf-8"
                            ),
                            canonical_payload_bytes(
                                list(evidence.source_fields)
                            )[:-1].decode("utf-8"),
                            evidence.mapping_operation,
                            evidence.interpretation_status,
                        )
                        for evidence in findings[0].evidence
                    ),
                )
                self.assertIsNone(
                    connection.execute("PRAGMA foreign_key_check").fetchone()
                )
            finally:
                connection.close()

    def test_empty_valid_run_creates_a_single_run_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(directory, ())
            processed_directory = temporary_processed_directory(directory)
            database_path = processed_directory / "empty.sqlite3"

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                imported = import_detection_run(
                    findings_path,
                    summary_path,
                    database_path,
                )

            self.assertEqual(imported.finding_count, 0)
            self.assertEqual(imported.evidence_count, 0)
            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM detection_runs").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                    0,
                )
            finally:
                connection.close()

    def test_existing_final_database_is_rejected_without_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            processed_directory = temporary_processed_directory(directory)
            database_path = processed_directory / "existing.sqlite3"
            original_bytes = b"existing database must remain unchanged"
            database_path.write_bytes(original_bytes)

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                with self.assertRaises(StorageImportError) as context:
                    import_detection_run(findings_path, summary_path, database_path)

            self.assertEqual(context.exception.code, "DATABASE_EXISTS")
            self.assertEqual(database_path.read_bytes(), original_bytes)
            self.assertFalse(list(processed_directory.glob(".existing.*")))

    def test_invalid_input_and_mid_import_failure_publish_no_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            processed_directory = temporary_processed_directory(directory)
            invalid_database_path = processed_directory / "invalid.sqlite3"
            findings_path.write_bytes(b"{not-json}\n")

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                with self.assertRaises(StorageInputValidationError):
                    import_detection_run(
                        findings_path,
                        summary_path,
                        invalid_database_path,
                    )

            self.assertFalse(invalid_database_path.exists())
            self.assertFalse(list(processed_directory.glob(".invalid.*")))

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1), build_stage_1_4_finding(2)),
            )
            processed_directory = temporary_processed_directory(directory)
            failed_database_path = processed_directory / "failed.sqlite3"

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ), patch.object(
                storage_importer,
                "_insert_finding",
                side_effect=StorageImportError("INJECTED_FAILURE", "Synthetic failure."),
            ):
                with self.assertRaises(StorageImportError) as context:
                    import_detection_run(
                        findings_path,
                        summary_path,
                        failed_database_path,
                    )

            self.assertEqual(context.exception.code, "INJECTED_FAILURE")
            self.assertFalse(failed_database_path.exists())
            self.assertFalse(list(processed_directory.glob(".failed.*")))

    def test_unsafe_output_and_upstream_artifacts_are_rejected_before_opening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            processed_directory = temporary_processed_directory(directory)

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                with self.assertRaises(StorageImportError) as context:
                    import_detection_run(findings_path, summary_path, findings_path)
            self.assertEqual(context.exception.code, "DATABASE_INPUT_PATH_EQUAL")

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                with self.assertRaises(StorageImportError) as context:
                    import_detection_run(
                        findings_path,
                        summary_path,
                        directory / "outside_processed.sqlite3",
                    )
            self.assertEqual(context.exception.code, "DATABASE_OUTSIDE_PROCESSED")

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ):
                with self.assertRaises(StorageImportError) as context:
                    import_detection_run(
                        findings_path,
                        summary_path,
                        processed_directory / "missing_parent" / "store.sqlite3",
                    )
            self.assertEqual(context.exception.code, "DATABASE_PARENT_UNAVAILABLE")

            fake_project_root = directory / "upstream_project"
            raw_path = fake_project_root / "data" / "raw" / "blocked.csv"
            normalized_path = (
                fake_project_root
                / "data"
                / "processed"
                / "stage_1_3f_normalized_events.jsonl"
            )
            raw_path.parent.mkdir(parents=True)
            normalized_path.parent.mkdir(parents=True)
            raw_path.write_text("not-opened", encoding="utf-8")
            normalized_path.write_text("not-opened", encoding="utf-8")
            blocked_database_path = processed_directory / "blocked.sqlite3"

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ), patch.object(storage_input, "PROJECT_ROOT", fake_project_root):
                for upstream_path in (raw_path, normalized_path):
                    with self.subTest(upstream_path=upstream_path.name), patch.object(
                        Path,
                        "open",
                        side_effect=AssertionError("upstream input was opened"),
                    ) as open_mock:
                        with self.assertRaises(StorageInputValidationError) as context:
                            import_detection_run(
                                upstream_path,
                                summary_path,
                                blocked_database_path,
                            )
                    self.assertEqual(context.exception.code, "UPSTREAM_ARTIFACT_FORBIDDEN")
                    open_mock.assert_not_called()
                    self.assertFalse(blocked_database_path.exists())

    def test_import_cli_prints_only_bounded_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            findings_path, summary_path, _, _ = write_synthetic_artifacts(
                directory,
                (build_stage_1_4_finding(1),),
            )
            processed_directory = temporary_processed_directory(directory)
            database_path = processed_directory / "cli.sqlite3"
            stdout = StringIO()
            stderr = StringIO()

            with patch.object(
                storage_importer,
                "PROCESSED_DATA_DIRECTORY",
                processed_directory,
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = load_detection_store_main(
                    (
                        "--findings",
                        str(findings_path),
                        "--summary",
                        str(summary_path),
                        "--database",
                        str(database_path),
                    )
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                json.loads(stdout.getvalue()),
                {
                    "evidence_count": 1,
                    "finding_count": 1,
                    "findings_sha256": sha256(findings_path.read_bytes()).hexdigest(),
                    "rule_count": len(ACTIVE_RULES),
                    "run_id": sha256(findings_path.read_bytes()).hexdigest(),
                    "storage_schema_version": "1.0",
                    "summary_sha256": sha256(summary_path.read_bytes()).hexdigest(),
                },
            )
