"""Synthetic lifecycle tests for the Stage 1.6B read-only API boundary."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import inspect
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from api import ApiSettings, ApiSettingsError, create_app  # noqa: E402
from api import bridge as api_bridge  # noqa: E402
from api.bridge import ApiStartupError, verify_startup_store  # noqa: E402
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
from storage import (  # noqa: E402
    StorageAuditError,
    import_detection_run,
)
from storage import audit as storage_audit  # noqa: E402
from storage import importer as storage_importer  # noqa: E402
from storage import query as storage_query  # noqa: E402


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _build_finding(record_number: int = 1) -> DetectionFinding:
    metadata = ACTIVE_RULES[0].metadata
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
        false_positive_note="Synthetic inputs can model legitimate activity.",
    )


def _build_summary(findings_path: Path, findings: tuple[DetectionFinding, ...]) -> DetectionRunSummary:
    findings_by_rule_id: Counter[str] = Counter(
        finding.rule.rule_id for finding in findings
    )
    findings_by_rule_severity: Counter[str] = Counter(
        finding.rule.severity for finding in findings
    )
    samples_by_rule: dict[str, tuple[FindingSample, ...]] = {}
    for rule_id in findings_by_rule_id:
        samples_by_rule[rule_id] = tuple(
            FindingSample(
                finding_id=finding.finding_id,
                source_record_number=finding.source_event.source_record_number,
            )
            for finding in findings
            if finding.rule.rule_id == rule_id
        )[:5]
    return DetectionRunSummary(
        input_path=str(findings_path.parent / "synthetic_normalized_events.jsonl"),
        output_path=str(findings_path),
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
        sample_findings_by_rule=samples_by_rule,
        active_rules=tuple(
            ActiveRuleVersion(rule.metadata.rule_id, rule.metadata.version)
            for rule in ACTIVE_RULES
        ),
    )


def _stage_1_4f_envelope(summary: DetectionRunSummary) -> dict[str, object]:
    """Return a small, exact-shape synthetic Stage 1.4F summary envelope."""

    return {
        "validation_stage": "1.4F",
        "python_version": "Python 3.12.10",
        "raw": {
            "path": "data/raw/synthetic.csv",
            "file_size_bytes_before": 1,
            "file_size_bytes_after": 1,
            "sha256_before": "0" * 64,
            "sha256_after": "0" * 64,
        },
        "normalized_input": {
            "path": "data/processed/synthetic_normalized_events.jsonl",
            "file_size_bytes_before": 1,
            "file_size_bytes_after": 1,
            "sha256_before": "1" * 64,
            "sha256_after": "1" * 64,
        },
        "primary_run": summary.to_dict(),
        "primary_findings": {
            "path": "data/processed/synthetic_findings.jsonl",
            "file_size_bytes": 1,
            "sha256": "2" * 64,
        },
        "primary_audit": {
            "finding_count": summary.total_finding_count,
            "findings_by_rule_id": dict(summary.findings_by_rule_id),
            "findings_by_rule_severity": dict(summary.findings_by_rule_severity),
            "sample_findings_by_rule": {
                rule_id: [sample.to_dict() for sample in samples]
                for rule_id, samples in summary.sample_findings_by_rule.items()
            },
            "unique_matched_source_record_count": (
                summary.unique_matched_source_record_count
            ),
        },
        "determinism": {
            "secondary_findings_sha256": "2" * 64,
            "hashes_match": True,
            "temporary_findings_removed": True,
        },
        "validation_checks": {
            "full_tests_before": "PASS",
            "full_tests_after": "PASS",
            "raw_processed_git_safety_before": "PASS",
            "raw_processed_git_safety_after": "PASS",
            "git_diff_check": "PASS",
        },
        "expected_reconciliation": {
            "source_threat_observation_count": 0,
            "anomaly_subtype_observation_count": 0,
            "total_finding_count": summary.total_finding_count,
            "unique_matched_source_record_count": (
                summary.unique_matched_source_record_count
            ),
            "informational_finding_count": summary.total_finding_count,
        },
        "verdict": "PASS",
    }


@contextmanager
def _synthetic_store() -> object:
    """Create one isolated Stage 1.5 store and matching Stage 1.4F artifacts."""

    with tempfile.TemporaryDirectory() as temporary_directory:
        processed_directory = (
            Path(temporary_directory) / "project" / "data" / "processed"
        )
        processed_directory.mkdir(parents=True)
        findings = (_build_finding(),)
        findings_path = processed_directory / "synthetic_findings.jsonl"
        findings_path.write_bytes(
            b"".join(_canonical_json_bytes(finding.to_dict()) for finding in findings)
        )
        summary = _build_summary(findings_path, findings)
        summary_path = processed_directory / "synthetic_summary.json"
        summary_path.write_bytes(_canonical_json_bytes(_stage_1_4f_envelope(summary)))
        database_path = processed_directory / "synthetic_store.sqlite3"

        with (
            patch.object(storage_importer, "PROCESSED_DATA_DIRECTORY", processed_directory),
            patch.object(storage_audit, "PROCESSED_DATA_DIRECTORY", processed_directory),
            patch.object(storage_query, "PROCESSED_DATA_DIRECTORY", processed_directory),
            patch.object(api_bridge, "PROCESSED_DATA_DIRECTORY", processed_directory),
        ):
            imported = import_detection_run(findings_path, summary_path, database_path)
            yield {
                "database_path": database_path,
                "findings_path": findings_path,
                "summary_path": summary_path,
                "run_id": imported.run_id,
            }


def _settings(fixture: dict[str, object], **changes: object) -> ApiSettings:
    values: dict[str, object] = {
        "database_path": fixture["database_path"],
        "findings_path": fixture["findings_path"],
        "summary_path": fixture["summary_path"],
        "expected_run_id": fixture["run_id"],
    }
    values.update(changes)
    return ApiSettings(**values)  # type: ignore[arg-type]


class ApiSettingsTests(unittest.TestCase):
    """Settings validation is side-effect free and rejects unsafe primitives."""

    def test_settings_require_paths_lowercase_run_id_and_safe_port(self) -> None:
        paths = {
            "database_path": Path("database.sqlite3"),
            "findings_path": Path("findings.jsonl"),
            "summary_path": Path("summary.json"),
        }
        settings = ApiSettings(expected_run_id="a" * 64, **paths)
        self.assertEqual(settings.port, 8000)
        invalid_changes = (
            {"expected_run_id": "A" * 64},
            {"expected_run_id": "a" * 63},
            {"port": True},
            {"port": 0},
            {"port": 65_536},
            {"database_path": "database.sqlite3"},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes), self.assertRaises(ApiSettingsError):
                values = paths | {"expected_run_id": "a" * 64, "port": 8000}
                values.update(changes)
                ApiSettings(**values)


class ApiLifecycleTests(unittest.TestCase):
    """The lifecycle uses synthetic artifacts only and never creates a store."""

    def test_factory_does_not_open_storage_or_create_files(self) -> None:
        with _synthetic_store() as fixture:
            settings = _settings(fixture)
            database_bytes = Path(fixture["database_path"]).read_bytes()
            with patch.object(api_bridge, "audit_detection_store") as audit:
                app = create_app(settings)
            audit.assert_not_called()
            self.assertFalse(hasattr(app.state, "readiness_snapshot"))
            self.assertEqual(Path(fixture["database_path"]).read_bytes(), database_bytes)

    def test_healthy_store_has_only_health_and_schema_routes(self) -> None:
        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            findings_path = Path(fixture["findings_path"])
            summary_path = Path(fixture["summary_path"])
            bytes_before = {
                path: path.read_bytes()
                for path in (database_path, findings_path, summary_path)
            }
            app = create_app(_settings(fixture))
            with TestClient(app) as client:
                response = client.get("/healthz")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.content,
                    b'{"api_version":"1.0","status":"ready","storage_schema_version":"1.0"}',
                )
                self.assertEqual(client.get("/docs").status_code, 404)
                self.assertEqual(client.get("/redoc").status_code, 404)
                self.assertEqual(client.get("/openapi.json").status_code, 200)
                self.assertEqual(client.get("/api/v1/runs").status_code, 404)
            self.assertFalse(hasattr(app.state, "readiness_snapshot"))
            for path, expected_bytes in bytes_before.items():
                self.assertEqual(path.read_bytes(), expected_bytes)

    def test_startup_rejects_missing_artifact_wrong_run_and_mismatched_artifacts(self) -> None:
        with _synthetic_store() as fixture:
            missing_settings = _settings(
                fixture,
                summary_path=Path(fixture["summary_path"]).with_name("missing.json"),
            )
            with self.assertRaises(ApiStartupError):
                with TestClient(create_app(missing_settings)):
                    pass

        with _synthetic_store() as fixture:
            wrong_run_settings = _settings(fixture, expected_run_id="f" * 64)
            with self.assertRaises(ApiStartupError):
                with TestClient(create_app(wrong_run_settings)):
                    pass

        with _synthetic_store() as fixture:
            Path(fixture["summary_path"]).write_bytes(b"{}\n")
            with self.assertRaises(ApiStartupError):
                with TestClient(create_app(_settings(fixture))):
                    pass

    def test_startup_rejects_aliases_uris_and_upstream_inputs_before_storage(self) -> None:
        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            alias_settings = _settings(fixture, findings_path=database_path)
            with self.assertRaises(ApiStartupError):
                verify_startup_store(alias_settings)

            uri_settings = _settings(fixture, database_path=Path("file:store?mode=ro"))
            with self.assertRaises(ApiStartupError):
                verify_startup_store(uri_settings)

            processed_directory = database_path.parent
            normalized_path = processed_directory / "stage_1_3f_normalized_events.jsonl"
            normalized_path.write_bytes(b"synthetic normalized input")
            upstream_settings = _settings(fixture, findings_path=normalized_path)
            with patch.object(api_bridge, "audit_detection_store") as audit:
                with self.assertRaises(ApiStartupError):
                    verify_startup_store(upstream_settings)
            audit.assert_not_called()

            raw_path = database_path.parents[1] / "raw" / "synthetic.csv"
            raw_path.parent.mkdir()
            raw_path.write_bytes(b"synthetic raw input")
            raw_settings = _settings(fixture, findings_path=raw_path)
            with patch.object(api_bridge, "audit_detection_store") as audit:
                with self.assertRaises(ApiStartupError):
                    verify_startup_store(raw_settings)
            audit.assert_not_called()

    def test_startup_rejects_schema_corruption_multi_run_and_audit_failure(self) -> None:
        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            connection = sqlite3.connect(database_path)
            try:
                connection.execute("PRAGMA foreign_keys = OFF")
                connection.execute("DROP TABLE findings")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ApiStartupError):
                with TestClient(create_app(_settings(fixture))):
                    pass

        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            connection = sqlite3.connect(database_path)
            try:
                connection.execute(
                    "INSERT INTO detection_runs "
                    "SELECT ?, ?, ?, finding_artifact_path, summary_artifact_path, "
                    "finding_schema_version, normalized_input_schema_version, "
                    "normalized_input_record_count, evaluated_record_count, "
                    "invalid_input_count, total_finding_count, "
                    "unique_matched_source_record_count FROM detection_runs",
                    ("d" * 64, "d" * 64, "e" * 64),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ApiStartupError):
                with TestClient(create_app(_settings(fixture))):
                    pass

        with _synthetic_store() as fixture:
            with patch.object(
                api_bridge,
                "audit_detection_store",
                side_effect=StorageAuditError("SYNTHETIC_FAILURE", "Synthetic failure."),
            ):
                with self.assertRaises(ApiStartupError):
                    with TestClient(create_app(_settings(fixture))):
                        pass

    def test_changed_database_fails_health_without_rereading_artifacts(self) -> None:
        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            app = create_app(_settings(fixture))
            with TestClient(app) as client:
                before = database_path.stat()
                os.utime(
                    database_path,
                    ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
                )
                response = client.get("/healthz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "STORE_UNAVAILABLE")
            self.assertNotIn(str(database_path), response.text)

    def test_lifecycle_keeps_connections_owned_by_storage_calls(self) -> None:
        with _synthetic_store() as fixture:
            real_connect = sqlite3.connect
            with patch("sqlite3.connect", wraps=real_connect) as connect:
                app = create_app(_settings(fixture))
                with TestClient(app) as client:
                    self.assertEqual(client.get("/healthz").status_code, 200)
            self.assertTrue(connect.called)
            for call in connect.call_args_list:
                self.assertIsNot(call.kwargs.get("check_same_thread", True), False)
            self.assertFalse(hasattr(app.state, "readiness_snapshot"))

    def test_api_source_does_not_introduce_private_storage_or_import_workflow(self) -> None:
        bridge_source = inspect.getsource(api_bridge)
        app_source = inspect.getsource(sys.modules["api.app"])
        self.assertNotIn("import_detection_run", bridge_source)
        self.assertNotIn("sqlite3", bridge_source)
        self.assertNotIn("check_same_thread=False", bridge_source)
        self.assertNotIn("/api/v1/runs", app_source)


if __name__ == "__main__":
    unittest.main()
