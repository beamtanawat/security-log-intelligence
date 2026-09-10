"""Synthetic tests for the bounded Stage 1.6 read-only API boundary."""

from __future__ import annotations

import ast
from collections import Counter
from contextlib import contextmanager, redirect_stderr
from dataclasses import replace
from http.client import HTTPConnection
import importlib.util
import inspect
from io import StringIO
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import uvicorn


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from api import ApiSettings, ApiSettingsError, create_app  # noqa: E402
from api import app as api_app  # noqa: E402
from api import bridge as api_bridge  # noqa: E402
from api.bridge import ApiStartupError, verify_startup_store  # noqa: E402
import serve_api  # noqa: E402
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
    FindingQuery,
    StorageAuditError,
    import_detection_run,
    list_findings,
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


_DEFAULT_SOURCE_IDENTIFIER = object()


def _build_finding(
    record_number: int = 1,
    *,
    rule_index: int = 0,
    source_record_id: str | None | object = _DEFAULT_SOURCE_IDENTIFIER,
    observed_value: object = "synthetic-source-observation",
) -> DetectionFinding:
    metadata = ACTIVE_RULES[rule_index].metadata
    rule = FindingRuleReference.from_metadata(metadata)
    if source_record_id is _DEFAULT_SOURCE_IDENTIFIER:
        source_record_id = f"LOGUID_OPAQUE_{record_number}"
    source_event = SourceEventReference(
        source_type="fortigate",
        normalized_schema_version="1.0",
        source_record_number=record_number,
        source_record_id=source_record_id,
    )
    evidence = DetectionEvidence(
        canonical_path=metadata.evidence_paths[0],
        observed_value=observed_value,
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
def _synthetic_store(findings: tuple[DetectionFinding, ...] | None = None) -> object:
    """Create one isolated Stage 1.5 store and matching Stage 1.4F artifacts."""

    with tempfile.TemporaryDirectory() as temporary_directory:
        processed_directory = (
            Path(temporary_directory) / "project" / "data" / "processed"
        )
        processed_directory.mkdir(parents=True)
        if findings is None:
            findings = (_build_finding(),)
        findings = tuple(
            sorted(
                findings,
                key=lambda finding: (
                    finding.source_event.source_record_number,
                    finding.rule.rule_id,
                ),
            )
        )
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


def _test_client(
    app: object,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Use an approved local Host instead of TestClient's testserver default."""

    return TestClient(
        app,
        base_url="http://127.0.0.1",
        raise_server_exceptions=raise_server_exceptions,
    )


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
            with _test_client(app) as client:
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
                with _test_client(create_app(missing_settings)):
                    pass

        with _synthetic_store() as fixture:
            wrong_run_settings = _settings(fixture, expected_run_id="f" * 64)
            with self.assertRaises(ApiStartupError):
                with _test_client(create_app(wrong_run_settings)):
                    pass

        with _synthetic_store() as fixture:
            Path(fixture["summary_path"]).write_bytes(b"{}\n")
            with self.assertRaises(ApiStartupError):
                with _test_client(create_app(_settings(fixture))):
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
                with _test_client(create_app(_settings(fixture))):
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
                with _test_client(create_app(_settings(fixture))):
                    pass

        with _synthetic_store() as fixture:
            with patch.object(
                api_bridge,
                "audit_detection_store",
                side_effect=StorageAuditError("SYNTHETIC_FAILURE", "Synthetic failure."),
            ):
                with self.assertRaises(ApiStartupError):
                    with _test_client(create_app(_settings(fixture))):
                        pass

    def test_changed_database_fails_health_without_rereading_artifacts(self) -> None:
        with _synthetic_store() as fixture:
            database_path = Path(fixture["database_path"])
            app = create_app(_settings(fixture))
            with _test_client(app) as client:
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
                with _test_client(app) as client:
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
        self.assertNotIn("sqlite3", app_source)
        self.assertNotIn("storage.query", app_source)
        self.assertNotIn("storage.schema", app_source)
        self.assertNotIn("serve_api", app_source)
        self.assertNotIn("validate_api", app_source)


class ApiFindingRouteTests(unittest.TestCase):
    """Synthetic contract tests for the Stage 1.6C findings routes."""

    def _findings(self) -> tuple[DetectionFinding, ...]:
        return (
            _build_finding(1, rule_index=0),
            _build_finding(1, rule_index=1),
            _build_finding(
                2,
                rule_index=0,
                source_record_id=None,
                observed_value={"nested": ["evidence", {"count": 2}]},
            ),
        )

    def _list_path(self, run_id: str) -> str:
        return f"/api/v1/runs/{run_id}/findings"

    def _detail_path(self, run_id: str, finding_id: str) -> str:
        return f"{self._list_path(run_id)}/{finding_id}"

    def test_list_defaults_limits_order_and_no_pagination_claim(self) -> None:
        findings = self._findings()
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            with _test_client(create_app(_settings(fixture))) as client:
                default_response = client.get(self._list_path(run_id))
                minimum_response = client.get(self._list_path(run_id), params={"limit": "1"})
                maximum_response = client.get(self._list_path(run_id), params={"limit": "500"})

        self.assertEqual(default_response.status_code, 200)
        self.assertEqual(minimum_response.status_code, 200)
        self.assertEqual(maximum_response.status_code, 200)
        default_payload = default_response.json()
        self.assertEqual(default_payload["limit"], 50)
        self.assertEqual(default_payload["returned_count"], 3)
        expected_findings = sorted(
            findings,
            key=lambda finding: (
                finding.source_event.source_record_number,
                finding.rule.rule_id,
                finding.rule.version,
                finding.finding_id,
            ),
        )
        self.assertEqual(
            default_payload["items"],
            [finding.to_dict() for finding in expected_findings],
        )
        same_source_record = [
            item
            for item in default_payload["items"]
            if item["source_event"]["source_record_number"] == 1
        ]
        self.assertEqual(len(same_source_record), 2)
        self.assertNotEqual(
            same_source_record[0]["rule"]["rule_id"],
            same_source_record[1]["rule"]["rule_id"],
        )
        self.assertEqual(minimum_response.json()["returned_count"], 1)
        self.assertEqual(maximum_response.json()["limit"], 500)
        self.assertEqual(maximum_response.json()["returned_count"], 3)
        self.assertEqual(
            set(default_payload),
            {"api_version", "run_id", "limit", "returned_count", "items"},
        )
        self.assertFalse({"total", "filtered_total", "next_cursor", "has_more", "is_complete"} & set(default_payload))

    def test_list_supports_each_filter_combined_filter_and_valid_no_match(self) -> None:
        findings = self._findings()
        first, second, third = findings
        filters = {
            "finding_id": first.finding_id,
            "rule_id": first.rule.rule_id,
            "rule_version": first.rule.version,
            "severity": first.rule.severity,
            "reason_code": first.reason_code,
            "source_type": first.source_event.source_type,
            "source_record_number": str(first.source_event.source_record_number),
            "evidence_path": first.evidence[0].canonical_path,
        }
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            with _test_client(create_app(_settings(fixture))) as client:
                for name, value in filters.items():
                    with self.subTest(name=name):
                        response = client.get(self._list_path(run_id), params={name: value})
                        self.assertEqual(response.status_code, 200)
                        self.assertGreaterEqual(response.json()["returned_count"], 1)
                combined = client.get(
                    self._list_path(run_id),
                    params={
                        "rule_id": first.rule.rule_id,
                        "source_record_number": str(first.source_event.source_record_number),
                    },
                )
                no_match = client.get(
                    self._list_path(run_id), params={"source_type": "unmatched-source"}
                )
                sql_text = client.get(
                    self._list_path(run_id),
                    params={"source_type": "fortigate' OR 1=1 --"},
                )

        self.assertEqual(combined.status_code, 200)
        self.assertEqual(combined.json()["returned_count"], 1)
        self.assertEqual(combined.json()["items"][0]["finding_id"], first.finding_id)
        self.assertEqual(no_match.status_code, 200)
        self.assertEqual(no_match.json()["returned_count"], 0)
        self.assertEqual(no_match.json()["items"], [])
        self.assertEqual(sql_text.status_code, 200)
        self.assertEqual(sql_text.json()["items"], [])
        self.assertNotEqual(second.finding_id, third.finding_id)

    def test_list_rejects_unknown_duplicate_blank_and_invalid_values(self) -> None:
        with _synthetic_store(self._findings()) as fixture:
            run_id = str(fixture["run_id"])
            path = self._list_path(run_id)
            with _test_client(create_app(_settings(fixture))) as client:
                invalid_limits = ("0", "501", "+1", " 1", "1.0", "1e1", "true")
                for value in invalid_limits:
                    with self.subTest(limit=value):
                        response = client.get(path, params={"limit": value})
                        self.assertEqual(response.status_code, 422)
                invalid_record_numbers = ("0", "-1", "1.0", "1e1", "true", "9223372036854775808")
                for value in invalid_record_numbers:
                    with self.subTest(source_record_number=value):
                        response = client.get(path, params={"source_record_number": value})
                        self.assertEqual(response.status_code, 422)
                responses = (
                    client.get(path, params={"unexpected": "value"}),
                    client.get(f"{path}?limit=1&limit=2"),
                    client.get(path, params={"source_type": ""}),
                    client.get(path, params={"severity": "CRITICAL"}),
                )

        for response in responses:
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
            self.assertNotIn("value", response.text)

    def test_list_is_bounded_when_synthetic_store_has_more_than_500_matches(self) -> None:
        findings = tuple(_build_finding(record_number) for record_number in range(1, 502))
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            with _test_client(create_app(_settings(fixture))) as client:
                default_response = client.get(self._list_path(run_id))
                maximum_response = client.get(self._list_path(run_id), params={"limit": "500"})

        self.assertEqual(default_response.status_code, 200)
        self.assertEqual(default_response.json()["returned_count"], 50)
        self.assertEqual(maximum_response.status_code, 200)
        self.assertEqual(maximum_response.json()["returned_count"], 500)
        self.assertEqual(maximum_response.json()["limit"], 500)
        self.assertNotIn("has_more", maximum_response.json())

    def test_detail_preserves_complete_canonical_finding_values(self) -> None:
        findings = self._findings()
        optional_finding = findings[2]
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            with _test_client(create_app(_settings(fixture))) as client:
                response = client.get(self._detail_path(run_id, optional_finding.finding_id))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["finding"], optional_finding.to_dict())
        self.assertIsNone(payload["finding"]["source_event"]["source_record_id"])
        self.assertEqual(
            payload["finding"]["evidence"][0]["observed_value"],
            {"nested": ["evidence", {"count": 2}]},
        )

    def test_detail_and_run_scope_errors_do_not_query_other_runs(self) -> None:
        findings = self._findings()
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            path = self._detail_path(run_id, findings[0].finding_id)
            with _test_client(create_app(_settings(fixture))) as client:
                valid = client.get(path)
                unknown = client.get(self._detail_path(run_id, "e" * 64))
                malformed_run = client.get(self._detail_path("bad", findings[0].finding_id))
                malformed_finding = client.get(self._detail_path(run_id, "bad"))
                with patch.object(api_app, "get_finding") as finding_lookup:
                    wrong_run = client.get(self._detail_path("f" * 64, findings[0].finding_id))
                finding_lookup.assert_not_called()
                with patch.object(api_app, "list_findings") as findings_lookup:
                    wrong_run_list = client.get(self._list_path("f" * 64))
                findings_lookup.assert_not_called()
                extra_query = client.get(f"{path}?limit=1")

        self.assertEqual(valid.status_code, 200)
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(unknown.json()["error"]["code"], "FINDING_NOT_FOUND")
        self.assertEqual(wrong_run.status_code, 404)
        self.assertEqual(wrong_run.json()["error"]["code"], "RUN_NOT_FOUND")
        self.assertEqual(wrong_run_list.status_code, 404)
        self.assertEqual(wrong_run_list.json()["error"]["code"], "RUN_NOT_FOUND")
        self.assertEqual(malformed_run.status_code, 422)
        self.assertEqual(malformed_finding.status_code, 422)
        self.assertEqual(extra_query.status_code, 422)

    def test_identity_guard_and_impossible_finding_run_mismatch_fail_closed(self) -> None:
        findings = self._findings()
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            database_path = Path(fixture["database_path"])
            with _test_client(create_app(_settings(fixture))) as client:
                before = database_path.stat()
                os.utime(
                    database_path,
                    ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
                )
                changed_response = client.get(self._list_path(run_id))

        self.assertEqual(changed_response.status_code, 503)
        self.assertEqual(changed_response.json()["error"]["code"], "STORE_UNAVAILABLE")

        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            database_path = Path(fixture["database_path"])
            stored = list_findings(database_path, FindingQuery(run_id=run_id, limit=1))[0]
            inconsistent = replace(stored, run_id="b" * 64)
            with patch.object(api_app, "list_findings", return_value=(inconsistent,)):
                with _test_client(create_app(_settings(fixture))) as client:
                    mismatch_response = client.get(self._list_path(run_id))

        self.assertEqual(mismatch_response.status_code, 503)
        self.assertEqual(mismatch_response.json()["error"]["code"], "STORE_UNAVAILABLE")

    def test_list_and_detail_response_bodies_are_deterministic(self) -> None:
        findings = self._findings()
        with _synthetic_store(findings) as fixture:
            run_id = str(fixture["run_id"])
            list_path = self._list_path(run_id)
            detail_path = self._detail_path(run_id, findings[0].finding_id)
            with _test_client(create_app(_settings(fixture))) as client:
                first_list = client.get(list_path)
                second_list = client.get(list_path)
                first_detail = client.get(detail_path)
                second_detail = client.get(detail_path)

        self.assertEqual(first_list.status_code, 200)
        self.assertEqual(first_list.content, second_list.content)
        self.assertEqual(first_detail.status_code, 200)
        self.assertEqual(first_detail.content, second_detail.content)


class ApiHttpSafetyTests(unittest.TestCase):
    """Synthetic Stage 1.6D tests for the bounded local HTTP boundary."""

    @staticmethod
    def _list_path(run_id: str) -> str:
        return f"/api/v1/runs/{run_id}/findings"

    @classmethod
    def _detail_path(cls, run_id: str, finding_id: str) -> str:
        return f"{cls._list_path(run_id)}/{finding_id}"

    def _assert_application_headers(self, response: object) -> None:
        self.assertEqual(response.headers["cache-control"], "no-store")  # type: ignore[attr-defined]
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")  # type: ignore[attr-defined]
        self.assertNotIn("access-control-allow-origin", response.headers)  # type: ignore[attr-defined]

    def test_local_host_allowlist_and_forwarded_headers(self) -> None:
        with _synthetic_store() as fixture:
            app = create_app(_settings(fixture))
            with _test_client(app) as client:
                for host in ("localhost", "localhost:8000", "127.0.0.1", "127.0.0.1:8000"):
                    with self.subTest(allowed_host=host):
                        response = client.get("/healthz", headers={"Host": host})
                        self.assertEqual(response.status_code, 200)
                        self._assert_application_headers(response)

                forwarded_headers = {
                    "Host": "127.0.0.1",
                    "Forwarded": "host=untrusted.invalid",
                    "X-Forwarded-Host": "untrusted.invalid",
                }
                self.assertEqual(
                    client.get("/healthz", headers=forwarded_headers).status_code,
                    200,
                )

                for host in ("testserver", "0.0.0.0", "untrusted.invalid"):
                    with self.subTest(rejected_host=host):
                        response = client.get("/healthz", headers={"Host": host})
                        self.assertEqual(response.status_code, 400)
                        self.assertEqual(response.content, b"Invalid host header")
                        self.assertNotIn("cache-control", response.headers)

                response = client.get(
                    "/healthz",
                    headers={
                        "Host": "untrusted.invalid",
                        "Forwarded": "host=127.0.0.1",
                        "X-Forwarded-Host": "127.0.0.1",
                    },
                )
                self.assertEqual(response.status_code, 400)

    def test_origin_rejection_and_application_security_headers(self) -> None:
        with _synthetic_store() as fixture:
            with _test_client(create_app(_settings(fixture))) as client:
                ready = client.get("/healthz")
                self.assertEqual(ready.status_code, 200)
                self._assert_application_headers(ready)

                first = client.get(
                    "/healthz",
                    headers={"Origin": "https://untrusted.invalid"},
                )
                second = client.get(
                    "/healthz",
                    headers={"Origin": "https://untrusted.invalid"},
                )
                blank_origin = client.get("/healthz", headers={"Origin": ""})

        for response in (first, second, blank_origin):
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["error"]["code"], "ORIGIN_NOT_ALLOWED")
            self._assert_application_headers(response)
        self.assertEqual(first.content, second.content)

    def test_request_target_limit_uses_raw_path_and_runs_before_routing(self) -> None:
        with _synthetic_store() as fixture:
            run_id = str(fixture["run_id"])
            app = create_app(_settings(fixture))
            exact_path = "/" + "x" * (api_app.MAX_REQUEST_TARGET_BYTES - 1)
            over_path = "/" + "x" * api_app.MAX_REQUEST_TARGET_BYTES
            health_path = "/healthz"
            exact_query = "x" * (
                api_app.MAX_REQUEST_TARGET_BYTES - len(health_path) - 1
            )
            with _test_client(app) as client:
                exact_response = client.get(exact_path)
                exact_query_response = client.get(f"{health_path}?{exact_query}")
                with patch.object(api_app, "require_current_store") as current_store:
                    first_over_limit = client.get(over_path)
                    second_over_limit = client.get(over_path)
                    over_query_response = client.get(f"{health_path}?{exact_query}x")
                current_store.assert_not_called()
                normal_response = client.get(self._list_path(run_id))

        self.assertEqual(normal_response.status_code, 200)
        self.assertEqual(exact_response.status_code, 404)
        self.assertEqual(exact_response.json()["error"]["code"], "NOT_FOUND")
        self.assertEqual(exact_query_response.status_code, 422)
        self.assertEqual(
            exact_query_response.json()["error"]["code"], "INVALID_REQUEST"
        )
        for response in (first_over_limit, second_over_limit, over_query_response):
            self.assertEqual(response.status_code, 414)
            self.assertEqual(
                response.json()["error"]["code"], "REQUEST_TARGET_TOO_LONG"
            )
            self._assert_application_headers(response)
        self.assertEqual(first_over_limit.content, second_over_limit.content)

    def test_query_free_routes_and_stable_http_error_mapping(self) -> None:
        finding = _build_finding()
        with _synthetic_store((finding,)) as fixture:
            run_id = str(fixture["run_id"])
            list_path = self._list_path(run_id)
            detail_path = self._detail_path(run_id, finding.finding_id)
            with _test_client(create_app(_settings(fixture))) as client:
                first_openapi = client.get("/openapi.json")
                second_openapi = client.get("/openapi.json")
                openapi_head = client.head("/openapi.json")
                health_query = client.get("/healthz?unexpected=value")
                openapi_query = client.get("/openapi.json?unexpected=value")
                invalid_request = client.get(f"{list_path}?limit=0")
                unknown_route = client.get("/not-a-route")
                wrong_run = client.get(self._list_path("f" * 64))
                missing_finding = client.get(self._detail_path(run_id, "e" * 64))
                method_responses = tuple(
                    getattr(client, method)(detail_path)
                    for method in ("post", "put", "patch", "delete", "options")
                )

        self.assertEqual(first_openapi.status_code, 200)
        self.assertEqual(first_openapi.content, second_openapi.content)
        self.assertEqual(first_openapi.content, api_app._json_bytes(first_openapi.json()))
        self._assert_application_headers(first_openapi)
        self.assertEqual(openapi_head.status_code, 200)
        self._assert_application_headers(openapi_head)

        expected_codes = (
            (health_query, "INVALID_REQUEST"),
            (openapi_query, "INVALID_REQUEST"),
            (invalid_request, "INVALID_REQUEST"),
            (unknown_route, "NOT_FOUND"),
            (wrong_run, "RUN_NOT_FOUND"),
            (missing_finding, "FINDING_NOT_FOUND"),
        )
        for response, code in expected_codes:
            self._assert_application_headers(response)
            self.assertEqual(response.json()["error"]["code"], code)
        for response in method_responses:
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.json()["error"]["code"], "METHOD_NOT_ALLOWED")
            self.assertIn("GET", response.headers["allow"])
            self._assert_application_headers(response)

    def test_response_budget_allows_exact_size_and_rejects_oversized_results(self) -> None:
        empty_body_size = len(api_app._json_bytes({"value": ""}))
        below_budget = api_app._json_response(
            {"value": "x" * (api_app.MAX_RESPONSE_BODY_BYTES - empty_body_size - 1)}
        )
        exact_budget = api_app._json_response(
            {"value": "x" * (api_app.MAX_RESPONSE_BODY_BYTES - empty_body_size)}
        )
        over_budget = api_app._json_response(
            {"value": "x" * (api_app.MAX_RESPONSE_BODY_BYTES - empty_body_size + 1)}
        )
        self.assertEqual(len(below_budget.body), api_app.MAX_RESPONSE_BODY_BYTES - 1)
        self.assertEqual(len(exact_budget.body), api_app.MAX_RESPONSE_BODY_BYTES)
        self.assertEqual(over_budget.status_code, 422)
        over_budget_payload = json.loads(over_budget.body)
        self.assertEqual(over_budget_payload["error"]["code"], "RESULT_TOO_LARGE")
        self.assertEqual(over_budget.body, api_app._json_bytes(over_budget_payload))
        self._assert_application_headers(over_budget)

        finding = _build_finding()
        oversized_payload = {"opaque": "x" * api_app.MAX_RESPONSE_BODY_BYTES}
        with _synthetic_store((finding,)) as fixture:
            run_id = str(fixture["run_id"])
            with _test_client(create_app(_settings(fixture))) as client:
                with patch.object(
                    api_app,
                    "_complete_finding_payload",
                    return_value=oversized_payload,
                ):
                    oversized_list = client.get(self._list_path(run_id))
                with patch.object(
                    api_app,
                    "_complete_finding_payload",
                    return_value=oversized_payload,
                ):
                    oversized_detail = client.get(
                        self._detail_path(run_id, finding.finding_id)
                    )

        for response in (oversized_list, oversized_detail):
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["error"]["code"], "RESULT_TOO_LARGE")
            self.assertNotIn(b"opaque", response.content)
            self._assert_application_headers(response)

    def test_deterministic_utf8_and_internal_failures_do_not_leak(self) -> None:
        finding = _build_finding(observed_value="หลักฐานสังเคราะห์")
        with _synthetic_store((finding,)) as fixture:
            run_id = str(fixture["run_id"])
            list_path = self._list_path(run_id)
            app = create_app(_settings(fixture))
            with _test_client(app, raise_server_exceptions=False) as client:
                first_success = client.get(list_path)
                second_success = client.get(list_path)
                with patch.object(
                    api_app,
                    "list_findings",
                    side_effect=RuntimeError(
                        "RuntimeError C:\\private\\store.sqlite3 SELECT secret"
                    ),
                ):
                    first_internal = client.get(list_path)
                    second_internal = client.get(list_path)
                with patch.object(
                    api_app,
                    "_complete_finding_payload",
                    return_value={"value": float("nan")},
                ):
                    nonfinite_internal = client.get(list_path)

        self.assertEqual(first_success.status_code, 200)
        self.assertEqual(first_success.content, second_success.content)
        self.assertEqual(first_success.content, api_app._json_bytes(first_success.json()))
        self.assertIn("หลักฐานสังเคราะห์".encode("utf-8"), first_success.content)
        self.assertNotIn(b"\\u0e2b", first_success.content)
        self._assert_application_headers(first_success)

        for response in (first_internal, second_internal, nonfinite_internal):
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.json()["error"]["code"], "INTERNAL_ERROR")
            self._assert_application_headers(response)
        self.assertEqual(first_internal.content, second_internal.content)
        for forbidden_text in ("RuntimeError", "private", "SELECT", "Traceback"):
            self.assertNotIn(forbidden_text, first_internal.text)
        self.assertNotIn("NaN", nonfinite_internal.text)


class ApiLauncherTests(unittest.TestCase):
    """Synthetic Stage 1.6E tests for the fixed-local launcher."""

    @staticmethod
    def _launcher_arguments(
        *,
        database_path: Path = Path("synthetic/store.sqlite3"),
        findings_path: Path = Path("synthetic/findings.jsonl"),
        summary_path: Path = Path("synthetic/summary.json"),
        run_id: str = "a" * 64,
        port: int | None = 8123,
    ) -> list[str]:
        arguments = [
            "--database",
            str(database_path),
            "--findings",
            str(findings_path),
            "--summary",
            str(summary_path),
            "--expected-run-id",
            run_id,
        ]
        if port is not None:
            arguments.extend(("--port", str(port)))
        return arguments

    @staticmethod
    def _loopback_request(
        port: int,
        method: str,
        target: str,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request(method, target, headers={"Host": "127.0.0.1"})
            response = connection.getresponse()
            return (
                response.status,
                {name.lower(): value for name, value in response.getheaders()},
                response.read(),
            )
        finally:
            connection.close()

    def test_launcher_import_is_side_effect_free(self) -> None:
        module_name = "_serve_api_import_safety_probe"
        specification = importlib.util.spec_from_file_location(
            module_name,
            PROJECT_ROOT / "src" / "serve_api.py",
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        assert specification is not None
        assert specification.loader is not None
        module = importlib.util.module_from_spec(specification)
        sys.modules[module_name] = module
        try:
            with (
                patch.object(uvicorn, "run") as server_start,
                patch("api.create_app") as application_factory,
            ):
                specification.loader.exec_module(module)
            server_start.assert_not_called()
            application_factory.assert_not_called()
            self.assertTrue(callable(module.main))
        finally:
            sys.modules.pop(module_name, None)

    def test_launcher_uses_explicit_settings_and_fixed_uvicorn_options(self) -> None:
        application = object()
        arguments = self._launcher_arguments(port=8123)
        with (
            patch.dict(
                os.environ,
                {
                    "WEB_CONCURRENCY": "99",
                    "FORWARDED_ALLOW_IPS": "*",
                    "UVICORN_HOST": "0.0.0.0",
                },
            ),
            patch.object(serve_api, "create_app", return_value=application) as factory,
            patch.object(serve_api.uvicorn, "run") as server_start,
        ):
            result = serve_api.main(arguments)

        self.assertEqual(result, 0)
        factory.assert_called_once()
        settings = factory.call_args.args[0]
        self.assertIsInstance(settings, ApiSettings)
        self.assertEqual(settings.database_path, Path("synthetic/store.sqlite3"))
        self.assertEqual(settings.findings_path, Path("synthetic/findings.jsonl"))
        self.assertEqual(settings.summary_path, Path("synthetic/summary.json"))
        self.assertEqual(settings.expected_run_id, "a" * 64)
        self.assertEqual(settings.port, 8123)
        server_start.assert_called_once_with(
            application,
            host="127.0.0.1",
            port=8123,
            reload=False,
            workers=1,
            proxy_headers=False,
            access_log=False,
            log_level="critical",
        )

        with (
            patch.object(serve_api, "create_app", return_value=application) as factory,
            patch.object(serve_api.uvicorn, "run") as server_start,
        ):
            result = serve_api.main(self._launcher_arguments(port=None))

        self.assertEqual(result, 0)
        self.assertEqual(factory.call_args.args[0].port, 8000)
        self.assertEqual(server_start.call_args.kwargs["port"], 8000)

    def test_launcher_rejects_invalid_or_unapproved_options_before_startup(self) -> None:
        missing_database = self._launcher_arguments()
        del missing_database[:2]
        cases = {
            "missing database": missing_database,
            "invalid run id": self._launcher_arguments(run_id="A" * 64),
            "zero port": self._launcher_arguments(port=0),
            "out of range port": self._launcher_arguments(port=65_536),
            "noninteger port": self._launcher_arguments()[:-1] + ["not-an-integer"],
            "host option": self._launcher_arguments() + ["--host", "0.0.0.0"],
            "reload option": self._launcher_arguments() + ["--reload"],
            "workers option": self._launcher_arguments() + ["--workers", "2"],
            "proxy option": self._launcher_arguments() + ["--proxy-headers"],
            "database create option": self._launcher_arguments() + ["--create-database"],
        }
        for name, arguments in cases.items():
            with self.subTest(option=name):
                with (
                    patch.object(serve_api, "create_app") as factory,
                    patch.object(serve_api.uvicorn, "run") as server_start,
                    redirect_stderr(StringIO()) as standard_error,
                    self.assertRaises(SystemExit) as exited,
                ):
                    serve_api.main(arguments)
                self.assertEqual(exited.exception.code, 2)
                self.assertIn("error:", standard_error.getvalue())
                factory.assert_not_called()
                server_start.assert_not_called()

    def test_launcher_reports_startup_failure_without_retry_or_fallback(self) -> None:
        application = object()
        with (
            patch.object(serve_api, "create_app", return_value=application),
            patch.object(
                serve_api.uvicorn,
                "run",
                side_effect=SystemExit(1),
            ) as server_start,
            redirect_stderr(StringIO()) as standard_error,
        ):
            result = serve_api.main(self._launcher_arguments(port=8123))

        self.assertEqual(result, 1)
        self.assertEqual(standard_error.getvalue(), "API_STARTUP_FAILED\n")
        server_start.assert_called_once_with(
            application,
            host="127.0.0.1",
            port=8123,
            reload=False,
            workers=1,
            proxy_headers=False,
            access_log=False,
            log_level="critical",
        )

    def test_launcher_reports_port_in_use_without_rebinding(self) -> None:
        application = object()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied_socket:
            occupied_socket.bind(("127.0.0.1", 0))
            occupied_socket.listen(1)
            occupied_port = int(occupied_socket.getsockname()[1])

            def port_in_use(_application: object, **configuration: object) -> None:
                self.assertEqual(configuration["host"], "127.0.0.1")
                self.assertEqual(configuration["port"], occupied_port)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as competing_socket:
                    with self.assertRaises(OSError):
                        competing_socket.bind(("127.0.0.1", occupied_port))
                raise SystemExit(1)

            with (
                patch.object(serve_api, "create_app", return_value=application),
                patch.object(
                    serve_api.uvicorn,
                    "run",
                    side_effect=port_in_use,
                ) as server_start,
                redirect_stderr(StringIO()) as standard_error,
            ):
                result = serve_api.main(self._launcher_arguments(port=occupied_port))

        self.assertEqual(result, 1)
        self.assertEqual(standard_error.getvalue(), "API_STARTUP_FAILED\n")
        self.assertEqual(server_start.call_count, 1)

    def test_launcher_configuration_is_offline_before_owned_server_startup(self) -> None:
        application = object()
        with (
            patch.object(serve_api, "create_app", return_value=application),
            patch.object(serve_api.uvicorn, "run") as server_start,
            patch(
                "socket.create_connection",
                side_effect=AssertionError("launcher must not make an outbound connection"),
            ) as create_connection,
        ):
            result = serve_api.main(self._launcher_arguments())

        self.assertEqual(result, 0)
        server_start.assert_called_once()
        create_connection.assert_not_called()

    def test_launcher_has_no_direct_storage_or_data_access(self) -> None:
        source = inspect.getsource(serve_api)
        tree = ast.parse(source)
        imported_modules = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_modules.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertNotIn("sqlite3", imported_modules)
        self.assertNotIn("storage", imported_modules)
        self.assertFalse(
            imported_modules
            & {"http", "httpx", "requests", "socket", "subprocess", "urllib"}
        )

        direct_data_calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr
            in {"connect", "open", "read_bytes", "read_text", "write_bytes", "write_text"}
        }
        direct_data_calls.update(
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        )
        self.assertEqual(direct_data_calls, set())
        source_strings = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertFalse(
            any(
                forbidden in value
                for value in source_strings
                for forbidden in (
                    "data/raw",
                    "network_log_SAFE.csv",
                    "stage_1_3f_normalized_events.jsonl",
                )
            )
        )

    def test_launcher_runs_controlled_synthetic_loopback_smoke_and_cleans_up(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owned_socket:
            owned_socket.bind(("127.0.0.1", 0))
            owned_socket.listen(1)
            owned_socket.setblocking(False)
            port = int(owned_socket.getsockname()[1])
            with _synthetic_store() as fixture:
                arguments = self._launcher_arguments(
                    database_path=Path(fixture["database_path"]),
                    findings_path=Path(fixture["findings_path"]),
                    summary_path=Path(fixture["summary_path"]),
                    run_id=str(fixture["run_id"]),
                    port=port,
                )
                server_thread: threading.Thread | None = None
                server: uvicorn.Server | None = None
                server_failures: list[BaseException] = []

                def run_owned_server(application: object, **configuration: object) -> None:
                    nonlocal server, server_thread
                    self.assertEqual(configuration["host"], "127.0.0.1")
                    self.assertEqual(configuration["port"], port)
                    self.assertEqual(configuration["reload"], False)
                    self.assertEqual(configuration["workers"], 1)
                    self.assertEqual(configuration["proxy_headers"], False)
                    self.assertEqual(configuration["access_log"], False)
                    self.assertEqual(configuration["log_level"], "critical")
                    config = uvicorn.Config(
                        application,
                        host="127.0.0.1",
                        port=port,
                        reload=False,
                        workers=1,
                        proxy_headers=False,
                        access_log=False,
                        log_config=None,
                        log_level="critical",
                    )
                    server = uvicorn.Server(config)

                    def serve() -> None:
                        try:
                            server.run(sockets=[owned_socket])
                        except BaseException as error:
                            server_failures.append(error)

                    server_thread = threading.Thread(target=serve, daemon=True)
                    server_thread.start()
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if server_failures:
                                raise server_failures[0]
                            if server.started:
                                break
                            if not server_thread.is_alive():
                                self.fail("Synthetic loopback server exited before startup.")
                            time.sleep(0.01)
                        else:
                            self.fail("Synthetic loopback server did not start before the deadline.")

                        health_status, health_headers, health_body = self._loopback_request(
                            port,
                            "GET",
                            "/healthz",
                        )
                        method_status, method_headers, method_body = self._loopback_request(
                            port,
                            "POST",
                            "/healthz",
                        )
                        schema_status, _schema_headers, schema_body = self._loopback_request(
                            port,
                            "GET",
                            "/openapi.json",
                        )
                    finally:
                        server.should_exit = True
                        server_thread.join(timeout=5)

                    self.assertFalse(server_thread.is_alive())
                    self.assertFalse(server_failures)
                    self.assertEqual(health_status, 200)
                    self.assertEqual(
                        health_body,
                        b'{"api_version":"1.0","status":"ready","storage_schema_version":"1.0"}',
                    )
                    self.assertEqual(health_headers["cache-control"], "no-store")
                    self.assertEqual(health_headers["x-content-type-options"], "nosniff")
                    self.assertEqual(method_status, 405)
                    self.assertIn("GET", method_headers["allow"])
                    self.assertEqual(json.loads(method_body)["error"]["code"], "METHOD_NOT_ALLOWED")
                    self.assertEqual(schema_status, 200)
                    self.assertEqual(
                        set(json.loads(schema_body)["paths"]),
                        {
                            "/healthz",
                            "/api/v1/runs/{run_id}/findings",
                            "/api/v1/runs/{run_id}/findings/{finding_id}",
                        },
                    )

                with patch.object(serve_api.uvicorn, "run", side_effect=run_owned_server):
                    result = serve_api.main(arguments)

        self.assertEqual(result, 0)
        with self.assertRaises(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                pass


if __name__ == "__main__":
    unittest.main()
