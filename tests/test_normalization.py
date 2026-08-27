"""Synthetic contract tests for the Stage 1.3 normalization foundation."""

from __future__ import annotations

import csv
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from normalization.models import (  # noqa: E402
    REQUIRED_EVENT_SECTIONS,
    FieldProvenance,
    NormalizationContractError,
    NormalizationIssue,
    NormalizationRunSummary,
    NormalizedSecurityEvent,
    SourceRecord,
)
from data_quality import KNOWN_FORTIGATE_COLUMNS  # noqa: E402
from normalization.fortigate_mapping import (  # noqa: E402
    MAPPING_CATEGORIES,
    FORTIGATE_FIELD_MAPPINGS,
    FortiGateFieldMapping,
    FortiGateMappingError,
    validate_fortigate_mapping_specification,
)
from normalization.fortigate import (  # noqa: E402
    normalize_fortigate_record,
)
from parsers.fortigate import (  # noqa: E402
    BASELINE_FORTIGATE_FIELDS,
    FORTIGATE_SOURCE_TYPE,
    FortiGateAdapterError,
    iter_fortigate_records,
)
from normalization.validation import validate_normalized_event  # noqa: E402
from normalize_dataset import (  # noqa: E402
    PROCESSED_DATA_DIRECTORY,
    NormalizationRunError,
    main as normalize_dataset_main,
    normalize_fortigate_csv,
)


def build_event() -> NormalizedSecurityEvent:
    """Build a generic synthetic event with optional canonical null values."""

    source_fields = {
        "example_identifier": "OPAQUE_TOKEN",
        "example_optional_value": "",
        "example_numeric_text": "42",
    }
    return NormalizedSecurityEvent(
        source={"source_type": "example_source", "record_number": 1},
        event={"source_record_id": "example-record"},
        time={"raw_value": None, "derived_value": None},
        network={"source_identifier": "OPAQUE_TOKEN", "source_port": None},
        application={},
        session={},
        host={},
        threat_observations={},
        source_record=SourceRecord(
            source_type="example_source",
            record_number=1,
            fields=source_fields,
        ),
        unmapped_fields={"example_optional_value": ""},
        provenance=(
            FieldProvenance(
                canonical_path="network.source_identifier",
                source_fields=("example_identifier",),
                operation="COPIED",
                interpretation_status="VERIFIED",
                note="Opaque source-defined identifier.",
            ),
        ),
        normalization_issues=(),
    )


def documented_mapping_rows() -> list[tuple[str, ...]]:
    """Read the checked-in Stage 1.3B table without inspecting source data."""

    path = PROJECT_ROOT / "docs" / "fortigate_normalization_mapping.md"
    rows: list[tuple[str, ...]] = []
    in_table = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "## Complete 58-field mapping table":
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("| "):
            continue

        cells = tuple(cell.strip() for cell in line.strip().split("|")[1:-1])
        if cells[0] == "Source field" or set(cells[0]) == {"-"}:
            continue
        rows.append(cells)
    return rows


class NormalizationContractTests(unittest.TestCase):
    def test_event_serialization_is_complete_deterministic_and_json_compatible(self) -> None:
        event = build_event()

        first = event.to_dict()
        second = event.to_dict()
        self.assertEqual(first, second)
        self.assertEqual(tuple(first), REQUIRED_EVENT_SECTIONS)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(first["time"]["raw_value"], None)
        self.assertEqual(first["network"]["source_port"], None)
        self.assertEqual(first["source_record"]["example_optional_value"], "")

    def test_source_record_copies_input_mapping_without_changing_raw_values(self) -> None:
        original_fields = {"z_field": "  value  ", "a_field": ""}
        record = SourceRecord(
            source_type="example_source",
            record_number=3,
            fields=original_fields,
        )
        original_fields["a_field"] = "changed after construction"

        self.assertEqual(record.to_dict(), {"a_field": "", "z_field": "  value  "})

    def test_unmapped_fields_must_match_the_preserved_source_record(self) -> None:
        event = build_event()
        self.assertEqual(event.to_dict()["unmapped_fields"], {"example_optional_value": ""})

        with self.assertRaisesRegex(NormalizationContractError, "must exist"):
            NormalizedSecurityEvent(
                source=event.source,
                event=event.event,
                time=event.time,
                network=event.network,
                application=event.application,
                session=event.session,
                host=event.host,
                threat_observations=event.threat_observations,
                source_record=event.source_record,
                unmapped_fields={"not_in_source_record": ""},
                provenance=event.provenance,
                normalization_issues=event.normalization_issues,
            )

    def test_status_vocabularies_reject_unknown_or_prohibited_names(self) -> None:
        with self.assertRaisesRegex(NormalizationContractError, "operation must be one"):
            FieldProvenance(
                canonical_path="network.example",
                source_fields=("example_field",),
                operation="ATTACK",
                interpretation_status="VERIFIED",
            )
        with self.assertRaisesRegex(NormalizationContractError, "status must be one"):
            NormalizationIssue(
                source_field="example_field",
                issue_code="EXAMPLE",
                status="RISK",
                description="Synthetic unsupported status.",
            )
        with self.assertRaisesRegex(
            NormalizationContractError, "interpretation_status must be one"
        ):
            FieldProvenance(
                canonical_path="network.example",
                source_fields=("example_field",),
                operation="COPIED",
                interpretation_status="UNSUPPORTED",
            )

    def test_run_summary_uses_null_for_optional_output_and_sorted_aggregates(self) -> None:
        summary = NormalizationRunSummary(
            source_type="example_source",
            input_path="input.csv",
            output_path=None,
            input_record_count=2,
            valid_record_count=2,
            malformed_record_count=0,
            output_record_count=2,
            mapping_coverage={"unmapped": 1, "mapped": 2},
            issue_counts={"Z_CODE": 1, "A_CODE": 2},
            unknown_field_names=("z_field", "a_field"),
        )

        result = summary.to_dict()
        self.assertEqual(result["output_path"], None)
        self.assertEqual(result["mapping_coverage"], {"mapped": 2, "unmapped": 1})
        self.assertEqual(result["issue_counts"], {"A_CODE": 2, "Z_CODE": 1})
        self.assertEqual(result["unknown_field_names"], ["z_field", "a_field"])

    def test_generic_contract_has_no_source_mapping_or_security_decision_fields(self) -> None:
        rendered = json.dumps(build_event().to_dict()).lower()
        for prohibited_field in (
            "is_attack",
            "is_malicious",
            "risk_score",
            "detection",
            "mitre",
        ):
            self.assertNotIn(prohibited_field, rendered)

    def test_fortigate_mapping_has_every_verified_field_in_header_order(self) -> None:
        validate_fortigate_mapping_specification()

        fields = tuple(mapping.source_field for mapping in FORTIGATE_FIELD_MAPPINGS)
        self.assertEqual(len(fields), 58)
        self.assertEqual(len(set(fields)), 58)
        self.assertEqual(fields, KNOWN_FORTIGATE_COLUMNS)

    def test_fortigate_mapping_rules_use_supported_categories_and_statuses(self) -> None:
        for mapping in FORTIGATE_FIELD_MAPPINGS:
            self.assertIn(mapping.mapping_category, MAPPING_CATEGORIES)
            self.assertTrue(mapping.operations)
            self.assertTrue(mapping.interpretation_status)
            self.assertTrue(mapping.missingness_status)
            self.assertTrue(mapping.source_representation)
            self.assertTrue(mapping.target_type)
            self.assertTrue(mapping.conversion_failure_behavior)
            self.assertTrue(mapping.rationale)

        with self.assertRaisesRegex(FortiGateMappingError, "not supported"):
            FortiGateFieldMapping(
                source_field="example_field",
                canonical_paths=("event.example",),
                mapping_category="UNSUPPORTED",
                source_representation="string",
                target_type="string_or_null",
                operations=("COPIED",),
                interpretation_status="VERIFIED",
                missingness_status="UNKNOWN",
                conversion_failure_behavior="not_converted_preserve_raw",
                rationale="Synthetic invalid category.",
            )

    def test_mapping_keeps_timestamp_identifier_and_threat_boundaries(self) -> None:
        by_field = {
            mapping.source_field: mapping for mapping in FORTIGATE_FIELD_MAPPINGS
        }

        data_timestamp = by_field["data_timestamp"]
        self.assertEqual(data_timestamp.mapping_category, "PRESERVED_UNMAPPED")
        self.assertEqual(data_timestamp.canonical_paths, ())
        self.assertEqual(data_timestamp.interpretation_status, "UNKNOWN")

        for field in ("src_ip", "dst_ip", "host_ip", "src_mac", "dst_mac", "host_mac"):
            mapping = by_field[field]
            self.assertIn("opaque_identifier", mapping.target_type)
            self.assertNotIn("ip_address", mapping.target_type)
            self.assertNotIn("mac_address", mapping.target_type)

        for field in (
            "threat_action",
            "threat_name",
            "threat_severity",
            "threat_type",
            "threat_pattern",
            "threat_id",
            "threat_ref",
        ):
            mapping = by_field[field]
            self.assertEqual(mapping.mapping_category, "PRESERVED_OBSERVATION")
            self.assertTrue(
                all(path.startswith("threat_observations.") for path in mapping.canonical_paths)
            )
            self.assertNotIn("label", " ".join(mapping.canonical_paths))

    def test_documentation_table_matches_machine_readable_mapping_decisions(self) -> None:
        expected_rows = [
            mapping.documentation_row() for mapping in FORTIGATE_FIELD_MAPPINGS
        ]
        self.assertEqual(documented_mapping_rows(), expected_rows)

        unmapped_fields = [
            mapping.source_field
            for mapping in FORTIGATE_FIELD_MAPPINGS
            if mapping.mapping_category == "PRESERVED_UNMAPPED"
        ]
        self.assertEqual(
            unmapped_fields,
            ["adom_oid", "data_timestamp", "epid", "euid", "event_profile"],
        )


class FortiGateAdapterTests(unittest.TestCase):
    """Synthetic tests for the read-only Stage 1.3C FortiGate adapter."""

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary_directory.name)

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def write_csv(
        self,
        filename: str,
        header: list[str],
        rows: list[list[str]],
        *,
        encoding: str = "utf-8-sig",
    ) -> Path:
        path = self.directory / filename
        with path.open("w", encoding=encoding, newline="") as output_file:
            writer = csv.writer(output_file)
            writer.writerow(header)
            writer.writerows(rows)
        return path

    @staticmethod
    def raw_values(header: list[str], suffix: str) -> list[str]:
        values = [f"raw-{suffix}-{field}" for field in header]
        values[header.index("src_ip")] = f"SRCIP_{suffix}"
        values[header.index("dst_ip")] = f"DSTIP_{suffix}"
        values[header.index("host_mac")] = f"HOSTMAC_{suffix}"
        return values

    def assert_adapter_error(self, code: str, path: Path) -> FortiGateAdapterError:
        with self.assertRaises(FortiGateAdapterError) as caught:
            list(iter_fortigate_records(path))
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_adapter_preserves_bom_raw_values_and_input_order(self) -> None:
        header = list(reversed(BASELINE_FORTIGATE_FIELDS))
        first_row = self.raw_values(header, "ONE")
        second_row = self.raw_values(header, "TWO")
        path = self.write_csv("valid.csv", header, [first_row, second_row])

        records = list(iter_fortigate_records(path))

        self.assertEqual([record.record_number for record in records], [1, 2])
        self.assertTrue(all(record.source_type == FORTIGATE_SOURCE_TYPE for record in records))
        self.assertEqual(tuple(records[0].fields), tuple(header))
        self.assertEqual(records[0].fields, dict(zip(header, first_row)))
        self.assertEqual(records[1].fields, dict(zip(header, second_row)))
        self.assertEqual(records[0].fields["src_ip"], "SRCIP_ONE")
        self.assertEqual(records[0].fields["host_mac"], "HOSTMAC_ONE")

    def test_adapter_rejects_empty_and_header_only_files(self) -> None:
        empty_path = self.directory / "empty.csv"
        empty_path.write_bytes(b"")
        self.assert_adapter_error("EMPTY_CSV", empty_path)

        header_only_path = self.write_csv(
            "header-only.csv", list(BASELINE_FORTIGATE_FIELDS), []
        )
        self.assert_adapter_error("HEADER_ONLY_CSV", header_only_path)

    def test_adapter_rejects_blank_and_duplicate_header_names(self) -> None:
        blank_header = list(BASELINE_FORTIGATE_FIELDS)
        blank_header[0] = " "
        blank_path = self.write_csv("blank-header.csv", blank_header, [])
        self.assert_adapter_error("BLANK_HEADER", blank_path)

        duplicate_header = list(BASELINE_FORTIGATE_FIELDS)
        duplicate_header[1] = duplicate_header[0]
        duplicate_path = self.write_csv("duplicate-header.csv", duplicate_header, [])
        self.assert_adapter_error("DUPLICATE_HEADER", duplicate_path)

    def test_adapter_rejects_missing_baseline_fields(self) -> None:
        header = [field for field in BASELINE_FORTIGATE_FIELDS if field != "loguid"]
        path = self.write_csv("missing-field.csv", header, [])

        error = self.assert_adapter_error("MISSING_BASELINE_FIELDS", path)

        self.assertIn("loguid", str(error))

    def test_adapter_preserves_extra_unique_columns_as_source_evidence(self) -> None:
        header = [*BASELINE_FORTIGATE_FIELDS, "future_vendor_field"]
        row = self.raw_values(header, "EXTRA")
        row[-1] = "future raw value"
        path = self.write_csv("extra-column.csv", header, [row])

        record = next(iter_fortigate_records(path))

        self.assertEqual(record.fields["future_vendor_field"], "future raw value")
        self.assertEqual(tuple(record.fields), tuple(header))

    def test_adapter_rejects_malformed_row_widths(self) -> None:
        header = list(BASELINE_FORTIGATE_FIELDS)
        path = self.write_csv("malformed-width.csv", header, [["too", "short"]])

        error = self.assert_adapter_error("ROW_WIDTH_MISMATCH", path)

        self.assertEqual(error.record_number, 1)

    def test_adapter_rejects_invalid_utf8(self) -> None:
        path = self.directory / "invalid-utf8.csv"
        path.write_bytes(b"\xff\xfe\xff")

        self.assert_adapter_error("INVALID_UTF8", path)

    def test_adapter_detects_a_source_change_during_iteration(self) -> None:
        header = list(BASELINE_FORTIGATE_FIELDS)
        path = self.write_csv(
            "changed-source.csv",
            header,
            [self.raw_values(header, "ONE"), self.raw_values(header, "TWO")],
        )
        records = iter_fortigate_records(path)

        self.assertEqual(next(records).record_number, 1)
        original_status = path.stat()
        os.utime(
            path,
            ns=(original_status.st_atime_ns, original_status.st_mtime_ns + 1_000_000_000),
        )

        with self.assertRaises(FortiGateAdapterError) as caught:
            next(records)
        self.assertEqual(caught.exception.code, "SOURCE_CHANGED")


class FortiGateNormalizerTests(unittest.TestCase):
    """Synthetic tests for the pure Stage 1.3D FortiGate normalizer."""

    @staticmethod
    def build_record(
        *,
        record_number: int = 1,
        overrides: dict[str, str | None] | None = None,
        extra_fields: dict[str, str | None] | None = None,
    ) -> SourceRecord:
        fields = {
            field: f"raw-{field}" for field in BASELINE_FORTIGATE_FIELDS
        }
        fields.update(
            {
                "itime": "1700000000",
                "data_timestamp": "1700000000123",
                "src_ip": "SRCIP_OPAQUE",
                "dst_ip": "DSTIP_OPAQUE",
                "host_ip": "HOSTIP_OPAQUE",
                "src_mac": "SRCMAC_OPAQUE",
                "dst_mac": "DSTMAC_OPAQUE",
                "host_mac": "HOSTMAC_OPAQUE",
                "src_port": "51515",
                "dst_port": "443",
                "net_proto": "6",
                "net_rcvdpkts": "10",
                "net_recvbytes": "1000",
                "net_sentbytes": "2000",
                "net_sentpkts": "20",
                "net_sessionduration": "30",
                "net_sessionid": "SESSION_REPEATED",
                "loguid": f"LOG_{record_number}",
                "app_cat": "network",
                "app_service": "HTTPS",
                "app_id": "APP_001",
                "app_name": "application-source-name",
                "threat_action": "",
                "threat_name": "",
                "threat_severity": "",
                "threat_type": "",
                "threat_pattern": "",
                "threat_id": "",
                "threat_ref": "",
            }
        )
        if overrides:
            fields.update(overrides)
        if extra_fields:
            fields.update(extra_fields)
        return SourceRecord(
            source_type=FORTIGATE_SOURCE_TYPE,
            record_number=record_number,
            fields=fields,
        )

    def issue_codes(self, event: NormalizedSecurityEvent) -> set[str]:
        return {issue.issue_code for issue in event.normalization_issues}

    def test_normalizer_copies_opaque_values_and_records_complete_provenance(self) -> None:
        record = self.build_record()

        event = normalize_fortigate_record(record)

        self.assertEqual(event.source["adapter_type"], "fortigate")
        self.assertEqual(event.source["record_number"], 1)
        self.assertEqual(event.network["source"]["identifier"], "SRCIP_OPAQUE")
        self.assertEqual(event.network["destination"]["identifier"], "DSTIP_OPAQUE")
        self.assertEqual(event.network["source"]["port"], 51515)
        self.assertEqual(event.network["destination"]["port"], 443)
        self.assertEqual(event.network["protocol_raw"], "6")
        self.assertEqual(event.network["protocol_number"], 6)
        self.assertEqual(event.network["protocol_name"], "TCP")
        self.assertEqual(event.session["duration_raw_value"], 30)
        self.assertTrue(event.time["itime_utc_derived"].endswith("Z"))
        self.assertEqual(event.time["itime_utc_interpretation_status"], "NEEDS_VERIFICATION")
        self.assertEqual(event.source_record.fields["src_ip"], "SRCIP_OPAQUE")
        self.assertIn("data_timestamp", event.unmapped_fields)
        provenance_paths = {item.canonical_path for item in event.provenance}
        self.assertIn("network.source.identifier", provenance_paths)
        self.assertIn("network.protocol_name", provenance_paths)
        self.assertIn("time.itime_utc_derived", provenance_paths)
        self.assertEqual(validate_normalized_event(event), [])

    def test_normalizer_marks_both_missing_icmp_ports_as_expected_not_invalid(self) -> None:
        record = self.build_record(
            overrides={"net_proto": "1", "src_port": "", "dst_port": " "}
        )

        event = normalize_fortigate_record(record)

        self.assertEqual(event.network["protocol_name"], "ICMP")
        self.assertIsNone(event.network["source"]["port"])
        self.assertIsNone(event.network["destination"]["port"])
        expected_issues = [
            issue
            for issue in event.normalization_issues
            if issue.issue_code == "MISSING_PORTS_EXPECTED_FOR_ICMP"
        ]
        self.assertEqual(len(expected_issues), 1)
        self.assertEqual(expected_issues[0].status, "EXPECTED")
        self.assertFalse(
            any(
                issue.issue_code == "INVALID_PORT"
                for issue in event.normalization_issues
            )
        )

    def test_normalizer_converts_boundary_ports_and_nonnegative_session_metrics(self) -> None:
        record = self.build_record(
            overrides={
                "src_port": "0",
                "dst_port": "65535",
                "net_rcvdpkts": "0",
                "net_recvbytes": "1",
                "net_sentbytes": "2",
                "net_sentpkts": "3",
                "net_sessionduration": "4",
            }
        )

        event = normalize_fortigate_record(record)

        self.assertEqual(event.network["source"]["port"], 0)
        self.assertEqual(event.network["destination"]["port"], 65535)
        self.assertEqual(event.session["received_packets"], 0)
        self.assertEqual(event.session["received_bytes"], 1)
        self.assertEqual(event.session["sent_bytes"], 2)
        self.assertEqual(event.session["sent_packets"], 3)
        self.assertEqual(event.session["duration_raw_value"], 4)
        self.assertNotIn("INVALID_PORT", self.issue_codes(event))
        self.assertNotIn("INVALID_NONNEGATIVE_INTEGER", self.issue_codes(event))

    def test_normalizer_reports_invalid_numeric_values_without_losing_raw_evidence(self) -> None:
        record = self.build_record(
            overrides={
                "itime": "not-a-number",
                "net_proto": "not-a-protocol",
                "src_port": "-1",
                "dst_port": "65536",
                "net_recvbytes": "-1",
                "net_sessionduration": "bad",
            }
        )

        event = normalize_fortigate_record(record)

        self.assertIsNone(event.time["itime_utc_derived"])
        self.assertIsNone(event.network["protocol_number"])
        self.assertIsNone(event.network["source"]["port"])
        self.assertIsNone(event.network["destination"]["port"])
        self.assertIsNone(event.session["received_bytes"])
        self.assertIsNone(event.session["duration_raw_value"])
        self.assertTrue(
            {
                "INVALID_ITIME_INTEGER",
                "INVALID_PROTOCOL_INTEGER",
                "INVALID_PORT",
                "INVALID_NONNEGATIVE_INTEGER",
            }.issubset(self.issue_codes(event))
        )
        self.assertEqual(event.source_record.fields["itime"], "not-a-number")
        self.assertEqual(event.source_record.fields["src_port"], "-1")
        self.assertEqual(event.source_record.fields["net_recvbytes"], "-1")

    def test_normalizer_keeps_missing_session_metrics_contextual(self) -> None:
        record = self.build_record(
            overrides={field: "" for field in (
                "net_rcvdpkts",
                "net_recvbytes",
                "net_sentbytes",
                "net_sentpkts",
                "net_sessionduration",
            )}
        )

        event = normalize_fortigate_record(record)

        self.assertTrue(all(value is None for value in event.session.values() if value != "SESSION_REPEATED"))
        contextual = [
            issue
            for issue in event.normalization_issues
            if issue.issue_code == "ALL_SESSION_METRICS_MISSING"
        ]
        self.assertEqual(len(contextual), 1)
        self.assertEqual(contextual[0].status, "CONTEXT_DEPENDENT")

    def test_normalizer_preserves_unknown_timestamp_and_extra_source_fields_as_unmapped(self) -> None:
        record = self.build_record(
            extra_fields={"future_vendor_field": "future raw evidence"}
        )

        event = normalize_fortigate_record(record)

        self.assertEqual(event.unmapped_fields["data_timestamp"], "1700000000123")
        self.assertEqual(event.unmapped_fields["future_vendor_field"], "future raw evidence")
        self.assertNotIn("data_timestamp", event.time)
        self.assertEqual(event.source_record.fields["future_vendor_field"], "future raw evidence")

    def test_normalizer_preserves_source_observations_and_repeated_sessions_separately(self) -> None:
        first = normalize_fortigate_record(
            self.build_record(
                record_number=1,
                overrides={
                    "threat_name": "source-threat-observation",
                    "threat_severity": "source-severity",
                    "app_name": "unknown-source-application",
                },
            )
        )
        second = normalize_fortigate_record(self.build_record(record_number=2))

        self.assertEqual(first.session["identifier"], "SESSION_REPEATED")
        self.assertEqual(second.session["identifier"], "SESSION_REPEATED")
        self.assertNotEqual(first.source["record_number"], second.source["record_number"])
        self.assertEqual(first.threat_observations["name_source"], "source-threat-observation")
        self.assertEqual(first.threat_observations["severity_source"], "source-severity")
        self.assertEqual(first.application["name_source"], "unknown-source-application")
        rendered = json.dumps(first.to_dict()).lower()
        self.assertNotIn("is_attack", rendered)
        self.assertNotIn("risk_score", rendered)

    def test_normalizer_is_deterministic_and_does_not_mutate_input(self) -> None:
        record = self.build_record()
        original_fields = dict(record.fields)

        first = normalize_fortigate_record(record)
        second = normalize_fortigate_record(record)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(record.fields, original_fields)

    def test_contract_validator_accepts_normalized_output_and_flags_missing_provenance(self) -> None:
        event = normalize_fortigate_record(self.build_record())

        self.assertEqual(validate_normalized_event(event), [])

        invalid_event = replace(event, provenance=())
        validation_codes = {
            issue.issue_code for issue in validate_normalized_event(invalid_event)
        }
        self.assertIn("PROVENANCE_MISSING", validation_codes)


class StreamingNormalizationTests(unittest.TestCase):
    """Synthetic end-to-end tests for the Stage 1.3E streaming output path."""

    def setUp(self) -> None:
        self._input_directory = tempfile.TemporaryDirectory()
        self._output_directory = tempfile.TemporaryDirectory(
            dir=PROCESSED_DATA_DIRECTORY
        )
        self.input_directory = Path(self._input_directory.name)
        self.output_directory = Path(self._output_directory.name)

    def tearDown(self) -> None:
        self._input_directory.cleanup()
        self._output_directory.cleanup()

    def write_input(self, filename: str, records: list[SourceRecord]) -> Path:
        path = self.input_directory / filename
        header = list(BASELINE_FORTIGATE_FIELDS)
        with path.open("w", encoding="utf-8-sig", newline="") as output_file:
            writer = csv.writer(output_file)
            writer.writerow(header)
            writer.writerows(
                [[record.fields[field] for field in header] for record in records]
            )
        return path

    @staticmethod
    def json_lines(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def test_streaming_normalization_preserves_record_count_and_order(self) -> None:
        input_path = self.write_input(
            "two-records.csv",
            [
                FortiGateNormalizerTests.build_record(record_number=1),
                FortiGateNormalizerTests.build_record(record_number=2),
            ],
        )
        output_path = self.output_directory / "normalized.jsonl"

        summary = normalize_fortigate_csv(input_path, output_path)
        output_records = self.json_lines(output_path)

        self.assertEqual(summary.input_record_count, 2)
        self.assertEqual(summary.valid_record_count, 2)
        self.assertEqual(summary.malformed_record_count, 0)
        self.assertEqual(summary.output_record_count, 2)
        self.assertEqual(len(output_records), 2)
        self.assertEqual(
            [record["source"]["record_number"] for record in output_records], [1, 2]
        )
        self.assertEqual(
            [record["session"]["identifier"] for record in output_records],
            ["SESSION_REPEATED", "SESSION_REPEATED"],
        )
        self.assertEqual(summary.mapping_coverage["unexpected_source_field_values"], 0)

    def test_streaming_output_is_byte_for_byte_deterministic(self) -> None:
        input_path = self.write_input(
            "deterministic.csv", [FortiGateNormalizerTests.build_record()]
        )
        first_output = self.output_directory / "first.jsonl"
        second_output = self.output_directory / "second.jsonl"

        normalize_fortigate_csv(input_path, first_output)
        normalize_fortigate_csv(input_path, second_output)

        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())

    def test_streaming_summary_reconciles_conversion_issues(self) -> None:
        input_path = self.write_input(
            "invalid-port.csv",
            [FortiGateNormalizerTests.build_record(overrides={"src_port": "invalid"})],
        )
        output_path = self.output_directory / "invalid-port.jsonl"

        summary = normalize_fortigate_csv(input_path, output_path)
        output_record = self.json_lines(output_path)[0]

        self.assertEqual(summary.issue_counts["INVALID_PORT"], 1)
        self.assertIn(
            "INVALID_PORT",
            {issue["issue_code"] for issue in output_record["normalization_issues"]},
        )

    def test_structural_failure_removes_temporary_output_without_publishing_final(self) -> None:
        input_path = self.input_directory / "malformed.csv"
        header = list(BASELINE_FORTIGATE_FIELDS)
        with input_path.open("w", encoding="utf-8-sig", newline="") as output_file:
            writer = csv.writer(output_file)
            writer.writerow(header)
            valid_record = FortiGateNormalizerTests.build_record()
            writer.writerow([valid_record.fields[field] for field in header])
            writer.writerow(["too", "short"])
        output_path = self.output_directory / "malformed.jsonl"

        with self.assertRaises(FortiGateAdapterError):
            normalize_fortigate_csv(input_path, output_path)

        self.assertFalse(output_path.exists())
        self.assertEqual(
            list(PROCESSED_DATA_DIRECTORY.glob(f".{output_path.stem}.*.tmp")), []
        )

    def test_output_path_checks_reject_unsafe_or_existing_files(self) -> None:
        input_path = self.write_input(
            "source.csv", [FortiGateNormalizerTests.build_record()]
        )

        with self.assertRaises(NormalizationRunError) as outside_error:
            normalize_fortigate_csv(input_path, self.input_directory / "outside.jsonl")
        self.assertEqual(outside_error.exception.code, "OUTPUT_OUTSIDE_PROCESSED")

        processed_input = self.output_directory / "processed-input.csv"
        processed_input.write_bytes(input_path.read_bytes())
        with self.assertRaises(NormalizationRunError) as same_path_error:
            normalize_fortigate_csv(processed_input, processed_input)
        self.assertEqual(same_path_error.exception.code, "INPUT_OUTPUT_SAME")

        existing_output = self.output_directory / "existing.jsonl"
        existing_output.write_text("existing content", encoding="utf-8")
        with self.assertRaises(NormalizationRunError) as existing_error:
            normalize_fortigate_csv(input_path, existing_output)
        self.assertEqual(existing_error.exception.code, "OUTPUT_EXISTS")
        self.assertEqual(existing_output.read_text(encoding="utf-8"), "existing content")

    def test_cli_requires_fortigate_and_prints_only_a_bounded_summary(self) -> None:
        input_path = self.write_input(
            "cli.csv", [FortiGateNormalizerTests.build_record()]
        )
        output_path = self.output_directory / "cli.jsonl"

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = normalize_dataset_main(
                [
                    "--source",
                    "unsupported",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(exit_code, 2)
        self.assertFalse(output_path.exists())
        self.assertIn("--source must be 'fortigate'", stderr.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = normalize_dataset_main(
                [
                    "--source",
                    "fortigate",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        rendered_summary = json.loads(stdout.getvalue())
        self.assertEqual(rendered_summary["output_record_count"], 1)
        self.assertTrue(output_path.exists())


if __name__ == "__main__":
    unittest.main()
