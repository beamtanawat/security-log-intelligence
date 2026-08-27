"""Synthetic contract tests for the Stage 1.3 normalization foundation."""

from __future__ import annotations

import csv
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
from parsers.fortigate import (  # noqa: E402
    BASELINE_FORTIGATE_FIELDS,
    FORTIGATE_SOURCE_TYPE,
    FortiGateAdapterError,
    iter_fortigate_records,
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


if __name__ == "__main__":
    unittest.main()
