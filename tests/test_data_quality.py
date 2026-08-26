"""Synthetic tests for the Stage 1.2A field-inventory foundation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from data_quality import (  # noqa: E402
    KNOWN_FORTIGATE_COLUMNS,
    SESSION_METRIC_FIELDS,
    analyze_rows,
    build_field_inventory,
    percentage,
    validate_inventory_complete,
)
from analyze_data_quality import DataQualityAnalysisError, validate_output_path  # noqa: E402


class FieldInventoryTests(unittest.TestCase):
    def test_known_header_has_one_entry_per_field(self) -> None:
        inventory = build_field_inventory(KNOWN_FORTIGATE_COLUMNS)

        self.assertEqual(len(inventory), 58)
        self.assertEqual([entry["field"] for entry in inventory], list(KNOWN_FORTIGATE_COLUMNS))
        validate_inventory_complete(KNOWN_FORTIGATE_COLUMNS, inventory)

    def test_known_optional_fields_keep_their_documented_nullable_notes(self) -> None:
        inventory = build_field_inventory(("app_name", "threat_name", "src_natip"))
        by_field = {entry["field"]: entry for entry in inventory}

        self.assertIn("129 non-missing", by_field["app_name"]["nullable_behavior"])
        self.assertIn("25 non-missing", by_field["threat_name"]["nullable_behavior"])
        self.assertIn("98,350 missing", by_field["src_natip"]["nullable_behavior"])

    def test_unknown_column_is_preserved_for_verification(self) -> None:
        inventory = build_field_inventory(("event_type", "future_source_field"))

        unknown = inventory[1]
        self.assertEqual(unknown["field"], "future_source_field")
        self.assertEqual(unknown["group"], "Unknown")
        self.assertEqual(unknown["confidence"], "NEEDS VERIFICATION")
        self.assertIn("do not discard", unknown["nullable_behavior"])

    def test_sanitized_identifier_fields_are_documented_as_opaque(self) -> None:
        inventory = build_field_inventory(("src_ip", "dst_ip", "host_ip", "src_mac"))

        for entry in inventory:
            self.assertIn("Opaque sanitized identifier", entry["observed_representation"])
            self.assertIn("not validated", entry["observed_representation"])

    def test_completeness_validation_rejects_a_missing_entry(self) -> None:
        columns = ("event_type", "event_action")
        inventory = build_field_inventory(columns)

        with self.assertRaisesRegex(ValueError, "do not match"):
            validate_inventory_complete(columns, inventory[:1])

    def test_conditional_missingness_has_explicit_group_denominators(self) -> None:
        result = analyze_rows(
            [
                {"event_type": "traffic", "event_action": "accept", "net_proto": "6", "src_port": "50000", "dst_port": "443"},
                {"event_type": "traffic", "event_action": "deny", "net_proto": "6", "src_port": "", "dst_port": "443"},
                {"event_type": "utm", "event_action": "pass", "net_proto": "17", "src_port": "", "dst_port": ""},
            ]
        )

        by_event_type = result["conditional_missingness"][0]["groups"]
        traffic = next(group for group in by_event_type if group["group"]["event_type"] == "traffic")
        self.assertEqual(traffic["row_count"], 2)
        self.assertEqual(traffic["fields"]["src_port"]["missing_count"], 1)
        self.assertEqual(traffic["fields"]["src_port"]["denominator_row_count"], 2)
        self.assertEqual(traffic["fields"]["src_port"]["missing_percentage_of_group"], 50.0)

    def test_protocol_port_summary_preserves_missing_port_patterns(self) -> None:
        result = analyze_rows(
            [
                {"net_proto": "1", "src_port": "", "dst_port": ""},
                {"net_proto": "6", "src_port": "50000", "dst_port": "443"},
                {"net_proto": "17", "src_port": "", "dst_port": "53"},
            ]
        )

        by_protocol = {
            row["net_proto_raw"]: row for row in result["protocol_port_population"]
        }
        self.assertEqual(by_protocol["1"]["both_missing_count"], 1)
        self.assertEqual(by_protocol["1"]["data_quality_status"], "EXPECTED")
        self.assertEqual(by_protocol["6"]["both_populated_count"], 1)
        self.assertEqual(by_protocol["17"]["source_only_missing_count"], 1)

    def test_session_metric_masks_distinguish_all_partial_and_complete_rows(self) -> None:
        all_missing = {field: "" for field in SESSION_METRIC_FIELDS}
        complete = {field: "1" for field in SESSION_METRIC_FIELDS}
        partial = {field: "1" for field in SESSION_METRIC_FIELDS}
        partial["net_sentpkts"] = ""

        result = analyze_rows([all_missing, complete, partial])
        summary = result["session_metric_missingness"]

        self.assertEqual(summary["all_metrics_missing_count"], 1)
        self.assertEqual(summary["all_metrics_populated_count"], 1)
        self.assertEqual(summary["partial_metric_missing_count"], 1)
        self.assertEqual(summary["denominator_row_count"], 3)

    def test_missing_itime_context_and_optional_fields_remain_descriptive(self) -> None:
        result = analyze_rows(
            [
                {"itime": "", "event_type": "utm", "event_subtype": "anomaly", "event_action": "clear_session", "net_proto": "1", "app_service": "PING", "data_sourcetype": "FortiGate", "threat_action": "blocked", "app_name": "", "src_natip": ""},
                {"itime": "1729294669", "event_type": "traffic", "threat_action": "", "app_name": "AnyDesk", "src_natip": "SRCIP_nat"},
            ]
        )

        missing_itime = result["missing_itime_context"]
        self.assertEqual(missing_itime["missing_count"], 1)
        self.assertEqual(missing_itime["data_quality_status"], "UNKNOWN")
        self.assertEqual(missing_itime["context"]["event_type"][0]["value"], "utm")
        by_threat_presence = next(
            summary
            for summary in result["conditional_missingness"]
            if summary["group_fields"] == ["threat_presence"]
        )
        self.assertEqual(by_threat_presence["groups"][0]["group"]["threat_presence"], "absent")
        self.assertEqual(by_threat_presence["groups"][1]["group"]["threat_presence"], "present")
        optional = result["optional_field_population_by_event_type"]
        utm = next(group for group in optional if group["event_type"] == "utm")
        self.assertEqual(utm["fields"]["threat_action"]["non_missing_count"], 1)

    def test_empty_group_percentage_is_safe_and_raw_output_is_rejected(self) -> None:
        self.assertEqual(percentage(0, 0), 0.0)

        unsafe_path = PROJECT_ROOT / "data" / "raw" / "stage_1_2.json"
        with self.assertRaisesRegex(DataQualityAnalysisError, "never"):
            validate_output_path(unsafe_path)


if __name__ == "__main__":
    unittest.main()
