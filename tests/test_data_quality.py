"""Synthetic tests for the Stage 1.2A field-inventory foundation."""

from __future__ import annotations

import json
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
    derived_protocol_name,
    percentage,
    validate_inventory_complete,
)
from analyze_data_quality import DataQualityAnalysisError, validate_output_path  # noqa: E402
from semantic_analysis import SemanticAnalysisAccumulator  # noqa: E402
from timestamp_analysis import TimestampAnalysisAccumulator  # noqa: E402


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

    def test_protocol_port_edge_cases_preserve_raw_protocols_and_derived_names(self) -> None:
        result = analyze_rows(
            [
                {"net_proto": "1", "src_port": "", "dst_port": ""},
                {"net_proto": "1", "src_port": "123", "dst_port": "456"},
                {"net_proto": "6", "src_port": "", "dst_port": "443"},
                {"net_proto": "17", "src_port": "50000", "dst_port": ""},
                {"net_proto": "99", "src_port": "", "dst_port": ""},
            ]
        )

        by_protocol = {
            row["net_proto_raw"]: row for row in result["protocol_port_population"]
        }
        self.assertEqual(by_protocol["1"]["both_missing_count"], 1)
        self.assertEqual(by_protocol["1"]["both_populated_count"], 1)
        self.assertEqual(by_protocol["1"]["derived_protocol_name"], "ICMP")
        self.assertEqual(by_protocol["6"]["source_only_missing_count"], 1)
        self.assertEqual(by_protocol["17"]["destination_only_missing_count"], 1)
        self.assertIsNone(by_protocol["99"]["derived_protocol_name"])
        self.assertIsNone(derived_protocol_name("99"))

    def test_numeric_service_labels_report_alignment_without_security_labels(self) -> None:
        result = analyze_rows(
            [
                {"net_proto": "6", "dst_port": "8080", "app_service": "tcp/8080", "app_cat": "unscanned", "app_name": "", "app_id": ""},
                {"net_proto": "17", "dst_port": "8080", "app_service": "tcp/8080", "app_cat": "unscanned", "app_name": "", "app_id": ""},
                {"net_proto": "6", "dst_port": "80", "app_service": "tcp/8080", "app_cat": "unscanned", "app_name": "", "app_id": ""},
                {"net_proto": "17", "dst_port": "53", "app_service": "DNS", "app_cat": "Network.Service", "app_name": "", "app_id": ""},
            ]
        )

        summary = result["service_protocol_port_summary"]
        self.assertLessEqual(summary["reported_group_count"], summary["service_group_limit"])
        numeric = result["numeric_service_label_alignment"]["labels"][0]
        self.assertEqual(numeric["app_service"], "tcp/8080")
        self.assertEqual(numeric["derived_protocol_name"], "TCP")
        self.assertEqual(numeric["derived_destination_port"], "8080")
        self.assertEqual(numeric["matches_protocol_and_destination_port_count"], 1)
        self.assertEqual(numeric["protocol_mismatch_count"], 1)
        self.assertEqual(numeric["destination_port_mismatch_count"], 1)
        self.assertEqual(numeric["data_quality_status"], "UNKNOWN")

    def test_application_field_population_is_grouped_by_protocol(self) -> None:
        result = analyze_rows(
            [
                {"net_proto": "6", "app_service": "HTTPS", "app_cat": "unscanned", "app_name": "", "app_id": ""},
                {"net_proto": "6", "app_service": "RDP", "app_cat": "Remote.Access", "app_name": "AnyDesk", "app_id": "39164"},
            ]
        )

        protocol_summary = result["application_field_population_by_protocol"][0]
        self.assertEqual(protocol_summary["net_proto_raw"], "6")
        self.assertEqual(protocol_summary["derived_protocol_name"], "TCP")
        self.assertEqual(protocol_summary["fields"]["app_name"]["non_missing_count"], 1)
        self.assertEqual(protocol_summary["fields"]["app_id"]["missing_count"], 1)

    def test_session_group_statistics_and_lifecycle_keep_all_records(self) -> None:
        def session_row(
            session_id: str, loguid: str, action: str, subtype: str, sent_bytes: str
        ) -> dict[str, str]:
            return {
                "net_sessionid": session_id,
                "loguid": loguid,
                "event_type": "traffic",
                "event_action": action,
                "event_subtype": subtype,
                "net_proto": "6",
                "app_service": "HTTPS",
                "net_rcvdpkts": "1",
                "net_recvbytes": "10",
                "net_sentbytes": sent_bytes,
                "net_sentpkts": "1",
                "net_sessionduration": "2",
            }

        rows = [
            session_row("one", "log-1", "accept", "forward", "10"),
            session_row("two", "log-2", "accept", "forward", "10"),
            session_row("two", "log-3", "close", "local", "20"),
            session_row("three", "log-4", "accept", "forward", "10"),
            session_row("three", "log-5", "accept", "forward", "10"),
            session_row("three", "log-6", "accept", "forward", "10"),
            session_row("four", "log-7", "accept", "forward", "10"),
            session_row("four", "log-8", "accept", "forward", "10"),
            session_row("four", "log-9", "accept", "forward", "10"),
            session_row("four", "log-10", "accept", "forward", "10"),
        ]

        session = analyze_rows(rows)["session_behavior"]
        statistics = session["session_group_size_statistics"]
        distribution = {
            item["records_per_session"]: item["session_count"]
            for item in session["session_group_size_distribution"]
        }

        self.assertEqual(session["record_count"], 10)
        self.assertEqual(session["unique_session_count"], 4)
        self.assertEqual(session["single_record_session_count"], 1)
        self.assertEqual(session["repeated_session_count"], 3)
        self.assertEqual(session["repeated_session_record_count"], 9)
        self.assertEqual(statistics["minimum_records_per_session"], 1)
        self.assertEqual(statistics["maximum_records_per_session"], 4)
        self.assertEqual(statistics["median_records_per_session"], 2.5)
        self.assertEqual(statistics["nearest_rank_percentiles"], {"p50": 2, "p75": 3, "p90": 4, "p95": 4})
        self.assertEqual(distribution, {"1": 1, "2": 1, "3-5": 2})
        lifecycle = session["repeated_session_lifecycle"]
        self.assertEqual(lifecycle["sessions_with_multiple_event_actions_count"], 1)
        self.assertEqual(lifecycle["sessions_with_multiple_event_subtypes_count"], 1)
        metrics = session["repeated_session_metric_comparison"]["fields"]
        self.assertEqual(
            metrics["net_sentbytes"]["sessions_with_varying_non_missing_raw_values_count"],
            1,
        )

    def test_repeated_session_ids_are_not_deduplicated_even_for_equal_rows(self) -> None:
        duplicate_row = {
            "net_sessionid": "same-session",
            "loguid": "same-loguid",
            "event_type": "traffic",
            "event_action": "accept",
            "event_subtype": "forward",
            **{field: "1" for field in SESSION_METRIC_FIELDS},
        }

        session = analyze_rows([duplicate_row, duplicate_row])["session_behavior"]

        self.assertEqual(session["record_count"], 2)
        self.assertEqual(session["unique_session_count"], 1)
        self.assertEqual(session["repeated_session_count"], 1)
        self.assertEqual(session["session_group_size_statistics"]["maximum_records_per_session"], 2)
        self.assertIn("without deduplication", session["interpretation"])

    def test_all_metric_missing_context_is_separate_from_partial_missingness(self) -> None:
        all_missing_metrics = {field: "" for field in SESSION_METRIC_FIELDS}
        populated_metrics = {field: "1" for field in SESSION_METRIC_FIELDS}
        partial_metrics = {field: "1" for field in SESSION_METRIC_FIELDS}
        partial_metrics["net_sentpkts"] = ""
        rows = [
            {
                "net_sessionid": "repeated",
                "loguid": "log-1",
                "event_type": "traffic",
                "event_subtype": "ip-conn",
                "event_action": "accept",
                "net_proto": "6",
                "app_service": "SMB",
                "threat_action": "",
                **all_missing_metrics,
            },
            {
                "net_sessionid": "repeated",
                "loguid": "log-2",
                "event_type": "traffic",
                "event_subtype": "ip-conn",
                "event_action": "accept",
                "net_proto": "6",
                "app_service": "SMB",
                **populated_metrics,
            },
            {
                "net_sessionid": "single",
                "loguid": "log-3",
                "event_type": "utm",
                "event_subtype": "anomaly",
                "event_action": "clear_session",
                "net_proto": "17",
                "app_service": "DNS",
                "threat_action": "blocked",
                **all_missing_metrics,
            },
            {
                "net_sessionid": "partial",
                "loguid": "log-4",
                "event_type": "traffic",
                "event_subtype": "ip-conn",
                "event_action": "accept",
                **partial_metrics,
            },
        ]

        result = analyze_rows(rows)
        missingness = result["session_metric_missingness"]
        context = result["session_behavior"]["all_metrics_missing_context"]
        action_counts = {
            (item["event_type"], item["event_action"]): item["row_count"]
            for item in context["event_type_action"]
        }
        repeated_metrics = result["session_behavior"]["repeated_session_metric_comparison"]

        self.assertEqual(missingness["all_metrics_missing_count"], 2)
        self.assertEqual(missingness["partial_metric_missing_count"], 1)
        self.assertEqual(context["all_metrics_missing_record_count"], 2)
        self.assertEqual(context["data_quality_status"], "UNKNOWN")
        self.assertEqual(
            action_counts,
            {("traffic", "accept"): 1, ("utm", "clear_session"): 1},
        )
        self.assertEqual(
            repeated_metrics["fields"]["net_rcvdpkts"]["mixed_population_session_count"],
            1,
        )

    def test_timestamp_analysis_reports_numeric_order_and_derived_utc_separately(self) -> None:
        rows = [
            {"itime": "10", "data_timestamp": "0"},
            {"itime": "20", "data_timestamp": "1"},
            {"itime": "20", "data_timestamp": "1"},
            {"itime": "5", "data_timestamp": "0"},
            {
                "itime": "",
                "data_timestamp": "not-a-number",
                "event_type": "traffic",
                "event_subtype": "forward",
                "event_action": "accept",
                "net_proto": "6",
                "app_service": "SMB",
                "data_sourcetype": "FortiGate",
            },
            {"itime": "invalid", "data_timestamp": "2"},
        ]
        original_rows = [dict(row) for row in rows]

        timestamp = analyze_rows(rows)["timestamp_analysis"]
        itime = timestamp["itime"]
        data_timestamp = timestamp["data_timestamp"]

        self.assertEqual(rows, original_rows)
        self.assertEqual(itime["missing_count"], 1)
        self.assertEqual(itime["valid_integer_count"], 4)
        self.assertEqual(itime["conversion_failure_count"], 1)
        self.assertEqual(itime["minimum_numeric_value"], 5)
        self.assertEqual(itime["maximum_numeric_value"], 20)
        self.assertEqual(itime["observed_numeric_span"], 15)
        self.assertEqual(itime["repeated_valid_integer_occurrence_count"], 1)
        self.assertEqual(itime["file_order"]["adjacent_increase_count"], 1)
        self.assertEqual(itime["file_order"]["adjacent_equal_count"], 1)
        self.assertEqual(itime["file_order"]["adjacent_decrease_count"], 1)
        self.assertEqual(itime["derived_utc_epoch_seconds"]["label"], "DERIVED")
        self.assertEqual(itime["derived_utc_epoch_seconds"]["timezone"], "UTC")
        self.assertEqual(
            itime["derived_utc_epoch_seconds"]["interpretation_status"],
            "NEEDS VERIFICATION",
        )
        self.assertTrue(
            itime["derived_utc_epoch_seconds"]["derived_minimum_utc"].endswith("+00:00")
        )

        self.assertEqual(data_timestamp["valid_integer_count"], 5)
        self.assertEqual(data_timestamp["conversion_failure_count"], 1)
        self.assertEqual(data_timestamp["unique_valid_integer_count"], 3)
        self.assertEqual(
            data_timestamp["repeated_valid_integer_occurrence_count"], 2
        )
        self.assertEqual(data_timestamp["file_order"]["adjacent_decrease_count"], 1)
        self.assertEqual(data_timestamp["semantic_status"], "UNKNOWN")
        self.assertEqual(
            data_timestamp["value_frequency_summary"]["top_values"][:2],
            [
                {
                    "numeric_value": 0,
                    "row_count": 2,
                    "percentage_of_valid_integer_rows": 40.0,
                },
                {
                    "numeric_value": 1,
                    "row_count": 2,
                    "percentage_of_valid_integer_rows": 40.0,
                },
            ],
        )

        context = {summary["field"]: summary for summary in itime["missing_context"]}
        self.assertEqual(context["event_type"]["values"], [{"value": "traffic", "row_count": 1}])
        relationship = timestamp["itime_data_timestamp_relationship"]
        self.assertEqual(relationship["both_valid_row_count"], 4)
        self.assertEqual(relationship["itime_minus_data_timestamp_minimum"], 5)
        self.assertEqual(relationship["itime_minus_data_timestamp_maximum"], 19)
        self.assertFalse(relationship["constant_difference_observed"])
        self.assertEqual(relationship["semantic_status"], "UNKNOWN")

    def test_timestamp_relationship_can_report_a_constant_numeric_difference(self) -> None:
        accumulator = TimestampAnalysisAccumulator(value_frequency_limit=2)
        accumulator.add_row({"itime": "100", "data_timestamp": "1"})
        accumulator.add_row({"itime": "101", "data_timestamp": "2"})
        accumulator.add_row({"itime": "102", "data_timestamp": "3"})

        relationship = accumulator.as_dict()["itime_data_timestamp_relationship"]

        self.assertEqual(relationship["both_valid_row_count"], 3)
        self.assertEqual(relationship["itime_minus_data_timestamp_minimum"], 99)
        self.assertEqual(relationship["itime_minus_data_timestamp_maximum"], 99)
        self.assertTrue(relationship["constant_difference_observed"])
        self.assertEqual(relationship["semantic_status"], "UNKNOWN")

    def test_timestamp_frequency_summary_is_bounded_and_stably_sorted(self) -> None:
        accumulator = TimestampAnalysisAccumulator(value_frequency_limit=2)
        for data_timestamp in ("2", "1", "3", "4"):
            accumulator.add_row({"itime": "100", "data_timestamp": data_timestamp})

        data_timestamp = accumulator.as_dict()["data_timestamp"]
        frequency = data_timestamp["value_frequency_summary"]

        self.assertEqual(frequency["reported_value_count"], 2)
        self.assertEqual(frequency["omitted_value_count"], 2)
        self.assertEqual(
            [item["numeric_value"] for item in frequency["top_values"]], [1, 2]
        )
        self.assertEqual(data_timestamp["semantic_status"], "UNKNOWN")

    def test_event_semantics_accept_unknown_categories_with_bounded_stable_output(self) -> None:
        accumulator = SemanticAnalysisAccumulator(
            top_value_limit=2, combination_limit=1, rare_combination_limit=1
        )
        accumulator.add_row(
            {
                "event_type": "beta",
                "event_subtype": "custom",
                "event_action": "observe",
                "event_severity": "notice",
            }
        )
        accumulator.add_row(
            {
                "event_type": "alpha",
                "event_subtype": "custom",
                "event_action": "observe",
                "event_severity": "notice",
            }
        )
        accumulator.add_row(
            {
                "event_type": "gamma",
                "event_subtype": "other",
                "event_action": "record",
                "event_severity": "information",
            }
        )

        event = accumulator.as_dict()["event_semantics"]
        application_context = accumulator.as_dict()["application_semantics"][
            "population_by_event_type_action"
        ]
        event_types = event["field_frequencies"]["event_type"]
        type_action = next(
            summary
            for summary in event["combinations"]
            if summary["fields"] == ["event_type", "event_action"]
        )

        self.assertEqual(
            [item["value"] for item in event_types["top_values"]], ["alpha", "beta"]
        )
        self.assertEqual(event_types["omitted_value_count"], 1)
        self.assertEqual(type_action["common_combinations"][0]["row_count"], 1)
        self.assertEqual(type_action["omitted_common_combination_count"], 2)
        self.assertEqual(application_context["reported_context_count"], 1)
        self.assertEqual(application_context["omitted_context_count"], 2)

    def test_application_and_threat_semantics_are_contextual_not_security_labels(self) -> None:
        rows = [
            {
                "event_type": "traffic",
                "event_action": "accept",
                "event_subtype": "forward",
                "event_severity": "information",
                "app_cat": "unscanned",
                "app_service": "HTTPS",
                "app_id": "",
                "app_name": "",
                "net_proto": "6",
            },
            {
                "event_type": "utm",
                "event_action": "blocked",
                "event_subtype": "anomaly",
                "event_severity": "warning",
                "app_cat": "Network.Service",
                "app_service": "PING",
                "app_id": "42",
                "app_name": "ICMP utility",
                "net_proto": "1",
                "threat_action": "blocked",
                "threat_name": "icmp_sweep",
                "threat_severity": "medium",
                "threat_type": "Reconnaissance",
            },
            {
                "event_type": "utm",
                "event_action": "pass",
                "event_subtype": "anomaly",
                "event_severity": "warning",
                "app_cat": "",
                "app_service": "PING",
                "app_id": "",
                "app_name": "",
                "net_proto": "1",
                "threat_name": "Policy Violation",
            },
        ]

        semantic = analyze_rows(rows)["semantic_analysis"]
        application = semantic["application_semantics"]
        threat = semantic["threat_semantics"]
        utm_blocked = next(
            context
            for context in application["population_by_event_type_action"]["contexts"]
            if context["event_type"] == "utm" and context["event_action"] == "blocked"
        )

        self.assertEqual(application["field_population"]["app_name"]["non_missing_count"], 1)
        self.assertEqual(utm_blocked["fields"]["app_id"]["non_missing_count"], 1)
        self.assertEqual(threat["threat_present_record_count"], 2)
        self.assertEqual(
            threat["field_completeness_when_threat_present"]["threat_action"][
                "non_missing_count"
            ],
            1,
        )
        self.assertIn("source-product observations", threat["interpretation"])
        rendered = json.dumps(semantic).lower()
        for prohibited_name in ("is_attack", "is_malicious", "risk_score", "mitre"):
            self.assertNotIn(prohibited_name, rendered)

    def test_identifier_cardinality_hides_opaque_values_and_numeric_stats_are_descriptive(self) -> None:
        rows = [
            {
                "src_ip": "SRCIP_one",
                "dst_ip": "DSTIP_one",
                "host_ip": "HOSTIP_one",
                "loguid": "LOG_one",
                "net_sessionid": "SESSION_one",
                "src_port": "0",
                "dst_port": "443",
                "net_rcvdpkts": "0",
                "net_recvbytes": "1",
                "net_sentbytes": "2",
                "net_sentpkts": "3",
                "net_sessionduration": "4",
            },
            {
                "src_ip": "SRCIP_one",
                "dst_ip": "DSTIP_two",
                "host_ip": "HOSTIP_one",
                "loguid": "LOG_two",
                "net_sessionid": "SESSION_one",
                "src_port": "5",
                "dst_port": "",
                "net_rcvdpkts": "100",
                "net_recvbytes": "0",
                "net_sentbytes": "0",
                "net_sentpkts": "0",
                "net_sessionduration": "0",
            },
        ]

        semantic = analyze_rows(rows)["semantic_analysis"]
        source_identifier = semantic["identifier_cardinality"]["src_ip"]
        received_packets = semantic["selected_numeric_fields"]["net_rcvdpkts"]

        self.assertEqual(source_identifier["unique_value_count"], 1)
        self.assertEqual(source_identifier["repeated_occurrence_count"], 1)
        self.assertFalse(source_identifier["identifier_values_reported"])
        self.assertEqual(
            source_identifier["occurrence_distribution"],
            [
                {
                    "occurrences_per_identifier": "2",
                    "identifier_count": 1,
                    "percentage_of_unique_identifiers": 100.0,
                }
            ],
        )
        self.assertEqual(received_packets["zero_count"], 1)
        self.assertEqual(received_packets["nonzero_count"], 1)
        self.assertEqual(received_packets["median"], 50.0)
        self.assertEqual(received_packets["nearest_rank_percentiles"]["p95"], 100)
        self.assertNotIn("values", received_packets)

    def test_semantic_analysis_handles_empty_optional_groups(self) -> None:
        semantic = SemanticAnalysisAccumulator().as_dict()

        self.assertEqual(semantic["row_count"], 0)
        self.assertEqual(semantic["threat_semantics"]["threat_present_record_count"], 0)
        self.assertEqual(
            semantic["application_semantics"]["field_population"]["app_service"][
                "non_missing_percentage_of_denominator"
            ],
            0.0,
        )
        self.assertEqual(
            semantic["selected_numeric_fields"]["net_sentbytes"]["median"], None
        )


if __name__ == "__main__":
    unittest.main()
