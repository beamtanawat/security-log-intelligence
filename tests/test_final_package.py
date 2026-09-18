from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from reporting.audit import (  # noqa: E402
    EXPECTED_UPSTREAM_IDENTITIES,
    PackageAuditError,
    _matches_final_jsonl_contract,
    audit_package,
    rank_validation,
)
from reporting.cases import select_case_studies  # noqa: E402
from reporting.graphs import (  # noqa: E402
    _suspected_attack_interpretation_counts,
    build_graph_data,
    graph_manifest_counts,
)
from reporting.export import (  # noqa: E402
    FINAL_CSV_FIELDS,
    FINAL_JSON_FIELDS,
    aggregate_rows,
    build_final_row,
    canonical_json,
    percent,
    file_sha256,
    write_csv,
    write_csv_row,
    write_jsonl,
)


def explanation_row(
    number: int,
    *,
    rank: int,
    triage: str,
    band: str = "BASELINE",
    behaviors: list[str] | None = None,
    rule_present: bool = False,
    review_status: str | None = None,
    anomaly_score: float = 99.0,
    investigation_priority_score: float = 89.0,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "anomaly_rank": rank,
        "investigation_rank": rank,
        "source_record_number": number,
        "source_record_id": f"LOG_{number}",
        "partition": "REFERENCE" if number % 2 else "HOLDOUT",
        "anomaly_score": anomaly_score,
        "investigation_priority_score": investigation_priority_score,
        "anomaly_band": band,
        "auto_triage": triage,
        "analyst_review_selected": rank <= 50,
        "suspected_behaviors": behaviors or [],
        "suspected_attack_type": None,
        "evidence_strength": "LOW" if rule_present else None,
        "explanation_status": "COMPLETE",
        "top_reasons": [],
        "rule_observation_present": rule_present,
        "rule_ids": ["fortigate.source_threat_observation"] if rule_present else [],
        "source_threat_observation_present": rule_present,
        "anomaly_subtype_observation_present": False,
        "source_threat_type": "test" if rule_present else None,
        "display_context": {"protocol_name": "TCP", "service_source": "HTTPS"},
        "review_id": None,
        "analyst_label": None,
        "contextual_label": None,
        "review_status": review_status if review_status is not None else ("PENDING" if rank <= 50 else "NOT_SELECTED"),
        "model_score": -0.5,
        "raw_abnormality": 0.5,
    }


class FinalExportTests(unittest.TestCase):
    def test_final_row_copies_auto_triage_and_preserves_nullable_review_fields(self) -> None:
        explanation = explanation_row(1, rank=1, triage="HIGH_INTEREST", rule_present=True)
        auto = {
            "source_record_number": "1",
            "source_record_id": "LOG_1",
            "auto_triage": "HIGH_INTEREST",
            "review_status": "PENDING",
        }
        row = build_final_row(explanation, auto)
        self.assertEqual(tuple(row), FINAL_JSON_FIELDS)
        self.assertEqual(row["auto_triage"], "HIGH_INTEREST")
        self.assertIsNone(row["analyst_label"])
        self.assertEqual(row["review_status"], "PENDING")

    def test_canonical_final_jsonl_row_matches_the_exact_field_set_contract(self) -> None:
        row = build_final_row(
            explanation_row(1, rank=1, triage="HIGH_INTEREST"),
            {
                "source_record_number": "1",
                "source_record_id": "LOG_1",
                "auto_triage": "HIGH_INTEREST",
                "review_status": "PENDING",
            },
        )
        decoded = json.loads(canonical_json(row))
        self.assertEqual(set(decoded), set(FINAL_JSON_FIELDS))
        self.assertTrue(_matches_final_jsonl_contract(decoded))

    def test_final_row_flattens_actual_v3_reference_context_rule_id_forms(self) -> None:
        actual_forms = (
            ([], False, False),
            (["fortigate.source_threat_observation"], True, False),
            (
                [
                    "fortigate.anomaly_subtype_observation",
                    "fortigate.source_threat_observation",
                ],
                True,
                True,
            ),
        )
        for rule_ids, source_threat_present, anomaly_subtype_present in actual_forms:
            with self.subTest(rule_ids=rule_ids):
                explanation = explanation_row(1, rank=1, triage="HIGH_INTEREST")
                for name in (
                    "rule_observation_present",
                    "rule_ids",
                    "source_threat_observation_present",
                    "anomaly_subtype_observation_present",
                    "source_threat_type",
                ):
                    explanation.pop(name)
                explanation["reference_context"] = {
                    "rule_ids": rule_ids,
                    "rule_observation_present": bool(rule_ids),
                    "source_threat_observation_present": source_threat_present,
                    "anomaly_subtype_observation_present": anomaly_subtype_present,
                    "source_threat_type": None,
                }
                row = build_final_row(
                    explanation,
                    {
                        "source_record_number": "1",
                        "source_record_id": "LOG_1",
                        "auto_triage": "HIGH_INTEREST",
                        "review_status": "PENDING",
                    },
                )
                self.assertEqual(row["rule_ids"], rule_ids)
                self.assertEqual(row["rule_observation_present"], bool(rule_ids))
                self.assertEqual(row["source_threat_observation_present"], source_threat_present)
                self.assertEqual(row["anomaly_subtype_observation_present"], anomaly_subtype_present)

    def test_aggregate_rows_reconciles_counts_and_percentages(self) -> None:
        rows = [
            explanation_row(1, rank=1, triage="HIGH_INTEREST", band="TOP_0_1_PERCENT", review_status="PENDING"),
            explanation_row(2, rank=2, triage="MEDIUM_INTEREST", band="TOP_1_PERCENT", review_status="NOT_SELECTED"),
            explanation_row(3, rank=3, triage="LOW_INTEREST", review_status="NOT_SELECTED"),
        ]
        summary = aggregate_rows(rows, feature_count=36)
        self.assertEqual(summary["record_count"], 3)
        self.assertEqual(summary["auto_triage_counts"], {"HIGH_INTEREST": 1, "MEDIUM_INTEREST": 1, "LOW_INTEREST": 1})
        self.assertEqual(sum(summary["auto_triage_counts"].values()), 3)
        self.assertEqual(summary["auto_triage_distribution"][0]["percentage"], percent(1, 3))
        self.assertEqual(summary["review_counts"]["PENDING"], 1)

    def test_csv_round_trip_quotes_unicode_and_formula_like_text(self) -> None:
        row = explanation_row(1, rank=1, triage="HIGH_INTEREST")
        row["display_context"] = {"service_source": "+安全\nnext"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.csv"
            with path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(FINAL_CSV_FIELDS)
                write_csv_row(writer, build_final_row(row, {"auto_triage": "HIGH_INTEREST", "review_status": "PENDING", "source_record_number": "1", "source_record_id": "LOG_1"}))
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                values = list(csv.reader(handle))
        self.assertEqual(len(values), 2)
        source_id_index = values[0].index("source_record_id")
        service_index = values[0].index("service_source")
        self.assertEqual(values[1][source_id_index], "LOG_1")
        self.assertEqual(values[1][service_index], "'+安全\nnext")


class CaseSelectionTests(unittest.TestCase):
    def test_case_selection_returns_unique_records_and_fallbacks_explicitly(self) -> None:
        rows = [
            explanation_row(1, rank=1, triage="HIGH_INTEREST", rule_present=True),
            explanation_row(2, rank=2, triage="HIGH_INTEREST", rule_present=False),
            explanation_row(3, rank=60, triage="LOW_INTEREST", rule_present=True, behaviors=["UNUSUAL_TRAFFIC_VOLUME"]),
            explanation_row(4, rank=70, triage="MEDIUM_INTEREST", band="TOP_1_PERCENT", behaviors=["RARE_PORT_OR_SERVICE_CONTEXT"]),
        ]
        cases = select_case_studies(rows)
        self.assertEqual(len(cases), 4)
        self.assertEqual(len({case["source_record_number"] for case in cases}), 4)
        self.assertTrue(all("requested_category" in case and "actual_category" in case for case in cases))
        self.assertEqual(cases[2]["requested_category"], "REFERENCE_OBSERVATION_OUTSIDE_TOP50")
        self.assertEqual(cases[2]["actual_category"], "REFERENCE_OBSERVATION_OUTSIDE_TOP50")
        self.assertEqual(cases[2]["source_record_number"], 3)


class FinalGraphTests(unittest.TestCase):
    def test_suspected_attack_interpretation_counts_keep_zero_reconnaissance_visible(self) -> None:
        rows = [
            explanation_row(1, rank=1, triage="HIGH_INTEREST"),
            explanation_row(2, rank=2, triage="HIGH_INTEREST"),
            explanation_row(3, rank=3, triage="LOW_INTEREST"),
        ]
        rows[0]["suspected_attack_type"] = "Unclassified suspicious behavior"
        self.assertEqual(_suspected_attack_interpretation_counts(rows), [0, 1, 2])

    def test_graph_data_uses_rank_group_record_shares_and_stage_1_7_features(self) -> None:
        rows = [
            explanation_row(1, rank=1, triage="HIGH_INTEREST", behaviors=["UNUSUAL_TRAFFIC_VOLUME"]),
            explanation_row(2, rank=2, triage="HIGH_INTEREST", behaviors=["UNCLASSIFIED_ANOMALOUS_PATTERN"]),
            explanation_row(3, rank=1001, triage="LOW_INTEREST", behaviors=["UNUSUAL_TRAFFIC_VOLUME", "RARE_PORT_OR_SERVICE_CONTEXT"]),
        ]
        rows[0]["display_context"] = {"protocol_name": "TCP", "service_source": "HTTPS"}
        rows[1]["display_context"] = {"protocol_name": "UDP", "service_source": "DNS"}
        rows[2]["display_context"] = {"protocol_name": "TCP", "service_source": "HTTPS"}
        feature_names = (
            "log_duration", "log_total_bytes", "duration_missing",
            "sent_bytes_missing", "received_bytes_missing", "zero_total_bytes",
        )
        features = [
            {"source_record_number": 1, "source_record_id": "LOG_1", "values": [2.0, 3.0, 0.0, 0.0, 0.0, 0.0]},
            {"source_record_number": 2, "source_record_id": "LOG_2", "values": [0.0, 0.0, 1.0, 1.0, 1.0, 0.0]},
            {"source_record_number": 3, "source_record_id": "LOG_3", "values": [4.0, 5.0, 0.0, 0.0, 0.0, 0.0]},
        ]

        scores = [
            {"source_record_number": 1, "source_record_id": "LOG_1", "raw_abnormality": 0.9},
            {"source_record_number": 2, "source_record_id": "LOG_2", "raw_abnormality": 0.8},
            {"source_record_number": 3, "source_record_id": "LOG_3", "raw_abnormality": 0.1},
        ]
        data = build_graph_data(rows, features, feature_names, scores)

        histogram = data["01_score_distribution.png"]["histogram_bins"]
        self.assertEqual(sum(histogram["REFERENCE"].values()), 2)
        self.assertEqual(sum(histogram["HOLDOUT"].values()), 1)
        top20 = graph_manifest_counts("02_top20_scores.png", data["02_top20_scores.png"])
        self.assertEqual(top20["ranked_values"][0]["raw_abnormality"], 0.9)

        protocol = data["04_protocol_representation.png"]
        self.assertEqual(protocol["selected_denominator"], 2)
        self.assertEqual(protocol["remaining_denominator"], 1)
        self.assertEqual(protocol["selected_counts"]["TCP"], 1)
        self.assertEqual(protocol["selected_shares"]["TCP"], 50.0)
        self.assertEqual(protocol["remaining_shares"]["TCP"], 100.0)

        services = data["05_service_representation.png"]
        self.assertEqual(services["selected_denominator"], 2)
        self.assertEqual(services["remaining_denominator"], 1)
        self.assertEqual(services["selected_shares"]["HTTPS"], 50.0)
        self.assertEqual(services["remaining_shares"]["HTTPS"], 100.0)

        drivers = data["06_observed_anomaly_driver_frequency.png"]
        self.assertEqual(drivers["top_50_denominator"], 2)
        self.assertEqual(drivers["top_1000_denominator"], 2)
        self.assertEqual(drivers["top_50_counts"]["UNUSUAL_TRAFFIC_VOLUME"], 1)
        self.assertEqual(drivers["top_50_counts"]["UNCLASSIFIED_ANOMALOUS_PATTERN"], 1)
        self.assertEqual(drivers["top_1000_counts"]["UNCLASSIFIED_ANOMALOUS_PATTERN"], 0)

        features_data = data["10_feature_comparison.png"]["features"]
        self.assertEqual(features_data["log_total_bytes"]["top_100"]["values"], [3.0])
        self.assertEqual(features_data["log_total_bytes"]["remainder"]["values"], [5.0])
        self.assertEqual(features_data["log_duration"]["top_100"]["missing_count"], 1)
        feature_manifest = graph_manifest_counts("10_feature_comparison.png", data["10_feature_comparison.png"])
        self.assertEqual(len(feature_manifest["features"]["log_total_bytes"]["top_100"]["values_sha256"]), 64)


class FinalAuditTests(unittest.TestCase):
    def test_audit_reconciles_csv_case_selection_and_required_report_references(self) -> None:
        rows = [
            build_final_row(
                explanation_row(number, rank=number, triage="HIGH_INTEREST" if number <= 2 else "LOW_INTEREST", rule_present=number in (1, 3), behaviors=["UNUSUAL_TRAFFIC_VOLUME"] if number >= 3 else []),
                {"source_record_number": str(number), "source_record_id": f"LOG_{number}", "auto_triage": "HIGH_INTEREST" if number <= 2 else "LOW_INTEREST", "review_status": "PENDING" if number <= 2 else "NOT_SELECTED"},
            )
            for number in range(1, 5)
        ]
        graph_names = (
            "01_score_distribution.png", "02_top20_scores.png", "03_anomaly_bands.png", "04_protocol_representation.png", "05_service_representation.png",
            "06_observed_anomaly_driver_frequency.png", "07_auto_triage_distribution.png", "08_evidence_strength.png", "09_suspected_attack_interpretation.png", "10_feature_comparison.png",
        )
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            graphs = package / "graphs"
            tables = package / "tables"
            graphs.mkdir(parents=True)
            tables.mkdir()
            write_jsonl(package / "final_anomaly_findings.jsonl", rows)
            write_csv(package / "final_anomaly_findings.csv", rows)
            for name in graph_names:
                (graphs / name).write_bytes(b"png")
            summary = aggregate_rows(rows, feature_count=36)
            summary.update({
                "upstream_identities": EXPECTED_UPSTREAM_IDENTITIES,
                "final_jsonl_identity": {"path": "final_anomaly_findings.jsonl", "sha256": file_sha256(package / "final_anomaly_findings.jsonl"), "row_count": 4},
                "final_csv_identity": {"path": "final_anomaly_findings.csv", "sha256": file_sha256(package / "final_anomaly_findings.csv"), "row_count": 4},
                "rank_validation": rank_validation(rows),
                "model_diagnostics": {},
                "reference_agreement": None,
                "graph_manifest": [
                    {
                        "name": name,
                        "status": "PASS",
                        "reason": "synthetic",
                        "source_identities": {
                            "final_jsonl_sha256": file_sha256(package / "final_anomaly_findings.jsonl"),
                            "stage_1_8_score_sha256": EXPECTED_UPSTREAM_IDENTITIES["stage_1_8_score_sha256"],
                            **(
                                {"stage_1_7_feature_sha256": EXPECTED_UPSTREAM_IDENTITIES["stage_1_7_feature_sha256"]}
                                if name == "10_feature_comparison.png"
                                else {}
                            ),
                        },
                        "counts": {},
                        "relative_path": f"graphs/{name}",
                    }
                    for name in graph_names
                ],
                "case_selection": select_case_studies(rows),
                "report_contract_version": "1.0",
                "package_validation": {"status": "PASS", "scope": "final rows, full CSV/JSONL reconciliation, rank permutations, summary, chart aggregates, cases, and required report references"},
            })
            for name, values in (
                ("auto_triage_distribution", summary["auto_triage_distribution"]),
                ("anomaly_band_distribution", summary["anomaly_band_distribution"]),
                ("suspected_behavior_distribution", summary["suspected_behavior_distribution"]),
                ("evidence_strength_distribution", summary["evidence_strength_distribution"]),
                ("suspected_attack_interpretation_distribution", summary["suspected_attack_interpretation_distribution"]),
                ("review_status_distribution", summary["review_status_distribution"]),
            ):
                with (tables / f"{name}.csv").open("w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(("value", "count", "percentage"))
                    writer.writerows((value["value"] if value["value"] is not None else "NULL", value["count"], value["percentage"]) for value in values)
            with (tables / "top_50_anomalies.csv").open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=("anomaly_rank", "source_record_number", "source_record_id", "partition", "anomaly_score", "auto_triage", "investigation_priority_score", "suspected_behaviors", "suspected_attack_type", "evidence_strength", "top_reasons"))
                writer.writeheader()
                for row in rows:
                    writer.writerow({"anomaly_rank": row["anomaly_rank"], "source_record_number": row["source_record_number"], "source_record_id": row["source_record_id"], "partition": row["partition"], "anomaly_score": row["anomaly_score"], "auto_triage": row["auto_triage"], "investigation_priority_score": row["investigation_priority_score"], "suspected_behaviors": "[]", "suspected_attack_type": "", "evidence_strength": "", "top_reasons": "[]"})
            (tables / "case_studies.json").write_text(canonical_json(summary["case_selection"]), encoding="utf-8")
            with (tables / "overall_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(("metric", "value"))
                for name, value in summary.items():
                    writer.writerow((name, canonical_json(value) if isinstance(value, (dict, list)) else value))
            (package / "analysis_summary.json").write_text(canonical_json(summary), encoding="utf-8")
            report = Path(directory) / "report.md"
            report_sections = (
                "Problem and Dataset", "Data Limitations and Interpretation Boundaries",
                "Architecture", "Workflow", "Rule Baseline", "Feature Engineering",
                "Leakage Controls", "Model", "Anomaly Scoring", "Explanation Method",
                "Suspected Behavior and Attack Boundaries",
                "Automated Triage and Optional Human Evaluation Methodology",
                "Results/Metrics/Graphs", "Results Tables", "Visualizations",
                "Top-50 Investigation Results", "Four Case Studies", "Limitations",
                "Reproducibility", "Local Demo", "Future Work",
            )
            report_links = (
                *(f"![{name}](package/graphs/{name})" for name in graph_names),
                "[final JSONL](package/final_anomaly_findings.jsonl)",
                "[final CSV](package/final_anomaly_findings.csv)",
                "[summary](package/analysis_summary.json)",
                "[Top-50](package/tables/top_50_anomalies.csv)",
            )
            report.write_text("\n".join((*report_sections, *report_links)), encoding="utf-8")

            result = audit_package(package, expected_rows=4, report_path=report)

            with (package / "final_anomaly_findings.csv").open("r", encoding="utf-8-sig", newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
            csv_rows[0]["review_status"] = "NOT_SELECTED"
            with (package / "final_anomaly_findings.csv").open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FINAL_CSV_FIELDS, quoting=csv.QUOTE_ALL, lineterminator="\n")
                writer.writeheader()
                writer.writerows(csv_rows)
            summary["final_csv_identity"] = {"path": "final_anomaly_findings.csv", "sha256": file_sha256(package / "final_anomaly_findings.csv"), "row_count": 4}
            (package / "analysis_summary.json").write_text(canonical_json(summary), encoding="utf-8")
            with self.assertRaisesRegex(PackageAuditError, "review_status"):
                audit_package(package, expected_rows=4, report_path=report)

            write_csv(package / "final_anomaly_findings.csv", rows)
            summary["final_csv_identity"] = {"path": "final_anomaly_findings.csv", "sha256": file_sha256(package / "final_anomaly_findings.csv"), "row_count": 4}
            altered_rows = [dict(row) for row in rows]
            altered_rows[0]["investigation_rank"] = 2
            write_jsonl(package / "final_anomaly_findings.jsonl", altered_rows)
            summary["final_jsonl_identity"] = {"path": "final_anomaly_findings.jsonl", "sha256": file_sha256(package / "final_anomaly_findings.jsonl"), "row_count": 4}
            (package / "analysis_summary.json").write_text(canonical_json(summary), encoding="utf-8")
            with self.assertRaisesRegex(PackageAuditError, "investigation rank"):
                audit_package(package, expected_rows=4, report_path=report)

        self.assertEqual(result, {"status": "PASS", "record_count": 4, "top_50_count": 4, "graph_count": 10})


if __name__ == "__main__":
    unittest.main()
