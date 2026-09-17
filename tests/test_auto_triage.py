"""Synthetic contracts for Stage 1.9 automatic investigation triage.

These tests exercise only small in-memory explanation rows.  They never use
human labels, raw logs, processed artifacts, or a model.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from auto_triage import (  # noqa: E402
    AUTO_TRIAGE_VALUES,
    build_auto_triage_summary,
    classify_auto_triage,
    project_auto_triage_row,
)


def explanation_row(
    record_number: int,
    *,
    rank: int,
    anomaly_band: str,
    review_id: str | None = None,
    evidence_strength: str | None = None,
    behaviors: list[str] | None = None,
    attack_type: str | None = None,
) -> dict[str, object]:
    return {
        "source_record_number": record_number,
        "source_record_id": f"LOGUID_OPAQUE_{record_number}",
        "partition": "REFERENCE",
        "anomaly_rank": rank,
        "anomaly_score": 99.0 - record_number,
        "anomaly_band": anomaly_band,
        "analyst_review_selected": rank <= 50,
        "investigation_priority_score": 90.0 - record_number,
        "evidence_strength": evidence_strength,
        "suspected_attack_type": attack_type,
        "suspected_behaviors": [] if behaviors is None else behaviors,
        "top_reasons": [],
        "review_id": review_id,
    }


class AutoTriageTests(unittest.TestCase):
    def test_only_the_three_approved_triage_values_are_emitted(self) -> None:
        rows = [
            explanation_row(1, rank=1, anomaly_band="TOP_0_1_PERCENT", review_id="R-" + "a" * 64),
            explanation_row(51, rank=51, anomaly_band="TOP_5_PERCENT"),
            explanation_row(52, rank=52, anomaly_band="BASELINE"),
        ]
        self.assertEqual(
            [classify_auto_triage(row) for row in rows],
            ["HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST"],
        )
        self.assertEqual(AUTO_TRIAGE_VALUES, frozenset({"HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST"}))

    def test_top_50_is_high_interest_without_changing_its_membership(self) -> None:
        row = explanation_row(1, rank=1, anomaly_band="BASELINE", review_id="R-" + "a" * 64)
        projected = project_auto_triage_row(row)
        self.assertEqual(projected["auto_triage"], "HIGH_INTEREST")
        self.assertEqual(projected["anomaly_rank"], 1)

    def test_invalid_top_50_flag_fails_closed(self) -> None:
        row = explanation_row(1, rank=1, anomaly_band="TOP_0_1_PERCENT")
        row["analyst_review_selected"] = False
        with self.assertRaises(ValueError):
            classify_auto_triage(row)

    def test_non_top_frozen_anomaly_bands_are_medium_interest(self) -> None:
        for position, band in enumerate(("TOP_0_1_PERCENT", "TOP_1_PERCENT", "TOP_5_PERCENT"), start=51):
            self.assertEqual(
                classify_auto_triage(explanation_row(position, rank=position, anomaly_band=band)),
                "MEDIUM_INTEREST",
            )

    def test_non_top_attack_interpretation_remains_null_and_review_is_not_fabricated(self) -> None:
        row = explanation_row(51, rank=51, anomaly_band="BASELINE")
        projected = project_auto_triage_row(row)
        self.assertIsNone(projected["suspected_attack_type"])
        self.assertEqual(projected["review_status"], "NOT_SELECTED")

    def test_low_interest_is_not_presented_as_benign_or_safe(self) -> None:
        row = explanation_row(51, rank=51, anomaly_band="BASELINE")
        projected = project_auto_triage_row(row)
        self.assertEqual(projected["auto_triage"], "LOW_INTEREST")
        self.assertNotIn("BENIGN", projected.values())
        self.assertNotIn("SAFE", projected.values())

    def test_queue_member_is_pending_without_human_labels(self) -> None:
        row = explanation_row(51, rank=51, anomaly_band="BASELINE", review_id="R-" + "b" * 64)
        self.assertEqual(project_auto_triage_row(row)["review_status"], "PENDING")

    def test_summary_counts_reconcile_without_supervised_metrics(self) -> None:
        rows = [
            explanation_row(
                1,
                rank=1,
                anomaly_band="TOP_0_1_PERCENT",
                review_id="R-" + "a" * 64,
                evidence_strength="HIGH",
                behaviors=["UNUSUAL_TRAFFIC_VOLUME"],
                attack_type="Unclassified suspicious behavior",
            ),
            explanation_row(51, rank=51, anomaly_band="TOP_5_PERCENT", review_id="R-" + "b" * 64),
            explanation_row(52, rank=52, anomaly_band="BASELINE"),
        ]
        summary = build_auto_triage_summary(rows)
        self.assertEqual(summary["row_count"], 3)
        self.assertEqual(summary["auto_triage_counts"], {
            "HIGH_INTEREST": 1,
            "MEDIUM_INTEREST": 1,
            "LOW_INTEREST": 1,
        })
        self.assertEqual(summary["review_status_counts"], {
            "NOT_SELECTED": 1,
            "PENDING": 2,
            "REVIEWED_RESOLVED": 0,
            "REVIEWED_UNCERTAIN": 0,
        })
        self.assertNotIn("precision", summary)
        self.assertNotIn("recall", summary)
        self.assertNotIn("f1", summary)
        self.assertNotIn("confusion_matrix", summary)

    def test_triage_summary_covers_100000_logical_rows(self) -> None:
        def rows():
            for record_number in range(1, 100_001):
                if record_number <= 100:
                    band = "TOP_0_1_PERCENT"
                elif record_number <= 1_000:
                    band = "TOP_1_PERCENT"
                elif record_number <= 5_000:
                    band = "TOP_5_PERCENT"
                else:
                    band = "BASELINE"
                yield explanation_row(
                    record_number,
                    rank=record_number,
                    anomaly_band=band,
                )

        summary = build_auto_triage_summary(rows())
        self.assertEqual(summary["row_count"], 100_000)
        self.assertEqual(summary["top_50_count"], 50)
        self.assertEqual(
            summary["auto_triage_counts"],
            {
                "HIGH_INTEREST": 50,
                "MEDIUM_INTEREST": 4_950,
                "LOW_INTEREST": 95_000,
            },
        )

    def test_projection_preserves_canonical_behavior_order_without_reclassification(self) -> None:
        behaviors = [
            "UNUSUAL_TRAFFIC_VOLUME",
            "UNUSUAL_SESSION_CHARACTERISTICS",
            "RARE_PORT_OR_SERVICE_CONTEXT",
        ]
        row = explanation_row(1, rank=1, anomaly_band="TOP_0_1_PERCENT", review_id="R-" + "a" * 64, behaviors=behaviors)
        self.assertEqual(project_auto_triage_row(row)["suspected_behaviors"], behaviors)

    def test_triage_projection_and_summary_are_deterministic(self) -> None:
        rows = [
            explanation_row(1, rank=1, anomaly_band="TOP_0_1_PERCENT", review_id="R-" + "a" * 64),
            explanation_row(51, rank=51, anomaly_band="TOP_5_PERCENT", review_id="R-" + "b" * 64),
            explanation_row(52, rank=52, anomaly_band="BASELINE"),
        ]
        self.assertEqual([project_auto_triage_row(row) for row in rows], [project_auto_triage_row(row) for row in rows])
        self.assertEqual(build_auto_triage_summary(rows), build_auto_triage_summary(rows))
