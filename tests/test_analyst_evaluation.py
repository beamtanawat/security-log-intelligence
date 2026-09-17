"""Synthetic review/evaluation contracts for Stage 1.9.

No test reads a real review label, normalized event, score bundle, or raw CSV.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.metrics import (  # noqa: E402
    EvaluationError,
    evaluate_review_mapping,
    review_status_for,
)
from evaluation.review import ReviewError, validate_blind_reviews  # noqa: E402


def expected_review(review_id: str, membership: str) -> dict[str, object]:
    return {
        "review_id": review_id,
        "source_record_number": int(review_id.split("-")[-1], 16) if len(review_id) < 10 else 1,
        "review_membership": membership,
        "analyst_review_selected": membership == "TOP_50",
    }


class ReviewStatusTests(unittest.TestCase):
    def test_no_review_id_is_not_selected(self) -> None:
        self.assertEqual(review_status_for(None, None), "NOT_SELECTED")

    def test_selected_without_an_accepted_review_is_pending(self) -> None:
        self.assertEqual(review_status_for("R-" + "a" * 64, None), "PENDING")

    def test_uncertain_maps_to_reviewed_uncertain(self) -> None:
        self.assertEqual(review_status_for("R-" + "a" * 64, "UNCERTAIN"), "REVIEWED_UNCERTAIN")

    def test_resolved_labels_map_to_reviewed_resolved(self) -> None:
        review_id = "R-" + "a" * 64
        self.assertEqual(review_status_for(review_id, "SUSPICIOUS"), "REVIEWED_RESOLVED")
        self.assertEqual(review_status_for(review_id, "NOT_SUSPICIOUS"), "REVIEWED_RESOLVED")


class LabelValidationTests(unittest.TestCase):
    def test_invalid_decision_fails_closed(self) -> None:
        expected = {"R-" + "a" * 64}
        with self.assertRaises(ReviewError):
            validate_blind_reviews(
                [{"review_id": next(iter(expected)), "blind_label": "ATTACK", "blind_rationale": "x", "reviewer_alias": "a", "reviewed_at": "2026-01-01T00:00:00+00:00"}],
                expected,
            )

    def test_duplicate_or_conflicting_reviews_fail_closed(self) -> None:
        review_id = "R-" + "a" * 64
        entries = [
            {"review_id": review_id, "blind_label": "SUSPICIOUS", "blind_rationale": "x", "reviewer_alias": "a", "reviewed_at": "2026-01-01T00:00:00+00:00"},
            {"review_id": review_id, "blind_label": "NOT_SUSPICIOUS", "blind_rationale": "y", "reviewer_alias": "a", "reviewed_at": "2026-01-01T00:00:00+00:00"},
        ]
        with self.assertRaises(ReviewError):
            validate_blind_reviews(entries, {review_id})

    def test_no_fake_review_id_is_created(self) -> None:
        expected = {"R-" + "a" * 64}
        with self.assertRaises(ReviewError):
            validate_blind_reviews(
                [{"review_id": "R-" + "b" * 64, "blind_label": "SUSPICIOUS", "blind_rationale": "x", "reviewer_alias": "a", "reviewed_at": "2026-01-01T00:00:00+00:00"}],
                expected,
            )


class EvaluationTests(unittest.TestCase):
    def test_insufficient_review_evidence_does_not_create_metrics(self) -> None:
        records = [
            {"source_record_number": 1, "review_id": "R-" + "a" * 64, "review_membership": "TOP_50", "analyst_review_selected": True},
            {"source_record_number": 2, "review_id": "R-" + "b" * 64, "review_membership": "COMPARISON", "analyst_review_selected": False},
        ]
        reviews = {
            "R-" + "a" * 64: {"blind_label": "UNCERTAIN"},
            "R-" + "b" * 64: {"blind_label": "UNCERTAIN"},
        }
        result = evaluate_review_mapping(records, reviews)
        self.assertIsNone(result["metrics"]["precision"])
        self.assertEqual(result["metrics"]["reason"], "INSUFFICIENT_RESOLVED_REVIEW_EVIDENCE")

    def test_valid_reviewed_evaluation_is_deterministic_and_uses_only_blind_labels(self) -> None:
        records = [
            {"source_record_number": 1, "review_id": "R-" + "a" * 64, "review_membership": "TOP_50", "analyst_review_selected": True, "source_threat_type": "Reconnaissance", "anomaly_score": 100.0},
            {"source_record_number": 2, "review_id": "R-" + "b" * 64, "review_membership": "COMPARISON", "analyst_review_selected": False, "source_threat_type": None, "anomaly_score": 0.0},
        ]
        reviews = {
            "R-" + "a" * 64: {"blind_label": "SUSPICIOUS"},
            "R-" + "b" * 64: {"blind_label": "NOT_SUSPICIOUS"},
        }
        first = evaluate_review_mapping(records, reviews)
        second = evaluate_review_mapping(records, reviews)
        self.assertEqual(first, second)
        self.assertEqual(first["resolved_matrix"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        self.assertEqual(first["metrics"]["precision"], 1.0)

    def test_changing_source_threats_or_scores_cannot_change_review_metrics(self) -> None:
        records = [
            {"source_record_number": 1, "review_id": "R-" + "a" * 64, "review_membership": "TOP_50", "analyst_review_selected": True, "source_threat_type": "Reconnaissance", "anomaly_score": 100.0},
            {"source_record_number": 2, "review_id": "R-" + "b" * 64, "review_membership": "COMPARISON", "analyst_review_selected": False, "source_threat_type": None, "anomaly_score": 0.0},
        ]
        changed = [
            {**records[0], "source_threat_type": None, "anomaly_score": 0.0},
            {**records[1], "source_threat_type": "Reconnaissance", "anomaly_score": 100.0},
        ]
        reviews = {"R-" + "a" * 64: {"blind_label": "SUSPICIOUS"}, "R-" + "b" * 64: {"blind_label": "NOT_SUSPICIOUS"}}
        self.assertEqual(evaluate_review_mapping(records, reviews), evaluate_review_mapping(changed, reviews))

    def test_review_counts_reconcile_and_status_projection_is_authoritative(self) -> None:
        records = [
            {"source_record_number": 1, "review_id": None, "review_membership": "NOT_SELECTED", "analyst_review_selected": False},
            {"source_record_number": 2, "review_id": "R-" + "a" * 64, "review_membership": "TOP_50", "analyst_review_selected": True},
            {"source_record_number": 3, "review_id": "R-" + "b" * 64, "review_membership": "COMPARISON", "analyst_review_selected": False},
        ]
        result = evaluate_review_mapping(
            records,
            {"R-" + "a" * 64: {"blind_label": "SUSPICIOUS"}, "R-" + "b" * 64: {"blind_label": "UNCERTAIN"}},
        )
        self.assertEqual(result["review_status_counts"], {"NOT_SELECTED": 1, "PENDING": 0, "REVIEWED_RESOLVED": 1, "REVIEWED_UNCERTAIN": 1})
        self.assertEqual([item["review_status"] for item in result["record_review_results"]], ["NOT_SELECTED", "REVIEWED_RESOLVED", "REVIEWED_UNCERTAIN"])

    def test_invalid_review_membership_fails_closed(self) -> None:
        with self.assertRaises(EvaluationError):
            evaluate_review_mapping(
                [{"source_record_number": 1, "review_id": None, "review_membership": "TOP_50", "analyst_review_selected": False}],
                {},
            )

    def test_uncertain_prefix_metrics_report_bounds_and_coverage(self) -> None:
        records = [
            {
                "source_record_number": number,
                "anomaly_rank": number,
                "review_id": "R-" + f"{number:064x}",
                "review_membership": "TOP_50",
                "analyst_review_selected": True,
            }
            for number in range(1, 51)
        ]
        reviews = {
            record["review_id"]: {"blind_label": "UNCERTAIN" if record["source_record_number"] == 1 else "SUSPICIOUS"}
            for record in records
        }
        result = evaluate_review_mapping(records, reviews)
        self.assertEqual(result["precision_at_k"]["10"], {
            "point_estimate": None,
            "bounds": [0.9, 1.0],
            "coverage": 0.9,
            "reason": "UNCERTAIN_REVIEWS_PRESENT",
        })

    def test_contextual_data_cannot_change_primary_blind_evaluation(self) -> None:
        records = [
            {"source_record_number": 1, "review_id": "R-" + "a" * 64, "review_membership": "TOP_50", "analyst_review_selected": True},
            {"source_record_number": 2, "review_id": "R-" + "b" * 64, "review_membership": "COMPARISON", "analyst_review_selected": False},
        ]
        blind = {
            "R-" + "a" * 64: {"blind_label": "SUSPICIOUS"},
            "R-" + "b" * 64: {"blind_label": "NOT_SUSPICIOUS"},
        }
        with_context = {
            review_id: {**value, "contextual_label": "UNCERTAIN"}
            for review_id, value in blind.items()
        }
        self.assertEqual(evaluate_review_mapping(records, blind), evaluate_review_mapping(records, with_context))
