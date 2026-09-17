"""Synthetic contracts for deterministic Stage 1.9 explanations.

These tests use only small in-memory values.  They never open the raw CSV or
any real processed artifact.
"""

from __future__ import annotations

import sys
import csv
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ai_features.models import FEATURE_NAMES, HOLDOUT_PARTITION, REFERENCE_PARTITION, FeatureRow  # noqa: E402
from anomaly.models import AnomalyScoreRow  # noqa: E402
from explainability.drivers import (  # noqa: E402
    build_feature_drivers,
    compile_reference_index,
    numeric_extremeness,
    rarity_extremeness,
)
from explainability.interpretation import (  # noqa: E402
    CANONICAL_BEHAVIORS,
    InterpretationError,
    build_explanation,
)
from evaluation.review import (  # noqa: E402
    QUEUE_COLUMNS,
    build_review_sample,
    review_id_for_record,
    write_review_queue,
)


def feature_values(**overrides: float) -> tuple[float, ...]:
    values = [0.0] * len(FEATURE_NAMES)
    for name, value in overrides.items():
        values[FEATURE_NAMES.index(name)] = float(value)
    return tuple(values)


def feature_row(
    record_number: int, *, partition: str = HOLDOUT_PARTITION, **overrides: float
) -> FeatureRow:
    return FeatureRow(
        source_record_number=record_number,
        source_record_id=f"LOGUID_OPAQUE_{record_number}",
        partition=partition,
        values=feature_values(**overrides),
    )


def score_row(
    record_number: int,
    *,
    rank: int,
    selected: bool | None = None,
    partition: str = HOLDOUT_PARTITION,
) -> AnomalyScoreRow:
    return AnomalyScoreRow(
        source_record_number=record_number,
        source_record_id=f"LOGUID_OPAQUE_{record_number}",
        partition=partition,
        model_score=float(rank),
        raw_abnormality=float(-rank),
        anomaly_score=99.0,
        anomaly_rank=rank,
        anomaly_band="TOP_1_PERCENT",
        analyst_review_selected=rank <= 50 if selected is None else selected,
    )


def metadata() -> dict[str, object]:
    distributions = []
    for name in FEATURE_NAMES:
        values = [[0.0, 99], [1.0, 1]]
        if name.startswith("log_"):
            values = [[0.0, 99], [5.0, 1]]
        distributions.append({"name": name, "values": values, "eligible_count": 100})
    return {"eligible_reference_distributions": distributions}


def context(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_number": 6,
        "protocol_name": "TCP",
        "source_port": 51515,
        "destination_port": 443,
        "service_source": "HTTPS",
        "source_identifier": "SRCIP_OPAQUE",
        "destination_identifier": "DSTIP_OPAQUE",
        "sent_bytes": 100,
        "received_bytes": 100,
        "sent_packets": 1,
        "received_packets": 1,
        "duration_raw_value": 1,
        "source_port_missing": False,
        "destination_port_missing": False,
        "service_missing": False,
        "sent_bytes_missing": False,
        "received_bytes_missing": False,
        "sent_packets_missing": False,
        "received_packets_missing": False,
        "duration_missing": False,
        "source_threat_type": None,
        "matched_rule_ids": (),
        "source_threat_observation_present": False,
        "anomaly_subtype_observation_present": False,
    }
    value.update(overrides)
    return value


class DriverFormulaTests(unittest.TestCase):
    def test_numeric_extremeness_uses_midrank_and_handles_a_constant(self) -> None:
        self.assertEqual(numeric_extremeness(1.0, ((1.0, 10),)), (0.0, 0, 10, 10))
        self.assertEqual(numeric_extremeness(2.0, ((1.0, 10),)), (1.0, 10, 0, 10))

    def test_rarity_extremeness_only_treats_the_upper_tail_as_rare(self) -> None:
        self.assertEqual(rarity_extremeness(0.0, ((0.0, 90), (1.0, 10))), (0.0, 0, 90, 100))
        extremeness, less, equal, total = rarity_extremeness(1.0, ((0.0, 90), (1.0, 10)))
        self.assertAlmostEqual(extremeness, 0.9, places=12)
        self.assertEqual((less, equal, total), (90, 10, 100))

    def test_compiled_reference_index_preserves_all_driver_values(self) -> None:
        row = feature_row(1, log_sent_bytes=5.0, src_port_rarity=1.0, protocol_tcp=1.0)
        original = build_feature_drivers(row, metadata(), context())
        compiled = build_feature_drivers(
            row,
            metadata(),
            context(),
            reference_index=compile_reference_index(metadata()),
        )
        self.assertEqual(compiled, original)

    def test_compiled_counts_match_scalar_formulas_at_and_between_reference_values(self) -> None:
        distribution = ((0.0, 90), (1.0, 10))
        feature_metadata = metadata()
        for item in feature_metadata["eligible_reference_distributions"]:
            if item["name"] in {"log_sent_bytes", "src_port_rarity"}:
                item["values"] = [[0.0, 90], [1.0, 10]]
        reference_index = compile_reference_index(feature_metadata)
        cases = (
            (-0.5, (0, 0, 100), 1.0, 0.0),
            (0.9, (90, 0, 100), 0.8, 0.8),
            (1.5, (100, 0, 100), 1.0, 1.0),
            (1.0, (90, 10, 100), 0.9, 0.9),
        )
        for observed, expected_counts, expected_numeric, expected_rarity in cases:
            with self.subTest(observed=observed):
                drivers = {
                    driver.feature_name: driver
                    for driver in build_feature_drivers(
                        feature_row(1, log_sent_bytes=observed, src_port_rarity=observed),
                        feature_metadata,
                        context(),
                        reference_index=reference_index,
                    )
                }
                for name, scalar_formula, expected_extremeness in (
                    ("log_sent_bytes", numeric_extremeness, expected_numeric),
                    ("src_port_rarity", rarity_extremeness, expected_rarity),
                ):
                    driver = drivers[name]
                    scalar_extremeness, less, equal, total = scalar_formula(observed, distribution)
                    self.assertEqual((less, equal, total), expected_counts)
                    self.assertEqual(
                        (driver.less_count, driver.equal_count, driver.reference_n),
                        expected_counts,
                    )
                    self.assertAlmostEqual(scalar_extremeness, expected_extremeness, places=12)
                    self.assertAlmostEqual(driver.extremeness, scalar_extremeness, places=12)

    def test_empty_reference_distribution_still_produces_no_driver(self) -> None:
        metadata_with_empty_rarity = metadata()
        for distribution in metadata_with_empty_rarity["eligible_reference_distributions"]:
            if distribution["name"] == "src_port_rarity":
                distribution["values"] = []
                distribution["eligible_count"] = 0
        drivers = build_feature_drivers(
            feature_row(1, src_port_rarity=1.0),
            metadata_with_empty_rarity,
            context(),
        )
        self.assertNotIn("src_port_rarity", [driver.feature_name for driver in drivers])


class InterpretationTests(unittest.TestCase):
    def test_behaviors_are_in_the_fixed_non_alphabetical_order(self) -> None:
        explanation = build_explanation(
            feature_row(
                1,
                log_sent_bytes=5.0,
                sent_byte_share=1.0,
                log_duration=5.0,
                src_port_rarity=1.0,
                protocol_other=1.0,
            ),
            score_row(1, rank=1),
            metadata(),
            context(protocol_number=99, protocol_name="OTHER"),
        )
        self.assertEqual(explanation["suspected_behaviors"], list(CANONICAL_BEHAVIORS))

    def test_non_top_50_keeps_descriptive_tags_but_never_gets_an_attack_type(self) -> None:
        explanation = build_explanation(
            feature_row(51, log_sent_bytes=5.0),
            score_row(51, rank=51),
            metadata(),
            context(),
        )
        self.assertEqual(explanation["suspected_attack_type"], None)
        self.assertEqual(explanation["suspected_behaviors"], ["UNUSUAL_TRAFFIC_VOLUME"])
        self.assertNotIn("UNCLASSIFIED_ANOMALOUS_PATTERN", explanation["suspected_behaviors"])

    def test_top_50_reconnaissance_uses_the_exact_cautious_phrase(self) -> None:
        explanation = build_explanation(
            feature_row(1, src_port_rarity=1.0),
            score_row(1, rank=1),
            metadata(),
            context(source_threat_type="Reconnaissance"),
        )
        self.assertEqual(explanation["suspected_attack_type"], "Possible reconnaissance activity")

    def test_other_top_50_uses_the_exact_fallback_attack_phrase(self) -> None:
        explanation = build_explanation(
            feature_row(1, log_sent_bytes=5.0),
            score_row(1, rank=1),
            metadata(),
            context(),
        )
        self.assertEqual(explanation["suspected_attack_type"], "Unclassified suspicious behavior")

    def test_unclassified_behavior_is_a_top_50_only_fallback(self) -> None:
        top = build_explanation(feature_row(1), score_row(1, rank=1), metadata(), context())
        other = build_explanation(feature_row(51), score_row(51, rank=51), metadata(), context())
        self.assertEqual(top["suspected_behaviors"], ["UNCLASSIFIED_ANOMALOUS_PATTERN"])
        self.assertEqual(other["suspected_behaviors"], [])

    def test_a_changed_stage_1_8_top_50_flag_fails_closed(self) -> None:
        with self.assertRaises(InterpretationError):
            build_explanation(feature_row(1), score_row(1, rank=1, selected=False), metadata(), context())

    def test_evidence_strength_uses_only_the_four_approved_values(self) -> None:
        high = build_explanation(
            feature_row(1, log_sent_bytes=5.0, src_port_rarity=1.0),
            score_row(1, rank=1),
            metadata(),
            context(matched_rule_ids=("fortigate.source_threat_observation",)),
        )
        low = build_explanation(
            feature_row(2, log_sent_bytes=5.0),
            score_row(2, rank=2),
            metadata(),
            context(),
        )
        baseline = build_explanation(feature_row(3), score_row(3, rank=3), metadata(), context())
        self.assertEqual(high["evidence_strength"], "HIGH")
        self.assertEqual(low["evidence_strength"], "LOW")
        self.assertIsNone(baseline["evidence_strength"])

    def test_medium_evidence_wins_over_low_when_two_families_qualify(self) -> None:
        explanation = build_explanation(
            feature_row(1, log_sent_bytes=5.0, src_port_rarity=1.0),
            score_row(1, rank=1),
            metadata(),
            context(),
        )
        self.assertEqual(explanation["evidence_strength"], "MEDIUM")

    def test_explanations_are_deterministic_and_do_not_interpret_opaque_identifiers(self) -> None:
        row = feature_row(1, log_sent_bytes=5.0)
        first = build_explanation(row, score_row(1, rank=1), metadata(), context())
        second = build_explanation(row, score_row(1, rank=1), metadata(), context())
        self.assertEqual(first, second)
        rendered = str(first["top_reasons"])
        self.assertNotIn("SRCIP_OPAQUE", rendered)
        self.assertNotIn("DSTIP_OPAQUE", rendered)

    def test_priority_is_a_bounded_heuristic_not_an_attack_probability(self) -> None:
        explanation = build_explanation(
            feature_row(1), score_row(1, rank=1), metadata(),
            context(matched_rule_ids=("fortigate.source_threat_observation",)),
        )
        self.assertEqual(explanation["investigation_priority_score"], 99.1)

    def test_missingness_alone_cannot_establish_a_specific_behavior(self) -> None:
        explanation = build_explanation(
            feature_row(1, sent_bytes_missing=1.0),
            score_row(1, rank=1),
            metadata(),
            context(sent_bytes=None, sent_bytes_missing=True),
        )
        self.assertEqual(explanation["suspected_behaviors"], ["UNCLASSIFIED_ANOMALOUS_PATTERN"])
        self.assertIsNone(explanation["evidence_strength"])

    def test_top_reasons_are_bounded_without_padding(self) -> None:
        explanation = build_explanation(
            feature_row(1, log_sent_bytes=5.0, sent_byte_share=1.0, log_duration=5.0, src_port_rarity=1.0),
            score_row(1, rank=1),
            metadata(),
            context(),
        )
        self.assertLessEqual(len(explanation["top_reasons"]), 3)


class ReviewSampleTests(unittest.TestCase):
    def test_review_id_is_deterministic_and_contains_no_source_token(self) -> None:
        review_id = review_id_for_record("a" * 64, 42)
        self.assertTrue(review_id.startswith("R-"))
        self.assertNotIn("LOGUID", review_id)
        self.assertEqual(review_id, review_id_for_record("a" * 64, 42))

    def test_sample_preserves_exact_stage_1_8_top_50_membership(self) -> None:
        rows = []
        for number in range(1, 101):
            score = score_row(number, rank=number, partition=REFERENCE_PARTITION)
            rows.append({**build_explanation(feature_row(number, partition=REFERENCE_PARTITION), score, metadata(), context()), "raw_abnormality": float(101 - number)})
        sample, counts = build_review_sample(rows, "a" * 64)
        top = {item["source_record_number"] for item in sample if item["review_membership"] == "TOP_50"}
        self.assertEqual(top, set(range(1, 51)))
        self.assertEqual(sum(counts.values()), 100)

    def test_queue_is_blinded_and_formula_safe(self) -> None:
        row = build_explanation(feature_row(1), score_row(1, rank=1), metadata(), context(source_identifier="=opaque"))
        row["review_id"] = review_id_for_record("a" * 64, 1)
        with tempfile.TemporaryDirectory() as directory:
            queue_path = Path(directory) / "queue.csv"
            self.assertEqual(write_review_queue(queue_path, [row]), 1)
            with queue_path.open("r", encoding="utf-8", newline="") as handle:
                queue = csv.DictReader(handle)
                self.assertEqual(tuple(queue.fieldnames or ()), QUEUE_COLUMNS)
                exported = next(queue)
        self.assertEqual(exported["source_identifier"], "'=opaque")
        self.assertNotIn("anomaly_score", exported)
        self.assertNotIn("source_record_number", exported)
