from __future__ import annotations

import numpy as np
import pytest

from unsupervised.evaluation import (
    ALL_ANOMALY,
    ALL_INLIER,
    ThresholdPolicy,
    compare_validation_models,
    evaluate_scores,
    select_threshold,
)
from run_unsw_validation import _assert_no_cross_partition_vector_collisions


def test_threshold_tie_prefers_minimum_numeric_over_all_anomaly() -> None:
    policy = select_threshold([1.0, 2.0], [1, 0])
    assert policy.threshold == 1.0
    assert policy.predict([0.5, 1.0, 2.0]).tolist() == [False, True, True]


def test_threshold_boundaries_and_total_order_are_explicit() -> None:
    all_anomaly = ThresholdPolicy(ALL_ANOMALY, 0, 1, 2)
    all_inlier = ThresholdPolicy(ALL_INLIER, 0, 1, 2)
    assert all_anomaly.threshold == ALL_ANOMALY
    assert all_inlier.threshold == ALL_INLIER
    assert all_anomaly.predict([0.0, 3.0]).tolist() == [True, True]
    assert all_inlier.predict([0.0, 3.0]).tolist() == [False, False]


def test_evaluation_uses_attack_positive_and_confusion_axis_order() -> None:
    report = evaluate_scores(
        np.asarray([0.1, 0.8, 0.9, 0.2]),
        [0, 1, 0, 1],
        select_threshold([0.2, 0.8], [0, 1]),
    )
    assert report["confusion_matrix"] == [[1, 1], [1, 1]]
    assert report["tp"] == 1
    assert report["fp"] == 1
    assert report["tn"] == 1
    assert report["fn"] == 1
    assert report["pr_auc_convention"] == "PR_AUC_AP"
    assert report["roc_auc"] == 0.5


def test_comparison_prefers_ap_then_runtime_then_u1() -> None:
    assert compare_validation_models(0.7, 0.700002, 4.0, 2.0)["selected_model"] == "U2"
    assert compare_validation_models(0.7, 0.7000005, 4.0, 2.0)["selected_model"] == "U2"
    assert compare_validation_models(0.7, 0.7, 4.0, 2.0)["selected_model"] == "U2"
    assert compare_validation_models(0.7, 0.7, 2.0, 2.0)["selected_model"] == "U1"


def test_conflict_rows_are_counted_without_replacing_primary_metrics() -> None:
    report = evaluate_scores(
        np.asarray([0.1, 0.95, 0.9, 0.2]),
        [1, 0, 1, 0],
        select_threshold([0.1, 0.9], [0, 1]),
        conflict_mask=[True, True, False, False],
    )
    assert report["row_count"] == 4
    assert report["conflict_rows"] == 2
    assert report["conflict_attack"] == 1
    assert report["conflict_normal"] == 1
    assert report["conflict_error_count"] == 2
    assert report["confusion_matrix"] == [[1, 1], [1, 1]]


def test_post_transform_collision_gate_rejects_cross_partition_duplicates() -> None:
    matrices = {
        "TRAIN_INTERNAL": np.asarray([[1.0, 2.0]]),
        "VALIDATION_CALIBRATION": np.asarray([[1.0, 2.0]]),
    }
    with pytest.raises(RuntimeError, match="collision gate"):
        _assert_no_cross_partition_vector_collisions(matrices)
