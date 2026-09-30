from __future__ import annotations

import numpy as np
import pytest

from supervised.models import (
    S1_CANDIDATES,
    S2_CONFIG,
    build_s1_estimator,
    build_s2_estimator,
    evaluate_s1_predictions,
    fit_s2_classifier,
    predict_p_attack,
    select_s1_candidate,
    validate_s2_resource,
    _pilot_prefix,
)


def test_s1_recipe_is_exact_and_bounded() -> None:
    assert S1_CANDIDATES == (0.1, 1.0)
    estimator = build_s1_estimator(1.0)
    params = estimator.get_params()
    assert params["C"] == 1.0
    assert params["solver"] == "lbfgs"
    assert params["l1_ratio"] == 0.0
    assert params["dual"] is False
    assert params["tol"] == 1e-4
    assert params["max_iter"] == 1000
    assert params["fit_intercept"] is True
    assert params["class_weight"] is None
    assert params["random_state"] == 1729
    assert params["warm_start"] is False
    assert params["verbose"] == 0


def test_ap_tie_within_tolerance_prefers_smaller_c() -> None:
    result = select_s1_candidate(
        {
            0.1: (0.8000000, 0.7000000),
            1.0: (0.8000005, 0.7000004),
        }
    )
    assert result == 0.1


def test_positive_probability_uses_verified_attack_class() -> None:
    estimator = build_s1_estimator(1.0)
    X = np.asarray([[0.0], [1.0], [2.0], [3.0]])
    y = np.asarray([0, 0, 1, 1])
    estimator.fit(X, y)
    assert np.array_equal(estimator.classes_, np.asarray([0, 1]))
    probabilities = predict_p_attack(estimator, X)
    assert probabilities.shape == (4,)
    assert np.isfinite(probabilities).all()
    assert np.all((probabilities >= 0.0) & (probabilities <= 1.0))

    estimator.classes_ = np.asarray([1, 0])
    with pytest.raises(ValueError, match="class ordering"):
        predict_p_attack(estimator, X)


def test_threshold_equality_and_average_precision_contract() -> None:
    report = evaluate_s1_predictions(np.asarray([0, 1, 1, 0]), np.asarray([0.5, 0.5, 0.2, 0.1]))
    assert report["threshold"] == 0.5
    assert report["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert report["average_precision"] == pytest.approx(0.5833333333333333)
    assert report["positive_class"] == 1


def test_s2_is_the_single_approved_random_forest_recipe() -> None:
    assert S2_CONFIG == {
        "n_estimators": 150,
        "criterion": "gini",
        "max_depth": 16,
        "min_samples_split": 2,
        "min_samples_leaf": 2,
        "min_weight_fraction_leaf": 0.0,
        "max_features": "sqrt",
        "max_leaf_nodes": 1024,
        "min_impurity_decrease": 0.0,
        "bootstrap": True,
        "oob_score": False,
        "class_weight": None,
        "n_jobs": 1,
        "random_state": 1729,
        "warm_start": False,
        "ccp_alpha": 0.0,
        "max_samples": None,
        "monotonic_cst": None,
        "verbose": 0,
    }
    estimator = build_s2_estimator()
    params = estimator.get_params()
    for key, value in S2_CONFIG.items():
        assert params[key] == value


def test_s2_resource_gate_rejects_over_budget_without_fallback() -> None:
    assert validate_s2_resource(elapsed_seconds=119.0, peak_rss_bytes=100, pilot=True) is True
    assert validate_s2_resource(elapsed_seconds=120.1, peak_rss_bytes=100, pilot=True) is False
    assert validate_s2_resource(elapsed_seconds=600.1, peak_rss_bytes=100, pilot=False) is False


def test_s2_pilot_is_group_prefix_and_replay_is_exact() -> None:
    rows = []
    for group, label in (("g1", "0"), ("g2", "1"), ("g3", "0")):
        rows.extend({"group_id": group, "label": label} for _ in range(10_000))
    selected = _pilot_prefix(rows)
    assert len(selected) == 20_000
    assert {row["group_id"] for row in selected} == {"g1", "g2"}

    X = np.asarray([[0.0], [0.1], [0.9], [1.0], [0.2], [0.8]], dtype=float)
    y = np.asarray([0, 0, 1, 1, 0, 1], dtype=np.int8)
    first, report = fit_s2_classifier(X, y, context="synthetic-pilot-0", pilot=True)
    second, _ = fit_s2_classifier(X, y, context="synthetic-pilot-1", pilot=True)
    first_p = predict_p_attack(first, X)
    second_p = predict_p_attack(second, X)
    assert report["status"] == "PASS"
    assert np.max(np.abs(first_p - second_p)) <= 1e-12
    assert np.array_equal(first_p >= 0.5, second_p >= 0.5)


def test_s2_capability_does_not_apply_ap_floor() -> None:
    report = evaluate_s1_predictions(
        np.asarray([0, 0, 1, 1]),
        np.asarray([0.9, 0.8, 0.7, 0.6]),
    )
    assert report["average_precision"] < 1.0
    assert report["positive_class"] == 1
