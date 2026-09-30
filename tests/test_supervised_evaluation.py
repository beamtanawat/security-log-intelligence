from __future__ import annotations

import numpy as np
import pytest

from supervised.evaluation import evaluate_probabilities, select_preferred_model, validate_selection_lock


def test_fixed_threshold_includes_equality_and_reports_ap() -> None:
    report = evaluate_probabilities(np.asarray([0, 1, 1, 0]), np.asarray([0.5, 0.5, 0.2, 0.1]))
    assert report["threshold"] == 0.5
    assert report["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert report["average_precision"] == pytest.approx(0.5833333333333333)


def test_validation_ap_preference_tie_prefers_s1() -> None:
    assert select_preferred_model({"S1": 0.9000000, "S2": 0.9000005}) == "S1"
    assert select_preferred_model({"S1": 0.8, "S2": 0.9}) == "S2"


def test_selection_lock_rejects_test_or_chained_signals() -> None:
    lock = {"test_used": False, "chained_signals_used": False, "thresholds": {"S1": 0.5, "S2": 0.5}}
    assert validate_selection_lock(lock) is True
    with pytest.raises(ValueError, match="TEST"):
        validate_selection_lock({**lock, "test_used": True})
    with pytest.raises(ValueError, match="chained"):
        validate_selection_lock({**lock, "chained_signals_used": True})
