from __future__ import annotations

import numpy as np
import pytest

from fortigate_u2 import (
    compare_fortigate_scores,
    fit_reference_scaler,
    score_top_residuals,
)


def test_scaler_fits_reference_only() -> None:
    reference = np.asarray([[0.0, 0.0], [2.0, 2.0]], dtype=np.float64)
    holdout = np.asarray([[100.0, 100.0]], dtype=np.float64)
    scaler = fit_reference_scaler(reference)
    assert scaler.mean_.tolist() == [1.0, 1.0]
    transformed = scaler.transform(holdout)
    np.testing.assert_allclose(transformed, [[99.0, 99.0]])


def test_comparison_uses_holdout_rank_and_exact_top_k_rules() -> None:
    row_numbers = np.arange(1, 101)
    u1 = np.linspace(0.0, 1.0, 100)
    u2 = u1.copy()
    result = compare_fortigate_scores(row_numbers, u1, u2, reference_u1=[0.1, 0.2], reference_u2=[0.1, 0.2])
    assert result["holdout"]["spearman_rank_correlation"] == pytest.approx(1.0)
    assert result["holdout"]["top_50_jaccard"] == 1.0
    assert result["holdout"]["top_100_jaccard"] == 1.0
    assert result["holdout"]["top_1_percent_jaccard"] == 1.0


def test_top_residuals_are_sorted_by_contribution_then_feature_order() -> None:
    matrix = np.asarray([[3.0, 1.0]], dtype=np.float64)
    centers = np.asarray([[0.0, 0.0], [10.0, 10.0]], dtype=np.float64)
    rows = score_top_residuals(matrix, centers, [7], ["a", "b"], top_rows=1)
    assert rows[0]["source_record_number"] == 7
    assert rows[0]["residuals"][0]["feature"] == "a"
    assert rows[0]["residuals"][0]["contribution"] == 9.0
