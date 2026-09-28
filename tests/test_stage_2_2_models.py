from __future__ import annotations

import pickle

import numpy as np
import pytest

from unsupervised.models import (
    U2Config,
    U2ModelError,
    fit_u2,
    pilot_order,
    score_u2,
)


def _matrix(rows: int = 3072, columns: int = 4) -> np.ndarray:
    values = np.arange(rows * columns, dtype=np.float64).reshape(rows, columns)
    return np.ascontiguousarray(values / 100.0)


def test_fit_u2_uses_frozen_minibatch_kmeans_contract_and_scores_unseen_rows() -> None:
    matrix = _matrix()
    membership = [f"row-{index}" for index in range(len(matrix))]
    bundle = fit_u2(matrix, membership)
    assert bundle.config == U2Config()
    assert bundle.fit_row_count == len(matrix)
    query = np.ascontiguousarray(matrix[:8] + 0.25)
    scores = score_u2(bundle, query)
    assert scores.shape == (8,)
    assert scores.dtype == np.float64
    assert np.isfinite(scores).all()
    assert np.ptp(scores) > 0
    assert scores[0] >= 0


def test_u2_is_deterministic_and_survives_serialization_replay() -> None:
    matrix = _matrix()
    membership = [f"row-{index}" for index in range(len(matrix))]
    first = fit_u2(matrix, membership)
    second = fit_u2(matrix, membership)
    query = np.ascontiguousarray(matrix[-32:] + 0.5)
    first_scores = score_u2(first, query)
    second_scores = score_u2(second, query)
    replay = score_u2(pickle.loads(pickle.dumps(first)), query)
    np.testing.assert_allclose(first_scores, second_scores, rtol=1e-10, atol=1e-12)
    np.testing.assert_allclose(first_scores, replay, rtol=1e-10, atol=1e-12)


def test_u2_rejects_small_nonfinite_or_degenerate_inputs() -> None:
    membership = [f"row-{index}" for index in range(3071)]
    with pytest.raises(U2ModelError, match="3072"):
        fit_u2(_matrix(3071), membership)
    matrix = _matrix()
    matrix[0, 0] = np.nan
    with pytest.raises(U2ModelError, match="finite"):
        fit_u2(matrix, [f"row-{index}" for index in range(len(matrix))])
    constant = np.ones((3072, 4), dtype=np.float64)
    with pytest.raises(U2ModelError, match="distinct"):
        fit_u2(constant, [f"row-{index}" for index in range(len(constant))])


def test_u2_fit_api_accepts_membership_only_not_labels() -> None:
    matrix = _matrix()
    with pytest.raises(U2ModelError, match="membership"):
        fit_u2(matrix, [{"row_key": "row-0", "label": 1} for _ in range(len(matrix))])


def test_u2_rejects_wrong_query_shape_and_nonfinite_scores() -> None:
    matrix = _matrix()
    bundle = fit_u2(matrix, [f"row-{index}" for index in range(len(matrix))])
    with pytest.raises(U2ModelError, match="feature dimension"):
        score_u2(bundle, np.zeros((2, 3), dtype=np.float64))
    bad_query = np.zeros((2, 4), dtype=np.float64)
    bad_query[0, 0] = np.inf
    with pytest.raises(U2ModelError, match="finite"):
        score_u2(bundle, bad_query)


def test_pilot_order_is_hash_ordered_and_label_free() -> None:
    row_keys = ["row-3", "row-1", "row-2"]
    first = pilot_order(row_keys, "UNSW_NB15_BENCHMARK")
    second = pilot_order(list(reversed(row_keys)), "UNSW_NB15_BENCHMARK")
    assert first == second
    assert sorted(first) == sorted(row_keys)
