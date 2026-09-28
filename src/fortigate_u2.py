"""FortiGate-specific Stage 2.2C U2 scaling and comparison helpers."""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np
from scipy.stats import spearmanr
from sklearn.preprocessing import StandardScaler


class FortiGateU2Error(ValueError):
    """Raised when the frozen FortiGate U2 contract cannot be satisfied."""


def fit_reference_scaler(reference_matrix: np.ndarray) -> StandardScaler:
    """Fit StandardScaler on REFERENCE values only."""

    matrix = np.ascontiguousarray(np.asarray(reference_matrix, dtype=np.float64))
    if matrix.ndim != 2 or matrix.shape[0] == 0 or matrix.shape[1] == 0:
        raise FortiGateU2Error("REFERENCE matrix must be non-empty and two-dimensional")
    if not np.isfinite(matrix).all():
        raise FortiGateU2Error("REFERENCE matrix must contain finite values")
    scaler = StandardScaler()
    scaler.fit(matrix)
    if not np.isfinite(scaler.mean_).all() or not np.isfinite(scaler.scale_).all():
        raise FortiGateU2Error("REFERENCE scaler state is non-finite")
    return scaler


def _ordered_top(row_numbers: Sequence[int], scores: Sequence[float], count: int) -> set[int]:
    if len(row_numbers) != len(scores) or count < 1:
        raise FortiGateU2Error("top-list inputs are incompatible")
    pairs = [(int(number), float(score)) for number, score in zip(row_numbers, scores, strict=True)]
    if not all(math.isfinite(score) for _, score in pairs):
        raise FortiGateU2Error("comparison scores must be finite")
    return {number for number, _ in sorted(pairs, key=lambda item: (-item[1], item[0]))[: min(count, len(pairs))]}


def _jaccard(left: set[int], right: set[int]) -> float:
    union = left | right
    return 1.0 if not union else float(len(left & right) / len(union))


def _nearest_rank_99(values: Sequence[float]) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered or not all(math.isfinite(value) for value in ordered):
        raise FortiGateU2Error("REFERENCE scores must be finite and non-empty")
    rank = max(1, math.ceil(0.99 * len(ordered)))
    return ordered[rank - 1]


def compare_fortigate_scores(
    row_numbers: Sequence[int],
    u1_scores: Sequence[float],
    u2_scores: Sequence[float],
    *,
    reference_u1: Sequence[float],
    reference_u2: Sequence[float],
) -> dict[str, object]:
    """Compute only the plan-approved descriptive anomaly comparison."""

    if len(row_numbers) != len(u1_scores) or len(row_numbers) != len(u2_scores):
        raise FortiGateU2Error("comparison row and score counts must match")
    row_numbers = [int(value) for value in row_numbers]
    u1 = np.asarray(u1_scores, dtype=np.float64)
    u2 = np.asarray(u2_scores, dtype=np.float64)
    if not np.isfinite(u1).all() or not np.isfinite(u2).all():
        raise FortiGateU2Error("comparison scores must be finite")
    correlation = spearmanr(u1, u2)
    if not math.isfinite(float(correlation.statistic)):
        raise FortiGateU2Error("Spearman correlation is undefined")
    top_1_percent = max(1, math.ceil(0.01 * len(row_numbers)))
    holdout = {
        "row_count": len(row_numbers),
        "spearman_rank_correlation": float(correlation.statistic),
        "top_50_jaccard": _jaccard(_ordered_top(row_numbers, u1, 50), _ordered_top(row_numbers, u2, 50)),
        "top_100_jaccard": _jaccard(_ordered_top(row_numbers, u1, 100), _ordered_top(row_numbers, u2, 100)),
        "top_1_percent_jaccard": _jaccard(_ordered_top(row_numbers, u1, top_1_percent), _ordered_top(row_numbers, u2, top_1_percent)),
        "u1_alert_fraction": float(np.mean(u1 > _nearest_rank_99(reference_u1))),
        "u2_alert_fraction": float(np.mean(u2 > _nearest_rank_99(reference_u2))),
        "u1_reference_99th_nearest_rank": _nearest_rank_99(reference_u1),
        "u2_reference_99th_nearest_rank": _nearest_rank_99(reference_u2),
    }
    return {"holdout": holdout}


def score_top_residuals(
    matrix: np.ndarray,
    centers: np.ndarray,
    row_numbers: Sequence[int],
    feature_names: Sequence[str],
    *,
    top_rows: int = 50,
) -> list[dict[str, object]]:
    """Explain largest squared scaled-space residuals for top U2 rows."""

    values = np.ascontiguousarray(np.asarray(matrix, dtype=np.float64))
    center_values = np.ascontiguousarray(np.asarray(centers, dtype=np.float64))
    if values.ndim != 2 or center_values.ndim != 2 or values.shape[1] != center_values.shape[1]:
        raise FortiGateU2Error("residual matrices have incompatible dimensions")
    if len(row_numbers) != len(values) or len(feature_names) != values.shape[1]:
        raise FortiGateU2Error("residual provenance does not match matrices")
    explanations: list[dict[str, object]] = []
    for index, row_number in enumerate(row_numbers):
        residuals = np.square(values[index][None, :] - center_values)
        center_index = int(np.argmin(np.sum(residuals, axis=1)))
        contributions = residuals[center_index]
        order = sorted(range(len(feature_names)), key=lambda feature: (-float(contributions[feature]), feature))[:3]
        explanations.append({
            "source_record_number": int(row_number),
            "center_index": center_index,
            "raw_abnormality": float(np.sum(contributions)),
            "residuals": [
                {"feature": str(feature_names[feature]), "contribution": float(contributions[feature])}
                for feature in order
            ],
        })
    explanations.sort(key=lambda item: (-float(item["raw_abnormality"]), int(item["source_record_number"])))
    return explanations[: min(top_rows, len(explanations))]
