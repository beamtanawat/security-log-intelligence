"""Stage 2.2D thresholding and validation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


ALL_ANOMALY = "ALL_ANOMALY"
ALL_INLIER = "ALL_INLIER"
ThresholdValue = str | float


class EvaluationContractError(ValueError):
    """Raised when Stage 2.2D inputs violate the frozen contract."""


def _as_scores(values: Sequence[float]) -> np.ndarray:
    scores = np.asarray(values, dtype=np.float64)
    if scores.ndim != 1 or scores.size == 0 or not np.isfinite(scores).all():
        raise EvaluationContractError("scores must be a non-empty finite vector")
    return scores


def _as_labels(values: Sequence[int | str]) -> np.ndarray:
    labels = np.asarray([int(value) for value in values], dtype=np.int8)
    if labels.ndim != 1 or labels.size == 0 or not np.isin(labels, [0, 1]).all():
        raise EvaluationContractError("labels must be a non-empty binary vector")
    return labels


def _threshold_order(value: ThresholdValue) -> tuple[int, float]:
    if value == ALL_ANOMALY:
        return (0, 0.0)
    if value == ALL_INLIER:
        return (2, 0.0)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(float(value)):
        raise EvaluationContractError("threshold must be a finite number or approved sentinel")
    return (1, float(value))


def _f1_fraction(predicted: np.ndarray, labels: np.ndarray) -> tuple[int, int, tuple[int, int, int, int]]:
    tn, fp, fn, tp = [int(value) for value in confusion_matrix(labels, predicted, labels=[0, 1]).ravel()]
    return 2 * tp, 2 * tp + fp + fn, (tp, fp, tn, fn)


@dataclass(frozen=True)
class ThresholdPolicy:
    """A serialized threshold with the approved anomaly semantics."""

    threshold: ThresholdValue
    calibration_f1_numerator: int
    calibration_f1_denominator: int
    calibration_row_count: int

    def predict(self, scores: Sequence[float]) -> np.ndarray:
        values = _as_scores(scores)
        if self.threshold == ALL_ANOMALY:
            return np.ones(values.shape, dtype=bool)
        if self.threshold == ALL_INLIER:
            return np.zeros(values.shape, dtype=bool)
        return values >= float(self.threshold)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "stage_2.2d-threshold/1.0",
            "threshold": self.threshold,
            "prediction_rule": "ANOMALY_IF_SCORE_GREATER_OR_EQUAL_THRESHOLD",
            "calibration_f1_numerator": self.calibration_f1_numerator,
            "calibration_f1_denominator": self.calibration_f1_denominator,
            "calibration_row_count": self.calibration_row_count,
            "threshold_order": "ALL_ANOMALY<FINITE_NUMERIC<ALL_INLIER",
        }


def select_threshold(scores: Sequence[float], labels: Sequence[int | str]) -> ThresholdPolicy:
    """Select the exact approved F1-maximizing calibration threshold."""

    values = _as_scores(scores)
    truth = _as_labels(labels)
    if values.size != truth.size:
        raise EvaluationContractError("scores and labels must have equal length")
    if set(truth.tolist()) != {0, 1}:
        raise EvaluationContractError("threshold calibration requires both NORMAL and ATTACK")
    candidates: list[ThresholdValue] = [ALL_ANOMALY]
    candidates.extend(float(value) for value in sorted(set(values.tolist())))
    candidates.append(ALL_INLIER)
    best: tuple[int, int, tuple[int, float], ThresholdValue] | None = None
    for candidate in candidates:
        if candidate == ALL_ANOMALY:
            predicted = np.ones(values.shape, dtype=bool)
        elif candidate == ALL_INLIER:
            predicted = np.zeros(values.shape, dtype=bool)
        else:
            predicted = values >= float(candidate)
        numerator, denominator, _ = _f1_fraction(predicted, truth)
        ranking = (numerator, denominator, _threshold_order(candidate), candidate)
        if best is None:
            best = ranking
            continue
        best_num, best_den, best_order, _ = best
        left = numerator * best_den
        right = best_num * denominator
        if left > right or (left == right and _threshold_order(candidate) > best_order):
            best = ranking
    assert best is not None
    numerator, denominator, _, threshold = best
    return ThresholdPolicy(threshold, numerator, denominator, int(values.size))


def _safe_metric(value: float, *, reason: str | None = None) -> tuple[float | None, str | None]:
    if not isfinite(float(value)):
        return None, reason or "UNDEFINED"
    return float(value), reason


def evaluate_scores(
    scores: Sequence[float],
    labels: Sequence[int | str],
    threshold: ThresholdPolicy,
    *,
    conflict_mask: Sequence[bool] | None = None,
) -> dict[str, object]:
    """Evaluate one frozen threshold on one labeled validation population."""

    values = _as_scores(scores)
    truth = _as_labels(labels)
    if values.size != truth.size:
        raise EvaluationContractError("scores and labels must have equal length")
    if conflict_mask is None:
        conflicts = np.zeros(values.shape, dtype=bool)
    else:
        conflicts = np.asarray(conflict_mask, dtype=bool)
        if conflicts.shape != values.shape:
            raise EvaluationContractError("conflict mask must match score length")
    predicted = threshold.predict(values).astype(np.int8)
    tn, fp, fn, tp = [int(value) for value in confusion_matrix(truth, predicted, labels=[0, 1]).ravel()]
    conflict_truth = truth[conflicts]
    conflict_predicted = predicted[conflicts]
    if conflict_truth.size:
        ctn, cfp, cfn, ctp = [
            int(value) for value in confusion_matrix(conflict_truth, conflict_predicted, labels=[0, 1]).ravel()
        ]
    else:
        ctn = cfp = cfn = ctp = 0
    unique_labels = set(truth.tolist())
    if unique_labels == {0, 1}:
        roc_value, roc_reason = _safe_metric(roc_auc_score(truth, values))
        ap_value, ap_reason = _safe_metric(average_precision_score(truth, values))
        fpr, tpr, roc_thresholds = roc_curve(truth, values)
        precision_curve, recall_curve, pr_thresholds = precision_recall_curve(truth, values)
        roc_points = {
            "fpr": [float(value) for value in fpr],
            "tpr": [float(value) for value in tpr],
            "thresholds": [None if not np.isfinite(value) else float(value) for value in roc_thresholds],
        }
        pr_points = {
            "precision": [float(value) for value in precision_curve],
            "recall": [float(value) for value in recall_curve],
            "thresholds": [float(value) for value in pr_thresholds],
        }
    else:
        roc_value, roc_reason = None, "SINGLE_CLASS_LABELS"
        ap_value, ap_reason = None, "SINGLE_CLASS_LABELS"
        roc_points = pr_points = None
    accuracy_value, _ = _safe_metric(accuracy_score(truth, predicted))
    precision_value = None if tp + fp == 0 else float(precision_score(truth, predicted, zero_division=0))
    recall_value = None if tp + fn == 0 else float(recall_score(truth, predicted, zero_division=0))
    f1_value = None if 2 * tp + fp + fn == 0 else float(2 * tp / (2 * tp + fp + fn))
    return {
        "schema_version": "stage_2.2d-validation-metrics/1.0",
        "row_count": int(values.size),
        "threshold": threshold.threshold,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "accuracy": accuracy_value,
        "precision": precision_value,
        "recall": recall_value,
        "f1": f1_value,
        "roc_auc": roc_value,
        "roc_auc_reason": roc_reason,
        "pr_auc_ap": ap_value,
        "pr_auc_convention": "PR_AUC_AP",
        "pr_auc_reason": ap_reason,
        "predicted_anomaly_fraction": float(np.mean(predicted)),
        "conflict_rows": int(conflicts.sum()),
        "conflict_attack": int(conflict_truth.sum()),
        "conflict_normal": int(conflict_truth.size - conflict_truth.sum()),
        "conflict_tp": ctp,
        "conflict_fp": cfp,
        "conflict_tn": ctn,
        "conflict_fn": cfn,
        "conflict_error_count": cfp + cfn,
        "roc_points": roc_points,
        "pr_points": pr_points,
    }


def compare_validation_models(
    u1_ap: float,
    u2_ap: float,
    u1_runtime_seconds: float,
    u2_runtime_seconds: float,
) -> dict[str, object]:
    """Apply the frozen AP, runtime, then U1 tie-breaking rule."""

    if not all(isfinite(float(value)) for value in (u1_ap, u2_ap, u1_runtime_seconds, u2_runtime_seconds)):
        raise EvaluationContractError("comparison inputs must be finite")
    difference = float(u2_ap - u1_ap)
    if difference > 1e-6:
        selected = "U2"
        reason = "U2_AP_HIGHER_BY_MORE_THAN_1E-6"
    elif difference < -1e-6:
        selected = "U1"
        reason = "U1_AP_HIGHER_BY_MORE_THAN_1E-6"
    else:
        u1_ms = int(round(float(u1_runtime_seconds) * 1000.0))
        u2_ms = int(round(float(u2_runtime_seconds) * 1000.0))
        if u2_ms < u1_ms:
            selected = "U2"
            reason = "AP_TIE_RUNTIME_MILLISECONDS_LOWER"
        else:
            selected = "U1"
            reason = "AP_TIE_RUNTIME_TIE_OR_U1_LOWER"
    return {
        "schema_version": "stage_2.2d-model-comparison/1.0",
        "primary_metric": "AVERAGE_PRECISION",
        "u1_ap": float(u1_ap),
        "u2_ap": float(u2_ap),
        "ap_difference_u2_minus_u1": difference,
        "ap_tolerance": 1e-6,
        "u1_runtime_seconds": float(u1_runtime_seconds),
        "u2_runtime_seconds": float(u2_runtime_seconds),
        "u1_runtime_milliseconds_rounded": int(round(float(u1_runtime_seconds) * 1000.0)),
        "u2_runtime_milliseconds_rounded": int(round(float(u2_runtime_seconds) * 1000.0)),
        "selected_model": selected,
        "selection_reason": reason,
        "keep_both_models": True,
    }
