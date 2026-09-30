"""Stage 2.3D validation metrics and deterministic pre-TEST selection rules."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


FIXED_THRESHOLD = 0.5
SELECTION_TOLERANCE = 1e-6


def evaluate_probabilities(y_true: object, p_attack: object, *, threshold: float = FIXED_THRESHOLD) -> dict[str, Any]:
    """Evaluate official binary labels with the frozen 0.5 ATTACK threshold."""

    if float(threshold) != FIXED_THRESHOLD:
        raise ValueError("Stage 2.3 threshold is fixed at 0.5")
    labels = np.asarray(y_true, dtype=np.int8)
    scores = np.asarray(p_attack, dtype=np.float64)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape or labels.size == 0:
        raise ValueError("labels and p_attack must be non-empty one-dimensional arrays with equal shape")
    if set(labels.tolist()) - {0, 1}:
        raise ValueError("labels must use NORMAL=0 and ATTACK=1")
    if not np.isfinite(scores).all() or not np.all((scores >= 0.0) & (scores <= 1.0)):
        raise ValueError("p_attack must be finite and within [0, 1]")
    predicted = (scores >= FIXED_THRESHOLD).astype(np.int8)
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    both_classes = set(labels.tolist()) == {0, 1}
    return {
        "row_count": int(labels.size),
        "positive_class": 1,
        "threshold": FIXED_THRESHOLD,
        "average_precision": float(average_precision_score(labels, scores)) if both_classes else None,
        "roc_auc": float(roc_auc_score(labels, scores)) if both_classes else None,
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "undefined_metric_reason": None if both_classes else "ONE_CLASS_LABELS",
    }


def select_preferred_model(validation_ap: Mapping[str, float]) -> str:
    """Prefer larger comparison AP; ties within 1e-6 prefer simpler S1."""

    if set(validation_ap) != {"S1", "S2"}:
        raise ValueError("validation AP must contain exactly S1 and S2")
    s1 = float(validation_ap["S1"])
    s2 = float(validation_ap["S2"])
    if not np.isfinite([s1, s2]).all():
        raise ValueError("validation AP must be finite")
    return "S1" if s2 <= s1 + SELECTION_TOLERANCE else "S2"


def validate_selection_lock(lock: Mapping[str, object]) -> bool:
    """Validate development lock safety before any separately authorized TEST run."""

    if lock.get("test_used") is not False:
        raise ValueError("selection lock must record TEST=false")
    if lock.get("chained_signals_used") is not False:
        raise ValueError("selection lock must record chained signals=false")
    thresholds = lock.get("thresholds")
    if not isinstance(thresholds, Mapping) or set(thresholds) != {"S1", "S2"} or any(float(value) != FIXED_THRESHOLD for value in thresholds.values()):
        raise ValueError("selection lock must freeze threshold 0.5 for S1 and S2")
    return True
