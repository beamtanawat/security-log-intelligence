"""Leakage-safe CHAIN-S1 feature and model adapters for Stage 2.4C."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from supervised.models import fit_s1_classifier, fit_s2_classifier, predict_p_attack
from unsupervised.features import FeatureState, fit_features, transform_features

from .contracts import BASE_FEATURES, BRANCH_ID, CHAIN_S2_CONFIG, CHAIN_SCHEMA_VERSION, DATASET_ID, membership_sha256


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _base_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for row in rows:
        projected.append(
            {
                **{field: row.get(field) for field in BASE_FEATURES},
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": row.get("official_split", "TRAIN"),
                "development_partition": row.get("development_partition", "TRAIN_INTERNAL"),
                "row_number": row.get("row_number", "?"),
            }
        )
    return projected


def _validate_keys(rows: Sequence[Mapping[str, object]], signals: Mapping[str, Mapping[str, object]]) -> list[str]:
    keys = [str(row.get("row_key", "")) for row in rows]
    if not keys or any(not key for key in keys) or len(set(keys)) != len(keys):
        raise ValueError("signal rows require unique row keys")
    if set(keys) != {str(key) for key in signals}:
        raise ValueError("signal coverage does not match rows")
    return keys


def _signal_pair(key: str, value: Mapping[str, object]) -> tuple[float, float]:
    if set(value) != {"U1", "U2"}:
        if any(str(field).lower() in {"fallback", "imputed", "global", "in_sample"} for field in value):
            raise ValueError(f"fallback or imputed signal is forbidden for {key}")
        raise ValueError(f"signal schema mismatch for {key}")
    try:
        u1 = float(value["U1"])
        u2 = float(value["U2"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"signal values must be finite for {key}") from exc
    if not math.isfinite(u1) or not math.isfinite(u2) or u2 < 0:
        raise ValueError(f"signal values must be finite and U2 nonnegative for {key}")
    return u1, u2


@dataclass(frozen=True)
class SignalScaler:
    """Train-population-only standardization state for the two U signals."""

    dataset_id: str
    branch_id: str
    fit_membership_sha256: str
    fit_row_count: int
    u1_mean: float
    u1_scale: float
    u2_log1p_mean: float
    u2_log1p_scale: float
    input_signal_sha256: str
    state_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CHAIN_SCHEMA_VERSION,
            "dataset_id": self.dataset_id,
            "branch_id": self.branch_id,
            "fit_membership_sha256": self.fit_membership_sha256,
            "fit_row_count": self.fit_row_count,
            "u1_mean": self.u1_mean,
            "u1_scale": self.u1_scale,
            "u2_log1p_mean": self.u2_log1p_mean,
            "u2_log1p_scale": self.u2_log1p_scale,
            "input_signal_sha256": self.input_signal_sha256,
            "state_sha256": self.state_sha256,
            "fit_boundary": "OOF_SIGNAL_TRAINING_ROWS_ONLY",
        }


def fit_chain_base_state(rows: Sequence[Mapping[str, object]]) -> FeatureState:
    """Fit the frozen 28-feature preprocessing state on training rows only."""

    if not rows:
        raise ValueError("chain base fit rows cannot be empty")
    if any(row.get("development_partition") != "TRAIN_INTERNAL" for row in rows):
        raise ValueError("chain base preprocessing requires TRAIN_INTERNAL rows")
    return fit_features(_base_rows(rows), DATASET_ID)


def fit_signal_scaler(rows: Sequence[Mapping[str, object]], signals: Mapping[str, Mapping[str, object]]) -> SignalScaler:
    """Fit U1/U2 scaling exclusively from the supplied OOF training rows."""

    keys = _validate_keys(rows, signals)
    values = [_signal_pair(key, signals[key]) for key in keys]
    u1 = np.asarray([value[0] for value in values], dtype=np.float64)
    u2 = np.log1p(np.asarray([value[1] for value in values], dtype=np.float64))
    if not np.isfinite(u1).all() or not np.isfinite(u2).all():
        raise ValueError("signal values must be finite")
    u1_mean = float(np.mean(u1))
    u1_scale = float(np.std(u1, ddof=0)) or 1.0
    u2_mean = float(np.mean(u2))
    u2_scale = float(np.std(u2, ddof=0)) or 1.0
    payload = {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "fit_membership_sha256": membership_sha256(keys),
        "fit_row_count": len(keys),
        "u1_mean": u1_mean,
        "u1_scale": u1_scale,
        "u2_log1p_mean": u2_mean,
        "u2_log1p_scale": u2_scale,
        "input_signal_sha256": _sha256_bytes(_canonical_bytes([[key, values[index][0], values[index][1]] for index, key in enumerate(keys)])),
    }
    state_sha256 = _sha256_bytes(_canonical_bytes(payload))
    return SignalScaler(**payload, state_sha256=state_sha256)


def transform_chain_features(
    rows: Sequence[Mapping[str, object]],
    signals: Mapping[str, Mapping[str, object]],
    scaler: SignalScaler,
    base_state: FeatureState,
) -> np.ndarray:
    """Transform base fields and append exactly ``z_u1`` and ``z_log1p_u2``."""

    keys = _validate_keys(rows, signals)
    base = transform_features(_base_rows(rows), base_state)
    values = [_signal_pair(key, signals[key]) for key in keys]
    u1 = np.asarray([value[0] for value in values], dtype=np.float64)
    u2 = np.log1p(np.asarray([value[1] for value in values], dtype=np.float64))
    appended = np.column_stack(((u1 - scaler.u1_mean) / scaler.u1_scale, (u2 - scaler.u2_log1p_mean) / scaler.u2_log1p_scale))
    result = np.ascontiguousarray(np.column_stack((base, appended)), dtype=np.float64)
    if result.shape[1] > 514:
        raise ValueError("chained transformed feature count exceeds the approved bound")
    if not np.isfinite(result).all():
        raise ValueError("chained features must be finite")
    return result


def fit_chain_s1(X: object, y: object, *, context: str = "CHAIN-S1") -> tuple[Any, dict[str, Any]]:
    """Fit frozen CHAIN-S1 Logistic Regression with C=1.0 and no tuning."""

    matrix = np.asarray(X, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] < len(BASE_FEATURES) + 2:
        raise ValueError("CHAIN-S1 requires 28 base features plus U1/U2")
    estimator, report = fit_s1_classifier(matrix, y, 1.0, context=context)
    report = {**report, "model_id": "CHAIN-S1", "source_feature_count": len(BASE_FEATURES) + 2, "chain_specific_tuning": "NONE"}
    return estimator, report


def predict_chain_s1(estimator: Any, X: object) -> np.ndarray:
    """Return the verified probability of class ATTACK=1."""

    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise ValueError("CHAIN-S1 classes must be [0, 1]")
    return predict_p_attack(estimator, X)


def fit_chain_s2(X: object, y: object, *, context: str = "CHAIN-S2") -> tuple[Any, dict[str, Any]]:
    """Fit frozen CHAIN-S2 Random Forest with no candidate search or tuning."""

    matrix = np.asarray(X, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] < len(BASE_FEATURES) + 2:
        raise ValueError("CHAIN-S2 requires 28 base features plus U1/U2")
    estimator, report = fit_s2_classifier(matrix, y, context=context, pilot=False)
    report = {
        **report,
        "config": dict(CHAIN_S2_CONFIG),
        "model_id": "CHAIN-S2",
        "source_feature_count": len(BASE_FEATURES) + 2,
        "chain_specific_tuning": "NONE",
    }
    return estimator, report


def predict_chain_s2(estimator: Any, X: object) -> np.ndarray:
    """Return the verified probability of class ATTACK=1."""

    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise ValueError("CHAIN-S2 classes must be [0, 1]")
    return predict_p_attack(estimator, X)
