"""Leakage-safe Stage 2.4B U1/U2 signal generation and audits."""

from __future__ import annotations

import math
import pickle
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from threadpoolctl import threadpool_limits

from unsupervised.features import FeatureState, fit_features, transform_features
from unsupervised.models import U2Config, U2ModelBundle, fit_u2, score_u2

from .contracts import (
    BASE_FEATURES,
    BRANCH_ID,
    CHAIN_SCHEMA_VERSION,
    DATASET_ID,
    SCORE_DIRECTION,
    U1_CONFIG,
    U1_SIGNAL_FIELD,
    U2_CONFIG,
    U2_SIGNAL_FIELD,
    membership_sha256,
)


class SignalBlocker(ValueError):
    """Raised when a signal fit or artifact fails its frozen contract."""


def _as_matrix(values: object, *, name: str, allow_empty: bool = False) -> np.ndarray:
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] == 0 or (not allow_empty and matrix.shape[0] == 0):
        raise SignalBlocker(f"{name} must be a non-empty two-dimensional matrix")
    if not np.isfinite(matrix).all():
        raise SignalBlocker(f"{name} must contain finite values")
    return np.ascontiguousarray(matrix, dtype=np.float64)


def score_u1(model: IsolationForest, X_query: object) -> np.ndarray:
    """Return negative ``score_samples`` with higher values more anomalous."""

    matrix = _as_matrix(X_query, name="X_query", allow_empty=True)
    if matrix.shape[0] == 0:
        return np.empty(0, dtype=np.float64)
    with threadpool_limits(limits=1):
        scores = -np.asarray(model.score_samples(matrix), dtype=np.float64)
    if scores.shape != (matrix.shape[0],) or not np.isfinite(scores).all():
        raise SignalBlocker("U1 produced invalid anomaly scores")
    return np.ascontiguousarray(scores, dtype=np.float64)


def nearest_centroid_squared_distance(X_query: object, centers: object) -> np.ndarray:
    """Return exact nearest-centroid squared Euclidean distance."""

    matrix = _as_matrix(X_query, name="X_query", allow_empty=True)
    center_matrix = _as_matrix(centers, name="centers")
    if matrix.shape[1] != center_matrix.shape[1]:
        raise SignalBlocker("U2 query and centroid feature dimensions differ")
    if matrix.shape[0] == 0:
        return np.empty(0, dtype=np.float64)
    values = np.empty(matrix.shape[0], dtype=np.float64)
    for start in range(0, matrix.shape[0], 4096):
        stop = min(start + 4096, matrix.shape[0])
        distances = matrix[start:stop, None, :] - center_matrix[None, :, :]
        values[start:stop] = np.min(np.sum(np.square(distances), axis=2), axis=1)
    if not np.isfinite(values).all() or np.any(values < 0):
        raise SignalBlocker("U2 produced invalid anomaly scores")
    return values


def _feature_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row in rows:
        if {"label", "attack_cat", "target", "binary_target"} & set(row):
            # Full source rows may contain labels.  They are stripped below;
            # this check protects the fitted feature boundary, not the source.
            pass
        feature_row = {field: row.get(field) for field in BASE_FEATURES}
        feature_row.update(
            {
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": "TRAIN",
                "development_partition": "TRAIN_INTERNAL",
                "row_number": row.get("row_number", "?"),
            }
        )
        if {"label", "attack_cat", "target", "binary_target"} & set(feature_row):
            raise SignalBlocker("labels entered anomaly feature rows")
        output.append(feature_row)
    return output


def feature_state_from_dict(payload: Mapping[str, object]) -> FeatureState:
    """Restore a frozen Stage 2.2 feature state for a validated resume."""

    try:
        return FeatureState(
            dataset_id=str(payload["dataset_id"]),
            branch_id=str(payload["branch_id"]),
            feature_order=tuple(str(value) for value in payload["feature_order"]),
            numeric_medians={str(key): float(value) for key, value in dict(payload["numeric_medians"]).items()},
            numeric_means={str(key): float(value) for key, value in dict(payload["numeric_means"]).items()},
            numeric_scales={str(key): float(value) for key, value in dict(payload["numeric_scales"]).items()},
            categorical_vocabularies={
                str(key): tuple(str(value) for value in values)
                for key, values in dict(payload["categorical_vocabularies"]).items()
            },
            output_feature_names=tuple(str(value) for value in payload["output_feature_names"]),
            fit_row_count=int(payload["fit_row_count"]),
            state_sha256=str(payload["state_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SignalBlocker("invalid preprocessing state artifact") from exc


def _fit_u1(X_fit: np.ndarray, membership: Sequence[str]) -> IsolationForest:
    if X_fit.shape[0] < 4096 or np.unique(X_fit, axis=0).shape[0] < 32:
        raise SignalBlocker("U1 fit minimum rows/distinct vectors gate failed")
    model = IsolationForest(**U1_CONFIG)
    with threadpool_limits(limits=1):
        model.fit(X_fit)
    return model


def _fit_u2(X_fit: np.ndarray, membership: Sequence[str]) -> U2ModelBundle:
    if X_fit.shape[0] < 4096 or np.unique(X_fit, axis=0).shape[0] < 32:
        raise SignalBlocker("U2 fit minimum rows/distinct vectors gate failed")
    return fit_u2(X_fit, membership, U2Config(**U2_CONFIG))


def _score_u2(bundle: U2ModelBundle, X_query: np.ndarray) -> np.ndarray:
    if X_query.shape[0] == 0:
        return np.empty(0, dtype=np.float64)
    scores = score_u2(bundle, X_query)
    if not np.isfinite(scores).all() or np.any(scores < 0):
        raise SignalBlocker("U2 produced invalid anomaly scores")
    return np.ascontiguousarray(scores, dtype=np.float64)


def _model_version(model_id: str) -> str:
    return "stage_2.4b-u1/1.0" if model_id == "U1" else "stage_2.4b-u2/1.0"


def _model_family(model_id: str) -> str:
    return "ISOLATION_FOREST" if model_id == "U1" else "MINIBATCHKMEANS_DISTANCE_SCORER"


def _build_records(
    *,
    rows_by_key: Mapping[str, Mapping[str, object]],
    context: Mapping[str, object],
    model_id: str,
    scores: Sequence[float],
    artifact_identity: str,
) -> list[dict[str, object]]:
    score_keys = [str(value) for value in context["score_row_keys"]]
    if len(score_keys) != len(scores):
        raise SignalBlocker("score and row coverage lengths differ")
    signal_role = {
        "INNER_SIGNAL": "OOF_TRAINING",
        "OUTER_INFERENCE": "OUTER_HELDOUT_OOF",
        "FINAL_INFERENCE": "INFERENCE_STATE",
    }[str(context["kind"])]
    signal_field = U1_SIGNAL_FIELD if model_id == "U1" else U2_SIGNAL_FIELD
    fit_groups = [str(value) for value in context["fit_group_ids"]]
    fit_group_fingerprint = membership_sha256(fit_groups)
    records: list[dict[str, object]] = []
    for row_key, value in zip(score_keys, scores, strict=True):
        row = rows_by_key[row_key]
        records.append(
            {
                "schema_version": CHAIN_SCHEMA_VERSION,
                "row_key": row_key,
                "group_id": str(row["group_id"]),
                "outer_fold": context["outer_fold"],
                "inner_fold": context["inner_fold"],
                "context_id": context["context_id"],
                "signal_role": signal_role,
                "signal_field": signal_field,
                "model_id": model_id,
                "model_family": _model_family(model_id),
                "model_version": _model_version(model_id),
                "fit_membership_sha256": context["fit_membership_sha256"],
                "score_membership_sha256": context["score_membership_sha256"],
                "fit_group_fingerprint": fit_group_fingerprint,
                "preprocessing_identity": context.get("preprocessing_identity", "FEATURE_STATE_BOUND_TO_FIT_MEMBERSHIP"),
                "score": float(value),
                "score_direction": SCORE_DIRECTION,
                "artifact_identity": artifact_identity,
                "label_free_fit": True,
                "labels_used": False,
                "attack_cat_used": False,
                "test_used": False,
            }
        )
    return records


def audit_signal_artifact(
    records: Sequence[Mapping[str, object]],
    context: Mapping[str, object],
    model_id: str,
) -> dict[str, Any]:
    """Validate signal coverage, provenance, direction, and exclusions."""

    if model_id not in {"U1", "U2"}:
        raise SignalBlocker("unsupported anomaly signal model")
    expected = [str(value) for value in context.get("score_row_keys", [])]
    expected_set = set(expected)
    seen: set[str] = set()
    required = {
        "row_key",
        "group_id",
        "context_id",
        "model_id",
        "model_version",
        "fit_membership_sha256",
        "score_membership_sha256",
        "fit_group_fingerprint",
        "preprocessing_identity",
        "signal_role",
        "artifact_identity",
        "score",
        "score_direction",
        "label_free_fit",
        "labels_used",
        "attack_cat_used",
        "test_used",
    }
    context_fit_groups = {str(value) for value in context.get("fit_group_ids", [])}
    expected_fit_group_fingerprint = membership_sha256([str(value) for value in context.get("fit_group_ids", [])])
    expected_fit_hash = str(context.get("fit_membership_sha256"))
    expected_score_hash = str(context.get("score_membership_sha256"))
    expected_context_id = str(context.get("context_id"))
    for record in records:
        if seen and str(record.get("row_key")) in seen:
            raise SignalBlocker("duplicate signal assignment")
        missing = required - set(record)
        if missing:
            raise SignalBlocker(f"signal provenance missing: {sorted(missing)}")
        forbidden = {"label", "attack_cat", "target", "binary_target", "p_attack", "predicted_label"} & set(record)
        if forbidden:
            raise SignalBlocker("label or attack prediction entered signal artifact")
        key = str(record["row_key"])
        group_id = str(record["group_id"])
        if key not in expected_set:
            raise SignalBlocker("signal coverage contains unexpected row")
        if str(record["context_id"]) != expected_context_id or str(record["model_id"]) != model_id:
            raise SignalBlocker("signal context/model identity mismatch")
        if str(record["fit_membership_sha256"]) != expected_fit_hash or str(record["score_membership_sha256"]) != expected_score_hash:
            raise SignalBlocker("signal partition identity mismatch")
        record_fit_groups_value = record.get("fit_group_ids")
        record_fit_groups = (
            {str(value) for value in record_fit_groups_value}
            if record_fit_groups_value is not None
            else context_fit_groups
        )
        if group_id in record_fit_groups or group_id in context_fit_groups:
            raise SignalBlocker("same-group fit/signal overlap")
        if str(record["fit_group_fingerprint"]) != expected_fit_group_fingerprint:
            raise SignalBlocker("fit group fingerprint mismatch")
        if record["labels_used"] is not False or record["attack_cat_used"] is not False:
            raise SignalBlocker("labels used in anomaly fit")
        if record["label_free_fit"] is not True or record["test_used"] is not False:
            raise SignalBlocker("signal provenance policy failed")
        if str(record["score_direction"]) != SCORE_DIRECTION:
            raise SignalBlocker("score direction mismatch")
        score = float(record["score"])
        if not math.isfinite(score) or (model_id == "U2" and score < 0):
            raise SignalBlocker("invalid finite signal score")
        seen.add(key)
    if seen != set(expected):
        raise SignalBlocker("signal coverage incomplete")
    return {
        "status": "PASS",
        "model_id": model_id,
        "context_id": expected_context_id,
        "score_row_count": len(seen),
        "same_row_overlap": 0,
        "same_group_overlap": 0,
        "fit_signal_group_overlap": 0,
        "labels_used": False,
        "attack_cat_used": False,
        "test_used": False,
    }


def fit_score_signals(
    rows: Sequence[Mapping[str, object]],
    fit_keys: frozenset[str],
    score_keys: frozenset[str],
    context: Mapping[str, object],
) -> dict[str, Any]:
    """Fit U1/U2 on fit keys and score only held-out keys.

    No target or attack category is copied into feature rows.  This function
    returns in-memory artifacts; the runner persists them only after audits.
    """

    row_by_key = {str(row["row_key"]): row for row in rows}
    if len(row_by_key) != len(rows):
        raise SignalBlocker("source rows must have unique row keys")
    expected_fit = {str(value) for value in context["fit_row_keys"]}
    expected_score = {str(value) for value in context["score_row_keys"]}
    if set(fit_keys) != expected_fit or set(score_keys) != expected_score:
        raise SignalBlocker("fit/score keys differ from frozen context")
    if set(fit_keys) & set(score_keys):
        raise SignalBlocker("same-row fit/signal overlap")
    fit_rows = [row_by_key[key] for key in context["fit_row_keys"]]
    score_rows = [row_by_key[key] for key in context["score_row_keys"]]
    fit_groups = {str(row["group_id"]) for row in fit_rows}
    score_groups = {str(row["group_id"]) for row in score_rows}
    if fit_groups & score_groups:
        raise SignalBlocker("same-group fit/signal overlap")
    feature_fit_rows = _feature_rows(fit_rows)
    feature_score_rows = _feature_rows(score_rows)
    state = fit_features(feature_fit_rows, DATASET_ID)
    X_fit = transform_features(feature_fit_rows, state)
    X_score = transform_features(feature_score_rows, state) if score_rows else np.empty((0, X_fit.shape[1]), dtype=np.float64)
    fit_membership = [str(row["row_key"]) for row in fit_rows]
    u1_model = _fit_u1(X_fit, fit_membership)
    u1_scores = score_u1(u1_model, X_score)
    u1_replay = score_u1(pickle.loads(pickle.dumps(u1_model, protocol=pickle.HIGHEST_PROTOCOL)), X_score)
    if not np.allclose(u1_scores, u1_replay, rtol=1e-12, atol=1e-12):
        raise SignalBlocker("U1 deterministic replay mismatch")
    u2_model = _fit_u2(X_fit, fit_membership)
    u2_scores = _score_u2(u2_model, X_score)
    u2_replay = _score_u2(pickle.loads(pickle.dumps(u2_model, protocol=pickle.HIGHEST_PROTOCOL)), X_score)
    if not np.allclose(u2_scores, u2_replay, rtol=1e-12, atol=1e-12):
        raise SignalBlocker("U2 deterministic replay mismatch")
    metadata = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "context_id": context["context_id"],
        "fit_membership_sha256": context["fit_membership_sha256"],
        "score_membership_sha256": context["score_membership_sha256"],
        "fit_group_fingerprint": membership_sha256(list(context["fit_group_ids"])),
        "fit_row_count": len(fit_rows),
        "score_row_count": len(score_rows),
        "preprocessing_state_sha256": state.state_sha256,
        "feature_count": int(X_fit.shape[1]),
        "score_direction": SCORE_DIRECTION,
        "labels_used": False,
        "attack_cat_used": False,
        "test_used": False,
        "deterministic_replay": "PASS",
        "same_row_overlap": 0,
        "same_group_overlap": 0,
    }
    return {
        "U1": {"model": u1_model, "scores": u1_scores, "metadata": {**metadata, "model_id": "U1", "model_family": _model_family("U1"), "model_version": _model_version("U1"), "config": dict(U1_CONFIG)}},
        "U2": {"model": u2_model, "scores": u2_scores, "metadata": {**metadata, "model_id": "U2", "model_family": _model_family("U2"), "model_version": _model_version("U2"), "config": dict(U2_CONFIG)}},
        "feature_state": state,
        "rows_by_key": row_by_key,
    }


build_signal_records = _build_records
