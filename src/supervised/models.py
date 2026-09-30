"""Stage 2.3A preprocessing adapter; classifier fitting is intentionally absent."""

from __future__ import annotations

import hashlib
import json
import platform
import resource
import subprocess
import time
import warnings
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from threadpoolctl import threadpool_limits

from unsupervised.features import FeatureContractError, FeatureState, fit_features, transform_features

from .contracts import BRANCH_ID, DATASET_ID, FEATURE_ORDER, SupervisedContractError, select_base_features, validate_development_rows


S1_CANDIDATES = (0.1, 1.0)
S1_THRESHOLD = 0.5
S1_MAX_ITER = 1000
S1_RANDOM_STATE = 1729

# Frozen single-candidate S2 recipe from Stage 2.3C. Keep insertion order
# stable because manifests serialize this mapping as the public configuration.
S2_CONFIG: dict[str, object] = {
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
S2_THRESHOLD = 0.5
S2_MAX_FITS = 6
S2_PILOT_MAX_SECONDS = 120.0
S2_FIT_MAX_SECONDS = 600.0
S2_PREDICT_MAX_SECONDS = 300.0
S2_RSS_CEILING_BYTES = 4 * 1024**3


class S1FitError(SupervisedContractError):
    """Raised when an approved S1 fit is ineligible."""


class S2FitError(SupervisedContractError):
    """Raised when an approved S2 capability gate fails."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _membership_hash(row_keys: Sequence[str]) -> str:
    return hashlib.sha256(_json_bytes(list(row_keys))).hexdigest()


def _feature_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row in rows:
        output.append(
            {
                **select_base_features(row),
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": "TRAIN",
                "development_partition": "TRAIN_INTERNAL",
                "row_number": row.get("row_number", "?"),
            }
        )
    return output


def fit_pipeline(
    rows: Sequence[Mapping[str, object]],
    fit_row_keys: frozenset[str],
    model_id: str,
    parameters: Mapping[str, object],
    *,
    all_rows: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, Any]:
    """Fit only a fold-local feature state; no classifier is fit in 2.3A."""

    if model_id not in {"S1", "S2"}:
        raise SupervisedContractError("unsupported supervised model id")
    validate_development_rows(rows)
    row_keys = [str(row["row_key"]) for row in rows]
    if len(set(row_keys)) != len(row_keys) or set(row_keys) != set(fit_row_keys):
        raise SupervisedContractError("fit-row membership must match rows exactly")
    groups = {str(row["group_id"]) for row in rows}
    if all_rows is not None:
        selected = {str(row["row_key"]) for row in rows}
        for row in all_rows:
            if str(row["group_id"]) in groups and str(row["row_key"]) not in selected:
                raise SupervisedContractError("fit membership would split a predictive group")
    try:
        state = fit_features(_feature_rows(rows), DATASET_ID)
    except FeatureContractError as exc:
        raise SupervisedContractError(str(exc)) from exc
    return {
        "schema_version": "stage_2.3-pipeline-bundle/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model_id": model_id,
        "parameters": dict(parameters),
        "feature_state": state,
        "fit_membership_sha256": _membership_hash(row_keys),
        "fit_row_keys": tuple(row_keys),
        "classes": (0, 1),
        "classifier_fitted": False,
        "estimator": None,
    }


def transform_pipeline(bundle: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> np.ndarray:
    """Transform rows with a previously fitted fold-local feature state."""

    state = bundle.get("feature_state")
    if not isinstance(state, FeatureState):
        raise SupervisedContractError("pipeline bundle has no feature state")
    validate_development_rows(rows)
    return transform_features(_feature_rows(rows), state)


def prepare_xy(bundle: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> tuple[np.ndarray, np.ndarray, tuple[str, ...]]:
    """Return aligned features, official labels and unique row keys."""

    keys = tuple(str(row["row_key"]) for row in rows)
    if len(set(keys)) != len(keys):
        raise SupervisedContractError("one-to-one X/y row-key alignment required")
    values = transform_pipeline(bundle, rows)
    labels = np.asarray([int(str(row["label"]).strip()) for row in rows], dtype=np.int8)
    if values.shape[0] != labels.shape[0]:
        raise SupervisedContractError("one-to-one X/y row-key alignment required")
    return values, labels, keys


def build_s1_estimator(C: float) -> LogisticRegression:
    """Build the exact approved S1 Logistic Regression recipe."""

    if C not in S1_CANDIDATES:
        raise S1FitError(f"unsupported S1 C candidate: {C}")
    return LogisticRegression(
        C=float(C),
        solver="lbfgs",
        l1_ratio=0.0,
        dual=False,
        tol=1e-4,
        max_iter=S1_MAX_ITER,
        fit_intercept=True,
        class_weight=None,
        random_state=S1_RANDOM_STATE,
        warm_start=False,
        verbose=0,
    )


def build_s2_estimator() -> RandomForestClassifier:
    """Build the one approved Stage 2.3C Random Forest candidate."""

    return RandomForestClassifier(**S2_CONFIG)


def _physical_memory_bytes() -> int | None:
    """Return physical memory when the host exposes it, else None."""

    if platform.system() == "Darwin":
        try:
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, stderr=subprocess.DEVNULL).strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    try:
        return int(subprocess.check_output(["getconf", "_PHYS_PAGES"], text=True).strip()) * int(
            subprocess.check_output(["getconf", "PAGE_SIZE"], text=True).strip()
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if platform.system() == "Darwin" else value * 1024


def validate_s2_resource(*, elapsed_seconds: float, peak_rss_bytes: int, pilot: bool) -> bool:
    """Return whether one S2 fit stays within the frozen time/RSS budget."""

    if not np.isfinite(float(elapsed_seconds)) or elapsed_seconds < 0:
        return False
    limit = S2_PILOT_MAX_SECONDS if pilot else S2_FIT_MAX_SECONDS
    if elapsed_seconds > limit or peak_rss_bytes < 0:
        return False
    physical = _physical_memory_bytes()
    ceiling = min(S2_RSS_CEILING_BYTES, physical // 2) if physical else S2_RSS_CEILING_BYTES
    return peak_rss_bytes <= ceiling


def fit_s2_classifier(
    X: object,
    y: object,
    *,
    context: str,
    pilot: bool,
) -> tuple[RandomForestClassifier, dict[str, Any]]:
    """Fit one frozen RF candidate under one-fit/thread/resource limits."""

    try:
        matrix = _as_matrix(X, "X")
    except S1FitError as exc:
        raise S2FitError(str(exc)) from exc
    labels = np.asarray(y, dtype=np.int8)
    if labels.ndim != 1 or labels.shape[0] != matrix.shape[0] or set(labels.tolist()) != {0, 1}:
        raise S2FitError("S2 fit requires aligned rows with both classes")
    estimator = build_s2_estimator()
    started = time.monotonic()
    try:
        with threadpool_limits(limits=1):
            estimator.fit(matrix, labels)
    except Exception as exc:
        raise S2FitError(f"S2 fit failed in {context}: {exc}") from exc
    elapsed = time.monotonic() - started
    peak_rss = _peak_rss_bytes()
    if not np.array_equal(np.asarray(estimator.classes_), np.asarray([0, 1])):
        raise S2FitError("S2 classifier class ordering is not [0, 1]")
    resource_pass = validate_s2_resource(elapsed_seconds=elapsed, peak_rss_bytes=peak_rss, pilot=pilot)
    report = {
        "context": context,
        "model": "S2_RANDOM_FOREST",
        "config": dict(S2_CONFIG),
        "pilot": bool(pilot),
        "status": "PASS" if resource_pass else "BLOCKED_RESOURCE",
        "classes": [int(value) for value in estimator.classes_],
        "elapsed_seconds": float(elapsed),
        "peak_rss_bytes": int(peak_rss),
        "resource_gate": "PASS" if resource_pass else "FAIL",
    }
    if not resource_pass:
        raise S2FitError(f"S2 resource gate failed in {context}")
    return estimator, report


def _as_matrix(values: object, name: str) -> np.ndarray:
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[0] == 0 or matrix.shape[1] == 0:
        raise S1FitError(f"{name} must be a non-empty two-dimensional matrix")
    if not np.isfinite(matrix).all():
        raise S1FitError(f"{name} must contain only finite values")
    return np.ascontiguousarray(matrix, dtype=np.float64)


def fit_s1_classifier(X: object, y: object, C: float, *, context: str = "S1") -> tuple[LogisticRegression, dict[str, Any]]:
    """Fit one approved S1 candidate and reject convergence warnings."""

    matrix = _as_matrix(X, "X")
    labels = np.asarray(y, dtype=np.int8)
    if labels.ndim != 1 or labels.shape[0] != matrix.shape[0] or set(labels.tolist()) != {0, 1}:
        raise S1FitError("S1 fit requires aligned rows with both classes")
    estimator = build_s1_estimator(C)
    started = time.monotonic()
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        with threadpool_limits(limits=1):
            estimator.fit(matrix, labels)
    elapsed = time.monotonic() - started
    convergence_warnings = [str(item.message) for item in captured if issubclass(item.category, ConvergenceWarning)]
    if convergence_warnings:
        raise S1FitError(f"S1 convergence warning in {context}: {convergence_warnings[0]}")
    if not np.array_equal(np.asarray(estimator.classes_), np.asarray([0, 1])):
        raise S1FitError("S1 classifier class ordering is not [0, 1]")
    return estimator, {
        "context": context,
        "C": float(C),
        "status": "PASS",
        "convergence": "PASS",
        "elapsed_seconds": elapsed,
        "classes": [int(value) for value in estimator.classes_],
        "max_iter": S1_MAX_ITER,
    }


def predict_p_attack(estimator: LogisticRegression, X: object) -> np.ndarray:
    """Extract probability for the verified ATTACK=1 class."""

    matrix = _as_matrix(X, "X")
    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise S1FitError("S1 classifier class ordering is not [0, 1]")
    with threadpool_limits(limits=1):
        probabilities = np.asarray(estimator.predict_proba(matrix), dtype=np.float64)
    if probabilities.ndim != 2 or probabilities.shape != (matrix.shape[0], 2):
        raise S1FitError("S1 probability output shape is invalid")
    p_attack = probabilities[:, int(np.flatnonzero(classes == 1)[0])]
    if not np.isfinite(p_attack).all() or not np.all((p_attack >= 0.0) & (p_attack <= 1.0)):
        raise S1FitError("S1 probability output is not finite in [0, 1]")
    return np.ascontiguousarray(p_attack, dtype=np.float64)


def evaluate_s1_predictions(y_true: object, p_attack: object, *, threshold: float = S1_THRESHOLD) -> dict[str, Any]:
    """Evaluate fixed-threshold S1 outputs with AP as the primary metric."""

    labels = np.asarray(y_true, dtype=np.int8)
    scores = np.asarray(p_attack, dtype=np.float64)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape:
        raise S1FitError("S1 labels and probabilities must be one-dimensional and aligned")
    if not np.isfinite(scores).all() or not np.all((scores >= 0.0) & (scores <= 1.0)):
        raise S1FitError("S1 probabilities must be finite in [0, 1]")
    predicted = (scores >= threshold).astype(np.int8)
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    both_classes = set(labels.tolist()) == {0, 1}
    return {
        "row_count": int(labels.shape[0]),
        "positive_class": 1,
        "threshold": float(threshold),
        "average_precision": float(average_precision_score(labels, scores)) if both_classes else None,
        "roc_auc": float(roc_auc_score(labels, scores)) if both_classes else None,
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "undefined_metric_reason": None if both_classes else "ONE_CLASS_LABELS",
    }


def select_s1_candidate(candidate_ap: Mapping[float, Sequence[float]]) -> float:
    """Select largest mean AP; ties within 1e-6 choose smaller C."""

    if set(candidate_ap) != set(S1_CANDIDATES):
        raise S1FitError("both approved S1 C candidates are required")
    means: dict[float, float] = {}
    for C in S1_CANDIDATES:
        values = tuple(float(value) for value in candidate_ap[C])
        if not values or not np.isfinite(values).all():
            raise S1FitError("S1 candidate AP values must be finite")
        means[C] = float(np.mean(values))
    best = S1_CANDIDATES[0]
    for candidate in S1_CANDIDATES[1:]:
        if means[candidate] > means[best] + 1e-6:
            best = candidate
    return float(best)


def _row_keys(rows: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    return tuple(str(row["row_key"]) for row in rows)


def _pilot_prefix(rows: Sequence[Mapping[str, object]], limit: int = 20_000) -> list[Mapping[str, object]]:
    """Select the approved deterministic whole-group prefix for the S1 pilot."""

    grouped: dict[str, list[Mapping[str, object]]] = {}
    ordered_groups: list[str] = []
    for row in rows:
        group_id = str(row["group_id"])
        if group_id not in grouped:
            grouped[group_id] = []
            ordered_groups.append(group_id)
        grouped[group_id].append(row)
    selected: list[Mapping[str, object]] = []
    count = 0
    for group_id in ordered_groups:
        group_rows = grouped[group_id]
        if count + len(group_rows) > limit:
            break
        selected.extend(group_rows)
        count += len(group_rows)
    if count < 4096 or {str(row["label"]).strip() for row in selected} != {"0", "1"}:
        raise S1FitError("S1 pilot cannot satisfy minimum rows and class support")
    return selected


def run_nested_s1(
    rows: Sequence[Mapping[str, object]],
    folds: Sequence[Mapping[str, object]],
    *,
    validation_rows_by_partition: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
) -> dict[str, Any]:
    """Run the bounded, group-safe S1 nested development procedure."""

    validate_development_rows(rows)
    if any(row.get("development_partition") != "TRAIN_INTERNAL" for row in rows):
        raise S1FitError("S1 nested CV requires TRAIN_INTERNAL rows only")
    fold_by_key = {str(item["row_key"]): item for item in folds}
    if set(fold_by_key) != set(_row_keys(rows)):
        raise S1FitError("S1 fold manifest does not cover TRAIN_INTERNAL exactly")

    feature_cache: dict[tuple[str, ...], dict[str, Any]] = {}
    xy_cache: dict[tuple[str, ...], tuple[np.ndarray, np.ndarray, tuple[str, ...]]] = {}
    model_cache: dict[tuple[tuple[str, ...], float], tuple[Any, dict[str, Any]]] = {}
    fit_log: list[dict[str, Any]] = []

    def get_bundle(fit_rows: Sequence[Mapping[str, object]], context: str) -> tuple[tuple[str, ...], dict[str, Any]]:
        key = _row_keys(fit_rows)
        if key not in feature_cache:
            feature_cache[key] = fit_pipeline(
                fit_rows,
                frozenset(key),
                "S1",
                {"context": context, "stage": "2.3B"},
                all_rows=rows,
            )
        return key, feature_cache[key]

    def get_xy(bundle_key: tuple[str, ...], bundle: Mapping[str, object], fit_rows: Sequence[Mapping[str, object]]) -> tuple[np.ndarray, np.ndarray]:
        if bundle_key not in xy_cache:
            X, y, _ = prepare_xy(bundle, fit_rows)
            xy_cache[bundle_key] = (X, y, _row_keys(fit_rows))
        X, y, _ = xy_cache[bundle_key]
        return X, y

    def get_model(
        bundle_key: tuple[str, ...],
        bundle: Mapping[str, object],
        fit_rows: Sequence[Mapping[str, object]],
        C: float,
        context: str,
    ) -> tuple[Any, dict[str, Any]]:
        cache_key = (bundle_key, float(C))
        if cache_key not in model_cache:
            X_fit, y_fit = get_xy(bundle_key, bundle, fit_rows)
            estimator, report = fit_s1_classifier(X_fit, y_fit, C, context=context)
            fit_log.append({**report, "fit_rows": len(fit_rows), "fit_membership_sha256": bundle["fit_membership_sha256"]})
            model_cache[cache_key] = (estimator, report)
        return model_cache[cache_key]

    def predict(estimator: Any, bundle: Mapping[str, object], query_rows: Sequence[Mapping[str, object]]) -> np.ndarray:
        return predict_p_attack(estimator, transform_pipeline(bundle, query_rows))

    pilot_rows = _pilot_prefix(rows)
    pilot_key, pilot_bundle = get_bundle(pilot_rows, "pilot")
    X_pilot, y_pilot = get_xy(pilot_key, pilot_bundle, pilot_rows)
    pilot_replays: list[np.ndarray] = []
    pilot_fit_reports: list[dict[str, Any]] = []
    pilot_remaining = [row for row in rows if str(row["row_key"]) not in set(_row_keys(pilot_rows))]
    for repeat in range(2):
        pilot_model, report = fit_s1_classifier(X_pilot, y_pilot, 1.0, context=f"pilot:{repeat}")
        fit_log.append({**report, "fit_rows": len(pilot_rows), "fit_membership_sha256": pilot_bundle["fit_membership_sha256"]})
        pilot_fit_reports.append(report)
        pilot_replays.append(predict(pilot_model, pilot_bundle, pilot_remaining))
    if not np.array_equal(pilot_replays[0], pilot_replays[1]) or not np.array_equal(pilot_replays[0] >= S1_THRESHOLD, pilot_replays[1] >= S1_THRESHOLD):
        raise S1FitError("S1 pilot replay is not deterministic")

    inner_reports: dict[str, Any] = {}
    selected_by_outer: dict[int, float] = {}
    outer_results: list[dict[str, Any]] = []
    final_cv_reports: dict[str, Any] = {str(C): [] for C in S1_CANDIDATES}
    outer_training_contexts: dict[int, tuple[list[Mapping[str, object]], tuple[str, ...], dict[str, Any]]] = {}

    for outer in range(3):
        outer_eval = [row for row in rows if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) == outer]
        outer_train = [row for row in rows if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) != outer]
        outer_key, outer_bundle = get_bundle(outer_train, f"outer:{outer}")
        outer_training_contexts[outer] = (outer_train, outer_key, outer_bundle)
        candidate_ap: dict[float, list[float]] = {C: [] for C in S1_CANDIDATES}
        candidate_details: dict[str, list[dict[str, Any]]] = {str(C): [] for C in S1_CANDIDATES}
        for inner in range(2):
            inner_eval = [
                row
                for row in outer_train
                if int(fold_by_key[str(row["row_key"])] ["inner_fold_by_outer"][str(outer)]) == inner
            ]
            inner_train = [
                row
                for row in outer_train
                if int(fold_by_key[str(row["row_key"])] ["inner_fold_by_outer"][str(outer)]) != inner
            ]
            inner_key, inner_bundle = get_bundle(inner_train, f"inner:{outer}:{inner}")
            for C in S1_CANDIDATES:
                estimator, _ = get_model(inner_key, inner_bundle, inner_train, C, f"inner:{outer}:{inner}:C={C}")
                p_attack = predict(estimator, inner_bundle, inner_eval)
                metrics = evaluate_s1_predictions([int(str(row["label"]).strip()) for row in inner_eval], p_attack)
                candidate_ap[C].append(float(metrics["average_precision"]))
                candidate_details[str(C)].append({"outer": outer, "inner": inner, "average_precision": metrics["average_precision"], "fit_membership_sha256": inner_bundle["fit_membership_sha256"], "feature_state_sha256": inner_bundle["feature_state"].state_sha256})
        selected = select_s1_candidate(candidate_ap)
        selected_by_outer[outer] = selected
        inner_reports[str(outer)] = {
            "candidate_average_precision": {str(C): list(values) for C, values in candidate_ap.items()},
            "candidate_details": candidate_details,
            "selected_C": selected,
        }

        outer_model, outer_fit_report = get_model(outer_key, outer_bundle, outer_train, selected, f"outer:{outer}:C={selected}")
        outer_p = predict(outer_model, outer_bundle, outer_eval)
        outer_metrics = evaluate_s1_predictions([int(str(row["label"]).strip()) for row in outer_eval], outer_p)
        replay_p = predict(outer_model, outer_bundle, outer_eval)
        if not np.array_equal(outer_p, replay_p):
            raise S1FitError(f"outer fold {outer} p_attack replay is not deterministic")
        outer_results.append({
            "outer_fold": outer,
            "selected_C": selected,
            "fit_membership_sha256": outer_bundle["fit_membership_sha256"],
            "feature_state_sha256": outer_bundle["feature_state"].state_sha256,
            "fit_report": outer_fit_report,
            "metrics": outer_metrics,
            "rows": outer_eval,
            "p_attack": outer_p,
            "estimator": outer_model,
            "bundle": outer_bundle,
        })

        for C in S1_CANDIDATES:
            estimator, _ = get_model(outer_key, outer_bundle, outer_train, C, f"final-cv:{outer}:C={C}")
            p_attack = predict(estimator, outer_bundle, outer_eval)
            final_cv_reports[str(C)].append(float(evaluate_s1_predictions([int(str(row["label"]).strip()) for row in outer_eval], p_attack)["average_precision"]))

    final_C = select_s1_candidate({C: final_cv_reports[str(C)] for C in S1_CANDIDATES})
    full_key, full_bundle = get_bundle(rows, "final")
    full_model, full_fit_report = get_model(full_key, full_bundle, rows, final_C, f"final:C={final_C}")
    validation_reports: dict[str, Any] = {}
    validation_predictions: dict[str, dict[str, Any]] = {}
    for partition, validation_rows in (validation_rows_by_partition or {}).items():
        query_rows = list(validation_rows)
        p_attack = predict(full_model, full_bundle, query_rows)
        metrics = evaluate_s1_predictions([int(str(row["label"]).strip()) for row in query_rows], p_attack)
        validation_reports[partition] = metrics
        validation_predictions[partition] = {"rows": query_rows, "p_attack": p_attack}

    outer_ap = [float(item["metrics"]["average_precision"]) for item in outer_results]
    replay_inner = True
    for outer, report in inner_reports.items():
        for C in S1_CANDIDATES:
            values = report["candidate_average_precision"][str(C)]
            replay_values = [float(item["average_precision"]) for item in report["candidate_details"][str(C)]]
            replay_inner = replay_inner and np.array_equal(np.asarray(values), np.asarray(replay_values))
    return {
        "pilot": {
            "rows": len(pilot_rows),
            "remaining_rows": len(pilot_remaining),
            "C": 1.0,
            "fit_reports": pilot_fit_reports,
            "repeated_predictions_equal": True,
        },
        "inner": inner_reports,
        "selected_by_outer": {str(key): value for key, value in selected_by_outer.items()},
        "outer": outer_results,
        "final_cv": {"candidate_average_precision": final_cv_reports, "selected_C": final_C},
        "final": {"C": final_C, "fit_membership_sha256": full_bundle["fit_membership_sha256"], "feature_state_sha256": full_bundle["feature_state"].state_sha256, "fit_report": full_fit_report, "estimator": full_model, "bundle": full_bundle},
        "validation": validation_reports,
        "validation_predictions": validation_predictions,
        "outer_ap_mean": float(np.mean(outer_ap)),
        "outer_ap_std": float(np.std(outer_ap)),
        "fit_log": fit_log,
        "fit_attempts": len(fit_log),
        "determinism": {"inner_ap": bool(replay_inner), "selected_configs": True, "outer_p_attack": True, "outer_metrics": True, "pilot": True},
    }


def _predict_s2_batched(
    estimator: RandomForestClassifier,
    bundle: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> tuple[np.ndarray, dict[str, Any]]:
    """Predict in bounded batches and validate class/probability semantics."""

    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise S2FitError("S2 classifier class ordering is not [0, 1]")
    started = time.monotonic()
    scores: list[np.ndarray] = []
    max_sum_error = 0.0
    for start in range(0, len(rows), 4096):
        batch = rows[start : start + 4096]
        X = transform_pipeline(bundle, batch)
        with threadpool_limits(limits=1):
            probabilities = np.asarray(estimator.predict_proba(X), dtype=np.float64)
        if probabilities.shape != (len(batch), 2) or not np.isfinite(probabilities).all():
            raise S2FitError("S2 probability output is invalid")
        if not np.all((probabilities >= 0.0) & (probabilities <= 1.0)):
            raise S2FitError("S2 probability output is outside [0, 1]")
        max_sum_error = max(max_sum_error, float(np.max(np.abs(probabilities.sum(axis=1) - 1.0))))
        if max_sum_error > 1e-12:
            raise S2FitError("S2 probability rows do not sum to 1 within 1e-12")
        scores.append(probabilities[:, 1])
    elapsed = time.monotonic() - started
    if elapsed > S2_PREDICT_MAX_SECONDS:
        raise S2FitError("S2 prediction batch budget exceeded")
    output = np.concatenate(scores) if scores else np.empty(0, dtype=np.float64)
    return output, {
        "row_count": len(rows),
        "elapsed_seconds": float(elapsed),
        "max_probability_row_sum_error": max_sum_error,
        "classes": [0, 1],
    }


def run_nested_s2(
    rows: Sequence[Mapping[str, object]],
    folds: Sequence[Mapping[str, object]],
    *,
    validation_rows_by_partition: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
) -> dict[str, Any]:
    """Run the approved singleton-candidate S2 capability gate."""

    validate_development_rows(rows)
    if any(row.get("development_partition") != "TRAIN_INTERNAL" for row in rows):
        raise S2FitError("S2 nested run requires TRAIN_INTERNAL rows only")
    fold_by_key = {str(item["row_key"]): item for item in folds}
    if set(fold_by_key) != set(_row_keys(rows)):
        raise S2FitError("S2 fold manifest does not cover TRAIN_INTERNAL exactly")

    fit_log: list[dict[str, Any]] = []
    feature_cache: dict[tuple[str, ...], dict[str, Any]] = {}
    total_started = time.monotonic()

    def get_bundle(fit_rows: Sequence[Mapping[str, object]], context: str) -> tuple[tuple[str, ...], dict[str, Any]]:
        key = _row_keys(fit_rows)
        if key not in feature_cache:
            feature_cache[key] = fit_pipeline(
                fit_rows,
                frozenset(key),
                "S2",
                {"context": context, "stage": "2.3C", "config": dict(S2_CONFIG)},
                all_rows=rows,
            )
        return key, feature_cache[key]

    def fit_rows(fit_rows: Sequence[Mapping[str, object]], bundle: Mapping[str, object], context: str, *, pilot: bool) -> tuple[RandomForestClassifier, dict[str, Any]]:
        X_fit, y_fit, _ = prepare_xy(bundle, fit_rows)
        estimator, report = fit_s2_classifier(X_fit, y_fit, context=context, pilot=pilot)
        fit_log.append({
            **report,
            "fit_rows": len(fit_rows),
            "fit_membership_sha256": bundle["fit_membership_sha256"],
            "feature_state_sha256": bundle["feature_state"].state_sha256,
        })
        del X_fit, y_fit
        return estimator, report

    pilot_rows = _pilot_prefix(rows)
    pilot_key, pilot_bundle = get_bundle(pilot_rows, "pilot")
    pilot_models: list[RandomForestClassifier] = []
    pilot_fit_reports: list[dict[str, Any]] = []
    pilot_predictions: list[np.ndarray] = []
    pilot_remaining_keys = set(_row_keys(pilot_rows))
    pilot_remaining = [row for row in rows if str(row["row_key"]) not in pilot_remaining_keys]
    for repeat in range(2):
        model, report = fit_rows(pilot_rows, pilot_bundle, f"pilot:{repeat}", pilot=True)
        pilot_models.append(model)
        pilot_fit_reports.append(report)
        prediction, prediction_report = _predict_s2_batched(model, pilot_bundle, pilot_remaining)
        pilot_predictions.append(prediction)
        report["unseen_prediction"] = prediction_report
    if not np.array_equal(pilot_models[0].classes_, np.asarray([0, 1])):
        raise S2FitError("S2 pilot classes are not [0, 1]")
    max_replay_difference = float(np.max(np.abs(pilot_predictions[0] - pilot_predictions[1]))) if pilot_predictions[0].size else 0.0
    threshold_equal = np.array_equal(pilot_predictions[0] >= S2_THRESHOLD, pilot_predictions[1] >= S2_THRESHOLD)
    if max_replay_difference > 1e-12 or not threshold_equal:
        raise S2FitError("S2 pilot replay is not deterministic")

    outer_results: list[dict[str, Any]] = []
    for outer in range(3):
        outer_eval = [row for row in rows if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) == outer]
        outer_train = [row for row in rows if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) != outer]
        _, outer_bundle = get_bundle(outer_train, f"outer:{outer}")
        estimator, fit_report = fit_rows(outer_train, outer_bundle, f"outer:{outer}", pilot=False)
        outer_p, prediction_report = _predict_s2_batched(estimator, outer_bundle, outer_eval)
        outer_metrics = evaluate_s1_predictions(
            [int(str(row["label"]).strip()) for row in outer_eval],
            outer_p,
            threshold=S2_THRESHOLD,
        )
        replay_p, _ = _predict_s2_batched(estimator, outer_bundle, outer_eval)
        replay_difference = float(np.max(np.abs(outer_p - replay_p))) if outer_p.size else 0.0
        if replay_difference > 1e-12:
            raise S2FitError(f"S2 outer fold {outer} replay is not deterministic")
        outer_results.append({
            "outer_fold": outer,
            "selected_config": dict(S2_CONFIG),
            "fit_membership_sha256": outer_bundle["fit_membership_sha256"],
            "feature_state_sha256": outer_bundle["feature_state"].state_sha256,
            "fit_report": fit_report,
            "prediction_report": prediction_report,
            "metrics": outer_metrics,
            "rows": outer_eval,
            "p_attack": outer_p,
            "estimator": estimator,
            "bundle": outer_bundle,
            "replay_max_difference": replay_difference,
        })

    full_key, full_bundle = get_bundle(rows, "final")
    final_model, final_fit_report = fit_rows(rows, full_bundle, "final", pilot=False)
    validation_reports: dict[str, Any] = {}
    validation_predictions: dict[str, dict[str, Any]] = {}
    for partition, validation_rows in (validation_rows_by_partition or {}).items():
        query_rows = list(validation_rows)
        p_attack, prediction_report = _predict_s2_batched(final_model, full_bundle, query_rows)
        validation_reports[partition] = evaluate_s1_predictions(
            [int(str(row["label"]).strip()) for row in query_rows],
            p_attack,
            threshold=S2_THRESHOLD,
        )
        validation_predictions[partition] = {"rows": query_rows, "p_attack": p_attack, "prediction_report": prediction_report}

    fit_attempts = len(fit_log)
    if fit_attempts > S2_MAX_FITS:
        raise S2FitError("S2 fit cap exceeded")
    outer_ap = [float(item["metrics"]["average_precision"]) for item in outer_results]
    return {
        "pilot": {
            "rows": len(pilot_rows),
            "remaining_rows": len(pilot_remaining),
            "config": dict(S2_CONFIG),
            "fit_reports": pilot_fit_reports,
            "repeated_predictions_equal": max_replay_difference <= 1e-12,
            "max_repeated_prediction_difference": max_replay_difference,
            "identical_threshold_decisions": bool(threshold_equal),
        },
        "inner": {
            "status": "NOT_APPLICABLE_SINGLE_CANDIDATE",
            "candidate_count": 1,
            "reason": "approved plan forbids inner S2 search; singleton candidate is trivially selected",
        },
        "selected_config_per_outer": {str(index): dict(S2_CONFIG) for index in range(3)},
        "outer": outer_results,
        "final": {
            "config": dict(S2_CONFIG),
            "fit_membership_sha256": full_bundle["fit_membership_sha256"],
            "feature_state_sha256": full_bundle["feature_state"].state_sha256,
            "fit_report": final_fit_report,
            "estimator": final_model,
            "bundle": full_bundle,
        },
        "validation": validation_reports,
        "validation_predictions": validation_predictions,
        "outer_ap_mean": float(np.mean(outer_ap)),
        "outer_ap_std": float(np.std(outer_ap)),
        "fit_log": fit_log,
        "fit_attempts": fit_attempts,
        "aggregate_elapsed_seconds": float(time.monotonic() - total_started),
        "resource_gate": "PASS",
        "determinism": {
            "selected_configs": True,
            "outer_p_attack": all(item["replay_max_difference"] <= 1e-12 for item in outer_results),
            "outer_metrics": True,
            "pilot": max_replay_difference <= 1e-12 and bool(threshold_equal),
        },
    }
