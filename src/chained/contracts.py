"""Stage 2.4A contracts, context planning, and fail-closed validators.

This module only describes the approved chained pipeline.  It does not fit a
model, score a row, read official TEST, or use labels for anomaly features.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score

from supervised.contracts import FEATURE_ORDER
from unsupervised.contracts import BRANCH_ID, DATASET_ID


CHAIN_SCHEMA_VERSION = "stage_2.4/1.0"
PLAN_SHA256 = "0e56bb3ab24ef2d3a4ff7421fccb261db1846a38677178c6324323aeb181e76d"
MASTER_PLAN_SHA256 = "5d388f62e1d1c2a22de2e4388aee80da427c975b42ed87f2bea7c6112f0719ba"
BASE_FEATURES = tuple(FEATURE_ORDER)
U1_SCORE_FIELD = "U1_SCORE"
U2_SCORE_FIELD = "U2_SCORE"
CHAIN_SOURCE_FEATURES = BASE_FEATURES + (U1_SCORE_FIELD, U2_SCORE_FIELD)
CHAINED_SOURCE_FEATURES = CHAIN_SOURCE_FEATURES
U1_SIGNAL_FIELD = "u1_anomaly_score"
U2_SIGNAL_FIELD = "u2_anomaly_score"
SCORE_DIRECTION = "HIGHER_MORE_ANOMALOUS"
AP_TOLERANCE = 1e-6
EXPECTED_FIT_ATTEMPTS = 28
MIN_FIT_ROWS = 4096
MIN_DISTINCT_VECTORS = 32

U1_CONFIG: dict[str, object] = {
    "n_estimators": 200,
    "max_samples": 4096,
    "max_features": 1.0,
    "contamination": "auto",
    "bootstrap": False,
    "n_jobs": 1,
    "random_state": 1729,
    "warm_start": False,
}

U2_CONFIG: dict[str, object] = {
    "n_clusters": 32,
    "init": "k-means++",
    "n_init": 3,
    "batch_size": 1024,
    "init_size": 3072,
    "max_iter": 100,
    "tol": 0.0,
    "max_no_improvement": 10,
    "reassignment_ratio": 0.01,
    "compute_labels": False,
    "random_state": 1729,
    "score_batch_size": 4096,
}

CHAIN_S1_CONFIG: dict[str, object] = {
    "family": "LOGISTIC_REGRESSION",
    "C": 1.0,
    "solver": "lbfgs",
    "l1_ratio": 0.0,
    "dual": False,
    "tol": 1e-4,
    "max_iter": 1000,
    "fit_intercept": True,
    "class_weight": None,
    "random_state": 1729,
    "warm_start": False,
    "verbose": 0,
}

CHAIN_S2_CONFIG: dict[str, object] = {
    "family": "RANDOM_FOREST",
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

# These are byte identities approved by the Stage 2.4 plan.  Any change
# blocks the checkpoint rather than silently regenerating upstream state.
EXPECTED_UPSTREAM_HASHES: dict[str, str] = {
    "stage_2_2/v1/contracts/unsw_feature_contract.json": "bc66e157f74992c66b798f37a933f2894fe65b6df7d4b010e973465a7e6e14f6",
    "stage_2_2/v1/features/unsw_train_internal_feature_state.json": "1883e03e1b765c9153580e20ef66924a03ca2e70181d0b174c805d5fd26ec8b5",
    "stage_2_2/v1/manifests/unsw_split_manifest.jsonl": "f58d7527168a44588d095d0be9e718dccd86641f0d10570ef9986ea8efd9d06b",
    "stage_2_2/v1/reports/unsw_split_audit.json": "a2ceb27131db023ebd9dfb4236af1ba18c17fba191a91e06704a7130dd645c9d",
    "stage_2_2/v1/manifest.json": "ff76fb00da29cdaab4abddadc9fed0547cde394edc864148f7d50089cf5e514e",
    "stage_2_3/v1/contracts/supervised_contract.json": "057cc9b9eb1eb8183f4513ec30cc7471c4da5d3cd766d91d59309c603975f539",
    "stage_2_3/v1/manifests/folds.jsonl": "2c86ff51fa4cf2af761f2d26841747c2559a76999a92321351f4b09ef0d784dd",
    "stage_2_3/v1/manifests/fold_audit.json": "0f358cc6f2907759ecca3fe69b64251ed451f3cbcb1a5c00785216be111dad6e",
    "stage_2_3/v1/manifests/stage_2_4_handoff.json": "54db2ea4a8b5fa5e12a3a66226fc21ddd8fb5b953aaca9dcbdb5a7bf608acf0e",
    "stage_2_3/v1/manifests/selection_lock.json": "515df6a7b017853d3917dae276aa656b858587ba294ffdb28a001762ba6ceb5a",
    "stage_2_3/v1/reports/selection.json": "8f7fffecccad0999c7959654616eaef0b5d8bea60ebe32c5bf6915f7d78d059f",
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def membership_sha256(row_keys: Sequence[str]) -> str:
    return sha256_bytes(json.dumps(list(row_keys), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _groups_for_keys(rows: Sequence[Mapping[str, object]], keys: Iterable[str]) -> list[str]:
    key_set = set(keys)
    return _ordered_unique(str(row["group_id"]) for row in rows if str(row["row_key"]) in key_set)


def _ordered_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _feature_allowlist() -> list[str]:
    return list(BASE_FEATURES)


def build_chain_contract() -> dict[str, Any]:
    """Return the immutable Stage 2.4 V1 source/model contract."""

    return {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "plan_sha256": PLAN_SHA256,
        "master_plan_sha256": MASTER_PLAN_SHA256,
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "source_features": list(CHAIN_SOURCE_FEATURES),
        "base_features": _feature_allowlist(),
        "base_source_feature_count": len(BASE_FEATURES),
        "source_feature_count": len(CHAIN_SOURCE_FEATURES),
        "base_transformed_feature_count": 209,
        "maximum_chained_transformed_feature_count": 211,
        "signals": {
            "U1": {
                "field": U1_SCORE_FIELD,
                "storage_field": U1_SIGNAL_FIELD,
                "family": "ISOLATION_FOREST",
                "definition": "negative score_samples",
                "score_semantics": SCORE_DIRECTION,
                "binary_decision_included": False,
                "threshold_included": False,
                "label_free_fit": True,
                "config": dict(U1_CONFIG),
            },
            "U2": {
                "field": U2_SCORE_FIELD,
                "storage_field": U2_SIGNAL_FIELD,
                "family": "MINIBATCHKMEANS_DISTANCE_SCORER",
                "definition": "nearest-centroid squared distance",
                "score_semantics": SCORE_DIRECTION,
                "binary_decision_included": False,
                "threshold_included": False,
                "label_free_fit": True,
                "config": dict(U2_CONFIG),
            },
        },
        "excluded_fields": [
            "label",
            "attack_cat",
            "id",
            "row_id",
            "group_id",
            "U1_DECISION",
            "U2_DECISION",
            "anomaly_score",
            "anomaly_rank",
            "anomaly_band",
            "auto_triage",
            "stage_2_2_score",
            "stage_2_2_prediction",
            "predicted_label",
        ],
        "models": {"CHAIN-S1": dict(CHAIN_S1_CONFIG), "CHAIN-S2": dict(CHAIN_S2_CONFIG)},
        "thresholds": {"CHAIN-S1": 0.5, "CHAIN-S2": 0.5},
        "group_contract": {
            "definition": "28 BASE predictive features before learned preprocessing",
            "atomic": True,
            "anomaly_scores_change_identity": False,
            "same_row_overlap": 0,
            "same_group_overlap": 0,
        },
        "preprocessing_boundaries": {
            "base": "AUTHORIZED_TRAINING_ROWS_ONLY",
            "u1": "AUTHORIZED_U_FIT_ROWS_ONLY",
            "u2": "AUTHORIZED_U_FIT_ROWS_ONLY",
            "signal_scaling": "OOF_SIGNAL_TRAINING_ROWS_ONLY",
            "supervised": "AUTHORIZED_SUPERVISED_TRAINING_ROWS_ONLY",
            "official_test": "NO_FIT_OR_SCALING",
        },
        "nested_cross_fit": {
            "outer_folds": 3,
            "inner_folds_per_outer": 2,
            "training_signal_policy": "OOF_CROSS_FITTED",
            "global_oof_for_outer_training": "FORBIDDEN",
        },
        "comparison": {
            "metric": "AVERAGE_PRECISION",
            "implementation": "sklearn.metrics.average_precision_score",
            "positive_class": 1,
            "score_field": "p_attack",
            "ap_tolerance": AP_TOLERANCE,
            "tie_preference": "SIMPLER_BASE",
        },
        "test_policy": {
            "used_in_2_4A": False,
            "development": "LOCKED_FROM_TEST",
            "new_selection_lock_required_before_2_4E": True,
        },
        "fit_budget": {
            "u1_max": 10,
            "u2_max": 10,
            "chain_s1_max": 4,
            "chain_s2_max": 4,
            "expected_total_fit_attempts": EXPECTED_FIT_ATTEMPTS,
            "actual_fit_attempts_2_4A": 0,
        },
    }


def build_contexts(folds: Sequence[Mapping[str, object]]) -> list[dict[str, Any]]:
    """Build exact nested U signal contexts from the frozen Stage 2.3 folds."""

    if not folds:
        raise ValueError("fold manifest cannot be empty")
    keys: list[str] = []
    row_by_key: dict[str, Mapping[str, object]] = {}
    for item in folds:
        key = str(item.get("row_key", ""))
        if not key or key in row_by_key:
            raise ValueError("fold row keys must be unique")
        if item.get("dataset_id") != DATASET_ID or item.get("branch_id") != BRANCH_ID:
            raise ValueError("fold dataset or branch identity mismatch")
        if item.get("upstream_split") != "TRAIN_INTERNAL":
            raise ValueError("2.4A contexts require TRAIN_INTERNAL folds only")
        outer = item.get("outer_fold")
        if outer not in {0, 1, 2}:
            raise ValueError("outer fold must be 0, 1, or 2")
        inner_map = item.get("inner_fold_by_outer")
        if not isinstance(inner_map, Mapping):
            raise ValueError("inner fold mapping is required")
        row_by_key[key] = item
        keys.append(key)

    outer_keys = {outer: [key for key in keys if int(row_by_key[key]["outer_fold"]) == outer] for outer in range(3)}
    group_by_key = {key: str(row_by_key[key]["group_id"]) for key in keys}
    group_outer: dict[str, set[int]] = defaultdict(set)
    for key in keys:
        group_outer[group_by_key[key]].add(int(row_by_key[key]["outer_fold"]))
    if any(len(values) != 1 for values in group_outer.values()):
        raise ValueError("predictive group crosses outer folds")

    contexts: list[dict[str, Any]] = []

    def append_context(
        *,
        context_id: str,
        kind: str,
        outer: int | None,
        inner: int | None,
        fit_keys: list[str],
        score_keys: list[str],
        authorized_keys: list[str],
        excluded_groups: list[str],
        score_partitions: list[str] | None = None,
    ) -> None:
        fit_groups = _ordered_unique(group_by_key[key] for key in fit_keys)
        score_groups = _ordered_unique(group_by_key[key] for key in score_keys)
        contexts.append(
            {
                "schema_version": CHAIN_SCHEMA_VERSION,
                "context_id": context_id,
                "kind": kind,
                "outer_fold": outer,
                "inner_fold": inner,
                "authorized_context": "OUTER_TRAIN" if kind == "INNER_SIGNAL" else "TRAIN_INTERNAL",
                "fit_row_keys": fit_keys,
                "score_row_keys": score_keys,
                "authorized_row_keys": authorized_keys,
                "fit_group_ids": fit_groups,
                "score_group_ids": score_groups,
                "excluded_outer_group_ids": excluded_groups,
                "fit_membership_sha256": membership_sha256(fit_keys),
                "score_membership_sha256": membership_sha256(score_keys),
                "authorized_membership_sha256": membership_sha256(authorized_keys),
                "score_partitions": score_partitions or [],
                "signal_models": ["U1", "U2"],
                "label_free": True,
                "test_used": False,
            }
        )

    for outer in range(3):
        held_out = outer_keys[outer]
        held_out_set = set(held_out)
        authorized = [key for key in keys if key not in held_out_set]
        excluded_groups = _ordered_unique(group_by_key[key] for key in held_out)
        for inner in range(2):
            inner_score = [
                key for key in authorized
                if int(row_by_key[key]["inner_fold_by_outer"][str(outer)]) == inner
            ]
            inner_score_set = set(inner_score)
            inner_fit = [key for key in authorized if key not in inner_score_set]
            append_context(
                context_id=f"outer_{outer}_inner_{inner}_signal",
                kind="INNER_SIGNAL",
                outer=outer,
                inner=inner,
                fit_keys=inner_fit,
                score_keys=inner_score,
                authorized_keys=authorized,
                excluded_groups=excluded_groups,
            )
        append_context(
            context_id=f"outer_{outer}_heldout_inference",
            kind="OUTER_INFERENCE",
            outer=outer,
            inner=None,
            fit_keys=authorized,
            score_keys=held_out,
            authorized_keys=keys,
            excluded_groups=excluded_groups,
        )
    append_context(
        context_id="final_train_inference",
        kind="FINAL_INFERENCE",
        outer=None,
        inner=None,
        fit_keys=keys,
        score_keys=[],
        authorized_keys=keys,
        excluded_groups=[],
        score_partitions=["VALIDATION_CALIBRATION", "VALIDATION_COMPARISON", "TEST_AFTER_2_4E_LOCK"],
    )
    return contexts


def validate_nested_contexts(contexts: Sequence[Mapping[str, object]]) -> bool:
    """Validate row/group disjointness and recursive outer/inner containment."""

    if not contexts:
        raise ValueError("contexts cannot be empty")
    ids = [str(item.get("context_id", "")) for item in contexts]
    if not all(ids) or len(set(ids)) != len(ids):
        raise ValueError("context IDs must be unique")
    kinds = {str(item.get("kind")) for item in contexts}
    if kinds != {"INNER_SIGNAL", "OUTER_INFERENCE", "FINAL_INFERENCE"}:
        raise ValueError("nested context kinds incomplete")
    for item in contexts:
        fit_rows = [str(value) for value in item.get("fit_row_keys", [])]
        score_rows = [str(value) for value in item.get("score_row_keys", [])]
        if len(set(fit_rows)) != len(fit_rows) or len(set(score_rows)) != len(score_rows):
            raise ValueError("context row memberships must be unique")
        if set(fit_rows) & set(score_rows):
            raise ValueError("same-row fit/score overlap (row overlap)")
        fit_groups = {str(value) for value in item.get("fit_group_ids", [])}
        score_groups = {str(value) for value in item.get("score_group_ids", [])}
        if fit_groups & score_groups:
            raise ValueError("same-group fit/score overlap (group overlap)")
        authorized = {str(value) for value in item.get("authorized_row_keys", [])}
        if not set(fit_rows) <= authorized or not set(score_rows) <= authorized:
            raise ValueError("context membership outside authorized rows")
        excluded_groups = {str(value) for value in item.get("excluded_outer_group_ids", [])}
        if fit_groups & excluded_groups:
            raise ValueError("outer held-out group appears in fit groups")
        if str(item.get("kind")) == "INNER_SIGNAL":
            if set(fit_rows) | set(score_rows) != authorized:
                raise ValueError("inner context does not cover authorized outer training rows")
        elif str(item.get("kind")) == "OUTER_INFERENCE":
            if set(fit_rows) | set(score_rows) != authorized:
                raise ValueError("outer context does not cover TRAIN_INTERNAL rows")
    inner = [item for item in contexts if item.get("kind") == "INNER_SIGNAL"]
    outer = [item for item in contexts if item.get("kind") == "OUTER_INFERENCE"]
    final = [item for item in contexts if item.get("kind") == "FINAL_INFERENCE"]
    if len(inner) != 6 or len(outer) != 3 or len(final) != 1:
        raise ValueError("expected 6 inner, 3 outer, and 1 final context")
    return True


def audit_signal_records(records: Sequence[Mapping[str, object]], context: Mapping[str, object]) -> dict[str, Any]:
    """Audit one U1/U2 signal stream before any chained model fit."""

    expected = [str(value) for value in context.get("score_row_keys", [])]
    expected_set = set(expected)
    if not expected:
        raise ValueError("signal context has no expected score coverage")
    seen: set[str] = set()
    context_id = str(context.get("context_id"))
    allowed_fields = {"row_key", "group_id", "context_id", "fit_row_keys", "fit_group_ids", "score", "score_direction", "model_id", "model_version", "preprocessing_identity"}
    context_groups = {str(value) for value in context.get("score_group_ids", [])}
    for record in records:
        forbidden = {"label", "attack_cat", "target", "binary_target"} & set(record)
        if forbidden:
            raise ValueError("labels cannot enter anomaly signal records")
        key = str(record.get("row_key", ""))
        if not key or key in seen:
            raise ValueError("signal row keys must be unique")
        if key not in expected_set:
            raise ValueError("signal coverage contains unexpected row")
        if str(record.get("context_id")) != context_id:
            raise ValueError("signal context identity mismatch")
        group_id = str(record.get("group_id", ""))
        if group_id not in context_groups:
            raise ValueError("signal group identity mismatch")
        fit_rows = {str(value) for value in record.get("fit_row_keys", context.get("fit_row_keys", []))}
        fit_groups = {str(value) for value in record.get("fit_group_ids", context.get("fit_group_ids", []))}
        if key in fit_rows:
            raise ValueError("same-row fit/score overlap (row overlap)")
        if group_id in fit_groups:
            raise ValueError("same-group fit/score overlap (group overlap)")
        if str(record.get("score_direction")) != SCORE_DIRECTION:
            raise ValueError("score direction must be HIGHER_MORE_ANOMALOUS")
        try:
            score = float(record.get("score"))
        except (TypeError, ValueError) as exc:
            raise ValueError("signal score must be finite") from exc
        if not math.isfinite(score):
            raise ValueError("signal score must be finite")
        seen.add(key)
        unknown = set(record) - allowed_fields
        if unknown:
            raise ValueError(f"unsupported signal fields: {sorted(unknown)}")
    if seen != expected_set:
        raise ValueError("signal coverage incomplete")
    return {
        "status": "PASS",
        "context_id": context_id,
        "score_row_count": len(seen),
        "same_row_overlap": 0,
        "same_group_overlap": 0,
        "fit_signal_group_overlap": 0,
    }


def validate_cache_lineage(expected: Mapping[str, object], actual: Mapping[str, object]) -> bool:
    """Permit reuse only when every cache identity is equal."""

    required = (
        "dataset_id",
        "context_id",
        "fit_membership_sha256",
    )
    for field in required:
        if expected.get(field) != actual.get(field):
            raise ValueError(f"cache lineage mismatch: {field}")
    for field in ("feature_contract_version", "group_contract_version", "model_config_version", "preprocessing_identity", "score_semantics_version", "score_membership_sha256"):
        if field in expected and expected.get(field) != actual.get(field):
            raise ValueError(f"cache lineage mismatch: {field}")
    return True


def validate_preprocessing_boundaries(boundaries: Mapping[str, object]) -> bool:
    """Reject learned state fit on validation or official TEST."""

    if bool(boundaries.get("test_fit", False)):
        raise ValueError("TEST preprocessing fit is forbidden")
    for field, value in boundaries.items():
        if isinstance(value, str) and "TEST" in value.upper():
            if field != "official_test":
                raise ValueError("TEST preprocessing boundary is forbidden")
    required = {"base", "u1", "u2", "signal_scaling", "supervised"}
    missing = required - set(boundaries)
    if missing:
        raise ValueError(f"preprocessing boundaries missing: {sorted(missing)}")
    return True


def validate_upstream_artifacts(artifacts: Mapping[str, object]) -> bool:
    """Validate Stage 2.2/2.3 identity without opening TEST data."""

    if artifacts.get("dataset_id") != DATASET_ID:
        raise ValueError("FortiGate or mixed dataset is not allowed")
    if artifacts.get("branch_id") != BRANCH_ID:
        raise ValueError("branch identity mismatch")
    if "TEST" in str(artifacts.get("test_policy", "")).upper() and "LOCKED" not in str(artifacts.get("test_policy", "")).upper():
        raise ValueError("TEST is not locked from development")
    if artifacts.get("chained_signals_used") not in {False, None}:
        raise ValueError("upstream baseline already contains chained signals")
    if artifacts.get("baseline_preferred_model") not in {None, "S2"}:
        raise ValueError("baseline preferred model identity mismatch")
    for field in ("fold_manifest_sha256", "selection_lock_sha256"):
        if not artifacts.get(field):
            raise ValueError(f"missing upstream identity: {field}")
    return True


def validate_upstream_feature_contract(contract: Mapping[str, object]) -> None:
    if contract.get("dataset_id") != DATASET_ID or contract.get("branch_id") != BRANCH_ID:
        raise ValueError("upstream feature identity mismatch")
    if contract.get("feature_order") != list(BASE_FEATURES):
        raise ValueError("upstream base feature order mismatch")
    if contract.get("output_feature_count") != 209:
        raise ValueError("upstream transformed feature count mismatch")
    if contract.get("target_field") != "label" or contract.get("attack_category_field") != "attack_cat":
        raise ValueError("upstream target contract mismatch")


def compare_pair(y_true: Sequence[int], base_p: Sequence[float], chain_p: Sequence[float]) -> dict[str, Any]:
    """Compare BASE and CHAIN using frozen Average Precision and tie rule."""

    labels = np.asarray(y_true, dtype=np.int8)
    base = np.asarray(base_p, dtype=np.float64)
    chain = np.asarray(chain_p, dtype=np.float64)
    if labels.ndim != 1 or base.ndim != 1 or chain.ndim != 1 or not (labels.shape == base.shape == chain.shape):
        raise ValueError("comparison arrays must be one-dimensional and aligned")
    if labels.size == 0 or set(labels.tolist()) - {0, 1} or not np.isfinite(base).all() or not np.isfinite(chain).all():
        raise ValueError("comparison inputs invalid")
    if not np.all((base >= 0) & (base <= 1)) or not np.all((chain >= 0) & (chain <= 1)):
        raise ValueError("comparison probabilities must be in [0, 1]")
    base_ap = float(average_precision_score(labels, base, pos_label=1))
    chain_ap = float(average_precision_score(labels, chain, pos_label=1))
    delta = chain_ap - base_ap
    if delta > AP_TOLERANCE:
        decision = "IMPROVEMENT"
    elif delta < -AP_TOLERANCE:
        decision = "DEGRADATION"
    else:
        decision = "TIE"
    return {
        "primary": "AP",
        "metric": "AVERAGE_PRECISION",
        "implementation": "sklearn.metrics.average_precision_score",
        "base_ap": base_ap,
        "chain_ap": chain_ap,
        "delta_ap": delta,
        "tolerance": AP_TOLERANCE,
        "decision": decision,
        "positive_class": 1,
    }


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"expected JSON object line: {path}")
                rows.append(value)
    return rows


def validate_inputs(root: Path) -> dict[str, Any]:
    """Validate immutable upstream Stage 2.4A inputs; never read official TEST."""

    root = Path(root)
    processed_root = root / "data" / "unsw_nb15" / "processed"
    paths = {key: processed_root / Path(key) for key in EXPECTED_UPSTREAM_HASHES}
    for relative, path in paths.items():
        if not path.is_file():
            raise ValueError(f"missing immutable upstream artifact: {relative}")
        observed = sha256_file(path)
        if observed != EXPECTED_UPSTREAM_HASHES[relative]:
            raise ValueError(f"upstream artifact hash mismatch: {relative}")

    feature_contract = _load_json(paths["stage_2_2/v1/contracts/unsw_feature_contract.json"])
    validate_upstream_feature_contract(feature_contract)
    split_rows = _load_jsonl(paths["stage_2_2/v1/manifests/unsw_split_manifest.jsonl"])
    split_report = _load_json(paths["stage_2_2/v1/reports/unsw_split_audit.json"])
    fold_rows = _load_jsonl(paths["stage_2_3/v1/manifests/folds.jsonl"])
    fold_audit = _load_json(paths["stage_2_3/v1/manifests/fold_audit.json"])
    handoff = _load_json(paths["stage_2_3/v1/manifests/stage_2_4_handoff.json"])
    selection = _load_json(paths["stage_2_3/v1/manifests/selection_lock.json"])
    validate_upstream_artifacts(
        {
            "dataset_id": handoff.get("dataset_id"),
            "branch_id": handoff.get("branch_id"),
            "test_policy": handoff.get("test_results", "LOCKED"),
            "fold_manifest_sha256": handoff.get("fold_manifest_sha256"),
            "selection_lock_sha256": handoff.get("selection_lock_sha256"),
            "baseline_preferred_model": handoff.get("preferred_model"),
            "chained_signals_used": handoff.get("chained_signals_used"),
        }
    )
    if split_report.get("official_train_rows") != 175341 or len(split_rows) != 175341:
        raise ValueError("upstream TRAIN row preservation failed")
    if split_report.get("exact_predictive_group_count") != 88976 or split_report.get("exact_predictive_group_cross_split_count") != 0:
        raise ValueError("upstream group fingerprint failed")
    if len(fold_rows) != 140273 or fold_audit.get("status") != "PASS":
        raise ValueError("upstream fold audit failed")
    if fold_audit.get("outer_group_crossings") != 0 or fold_audit.get("inner_group_crossings") != 0:
        raise ValueError("upstream fold group leakage detected")
    if handoff.get("test_results") != "NOT_INCLUDED_TEST_LOCKED" or handoff.get("preferred_model") != "S2":
        raise ValueError("Stage 2.3 handoff is not locked for 2.4A")
    if selection.get("official_test", {}).get("opened") is True or selection.get("official_test", {}).get("labels_read") is True:
        raise ValueError("official TEST was opened by development selection")
    return {
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "official_train_rows": len(split_rows),
        "train_internal_rows": len(fold_rows),
        "exact_predictive_group_count": split_report["exact_predictive_group_count"],
        "fold_manifest_sha256": handoff["fold_manifest_sha256"],
        "selection_lock_sha256": handoff["selection_lock_sha256"],
        "upstream_hashes": dict(EXPECTED_UPSTREAM_HASHES),
        "test_used": False,
        "fortigate_used": False,
        "split_rows": split_rows,
        "folds": fold_rows,
        "fold_audit": fold_audit,
        "handoff": handoff,
    }
