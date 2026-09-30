"""Immutable Stage 2.3A supervised target and feature contracts."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from unsupervised.contracts import (
    BRANCH_ID,
    CATEGORICAL_FEATURES,
    DATASET_ID,
    EXCLUDED_FIELDS as UNSUPERVISED_EXCLUDED_FIELDS,
    FEATURE_ORDER,
    NUMERIC_FEATURES,
)


SUPERVISED_CONTRACT_VERSION = "stage_2.3-supervised-contract/1.0"
TARGET_FIELD = "label"
NORMAL_LABEL = 0
ATTACK_LABEL = 1
POSITIVE_CLASS = ATTACK_LABEL
ALLOWED_PARTITIONS = {
    "TRAIN_INTERNAL",
    "VALIDATION_INTERNAL",
    "VALIDATION_CALIBRATION",
    "VALIDATION_COMPARISON",
}

CHAINED_SIGNAL_FIELDS = (
    "anomaly_score",
    "anomaly_rank",
    "anomaly_band",
    "auto_triage",
    "u1_score",
    "u2_score",
    "u1_decision",
    "u2_decision",
    "stage_2_2_score",
    "stage_2_2_prediction",
    "predicted_label",
)
SUPERVISED_EXCLUDED_FIELDS = tuple(
    dict.fromkeys(
        (*UNSUPERVISED_EXCLUDED_FIELDS, "group_id", "outer_fold", "inner_fold", "row_key", *CHAINED_SIGNAL_FIELDS)
    )
)


class SupervisedContractError(ValueError):
    """Raised when a Stage 2.3A contract boundary is violated."""


def build_supervised_contract() -> dict[str, Any]:
    """Return the frozen, classifier-independent Stage 2.3A contract."""

    return {
        "schema_version": SUPERVISED_CONTRACT_VERSION,
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "feature_order": list(FEATURE_ORDER),
        "numeric_features": list(NUMERIC_FEATURES),
        "categorical_features": list(CATEGORICAL_FEATURES),
        "excluded_fields": list(SUPERVISED_EXCLUDED_FIELDS),
        "target": {"field": TARGET_FIELD, "normal": NORMAL_LABEL, "attack": ATTACK_LABEL},
        "attack_category": {"field": "attack_cat", "policy": "PRESERVE_RAW_SEPARATE_NON_FEATURE"},
        "group_identity": {
            "source": "UPSTREAM_STAGE_2_2_PREDICTIVE_GROUP_ID",
            "definition": "28 predictive features before learned preprocessing",
            "atomic": True,
        },
        "preprocessing": {
            "implementation": "REUSE_STAGE_2_2_PURE_FEATURE_CONTRACT",
            "fit_scope": "FOLD_LOCAL_TRAINING_ROWS_ONLY",
            "output_dtype": "float64_contiguous",
            "max_output_columns": 512,
        },
        "metric": {
            "primary": "AVERAGE_PRECISION",
            "implementation": "sklearn.metrics.average_precision_score",
            "positive_class": ATTACK_LABEL,
            "score_field": "p_attack",
            "pr_auc_convention": "PR_AUC_AP",
        },
        "threshold": {"value": 0.5, "rule": "p_attack >= 0.5 -> ATTACK"},
        "models": {
            "S1": {
                "family": "LOGISTIC_REGRESSION",
                "candidate_C": [0.1, 1.0],
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
            },
            "S2": {
                "family": "RANDOM_FOREST",
                "n_estimators": 150,
                "criterion": "gini",
                "max_depth": 16,
                "min_samples_split": 2,
                "min_samples_leaf": 2,
                "max_features": "sqrt",
                "max_leaf_nodes": 1024,
                "bootstrap": True,
                "max_samples": None,
                "class_weight": None,
                "n_jobs": 1,
                "random_state": 1729,
                "warm_start": False,
                "ccp_alpha": 0.0,
                "monotonic_cst": None,
                "verbose": 0,
            },
        },
        "folds": {
            "outer_count": 3,
            "inner_count_per_outer": 2,
            "outer_namespace": "S2.3-OUTER-V1",
            "inner_namespace": "S2.3-INNER-V1",
            "allocation": "DESCENDING_COMPONENT_SIZE_GREEDY_FEWEST_ROWS_TIE_LOW_INDEX",
            "label_blind": True,
            "minimum_rows": 4096,
        },
        "class_handling": {"class_weight": None, "sample_weight": False, "resampling": False},
        "test_policy": "LOCKED_FROM_DEVELOPMENT_AND_SELECTION",
        "stage_2_4_boundary": {"baseline_chained_signals": [], "oof_required": True},
    }


def select_base_features(row: Mapping[str, object]) -> dict[str, object]:
    """Project one row onto the exact 28-field baseline allowlist."""

    return {field: row.get(field) for field in FEATURE_ORDER}


def _label(value: object, row_number: object) -> str:
    label = str(value).strip()
    if label not in {"0", "1"}:
        raise SupervisedContractError(f"invalid binary label at row {row_number}")
    return label


def validate_development_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Validate UNSW TRAIN-derived rows and return non-mutating label diagnostics."""

    if not rows:
        raise SupervisedContractError("development rows cannot be empty")
    seen_keys: set[str] = set()
    labels_by_group: dict[str, list[str]] = defaultdict(list)
    counts: Counter[str] = Counter()
    for index, row in enumerate(rows, 1):
        if row.get("dataset_id") != DATASET_ID:
            raise SupervisedContractError("dataset identity mismatch")
        if row.get("branch_id") != BRANCH_ID:
            raise SupervisedContractError("branch identity mismatch")
        if row.get("official_split") == "TEST":
            raise SupervisedContractError("official TEST rows are locked from supervised development")
        if row.get("official_split") not in {None, "TRAIN"}:
            raise SupervisedContractError("unsupported official split")
        partition = row.get("development_partition")
        if partition not in ALLOWED_PARTITIONS:
            raise SupervisedContractError("unsupported development partition")
        key = str(row.get("row_key", ""))
        if not key or key in seen_keys:
            raise SupervisedContractError("row keys must be unique")
        seen_keys.add(key)
        group_id = str(row.get("group_id", ""))
        if not group_id:
            raise SupervisedContractError(f"missing group identity at row {index}")
        label = _label(row.get(TARGET_FIELD), row.get("row_number", index))
        labels_by_group[group_id].append(label)
        counts[label] += 1
    conflicts = {group: values for group, values in labels_by_group.items() if len(set(values)) > 1}
    return {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "row_count": len(rows),
        "label_counts": {"0": counts["0"], "1": counts["1"]},
        "group_count": len(labels_by_group),
        "conflict_group_count": len(conflicts),
        "conflict_row_count": sum(len(values) for values in conflicts.values()),
        "target_policy": "OFFICIAL_LABEL_PRESERVED_NO_RELABEL_OR_DROP",
    }


def labels_for_rows(rows: Iterable[Mapping[str, object]]) -> list[int]:
    """Return official binary labels without deriving them from attack_cat."""

    return [int(_label(row.get(TARGET_FIELD), row.get("row_number", "?"))) for row in rows]
