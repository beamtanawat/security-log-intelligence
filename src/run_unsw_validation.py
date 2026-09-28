"""Stage 2.2D UNSW U1/U2 validation runner.

This runner consumes only the materialized Stage 2.2A TRAIN/development
artifacts.  It never opens the official UNSW TEST CSV.
"""

from __future__ import annotations

import csv
import hashlib
import json
import pickle
import platform
import resource
import time
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from threadpoolctl import threadpool_limits

from unsupervised.contracts import BRANCH_ID, CATEGORICAL_FEATURES, DATASET_ID, NUMERIC_FEATURES
from unsupervised.evaluation import (
    ThresholdPolicy,
    compare_validation_models,
    evaluate_scores,
    select_threshold,
)
from unsupervised.features import FeatureState, transform_features
from unsupervised.models import U2Config, fit_u2, score_u2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_training-set.csv"
ACQUISITION_MANIFEST = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
CHECKPOINT_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_2" / "v1"
OUTPUT_ROOT = CHECKPOINT_ROOT / "validation"
PLAN_PATH = "docs/plans/stage_2_2_unsupervised_model_comparison_plan.md"
U1_MODEL_VERSION = "stage_2.2d-unsw-u1/1.0"
U2_MODEL_VERSION = "stage_2.2d-unsw-u2/1.0"
EXPECTED_U2_CONFIG = U2Config()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _write_json(path: Path, value: object) -> str:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _json_bytes(value) + b"\n"
    path.write_bytes(payload)
    return _sha256_bytes(payload)


def _write_jsonl(path: Path, rows: Sequence[dict[str, object]]) -> str:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"".join(_json_bytes(row) + b"\n" for row in rows)
    path.write_bytes(payload)
    return _sha256_bytes(payload)


def _load_feature_state(path: Path) -> FeatureState:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "stage_2.2a-feature-state/1.0":
        raise RuntimeError("unexpected Stage 2.2A feature-state schema")
    if payload.get("fit_boundary") != "TRAIN_INTERNAL_ONLY":
        raise RuntimeError("feature-state fit boundary is not TRAIN_INTERNAL_ONLY")
    canonical_payload = {
        "dataset_id": payload["dataset_id"],
        "branch_id": payload["branch_id"],
        "feature_order": payload["feature_order"],
        "numeric_medians": {field: payload["numeric_medians"][field] for field in NUMERIC_FEATURES},
        "numeric_means": {field: payload["numeric_means"][field] for field in NUMERIC_FEATURES},
        "numeric_scales": {field: payload["numeric_scales"][field] for field in NUMERIC_FEATURES},
        "categorical_vocabularies": {field: payload["categorical_vocabularies"][field] for field in CATEGORICAL_FEATURES},
        "output_feature_names": payload["output_feature_names"],
        "fit_row_count": payload["fit_row_count"],
    }
    feature_state_bytes = json.dumps(
        canonical_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if _sha256_bytes(feature_state_bytes) != payload.get("state_sha256"):
        raise RuntimeError("Stage 2.2A feature-state content hash mismatch")
    if payload["dataset_id"] != DATASET_ID or payload["branch_id"] != BRANCH_ID:
        raise RuntimeError("Stage 2.2A feature-state identity mismatch")
    return FeatureState(
        dataset_id=payload["dataset_id"],
        branch_id=payload["branch_id"],
        feature_order=tuple(payload["feature_order"]),
        numeric_medians={str(key): float(value) for key, value in payload["numeric_medians"].items()},
        numeric_means={str(key): float(value) for key, value in payload["numeric_means"].items()},
        numeric_scales={str(key): float(value) for key, value in payload["numeric_scales"].items()},
        categorical_vocabularies={str(key): tuple(value) for key, value in payload["categorical_vocabularies"].items()},
        output_feature_names=tuple(payload["output_feature_names"]),
        fit_row_count=int(payload["fit_row_count"]),
        state_sha256=str(payload["state_sha256"]),
    )


def _feature_only_row(row: dict[str, object], feature_order: Sequence[str]) -> dict[str, object]:
    return {
        **{field: row.get(field) for field in feature_order},
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "official_split": "TRAIN",
        "row_number": row["row_number"],
        "development_partition": row["development_partition"],
    }


def _load_preconditions() -> tuple[list[dict[str, object]], list[dict[str, object]], FeatureState, dict[str, Any], dict[str, Any]]:
    if not CHECKPOINT_ROOT.is_dir():
        raise RuntimeError("Stage 2.2A artifact root is missing")
    publication_path = CHECKPOINT_ROOT / "manifest.json"
    contract_path = CHECKPOINT_ROOT / "contracts" / "unsw_feature_contract.json"
    state_path = CHECKPOINT_ROOT / "features" / "unsw_train_internal_feature_state.json"
    split_path = CHECKPOINT_ROOT / "manifests" / "unsw_split_manifest.jsonl"
    report_path = CHECKPOINT_ROOT / "reports" / "unsw_split_audit.json"
    feasibility_path = CHECKPOINT_ROOT / "feasibility" / "unsw_u2_feasibility.json"
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    feasibility = json.loads(feasibility_path.read_text(encoding="utf-8"))
    for path, expected in publication["artifacts"].items():
        if _sha256(CHECKPOINT_ROOT / path) != expected:
            raise RuntimeError(f"Stage 2.2A artifact hash mismatch: {path}")
    if publication["source_train_sha256"] != _sha256(TRAIN_PATH):
        raise RuntimeError("official TRAIN source hash differs from Stage 2.2A")
    if len(contract["feature_order"]) != 28 or contract["fit_boundary"] != "TRAIN_INTERNAL_ONLY":
        raise RuntimeError("Stage 2.2A feature contract invariant failed")
    if report["official_train_rows"] != 175341 or report["partition_counts"]["TRAIN_INTERNAL"] != 140273:
        raise RuntimeError("Stage 2.2A TRAIN invariant failed")
    if report["partition_counts"]["VALIDATION_CALIBRATION"] + report["partition_counts"]["VALIDATION_COMPARISON"] != 35068:
        raise RuntimeError("Stage 2.2A validation invariant failed")
    if report["exact_predictive_group_count"] != 88976 or report["target_conflict_groups"] != 273:
        raise RuntimeError("Stage 2.2A predictive-group invariant failed")
    if report["target_conflict_rows"] != 6896 or report["target_conflict_normal"] != 2156 or report["target_conflict_attack"] != 4740:
        raise RuntimeError("Stage 2.2A conflict fingerprint failed")
    if report["exact_predictive_group_cross_split_count"] != 0:
        raise RuntimeError("Stage 2.2A group cross-split invariant failed")
    if publication["test_lock"] != "STRUCTURAL_ONLY_NO_TEST_CSV_OPENED" or report.get("test_csv_opened") or report.get("test_labels_read"):
        raise RuntimeError("Stage 2.2A TEST lock invariant failed")
    if feasibility.get("status") != "PASS" or feasibility.get("test_used") is not False or feasibility.get("label_free_fit") is not True:
        raise RuntimeError("Stage 2.2B U2 feasibility invariant failed")
    if feasibility.get("configuration") != EXPECTED_U2_CONFIG.to_dict():
        raise RuntimeError("Stage 2.2B U2 configuration differs from the approved recipe")

    split_rows = [
        json.loads(line)
        for line in split_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(split_rows) != 175341 or len({row["row_key"] for row in split_rows}) != 175341:
        raise RuntimeError("Stage 2.2A split manifest coverage invariant failed")
    split_by_number = {int(row["row_number"]): row for row in split_rows}
    if set(split_by_number) != set(range(1, 175342)):
        raise RuntimeError("Stage 2.2A split row-number coverage invariant failed")

    acquisition = json.loads(ACQUISITION_MANIFEST.read_text(encoding="utf-8"))
    train_entry = next(item for item in acquisition["files"] if item["role"] == "TRAIN")
    if _sha256(TRAIN_PATH) != train_entry["sha256"] or train_entry["observed_row_count"] != 175341:
        raise RuntimeError("official TRAIN acquisition identity failed")
    rows: list[dict[str, object]] = []
    with TRAIN_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != acquisition["schema"]["columns"]:
            raise RuntimeError("official TRAIN schema differs from acquisition contract")
        for number, raw in enumerate(reader, 1):
            if None in raw or any(value is None for value in raw.values()):
                raise RuntimeError(f"malformed official TRAIN row {number}")
            membership = split_by_number.get(number)
            if membership is None or membership["row_key"] != json.dumps([DATASET_ID, "TRAIN", number], separators=(",", ":")):
                raise RuntimeError(f"split membership mismatch at row {number}")
            label = str(raw.get("label", "")).strip()
            if label not in {"0", "1"}:
                raise RuntimeError(f"invalid binary label at row {number}")
            rows.append({
                **raw,
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": "TRAIN",
                "row_number": number,
                "development_partition": membership["partition"],
                "row_key": membership["row_key"],
            })
    if len(rows) != 175341:
        raise RuntimeError("official TRAIN row count changed")
    state = _load_feature_state(state_path)
    if state.fit_row_count != 140273 or len(state.output_feature_names) != 209:
        raise RuntimeError("Stage 2.2A preprocessing-state invariant failed")
    return rows, split_rows, state, report, contract


def _partition_rows(rows: Sequence[dict[str, object]], partition: str) -> list[dict[str, object]]:
    return [row for row in rows if row["development_partition"] == partition]


def _labels(rows: Sequence[dict[str, object]]) -> np.ndarray:
    return np.asarray([int(str(row["label"]).strip()) for row in rows], dtype=np.int8)


def _row_keys(rows: Sequence[dict[str, object]]) -> list[str]:
    return [str(row["row_key"]) for row in rows]


def _hash_json(value: object) -> str:
    return _sha256_bytes(_json_bytes(value))


def _model_score_rows(
    rows: Sequence[dict[str, object]],
    scores: Sequence[float],
    model_id: str,
    model_version: str,
    threshold: ThresholdPolicy,
    fit_membership_sha256: str,
    feature_state_sha256: str,
) -> list[dict[str, object]]:
    values = np.asarray(scores, dtype=np.float64)
    decisions = threshold.predict(values)
    output: list[dict[str, object]] = []
    for row, score, decision in zip(rows, values, decisions, strict=True):
        partition = str(row["development_partition"])
        output.append({
            "schema_version": "1.0",
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "row_key": str(row["row_key"]),
            "split_id": partition,
            "model_id": model_id,
            "model_version": model_version,
            "fit_membership_sha256": fit_membership_sha256,
            "feature_state_sha256": feature_state_sha256,
            "raw_abnormality": float(score),
            "score_direction": "HIGHER_MORE_ANOMALOUS",
            "fit_relationship": "IN_SAMPLE" if partition == "TRAIN_INTERNAL" else "HELD_OUT",
            "threshold_id": f"{model_id}_FINAL_VALIDATION_THRESHOLD",
            "decision": "ANOMALY" if bool(decision) else "INLIER",
            "chain_training_eligible": False,
        })
    return output


def _conflict_masks(
    rows: Sequence[dict[str, object]], report: dict[str, Any]
) -> tuple[dict[str, np.ndarray], dict[str, dict[str, Any]]]:
    conflict_rows_by_partition: dict[str, set[str]] = {
        "VALIDATION_CALIBRATION": set(),
        "VALIDATION_COMPARISON": set(),
    }
    groups_by_partition: dict[str, set[str]] = {
        "VALIDATION_CALIBRATION": set(),
        "VALIDATION_COMPARISON": set(),
    }
    for registry in report["target_conflict_registry"]:
        partition = registry["partition"]
        if partition in conflict_rows_by_partition:
            groups_by_partition[partition].add(str(registry["predictive_group_key"]))
            conflict_rows_by_partition[partition].update(registry["row_keys"])
    masks: dict[str, np.ndarray] = {}
    summaries: dict[str, dict[str, Any]] = {}
    for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON"):
        partition_rows = _partition_rows(rows, partition)
        mask = np.asarray([str(row["row_key"]) in conflict_rows_by_partition[partition] for row in partition_rows], dtype=bool)
        masks[partition] = mask
        conflict_labels = _labels([row for row, selected in zip(partition_rows, mask, strict=True) if selected])
        summaries[partition] = {
            "role": "THRESHOLD_CALIBRATION" if partition == "VALIDATION_CALIBRATION" else "PRIMARY_COMPARISON",
            "population_rows": len(partition_rows),
            "conflict_groups_represented": len(groups_by_partition[partition]),
            "conflict_rows": int(mask.sum()),
            "conflict_normal": int((conflict_labels == 0).sum()),
            "conflict_attack": int((conflict_labels == 1).sum()),
        }
    return masks, summaries


def _replay_order(rows: Sequence[dict[str, object]]) -> list[int]:
    keyed = [
        (
            _sha256_bytes(_json_bytes(["s2.2-full-replay-v1", row["row_key"]])),
            index,
        )
        for index, row in enumerate(rows)
    ]
    return [index for _, index in sorted(keyed)[:1000]]


def _assert_no_cross_partition_vector_collisions(matrices: dict[str, np.ndarray]) -> dict[str, object]:
    """Fail closed if frozen transformed vectors collide across partitions."""

    hashes: dict[str, set[bytes]] = {}
    for partition, matrix in matrices.items():
        if matrix.ndim != 2 or not np.isfinite(matrix).all():
            raise RuntimeError(f"invalid transformed matrix for {partition}")
        hashes[partition] = {hashlib.sha256(row.tobytes()).digest() for row in matrix}
    overlaps: dict[str, int] = {}
    partitions = tuple(matrices)
    for index, left in enumerate(partitions):
        for right in partitions[index + 1:]:
            overlaps[f"{left}__{right}"] = len(hashes[left] & hashes[right])
    if any(overlaps.values()):
        raise RuntimeError(f"post-transform cross-partition collision gate failed: {overlaps}")
    return {
        "schema_version": "stage_2.2d-post-transform-collision-audit/1.0",
        "cross_partition_overlap_counts": overlaps,
        "status": "PASS",
        "vector_hash_unique_counts": {partition: len(values) for partition, values in hashes.items()},
    }


def _assert_metric_replay(original: dict[str, Any], replay: dict[str, Any]) -> None:
    if _json_bytes(original) != _json_bytes(replay):
        raise RuntimeError("validation metrics replay mismatch")


def run() -> dict[str, object]:
    if OUTPUT_ROOT.exists():
        raise RuntimeError(f"refusing to overwrite accepted validation output root {OUTPUT_ROOT}")
    rows, split_rows, feature_state, split_report, feature_contract = _load_preconditions()
    train_rows = _partition_rows(rows, "TRAIN_INTERNAL")
    calibration_rows = _partition_rows(rows, "VALIDATION_CALIBRATION")
    comparison_rows = _partition_rows(rows, "VALIDATION_COMPARISON")
    if (len(train_rows), len(calibration_rows), len(comparison_rows)) != (140273, 17539, 17529):
        raise RuntimeError("development partition counts changed")
    train_features = [_feature_only_row(row, feature_contract["feature_order"]) for row in train_rows]
    calibration_features = [_feature_only_row(row, feature_contract["feature_order"]) for row in calibration_rows]
    comparison_features = [_feature_only_row(row, feature_contract["feature_order"]) for row in comparison_rows]
    X_train = transform_features(train_features, feature_state)
    X_calibration = transform_features(calibration_features, feature_state)
    X_comparison = transform_features(comparison_features, feature_state)
    if X_train.shape[1] != 209 or X_calibration.shape[1] != X_train.shape[1] or X_comparison.shape[1] != X_train.shape[1]:
        raise RuntimeError("UNSW transformed feature dimension mismatch")
    matrix_hashes = {
        "TRAIN_INTERNAL": _sha256_bytes(X_train.tobytes()),
        "VALIDATION_CALIBRATION": _sha256_bytes(X_calibration.tobytes()),
        "VALIDATION_COMPARISON": _sha256_bytes(X_comparison.tobytes()),
    }
    post_transform_collision_audit = _assert_no_cross_partition_vector_collisions({
        "TRAIN_INTERNAL": X_train,
        "VALIDATION_CALIBRATION": X_calibration,
        "VALIDATION_COMPARISON": X_comparison,
    })

    fit_membership_sha256 = _hash_json(_row_keys(train_rows))
    conflict_masks, conflict_summary = _conflict_masks(rows, split_report)
    calibration_labels = _labels(calibration_rows)
    comparison_labels = _labels(comparison_rows)

    u1_fit_started = time.perf_counter()
    with threadpool_limits(limits=1):
        u1 = IsolationForest(
            n_estimators=200,
            max_samples=4096,
            max_features=1.0,
            contamination="auto",
            bootstrap=False,
            n_jobs=1,
            random_state=1729,
            warm_start=False,
        )
        u1.fit(X_train)
        u1_train_scores = -np.asarray(u1.score_samples(X_train), dtype=np.float64)
        u1_calibration_scores = -np.asarray(u1.score_samples(X_calibration), dtype=np.float64)
        u1_comparison_scores = -np.asarray(u1.score_samples(X_comparison), dtype=np.float64)
    u1_runtime = time.perf_counter() - u1_fit_started
    if not all(np.isfinite(values).all() for values in (u1_train_scores, u1_calibration_scores, u1_comparison_scores)):
        raise RuntimeError("U1 produced non-finite scores")
    u1_threshold = select_threshold(u1_calibration_scores, calibration_labels)
    u1_calibration_metrics = evaluate_scores(
        u1_calibration_scores,
        calibration_labels,
        u1_threshold,
        conflict_mask=conflict_masks["VALIDATION_CALIBRATION"],
    )
    u1_comparison_metrics = evaluate_scores(
        u1_comparison_scores,
        comparison_labels,
        u1_threshold,
        conflict_mask=conflict_masks["VALIDATION_COMPARISON"],
    )

    u2_fit_started = time.perf_counter()
    with threadpool_limits(limits=1):
        u2 = fit_u2(X_train, _row_keys(train_rows), EXPECTED_U2_CONFIG)
        u2_train_scores = score_u2(u2, X_train)
        u2_calibration_scores = score_u2(u2, X_calibration)
        u2_comparison_scores = score_u2(u2, X_comparison)
    u2_runtime = time.perf_counter() - u2_fit_started
    if not all(np.isfinite(values).all() for values in (u2_train_scores, u2_calibration_scores, u2_comparison_scores)):
        raise RuntimeError("U2 produced non-finite scores")
    u2_threshold = select_threshold(u2_calibration_scores, calibration_labels)
    u2_calibration_metrics = evaluate_scores(
        u2_calibration_scores,
        calibration_labels,
        u2_threshold,
        conflict_mask=conflict_masks["VALIDATION_CALIBRATION"],
    )
    u2_comparison_metrics = evaluate_scores(
        u2_comparison_scores,
        comparison_labels,
        u2_threshold,
        conflict_mask=conflict_masks["VALIDATION_COMPARISON"],
    )
    if u1_comparison_metrics["pr_auc_ap"] is None or u2_comparison_metrics["pr_auc_ap"] is None:
        raise RuntimeError("VALIDATION_COMPARISON AP is unavailable")
    comparison = compare_validation_models(
        float(u1_comparison_metrics["pr_auc_ap"]),
        float(u2_comparison_metrics["pr_auc_ap"]),
        u1_runtime,
        u2_runtime,
    )

    # Full-model serialization replay on the fixed first-1,000 hash-ordered
    # comparison subset.  No refit is performed for replay.
    replay_indices = _replay_order(comparison_rows)
    u1_replay = pickle.loads(pickle.dumps(u1, protocol=pickle.HIGHEST_PROTOCOL))
    u2_replay = pickle.loads(pickle.dumps(u2, protocol=pickle.HIGHEST_PROTOCOL))
    u1_replayed_scores = -np.asarray(u1_replay.score_samples(X_comparison[replay_indices]), dtype=np.float64)
    u2_replayed_scores = score_u2(u2_replay, X_comparison[replay_indices])
    if not np.allclose(u1_replayed_scores, u1_comparison_scores[replay_indices], rtol=1e-10, atol=1e-12):
        raise RuntimeError("U1 serialization replay mismatch")
    if not np.allclose(u2_replayed_scores, u2_comparison_scores[replay_indices], rtol=1e-10, atol=1e-12):
        raise RuntimeError("U2 serialization replay mismatch")
    if u1_threshold.to_dict() != select_threshold(u1_calibration_scores, calibration_labels).to_dict():
        raise RuntimeError("U1 threshold replay mismatch")
    if u2_threshold.to_dict() != select_threshold(u2_calibration_scores, calibration_labels).to_dict():
        raise RuntimeError("U2 threshold replay mismatch")
    _assert_metric_replay(
        u1_comparison_metrics,
        evaluate_scores(u1_comparison_scores, comparison_labels, u1_threshold, conflict_mask=conflict_masks["VALIDATION_COMPARISON"]),
    )
    _assert_metric_replay(
        u2_comparison_metrics,
        evaluate_scores(u2_comparison_scores, comparison_labels, u2_threshold, conflict_mask=conflict_masks["VALIDATION_COMPARISON"]),
    )
    if comparison != compare_validation_models(
        float(u1_comparison_metrics["pr_auc_ap"]),
        float(u2_comparison_metrics["pr_auc_ap"]),
        u1_runtime,
        u2_runtime,
    ):
        raise RuntimeError("model comparison replay mismatch")

    scored_rows_order = [*train_rows, *calibration_rows, *comparison_rows]
    u1_score_rows = _model_score_rows(
        scored_rows_order,
        np.concatenate([u1_train_scores, u1_calibration_scores, u1_comparison_scores]),
        "UNSW_U1_ISOLATION_FOREST",
        U1_MODEL_VERSION,
        u1_threshold,
        fit_membership_sha256,
        feature_state.state_sha256,
    )
    u2_score_rows = _model_score_rows(
        scored_rows_order,
        np.concatenate([u2_train_scores, u2_calibration_scores, u2_comparison_scores]),
        "UNSW_U2_MINIBATCHKMEANS",
        U2_MODEL_VERSION,
        u2_threshold,
        fit_membership_sha256,
        feature_state.state_sha256,
    )
    # The concatenation above is partition ordered; source-order artifacts are
    # required, so remap them by row key before publication.
    score_rows_by_key_u1 = {row["row_key"]: row for row in u1_score_rows}
    score_rows_by_key_u2 = {row["row_key"]: row for row in u2_score_rows}
    u1_score_rows = [score_rows_by_key_u1[row["row_key"]] for row in rows]
    u2_score_rows = [score_rows_by_key_u2[row["row_key"]] for row in rows]

    u1_metrics = {
        "schema_version": "stage_2.2d-unsw-u1-validation/1.0",
        "model_id": "UNSW_U1_ISOLATION_FOREST",
        "calibration": u1_calibration_metrics,
        "comparison": u1_comparison_metrics,
        "threshold": u1_threshold.to_dict(),
    }
    u2_metrics = {
        "schema_version": "stage_2.2d-unsw-u2-validation/1.0",
        "model_id": "UNSW_U2_MINIBATCHKMEANS",
        "calibration": u2_calibration_metrics,
        "comparison": u2_comparison_metrics,
        "threshold": u2_threshold.to_dict(),
    }
    sensitivity = {
        "schema_version": "stage_2.2d-conflict-sensitivity/1.0",
        "label": "SENSITIVITY ANALYSIS ONLY — TARGET CONFLICT GROUPS",
        "primary_metrics_unchanged": True,
        "validation_internal": {
            "population_rows": len(calibration_rows) + len(comparison_rows),
            "conflict_groups_represented": sum(item["conflict_groups_represented"] for item in conflict_summary.values()),
            "conflict_rows": sum(item["conflict_rows"] for item in conflict_summary.values()),
            "conflict_normal": sum(item["conflict_normal"] for item in conflict_summary.values()),
            "conflict_attack": sum(item["conflict_attack"] for item in conflict_summary.values()),
        },
        "partitions": conflict_summary,
        "models": {
            "U1": {
                "calibration": {key: u1_calibration_metrics[key] for key in ("conflict_rows", "conflict_attack", "conflict_normal", "conflict_tp", "conflict_fp", "conflict_tn", "conflict_fn", "conflict_error_count")},
                "comparison": {key: u1_comparison_metrics[key] for key in ("conflict_rows", "conflict_attack", "conflict_normal", "conflict_tp", "conflict_fp", "conflict_tn", "conflict_fn", "conflict_error_count")},
                "comparison_primary_error_count": u1_comparison_metrics["fp"] + u1_comparison_metrics["fn"],
            },
            "U2": {
                "calibration": {key: u2_calibration_metrics[key] for key in ("conflict_rows", "conflict_attack", "conflict_normal", "conflict_tp", "conflict_fp", "conflict_tn", "conflict_fn", "conflict_error_count")},
                "comparison": {key: u2_comparison_metrics[key] for key in ("conflict_rows", "conflict_attack", "conflict_normal", "conflict_tp", "conflict_fp", "conflict_tn", "conflict_fn", "conflict_error_count")},
                "comparison_primary_error_count": u2_comparison_metrics["fp"] + u2_comparison_metrics["fn"],
            },
        },
    }

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=False)
    u1_model_path = OUTPUT_ROOT / "unsw_u1_isolation_forest.joblib"
    u2_model_path = OUTPUT_ROOT / "unsw_u2_minibatch_kmeans.joblib"
    joblib.dump(u1, u1_model_path)
    joblib.dump(u2, u2_model_path)
    u1_model_hash = _sha256(u1_model_path)
    u2_model_hash = _sha256(u2_model_path)
    u1_score_hash = _write_jsonl(OUTPUT_ROOT / "unsw_u1_scores.jsonl", u1_score_rows)
    u2_score_hash = _write_jsonl(OUTPUT_ROOT / "unsw_u2_scores.jsonl", u2_score_rows)
    u1_threshold_hash = _write_json(OUTPUT_ROOT / "unsw_u1_threshold.json", u1_threshold.to_dict())
    u2_threshold_hash = _write_json(OUTPUT_ROOT / "unsw_u2_threshold.json", u2_threshold.to_dict())
    u1_metrics_hash = _write_json(OUTPUT_ROOT / "unsw_u1_validation_metrics.json", u1_metrics)
    u2_metrics_hash = _write_json(OUTPUT_ROOT / "unsw_u2_validation_metrics.json", u2_metrics)
    sensitivity_hash = _write_json(OUTPUT_ROOT / "unsw_conflict_sensitivity.json", sensitivity)
    comparison_hash = _write_json(OUTPUT_ROOT / "unsw_u1_u2_comparison.json", comparison)
    resource_hash = _write_json(OUTPUT_ROOT / "unsw_validation_resource_replay.json", {
        "schema_version": "stage_2.2d-resource-replay/1.0",
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "u1_fit_plus_score_seconds": u1_runtime,
        "u2_fit_plus_score_seconds": u2_runtime,
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "replay_query_rows": len(replay_indices),
        "replay_order_sha256": _hash_json([comparison_rows[index]["row_key"] for index in replay_indices]),
        "u1_replay_score_sha256": _sha256_bytes(u1_replayed_scores.tobytes()),
        "u2_replay_score_sha256": _sha256_bytes(u2_replayed_scores.tobytes()),
        "determinism": "PASS",
        "matrix_hashes": matrix_hashes,
        "post_transform_collision_audit": post_transform_collision_audit,
        "u1_u2_received_identical_feature_matrices": True,
    })
    lock = {
        "schema_version": "stage_2.2d-selection-lock/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": PLAN_PATH,
        "source_train_sha256": _sha256(TRAIN_PATH),
        "stage_2_2a_manifest_sha256": _sha256(CHECKPOINT_ROOT / "manifest.json"),
        "feature_contract_sha256": _sha256(CHECKPOINT_ROOT / "contracts" / "unsw_feature_contract.json"),
        "feature_state_sha256": feature_state.state_sha256,
        "split_manifest_sha256": _sha256(CHECKPOINT_ROOT / "manifests" / "unsw_split_manifest.jsonl"),
        "fit_boundary": "TRAIN_INTERNAL_ONLY",
        "partitions": {"TRAIN_INTERNAL": 140273, "VALIDATION_CALIBRATION": 17539, "VALIDATION_COMPARISON": 17529},
        "feature_count": 209,
        "fit_membership_sha256": fit_membership_sha256,
        "models": {
            "U1": {"family": "ISOLATION_FOREST", "config": {"n_estimators": 200, "max_samples": 4096, "max_features": 1.0, "contamination": "auto", "bootstrap": False, "n_jobs": 1, "random_state": 1729, "warm_start": False}, "model_sha256": u1_model_hash, "score_sha256": u1_score_hash, "threshold_sha256": u1_threshold_hash, "metrics_sha256": u1_metrics_hash, "score_direction": "HIGHER_MORE_ANOMALOUS"},
            "U2": {"family": "MINIBATCHKMEANS_DISTANCE_SCORER", "config": EXPECTED_U2_CONFIG.to_dict(), "model_sha256": u2_model_hash, "score_sha256": u2_score_hash, "threshold_sha256": u2_threshold_hash, "metrics_sha256": u2_metrics_hash, "score_direction": "HIGHER_MORE_ANOMALOUS"},
        },
        "conflict_sensitivity_sha256": sensitivity_hash,
        "comparison_sha256": comparison_hash,
        "resource_replay_sha256": resource_hash,
        "comparison_decision": comparison,
        "threshold_policy": "VALIDATION_CALIBRATION_F1_ATTACK_POSITIVE_EXACT_RATIONAL_TIE_ORDER",
        "official_test": {"opened": False, "labels_read": False, "predictions_created": False, "status": "LOCKED"},
        "determinism": "PASS",
        "label_free_fit": True,
        "anomaly_not_attack": True,
    }
    lock_hash = _write_json(OUTPUT_ROOT / "selection_lock_manifest.json", lock)
    return {
        "status": "PASS",
        "u1_threshold": u1_threshold.threshold,
        "u2_threshold": u2_threshold.threshold,
        "u1_validation": u1_comparison_metrics,
        "u2_validation": u2_comparison_metrics,
        "comparison": comparison,
        "conflict_sensitivity": sensitivity,
        "determinism": "PASS",
        "test_used": False,
        "selection_lock_sha256": lock_hash,
        "output_root": str(OUTPUT_ROOT),
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
