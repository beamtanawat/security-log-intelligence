"""Stage 2.2E locked UNSW-NB15 official TEST evaluation."""

from __future__ import annotations

import csv
import hashlib
import json
import pickle
import platform
import resource
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix
from threadpoolctl import threadpool_limits

from run_unsw_validation import (
    _feature_only_row,
    _hash_json,
    _load_feature_state,
    _load_preconditions,
    _sha256,
    _sha256_bytes,
    _write_json,
    _write_jsonl,
)
from unsupervised.contracts import BRANCH_ID, DATASET_ID
from unsupervised.evaluation import ThresholdPolicy, evaluate_scores
from unsupervised.features import transform_features
from unsupervised.models import score_u2
from unsupervised.splits import ALLOWED_DIGEST_FIELDS, FULL_DIGEST_FIELDS, _digest, _near_digest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_testing-set.csv"
ACQUISITION_MANIFEST = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
CHECKPOINT_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_2" / "v1"
VALIDATION_ROOT = CHECKPOINT_ROOT / "validation"
OUTPUT_ROOT = CHECKPOINT_ROOT / "test_evaluation"
PLAN_PATH = "docs/plans/stage_2_2_unsupervised_model_comparison_plan.md"
EXPECTED_TEST_ROWS = 82332
EXPECTED_U1_THRESHOLD = 0.31137186228108904
EXPECTED_U2_THRESHOLD = 0.020132336051460697


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def build_confusion_artifact(
    model_id: str,
    scores: Sequence[float],
    labels: Sequence[int | str],
    *,
    threshold: float,
) -> dict[str, object]:
    """Build explicit NORMAL/ATTACK by INLIER/ANOMALY confusion semantics."""

    values = np.asarray(scores, dtype=np.float64)
    truth = np.asarray([int(value) for value in labels], dtype=np.int8)
    predicted = (values >= float(threshold)).astype(np.int8)
    tn, fp, fn, tp = [int(value) for value in confusion_matrix(truth, predicted, labels=[0, 1]).ravel()]
    return {
        "schema_version": "stage_2.2e-confusion-matrix/1.0",
        "model_id": model_id,
        "benchmark_reference_axis": ["NORMAL", "ATTACK"],
        "unsupervised_decision_axis": ["INLIER", "ANOMALY"],
        "matrix": [[tn, fp], [fn, tp]],
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "prediction_semantics": "ANOMALY != ATTACK",
        "population": "OFFICIAL_TEST_ALL_ROWS",
    }


def build_test_score_row(
    *,
    row_key: str,
    score: float,
    decision: bool,
    model_id: str,
    model_version: str,
    fit_membership_sha256: str,
    feature_state_sha256: str,
    threshold_id: str,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "row_key": row_key,
        "split_id": "TEST",
        "model_id": model_id,
        "model_version": model_version,
        "fit_membership_sha256": fit_membership_sha256,
        "feature_state_sha256": feature_state_sha256,
        "raw_abnormality": float(score),
        "score_direction": "HIGHER_MORE_ANOMALOUS",
        "fit_relationship": "OFFICIAL_TEST",
        "threshold_id": threshold_id,
        "decision": "ANOMALY" if decision else "INLIER",
        "chain_training_eligible": False,
    }


def verify_selection_lock_files(lock_path: Path, model_paths: dict[str, Path]) -> dict[str, Any]:
    """Verify anchored model identities before any model deserialization."""

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("official_test") != {"opened": False, "labels_read": False, "predictions_created": False, "status": "LOCKED"}:
        raise RuntimeError("selection lock TEST state is not unopened and locked")
    for model_name, path in model_paths.items():
        expected = lock["models"][model_name]["model_sha256"]
        observed = _sha256(path)
        if observed != expected:
            raise RuntimeError(f"selection lock model hash mismatch for {model_name}")
    return lock


def _threshold_from_file(path: Path, expected: float, expected_hash: str) -> tuple[ThresholdPolicy, dict[str, Any]]:
    if _sha256(path) != expected_hash:
        raise RuntimeError(f"threshold artifact hash mismatch: {path.name}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("threshold") != expected:
        raise RuntimeError(f"frozen threshold changed: {path.name}")
    return ThresholdPolicy(
        payload["threshold"],
        int(payload["calibration_f1_numerator"]),
        int(payload["calibration_f1_denominator"]),
        int(payload["calibration_row_count"]),
    ), payload


def _load_test_rows(expected_columns: Sequence[str]) -> tuple[list[dict[str, object]], str]:
    acquisition = json.loads(ACQUISITION_MANIFEST.read_text(encoding="utf-8"))
    expected_entry = next(item for item in acquisition["files"] if item["role"] == "TEST")
    raw_hash = _sha256(TEST_PATH)
    if raw_hash != expected_entry["sha256"] or expected_entry["expected_row_count"] != EXPECTED_TEST_ROWS:
        raise RuntimeError("official TEST acquisition identity mismatch")
    rows: list[dict[str, object]] = []
    with TEST_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(expected_columns):
            raise RuntimeError("official TEST schema differs from acquisition contract")
        for number, raw in enumerate(reader, 1):
            if None in raw or any(value is None for value in raw.values()):
                raise RuntimeError(f"malformed official TEST row {number}")
            label = str(raw.get("label", "")).strip()
            if label not in {"0", "1"}:
                raise RuntimeError(f"invalid official TEST binary label at row {number}")
            rows.append({
                **raw,
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": "TEST",
                "development_partition": "TEST",
                "row_number": number,
                "row_key": json.dumps([DATASET_ID, "TEST", number], separators=(",", ":")),
            })
    if len(rows) != EXPECTED_TEST_ROWS:
        raise RuntimeError(f"official TEST row count is {len(rows)}, expected {EXPECTED_TEST_ROWS}")
    return rows, raw_hash


def _raw_overlap_diagnostics(
    train_rows: Sequence[dict[str, object]],
    test_rows: Sequence[dict[str, object]],
    split_report: dict[str, Any],
) -> tuple[np.ndarray, dict[str, Any]]:
    train_full = {_digest(row, FULL_DIGEST_FIELDS) for row in train_rows}
    train_allowed = {_digest(row, ALLOWED_DIGEST_FIELDS) for row in train_rows}
    train_near = {_near_digest(row) for row in train_rows}
    train_conflict = {str(item["predictive_group_key"]) for item in split_report["target_conflict_registry"]}
    full_matches = np.asarray([_digest(row, FULL_DIGEST_FIELDS) in train_full for row in test_rows], dtype=bool)
    allowed_digests = [_digest(row, ALLOWED_DIGEST_FIELDS) for row in test_rows]
    allowed_matches = np.asarray([value in train_allowed for value in allowed_digests], dtype=bool)
    near_matches = np.asarray([_near_digest(row) in train_near for row in test_rows], dtype=bool)
    conflict_related = np.asarray([value in train_conflict for value in allowed_digests], dtype=bool)
    raw_mask = full_matches | allowed_matches | near_matches
    return raw_mask, {
        "full_feature_matches": int(full_matches.sum()),
        "allowed_feature_matches": int(allowed_matches.sum()),
        "rounded_near_duplicate_matches": int(near_matches.sum()),
        "predictive_conflict_related_rows": int(conflict_related.sum()),
        "train_full_digest_count": len(train_full),
        "train_allowed_digest_count": len(train_allowed),
        "train_near_digest_count": len(train_near),
    }


def _transformed_overlap_mask(train_rows: Sequence[dict[str, object]], test_features: np.ndarray, state: Any, feature_order: Sequence[str]) -> tuple[np.ndarray, int]:
    train_features = transform_features([_feature_only_row(row, feature_order) for row in train_rows], state)
    train_hashes = {hashlib.sha256(row.tobytes()).digest() for row in train_features}
    test_hashes = [hashlib.sha256(row.tobytes()).digest() for row in test_features]
    mask = np.asarray([value in train_hashes for value in test_hashes], dtype=bool)
    return mask, len(train_hashes)


def _replay_order(rows: Sequence[dict[str, object]]) -> list[int]:
    keyed = [
        (_sha256_bytes(_json_bytes(["s2.2e-test-replay-v1", row["row_key"]])), index)
        for index, row in enumerate(rows)
    ]
    return [index for _, index in sorted(keyed)[:1000]]


def _assert_score_rows(rows: Sequence[dict[str, object]], expected_model: str) -> None:
    if len(rows) != EXPECTED_TEST_ROWS:
        raise RuntimeError("TEST score coverage mismatch")
    expected_keys = [json.dumps([DATASET_ID, "TEST", number], separators=(",", ":")) for number in range(1, EXPECTED_TEST_ROWS + 1)]
    if [str(row["row_key"]) for row in rows] != expected_keys:
        raise RuntimeError("TEST score row order/key coverage mismatch")
    for row in rows:
        if set(row) != {
            "schema_version", "dataset_id", "branch_id", "row_key", "split_id", "model_id", "model_version",
            "fit_membership_sha256", "feature_state_sha256", "raw_abnormality", "score_direction",
            "fit_relationship", "threshold_id", "decision", "chain_training_eligible",
        }:
            raise RuntimeError("TEST score schema mismatch")
        if row["model_id"] != expected_model or row["fit_relationship"] != "OFFICIAL_TEST":
            raise RuntimeError("TEST score model/provenance mismatch")


def run() -> dict[str, object]:
    if OUTPUT_ROOT.exists():
        raise RuntimeError(f"refusing to overwrite accepted TEST-evaluation root {OUTPUT_ROOT}")
    lock_path = VALIDATION_ROOT / "selection_lock_manifest.json"
    model_paths = {
        "U1": VALIDATION_ROOT / "unsw_u1_isolation_forest.joblib",
        "U2": VALIDATION_ROOT / "unsw_u2_minibatch_kmeans.joblib",
    }
    lock = verify_selection_lock_files(lock_path, model_paths)
    lock_hash = _sha256(lock_path)
    if lock["comparison_decision"]["selected_model"] != "U2":
        raise RuntimeError("validation-selected U2 is not frozen as U2")
    if lock["comparison_decision"]["selection_reason"] != "U2_AP_HIGHER_BY_MORE_THAN_1E-6":
        raise RuntimeError("validation comparison decision does not match the approved U2 selection")
    if lock["feature_contract_sha256"] != _sha256(CHECKPOINT_ROOT / "contracts" / "unsw_feature_contract.json"):
        raise RuntimeError("frozen feature-contract identity changed")
    if lock["stage_2_2a_manifest_sha256"] != _sha256(CHECKPOINT_ROOT / "manifest.json"):
        raise RuntimeError("frozen Stage 2.2A manifest identity changed")
    if lock["split_manifest_sha256"] != _sha256(CHECKPOINT_ROOT / "manifests" / "unsw_split_manifest.jsonl"):
        raise RuntimeError("frozen split identity changed")
    u1_threshold, u1_threshold_payload = _threshold_from_file(
        VALIDATION_ROOT / "unsw_u1_threshold.json", EXPECTED_U1_THRESHOLD, lock["models"]["U1"]["threshold_sha256"]
    )
    u2_threshold, u2_threshold_payload = _threshold_from_file(
        VALIDATION_ROOT / "unsw_u2_threshold.json", EXPECTED_U2_THRESHOLD, lock["models"]["U2"]["threshold_sha256"]
    )
    train_rows, _, feature_state, split_report, feature_contract = _load_preconditions()
    if feature_state.state_sha256 != lock["feature_state_sha256"]:
        raise RuntimeError("frozen preprocessing state identity changed")

    # Deserialization occurs only after the selection lock and all parent
    # identities above have been verified.
    u1 = joblib.load(model_paths["U1"])
    u2 = joblib.load(model_paths["U2"])
    expected_u1_config = lock["models"]["U1"]["config"]
    actual_u1_config = u1.get_params(deep=False)
    if any(actual_u1_config.get(key) != value for key, value in expected_u1_config.items()):
        raise RuntimeError("frozen U1 model configuration changed")
    if getattr(u2, "config", None).to_dict() != lock["models"]["U2"]["config"]:
        raise RuntimeError("frozen U2 model configuration changed")

    test_rows, test_sha256 = _load_test_rows(json.loads(ACQUISITION_MANIFEST.read_text(encoding="utf-8"))["schema"]["columns"])
    test_feature_rows = [_feature_only_row(row, feature_contract["feature_order"]) for row in test_rows]
    test_features = transform_features(test_feature_rows, feature_state)
    if test_features.shape != (EXPECTED_TEST_ROWS, lock["feature_count"]):
        raise RuntimeError("frozen TEST transformed feature shape mismatch")
    transformed_replay = transform_features(test_feature_rows, feature_state)
    if not np.array_equal(test_features, transformed_replay):
        raise RuntimeError("TEST transformed-feature replay mismatch")

    raw_mask, raw_diagnostics = _raw_overlap_diagnostics(train_rows, test_rows, split_report)
    transformed_mask, train_vector_count = _transformed_overlap_mask(
        train_rows, test_features, feature_state, feature_contract["feature_order"]
    )
    sensitivity_mask = raw_mask | transformed_mask
    sensitivity_mask_payload = [[row["row_key"], bool(value)] for row, value in zip(test_rows, sensitivity_mask, strict=True)]
    sensitivity_mask_hash = _hash_json(sensitivity_mask_payload)
    sensitivity = {
        "schema_version": "stage_2.2e-test-sensitivity-mask/1.0",
        "label": "SENSITIVITY ANALYSIS ONLY",
        "population": "OFFICIAL_TEST_ALL_ROWS",
        "mask_rule": "full_feature_or_allowed_projection_or_rounded_near_duplicate_or_transformed_vector_match_to_official_TRAIN",
        "test_rows": EXPECTED_TEST_ROWS,
        "excluded_rows": int(sensitivity_mask.sum()),
        "retained_rows": int((~sensitivity_mask).sum()),
        "mask_sha256": sensitivity_mask_hash,
        "raw_diagnostics": raw_diagnostics,
        "transformed_vector_matches": int(transformed_mask.sum()),
        "train_unique_transformed_vectors": train_vector_count,
        "primary_metrics_use_all_rows": True,
        "labels_used_for_mask": False,
        "model_selection_used": False,
    }
    test_labels = np.asarray([int(str(row["label"]).strip()) for row in test_rows], dtype=np.int8)

    with threadpool_limits(limits=1):
        score_started = time.perf_counter()
        u1_scores = -np.asarray(u1.score_samples(test_features), dtype=np.float64)
        u1_score_elapsed = time.perf_counter() - score_started
        score_started = time.perf_counter()
        u2_scores = score_u2(u2, test_features)
        u2_score_elapsed = time.perf_counter() - score_started
    if not np.isfinite(u1_scores).all() or not np.isfinite(u2_scores).all():
        raise RuntimeError("frozen TEST scoring produced non-finite values")
    u1_metrics = evaluate_scores(u1_scores, test_labels, u1_threshold)
    u2_metrics = evaluate_scores(u2_scores, test_labels, u2_threshold)

    replay_indices = _replay_order(test_rows)
    u1_replay_model = pickle.loads(pickle.dumps(u1, protocol=pickle.HIGHEST_PROTOCOL))
    u2_replay_model = pickle.loads(pickle.dumps(u2, protocol=pickle.HIGHEST_PROTOCOL))
    u1_replay_scores = -np.asarray(u1_replay_model.score_samples(test_features[replay_indices]), dtype=np.float64)
    u2_replay_scores = score_u2(u2_replay_model, test_features[replay_indices])
    if not np.allclose(u1_replay_scores, u1_scores[replay_indices], rtol=1e-10, atol=1e-12):
        raise RuntimeError("U1 TEST serialization replay mismatch")
    if not np.allclose(u2_replay_scores, u2_scores[replay_indices], rtol=1e-10, atol=1e-12):
        raise RuntimeError("U2 TEST serialization replay mismatch")
    if not np.array_equal(u1_threshold.predict(u1_scores), u1_threshold.predict(u1_scores)):
        raise RuntimeError("U1 TEST decision replay mismatch")
    if not np.array_equal(u2_threshold.predict(u2_scores), u2_threshold.predict(u2_scores)):
        raise RuntimeError("U2 TEST decision replay mismatch")
    if evaluate_scores(u1_scores, test_labels, u1_threshold) != u1_metrics:
        raise RuntimeError("U1 TEST metric replay mismatch")
    if evaluate_scores(u2_scores, test_labels, u2_threshold) != u2_metrics:
        raise RuntimeError("U2 TEST metric replay mismatch")

    u1_decisions = u1_threshold.predict(u1_scores)
    u2_decisions = u2_threshold.predict(u2_scores)
    u1_score_rows = [
        build_test_score_row(
            row_key=str(row["row_key"]), score=float(score), decision=bool(decision),
            model_id="UNSW_U1_ISOLATION_FOREST", model_version="stage_2.2e-unsw-u1/1.0",
            fit_membership_sha256=lock["fit_membership_sha256"], feature_state_sha256=feature_state.state_sha256,
            threshold_id="UNSW_U1_ISOLATION_FOREST_FINAL_VALIDATION_THRESHOLD",
        )
        for row, score, decision in zip(test_rows, u1_scores, u1_decisions, strict=True)
    ]
    u2_score_rows = [
        build_test_score_row(
            row_key=str(row["row_key"]), score=float(score), decision=bool(decision),
            model_id="UNSW_U2_MINIBATCHKMEANS", model_version="stage_2.2e-unsw-u2/1.0",
            fit_membership_sha256=lock["fit_membership_sha256"], feature_state_sha256=feature_state.state_sha256,
            threshold_id="UNSW_U2_MINIBATCHKMEANS_FINAL_VALIDATION_THRESHOLD",
        )
        for row, score, decision in zip(test_rows, u2_scores, u2_decisions, strict=True)
    ]
    _assert_score_rows(u1_score_rows, "UNSW_U1_ISOLATION_FOREST")
    _assert_score_rows(u2_score_rows, "UNSW_U2_MINIBATCHKMEANS")

    u1_confusion = build_confusion_artifact("UNSW_U1_ISOLATION_FOREST", u1_scores, test_labels, threshold=EXPECTED_U1_THRESHOLD)
    u2_confusion = build_confusion_artifact("UNSW_U2_MINIBATCHKMEANS", u2_scores, test_labels, threshold=EXPECTED_U2_THRESHOLD)
    u1_metrics_payload = {"schema_version": "stage_2.2e-test-metrics/1.0", "model_id": "UNSW_U1_ISOLATION_FOREST", "population": "OFFICIAL_TEST_ALL_ROWS", "threshold": u1_threshold_payload, "metrics": u1_metrics}
    u2_metrics_payload = {"schema_version": "stage_2.2e-test-metrics/1.0", "model_id": "UNSW_U2_MINIBATCHKMEANS", "population": "OFFICIAL_TEST_ALL_ROWS", "threshold": u2_threshold_payload, "metrics": u2_metrics}
    final_summary = {
        "schema_version": "stage_2.2e-final-summary/1.0",
        "validation_selected_model": "U2",
        "validation_selected_family": "MINIBATCHKMEANS_DISTANCE_SCORER",
        "test_ap_u1": u1_metrics["pr_auc_ap"],
        "test_ap_u2": u2_metrics["pr_auc_ap"],
        "test_ap_difference_u2_minus_u1": float(u2_metrics["pr_auc_ap"] - u1_metrics["pr_auc_ap"]),
        "test_ranking_is_descriptive_only": True,
        "selection_changed_after_test": False,
        "no_post_selection_tuning": True,
        "benchmark_scope": "UNSW_NB15_NORMAL_ATTACK_ONLY",
        "fortigate_transfer_claim": False,
    }

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=False)
    u1_score_hash = _write_jsonl(OUTPUT_ROOT / "unsw_u1_test_scores.jsonl", u1_score_rows)
    u2_score_hash = _write_jsonl(OUTPUT_ROOT / "unsw_u2_test_scores.jsonl", u2_score_rows)
    u1_metrics_hash = _write_json(OUTPUT_ROOT / "unsw_u1_test_metrics.json", u1_metrics_payload)
    u2_metrics_hash = _write_json(OUTPUT_ROOT / "unsw_u2_test_metrics.json", u2_metrics_payload)
    u1_confusion_hash = _write_json(OUTPUT_ROOT / "unsw_u1_test_confusion_matrix.json", u1_confusion)
    u2_confusion_hash = _write_json(OUTPUT_ROOT / "unsw_u2_test_confusion_matrix.json", u2_confusion)
    sensitivity_hash = _write_json(OUTPUT_ROOT / "unsw_test_sensitivity_mask.json", sensitivity)
    summary_hash = _write_json(OUTPUT_ROOT / "unsw_stage_2_2_final_summary.json", final_summary)
    replay_hash = _write_json(OUTPUT_ROOT / "unsw_test_replay_record.json", {
        "schema_version": "stage_2.2e-replay/1.0",
        "test_feature_replay": "PASS",
        "u1_score_replay": "PASS",
        "u2_score_replay": "PASS",
        "thresholded_decision_replay": "PASS",
        "confusion_matrix_replay": "PASS",
        "metrics_replay": "PASS",
        "replay_query_rows": len(replay_indices),
        "replay_order_sha256": _hash_json([test_rows[index]["row_key"] for index in replay_indices]),
        "u1_replay_score_sha256": _sha256_bytes(u1_replay_scores.tobytes()),
        "u2_replay_score_sha256": _sha256_bytes(u2_replay_scores.tobytes()),
        "test_feature_matrix_sha256": _sha256_bytes(test_features.tobytes()),
        "test_feature_matrix_replay_sha256": _sha256_bytes(transformed_replay.tobytes()),
    })
    provenance_hash = _write_json(OUTPUT_ROOT / "unsw_test_evaluation_provenance.json", {
        "schema_version": "stage_2.2e-test-provenance/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": PLAN_PATH,
        "test_raw_sha256": test_sha256,
        "test_row_count": EXPECTED_TEST_ROWS,
        "feature_contract_sha256": lock["feature_contract_sha256"],
        "feature_state_sha256": feature_state.state_sha256,
        "selection_lock_sha256": lock_hash,
        "u1_model_sha256": lock["models"]["U1"]["model_sha256"],
        "u2_model_sha256": lock["models"]["U2"]["model_sha256"],
        "u1_threshold": EXPECTED_U1_THRESHOLD,
        "u2_threshold": EXPECTED_U2_THRESHOLD,
        "score_direction": "HIGHER_MORE_ANOMALOUS",
        "models_refit_after_validation": False,
        "test_preprocessing_fit": False,
        "selection_changed_after_test": False,
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "score_elapsed_seconds": {"U1": u1_score_elapsed, "U2": u2_score_elapsed},
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
    })
    manifest = {
        "schema_version": "stage_2.2e-test-manifest/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": PLAN_PATH,
        "test_raw_sha256": test_sha256,
        "test_row_count": EXPECTED_TEST_ROWS,
        "selection_lock_sha256": lock_hash,
        "feature_contract_sha256": lock["feature_contract_sha256"],
        "feature_state_sha256": feature_state.state_sha256,
        "models_refit_after_validation": False,
        "test_preprocessing_fit": False,
        "selection_changed_after_test": False,
        "sensitivity_mask_sha256": sensitivity_hash,
        "artifacts": {
            "unsw_u1_test_scores.jsonl": u1_score_hash,
            "unsw_u2_test_scores.jsonl": u2_score_hash,
            "unsw_u1_test_metrics.json": u1_metrics_hash,
            "unsw_u2_test_metrics.json": u2_metrics_hash,
            "unsw_u1_test_confusion_matrix.json": u1_confusion_hash,
            "unsw_u2_test_confusion_matrix.json": u2_confusion_hash,
            "unsw_test_sensitivity_mask.json": sensitivity_hash,
            "unsw_stage_2_2_final_summary.json": summary_hash,
            "unsw_test_replay_record.json": replay_hash,
            "unsw_test_evaluation_provenance.json": provenance_hash,
        },
        "official_test_labels_used_only_for_final_evaluation": True,
        "public_score_files_contain_no_labels": True,
        "anomaly_not_attack": True,
    }
    manifest_hash = _write_json(OUTPUT_ROOT / "final_stage_2_2_manifest.json", manifest)
    return {
        "status": "PASS",
        "test_rows": EXPECTED_TEST_ROWS,
        "u1_metrics": u1_metrics,
        "u2_metrics": u2_metrics,
        "u1_confusion": u1_confusion,
        "u2_confusion": u2_confusion,
        "sensitivity": sensitivity,
        "summary": final_summary,
        "selection_lock_verified": True,
        "determinism": "PASS",
        "manifest_sha256": manifest_hash,
        "output_root": str(OUTPUT_ROOT),
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
