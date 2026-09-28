"""Stage 2.2C FortiGate U2 fit and descriptive U1/U2 comparison."""

from __future__ import annotations

import hashlib
import json
import pickle
import platform
import resource
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from ai_features.artifact import file_sha256
from anomaly.artifact import read_manifest, read_score_rows
from anomaly.input import EXPECTED_STAGE_1_7_FEATURE_SHA256, load_feature_bundle
from fortigate_u2 import compare_fortigate_scores, fit_reference_scaler, score_top_residuals
from unsupervised.models import U2Config, fit_u2, score_u2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEATURE_DIR = PROJECT_ROOT / "data" / "processed" / "stage_1_7"
U1_DIR = PROJECT_ROOT / "data" / "processed" / "stage_1_8"
OUTPUT_ROOT = PROJECT_ROOT / "data" / "processed" / "stage_2_2" / "fortigate" / "v1"
DATASET_ID = "FORTIGATE_REAL_LOG"
BRANCH_ID = "BRANCH_A_REAL_LOG"
APPROVED_STAGE_1_8_MANIFEST_SHA256 = "9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77"
U2_MODEL_VERSION = "stage_2.2c-u2/1.0"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _write_json(path: Path, value: object) -> str:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _json_bytes(value) + b"\n"
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> str:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"".join(_json_bytes(row) + b"\n" for row in rows)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _row_key(partition: str, number: int) -> str:
    return json.dumps([DATASET_ID, partition, number], separators=(",", ":"))


def _membership_hash(keys: list[str]) -> str:
    return hashlib.sha256(_json_bytes(keys)).hexdigest()


def _validate_u1_and_features() -> tuple[Any, tuple[Any, ...], tuple[Any, ...], dict[str, Any], dict[str, str]]:
    feature_bundle = load_feature_bundle(FEATURE_DIR, expected_feature_sha256=EXPECTED_STAGE_1_7_FEATURE_SHA256)
    manifest_path = U1_DIR / "stage_1_8_manifest.json"
    if file_sha256(manifest_path) != APPROVED_STAGE_1_8_MANIFEST_SHA256:
        raise RuntimeError("Stage 1.8 manifest SHA-256 does not match approved identity")
    manifest = read_manifest(manifest_path)
    for filename, expected in {
        "stage_1_8_anomaly_scores.jsonl": manifest["score_artifact_sha256"],
        "stage_1_8_isolation_forest.joblib": manifest["model_artifact_sha256"],
        "stage_1_8_model_metadata.json": manifest["model_metadata_sha256"],
    }.items():
        if file_sha256(U1_DIR / filename) != expected:
            raise RuntimeError(f"Stage 1.8 {filename} hash mismatch")
    score_rows = tuple(read_score_rows(U1_DIR / "stage_1_8_anomaly_scores.jsonl"))
    if len(feature_bundle.rows) != 100000 or len(score_rows) != 100000:
        raise RuntimeError("FortiGate Stage 1.7/1.8 row count mismatch")
    for feature, score in zip(feature_bundle.rows, score_rows, strict=True):
        if feature.source_record_number != score.source_record_number or feature.source_record_id != score.source_record_id or feature.partition != score.partition:
            raise RuntimeError("Stage 1.8 score provenance does not match Stage 1.7 features")
        if score.raw_abnormality != -score.model_score:
            raise RuntimeError("Stage 1.8 U1 score direction mismatch")
    before_hashes = {
        "stage_1_7_features": str(feature_bundle.feature_artifact_identity["sha256"]),
        "stage_1_8_manifest": file_sha256(manifest_path),
        "stage_1_8_scores": file_sha256(U1_DIR / "stage_1_8_anomaly_scores.jsonl"),
        "stage_1_8_model": file_sha256(U1_DIR / "stage_1_8_isolation_forest.joblib"),
    }
    reference = tuple(row for row in feature_bundle.rows if row.partition == "REFERENCE")
    holdout = tuple(row for row in feature_bundle.rows if row.partition == "HOLDOUT")
    if len(reference) != 79947 or len(holdout) != 20053:
        raise RuntimeError("FortiGate REFERENCE/HOLDOUT counts do not match Stage 1.7 contract")
    return feature_bundle, reference, holdout, manifest, before_hashes


def _score_rows(
    values: np.ndarray,
    rows: tuple[Any, ...],
    scaler: Any,
    bundle: Any,
    fit_membership_hash: str,
    feature_state_sha256: str,
) -> list[dict[str, object]]:
    scaled = np.ascontiguousarray(scaler.transform(values), dtype=np.float64)
    scores = score_u2(bundle, scaled)
    output: list[dict[str, object]] = []
    for row, score in zip(rows, scores, strict=True):
        partition = row.partition
        output.append({
            "schema_version": "1.0",
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "row_key": _row_key(partition, row.source_record_number),
            "split_id": partition,
            "model_id": "FORTIGATE_U2_MINIBATCHKMEANS",
            "model_version": U2_MODEL_VERSION,
            "fit_membership_sha256": fit_membership_hash,
            "feature_state_sha256": feature_state_sha256,
            "raw_abnormality": float(score),
            "score_direction": "HIGHER_MORE_ANOMALOUS",
            "fit_relationship": "IN_SAMPLE" if partition == "REFERENCE" else "HELD_OUT",
            "threshold_id": None,
            "decision": None,
            "chain_training_eligible": False,
        })
    return output


def run() -> dict[str, object]:
    if OUTPUT_ROOT.exists():
        raise RuntimeError(f"refusing to overwrite accepted FortiGate output root {OUTPUT_ROOT}")
    feature_bundle, reference, holdout, u1_manifest, before_hashes = _validate_u1_and_features()
    feature_names = list(feature_bundle.metadata["feature_names"])
    reference_matrix = np.ascontiguousarray(np.asarray([row.values for row in reference], dtype=np.float64))
    holdout_matrix = np.ascontiguousarray(np.asarray([row.values for row in holdout], dtype=np.float64))
    scaler = fit_reference_scaler(reference_matrix)
    scaled_reference = np.ascontiguousarray(scaler.transform(reference_matrix), dtype=np.float64)
    scaled_holdout = np.ascontiguousarray(scaler.transform(holdout_matrix), dtype=np.float64)
    config = U2Config()
    reference_keys = [_row_key("REFERENCE", row.source_record_number) for row in reference]
    fit_membership_hash = _membership_hash(reference_keys)
    fit_started = time.perf_counter()
    with threadpool_limits(limits=1):
        bundle = fit_u2(scaled_reference, reference_keys, config)
    fit_elapsed = time.perf_counter() - fit_started
    score_started = time.perf_counter()
    reference_scores = score_u2(bundle, scaled_reference)
    holdout_scores = score_u2(bundle, scaled_holdout)
    score_elapsed = time.perf_counter() - score_started
    serialized_bundle = pickle.dumps(bundle, protocol=pickle.HIGHEST_PROTOCOL)
    replay_bundle = pickle.loads(serialized_bundle)
    hash_order = sorted(
        range(len(holdout)),
        key=lambda index: hashlib.sha256(_json_bytes(["s2.2-full-replay-v1", _row_key("HOLDOUT", holdout[index].source_record_number)])).hexdigest(),
    )[:1000]
    replay_scores = score_u2(replay_bundle, scaled_holdout[hash_order])
    if not np.allclose(replay_scores, holdout_scores[hash_order], rtol=1e-10, atol=1e-12):
        raise RuntimeError("FortiGate U2 serialization replay mismatch")
    if not np.isfinite(reference_scores).all() or not np.isfinite(holdout_scores).all() or np.ptp(reference_scores) <= 0:
        raise RuntimeError("FortiGate U2 produced invalid or degenerate scores")
    feature_state_payload = {
        "schema_version": "stage_2.2c-fortigate-scaler/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "feature_names": feature_names,
        "fit_split": "REFERENCE",
        "fit_row_count": len(reference),
        "mean": [float(value) for value in scaler.mean_],
        "scale": [float(value) for value in scaler.scale_],
        "var": [float(value) for value in scaler.var_],
        "dtype": "float64",
        "feature_artifact_sha256": before_hashes["stage_1_7_features"],
    }
    feature_state_sha256 = hashlib.sha256(_json_bytes(feature_state_payload)).hexdigest()
    reference_u2_rows = _score_rows(reference_matrix, reference, scaler, bundle, fit_membership_hash, feature_state_sha256)
    holdout_u2_rows = _score_rows(holdout_matrix, holdout, scaler, bundle, fit_membership_hash, feature_state_sha256)
    u2_by_number = {
        json.loads(row["row_key"])[2]: row
        for row in (*reference_u2_rows, *holdout_u2_rows)
    }
    u2_rows = [u2_by_number[row.source_record_number] for row in feature_bundle.rows]
    u1_by_number = {row.source_record_number: row for row in tuple(read_score_rows(U1_DIR / "stage_1_8_anomaly_scores.jsonl"))}
    comparison = compare_fortigate_scores(
        [row.source_record_number for row in holdout],
        [u1_by_number[row.source_record_number].raw_abnormality for row in holdout],
        holdout_scores,
        reference_u1=[row.raw_abnormality for row in u1_by_number.values() if row.partition == "REFERENCE"],
        reference_u2=reference_scores,
    )
    top_explanations = score_top_residuals(scaled_holdout, bundle.model.cluster_centers_, [row.source_record_number for row in holdout], feature_names)
    output_root = OUTPUT_ROOT
    scaler_path = output_root / "fortigate_u2_standard_scaler.joblib"
    model_path = output_root / "fortigate_u2_minibatch_kmeans.joblib"
    score_path = output_root / "fortigate_u2_scores.jsonl"
    comparison_path = output_root / "fortigate_u1_u2_comparison.json"
    explanations_path = output_root / "fortigate_u2_top50_explanations.json"
    state_path = output_root / "fortigate_u2_scaler_state.json"
    scaler_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, scaler_path)
    joblib.dump(bundle, model_path)
    score_hash = _write_jsonl(score_path, u2_rows)
    comparison_hash = _write_json(comparison_path, {
        "schema_version": "stage_2.2c-fortigate-comparison/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "u1_score_artifact_sha256": before_hashes["stage_1_8_scores"],
        "u2_score_artifact_sha256": score_hash,
        "holdout": comparison["holdout"],
        "reference_descriptive": compare_fortigate_scores(
            [row.source_record_number for row in reference],
            [u1_by_number[row.source_record_number].raw_abnormality for row in reference],
            reference_scores,
            reference_u1=[row.raw_abnormality for row in u1_by_number.values() if row.partition == "REFERENCE"],
            reference_u2=reference_scores,
        )["holdout"],
        "all_rows_descriptive": compare_fortigate_scores(
            [row.source_record_number for row in feature_bundle.rows],
            [u1_by_number[row.source_record_number].raw_abnormality for row in feature_bundle.rows],
            [u2_by_number[row.source_record_number]["raw_abnormality"] for row in feature_bundle.rows],
            reference_u1=[row.raw_abnormality for row in u1_by_number.values() if row.partition == "REFERENCE"],
            reference_u2=reference_scores,
        )["holdout"],
        "ground_truth_metrics": "NOT_APPLICABLE_FORTIGATE_NO_CANONICAL_ATTACK_BENIGN_LABELS",
    })
    explanations_hash = _write_json(explanations_path, {
        "schema_version": "stage_2.2c-fortigate-u2-explanations/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "score_direction": "HIGHER_MORE_ANOMALOUS",
        "explanations": top_explanations,
    })
    state_hash = _write_json(state_path, feature_state_payload)
    after_hashes = {
        name: file_sha256(path)
        for name, path in {
            "stage_1_7_features": FEATURE_DIR / "stage_1_7_ai_features.jsonl",
            "stage_1_8_manifest": U1_DIR / "stage_1_8_manifest.json",
            "stage_1_8_scores": U1_DIR / "stage_1_8_anomaly_scores.jsonl",
            "stage_1_8_model": U1_DIR / "stage_1_8_isolation_forest.joblib",
        }.items()
    }
    if before_hashes != after_hashes:
        raise RuntimeError("frozen U1 or Stage 1.7 artifact changed during U2 run")
    manifest = {
        "schema_version": "stage_2.2c-fortigate-manifest/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": "docs/plans/stage_2_2_unsupervised_model_comparison_plan.md",
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "fit_split": "REFERENCE",
        "reference_row_count": len(reference),
        "holdout_row_count": len(holdout),
        "feature_artifact_sha256": before_hashes["stage_1_7_features"],
        "u1_manifest_sha256": before_hashes["stage_1_8_manifest"],
        "u1_model_sha256": before_hashes["stage_1_8_model"],
        "u1_score_sha256": before_hashes["stage_1_8_scores"],
        "u2_config": config.to_dict(),
        "u2_score_direction": "HIGHER_MORE_ANOMALOUS",
        "u2_fit_membership_sha256": fit_membership_hash,
        "u2_scaler_state_sha256": state_hash,
        "u2_scaler_file_sha256": file_sha256(scaler_path),
        "u2_model_file_sha256": file_sha256(model_path),
        "u2_score_file_sha256": score_hash,
        "comparison_file_sha256": comparison_hash,
        "explanations_file_sha256": explanations_hash,
        "resource": {
            "python": platform.python_version(),
            "fit_elapsed_seconds": fit_elapsed,
            "score_elapsed_seconds": score_elapsed,
            "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        },
        "u1_modified": False,
        "datasets_merged": False,
        "unsw_test_used": False,
        "supervised_metrics": "NOT_CLAIMED",
    }
    manifest_hash = _write_json(output_root / "manifest.json", manifest)
    return {
        "status": "PASS",
        "rows_scored": len(u2_rows),
        "holdout_rows": len(holdout),
        "u2_score_sha256": score_hash,
        "comparison_sha256": comparison_hash,
        "manifest_sha256": manifest_hash,
        "output_root": str(output_root),
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
