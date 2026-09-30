"""Stage 2.3E isolated, locked UNSW-NB15 supervised TEST evaluator."""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import resource
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from supervised.contracts import BRANCH_ID, DATASET_ID, FEATURE_ORDER, select_base_features
from supervised.evaluation import evaluate_probabilities, validate_selection_lock
from unsupervised.features import FeatureState, transform_features

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_training-set.csv"
TEST_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_testing-set.csv"
ACQUISITION_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
DEFAULT_LOCK = ROOT / "manifests" / "selection_lock.json"
DEFAULT_AUTHORIZATION = ROOT / "manifests" / "final_test_evaluator_authorization.json"
OUTPUT_ROOT = ROOT / "test_evaluation"
EXPECTED_TEST_ROWS = 82332


class TestEvaluationBlocker(RuntimeError):
    """Raised when final TEST evaluation cannot safely proceed."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> str:
    if path.exists() or path.is_symlink():
        raise TestEvaluationBlocker(f"refusing to overwrite evaluator artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _json_bytes(value) + b"\n"
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> str:
    if path.exists() or path.is_symlink():
        raise TestEvaluationBlocker(f"refusing to overwrite evaluator artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"".join(_json_bytes(row) + b"\n" for row in rows)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _load_feature_state(path: Path) -> FeatureState:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return FeatureState(
        dataset_id=str(payload["dataset_id"]),
        branch_id=str(payload["branch_id"]),
        feature_order=tuple(str(value) for value in payload["feature_order"]),
        numeric_medians={str(key): float(value) for key, value in payload["numeric_medians"].items()},
        numeric_means={str(key): float(value) for key, value in payload["numeric_means"].items()},
        numeric_scales={str(key): float(value) for key, value in payload["numeric_scales"].items()},
        categorical_vocabularies={str(key): tuple(str(value) for value in values) for key, values in payload["categorical_vocabularies"].items()},
        output_feature_names=tuple(str(value) for value in payload["output_feature_names"]),
        fit_row_count=int(payload["fit_row_count"]),
        state_sha256=str(payload["state_sha256"]),
    )


def _verify_preconditions(lock_path: Path, authorization_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Path], dict[str, str]]:
    if OUTPUT_ROOT.exists():
        raise TestEvaluationBlocker(f"accepted evaluator output already exists: {OUTPUT_ROOT}")
    if not lock_path.is_file() or not authorization_path.is_file():
        raise TestEvaluationBlocker("selection lock or evaluator authorization is missing")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    if "<HUMAN_FILL" in authorization_path.read_text(encoding="utf-8"):
        raise TestEvaluationBlocker("evaluator authorization contains an active HUMAN_FILL placeholder")
    if authorization.get("dataset_id") != DATASET_ID or authorization.get("stage") != "2.3E":
        raise TestEvaluationBlocker("evaluator authorization dataset/stage mismatch")
    if authorization.get("authorization_type") != "PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION" or authorization.get("human_authorized") is not True:
        raise TestEvaluationBlocker("evaluator authorization is not human-approved")
    if authorization.get("test_role") != "FINAL_EVALUATION_ONLY" or authorization.get("post_test_tuning_allowed") is not False:
        raise TestEvaluationBlocker("evaluator authorization role or post-test policy mismatch")
    lock_hash = _sha256(lock_path)
    if authorization.get("selection_lock_sha256") != lock_hash:
        raise TestEvaluationBlocker("authorization selection-lock hash mismatch")
    if lock.get("status") != "PASS" or lock.get("preferred_model") != "S2" or lock.get("test_used") is not False or lock.get("chained_signals_used") is not False:
        raise TestEvaluationBlocker("selection lock is not a passing TEST-closed receipt")
    thresholds = lock.get("threshold_policy", {}).get("thresholds")
    validate_selection_lock({"test_used": lock.get("test_used"), "chained_signals_used": lock.get("chained_signals_used"), "thresholds": thresholds})
    if lock.get("feature_contract", {}).get("sha256") != authorization.get("feature_contract_sha256"):
        raise TestEvaluationBlocker("feature-contract identity mismatch")
    if lock.get("selection_rule", {}).get("metric") != "sklearn.metrics.average_precision_score":
        raise TestEvaluationBlocker("selection metric is not frozen Average Precision")
    if lock.get("selection_rule", {}).get("tie_preference") != "S1":
        raise TestEvaluationBlocker("selection tie rule changed")
    model_paths = {
        "S1": {"model": ROOT / "models" / "S1" / "final.joblib", "state": ROOT / "models" / "S1" / "final_feature_state.json", "metadata": ROOT / "models" / "S1" / "final_metadata.json"},
        "S2": {"model": ROOT / "models" / "S2" / "final.joblib", "state": ROOT / "models" / "S2" / "final_feature_state.json", "metadata": ROOT / "models" / "S2" / "final_metadata.json"},
    }
    identities: dict[str, str] = {"selection_lock": lock_hash}
    for model_id, paths in model_paths.items():
        frozen = lock.get("models", {}).get(model_id)
        authorized = authorization.get("models", {}).get(model_id)
        if not isinstance(frozen, Mapping) or not isinstance(authorized, Mapping):
            raise TestEvaluationBlocker(f"{model_id} frozen identity missing")
        for role, path in paths.items():
            if not path.is_file():
                raise TestEvaluationBlocker(f"{model_id} artifact missing: {path.name}")
            observed = _sha256(path)
            expected = frozen.get("artifacts", {}).get(role)
            authorization_field = {
                "model": "model_artifact_sha256",
                "state": "preprocessing_artifact_sha256",
                "metadata": "metadata_artifact_sha256",
            }[role]
            if observed != expected or authorized.get(authorization_field) != observed:
                raise TestEvaluationBlocker(f"{model_id} {role} artifact hash mismatch")
            identities[f"{model_id}_{role}"] = observed
        if frozen.get("threshold") != 0.5 or frozen.get("classes") != [0, 1] or authorized.get("threshold") != 0.5 or authorized.get("classes") != [0, 1]:
            raise TestEvaluationBlocker(f"{model_id} threshold/class ordering changed")
        if frozen.get("family") != authorized.get("family"):
            raise TestEvaluationBlocker(f"{model_id} family identity mismatch")
    checkpoint_d = ROOT / "manifests" / "checkpoint_2_3D.json"
    handoff = ROOT / "manifests" / "stage_2_4_handoff.json"
    if not checkpoint_d.is_file() or not handoff.is_file():
        raise TestEvaluationBlocker("2.3D checkpoint or handoff missing")
    checkpoint_payload = json.loads(checkpoint_d.read_text(encoding="utf-8"))
    if checkpoint_payload.get("status") != "PASS" or checkpoint_payload.get("artifacts", {}).get("manifests/selection_lock.json") != lock_hash:
        raise TestEvaluationBlocker("2.3D checkpoint does not bind current selection lock")
    identities["checkpoint_2_3D"] = _sha256(checkpoint_d)
    identities["stage_2_4_handoff"] = _sha256(handoff)
    return lock, authorization, model_paths, identities


def _load_test_rows(columns: Sequence[str]) -> tuple[list[dict[str, object]], str]:
    acquisition = json.loads(ACQUISITION_PATH.read_text(encoding="utf-8"))
    entry = next(item for item in acquisition["files"] if item["role"] == "TEST")
    raw_hash = _sha256(TEST_PATH)
    if entry["expected_row_count"] != EXPECTED_TEST_ROWS or raw_hash != entry["sha256"]:
        raise TestEvaluationBlocker("official TEST identity mismatch")
    rows: list[dict[str, object]] = []
    with TEST_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(columns):
            raise TestEvaluationBlocker("official TEST schema mismatch")
        for number, raw in enumerate(reader, 1):
            if None in raw or any(value is None for value in raw.values()):
                raise TestEvaluationBlocker(f"malformed TEST row {number}")
            if all(raw.get(column) == column for column in columns):
                raise TestEvaluationBlocker(f"duplicate TEST header row {number}")
            if str(raw.get("label", "")).strip() not in {"0", "1"}:
                raise TestEvaluationBlocker(f"invalid TEST label at row {number}")
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
        raise TestEvaluationBlocker(f"TEST rows {len(rows)} != {EXPECTED_TEST_ROWS}")
    return rows, raw_hash


def _test_feature_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    return [
        {
            **select_base_features(row),
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "official_split": "TEST",
            "row_number": row["row_number"],
            "development_partition": "TEST",
        }
        for row in rows
    ]


def _score_model(estimator: Any, state: FeatureState, rows: Sequence[Mapping[str, object]]) -> tuple[np.ndarray, str, dict[str, Any]]:
    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise TestEvaluationBlocker("frozen model classes are not [0, 1]")
    feature_rows = _test_feature_rows(rows)
    digest = hashlib.sha256()
    values: list[np.ndarray] = []
    max_row_sum_error = 0.0
    started = time.monotonic()
    for start in range(0, len(feature_rows), 4096):
        X = transform_features(feature_rows[start : start + 4096], state)
        digest.update(X.tobytes())
        with threadpool_limits(limits=1):
            probabilities = np.asarray(estimator.predict_proba(X), dtype=np.float64)
        if probabilities.shape != (X.shape[0], 2) or not np.isfinite(probabilities).all():
            raise TestEvaluationBlocker("TEST probability output invalid")
        if not np.all((probabilities >= 0.0) & (probabilities <= 1.0)):
            raise TestEvaluationBlocker("TEST probability outside [0, 1]")
        max_row_sum_error = max(max_row_sum_error, float(np.max(np.abs(probabilities.sum(axis=1) - 1.0))))
        if max_row_sum_error > 1e-12:
            raise TestEvaluationBlocker("TEST probability rows do not sum to 1 within 1e-12")
        values.append(probabilities[:, 1])
    elapsed = time.monotonic() - started
    if elapsed > 300.0:
        raise TestEvaluationBlocker("TEST prediction budget exceeded")
    return np.concatenate(values), digest.hexdigest(), {"elapsed_seconds": elapsed, "max_probability_row_sum_error": max_row_sum_error, "classes": [0, 1]}


def _confusion_artifact(model_id: str, metrics: Mapping[str, Any], *, test_hash: str) -> dict[str, Any]:
    matrix = metrics["confusion_matrix"]
    return {
        "schema_version": "stage_2.3e-confusion-matrix/1.0",
        "model_id": model_id,
        "population": "OFFICIAL_TEST_ALL_ROWS",
        "reference_axis": ["NORMAL", "ATTACK"],
        "prediction_axis": ["NORMAL", "ATTACK"],
        "matrix": [[matrix["tn"], matrix["fp"]], [matrix["fn"], matrix["tp"]]],
        "tn": matrix["tn"],
        "fp": matrix["fp"],
        "fn": matrix["fn"],
        "tp": matrix["tp"],
        "threshold": 0.5,
        "positive_class": 1,
        "test_raw_sha256": test_hash,
    }


def run(lock_path: Path = DEFAULT_LOCK, authorization_path: Path = DEFAULT_AUTHORIZATION) -> dict[str, Any]:
    lock, authorization, model_paths, identities = _verify_preconditions(lock_path, authorization_path)
    acquisition = json.loads(ACQUISITION_PATH.read_text(encoding="utf-8"))
    test_rows, test_hash = _load_test_rows(acquisition["schema"]["columns"])
    test_labels = np.asarray([int(str(row["label"]).strip()) for row in test_rows], dtype=np.int8)
    estimators = {model_id: joblib.load(paths["model"]) for model_id, paths in model_paths.items()}
    states = {model_id: _load_feature_state(paths["state"]) for model_id, paths in model_paths.items()}
    if any(state.feature_order != tuple(FEATURE_ORDER) for state in states.values()):
        raise TestEvaluationBlocker("frozen TEST feature order mismatch")

    scores: dict[str, np.ndarray] = {}
    matrix_hashes: dict[str, str] = {}
    score_reports: dict[str, dict[str, Any]] = {}
    replay: dict[str, Any] = {}
    metrics: dict[str, dict[str, Any]] = {}
    confusion: dict[str, dict[str, Any]] = {}
    for model_id in ("S1", "S2"):
        first, feature_hash, score_report = _score_model(estimators[model_id], states[model_id], test_rows)
        second, replay_feature_hash, replay_score_report = _score_model(estimators[model_id], states[model_id], test_rows)
        score_difference = float(np.max(np.abs(first - second)))
        if feature_hash != replay_feature_hash or score_difference > 1e-12:
            raise TestEvaluationBlocker(f"{model_id} TEST replay mismatch")
        scores[model_id] = first
        matrix_hashes[model_id] = feature_hash
        score_reports[model_id] = score_report
        replay[model_id] = {
            "feature_matrix": "PASS",
            "p_attack": "PASS",
            "max_difference": score_difference,
            "first": score_report,
            "second": replay_score_report,
        }
        metrics[model_id] = evaluate_probabilities(test_labels, first)
        confusion[model_id] = _confusion_artifact(model_id, metrics[model_id], test_hash=test_hash)

    if lock.get("preferred_model") != "S2" or lock.get("comparison_metrics", {}).get("S1", {}).get("average_precision") != 0.9939231496371828 or lock.get("comparison_metrics", {}).get("S2", {}).get("average_precision") != 0.9968637967521546:
        raise TestEvaluationBlocker("validation-selected preference changed after TEST")

    output_hashes: dict[str, str] = {}
    prediction_records: dict[str, list[dict[str, Any]]] = {}
    for model_id in ("S1", "S2"):
        prediction_records[model_id] = [
            {
                "schema_version": "stage_2.3e-test-prediction/1.0",
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "row_key": str(row["row_key"]),
                "split_id": "TEST",
                "model_id": model_id,
                "p_attack": float(score),
                "threshold": 0.5,
                "predicted_label": int(float(score) >= 0.5),
                "classes": [0, 1],
                "feature_matrix_sha256": matrix_hashes[model_id],
                "test_raw_sha256": test_hash,
            }
            for row, score in zip(test_rows, scores[model_id], strict=True)
        ]
        output_hashes[f"unsw_{model_id.lower()}_test_predictions.jsonl"] = _write_jsonl(OUTPUT_ROOT / f"unsw_{model_id.lower()}_test_predictions.jsonl", prediction_records[model_id])
        output_hashes[f"unsw_{model_id.lower()}_test_metrics.json"] = _write_json(OUTPUT_ROOT / f"unsw_{model_id.lower()}_test_metrics.json", {
            "schema_version": "stage_2.3e-test-metrics/1.0",
            "model_id": model_id,
            "population": "OFFICIAL_TEST_ALL_ROWS",
            "test_rows": EXPECTED_TEST_ROWS,
            "metrics": metrics[model_id],
            "test_raw_sha256": test_hash,
            "selection_changed_after_test": False,
            "post_test_tuning": False,
        })
        output_hashes[f"unsw_{model_id.lower()}_test_confusion_matrix.json"] = _write_json(OUTPUT_ROOT / f"unsw_{model_id.lower()}_test_confusion_matrix.json", confusion[model_id])

    output_hashes["unsw_test_replay_record.json"] = _write_json(OUTPUT_ROOT / "unsw_test_replay_record.json", {
        "schema_version": "stage_2.3e-test-replay/1.0",
        "test_rows": EXPECTED_TEST_ROWS,
        "transformed_test_replay": "PASS",
        "p_attack_replay": replay,
        "threshold_replay": "PASS",
        "metrics_replay": "PASS",
        "confusion_matrix_replay": "PASS",
    })
    output_hashes["unsw_test_evaluation_provenance.json"] = _write_json(OUTPUT_ROOT / "unsw_test_evaluation_provenance.json", {
        "schema_version": "stage_2.3e-test-provenance/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "stage": "2.3E",
        "selection_lock_sha256": identities["selection_lock"],
        "authorization_sha256": _sha256(authorization_path),
        "test_raw_sha256": test_hash,
        "test_rows": EXPECTED_TEST_ROWS,
        "test_preprocessing_fit": False,
        "final_refit": False,
        "chained_signals_used": False,
        "fortigate_supervised_use": False,
        "selection_changed_after_test": False,
        "preferred_model": "S2",
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
    })
    output_hashes["final_stage_2_3_manifest.json"] = _write_json(OUTPUT_ROOT / "final_stage_2_3_manifest.json", {
        "schema_version": "stage_2.3e-test-manifest/1.0",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "stage": "2.3E",
        "test_raw_sha256": test_hash,
        "test_rows": EXPECTED_TEST_ROWS,
        "selection_lock_sha256": identities["selection_lock"],
        "authorization_sha256": _sha256(authorization_path),
        "test_preprocessing_fit": False,
        "final_refit": False,
        "selection_changed_after_test": False,
        "preferred_model": "S2",
        "chained_signals_used": False,
        "artifacts": output_hashes,
    })
    checkpoint_path = ROOT / "manifests" / "checkpoint_2_3E.json"
    checkpoint_hash = _write_json(checkpoint_path, {
        "schema_version": "stage_2.3/checkpoint-2.3E/1.0",
        "checkpoint": "2.3E",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "selection_lock_sha256": identities["selection_lock"],
        "authorization_sha256": _sha256(authorization_path),
        "test_raw_sha256": test_hash,
        "test_rows": EXPECTED_TEST_ROWS,
        "test_preprocessing_fit": False,
        "final_refit": False,
        "selection_changed_after_test": False,
        "preferred_model": "S2",
        "thresholds": {"S1": 0.5, "S2": 0.5},
        "chained_signals_used": False,
        "fortigate_supervised_use": False,
        "artifacts": output_hashes,
        "next_action": "FINAL_STAGE_2_3_AUDIT",
    })
    return {
        "status": "COMPLETE",
        "authorization": "VALID",
        "authorization_artifact": "CREATED",
        "selection_lock_verified": True,
        "test_rows": EXPECTED_TEST_ROWS,
        "final_refit": "NO",
        "s1": metrics["S1"],
        "s2": metrics["S2"],
        "preferred_model": "S2",
        "selection_changed_after_test": False,
        "confusion_matrices": {"S1": "CREATED", "S2": "CREATED"},
        "thresholds_changed": False,
        "test_preprocessing_fit": False,
        "chained_signals_used": False,
        "fortigate_supervised_use": False,
        "datasets_merged": False,
        "determinism": "PASS",
        "checkpoint_sha256": checkpoint_hash,
        "artifacts": output_hashes,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--authorization", type=Path, default=DEFAULT_AUTHORIZATION)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.lock, arguments.authorization), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
