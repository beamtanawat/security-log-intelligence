"""Stage 2.4E locked, inference-only chained TEST evaluator.

This module is deliberately separate from TRAIN/development orchestration.  It
validates every frozen identity before opening the official TEST CSV, writes
predictions before reading TEST labels for metrics, and refuses to overwrite
any protected or accepted artifact.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pickle
import platform
import resource
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from chained.contracts import BASE_FEATURES, BRANCH_ID, DATASET_ID, canonical_json_bytes, sha256_file
from chained.models import SignalScaler, predict_chain_s1, predict_chain_s2, transform_chain_features
from chained.signals import feature_state_from_dict, score_u1
from supervised.evaluation import evaluate_probabilities
from unsupervised.features import transform_features
from unsupervised.models import score_u2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STAGE_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
TEST_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_testing-set.csv"
ACQUISITION_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
AUTH_PATH = STAGE_ROOT / "manifests" / "final_test_evaluator_authorization.json"
LOCK_PATH = STAGE_ROOT / "manifests" / "selection_lock.json"
OUTPUT_ROOT = STAGE_ROOT / "test_evaluation"
EXPECTED_TEST_ROWS = 82332
TEST_SHA256 = "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559"
STAGE2_2_SENSITIVITY = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_2" / "v1" / "test_evaluation" / "unsw_test_sensitivity_mask.json"


class EvaluationBlocker(ValueError):
    """Raised for any failed 2.4E boundary or integrity check."""


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvaluationBlocker(f"JSON object required: {path}")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_json(value: object) -> str:
    return _sha256_bytes(_canonical(value))


def _write_json(path: Path, payload: Mapping[str, object]) -> str:
    if path.exists() or path.is_symlink():
        raise EvaluationBlocker(f"refusing to overwrite {path}")
    data = canonical_json_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return _sha256_bytes(data)


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> str:
    if path.exists() or path.is_symlink():
        raise EvaluationBlocker(f"refusing to overwrite {path}")
    data = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return _sha256_bytes(data)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise EvaluationBlocker(f"JSON object line required: {path}")
                rows.append(value)
    return rows


def _require_hash(path: Path, expected: str, label: str) -> str:
    if not path.is_file():
        raise EvaluationBlocker(f"missing {label}: {path}")
    observed = sha256_file(path)
    if observed != expected:
        raise EvaluationBlocker(f"{label} hash mismatch")
    return observed


def _contains_placeholder(value: object) -> bool:
    return "<HUMAN_FILL>" in json.dumps(value, ensure_ascii=False, sort_keys=True)


def validate_authorization_boundary(lock: Mapping[str, object], authorization: Mapping[str, object], lock_hash: str) -> dict[str, object]:
    """Validate public human authorization and unopened development lock."""

    required_auth = {
        "schema_version": "stage_2.4-final-evaluator-authorization/1.0",
        "dataset_id": "UNSW-NB15",
        "artifact_dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "stage": "2.4E",
        "authorization_type": "PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION",
        "human_authorized": True,
        "selection_lock_sha256": lock_hash,
        "test_role": "FINAL_EVALUATION_ONLY",
        "post_test_tuning_allowed": False,
        "evaluator_boundary_version": "S2.4-PUBLIC-FINAL-EVALUATOR-V1",
        "prior_test_results_used_for_development": False,
        "test_used_for_development": False,
    }
    if _contains_placeholder(authorization):
        raise EvaluationBlocker("human authorization contains unresolved placeholder")
    for field, expected in required_auth.items():
        if authorization.get(field) != expected:
            raise EvaluationBlocker(f"authorization boundary mismatch: {field}")
    if not isinstance(authorization.get("authorized_at_utc"), str) or "T" not in str(authorization["authorized_at_utc"]):
        raise EvaluationBlocker("authorization timestamp is missing")
    if not authorization.get("human_approval_reference") or not authorization.get("human_approval_sha256"):
        raise EvaluationBlocker("human approval reference/hash is missing")
    if lock.get("status") != "PASS" or lock.get("dataset_id") != DATASET_ID or lock.get("branch_id") != BRANCH_ID:
        raise EvaluationBlocker("selection lock identity/status failed")
    if lock.get("checkpoint") != "2.4D" or lock.get("test_used") is not False or lock.get("test_role") != "LOCKED_FROM_DEVELOPMENT":
        raise EvaluationBlocker("selection lock TEST boundary failed")
    if lock.get("no_post_test_tuning") is not True:
        raise EvaluationBlocker("selection lock does not enforce no post-TEST tuning")
    chain_features = lock.get("chain_features")
    if not isinstance(chain_features, Mapping) or chain_features.get("source_feature_count") != 30:
        raise EvaluationBlocker("chain feature count is not frozen at 30")
    threshold_policy = lock.get("threshold_policy")
    if threshold_policy != {"CHAIN-S1": 0.5, "CHAIN-S2": 0.5, "post_test_tuning_allowed": False}:
        raise EvaluationBlocker("chain threshold policy changed")
    crossfit = lock.get("crossfit")
    if not isinstance(crossfit, Mapping) or authorization.get("crossfit_contract_sha256") != crossfit.get("contract_sha256"):
        raise EvaluationBlocker("cross-fit contract identity mismatch")
    return {"status": "PASS", "lock_hash": lock_hash, "human_authorized": True, "test_opened": False}


def _baseline_snapshot(root: Path) -> tuple[dict[str, str], dict[str, Any], dict[str, list[dict[str, Any]]]]:
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1" / "test_evaluation"
    manifest_path = baseline_root / "final_stage_2_3_manifest.json"
    manifest = _read_json(manifest_path)
    snapshot: dict[str, str] = {}
    for name, expected in dict(manifest.get("artifacts", {})).items():
        path = baseline_root / name
        snapshot[name] = _require_hash(path, str(expected), f"baseline {name}")
    if manifest.get("test_raw_sha256") != TEST_SHA256 or manifest.get("test_rows") != EXPECTED_TEST_ROWS:
        raise EvaluationBlocker("baseline TEST identity differs")
    prediction_rows = {
        "S1": _read_jsonl(baseline_root / "unsw_s1_test_predictions.jsonl"),
        "S2": _read_jsonl(baseline_root / "unsw_s2_test_predictions.jsonl"),
    }
    for model_id, rows in prediction_rows.items():
        if len(rows) != EXPECTED_TEST_ROWS or [row.get("row_key") for row in rows] != [json.dumps([DATASET_ID, "TEST", i], separators=(",", ":")) for i in range(1, EXPECTED_TEST_ROWS + 1)]:
            raise EvaluationBlocker(f"baseline {model_id} row identity mismatch")
        if any(row.get("model_id") != model_id or float(row.get("threshold")) != 0.5 for row in rows):
            raise EvaluationBlocker(f"baseline {model_id} prediction contract mismatch")
    return snapshot, manifest, prediction_rows


def _preflight(root: Path, lock_path: Path, authorization_path: Path) -> dict[str, Any]:
    if OUTPUT_ROOT.exists():
        raise EvaluationBlocker(f"refusing to overwrite accepted TEST-evaluation root {OUTPUT_ROOT}")
    lock = _read_json(lock_path)
    authorization = _read_json(authorization_path)
    lock_hash = sha256_file(lock_path)
    boundary = validate_authorization_boundary(lock, authorization, lock_hash)
    if authorization.get("chain_contract_sha256") != sha256_file(STAGE_ROOT / "contracts" / "chain_contract.json"):
        raise EvaluationBlocker("chain contract hash differs from authorization")
    if authorization.get("crossfit_contract_sha256") != sha256_file(STAGE_ROOT / "manifests" / "crossfit_contract.json"):
        raise EvaluationBlocker("cross-fit contract hash differs from authorization")
    checkpoint = _read_json(STAGE_ROOT / "manifests" / "checkpoint_2_4D.json")
    if checkpoint.get("status") != "PASS" or checkpoint.get("test_used") is not False or checkpoint.get("selection_lock_sha256") != lock_hash:
        raise EvaluationBlocker("2.4D checkpoint boundary failed")

    auth_models = authorization.get("models")
    lock_models = lock.get("models")
    if not isinstance(auth_models, Mapping) or not isinstance(lock_models, Mapping):
        raise EvaluationBlocker("frozen chain model identities missing")
    for model_id in ("CHAIN-S1", "CHAIN-S2"):
        model_records = lock_models.get(model_id, {}).get("artifacts", []) if isinstance(lock_models.get(model_id), Mapping) else []
        final = next((item for item in model_records if item.get("context_id") == "final_train_inference"), None)
        auth = auth_models.get(model_id)
        if not isinstance(final, Mapping) or not isinstance(auth, Mapping):
            raise EvaluationBlocker(f"missing final {model_id} identity")
        model_path = STAGE_ROOT / str(final["model"])
        metadata_path = STAGE_ROOT / str(final["metadata"])
        state_path = STAGE_ROOT / str(final["base_state"])
        scaler_path = STAGE_ROOT / str(final["signal_scaler"])
        _require_hash(model_path, str(final["model_sha256"]), f"{model_id} model")
        _require_hash(metadata_path, str(final["metadata_sha256"]), f"{model_id} metadata")
        _require_hash(state_path, str(final["base_state_sha256"]), f"{model_id} preprocessing")
        _require_hash(scaler_path, str(final["signal_scaler_sha256"]), f"{model_id} signal scaler")
        if auth.get("model_artifact_sha256") != final.get("model_sha256") or auth.get("metadata_artifact_sha256") != final.get("metadata_sha256"):
            raise EvaluationBlocker(f"{model_id} authorization hash mismatch")
        if auth.get("preprocessing_artifact_sha256") != final.get("base_state_sha256") or auth.get("signal_scaler_artifact_sha256") != final.get("signal_scaler_sha256"):
            raise EvaluationBlocker(f"{model_id} downstream artifact hash mismatch")
        metadata = _read_json(metadata_path)
        state = _read_json(state_path)
        scaler = _read_json(scaler_path)
        if metadata.get("model_id") != model_id or metadata.get("classes") != [0, 1] or metadata.get("threshold") != 0.5 or metadata.get("source_feature_count") != 30 or metadata.get("test_used") is not False:
            raise EvaluationBlocker(f"{model_id} metadata contract failed")
        if auth.get("preprocessing_state_sha256") != state.get("state_sha256") or auth.get("signal_scaler_state_sha256") != scaler.get("state_sha256"):
            raise EvaluationBlocker(f"{model_id} downstream state hash mismatch")

    u_identity = {"U1": authorization.get("u1_inference"), "U2": authorization.get("u2_inference")}
    for model_id, auth in u_identity.items():
        if not isinstance(auth, Mapping):
            raise EvaluationBlocker(f"{model_id} inference identity missing")
        model_path = STAGE_ROOT / "models" / "final_train_inference" / f"{model_id}.joblib"
        metadata_path = STAGE_ROOT / "models" / "final_train_inference" / f"{model_id}_metadata.json"
        _require_hash(model_path, str(auth["model_artifact_sha256"]), f"{model_id} model")
        metadata = _read_json(metadata_path)
        if metadata.get("test_used") is not False or metadata.get("labels_used") is not False or metadata.get("attack_cat_used") is not False:
            raise EvaluationBlocker(f"{model_id} inference metadata boundary failed")
        if metadata.get("model_artifact_sha256") != auth.get("model_artifact_sha256") or sha256_file(STAGE_ROOT / "models" / "final_train_inference" / "preprocessing_state.json") != auth.get("preprocessing_artifact_sha256"):
            raise EvaluationBlocker(f"{model_id} inference identity mismatch")

    acquisition = _read_json(ACQUISITION_PATH)
    test_entry = next((item for item in acquisition.get("files", []) if item.get("role") == "TEST"), None)
    if not isinstance(test_entry, Mapping) or test_entry.get("filename") != TEST_PATH.name or test_entry.get("expected_row_count") != EXPECTED_TEST_ROWS or test_entry.get("sha256") != TEST_SHA256:
        raise EvaluationBlocker("acquisition TEST identity mismatch")
    baseline_hashes, baseline_manifest, baseline_predictions = _baseline_snapshot(root)
    return {
        "lock": lock,
        "authorization": authorization,
        "lock_hash": lock_hash,
        "authorization_hash": sha256_file(authorization_path),
        "boundary": boundary,
        "checkpoint_2_4D": checkpoint,
        "baseline_hashes": baseline_hashes,
        "baseline_manifest": baseline_manifest,
        "baseline_predictions": baseline_predictions,
        "protected_paths": [lock_path, authorization_path, STAGE_ROOT / "contracts" / "chain_contract.json", STAGE_ROOT / "manifests" / "crossfit_contract.json"],
    }


def _load_test_rows(columns: Sequence[str]) -> tuple[list[dict[str, Any]], str]:
    if not TEST_PATH.is_file():
        raise EvaluationBlocker("official TEST CSV is missing")
    raw_hash = sha256_file(TEST_PATH)
    if raw_hash != TEST_SHA256:
        raise EvaluationBlocker("official TEST SHA-256 differs from acquisition identity")
    rows: list[dict[str, Any]] = []
    with TEST_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(columns):
            raise EvaluationBlocker("official TEST schema differs from acquisition contract")
        for number, raw in enumerate(reader, 1):
            if None in raw or any(value is None for value in raw.values()):
                raise EvaluationBlocker(f"malformed official TEST row {number}")
            if all(raw.get(column) == column for column in columns):
                raise EvaluationBlocker(f"duplicate header row in official TEST at row {number}")
            if str(raw.get("label", "")).strip() not in {"0", "1"}:
                raise EvaluationBlocker(f"invalid official TEST label at row {number}")
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
        raise EvaluationBlocker(f"official TEST row count is {len(rows)}")
    return rows, raw_hash


def _feature_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    return [
        {
            **{field: row.get(field) for field in BASE_FEATURES},
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "official_split": "TEST",
            "development_partition": "TEST",
            "row_number": row.get("row_number", "?"),
            "row_key": row.get("row_key"),
        }
        for row in rows
    ]


def _prediction_rows(model_id: str, scores: np.ndarray, rows: Sequence[Mapping[str, object]], model_hash: str, test_hash: str) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row, score in zip(rows, scores, strict=True):
        output.append({
            "schema_version": "stage_2.4e-test-prediction/1.0",
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "row_key": str(row["row_key"]),
            "split_id": "TEST",
            "model_id": model_id,
            "p_attack": float(score),
            "threshold": 0.5,
            "predicted_label": int(float(score) >= 0.5),
            "classes": [0, 1],
            "model_artifact_sha256": model_hash,
            "test_raw_sha256": test_hash,
            "source_feature_count": 30,
            "prediction_frozen_before_labels": True,
        })
    return output


def _baseline_arrays(rows: Sequence[Mapping[str, Any]], expected_model: str) -> np.ndarray:
    if any(row.get("model_id") != expected_model for row in rows):
        raise EvaluationBlocker(f"baseline {expected_model} model identity mismatch")
    values = np.asarray([float(row["p_attack"]) for row in rows], dtype=np.float64)
    if values.shape != (EXPECTED_TEST_ROWS,) or not np.isfinite(values).all() or np.any((values < 0) | (values > 1)):
        raise EvaluationBlocker(f"baseline {expected_model} scores invalid")
    return values


def _load_sensitivity(test_rows: Sequence[dict[str, Any]], test_features: np.ndarray, state: Any) -> dict[str, Any]:
    """Reconstruct predeclared Stage 2.2 mask without using labels or fitting."""

    from run_unsw_test_evaluation import _load_preconditions, _raw_overlap_diagnostics, _transformed_overlap_mask

    train_rows, _split_rows, upstream_state, split_report, feature_contract = _load_preconditions()
    if upstream_state.state_sha256 != state.state_sha256:
        raise EvaluationBlocker("sensitivity reconstruction preprocessing identity mismatch")
    raw_mask, raw_diagnostics = _raw_overlap_diagnostics(train_rows, list(test_rows), split_report)
    transformed_mask, train_vector_count = _transformed_overlap_mask(train_rows, test_features, state, feature_contract["feature_order"])
    mask = raw_mask | transformed_mask
    payload = [[str(row["row_key"]), bool(value)] for row, value in zip(test_rows, mask, strict=True)]
    mask_hash = _hash_json(payload)
    historical = _read_json(STAGE2_2_SENSITIVITY)
    if historical.get("mask_sha256") != mask_hash or historical.get("test_rows") != EXPECTED_TEST_ROWS:
        raise EvaluationBlocker("predeclared sensitivity mask identity changed")
    return {
        "schema_version": "stage_2.4e-test-sensitivity/1.0",
        "label": "SENSITIVITY ANALYSIS ONLY",
        "population": "OFFICIAL_TEST_ALL_ROWS",
        "mask_rule": historical.get("mask_rule"),
        "test_rows": EXPECTED_TEST_ROWS,
        "excluded_rows": int(mask.sum()),
        "retained_rows": int((~mask).sum()),
        "mask_sha256": mask_hash,
        "upstream_mask_artifact_sha256": sha256_file(STAGE2_2_SENSITIVITY),
        "raw_diagnostics": raw_diagnostics,
        "transformed_vector_matches": int(transformed_mask.sum()),
        "train_unique_transformed_vectors": train_vector_count,
        "primary_metrics_use_all_rows": True,
        "labels_used_for_mask": False,
        "model_selection_used": False,
        "mask": mask,
    }


def _metrics_payload(model_id: str, metrics: Mapping[str, object], test_hash: str, lock_hash: str, model_hash: str) -> dict[str, object]:
    return {
        "schema_version": "stage_2.4e-test-metrics/1.0",
        "model_id": model_id,
        "population": "OFFICIAL_TEST_ALL_ROWS",
        "evaluation_type": "LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION",
        "test_raw_sha256": test_hash,
        "selection_lock_sha256": lock_hash,
        "model_artifact_sha256": model_hash,
        "post_test_tuning": False,
        "selection_changed_after_test": False,
        "metrics": dict(metrics),
    }


def evaluate_locked_test(lock_path: Path = LOCK_PATH, authorization_path: Path = AUTH_PATH) -> dict[str, Any]:
    """Run one authorized, inference-only Stage 2.4E evaluation."""

    preflight = _preflight(PROJECT_ROOT, lock_path, authorization_path)
    acquisition = _read_json(ACQUISITION_PATH)
    test_rows, test_hash = _load_test_rows(acquisition["schema"]["columns"])
    feature_state = feature_state_from_dict(_read_json(STAGE_ROOT / "models" / "final_train_inference" / "preprocessing_state.json"))
    feature_rows = _feature_rows(test_rows)
    test_features = transform_features(feature_rows, feature_state)
    if test_features.shape != (EXPECTED_TEST_ROWS, 209):
        raise EvaluationBlocker("frozen TEST base feature shape mismatch")
    u1_model = joblib.load(STAGE_ROOT / "models" / "final_train_inference" / "U1.joblib")
    u2_model = joblib.load(STAGE_ROOT / "models" / "final_train_inference" / "U2.joblib")
    u1_scores = score_u1(u1_model, test_features)
    u2_scores = score_u2(u2_model, test_features)
    if not np.isfinite(u1_scores).all() or not np.isfinite(u2_scores).all() or np.any(u2_scores < 0):
        raise EvaluationBlocker("non-finite U1/U2 TEST scores")

    signal_map = {str(row["row_key"]): {"U1": float(u1), "U2": float(u2)} for row, u1, u2 in zip(test_rows, u1_scores, u2_scores, strict=True)}
    model_scores: dict[str, np.ndarray] = {}
    chain_features: np.ndarray | None = None
    for model_id in ("CHAIN-S1", "CHAIN-S2"):
        model_dir = STAGE_ROOT / "models" / "final_train_inference"
        base_state = feature_state_from_dict(_read_json(model_dir / f"{model_id}_base_preprocessing_state.json"))
        scaler_payload = _read_json(model_dir / f"{model_id}_signal_scaler.json")
        scaler = SignalScaler(**{key: scaler_payload[key] for key in SignalScaler.__dataclass_fields__})
        chain_features = transform_chain_features(test_rows, signal_map, scaler, base_state)
        estimator = joblib.load(model_dir / f"{model_id}.joblib")
        model_scores[model_id] = predict_chain_s1(estimator, chain_features) if model_id == "CHAIN-S1" else predict_chain_s2(estimator, chain_features)
        if not np.isfinite(model_scores[model_id]).all() or np.any((model_scores[model_id] < 0) | (model_scores[model_id] > 1)):
            raise EvaluationBlocker(f"{model_id} produced invalid probabilities")
    if chain_features is None or chain_features.shape != (EXPECTED_TEST_ROWS, 211):
        raise EvaluationBlocker("frozen chain feature shape mismatch")

    # Replay frozen inference before TEST labels are read for metrics.
    replay_scores: dict[str, np.ndarray] = {}
    for model_id in ("CHAIN-S1", "CHAIN-S2"):
        model_dir = STAGE_ROOT / "models" / "final_train_inference"
        estimator = pickle.loads(pickle.dumps(joblib.load(model_dir / f"{model_id}.joblib"), protocol=pickle.HIGHEST_PROTOCOL))
        replay_scores[model_id] = predict_chain_s1(estimator, chain_features) if model_id == "CHAIN-S1" else predict_chain_s2(estimator, chain_features)
        if not np.allclose(replay_scores[model_id], model_scores[model_id], rtol=1e-12, atol=1e-12):
            raise EvaluationBlocker(f"{model_id} deterministic replay mismatch")
    model_hashes = {model_id: str(preflight["authorization"]["models"][model_id]["model_artifact_sha256"]) for model_id in ("CHAIN-S1", "CHAIN-S2")}
    predictions = {model_id: _prediction_rows(model_id, model_scores[model_id], test_rows, model_hashes[model_id], test_hash) for model_id in model_scores}

    # Prediction artifacts are frozen before any official TEST labels enter metric code.
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=False)
    prediction_hashes = {
        "CHAIN-S1": _write_jsonl(OUTPUT_ROOT / "chained_s1_test_predictions.jsonl", predictions["CHAIN-S1"]),
        "CHAIN-S2": _write_jsonl(OUTPUT_ROOT / "chained_s2_test_predictions.jsonl", predictions["CHAIN-S2"]),
    }

    labels = np.asarray([int(str(row["label"]).strip()) for row in test_rows], dtype=np.int8)
    baseline_arrays = {
        "S1": _baseline_arrays(preflight["baseline_predictions"]["S1"], "S1"),
        "S2": _baseline_arrays(preflight["baseline_predictions"]["S2"], "S2"),
    }
    metrics = {model_id: evaluate_probabilities(labels, model_scores[model_id], threshold=0.5) for model_id in model_scores}
    baseline_metrics = {
        "S1": evaluate_probabilities(labels, baseline_arrays["S1"], threshold=0.5),
        "S2": evaluate_probabilities(labels, baseline_arrays["S2"], threshold=0.5),
    }
    saved_baseline_metrics = {
        "S1": _read_json(PROJECT_ROOT / "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s1_test_metrics.json")["metrics"],
        "S2": _read_json(PROJECT_ROOT / "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s2_test_metrics.json")["metrics"],
    }
    for model_id in ("S1", "S2"):
        if abs(float(baseline_metrics[model_id]["average_precision"]) - float(saved_baseline_metrics[model_id]["average_precision"])) > 1e-12:
            raise EvaluationBlocker(f"baseline {model_id} AP cannot be reconciled")
    sensitivity = _load_sensitivity(test_rows, test_features, feature_state)
    mask = np.asarray(sensitivity.pop("mask"), dtype=bool)
    sensitivity_metrics = {
        model_id: {
            "chain": evaluate_probabilities(labels[~mask], model_scores[model_id][~mask], threshold=0.5),
            "baseline": evaluate_probabilities(labels[~mask], baseline_arrays["S1" if model_id == "CHAIN-S1" else "S2"][~mask], threshold=0.5),
        }
        for model_id in ("CHAIN-S1", "CHAIN-S2")
    }
    metric_hashes: dict[str, str] = {}
    confusion_hashes: dict[str, str] = {}
    for model_id in ("CHAIN-S1", "CHAIN-S2"):
        baseline_id = "S1" if model_id == "CHAIN-S1" else "S2"
        payload = _metrics_payload(model_id, metrics[model_id], test_hash, preflight["lock_hash"], model_hashes[model_id])
        payload["baseline_model_id"] = baseline_id
        payload["baseline_average_precision"] = baseline_metrics[baseline_id]["average_precision"]
        payload["chain_test_ap_delta"] = float(metrics[model_id]["average_precision"] - baseline_metrics[baseline_id]["average_precision"])
        file_stem = model_id.lower().replace('-', '_').replace('chain_', 'chained_')
        metric_hashes[model_id] = _write_json(OUTPUT_ROOT / f"{file_stem}_test_metrics.json", payload)
        confusion_hashes[model_id] = _write_json(OUTPUT_ROOT / f"{file_stem}_test_confusion_matrix.json", {
            "schema_version": "stage_2.4e-confusion-matrix/1.0",
            "model_id": model_id,
            "population": "OFFICIAL_TEST_ALL_ROWS",
            "matrix": [[metrics[model_id]["confusion_matrix"]["tn"], metrics[model_id]["confusion_matrix"]["fp"]], [metrics[model_id]["confusion_matrix"]["fn"], metrics[model_id]["confusion_matrix"]["tp"]]],
            **metrics[model_id]["confusion_matrix"],
            "matrix_sum": EXPECTED_TEST_ROWS,
            "threshold": 0.5,
            "primary_metric": "AVERAGE_PRECISION",
        })
    sensitivity_hash = _write_json(OUTPUT_ROOT / "chained_test_sensitivity_analysis.json", {**sensitivity, "metrics": sensitivity_metrics})
    replay_hash = _write_json(OUTPUT_ROOT / "chained_test_replay_record.json", {
        "schema_version": "stage_2.4e-replay/1.0",
        "base_feature_replay": "PASS",
        "u1_score_replay": "PASS",
        "u2_score_replay": "PASS",
        "chain_s1_score_replay": "PASS",
        "chain_s2_score_replay": "PASS",
        "prediction_before_labels": True,
        "test_feature_matrix_sha256": _sha256_bytes(test_features.tobytes()),
        "chain_feature_matrix_sha256": _sha256_bytes(chain_features.tobytes()),
        "chain_score_sha256": {key: _sha256_bytes(value.tobytes()) for key, value in model_scores.items()},
        "replayed_chain_score_sha256": {key: _sha256_bytes(value.tobytes()) for key, value in replay_scores.items()},
    })
    provenance_hash = _write_json(OUTPUT_ROOT / "chained_test_evaluation_provenance.json", {
        "schema_version": "stage_2.4e-test-provenance/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "evaluation_type": "LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION",
        "test_raw_sha256": test_hash,
        "test_row_count": EXPECTED_TEST_ROWS,
        "selection_lock_sha256": preflight["lock_hash"],
        "authorization_sha256": preflight["authorization_hash"],
        "test_contribution_to_fitted_state": "NONE",
        "test_preprocessing_fit": False,
        "models_refit_after_validation": False,
        "model_selection_changed_after_test": False,
        "post_test_tuning": False,
        "prior_test_visibility": "DISCLOSED_OFFICIAL_TEST_USED_IN_STAGE_2_2_AND_STAGE_2_3",
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })
    artifacts = {
        "chained_s1_test_predictions.jsonl": prediction_hashes["CHAIN-S1"],
        "chained_s2_test_predictions.jsonl": prediction_hashes["CHAIN-S2"],
        "chained_s1_test_metrics.json": metric_hashes["CHAIN-S1"],
        "chained_s2_test_metrics.json": metric_hashes["CHAIN-S2"],
        "chained_s1_test_confusion_matrix.json": confusion_hashes["CHAIN-S1"],
        "chained_s2_test_confusion_matrix.json": confusion_hashes["CHAIN-S2"],
        "chained_test_sensitivity_analysis.json": sensitivity_hash,
        "chained_test_replay_record.json": replay_hash,
        "chained_test_evaluation_provenance.json": provenance_hash,
    }
    manifest_hash = _write_json(OUTPUT_ROOT / "final_stage_2_4_manifest.json", {
        "schema_version": "stage_2.4e-test-manifest/1.0",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "evaluation_type": "LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION",
        "test_raw_sha256": test_hash,
        "test_row_count": EXPECTED_TEST_ROWS,
        "selection_lock_sha256": preflight["lock_hash"],
        "authorization_sha256": preflight["authorization_hash"],
        "test_contribution_to_fitted_state": "NONE",
        "test_preprocessing_fit": False,
        "prior_test_visibility": "DISCLOSED",
        "primary_metrics_use_all_rows": True,
        "selection_changed_after_test": False,
        "post_test_tuning": False,
        "artifacts": artifacts,
    })
    protected_after = dict(preflight["baseline_hashes"])
    for name, observed in protected_after.items():
        baseline_path = PROJECT_ROOT / "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation" / name
        if sha256_file(baseline_path) != observed:
            raise EvaluationBlocker(f"baseline artifact modified during evaluation: {name}")
    handoff_hash = _write_json(STAGE_ROOT / "manifests" / "stage_2_5_handoff.json", {
        "schema_version": "stage_2.4e-stage-2.5-handoff/1.0",
        "status": "READY_FOR_STAGE_2_5_PLANNING",
        "dataset_scope": "UNSW_NB15_ONLY",
        "fortigate_supervised_use": "NONE",
        "datasets_merged": False,
        "base_interfaces": {"S1": "Stage 2.3 Logistic Regression", "S2": "Stage 2.3 Random Forest"},
        "chain_interfaces": {"CHAIN-S1": "28 BASE + U1 + U2", "CHAIN-S2": "28 BASE + U1 + U2"},
        "training_signal_policy": "OOF_CROSS_FITTED_ONLY",
        "test_results_separate_from_development": True,
        "prior_test_visibility_disclosed": True,
        "stage_2_4e_manifest": "test_evaluation/final_stage_2_4_manifest.json",
        "stage_2_4e_manifest_sha256": manifest_hash,
        "no_chained_training_table_precreated_for_stage_2_5": True,
    })
    checkpoint_payload = {
        "schema_version": "stage_2.4/checkpoint-2.4E/1.0",
        "status": "PASS",
        "checkpoint": "2.4E",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "evaluation_type": "LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION",
        "ledger": ["NOT_OPENED", "AUTHORIZED", "OPENED", "COMPLETE"],
        "selection_lock_sha256": preflight["lock_hash"],
        "authorization_sha256": preflight["authorization_hash"],
        "test_raw_sha256": test_hash,
        "test_rows": EXPECTED_TEST_ROWS,
        "test_contribution_to_fitted_state": "NONE",
        "test_preprocessing_fit": False,
        "post_test_tuning": False,
        "prior_test_visibility": "DISCLOSED_OFFICIAL_TEST_USED_IN_STAGE_2_2_AND_STAGE_2_3",
        "baseline_artifacts_modified": False,
        "artifacts": {**artifacts, "final_stage_2_4_manifest.json": manifest_hash, "manifests/stage_2_5_handoff.json": handoff_hash},
        "next_action": "STAGE_2_4_FINAL_AUDIT_REQUIRED",
    }
    checkpoint_hash = _write_json(STAGE_ROOT / "manifests" / "checkpoint_2_4E.json", checkpoint_payload)
    return {
        "status": "PASS",
        "test_rows": EXPECTED_TEST_ROWS,
        "selection_lock_verified": True,
        "human_authorization": True,
        "test_contribution_to_fitted_state": "NONE",
        "metrics": metrics,
        "baseline_metrics": baseline_metrics,
        "prediction_hashes": prediction_hashes,
        "manifest_sha256": manifest_hash,
        "checkpoint_sha256": checkpoint_hash,
        "handoff_sha256": handoff_hash,
        "output_root": str(OUTPUT_ROOT),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    parser.add_argument("--authorization", type=Path, default=AUTH_PATH)
    args = parser.parse_args()
    print(json.dumps(evaluate_locked_test(args.lock, args.authorization), sort_keys=True))


if __name__ == "__main__":
    main()
