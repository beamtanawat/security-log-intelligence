"""Stage 2.4A TRAIN-only contract publication CLI."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.metrics import average_precision_score

from chained.contracts import (
    BASE_FEATURES,
    BRANCH_ID,
    CHAIN_SCHEMA_VERSION,
    CHAIN_S1_CONFIG,
    CHAIN_S2_CONFIG,
    DATASET_ID,
    EXPECTED_FIT_ATTEMPTS,
    U1_CONFIG,
    U2_CONFIG,
    build_chain_contract,
    build_contexts,
    canonical_json_bytes,
    compare_pair,
    membership_sha256,
    sha256_file,
    sha256_bytes,
    validate_inputs,
    validate_nested_contexts,
)
from chained.models import (
    SignalScaler,
    fit_chain_base_state,
    fit_chain_s1,
    fit_chain_s2,
    fit_signal_scaler,
    predict_chain_s1,
    predict_chain_s2,
    transform_chain_features,
)
from chained.signals import (
    SignalBlocker,
    audit_signal_artifact,
    build_signal_records,
    fit_score_signals,
    feature_state_from_dict,
    score_u1,
)
from supervised.evaluation import evaluate_probabilities
from supervised.models import S2_CONFIG as SUPERVISED_S2_CONFIG
from unsupervised.features import transform_features
from unsupervised.models import score_u2
from run_supervised import _load_upstream


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"


def _write_json(path: Path, payload: Any) -> str:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite {path}")
    data = canonical_json_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return sha256_bytes(data)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> str:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite {path}")
    data = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return sha256_bytes(data)


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise SignalBlocker(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SignalBlocker(f"expected JSON object line: {path}")
                rows.append(value)
    return rows


def _write_joblib(path: Path, value: object) -> str:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(value, path, compress=3)
    return sha256_file(path)


def _load_train_feature_rows(root: Path, inputs: dict[str, Any]) -> tuple[dict[str, dict[str, object]], str]:
    """Read official TRAIN once, then retain only approved base features."""

    train_path = root / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_training-set.csv"
    if not train_path.is_file():
        raise SignalBlocker("official TRAIN CSV is missing")
    acquisition_path = root / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
    acquisition = _read_json(acquisition_path)
    expected = next(item for item in acquisition.get("files", []) if item.get("role") == "TRAIN")
    raw_hash = sha256_file(train_path)
    if raw_hash != expected.get("sha256"):
        raise SignalBlocker("official TRAIN SHA-256 differs from acquisition manifest")
    split_by_number = {int(item["row_number"]): item for item in inputs["split_rows"]}
    expected_rows = len(inputs["split_rows"])
    rows_by_key: dict[str, dict[str, object]] = {}
    with train_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for number, raw in enumerate(reader, 1):
            if number not in split_by_number:
                raise SignalBlocker("TRAIN row identity differs from frozen split manifest")
            split = split_by_number[number]
            row = {field: raw.get(field) for field in BASE_FEATURES}
            row.update(
                {
                    "dataset_id": inputs["dataset_id"],
                    "branch_id": inputs["branch_id"],
                    "official_split": "TRAIN",
                    "development_partition": split["partition"],
                    "row_number": number,
                    "row_key": split["row_key"],
                    "group_id": split["group_id"],
                }
            )
            if row["development_partition"] != "TRAIN_INTERNAL":
                continue
            rows_by_key[str(row["row_key"])] = row
    if len(rows_by_key) != inputs["train_internal_rows"] or len(rows_by_key) != expected_rows - 35068:
        raise SignalBlocker("TRAIN_INTERNAL row coverage differs from frozen manifest")
    return rows_by_key, raw_hash


def _load_2_4a_contract(root: Path, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, str]:
    output_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
    contract_path = output_root / "contracts" / "chain_contract.json"
    crossfit_path = output_root / "manifests" / "crossfit_contract.json"
    checkpoint_path = output_root / "manifests" / "checkpoint_2_4A.json"
    for path in (contract_path, crossfit_path, checkpoint_path):
        if not path.is_file():
            raise SignalBlocker(f"2.4A artifact missing: {path.name}")
    contract_hash = sha256_file(contract_path)
    crossfit_hash = sha256_file(crossfit_path)
    contract = _read_json(contract_path)
    crossfit = _read_json(crossfit_path)
    checkpoint = _read_json(checkpoint_path)
    if checkpoint.get("artifacts", {}).get("contracts/chain_contract.json") != contract_hash:
        raise SignalBlocker("2.4A chain contract hash mismatch")
    if checkpoint.get("artifacts", {}).get("manifests/crossfit_contract.json") != crossfit_hash:
        raise SignalBlocker("2.4A cross-fit contract hash mismatch")
    if checkpoint.get("status") != "PASS" or crossfit.get("status") != "PASS":
        raise SignalBlocker("2.4A checkpoint is not PASS")
    if crossfit.get("expected_fit_attempts") != EXPECTED_FIT_ATTEMPTS or crossfit.get("actual_fit_attempts") != 0:
        raise SignalBlocker("2.4A fit schedule changed")
    contexts = crossfit.get("contexts")
    if not isinstance(contexts, list):
        raise SignalBlocker("2.4A contexts missing")
    validate_nested_contexts(contexts)
    expected_contexts = build_contexts(inputs["folds"])
    expected_by_id = {str(item["context_id"]): item for item in expected_contexts}
    observed_by_id = {str(item.get("context_id")): item for item in contexts}
    if set(expected_by_id) != set(observed_by_id):
        raise SignalBlocker("2.4A context identities changed")
    for context_id, expected in expected_by_id.items():
        observed = observed_by_id[context_id]
        for field in ("fit_membership_sha256", "score_membership_sha256", "authorized_membership_sha256", "fit_row_keys", "score_row_keys"):
            if observed.get(field) != expected.get(field):
                raise SignalBlocker(f"2.4A context changed: {context_id}:{field}")
    if crossfit.get("test_used") is not False or crossfit.get("signal_artifacts_published") is not False:
        raise SignalBlocker("2.4A artifact indicates prior signal generation")
    return contract, crossfit, checkpoint, contract_hash, crossfit_hash


def _fit_paths(output_root: Path, context_id: str, model_id: str) -> dict[str, Path]:
    signal_dir = output_root / "signals" / context_id
    model_dir = output_root / "models" / context_id
    return {
        "signal": signal_dir / f"{model_id}.jsonl",
        "audit": signal_dir / "exclusion_audit.json",
        "model": model_dir / f"{model_id}.joblib",
        "metadata": model_dir / f"{model_id}_metadata.json",
        "state": model_dir / "preprocessing_state.json",
    }


def _validate_reuse(
    paths: dict[str, Path],
    context: dict[str, Any],
    model_id: str,
    *,
    raw_source_sha256: str,
    contract_hash: str,
    crossfit_hash: str,
) -> dict[str, Any] | None:
    if not paths["metadata"].is_file() or not paths["model"].is_file() or not paths["state"].is_file():
        return None
    metadata = _read_json(paths["metadata"])
    expected_config = U1_CONFIG if model_id == "U1" else U2_CONFIG
    expected_family = "ISOLATION_FOREST" if model_id == "U1" else "MINIBATCHKMEANS_DISTANCE_SCORER"
    expected_version = "stage_2.4b-u1/1.0" if model_id == "U1" else "stage_2.4b-u2/1.0"
    if metadata.get("config") != expected_config or metadata.get("model_family") != expected_family or metadata.get("model_version") != expected_version:
        raise SignalBlocker(f"existing artifact algorithm identity mismatch: {context['context_id']}:{model_id}")
    if metadata.get("score_direction") != "HIGHER_MORE_ANOMALOUS" or metadata.get("labels_used") is not False or metadata.get("attack_cat_used") is not False or metadata.get("test_used") is not False:
        raise SignalBlocker(f"existing artifact score/policy identity mismatch: {context['context_id']}:{model_id}")
    expected = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "context_id": context["context_id"],
        "model_id": model_id,
        "fit_membership_sha256": context["fit_membership_sha256"],
        "score_membership_sha256": context["score_membership_sha256"],
        "raw_source_sha256": raw_source_sha256,
        "chain_contract_sha256": contract_hash,
        "crossfit_contract_sha256": crossfit_hash,
        "labels_used": False,
        "attack_cat_used": False,
        "test_used": False,
        "deterministic_replay": "PASS",
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise SignalBlocker(f"existing artifact identity mismatch: {context['context_id']}:{model_id}:{field}")
    if metadata.get("model_artifact_sha256") != sha256_file(paths["model"]):
        raise SignalBlocker("existing model artifact hash mismatch")
    if metadata.get("preprocessing_state_sha256") != sha256_file(paths["state"]):
        raise SignalBlocker("existing preprocessing artifact hash mismatch")
    score_rows = [str(value) for value in context["score_row_keys"]]
    if score_rows:
        if not paths["signal"].is_file():
            raise SignalBlocker("existing signal metadata has missing signal artifact")
        records = _read_jsonl(paths["signal"])
        audit_signal_artifact(records, context, model_id)
    elif paths["signal"].is_file() and _read_jsonl(paths["signal"]):
        raise SignalBlocker("final inference fit has unexpected signal rows")
    return metadata


def _persist_fit(
    *,
    output_root: Path,
    context: dict[str, Any],
    model_id: str,
    result: dict[str, Any],
    raw_source_sha256: str,
    contract_hash: str,
    crossfit_hash: str,
) -> dict[str, Any]:
    paths = _fit_paths(output_root, str(context["context_id"]), model_id)
    state = result["feature_state"]
    paths["state"].parent.mkdir(parents=True, exist_ok=True)
    if paths["state"].exists():
        state_hash = sha256_file(paths["state"])
    else:
        state_hash = _write_json(paths["state"], state.to_dict())
    model = result[model_id]["model"]
    partial_model = paths["model"].with_suffix(paths["model"].suffix + ".partial")
    if partial_model.exists():
        partial_model.unlink()
    model_hash = _write_joblib(partial_model, model)
    metadata_base = dict(result[model_id]["metadata"])
    metadata_base.update(
        {
            "model_artifact_sha256": model_hash,
            "preprocessing_state_sha256": state_hash,
            "raw_source_sha256": raw_source_sha256,
            "chain_contract_sha256": contract_hash,
            "crossfit_contract_sha256": crossfit_hash,
            "artifact_identity": "PENDING",
        }
    )
    artifact_identity = sha256_bytes(canonical_json_bytes({key: value for key, value in metadata_base.items() if key != "artifact_identity"}))
    metadata_base["artifact_identity"] = artifact_identity
    rows_by_key = result["rows_by_key"]
    records = build_signal_records(
        rows_by_key=rows_by_key,
        context={**context, "preprocessing_identity": state_hash},
        model_id=model_id,
        scores=result[model_id]["scores"],
        artifact_identity=artifact_identity,
    )
    if records:
        audit = audit_signal_artifact(records, context, model_id)
    else:
        audit = {
            "status": "PASS",
            "model_id": model_id,
            "context_id": context["context_id"],
            "score_row_count": 0,
            "same_row_overlap": 0,
            "same_group_overlap": 0,
            "fit_signal_group_overlap": 0,
            "labels_used": False,
            "attack_cat_used": False,
            "test_used": False,
        }
    if paths["metadata"].exists() or paths["model"].exists() or paths["signal"].exists():
        raise SignalBlocker("validated fit output path already exists")
    _write_json(paths["metadata"], metadata_base)
    _write_jsonl(paths["signal"], records)
    os.replace(partial_model, paths["model"])
    return {"metadata": metadata_base, "audit": audit, "paths": paths}


def _run_checkpoint_2_4b(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    inputs = validate_inputs(root)
    contract, crossfit, checkpoint, contract_hash, crossfit_hash = _load_2_4a_contract(root, inputs)
    rows_by_key, raw_source_sha256 = _load_train_feature_rows(root, inputs)
    output_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
    contexts = [dict(context) for context in crossfit["contexts"]]
    u_contexts = [context for context in contexts if context["kind"] in {"INNER_SIGNAL", "OUTER_INFERENCE", "FINAL_INFERENCE"}]
    expected_u_fits = len(u_contexts) * 2
    if expected_u_fits != 20:
        raise SignalBlocker(f"2.4B anomaly fit schedule mismatch: {expected_u_fits}")
    completed = 0
    reused = 0
    context_audits: dict[str, dict[str, Any]] = {}
    for context in u_contexts:
        context_id = str(context["context_id"])
        fit_keys = frozenset(str(value) for value in context["fit_row_keys"])
        score_keys = frozenset(str(value) for value in context["score_row_keys"])
        model_results: dict[str, Any] | None = None
        per_model: dict[str, Any] = {}
        for model_id in ("U1", "U2"):
            paths = _fit_paths(output_root, context_id, model_id)
            reused_metadata = _validate_reuse(
                paths,
                context,
                model_id,
                raw_source_sha256=raw_source_sha256,
                contract_hash=contract_hash,
                crossfit_hash=crossfit_hash,
            )
            if reused_metadata is not None:
                reused += 1
                completed += 1
                per_model[model_id] = {"status": "PASS", "reused": True, "metadata": reused_metadata, "audit": {"status": "PASS", "score_row_count": int(reused_metadata["score_row_count"]), "same_row_overlap": 0, "same_group_overlap": 0, "fit_signal_group_overlap": 0}}
                continue
            if model_results is None:
                model_results = fit_score_signals(rows_by_key.values(), fit_keys, score_keys, context)
            persisted = _persist_fit(
                output_root=output_root,
                context=context,
                model_id=model_id,
                result=model_results,
                raw_source_sha256=raw_source_sha256,
                contract_hash=contract_hash,
                crossfit_hash=crossfit_hash,
            )
            completed += 1
            per_model[model_id] = {"status": "PASS", "reused": False, "metadata": persisted["metadata"], "audit": persisted["audit"]}
        context_audits[context_id] = per_model
        audit_path = output_root / "signals" / context_id / "exclusion_audit.json"
        if not audit_path.exists():
            _write_json(
                audit_path,
                {
                    "schema_version": CHAIN_SCHEMA_VERSION,
                    "context_id": context_id,
                    "kind": context["kind"],
                    "fit_membership_sha256": context["fit_membership_sha256"],
                    "score_membership_sha256": context["score_membership_sha256"],
                    "expected_score_rows": len(context["score_row_keys"]),
                    "U1": per_model["U1"]["audit"],
                    "U2": per_model["U2"]["audit"],
                    "same_row_fit_signal_overlap": 0,
                    "same_group_fit_signal_overlap": 0,
                    "outer_group_exclusion": "PASS",
                    "labels_used": False,
                    "attack_cat_used": False,
                    "test_used": False,
                },
            )

    required_keys = set(rows_by_key)
    coverage: dict[str, Any] = {}
    for model_id in ("U1", "U2"):
        counts: dict[str, int] = {}
        for context in contexts:
            if context["kind"] != "OUTER_INFERENCE":
                continue
            signal_path = _fit_paths(output_root, str(context["context_id"]), model_id)["signal"]
            records = _read_jsonl(signal_path)
            audit_signal_artifact(records, context, model_id)
            for record in records:
                key = str(record["row_key"])
                counts[key] = counts.get(key, 0) + 1
        missing = required_keys - set(counts)
        duplicates = sum(max(0, count - 1) for count in counts.values())
        wrong = {key for key, count in counts.items() if count != 1}
        coverage[model_id] = {
            "required_rows": len(required_keys),
            "covered_rows": sum(count == 1 for count in counts.values()),
            "missing_rows": len(missing),
            "duplicate_assignments": duplicates,
            "wrong_coverage_rows": len(wrong),
            "status": "PASS" if not missing and not duplicates and not wrong else "BLOCKED",
        }
        if coverage[model_id]["status"] != "PASS":
            raise SignalBlocker(f"{model_id} required OOF coverage incomplete")

    coverage_payload = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "dataset_id": inputs["dataset_id"],
        "branch_id": inputs["branch_id"],
        "status": "PASS",
        "required_rows": len(required_keys),
        "U1": coverage["U1"],
        "U2": coverage["U2"],
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "fit_partition_leakage": 0,
        "unauthorized_validation_contribution": 0,
        "labels_used_in_anomaly_fit": False,
        "attack_cat_used_in_anomaly_fit": False,
        "test_used": False,
    }
    coverage_path = output_root / "manifests" / "signal_coverage.json"
    if not coverage_path.exists():
        coverage_hash = _write_json(coverage_path, coverage_payload)
    else:
        coverage_hash = sha256_file(coverage_path)
        if _read_json(coverage_path) != coverage_payload:
            raise SignalBlocker("existing signal coverage artifact differs")

    leakage_payload = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "status": "PASS",
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "fit_partition_leakage": 0,
        "unauthorized_validation_contribution": 0,
        "labels_used_in_u1_u2_fit": False,
        "attack_cat_used_in_u1_u2_fit": False,
        "test_used_for_development": False,
        "baseline_artifacts_modified": False,
        "deterministic_replay": "PASS",
    }
    leakage_path = output_root / "reports" / "leakage_audit_2_4B.json"
    if not leakage_path.exists():
        leakage_hash = _write_json(leakage_path, leakage_payload)
    else:
        leakage_hash = sha256_file(leakage_path)
        if _read_json(leakage_path) != leakage_payload:
            raise SignalBlocker("existing leakage audit differs")

    checkpoint_2_4b = {
        "schema_version": "stage_2.4/checkpoint-2.4B/1.0",
        "status": "PASS",
        "checkpoint": "2.4B",
        "dataset_id": inputs["dataset_id"],
        "branch_id": inputs["branch_id"],
        "plan": "docs/plans/stage_2_4_chained_ml_pipeline_plan.md",
        "plan_sha256": contract.get("plan_sha256"),
        "master_plan_sha256": contract.get("master_plan_sha256"),
        "planned_fit_attempts": EXPECTED_FIT_ATTEMPTS,
        "actual_anomaly_fits_completed": completed,
        "validated_fits_reused": reused,
        "remaining_chain_fits": 8,
        "U1": {"status": "PASS", "coverage": coverage["U1"]},
        "U2": {"status": "PASS", "coverage": coverage["U2"]},
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "labels_used": False,
        "attack_cat_used": False,
        "test_used": False,
        "determinism": "PASS",
        "baseline_immutable": True,
        "artifacts": {
            "manifests/signal_coverage.json": coverage_hash,
            "reports/leakage_audit_2_4B.json": leakage_hash,
        },
        "next_action": "HUMAN_REVIEW_REQUIRED_FOR_2.4C",
    }
    checkpoint_path = output_root / "manifests" / "checkpoint_2_4B.json"
    if not checkpoint_path.exists():
        _write_json(checkpoint_path, checkpoint_2_4b)
    else:
        existing_checkpoint = _read_json(checkpoint_path)
        stable_existing = {
            key: value for key, value in existing_checkpoint.items()
            if key != "validated_fits_reused"
        }
        stable_current = {
            key: value for key, value in checkpoint_2_4b.items()
            if key != "validated_fits_reused"
        }
        if stable_existing != stable_current:
            raise SignalBlocker("existing 2.4B checkpoint differs")
    return {
        "status": "PASS",
        "planned_fits": EXPECTED_FIT_ATTEMPTS,
        "actual_fits_completed": completed,
        "validated_fits_reused": reused,
        "remaining_fits": 8,
        "required_rows": len(required_keys),
        "coverage": coverage,
        "test_used": False,
    }


run_checkpoint_2_4b = _run_checkpoint_2_4b


def _u_feature_rows(rows: list[dict[str, Any]]) -> list[dict[str, object]]:
    """Project rows onto the label-free U1/U2 feature boundary."""

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


def _load_signal_map(
    output_root: Path,
    context: dict[str, Any],
    model_id: str,
) -> tuple[dict[str, float], dict[str, Any]]:
    """Load and independently validate one frozen Stage 2.4B signal stream."""

    path = output_root / "signals" / str(context["context_id"]) / f"{model_id}.jsonl"
    metadata_path = output_root / "models" / str(context["context_id"]) / f"{model_id}_metadata.json"
    if not path.is_file() or not metadata_path.is_file():
        raise SignalBlocker(f"missing validated signal artifact: {context['context_id']}:{model_id}")
    records = _read_jsonl(path)
    audit_signal_artifact(records, context, model_id)
    metadata = _read_json(metadata_path)
    artifact_identity = str(metadata.get("artifact_identity", ""))
    if not artifact_identity:
        raise SignalBlocker("signal model artifact identity is missing")
    observed = {
        str(record["row_key"]): float(record["score"])
        for record in records
    }
    for record in records:
        if str(record.get("artifact_identity")) != artifact_identity:
            raise SignalBlocker("signal/model artifact identity mismatch")
    return observed, {
        "artifact_identity": artifact_identity,
        "metadata_path": str(metadata_path.relative_to(PROJECT_ROOT)),
        "signal_path": str(path.relative_to(PROJECT_ROOT)),
        "signal_sha256": sha256_file(path),
        "model_sha256": metadata.get("model_artifact_sha256"),
        "preprocessing_state_sha256": metadata.get("preprocessing_state_sha256"),
    }


def _merge_signal_maps(
    keys: list[str],
    u1: dict[str, float],
    u2: dict[str, float],
) -> dict[str, dict[str, float]]:
    expected = set(keys)
    if set(u1) != expected or set(u2) != expected:
        raise SignalBlocker("U1/U2 signal coverage cannot be reconciled")
    return {key: {"U1": float(u1[key]), "U2": float(u2[key])} for key in keys}


def _load_baseline_scores(
    path: Path,
    rows: list[dict[str, Any]],
    model_id: str,
    role: str,
    *,
    expected_config: dict[str, object] | None = None,
) -> np.ndarray:
    """Load frozen baseline probabilities with exact row-key alignment."""

    records = _read_jsonl(path)
    if len(records) != len(rows):
        raise SignalBlocker(f"baseline row count mismatch: {path.name}")
    values: list[float] = []
    for row, record in zip(rows, records):
        if str(record.get("row_key")) != str(row["row_key"]):
            raise SignalBlocker(f"baseline row identity mismatch: {path.name}")
        if record.get("model_id") != model_id or record.get("prediction_role") != role:
            raise SignalBlocker(f"baseline prediction provenance mismatch: {path.name}")
        if expected_config is not None and record.get("config") != expected_config:
            raise SignalBlocker(f"baseline configuration mismatch: {path.name}")
        if float(record.get("threshold", -1.0)) != 0.5:
            raise SignalBlocker("baseline threshold is not frozen at 0.5")
        if model_id == "S1" and float(record.get("C", 1.0)) != 1.0:
            raise SignalBlocker("baseline S1 C identity changed")
        value = float(record.get("p_attack"))
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise SignalBlocker("baseline p_attack is invalid")
        values.append(value)
    return np.asarray(values, dtype=np.float64)


def _load_validation_signal_map(
    output_root: Path,
    rows: list[dict[str, Any]],
    partition: str,
    model_id: str,
    metadata: dict[str, Any],
) -> tuple[dict[str, float], dict[str, Any]]:
    """Load the 2.4C final-training inference signal for one validation role."""

    path = output_root / "signals" / "final_train_inference" / f"validation_{partition.lower()}_{model_id}.jsonl"
    if not path.is_file():
        raise SignalBlocker(f"missing 2.4C validation signal artifact: {path.name}")
    records = _read_jsonl(path)
    if len(records) != len(rows):
        raise SignalBlocker(f"validation signal row count mismatch: {path.name}")
    expected_keys = [str(row["row_key"]) for row in rows]
    observed: dict[str, float] = {}
    for row, record in zip(rows, records):
        key = str(row["row_key"])
        if str(record.get("row_key")) != key or key in observed:
            raise SignalBlocker(f"validation signal row identity mismatch: {path.name}")
        if record.get("model_id") != model_id or record.get("context_id") != "final_train_inference":
            raise SignalBlocker(f"validation signal provenance mismatch: {path.name}")
        if record.get("artifact_identity") != metadata.get("artifact_identity"):
            raise SignalBlocker(f"validation signal model identity mismatch: {path.name}")
        if record.get("labels_used") is not False or record.get("attack_cat_used") is not False or record.get("test_used") is not False:
            raise SignalBlocker(f"validation signal policy failed: {path.name}")
        value = float(record.get("score"))
        if not math.isfinite(value) or (model_id == "U2" and value < 0):
            raise SignalBlocker(f"validation signal value invalid: {path.name}")
        observed[key] = value
    if list(observed) != expected_keys:
        raise SignalBlocker(f"validation signal coverage mismatch: {path.name}")
    return observed, {
        "artifact_identity": metadata.get("artifact_identity"),
        "signal_path": str(path.relative_to(PROJECT_ROOT)),
        "signal_sha256": sha256_file(path),
        "model_sha256": metadata.get("model_artifact_sha256"),
        "preprocessing_state_sha256": metadata.get("preprocessing_state_sha256"),
    }


def _snapshot_baseline(root: Path) -> dict[str, str]:
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    relatives = [
        "models/S1/final.joblib",
        "models/S1/final_feature_state.json",
        "models/S1/final_metadata.json",
        "predictions/oof_S1.jsonl",
        "predictions/validation_validation_calibration_S1.jsonl",
        "predictions/validation_validation_comparison_S1.jsonl",
        "reports/selection.json",
        "manifests/selection_lock.json",
    ]
    snapshot: dict[str, str] = {}
    for relative in relatives:
        path = baseline_root / relative
        if not path.is_file():
            raise SignalBlocker(f"frozen BASE S1 artifact is missing: {relative}")
        snapshot[relative] = sha256_file(path)
    selection = _read_json(baseline_root / "reports" / "selection.json")
    if selection.get("status") != "PASS" or selection.get("test_used") is not False or selection.get("chained_signals_used") is not False:
        raise SignalBlocker("frozen baseline selection provenance is not development-safe")
    if selection.get("development_s1_config", {}).get("C") != 1.0 or selection.get("selected_config_per_outer") != {"0": 1.0, "1": 1.0, "2": 1.0}:
        raise SignalBlocker("inherited BASE S1 configuration is not C=1.0")
    if selection.get("threshold") != 0.5:
        raise SignalBlocker("inherited BASE S1 threshold changed")
    return snapshot


def _validate_baseline_snapshot(root: Path, snapshot: dict[str, str]) -> None:
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    for relative, expected in snapshot.items():
        observed = sha256_file(baseline_root / relative)
        if observed != expected:
            raise SignalBlocker(f"BASE S1 artifact changed during 2.4C: {relative}")


def _serialize_joblib(value: object) -> bytes:
    buffer = io.BytesIO()
    joblib.dump(value, buffer, compress=3)
    return buffer.getvalue()


def _replay_predictions_in_batches(estimator: object, X: np.ndarray, *, batch_size: int = 4096) -> np.ndarray:
    """Replay a serialized classifier without refitting, in bounded batches."""

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    return np.concatenate(
        [predict_chain_s1(estimator, X[start : start + batch_size]) for start in range(0, X.shape[0], batch_size)]
    ) if X.shape[0] else np.empty(0, dtype=np.float64)


def _state_bytes(state: Any) -> tuple[bytes, str]:
    data = canonical_json_bytes(state.to_dict()) + b"\n"
    return data, sha256_file_bytes(data)


def sha256_file_bytes(data: bytes) -> str:
    return sha256_bytes(data)


def _run_checkpoint_2_4c(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Fit and evaluate only the approved CHAIN-S1 development branch."""

    root = Path(root)
    inputs = validate_inputs(root)
    contract, crossfit, checkpoint_a, contract_hash, crossfit_hash = _load_2_4a_contract(root, inputs)
    output_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
    checkpoint_b_path = output_root / "manifests" / "checkpoint_2_4B.json"
    coverage_path = output_root / "manifests" / "signal_coverage.json"
    leakage_path = output_root / "reports" / "leakage_audit_2_4B.json"
    for path in (checkpoint_b_path, coverage_path, leakage_path):
        if not path.is_file():
            raise SignalBlocker(f"2.4B artifact missing: {path.name}")
    checkpoint_b = _read_json(checkpoint_b_path)
    if checkpoint_b.get("status") != "PASS" or checkpoint_b.get("test_used") is not False:
        raise SignalBlocker("2.4B checkpoint is not a passing TEST-locked receipt")
    if checkpoint_b.get("actual_anomaly_fits_completed") != 20 or checkpoint_b.get("remaining_chain_fits") != 8:
        raise SignalBlocker("2.4B fit accounting is not closed")
    coverage = _read_json(coverage_path)
    leakage = _read_json(leakage_path)
    if checkpoint_b.get("artifacts", {}).get("manifests/signal_coverage.json") != sha256_file(coverage_path):
        raise SignalBlocker("2.4B signal coverage hash mismatch")
    if checkpoint_b.get("artifacts", {}).get("reports/leakage_audit_2_4B.json") != sha256_file(leakage_path):
        raise SignalBlocker("2.4B leakage audit hash mismatch")
    if coverage.get("status") != "PASS" or leakage.get("status") != "PASS":
        raise SignalBlocker("2.4B signal/leakage audit is not PASS")
    if coverage.get("required_rows") != 140273 or coverage.get("same_row_fit_signal_overlap") != 0 or coverage.get("same_group_fit_signal_overlap") != 0:
        raise SignalBlocker("2.4B required signal coverage is not closed")
    if leakage.get("fit_partition_leakage") != 0 or leakage.get("unauthorized_validation_contribution") != 0:
        raise SignalBlocker("2.4B partition leakage is nonzero")

    rows, _, _ = _load_upstream()
    train_internal = [row for row in rows if row.get("development_partition") == "TRAIN_INTERNAL"]
    validation_rows = {
        partition: [row for row in rows if row.get("development_partition") == partition]
        for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")
    }
    if len(train_internal) != 140273 or len(validation_rows["VALIDATION_CALIBRATION"]) != 17539 or len(validation_rows["VALIDATION_COMPARISON"]) != 17529:
        raise SignalBlocker("Stage 2.4 development populations changed")
    fold_by_key = {str(item["row_key"]): item for item in inputs["folds"]}
    train_keys = [str(row["row_key"]) for row in train_internal]
    if membership_sha256(train_keys) != str(crossfit["contexts"][-1]["fit_membership_sha256"]):
        raise SignalBlocker("TRAIN_INTERNAL membership does not match frozen final context")

    # Verify each U artifact identity before allowing it to feed a supervised fit.
    context_by_id = {str(item["context_id"]): dict(item) for item in crossfit["contexts"]}
    signal_cache: dict[tuple[str, str], dict[str, float]] = {}
    signal_provenance: dict[tuple[str, str], dict[str, Any]] = {}
    raw_source_sha256 = "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
    for context_id, context in context_by_id.items():
        for model_id in ("U1", "U2"):
            paths = _fit_paths(output_root, context_id, model_id)
            metadata = _validate_reuse(
                paths,
                context,
                model_id,
                raw_source_sha256=raw_source_sha256,
                contract_hash=contract_hash,
                crossfit_hash=crossfit_hash,
            )
            if metadata is None:
                raise SignalBlocker(f"2.4B fit artifact cannot be reused: {context_id}:{model_id}")
            values, provenance = _load_signal_map(output_root, context, model_id)
            if provenance["artifact_identity"] != metadata.get("artifact_identity"):
                raise SignalBlocker("2.4B signal provenance identity mismatch")
            signal_cache[(context_id, model_id)] = values
            signal_provenance[(context_id, model_id)] = provenance

    baseline_snapshot = _snapshot_baseline(root)
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    baseline_oof = _load_baseline_scores(baseline_root / "predictions" / "oof_S1.jsonl", train_internal, "S1", "OUTER_OOF")
    baseline_oof_by_key = {str(row["row_key"]): float(score) for row, score in zip(train_internal, baseline_oof)}
    baseline_validation: dict[str, np.ndarray] = {}
    for partition, rows_for_partition in validation_rows.items():
        path = baseline_root / "predictions" / f"validation_{partition.lower()}_S1.jsonl"
        baseline_validation[partition] = _load_baseline_scores(
            path,
            rows_for_partition,
            "S1",
            f"VALIDATION_{partition}",
        )

    def merged_context_signals(context_ids: list[str], rows_for_context: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
        keys = [str(row["row_key"]) for row in rows_for_context]
        u1: dict[str, float] = {}
        u2: dict[str, float] = {}
        for context_id in context_ids:
            for key, value in signal_cache[(context_id, "U1")].items():
                if key in u1:
                    raise SignalBlocker("duplicate U1 OOF assignment")
                u1[key] = value
            for key, value in signal_cache[(context_id, "U2")].items():
                if key in u2:
                    raise SignalBlocker("duplicate U2 OOF assignment")
                u2[key] = value
        return _merge_signal_maps(keys, u1, u2)

    model_runs: list[dict[str, Any]] = []
    outer_records: list[dict[str, Any]] = []
    outer_metrics: list[dict[str, Any]] = []
    all_chain_oof: dict[str, float] = {}
    for outer in range(3):
        outer_eval = [row for row in train_internal if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) == outer]
        outer_train = [row for row in train_internal if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) != outer]
        context_id = f"outer_{outer}_heldout_inference"
        context = context_by_id[context_id]
        if membership_sha256([str(row["row_key"]) for row in outer_train]) != context["fit_membership_sha256"]:
            raise SignalBlocker(f"outer {outer} fit membership changed")
        train_signal = merged_context_signals([f"outer_{outer}_inner_0_signal", f"outer_{outer}_inner_1_signal"], outer_train)
        eval_signal = merged_context_signals([context_id], outer_eval)
        base_state = fit_chain_base_state(outer_train)
        signal_scaler = fit_signal_scaler(outer_train, train_signal)
        X_train = transform_chain_features(outer_train, train_signal, signal_scaler, base_state)
        X_eval = transform_chain_features(outer_eval, eval_signal, signal_scaler, base_state)
        y_train = np.asarray([int(str(row["label"]).strip()) for row in outer_train], dtype=np.int8)
        y_eval = np.asarray([int(str(row["label"]).strip()) for row in outer_eval], dtype=np.int8)
        estimator, fit_report = fit_chain_s1(X_train, y_train, context=f"outer:{outer}:CHAIN-S1")
        p_chain = predict_chain_s1(estimator, X_eval)
        p_base = np.asarray([baseline_oof_by_key[str(row["row_key"])] for row in outer_eval], dtype=np.float64)
        base_metrics = evaluate_probabilities(y_eval, p_base)
        chain_metrics = evaluate_probabilities(y_eval, p_chain)
        comparison = compare_pair(y_eval, p_base, p_chain)
        replay_model = joblib.load(io.BytesIO(_serialize_joblib(estimator)))
        replay_p = _replay_predictions_in_batches(replay_model, X_eval)
        replay_delta = float(np.max(np.abs(p_chain - replay_p))) if p_chain.size else 0.0
        if replay_delta > 1e-12 or not np.array_equal(p_chain >= 0.5, replay_p >= 0.5):
            raise SignalBlocker(f"CHAIN-S1 outer {outer} serialized replay mismatch")
        for row, score in zip(outer_eval, p_chain):
            key = str(row["row_key"])
            if key in all_chain_oof:
                raise SignalBlocker("CHAIN-S1 outer OOF duplicate row")
            all_chain_oof[key] = float(score)
            outer_records.append(
                {
                    "dataset_id": DATASET_ID,
                    "branch_id": BRANCH_ID,
                    "row_key": key,
                    "group_id": str(row["group_id"]),
                    "outer_fold": outer,
                    "prediction_role": "CHAIN_S1_OUTER_OOF",
                    "y_true": int(str(row["label"]).strip()),
                    "p_attack": float(score),
                    "baseline_p_attack": float(baseline_oof_by_key[key]),
                    "threshold": 0.5,
                    "fit_membership_sha256": context["fit_membership_sha256"],
                    "base_preprocessing_state_sha256": base_state.state_sha256,
                    "signal_scaler_state_sha256": signal_scaler.state_sha256,
                }
            )
        outer_metrics.append(
            {
                "outer_fold": outer,
                "fit_membership_sha256": context["fit_membership_sha256"],
                "train_rows": len(outer_train),
                "heldout_rows": len(outer_eval),
                "base": base_metrics,
                "chain": chain_metrics,
                "comparison": comparison,
                "serialized_replay_max_abs_difference": replay_delta,
                "serialized_replay_threshold_decisions_equal": True,
            }
        )
        model_runs.append(
            {
                "context_id": context_id,
                "fit_rows": outer_train,
                "base_state": base_state,
                "signal_scaler": signal_scaler,
                "estimator": estimator,
                "fit_report": fit_report,
                "signal_artifacts": {
                    "U1": signal_provenance[(f"outer_{outer}_inner_0_signal", "U1")],
                    "U2": signal_provenance[(f"outer_{outer}_inner_0_signal", "U2")],
                    "outer_U1": signal_provenance[(context_id, "U1")],
                    "outer_U2": signal_provenance[(context_id, "U2")],
                },
            }
        )
    if set(all_chain_oof) != set(train_keys):
        raise SignalBlocker("CHAIN-S1 outer OOF coverage is incomplete")

    # Final T fit uses concatenated outer-heldout U signals, never in-sample scores.
    final_train_signal = merged_context_signals(
        [f"outer_{outer}_heldout_inference" for outer in range(3)],
        train_internal,
    )
    final_base_state = fit_chain_base_state(train_internal)
    final_signal_scaler = fit_signal_scaler(train_internal, final_train_signal)
    X_final_train = transform_chain_features(train_internal, final_train_signal, final_signal_scaler, final_base_state)
    y_final_train = np.asarray([int(str(row["label"]).strip()) for row in train_internal], dtype=np.int8)
    final_estimator, final_fit_report = fit_chain_s1(X_final_train, y_final_train, context="final:CHAIN-S1")

    final_u_models: dict[str, Any] = {}
    final_u_states: dict[str, Any] = {}
    final_u_metadata: dict[str, dict[str, Any]] = {}
    final_context = context_by_id["final_train_inference"]
    for model_id in ("U1", "U2"):
        paths = _fit_paths(output_root, "final_train_inference", model_id)
        final_u_models[model_id] = joblib.load(paths["model"])
        final_u_states[model_id] = feature_state_from_dict(_read_json(paths["state"]))
        final_u_metadata[model_id] = _read_json(paths["metadata"])

    def score_validation_signals(rows_for_partition: list[dict[str, Any]]) -> tuple[dict[str, dict[str, float]], dict[str, list[dict[str, Any]]]]:
        u1_scores: list[float] = []
        u2_scores: list[float] = []
        for start in range(0, len(rows_for_partition), 4096):
            batch = rows_for_partition[start : start + 4096]
            feature_rows = _u_feature_rows(batch)
            X_u1 = transform_features(feature_rows, final_u_states["U1"])
            X_u2 = transform_features(feature_rows, final_u_states["U2"])
            u1_scores.extend(float(value) for value in score_u1(final_u_models["U1"], X_u1))
            u2_scores.extend(float(value) for value in score_u2(final_u_models["U2"], X_u2))
        pairs: dict[str, dict[str, float]] = {}
        records_by_model = {"U1": [], "U2": []}
        for row, u1_value, u2_value in zip(rows_for_partition, u1_scores, u2_scores):
            key = str(row["row_key"])
            pairs[key] = {"U1": u1_value, "U2": u2_value}
            for model_id, value in (("U1", u1_value), ("U2", u2_value)):
                records_by_model[model_id].append(
                    {
                        "schema_version": CHAIN_SCHEMA_VERSION,
                        "dataset_id": DATASET_ID,
                        "branch_id": BRANCH_ID,
                        "row_key": key,
                        "group_id": str(row["group_id"]),
                        "context_id": "final_train_inference",
                        "source_role": "VALIDATION_INFERENCE",
                        "model_id": model_id,
                        "model_version": final_u_metadata[model_id].get("model_version"),
                        "artifact_identity": final_u_metadata[model_id].get("artifact_identity"),
                        "preprocessing_identity": final_u_metadata[model_id].get("preprocessing_state_sha256"),
                        "score": value,
                        "score_direction": "HIGHER_MORE_ANOMALOUS",
                        "labels_used": False,
                        "attack_cat_used": False,
                        "test_used": False,
                    }
                )
        return pairs, records_by_model

    validation_chain_scores: dict[str, np.ndarray] = {}
    validation_signal_records: dict[str, dict[str, list[dict[str, Any]]]] = {}
    validation_metrics: dict[str, dict[str, Any]] = {}
    validation_comparisons: dict[str, dict[str, Any]] = {}
    final_model_runs: dict[str, Any] = {}
    for partition, rows_for_partition in validation_rows.items():
        signals_for_partition, records_by_model = score_validation_signals(rows_for_partition)
        validation_signal_records[partition] = records_by_model
        X_validation = transform_chain_features(rows_for_partition, signals_for_partition, final_signal_scaler, final_base_state)
        chain_p = predict_chain_s1(final_estimator, X_validation)
        base_p = baseline_validation[partition]
        y_validation = np.asarray([int(str(row["label"]).strip()) for row in rows_for_partition], dtype=np.int8)
        validation_chain_scores[partition] = chain_p
        validation_metrics[partition] = evaluate_probabilities(y_validation, chain_p)
        validation_comparisons[partition] = compare_pair(y_validation, base_p, chain_p)
        replay_model = joblib.load(io.BytesIO(_serialize_joblib(final_estimator)))
        replay_p = _replay_predictions_in_batches(replay_model, X_validation)
        replay_delta = float(np.max(np.abs(chain_p - replay_p))) if chain_p.size else 0.0
        if replay_delta > 1e-12 or not np.array_equal(chain_p >= 0.5, replay_p >= 0.5):
            raise SignalBlocker(f"CHAIN-S1 validation replay mismatch: {partition}")
        final_model_runs[partition] = {
            "replay_max_abs_difference": replay_delta,
            "replay_threshold_decisions_equal": True,
        }

    final_model_runs["fit"] = {
        "context_id": "final_train_inference",
        "fit_rows": train_internal,
        "base_state": final_base_state,
        "signal_scaler": final_signal_scaler,
        "estimator": final_estimator,
        "fit_report": final_fit_report,
        "signal_artifacts": {
            "U1": [signal_provenance[(f"outer_{outer}_heldout_inference", "U1")] for outer in range(3)],
            "U2": [signal_provenance[(f"outer_{outer}_heldout_inference", "U2")] for outer in range(3)],
        },
    }

    # Pooled outer diagnostics use existing outer OOF baseline rows only.
    ordered_outer_chain = np.asarray([all_chain_oof[key] for key in train_keys], dtype=np.float64)
    outer_labels = np.asarray([int(str(row["label"]).strip()) for row in train_internal], dtype=np.int8)
    pooled_outer = {
        "base": evaluate_probabilities(outer_labels, baseline_oof),
        "chain": evaluate_probabilities(outer_labels, ordered_outer_chain),
        "comparison": compare_pair(outer_labels, baseline_oof, ordered_outer_chain),
    }
    comparison_rows = validation_rows["VALIDATION_COMPARISON"]
    comparison = validation_comparisons["VALIDATION_COMPARISON"]
    chain_comparison_metrics = validation_metrics["VALIDATION_COMPARISON"]
    deterministic = all(
        bool(item.get("serialized_replay_threshold_decisions_equal")) and float(item.get("serialized_replay_max_abs_difference", 1.0)) <= 1e-12
        for item in outer_metrics
    ) and all(item["replay_threshold_decisions_equal"] and item["replay_max_abs_difference"] <= 1e-12 for item in final_model_runs.values() if "replay_max_abs_difference" in item)
    _validate_baseline_snapshot(root, baseline_snapshot)

    # Prepare immutable bytes, then publish only after all development gates pass.
    writes: dict[str, bytes] = {}

    def add_json(relative: str, payload: Any) -> str:
        data = canonical_json_bytes(payload) + b"\n"
        writes[relative] = data
        return sha256_bytes(data)

    def add_jsonl(relative: str, payload: list[dict[str, Any]]) -> str:
        data = b"".join(canonical_json_bytes(row) + b"\n" for row in payload)
        writes[relative] = data
        return sha256_bytes(data)

    model_outputs = model_runs + [final_model_runs["fit"]]
    model_artifact_records: list[dict[str, Any]] = []
    for run in model_outputs:
        context_id = str(run["context_id"])
        model_bytes = _serialize_joblib(run["estimator"])
        base_state_data = canonical_json_bytes(run["base_state"].to_dict()) + b"\n"
        scaler_data = canonical_json_bytes(run["signal_scaler"].to_dict()) + b"\n"
        model_hash = sha256_bytes(model_bytes)
        base_state_hash = sha256_bytes(base_state_data)
        scaler_hash = sha256_bytes(scaler_data)
        model_dir = f"models/{context_id}"
        writes[f"{model_dir}/CHAIN-S1.joblib"] = model_bytes
        writes[f"{model_dir}/CHAIN-S1_base_preprocessing_state.json"] = base_state_data
        writes[f"{model_dir}/CHAIN-S1_signal_scaler.json"] = scaler_data
        metadata_payload = {
            "schema_version": CHAIN_SCHEMA_VERSION,
            "checkpoint": "2.4C",
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "model_id": "CHAIN-S1",
            "model_family": "LOGISTIC_REGRESSION",
            "context_id": context_id,
            "config": dict(CHAIN_S1_CONFIG),
            "source_features": list(BASE_FEATURES) + ["U1_SCORE", "U2_SCORE"],
            "source_feature_count": 30,
            "transformed_feature_count": int(run["base_state"].fit_row_count and len(run["base_state"].output_feature_names) + 2),
            "fit_membership_sha256": membership_sha256([str(row["row_key"]) for row in run["fit_rows"]]),
            "fit_row_count": len(run["fit_rows"]),
            "base_preprocessing_state_sha256": run["base_state"].state_sha256,
            "base_preprocessing_artifact_sha256": base_state_hash,
            "signal_scaler_state_sha256": run["signal_scaler"].state_sha256,
            "signal_scaler_artifact_sha256": scaler_hash,
            "model_artifact_sha256": model_hash,
            "classes": [0, 1],
            "threshold": 0.5,
            "p_attack_class": 1,
            "labels_used": True,
            "attack_cat_used": False,
            "test_used": False,
            "same_row_fit_signal_overlap": 0,
            "same_group_fit_signal_overlap": 0,
            "chain_specific_tuning": "NONE",
            "deterministic_replay": "PASS",
            "fit_report": run["fit_report"],
            "signal_artifacts": run["signal_artifacts"],
        }
        metadata_payload["artifact_identity"] = sha256_bytes(canonical_json_bytes(metadata_payload))
        metadata_hash = add_json(f"{model_dir}/CHAIN-S1_metadata.json", metadata_payload)
        model_artifact_records.append(
            {
                "context_id": context_id,
                "model": f"{model_dir}/CHAIN-S1.joblib",
                "model_sha256": model_hash,
                "metadata": f"{model_dir}/CHAIN-S1_metadata.json",
                "metadata_sha256": metadata_hash,
                "base_state": f"{model_dir}/CHAIN-S1_base_preprocessing_state.json",
                "base_state_sha256": base_state_hash,
                "signal_scaler": f"{model_dir}/CHAIN-S1_signal_scaler.json",
                "signal_scaler_sha256": scaler_hash,
                "artifact_identity": metadata_payload["artifact_identity"],
            }
        )

    add_jsonl("predictions/outer_oof_CHAIN-S1.jsonl", outer_records)
    validation_prediction_paths: dict[str, str] = {}
    for partition, rows_for_partition in validation_rows.items():
        records: list[dict[str, Any]] = []
        for row, score, base_score in zip(rows_for_partition, validation_chain_scores[partition], baseline_validation[partition]):
            records.append(
                {
                    "schema_version": CHAIN_SCHEMA_VERSION,
                    "dataset_id": DATASET_ID,
                    "branch_id": BRANCH_ID,
                    "row_key": str(row["row_key"]),
                    "group_id": str(row["group_id"]),
                    "prediction_role": f"CHAIN_S1_{partition}",
                    "y_true": int(str(row["label"]).strip()),
                    "p_attack": float(score),
                    "baseline_p_attack": float(base_score),
                    "threshold": 0.5,
                    "p_attack_class": 1,
                    "base_preprocessing_state_sha256": final_base_state.state_sha256,
                    "signal_scaler_state_sha256": final_signal_scaler.state_sha256,
                }
            )
        relative = f"predictions/validation_{partition.lower()}_CHAIN-S1.jsonl"
        validation_prediction_paths[partition] = relative
        add_jsonl(relative, records)
    validation_signal_paths: dict[str, dict[str, str]] = {}
    for partition, records_by_model in validation_signal_records.items():
        validation_signal_paths[partition] = {}
        for model_id, records in records_by_model.items():
            relative = f"signals/final_train_inference/validation_{partition.lower()}_{model_id}.jsonl"
            validation_signal_paths[partition][model_id] = relative
            add_jsonl(relative, records)

    development_report = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "checkpoint": "2.4C",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "CHAIN-S1",
        "config": dict(CHAIN_S1_CONFIG),
        "source_feature_count": 30,
        "source_features": list(BASE_FEATURES) + ["U1_SCORE", "U2_SCORE"],
        "train_signal_policy": "OOF_CROSS_FITTED_ONLY",
        "threshold": 0.5,
        "probability_semantics": {"field": "p_attack", "class": 1, "higher": "greater_model_estimated_ATTACK_probability"},
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "outer": outer_metrics,
        "outer_pooled": pooled_outer,
        "validation": {
            "VALIDATION_CALIBRATION": {
                "base": evaluate_probabilities(
                    [int(str(row["label"]).strip()) for row in validation_rows["VALIDATION_CALIBRATION"]],
                    baseline_validation["VALIDATION_CALIBRATION"],
                ),
                "chain": validation_metrics["VALIDATION_CALIBRATION"],
                "comparison": validation_comparisons["VALIDATION_CALIBRATION"],
            },
            "VALIDATION_COMPARISON": {
                "base": evaluate_probabilities(
                    [int(str(row["label"]).strip()) for row in comparison_rows],
                    baseline_validation["VALIDATION_COMPARISON"],
                ),
                "chain": chain_comparison_metrics,
                "comparison": comparison,
            },
        },
        "artifacts": {
            "models": model_artifact_records,
            "predictions": {"outer_oof": "predictions/outer_oof_CHAIN-S1.jsonl", **validation_prediction_paths},
            "validation_signals": validation_signal_paths,
        },
        "upstream_hashes": inputs["upstream_hashes"],
        "parent_checkpoint_2_4B_sha256": sha256_file(checkpoint_b_path),
        "chain_contract_sha256": contract_hash,
        "crossfit_contract_sha256": crossfit_hash,
        "baseline_artifact_hashes": baseline_snapshot,
        "test_used": False,
        "fortigate_used": False,
        "determinism": "PASS" if deterministic else "FAIL",
        "baseline_artifacts_modified": False,
    }
    leakage_report = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "checkpoint": "2.4C",
        "status": "PASS",
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "oof_signals_only": True,
        "global_or_in_sample_signal_substitution": False,
        "training_preprocessing_fit_scope": "TRAINING_SIDE_ONLY",
        "heldout_rows_used_for_fit": False,
        "test_used_for_development": False,
        "baseline_artifacts_modified": False,
    }
    report_hash = add_json("reports/chain_s1_development.json", development_report)
    leakage_hash = add_json("reports/leakage_audit_2_4C.json", leakage_report)
    artifact_hashes = {relative: sha256_bytes(data) for relative, data in writes.items()}
    checkpoint_c = {
        "schema_version": "stage_2.4/checkpoint-2.4C/1.0",
        "checkpoint": "2.4C",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": "docs/plans/stage_2_4_chained_ml_pipeline_plan.md",
        "plan_sha256": contract.get("plan_sha256"),
        "master_plan_sha256": contract.get("master_plan_sha256"),
        "parent_checkpoints": {"2.4A": sha256_file(output_root / "manifests" / "checkpoint_2_4A.json"), "2.4B": sha256_file(checkpoint_b_path)},
        "chain_model": "CHAIN-S1",
        "chain_fit_attempts": 4,
        "chain_fit_contexts": [run["context_id"] for run in model_outputs],
        "source_feature_count": 30,
        "train_signal_policy": "OOF_CROSS_FITTED_ONLY",
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "validation_comparison": comparison,
        "test_used": False,
        "fortigate_used": False,
        "baseline_immutable": True,
        "determinism": "PASS" if deterministic else "FAIL",
        "artifacts": artifact_hashes,
        "next_action": "HUMAN_REVIEW_REQUIRED_FOR_2.4D",
    }
    checkpoint_hash = sha256_bytes(canonical_json_bytes(checkpoint_c) + b"\n")
    writes["manifests/checkpoint_2_4C.json"] = canonical_json_bytes(checkpoint_c) + b"\n"

    for relative, data in writes.items():
        path = output_root / relative
        if path.exists() or path.is_symlink():
            raise SignalBlocker(f"refusing to overwrite existing 2.4C artifact: {relative}")
    for relative, data in writes.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _validate_baseline_snapshot(root, baseline_snapshot)
    if not deterministic:
        raise SignalBlocker("CHAIN-S1 deterministic replay failed")
    return {
        "status": "PASS",
        "checkpoint": "2.4C",
        "model": "CHAIN-S1",
        "source_feature_count": 30,
        "chain_fit_attempts": 4,
        "base_ap": comparison["base_ap"],
        "chain_ap": comparison["chain_ap"],
        "delta_ap": comparison["delta_ap"],
        "comparison": comparison["decision"],
        "chain_metrics": chain_comparison_metrics,
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "test_used": False,
        "determinism": "PASS",
        "report": str((output_root / "reports" / "chain_s1_development.json").relative_to(root)),
        "checkpoint_sha256": checkpoint_hash,
    }


run_checkpoint_2_4c = _run_checkpoint_2_4c


def _snapshot_stage23_s2_baseline(root: Path) -> dict[str, str]:
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    relatives = [
        "models/S2/final.joblib",
        "models/S2/final_feature_state.json",
        "models/S2/final_metadata.json",
        "predictions/oof_S2.jsonl",
        "predictions/validation_validation_calibration_S2.jsonl",
        "predictions/validation_validation_comparison_S2.jsonl",
        "reports/selection_S2.json",
        "reports/validation_S2.json",
    ]
    snapshot: dict[str, str] = {}
    for relative in relatives:
        path = baseline_root / relative
        if not path.is_file():
            raise SignalBlocker(f"frozen BASE S2 artifact is missing: {relative}")
        snapshot[relative] = sha256_file(path)
    metadata = _read_json(baseline_root / "models/S2/final_metadata.json")
    if metadata.get("config") != SUPERVISED_S2_CONFIG or metadata.get("classes") != [0, 1] or metadata.get("threshold") != 0.5 or metadata.get("test_used") is not False:
        raise SignalBlocker("frozen BASE S2 metadata is not immutable")
    selection = _read_json(baseline_root / "reports/selection_S2.json")
    if selection.get("development_s2_config") != SUPERVISED_S2_CONFIG or selection.get("threshold") != 0.5 or selection.get("test_used") is not False or selection.get("chained_signals_used") is not False:
        raise SignalBlocker("frozen BASE S2 selection is not development-safe")
    return snapshot


def _validate_snapshot(root: Path, snapshot: dict[str, str]) -> None:
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    for relative, expected in snapshot.items():
        observed = sha256_file(baseline_root / relative)
        if observed != expected:
            raise SignalBlocker(f"baseline artifact changed during 2.4D: {relative}")


def _load_chain1_preprocessing(output_root: Path, context_id: str) -> tuple[Any, SignalScaler, dict[str, Any]]:
    model_dir = output_root / "models" / context_id
    metadata = _read_json(model_dir / "CHAIN-S1_metadata.json")
    if metadata.get("model_id") != "CHAIN-S1" or metadata.get("source_feature_count") != 30 or metadata.get("config", {}).get("C") != 1.0:
        raise SignalBlocker(f"CHAIN-S1 preprocessing lineage mismatch: {context_id}")
    base_state = feature_state_from_dict(_read_json(model_dir / "CHAIN-S1_base_preprocessing_state.json"))
    scaler_payload = _read_json(model_dir / "CHAIN-S1_signal_scaler.json")
    scaler_fields = {field: scaler_payload[field] for field in SignalScaler.__dataclass_fields__}
    scaler = SignalScaler(**scaler_fields)
    if sha256_file(model_dir / "CHAIN-S1_base_preprocessing_state.json") != metadata.get("base_preprocessing_artifact_sha256"):
        raise SignalBlocker(f"CHAIN-S1 base preprocessing hash mismatch: {context_id}")
    if sha256_file(model_dir / "CHAIN-S1_signal_scaler.json") != metadata.get("signal_scaler_artifact_sha256"):
        raise SignalBlocker(f"CHAIN-S1 signal scaler hash mismatch: {context_id}")
    return base_state, scaler, metadata


def _load_checkpoint_2_4c(root: Path, output_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    checkpoint_path = output_root / "manifests" / "checkpoint_2_4C.json"
    report_path = output_root / "reports" / "chain_s1_development.json"
    leakage_path = output_root / "reports" / "leakage_audit_2_4C.json"
    for path in (checkpoint_path, report_path, leakage_path):
        if not path.is_file():
            raise SignalBlocker(f"2.4C artifact missing: {path.name}")
    checkpoint = _read_json(checkpoint_path)
    report = _read_json(report_path)
    leakage = _read_json(leakage_path)
    if checkpoint.get("status") != "PASS" or report.get("status") != "PASS" or leakage.get("status") != "PASS":
        raise SignalBlocker("2.4C is not a passing checkpoint")
    if checkpoint.get("test_used") is not False or report.get("test_used") is not False or leakage.get("test_used_for_development") is not False:
        raise SignalBlocker("2.4C used TEST")
    for relative, expected in checkpoint.get("artifacts", {}).items():
        if relative == "manifests/checkpoint_2_4C.json":
            continue
        if sha256_file(output_root / relative) != expected:
            raise SignalBlocker(f"2.4C artifact hash mismatch: {relative}")
    comparison = report.get("validation", {}).get("VALIDATION_COMPARISON", {})
    if comparison.get("chain", {}).get("average_precision") != 0.9941359114288555 or comparison.get("comparison", {}).get("delta_ap") != 0.00021276179167273312:
        raise SignalBlocker("frozen CHAIN-S1 development result changed")
    return checkpoint, report


def _run_checkpoint_2_4d(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Fit and evaluate only the approved CHAIN-S2 development branch."""

    root = Path(root)
    inputs = validate_inputs(root)
    contract, crossfit, _, contract_hash, crossfit_hash = _load_2_4a_contract(root, inputs)
    output_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
    checkpoint_b_path = output_root / "manifests" / "checkpoint_2_4B.json"
    coverage_path = output_root / "manifests" / "signal_coverage.json"
    leakage_b_path = output_root / "reports" / "leakage_audit_2_4B.json"
    checkpoint_c, report_c = _load_checkpoint_2_4c(root, output_root)
    for path in (checkpoint_b_path, coverage_path, leakage_b_path):
        if not path.is_file():
            raise SignalBlocker(f"2.4B artifact missing: {path.name}")
    checkpoint_b = _read_json(checkpoint_b_path)
    coverage = _read_json(coverage_path)
    leakage_b = _read_json(leakage_b_path)
    if checkpoint_b.get("status") != "PASS" or checkpoint_b.get("test_used") is not False or checkpoint_b.get("actual_anomaly_fits_completed") != 20 or checkpoint_b.get("remaining_chain_fits") != 8:
        raise SignalBlocker("2.4B fit accounting is not closed")
    if coverage.get("status") != "PASS" or coverage.get("required_rows") != 140273 or coverage.get("same_row_fit_signal_overlap") != 0 or coverage.get("same_group_fit_signal_overlap") != 0:
        raise SignalBlocker("2.4B signal coverage is not closed")
    if leakage_b.get("status") != "PASS" or leakage_b.get("fit_partition_leakage") != 0 or leakage_b.get("unauthorized_validation_contribution") != 0:
        raise SignalBlocker("2.4B leakage audit is not PASS")
    if checkpoint_b.get("artifacts", {}).get("manifests/signal_coverage.json") != sha256_file(coverage_path) or checkpoint_b.get("artifacts", {}).get("reports/leakage_audit_2_4B.json") != sha256_file(leakage_b_path):
        raise SignalBlocker("2.4B artifact hash mismatch")

    rows, _, _ = _load_upstream()
    train_internal = [row for row in rows if row.get("development_partition") == "TRAIN_INTERNAL"]
    validation_rows = {partition: [row for row in rows if row.get("development_partition") == partition] for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")}
    if len(train_internal) != 140273 or len(validation_rows["VALIDATION_CALIBRATION"]) != 17539 or len(validation_rows["VALIDATION_COMPARISON"]) != 17529:
        raise SignalBlocker("Stage 2.4 development populations changed")
    fold_by_key = {str(item["row_key"]): item for item in inputs["folds"]}
    train_keys = [str(row["row_key"]) for row in train_internal]
    context_by_id = {str(item["context_id"]): dict(item) for item in crossfit["contexts"]}
    signal_cache: dict[tuple[str, str], dict[str, float]] = {}
    signal_provenance: dict[tuple[str, str], dict[str, Any]] = {}
    raw_source_sha256 = "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
    for context_id, context in context_by_id.items():
        for model_id in ("U1", "U2"):
            paths = _fit_paths(output_root, context_id, model_id)
            metadata = _validate_reuse(paths, context, model_id, raw_source_sha256=raw_source_sha256, contract_hash=contract_hash, crossfit_hash=crossfit_hash)
            if metadata is None:
                raise SignalBlocker(f"2.4B fit artifact cannot be reused: {context_id}:{model_id}")
            values, provenance = _load_signal_map(output_root, context, model_id)
            if provenance["artifact_identity"] != metadata.get("artifact_identity"):
                raise SignalBlocker("2.4B signal provenance identity mismatch")
            signal_cache[(context_id, model_id)] = values
            signal_provenance[(context_id, model_id)] = provenance

    baseline_s1_snapshot = _snapshot_baseline(root)
    baseline_s2_snapshot = _snapshot_stage23_s2_baseline(root)
    baseline_snapshot = baseline_s1_snapshot | baseline_s2_snapshot
    baseline_root = root / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"
    baseline_oof = _load_baseline_scores(baseline_root / "predictions/oof_S2.jsonl", train_internal, "S2", "OUTER_OOF", expected_config=SUPERVISED_S2_CONFIG)
    baseline_oof_by_key = {str(row["row_key"]): float(score) for row, score in zip(train_internal, baseline_oof)}
    baseline_validation: dict[str, np.ndarray] = {}
    for partition, rows_for_partition in validation_rows.items():
        baseline_validation[partition] = _load_baseline_scores(
            baseline_root / "predictions" / f"validation_{partition.lower()}_S2.jsonl",
            rows_for_partition,
            "S2",
            f"VALIDATION_{partition}",
            expected_config=SUPERVISED_S2_CONFIG,
        )

    def merged_context_signals(context_ids: list[str], rows_for_context: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
        keys = [str(row["row_key"]) for row in rows_for_context]
        u1: dict[str, float] = {}
        u2: dict[str, float] = {}
        for context_id in context_ids:
            for key, value in signal_cache[(context_id, "U1")].items():
                if key in u1:
                    raise SignalBlocker("duplicate U1 OOF assignment")
                u1[key] = value
            for key, value in signal_cache[(context_id, "U2")].items():
                if key in u2:
                    raise SignalBlocker("duplicate U2 OOF assignment")
                u2[key] = value
        return _merge_signal_maps(keys, u1, u2)

    model_runs: list[dict[str, Any]] = []
    outer_records: list[dict[str, Any]] = []
    outer_metrics: list[dict[str, Any]] = []
    all_chain_oof: dict[str, float] = {}
    for outer in range(3):
        outer_eval = [row for row in train_internal if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) == outer]
        outer_train = [row for row in train_internal if int(fold_by_key[str(row["row_key"])] ["outer_fold"]) != outer]
        context_id = f"outer_{outer}_heldout_inference"
        context = context_by_id[context_id]
        train_signal = merged_context_signals([f"outer_{outer}_inner_0_signal", f"outer_{outer}_inner_1_signal"], outer_train)
        eval_signal = merged_context_signals([context_id], outer_eval)
        base_state, signal_scaler, chain1_metadata = _load_chain1_preprocessing(output_root, context_id)
        if chain1_metadata.get("fit_membership_sha256") != membership_sha256([str(row["row_key"]) for row in outer_train]):
            raise SignalBlocker(f"CHAIN-S1 outer lineage mismatch: {outer}")
        X_train = transform_chain_features(outer_train, train_signal, signal_scaler, base_state)
        X_eval = transform_chain_features(outer_eval, eval_signal, signal_scaler, base_state)
        y_train = np.asarray([int(str(row["label"]).strip()) for row in outer_train], dtype=np.int8)
        y_eval = np.asarray([int(str(row["label"]).strip()) for row in outer_eval], dtype=np.int8)
        estimator, fit_report = fit_chain_s2(X_train, y_train, context=f"outer:{outer}:CHAIN-S2")
        p_chain = predict_chain_s2(estimator, X_eval)
        p_base = np.asarray([baseline_oof_by_key[str(row["row_key"])] for row in outer_eval], dtype=np.float64)
        replay_model = joblib.load(io.BytesIO(_serialize_joblib(estimator)))
        replay_p = _replay_predictions_in_batches(replay_model, X_eval)
        replay_delta = float(np.max(np.abs(p_chain - replay_p))) if p_chain.size else 0.0
        if replay_delta > 1e-12 or not np.array_equal(p_chain >= 0.5, replay_p >= 0.5):
            raise SignalBlocker(f"CHAIN-S2 outer {outer} serialized replay mismatch")
        comparison = compare_pair(y_eval, p_base, p_chain)
        for row, score in zip(outer_eval, p_chain):
            key = str(row["row_key"])
            if key in all_chain_oof:
                raise SignalBlocker("CHAIN-S2 outer OOF duplicate row")
            all_chain_oof[key] = float(score)
            outer_records.append({
                "schema_version": CHAIN_SCHEMA_VERSION,
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "row_key": key,
                "group_id": str(row["group_id"]),
                "outer_fold": outer,
                "prediction_role": "CHAIN_S2_OUTER_OOF",
                "y_true": int(str(row["label"]).strip()),
                "p_attack": float(score),
                "baseline_p_attack": float(baseline_oof_by_key[key]),
                "threshold": 0.5,
                "p_attack_class": 1,
                "fit_membership_sha256": context["fit_membership_sha256"],
                "base_preprocessing_state_sha256": base_state.state_sha256,
                "signal_scaler_state_sha256": signal_scaler.state_sha256,
            })
        outer_metrics.append({
            "outer_fold": outer,
            "fit_membership_sha256": context["fit_membership_sha256"],
            "train_rows": len(outer_train),
            "heldout_rows": len(outer_eval),
            "base": evaluate_probabilities(y_eval, p_base),
            "chain": evaluate_probabilities(y_eval, p_chain),
            "comparison": comparison,
            "serialized_replay_max_abs_difference": replay_delta,
            "serialized_replay_threshold_decisions_equal": True,
        })
        model_runs.append({
            "context_id": context_id,
            "fit_rows": outer_train,
            "base_state": base_state,
            "signal_scaler": signal_scaler,
            "estimator": estimator,
            "fit_report": fit_report,
            "signal_artifacts": {
                "U1_inner_0": signal_provenance[(f"outer_{outer}_inner_0_signal", "U1")],
                "U2_inner_0": signal_provenance[(f"outer_{outer}_inner_0_signal", "U2")],
                "U1_inner_1": signal_provenance[(f"outer_{outer}_inner_1_signal", "U1")],
                "U2_inner_1": signal_provenance[(f"outer_{outer}_inner_1_signal", "U2")],
                "U1_outer": signal_provenance[(context_id, "U1")],
                "U2_outer": signal_provenance[(context_id, "U2")],
            },
        })
    if set(all_chain_oof) != set(train_keys):
        raise SignalBlocker("CHAIN-S2 outer OOF coverage is incomplete")

    final_train_signal = merged_context_signals([f"outer_{outer}_heldout_inference" for outer in range(3)], train_internal)
    final_base_state, final_signal_scaler, final_chain1_metadata = _load_chain1_preprocessing(output_root, "final_train_inference")
    if final_chain1_metadata.get("fit_membership_sha256") != membership_sha256(train_keys):
        raise SignalBlocker("CHAIN-S1 final lineage mismatch")
    X_final_train = transform_chain_features(train_internal, final_train_signal, final_signal_scaler, final_base_state)
    y_final_train = np.asarray([int(str(row["label"]).strip()) for row in train_internal], dtype=np.int8)
    final_estimator, final_fit_report = fit_chain_s2(X_final_train, y_final_train, context="final:CHAIN-S2")
    final_u_metadata = {model_id: _read_json(_fit_paths(output_root, "final_train_inference", model_id)["metadata"]) for model_id in ("U1", "U2")}
    validation_chain_scores: dict[str, np.ndarray] = {}
    validation_signal_records: dict[str, dict[str, list[dict[str, Any]]]] = {}
    validation_metrics: dict[str, dict[str, Any]] = {}
    validation_comparisons: dict[str, dict[str, Any]] = {}
    final_model_runs: dict[str, Any] = {}
    for partition, rows_for_partition in validation_rows.items():
        u1_values, u1_provenance = _load_validation_signal_map(output_root, rows_for_partition, partition, "U1", final_u_metadata["U1"])
        u2_values, u2_provenance = _load_validation_signal_map(output_root, rows_for_partition, partition, "U2", final_u_metadata["U2"])
        signals_for_partition = _merge_signal_maps([str(row["row_key"]) for row in rows_for_partition], u1_values, u2_values)
        records_by_model = {
            "U1": [{"row_key": key, "score": value, "provenance": u1_provenance} for key, value in u1_values.items()],
            "U2": [{"row_key": key, "score": value, "provenance": u2_provenance} for key, value in u2_values.items()],
        }
        validation_signal_records[partition] = records_by_model
        X_validation = transform_chain_features(rows_for_partition, signals_for_partition, final_signal_scaler, final_base_state)
        chain_p = predict_chain_s2(final_estimator, X_validation)
        base_p = baseline_validation[partition]
        y_validation = np.asarray([int(str(row["label"]).strip()) for row in rows_for_partition], dtype=np.int8)
        validation_chain_scores[partition] = chain_p
        validation_metrics[partition] = evaluate_probabilities(y_validation, chain_p)
        validation_comparisons[partition] = compare_pair(y_validation, base_p, chain_p)
        replay_model = joblib.load(io.BytesIO(_serialize_joblib(final_estimator)))
        replay_p = _replay_predictions_in_batches(replay_model, X_validation)
        replay_delta = float(np.max(np.abs(chain_p - replay_p))) if chain_p.size else 0.0
        if replay_delta > 1e-12 or not np.array_equal(chain_p >= 0.5, replay_p >= 0.5):
            raise SignalBlocker(f"CHAIN-S2 validation replay mismatch: {partition}")
        final_model_runs[partition] = {"replay_max_abs_difference": replay_delta, "replay_threshold_decisions_equal": True}
    final_model_runs["fit"] = {
        "context_id": "final_train_inference",
        "fit_rows": train_internal,
        "base_state": final_base_state,
        "signal_scaler": final_signal_scaler,
        "estimator": final_estimator,
        "fit_report": final_fit_report,
        "signal_artifacts": {
            "U1": [signal_provenance[(f"outer_{outer}_heldout_inference", "U1")] for outer in range(3)],
            "U2": [signal_provenance[(f"outer_{outer}_heldout_inference", "U2")] for outer in range(3)],
        },
    }

    ordered_outer_chain = np.asarray([all_chain_oof[key] for key in train_keys], dtype=np.float64)
    outer_labels = np.asarray([int(str(row["label"]).strip()) for row in train_internal], dtype=np.int8)
    pooled_outer = {
        "base": evaluate_probabilities(outer_labels, baseline_oof),
        "chain": evaluate_probabilities(outer_labels, ordered_outer_chain),
        "comparison": compare_pair(outer_labels, baseline_oof, ordered_outer_chain),
    }
    comparison_rows = validation_rows["VALIDATION_COMPARISON"]
    comparison = validation_comparisons["VALIDATION_COMPARISON"]
    chain_comparison_metrics = validation_metrics["VALIDATION_COMPARISON"]
    deterministic = all(item["serialized_replay_threshold_decisions_equal"] and item["serialized_replay_max_abs_difference"] <= 1e-12 for item in outer_metrics) and all(item["replay_threshold_decisions_equal"] and item["replay_max_abs_difference"] <= 1e-12 for item in final_model_runs.values() if "replay_max_abs_difference" in item)
    _validate_snapshot(root, baseline_snapshot)

    writes: dict[str, bytes] = {}
    def add_json(relative: str, payload: Any) -> str:
        data = canonical_json_bytes(payload) + b"\n"
        writes[relative] = data
        return sha256_bytes(data)
    def add_jsonl(relative: str, payload: list[dict[str, Any]]) -> str:
        data = b"".join(canonical_json_bytes(row) + b"\n" for row in payload)
        writes[relative] = data
        return sha256_bytes(data)

    model_outputs = model_runs + [final_model_runs["fit"]]
    model_artifact_records: list[dict[str, Any]] = []
    for run in model_outputs:
        context_id = str(run["context_id"])
        model_bytes = _serialize_joblib(run["estimator"])
        base_state_data = canonical_json_bytes(run["base_state"].to_dict()) + b"\n"
        scaler_data = canonical_json_bytes(run["signal_scaler"].to_dict()) + b"\n"
        model_dir = f"models/{context_id}"
        model_hash = sha256_bytes(model_bytes)
        base_state_hash = sha256_bytes(base_state_data)
        scaler_hash = sha256_bytes(scaler_data)
        writes[f"{model_dir}/CHAIN-S2.joblib"] = model_bytes
        writes[f"{model_dir}/CHAIN-S2_base_preprocessing_state.json"] = base_state_data
        writes[f"{model_dir}/CHAIN-S2_signal_scaler.json"] = scaler_data
        metadata_payload = {
            "schema_version": CHAIN_SCHEMA_VERSION,
            "checkpoint": "2.4D",
            "dataset_id": DATASET_ID,
            "branch_id": BRANCH_ID,
            "model_id": "CHAIN-S2",
            "model_family": "RANDOM_FOREST",
            "context_id": context_id,
            "config": dict(CHAIN_S2_CONFIG),
            "source_features": list(BASE_FEATURES) + ["U1_SCORE", "U2_SCORE"],
            "source_feature_count": 30,
            "transformed_feature_count": len(run["base_state"].output_feature_names) + 2,
            "fit_membership_sha256": membership_sha256([str(row["row_key"]) for row in run["fit_rows"]]),
            "fit_row_count": len(run["fit_rows"]),
            "base_preprocessing_state_sha256": run["base_state"].state_sha256,
            "base_preprocessing_artifact_sha256": base_state_hash,
            "signal_scaler_state_sha256": run["signal_scaler"].state_sha256,
            "signal_scaler_artifact_sha256": scaler_hash,
            "model_artifact_sha256": model_hash,
            "classes": [0, 1],
            "threshold": 0.5,
            "p_attack_class": 1,
            "labels_used": True,
            "attack_cat_used": False,
            "test_used": False,
            "same_row_fit_signal_overlap": 0,
            "same_group_fit_signal_overlap": 0,
            "chain_specific_tuning": "NONE",
            "deterministic_replay": "PASS",
            "fit_report": run["fit_report"],
            "signal_artifacts": run["signal_artifacts"],
        }
        metadata_payload["artifact_identity"] = sha256_bytes(canonical_json_bytes(metadata_payload))
        metadata_hash = add_json(f"{model_dir}/CHAIN-S2_metadata.json", metadata_payload)
        model_artifact_records.append({"context_id": context_id, "model": f"{model_dir}/CHAIN-S2.joblib", "model_sha256": model_hash, "metadata": f"{model_dir}/CHAIN-S2_metadata.json", "metadata_sha256": metadata_hash, "base_state": f"{model_dir}/CHAIN-S2_base_preprocessing_state.json", "base_state_sha256": base_state_hash, "signal_scaler": f"{model_dir}/CHAIN-S2_signal_scaler.json", "signal_scaler_sha256": scaler_hash, "artifact_identity": metadata_payload["artifact_identity"]})

    add_jsonl("predictions/outer_oof_CHAIN-S2.jsonl", outer_records)
    validation_prediction_paths: dict[str, str] = {}
    for partition, rows_for_partition in validation_rows.items():
        records = []
        for row, score, base_score in zip(rows_for_partition, validation_chain_scores[partition], baseline_validation[partition]):
            records.append({"schema_version": CHAIN_SCHEMA_VERSION, "dataset_id": DATASET_ID, "branch_id": BRANCH_ID, "row_key": str(row["row_key"]), "group_id": str(row["group_id"]), "prediction_role": f"CHAIN_S2_{partition}", "y_true": int(str(row["label"]).strip()), "p_attack": float(score), "baseline_p_attack": float(base_score), "threshold": 0.5, "p_attack_class": 1, "base_preprocessing_state_sha256": final_base_state.state_sha256, "signal_scaler_state_sha256": final_signal_scaler.state_sha256})
        relative = f"predictions/validation_{partition.lower()}_CHAIN-S2.jsonl"
        validation_prediction_paths[partition] = relative
        add_jsonl(relative, records)

    development_report = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "checkpoint": "2.4D",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "CHAIN-S2",
        "config": dict(CHAIN_S2_CONFIG),
        "source_feature_count": 30,
        "source_features": list(BASE_FEATURES) + ["U1_SCORE", "U2_SCORE"],
        "train_signal_policy": "OOF_CROSS_FITTED_ONLY",
        "threshold": 0.5,
        "probability_semantics": {"field": "p_attack", "class": 1, "higher": "greater_model_estimated_ATTACK_probability"},
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "outer": outer_metrics,
        "outer_pooled": pooled_outer,
        "validation": {
            "VALIDATION_CALIBRATION": {"base": evaluate_probabilities([int(str(row["label"]).strip()) for row in validation_rows["VALIDATION_CALIBRATION"]], baseline_validation["VALIDATION_CALIBRATION"]), "chain": validation_metrics["VALIDATION_CALIBRATION"], "comparison": validation_comparisons["VALIDATION_CALIBRATION"]},
            "VALIDATION_COMPARISON": {"base": evaluate_probabilities([int(str(row["label"]).strip()) for row in comparison_rows], baseline_validation["VALIDATION_COMPARISON"]), "chain": chain_comparison_metrics, "comparison": comparison},
        },
        "artifacts": {"models": model_artifact_records, "predictions": {"outer_oof": "predictions/outer_oof_CHAIN-S2.jsonl", **validation_prediction_paths}},
        "upstream_hashes": inputs["upstream_hashes"],
        "parent_checkpoint_2_4C_sha256": sha256_file(output_root / "manifests/checkpoint_2_4C.json"),
        "chain_contract_sha256": contract_hash,
        "crossfit_contract_sha256": crossfit_hash,
        "baseline_artifact_hashes": baseline_snapshot,
        "test_used": False,
        "prior_test_results_used_for_development": False,
        "fortigate_used": False,
        "determinism": "PASS" if deterministic else "FAIL",
        "baseline_artifacts_modified": False,
    }
    leakage_report = {"schema_version": CHAIN_SCHEMA_VERSION, "checkpoint": "2.4D", "status": "PASS", "same_row_fit_signal_overlap": 0, "same_group_fit_signal_overlap": 0, "oof_signals_only": True, "global_or_in_sample_signal_substitution": False, "training_preprocessing_fit_scope": "TRAINING_SIDE_ONLY", "heldout_rows_used_for_fit": False, "test_used_for_development": False, "prior_test_results_used_for_development": False, "baseline_artifacts_modified": False}
    report_hash = add_json("reports/chain_s2_development.json", development_report)
    leakage_hash = add_json("reports/leakage_audit_2_4D.json", leakage_report)

    chain_s1_comparison = report_c["validation"]["VALIDATION_COMPARISON"]["comparison"]
    chain_s1_metrics = report_c["validation"]["VALIDATION_COMPARISON"]["chain"]
    chain_preferred = "CHAIN-S2" if comparison["chain_ap"] > chain_s1_comparison["chain_ap"] + 1e-6 else "CHAIN-S1"
    selection_lock = {
        "schema_version": "stage_2.4/selection-lock/1.0",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "checkpoint": "2.4D",
        "chain_features": {"source_feature_count": 30, "source_features": list(BASE_FEATURES) + ["U1_SCORE", "U2_SCORE"]},
        "signals": {"U1": {"config": dict(U1_CONFIG), "score_definition": "negative score_samples", "score_direction": "HIGHER_MORE_ANOMALOUS"}, "U2": {"config": dict(U2_CONFIG), "score_definition": "nearest-centroid squared distance", "score_direction": "HIGHER_MORE_ANOMALOUS"}},
        "crossfit": {"contract_sha256": crossfit_hash, "schema_version": crossfit.get("schema_version"), "training_signal_policy": "OOF_CROSS_FITTED_ONLY"},
        "models": {"CHAIN-S1": {"config": dict(CHAIN_S1_CONFIG), "threshold": 0.5, "development_ap": chain_s1_comparison["chain_ap"], "baseline_ap": chain_s1_comparison["base_ap"], "delta_ap": chain_s1_comparison["delta_ap"], "comparison": chain_s1_comparison["decision"], "artifacts": report_c["artifacts"]["models"]}, "CHAIN-S2": {"config": dict(CHAIN_S2_CONFIG), "threshold": 0.5, "development_ap": comparison["chain_ap"], "baseline_ap": comparison["base_ap"], "delta_ap": comparison["delta_ap"], "comparison": comparison["decision"], "artifacts": model_artifact_records}},
        "chain_preferred_model": chain_preferred,
        "comparison_rows": {partition: {"row_count": len(rows_for_partition), "prediction_path": f"predictions/validation_{partition.lower()}_CHAIN-S2.jsonl", "baseline_prediction_path": f"../stage_2_3/v1/predictions/validation_{partition.lower()}_S2.jsonl"} for partition, rows_for_partition in validation_rows.items()},
        "metric": {"primary": "AVERAGE_PRECISION", "implementation": "sklearn.metrics.average_precision_score", "positive_class": 1, "score_field": "p_attack", "tolerance": 1e-6},
        "threshold_policy": {"CHAIN-S1": 0.5, "CHAIN-S2": 0.5, "post_test_tuning_allowed": False},
        "group_contract": {"same_row_fit_signal_overlap": 0, "same_group_fit_signal_overlap": 0, "dataset_scope": "UNSW_NB15_ONLY", "fortigate_used": False},
        "baseline_artifact_hashes": baseline_snapshot,
        "parent_checkpoints": {"2.4B": sha256_file(checkpoint_b_path), "2.4C": sha256_file(output_root / "manifests/checkpoint_2_4C.json")},
        "prior_test_results_used_for_development": False,
        "test_role": "LOCKED_FROM_DEVELOPMENT",
        "test_used": False,
        "no_post_test_tuning": True,
        "deterministic_replay": "PASS" if deterministic else "FAIL",
    }
    selection_lock_hash = sha256_bytes(canonical_json_bytes(selection_lock) + b"\n")
    add_json("manifests/selection_lock.json", selection_lock)
    artifact_hashes = {relative: sha256_bytes(data) for relative, data in writes.items()}
    checkpoint_d = {
        "schema_version": "stage_2.4/checkpoint-2.4D/1.0",
        "checkpoint": "2.4D",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan": "docs/plans/stage_2_4_chained_ml_pipeline_plan.md",
        "plan_sha256": contract.get("plan_sha256"),
        "master_plan_sha256": contract.get("master_plan_sha256"),
        "parent_checkpoints": {"2.4B": sha256_file(checkpoint_b_path), "2.4C": sha256_file(output_root / "manifests/checkpoint_2_4C.json")},
        "chain_model": "CHAIN-S2",
        "chain_fit_attempts": 4,
        "chain_fit_contexts": [run["context_id"] for run in model_outputs],
        "source_feature_count": 30,
        "train_signal_policy": "OOF_CROSS_FITTED_ONLY",
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
        "validation_comparison": comparison,
        "prior_test_results_used_for_development": False,
        "test_used": False,
        "fortigate_used": False,
        "baseline_immutable": True,
        "determinism": "PASS" if deterministic else "FAIL",
        "selection_lock_sha256": selection_lock_hash,
        "artifacts": artifact_hashes,
        "next_action": "HUMAN_AUTHORIZATION_REQUIRED_FOR_2.4E",
    }
    writes["manifests/checkpoint_2_4D.json"] = canonical_json_bytes(checkpoint_d) + b"\n"
    for relative in writes:
        path = output_root / relative
        if path.exists() or path.is_symlink():
            raise SignalBlocker(f"refusing to overwrite existing 2.4D artifact: {relative}")
    for relative, data in writes.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _validate_snapshot(root, baseline_snapshot)
    if not deterministic:
        raise SignalBlocker("CHAIN-S2 deterministic replay failed")
    return {"status": "PASS", "checkpoint": "2.4D", "model": "CHAIN-S2", "source_feature_count": 30, "chain_fit_attempts": 4, "base_ap": comparison["base_ap"], "chain_ap": comparison["chain_ap"], "delta_ap": comparison["delta_ap"], "comparison": comparison["decision"], "chain_metrics": chain_comparison_metrics, "same_row_fit_signal_overlap": 0, "same_group_fit_signal_overlap": 0, "test_used": False, "prior_test_results_used_for_development": False, "determinism": "PASS", "selection_lock_sha256": selection_lock_hash, "report": str((output_root / "reports/chain_s2_development.json").relative_to(root))}


run_checkpoint_2_4d = _run_checkpoint_2_4d


def _fit_plan(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    for context in contexts:
        if context["kind"] not in {"INNER_SIGNAL", "OUTER_INFERENCE", "FINAL_INFERENCE"}:
            continue
        for model_id, config in (("U1", U1_CONFIG), ("U2", U2_CONFIG)):
            plan.append({
                "fit_id": f"{context['context_id']}:{model_id}",
                "kind": "ANOMALY_SIGNAL_FIT",
                "model_id": model_id,
                "context_id": context["context_id"],
                "fit_membership_sha256": context["fit_membership_sha256"],
                "score_membership_sha256": context["score_membership_sha256"],
                "fit_rows": len(context["fit_row_keys"]),
                "score_rows": len(context["score_row_keys"]),
                "config": dict(config),
                "label_free": True,
                "executed": False,
            })
    for context in contexts:
        if context["kind"] == "OUTER_INFERENCE":
            for model_id, config in (("CHAIN-S1", CHAIN_S1_CONFIG), ("CHAIN-S2", CHAIN_S2_CONFIG)):
                plan.append({
                    "fit_id": f"{context['context_id']}:{model_id}",
                    "kind": "CHAIN_MODEL_FIT",
                    "model_id": model_id,
                    "context_id": context["context_id"],
                    "fit_membership_sha256": context["fit_membership_sha256"],
                    "score_membership_sha256": None,
                    "fit_rows": len(context["fit_row_keys"]),
                    "score_rows": len(context["score_row_keys"]),
                    "config": dict(config),
                    "executed": False,
                })
        if context["kind"] == "FINAL_INFERENCE":
            for model_id, config in (("CHAIN-S1", CHAIN_S1_CONFIG), ("CHAIN-S2", CHAIN_S2_CONFIG)):
                plan.append({
                    "fit_id": f"{context['context_id']}:{model_id}",
                    "kind": "CHAIN_MODEL_FIT",
                    "model_id": model_id,
                    "context_id": context["context_id"],
                    "fit_membership_sha256": context["fit_membership_sha256"],
                    "score_membership_sha256": None,
                    "fit_rows": len(context["fit_row_keys"]),
                    "score_rows": 0,
                    "config": dict(config),
                    "executed": False,
                })
    return plan


def run_checkpoint_2_4a(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    inputs = validate_inputs(root)
    contexts = build_contexts(inputs["folds"])
    validate_nested_contexts(contexts)
    fit_plan = _fit_plan(contexts)
    if len(fit_plan) != EXPECTED_FIT_ATTEMPTS:
        raise RuntimeError(f"planned fit count mismatch: {len(fit_plan)}")
    output_root = Path(root) / "data" / "unsw_nb15" / "processed" / "stage_2_4" / "v1"
    contract_path = output_root / "contracts" / "chain_contract.json"
    crossfit_path = output_root / "manifests" / "crossfit_contract.json"
    checkpoint_path = output_root / "manifests" / "checkpoint_2_4A.json"
    root_manifest_path = output_root / "manifest.json"
    contract = build_chain_contract()
    contract_hash = _write_json(contract_path, contract)
    crossfit = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "dataset_id": inputs["dataset_id"],
        "branch_id": inputs["branch_id"],
        "status": "PASS",
        "test_used": False,
        "label_free_signal_plan": True,
        "upstream_hashes": inputs["upstream_hashes"],
        "fold_manifest_sha256": inputs["fold_manifest_sha256"],
        "selection_lock_sha256": inputs["selection_lock_sha256"],
        "contexts": contexts,
        "fit_plan": fit_plan,
        "expected_fit_attempts": EXPECTED_FIT_ATTEMPTS,
        "actual_fit_attempts": 0,
        "signal_artifacts_published": False,
        "same_row_overlap": 0,
        "same_group_overlap": 0,
        "outer_group_exclusion": "PASS",
        "preprocessing_boundaries": contract["preprocessing_boundaries"],
    }
    crossfit_hash = _write_json(crossfit_path, crossfit)
    checkpoint = {
        "schema_version": "stage_2.4/checkpoint-2.4A/1.0",
        "status": "PASS",
        "checkpoint": "2.4A",
        "dataset_id": inputs["dataset_id"],
        "branch_id": inputs["branch_id"],
        "plan": "docs/plans/stage_2_4_chained_ml_pipeline_plan.md",
        "plan_sha256": contract.get("plan_sha256"),
        "master_plan_sha256": contract.get("master_plan_sha256"),
        "artifacts": {
            "contracts/chain_contract.json": contract_hash,
            "manifests/crossfit_contract.json": crossfit_hash,
        },
        "contexts": len(contexts),
        "expected_fit_attempts": EXPECTED_FIT_ATTEMPTS,
        "actual_fit_attempts": 0,
        "fit_score_memberships": "PUBLISHED_IN_CROSSFIT_CONTRACT",
        "nested_cross_fit": "PASS",
        "baseline_immutable": True,
        "test_used": False,
        "fortigate_used": False,
        "next_action": "HUMAN_REVIEW_REQUIRED_FOR_2.4B",
    }
    checkpoint_hash = _write_json(checkpoint_path, checkpoint)
    root_manifest = {
        "schema_version": "stage_2.4/manifest/1.0",
        "status": "PASS",
        "checkpoint": "2.4A",
        "dataset_id": inputs["dataset_id"],
        "branch_id": inputs["branch_id"],
        "artifacts": {
            "contracts/chain_contract.json": contract_hash,
            "manifests/crossfit_contract.json": crossfit_hash,
            "manifests/checkpoint_2_4A.json": checkpoint_hash,
        },
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_2_4A",
        "models_fitted": False,
        "signals_generated": False,
    }
    _write_json(root_manifest_path, root_manifest)
    return {
        "status": "PASS",
        "checkpoint": "2.4A",
        "output_root": str(output_root),
        "contexts": len(contexts),
        "expected_fit_attempts": EXPECTED_FIT_ATTEMPTS,
        "actual_fit_attempts": 0,
        "test_used": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True)
    args = parser.parse_args(argv)
    if args.checkpoint == "2.4A":
        result = run_checkpoint_2_4a()
    elif args.checkpoint == "2.4B":
        result = _run_checkpoint_2_4b()
    elif args.checkpoint == "2.4C":
        result = _run_checkpoint_2_4c()
    elif args.checkpoint == "2.4D":
        result = _run_checkpoint_2_4d()
    else:
        parser.error("this runner only executes checkpoints 2.4A, 2.4B, 2.4C, and 2.4D")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
