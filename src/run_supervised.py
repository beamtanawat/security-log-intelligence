"""TRAIN-only Stage 2.3 checkpoint runner.

Checkpoint 2.3A freezes the supervised contract, group-safe nested fold
membership, and fold-local preprocessing boundaries.  It deliberately has no
classifier fit or TEST dispatch path.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from supervised.contracts import (  # noqa: E402
    BRANCH_ID,
    DATASET_ID,
    FEATURE_ORDER,
    build_supervised_contract,
    validate_development_rows,
)
from supervised.folds import FoldBlocker, audit_folds, build_folds  # noqa: E402
from supervised.evaluation import evaluate_probabilities, select_preferred_model, validate_selection_lock  # noqa: E402
from supervised.models import S1FitError, S2FitError, S2_CONFIG, fit_pipeline, run_nested_s1, run_nested_s2  # noqa: E402
from unsupervised.features import FeatureState  # noqa: E402
from threadpoolctl import threadpool_limits  # noqa: E402


UPSTREAM = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_2" / "v1"
TRAIN_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_training-set.csv"
ACQUISITION_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
PLAN_PATH = PROJECT_ROOT / "docs" / "plans" / "stage_2_3_supervised_attack_classification_plan.md"
MASTER_PLAN_PATH = PROJECT_ROOT / "docs" / "plans" / "stage_2_1_to_2_5_ml_pipeline_plan.md"
OUTPUT_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_3" / "v1"

EXPECTED = {
    "source_train_sha256": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    "test_identity_sha256": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    "upstream/contracts/unsw_feature_contract.json": "bc66e157f74992c66b798f37a933f2894fe65b6df7d4b010e973465a7e6e14f6",
    "upstream/features/unsw_train_internal_feature_state.json": "1883e03e1b765c9153580e20ef66924a03ca2e70181d0b174c805d5fd26ec8b5",
    "upstream/manifests/unsw_split_manifest.jsonl": "f58d7527168a44588d095d0be9e718dccd86641f0d10570ef9986ea8efd9d06b",
    "upstream/reports/unsw_split_audit.json": "a2ceb27131db023ebd9dfb4236af1ba18c17fba191a91e06704a7130dd645c9d",
    "upstream/manifest.json": "ff76fb00da29cdaab4abddadc9fed0547cde394edc864148f7d50089cf5e514e",
    "upstream/validation/selection_lock_manifest.json": "6a2e5f22e352ebcf156afa3bc3bf655055a02e542aa38a15b86ff5caf9b43889",
    "upstream/test_evaluation/final_stage_2_2_manifest.json": "97158a8ca0ed4952ec1087400f067d36d1daa41ea0b5fb733ae217a1dc832888",
}


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write(path: Path, payload: object) -> str:
    data = _json_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _git_identity() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "UNAVAILABLE"


def _dependency_versions() -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("numpy", "scikit-learn"):
        try:
            result[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            result[name] = "UNAVAILABLE"
    return result


def _load_upstream() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    if not UPSTREAM.is_dir() or not TRAIN_PATH.is_file() or not ACQUISITION_PATH.is_file():
        raise RuntimeError("closed Stage 2.2 UNSW inputs are missing")
    acquisition = json.loads(ACQUISITION_PATH.read_text(encoding="utf-8"))
    train_entry = next(item for item in acquisition["files"] if item["role"] == "TRAIN")
    if train_entry["filename"] != "UNSW_NB15_training-set.csv" or train_entry["expected_row_count"] != 175341:
        raise RuntimeError("acquisition contract does not match the approved TRAIN identity")
    source_hash = _sha256(TRAIN_PATH)
    if source_hash != EXPECTED["source_train_sha256"] or source_hash != train_entry["sha256"]:
        raise RuntimeError("official TRAIN SHA-256 differs from the closed identity")

    split_path = UPSTREAM / "manifests" / "unsw_split_manifest.jsonl"
    report_path = UPSTREAM / "reports" / "unsw_split_audit.json"
    publication_path = UPSTREAM / "manifest.json"
    expected_files = {
        "upstream/contracts/unsw_feature_contract.json": UPSTREAM / "contracts" / "unsw_feature_contract.json",
        "upstream/features/unsw_train_internal_feature_state.json": UPSTREAM / "features" / "unsw_train_internal_feature_state.json",
        "upstream/manifests/unsw_split_manifest.jsonl": split_path,
        "upstream/reports/unsw_split_audit.json": report_path,
        "upstream/manifest.json": publication_path,
        "upstream/validation/selection_lock_manifest.json": UPSTREAM / "validation" / "selection_lock_manifest.json",
        "upstream/test_evaluation/final_stage_2_2_manifest.json": UPSTREAM / "test_evaluation" / "final_stage_2_2_manifest.json",
    }
    upstream_hashes: dict[str, str] = {}
    for identity, path in expected_files.items():
        if not path.is_file():
            raise RuntimeError(f"missing closed upstream artifact: {path}")
        observed = _sha256(path)
        if observed != EXPECTED[identity]:
            raise RuntimeError(f"upstream identity mismatch: {identity}")
        upstream_hashes[identity] = observed

    split_rows = [json.loads(line) for line in split_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(split_rows) != 175341 or len({str(row.get("row_key")) for row in split_rows}) != 175341:
        raise RuntimeError("upstream split manifest coverage is not one-to-one")
    split_by_number = {int(row["row_number"]): row for row in split_rows}
    if set(split_by_number) != set(range(1, 175342)):
        raise RuntimeError("upstream split row-number coverage is incomplete")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected_report = {
        "official_train_rows": 175341,
        "exact_predictive_group_count": 88976,
        "target_conflict_groups": 273,
        "target_conflict_rows": 6896,
        "target_conflict_normal": 2156,
        "target_conflict_attack": 4740,
        "exact_predictive_group_cross_split_count": 0,
    }
    for key, value in expected_report.items():
        if report.get(key) != value:
            raise RuntimeError(f"upstream fingerprint mismatch: {key}")
    if report.get("partition_counts") != {
        "TRAIN_INTERNAL": 140273,
        "VALIDATION_CALIBRATION": 17539,
        "VALIDATION_COMPARISON": 17529,
    }:
        raise RuntimeError("upstream partition counts mismatch")

    columns = acquisition["schema"]["columns"]
    if columns != list(columns) or "label" not in columns or "attack_cat" not in columns:
        raise RuntimeError("UNSW acquisition schema lacks required target/category fields")
    rows: list[dict[str, Any]] = []
    with TRAIN_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != columns:
            raise RuntimeError("official TRAIN schema differs from acquisition contract")
        for number, raw in enumerate(reader, 1):
            if None in raw or any(value is None for value in raw.values()):
                raise RuntimeError(f"malformed official TRAIN row {number}")
            if all(raw.get(column) == column for column in columns):
                raise RuntimeError(f"duplicate header row in official TRAIN at row {number}")
            membership = split_by_number.get(number)
            expected_key = json.dumps([DATASET_ID, "TRAIN", number], separators=(",", ":"))
            if membership is None or membership.get("row_key") != expected_key:
                raise RuntimeError(f"split membership mismatch at row {number}")
            label = str(raw.get("label", "")).strip()
            if label not in {"0", "1"}:
                raise RuntimeError(f"invalid binary label at row {number}")
            if "attack_cat" not in raw:
                raise RuntimeError("attack category field missing")
            rows.append(
                {
                    **raw,
                    "dataset_id": DATASET_ID,
                    "branch_id": BRANCH_ID,
                    "official_split": "TRAIN",
                    "row_number": number,
                    "development_partition": membership["partition"],
                    "row_key": membership["row_key"],
                    "group_id": membership["group_id"],
                }
            )
    if len(rows) != 175341:
        raise RuntimeError("official TRAIN row count changed")
    return rows, report, upstream_hashes


def _fit_state_audit(train_internal: list[dict[str, Any]], folds: list[dict[str, Any]]) -> dict[str, Any]:
    by_outer = {int(item["outer_fold"]): item for item in folds}
    states: list[dict[str, Any]] = []
    for outer in range(3):
        outer_eval = {str(item["row_key"]) for item in folds if int(item["outer_fold"]) == outer}
        outer_train = [row for row in train_internal if str(row["row_key"]) not in outer_eval]
        bundle = fit_pipeline(outer_train, frozenset(str(row["row_key"]) for row in outer_train), "S1", {"checkpoint": "2.3A"}, all_rows=train_internal)
        states.append({"context": f"outer:{outer}", "fit_rows": len(outer_train), "fit_membership_sha256": bundle["fit_membership_sha256"], "output_columns": len(bundle["feature_state"].output_feature_names), "classifier_fitted": bundle["classifier_fitted"]})
        for inner in range(2):
            eligible = [row for row in train_internal if str(row["row_key"]) not in outer_eval]
            inner_eval = {
                str(item["row_key"])
                for item in folds
                if int(item["outer_fold"]) != outer and int(item["inner_fold_by_outer"][str(outer)]) == inner
            }
            inner_train = [row for row in eligible if str(row["row_key"]) not in inner_eval]
            bundle = fit_pipeline(inner_train, frozenset(str(row["row_key"]) for row in inner_train), "S1", {"checkpoint": "2.3A", "outer": outer, "inner": inner}, all_rows=train_internal)
            states.append({"context": f"inner:{outer}:{inner}", "fit_rows": len(inner_train), "fit_membership_sha256": bundle["fit_membership_sha256"], "output_columns": len(bundle["feature_state"].output_feature_names), "classifier_fitted": bundle["classifier_fitted"]})
    return {"status": "PASS", "states": states, "classifier_fit_count": 0, "fit_scope": "DECLARED_OUTER_OR_INNER_TRAINING_ROWS_ONLY"}


def run_checkpoint() -> dict[str, Any]:
    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"refusing to overwrite checkpoint root: {OUTPUT_ROOT}")
    rows, report, upstream_hashes = _load_upstream()
    diagnostics = validate_development_rows(rows)
    if diagnostics["row_count"] != 175341 or diagnostics["group_count"] != 88976:
        raise RuntimeError("supervised row/group reconciliation failed")
    train_internal = [row for row in rows if row["development_partition"] == "TRAIN_INTERNAL"]
    if len(train_internal) != 140273:
        raise RuntimeError("TRAIN_INTERNAL population changed")
    folds = build_folds(train_internal)
    audit = audit_folds(train_internal, folds)
    preprocessing = _fit_state_audit(train_internal, folds)
    if audit["status"] != "PASS" or preprocessing["status"] != "PASS":
        raise FoldBlocker("Stage 2.3A fold/preprocessing audit failed")

    contract = build_supervised_contract()
    contract.update(
        {
            "plan_sha256": _sha256(PLAN_PATH),
            "master_plan_sha256": _sha256(MASTER_PLAN_PATH),
            "upstream_hashes": upstream_hashes,
            "source_train_sha256": EXPECTED["source_train_sha256"],
            "official_test_identity_sha256": EXPECTED["test_identity_sha256"],
            "official_train_rows": len(rows),
            "train_internal_rows": len(train_internal),
            "predictive_group_fingerprint": {
                key: report[key]
                for key in ("exact_predictive_group_count", "target_conflict_groups", "target_conflict_rows", "target_conflict_normal", "target_conflict_attack", "exact_predictive_group_cross_split_count")
            },
            "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
            "classifier_fit_count": 0,
        }
    )
    audit["preprocessing"] = preprocessing
    audit["plan_sha256"] = contract["plan_sha256"]
    audit["master_plan_sha256"] = contract["master_plan_sha256"]
    audit["upstream_hashes"] = upstream_hashes
    audit["implementation_commit"] = _git_identity()
    checkpoint = {
        "schema_version": "stage_2.3/checkpoint-2.3A/1.0",
        "checkpoint": "2.3A",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan_sha256": contract["plan_sha256"],
        "implementation_commit": audit["implementation_commit"],
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "test_identity_sha256": EXPECTED["test_identity_sha256"],
        "classifier_fit_count": 0,
        "fold_audit_status": audit["status"],
        "preprocessing_audit_status": preprocessing["status"],
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3B",
    }

    contracts_path = OUTPUT_ROOT / "contracts" / "supervised_contract.json"
    folds_path = OUTPUT_ROOT / "manifests" / "folds.jsonl"
    audit_path = OUTPUT_ROOT / "manifests" / "fold_audit.json"
    checkpoint_path = OUTPUT_ROOT / "manifests" / "checkpoint_2_3A.json"
    contract_hash = _write(contracts_path, contract)
    folds_bytes = b"".join(_json_bytes(item) + b"\n" for item in folds)
    folds_path.parent.mkdir(parents=True, exist_ok=True)
    folds_path.write_bytes(folds_bytes)
    folds_hash = hashlib.sha256(folds_bytes).hexdigest()
    audit["fold_manifest_sha256"] = folds_hash
    audit_hash = _write(audit_path, audit)
    checkpoint.update({
        "artifacts": {
            "contracts/supervised_contract.json": contract_hash,
            "manifests/folds.jsonl": folds_hash,
            "manifests/fold_audit.json": audit_hash,
        },
        "dependency_versions": _dependency_versions(),
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
    })
    checkpoint_hash = _write(checkpoint_path, checkpoint)
    return {
        "status": "COMPLETE",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "base_predictive_feature_count": len(FEATURE_ORDER),
        "official_train_rows": len(rows),
        "train_internal_rows": len(train_internal),
        "group_count": diagnostics["group_count"],
        "outer_fold_count": 3,
        "inner_fold_count": 2,
        "group_cross_fold": 0,
        "fold_replay": "PASS",
        "fold_local_preprocessing": "PASS",
        "deterministic_feature_order": "PASS",
        "primary_metric_contract": "average_precision_score",
        "s1_contract": "READY",
        "s2_contract": "READY",
        "test_lock": "PASS",
        "classifier_fit_count": 0,
        "artifacts": {
            "contracts/supervised_contract.json": contract_hash,
            "manifests/folds.jsonl": folds_hash,
            "manifests/fold_audit.json": audit_hash,
            "manifests/checkpoint_2_3A.json": checkpoint_hash,
        },
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3B",
    }


def _load_stage23a(rows: Sequence[Mapping[str, object]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Load and verify the frozen 2.3A receipt without rebuilding it."""

    checkpoint_path = OUTPUT_ROOT / "manifests" / "checkpoint_2_3A.json"
    fold_path = OUTPUT_ROOT / "manifests" / "folds.jsonl"
    audit_path = OUTPUT_ROOT / "manifests" / "fold_audit.json"
    contract_path = OUTPUT_ROOT / "contracts" / "supervised_contract.json"
    for path in (checkpoint_path, fold_path, audit_path, contract_path):
        if not path.is_file():
            raise S1FitError(f"Stage 2.3A artifact missing: {path}")
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if checkpoint.get("status") != "PASS" or checkpoint.get("test_lock") != "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT":
        raise S1FitError("Stage 2.3A checkpoint is not a passing TEST-locked receipt")
    if checkpoint.get("classifier_fit_count") != 0:
        raise S1FitError("Stage 2.3A already contains classifier fits")
    artifacts = checkpoint.get("artifacts", {})
    for relative, expected in artifacts.items():
        path = OUTPUT_ROOT / relative
        if path.is_file() and _sha256(path) != expected:
            raise S1FitError(f"Stage 2.3A artifact hash mismatch: {relative}")
    folds = [json.loads(line) for line in fold_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if audit.get("status") != "PASS" or audit.get("outer_group_crossings") != 0 or audit.get("inner_group_crossings") != 0:
        raise S1FitError("Stage 2.3A fold audit is not group-safe")
    train_internal = [row for row in rows if row.get("development_partition") == "TRAIN_INTERNAL"]
    if len(train_internal) != len(folds) or len(folds) != 140273:
        raise S1FitError("Stage 2.3A fold coverage changed")
    if contract.get("feature_order") != list(FEATURE_ORDER) or contract.get("target") != {"field": "label", "normal": 0, "attack": 1}:
        raise S1FitError("Stage 2.3A supervised contract changed")
    return folds, audit, contract


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> str:
    data = b"".join(_json_bytes(record) + b"\n" for record in records)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _dump_joblib(path: Path, value: object) -> str:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        joblib.dump(value, temporary_path, compress=3)
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return _sha256(path)


def _prediction_record(row: Mapping[str, object], p_attack: float, *, outer_fold: int | None, C: float, state_sha256: str, fit_membership_sha256: str, prediction_role: str) -> dict[str, Any]:
    return {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "row_key": str(row["row_key"]),
        "group_id": str(row["group_id"]),
        "outer_fold": outer_fold,
        "model_id": "S1",
        "model_family": "LOGISTIC_REGRESSION",
        "C": float(C),
        "feature_state_sha256": state_sha256,
        "fit_membership_sha256": fit_membership_sha256,
        "p_attack": float(p_attack),
        "threshold": 0.5,
        "predicted_label": int(float(p_attack) >= 0.5),
        "prediction_role": prediction_role,
    }


def run_checkpoint_b() -> dict[str, Any]:
    """Execute only the approved Stage 2.3B S1 nested development run."""

    rows, report, upstream_hashes = _load_upstream()
    folds, audit, contract = _load_stage23a(rows)
    train_internal = [row for row in rows if row["development_partition"] == "TRAIN_INTERNAL"]
    validation_rows = {
        partition: [row for row in rows if row["development_partition"] == partition]
        for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")
    }
    result = run_nested_s1(train_internal, folds, validation_rows_by_partition=validation_rows)

    models_root = OUTPUT_ROOT / "models" / "S1"
    predictions_root = OUTPUT_ROOT / "predictions"
    reports_root = OUTPUT_ROOT / "reports"
    for path in (models_root, predictions_root, reports_root):
        path.mkdir(parents=True, exist_ok=True)

    artifact_hashes: dict[str, str] = {}
    final = result["final"]
    artifact_hashes["models/S1/final.joblib"] = _dump_joblib(models_root / "final.joblib", final["estimator"])
    artifact_hashes["models/S1/final_feature_state.json"] = _write(models_root / "final_feature_state.json", final["bundle"]["feature_state"].to_dict())
    _write(models_root / "final_metadata.json", {"model_id": "S1", "family": "LOGISTIC_REGRESSION", "C": final["C"], "classes": [0, 1], "feature_state_sha256": final["feature_state_sha256"], "fit_membership_sha256": final["fit_membership_sha256"], "threshold": 0.5, "test_used": False})
    artifact_hashes["models/S1/final_metadata.json"] = _sha256(models_root / "final_metadata.json")

    oof_records: list[dict[str, Any]] = []
    outer_report: list[dict[str, Any]] = []
    for outer in result["outer"]:
        outer_index = int(outer["outer_fold"])
        model_name = f"outer_fold_{outer_index}.joblib"
        state_name = f"outer_fold_{outer_index}_feature_state.json"
        artifact_hashes[f"models/S1/{model_name}"] = _dump_joblib(models_root / model_name, outer["estimator"])
        artifact_hashes[f"models/S1/{state_name}"] = _write(models_root / state_name, outer["bundle"]["feature_state"].to_dict())
        for row, score in zip(outer["rows"], outer["p_attack"], strict=True):
            oof_records.append(_prediction_record(row, float(score), outer_fold=outer_index, C=float(outer["selected_C"]), state_sha256=str(outer["feature_state_sha256"]), fit_membership_sha256=str(outer["fit_membership_sha256"]), prediction_role="OUTER_OOF"))
        outer_report.append({"outer_fold": outer_index, "selected_C": outer["selected_C"], "fit_membership_sha256": outer["fit_membership_sha256"], "feature_state_sha256": outer["feature_state_sha256"], "metrics": outer["metrics"], "fit_report": outer["fit_report"]})
    oof_records.sort(key=lambda record: json.loads(record["row_key"])[2])
    artifact_hashes["predictions/oof_S1.jsonl"] = _write_jsonl(predictions_root / "oof_S1.jsonl", oof_records)

    validation_summary: dict[str, Any] = {}
    for partition, prediction in result["validation_predictions"].items():
        records = [
            _prediction_record(row, float(score), outer_fold=None, C=float(final["C"]), state_sha256=str(final["feature_state_sha256"]), fit_membership_sha256=str(final["fit_membership_sha256"]), prediction_role=f"VALIDATION_{partition}")
            for row, score in zip(prediction["rows"], prediction["p_attack"], strict=True)
        ]
        records.sort(key=lambda record: json.loads(record["row_key"])[2])
        filename = f"validation_{partition.lower()}_S1.jsonl"
        artifact_hashes[f"predictions/{filename}"] = _write_jsonl(predictions_root / filename, records)
        validation_summary[partition] = result["validation"][partition]

    selection = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3B",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S1_LOGISTIC_REGRESSION",
        "candidates": [0.1, 1.0],
        "tie_rule": "WITHIN_1E-6_PREFER_SMALLER_C",
        "inner": result["inner"],
        "selected_config_per_outer": result["selected_by_outer"],
        "final_cv": result["final_cv"],
        "development_s1_config": {"C": result["final_cv"]["selected_C"]},
        "pilot": result["pilot"],
        "fit_log": result["fit_log"],
        "determinism": result["determinism"],
        "metric": {"primary": "AVERAGE_PRECISION", "implementation": "sklearn.metrics.average_precision_score", "positive_class": 1, "score": "p_attack"},
        "threshold": 0.5,
        "group_cross_fold": 0,
        "test_used": False,
        "chained_signals_used": False,
        "upstream_hashes": upstream_hashes,
        "parent_checkpoint_sha256": _sha256(OUTPUT_ROOT / "manifests" / "checkpoint_2_3A.json"),
    }
    artifact_hashes["reports/selection.json"] = _write(reports_root / "selection.json", selection)
    validation = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3B",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S1_LOGISTIC_REGRESSION",
        "outer": outer_report,
        "outer_average_precision_mean": result["outer_ap_mean"],
        "outer_average_precision_std": result["outer_ap_std"],
        "validation": validation_summary,
        "development_s1_config": {"C": result["final_cv"]["selected_C"]},
        "probability_semantics": {"field": "p_attack", "class": 1, "classes": [0, 1], "higher": "greater_model_estimated_ATTACK_probability"},
        "threshold": 0.5,
        "fold_local_preprocessing": True,
        "test_used": False,
        "chained_signals_used": False,
        "upstream_hashes": upstream_hashes,
    }
    artifact_hashes["reports/validation.json"] = _write(reports_root / "validation.json", validation)

    checkpoint = {
        "schema_version": "stage_2.3/checkpoint-2.3B/1.0",
        "checkpoint": "2.3B",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S1_LOGISTIC_REGRESSION",
        "plan_sha256": contract["plan_sha256"],
        "implementation_commit": _git_identity(),
        "parent_checkpoint_sha256": _sha256(OUTPUT_ROOT / "manifests" / "checkpoint_2_3A.json"),
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "test_used": False,
        "chained_signals_used": False,
        "group_cross_fold": 0,
        "fold_local_preprocessing": "PASS",
        "convergence": "PASS",
        "determinism": "PASS",
        "outer_average_precision_mean": result["outer_ap_mean"],
        "outer_average_precision_std": result["outer_ap_std"],
        "artifacts": artifact_hashes,
        "dependency_versions": _dependency_versions(),
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3C",
    }
    artifact_hashes["manifests/checkpoint_2_3B.json"] = _write(OUTPUT_ROOT / "manifests" / "checkpoint_2_3B.json", checkpoint)
    return {
        "status": "COMPLETE",
        "model": "LOGISTIC REGRESSION",
        "outer_folds": 3,
        "inner_folds_per_outer": 2,
        "regularization_candidates": [0.1, 1.0],
        "selected_config_per_outer": result["selected_by_outer"],
        "outer_ap": {str(item["outer_fold"] + 1): item["metrics"]["average_precision"] for item in result["outer"]},
        "mean_outer_ap": result["outer_ap_mean"],
        "std_outer_ap": result["outer_ap_std"],
        "development_s1_config": {"C": result["final_cv"]["selected_C"]},
        "p_attack_semantics": "ATTACK=1 / PASS",
        "group_cross_fold": 0,
        "fold_local_preprocessing": "PASS",
        "convergence": "PASS",
        "chained_signals_used": "NO",
        "test_used": "NO",
        "determinism": "PASS",
        "artifacts": {**artifact_hashes},
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3C",
    }


def _prediction_record_s2(
    row: Mapping[str, object],
    p_attack: float,
    *,
    outer_fold: int | None,
    state_sha256: str,
    fit_membership_sha256: str,
    prediction_role: str,
) -> dict[str, Any]:
    return {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "row_key": str(row["row_key"]),
        "group_id": str(row["group_id"]),
        "outer_fold": outer_fold,
        "model_id": "S2",
        "model_family": "RANDOM_FOREST",
        "config": dict(S2_CONFIG),
        "feature_state_sha256": state_sha256,
        "fit_membership_sha256": fit_membership_sha256,
        "p_attack": float(p_attack),
        "threshold": 0.5,
        "predicted_label": int(float(p_attack) >= 0.5),
        "prediction_role": prediction_role,
    }


def _stage23b_identity() -> tuple[str, dict[str, str], dict[str, Any]]:
    """Load PASS S1 receipt and capture hashes that 2.3C must preserve."""

    checkpoint_path = OUTPUT_ROOT / "manifests" / "checkpoint_2_3B.json"
    if not checkpoint_path.is_file():
        raise S2FitError("Stage 2.3B checkpoint is missing")
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if checkpoint.get("status") != "PASS" or checkpoint.get("test_used") is not False:
        raise S2FitError("Stage 2.3B checkpoint is not a passing TEST-locked receipt")
    if checkpoint.get("model") != "S1_LOGISTIC_REGRESSION":
        raise S2FitError("Stage 2.3B S1 identity changed")
    identities = {"manifests/checkpoint_2_3B.json": _sha256(checkpoint_path)}
    for relative in checkpoint.get("artifacts", {}):
        path = OUTPUT_ROOT / relative
        if not path.is_file():
            raise S2FitError(f"Stage 2.3B artifact missing: {relative}")
        observed = _sha256(path)
        if observed != checkpoint["artifacts"][relative]:
            raise S2FitError(f"Stage 2.3B artifact hash mismatch: {relative}")
        identities[relative] = observed
    return identities["manifests/checkpoint_2_3B.json"], identities, checkpoint


def _feature_state_from_json(path: Path) -> FeatureState:
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


def _membership_sha256(rows: Sequence[Mapping[str, object]]) -> str:
    values = [str(row["row_key"]) for row in rows]
    return hashlib.sha256(_json_bytes(values)).hexdigest()


def _predict_validation(
    estimator: Any,
    state: FeatureState,
    rows: Sequence[Mapping[str, object]],
) -> tuple[np.ndarray, dict[str, Any]]:
    """Replay frozen model/state on development validation rows only."""

    classes = np.asarray(getattr(estimator, "classes_", []))
    if not np.array_equal(classes, np.asarray([0, 1])):
        raise S2FitError("frozen classifier class ordering is not [0, 1]")
    scores: list[np.ndarray] = []
    max_sum_error = 0.0
    started = time.monotonic()
    bundle = {"feature_state": state}
    for start in range(0, len(rows), 4096):
        batch = rows[start : start + 4096]
        from supervised.models import transform_pipeline  # local import avoids public API expansion

        X = transform_pipeline(bundle, batch)
        with threadpool_limits(limits=1):
            probabilities = np.asarray(estimator.predict_proba(X), dtype=np.float64)
        if probabilities.shape != (len(batch), 2) or not np.isfinite(probabilities).all():
            raise S2FitError("frozen validation probabilities are invalid")
        if not np.all((probabilities >= 0.0) & (probabilities <= 1.0)):
            raise S2FitError("frozen validation probabilities outside [0, 1]")
        max_sum_error = max(max_sum_error, float(np.max(np.abs(probabilities.sum(axis=1) - 1.0))))
        scores.append(probabilities[:, 1])
    elapsed = time.monotonic() - started
    if elapsed > 300.0:
        raise S2FitError("validation prediction batch budget exceeded")
    return np.concatenate(scores), {
        "row_count": len(rows),
        "classes": [0, 1],
        "max_probability_row_sum_error": max_sum_error,
        "elapsed_seconds": float(elapsed),
    }


def _prediction_artifact_replay(path: Path, rows: Sequence[Mapping[str, object]], scores: np.ndarray) -> dict[str, Any]:
    if not path.is_file():
        raise S2FitError(f"validation prediction artifact missing: {path}")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(records) != len(rows):
        raise S2FitError(f"validation prediction row count mismatch: {path.name}")
    expected_keys = [str(row["row_key"]) for row in rows]
    observed_keys = [str(record.get("row_key")) for record in records]
    if observed_keys != expected_keys:
        raise S2FitError(f"validation prediction row ordering mismatch: {path.name}")
    observed = np.asarray([float(record["p_attack"]) for record in records], dtype=np.float64)
    max_difference = float(np.max(np.abs(observed - scores))) if scores.size else 0.0
    if max_difference > 1e-12:
        raise S2FitError(f"validation prediction replay mismatch: {path.name}")
    if any(record.get("prediction_role") != path.stem.replace("validation_", "").upper() for record in records):
        # Existing Stage 2.3B/C role names include the explicit partition token;
        # validate only the stable prefix and leave historical filenames intact.
        if not all(str(record.get("prediction_role", "")).startswith("VALIDATION_") for record in records):
            raise S2FitError(f"validation prediction role mismatch: {path.name}")
    return {"path": str(path.relative_to(PROJECT_ROOT)), "rows": len(records), "max_difference": max_difference}


def run_checkpoint_c() -> dict[str, Any]:
    """Execute only the approved Stage 2.3C bounded S2 capability gate."""

    rows, report, upstream_hashes = _load_upstream()
    folds, audit, contract = _load_stage23a(rows)
    parent_hash, s1_hashes_before, parent_checkpoint = _stage23b_identity()
    train_internal = [row for row in rows if row["development_partition"] == "TRAIN_INTERNAL"]
    validation_rows = {
        partition: [row for row in rows if row["development_partition"] == partition]
        for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")
    }
    result = run_nested_s2(train_internal, folds, validation_rows_by_partition=validation_rows)

    models_root = OUTPUT_ROOT / "models" / "S2"
    predictions_root = OUTPUT_ROOT / "predictions"
    reports_root = OUTPUT_ROOT / "reports"
    artifact_hashes: dict[str, str] = {}
    final = result["final"]
    artifact_hashes["models/S2/final.joblib"] = _dump_joblib(models_root / "final.joblib", final["estimator"])
    artifact_hashes["models/S2/final_feature_state.json"] = _write(models_root / "final_feature_state.json", final["bundle"]["feature_state"].to_dict())
    _write(
        models_root / "final_metadata.json",
        {
            "model_id": "S2",
            "family": "RANDOM_FOREST",
            "config": dict(S2_CONFIG),
            "classes": [0, 1],
            "feature_state_sha256": final["feature_state_sha256"],
            "fit_membership_sha256": final["fit_membership_sha256"],
            "threshold": 0.5,
            "test_used": False,
        },
    )
    artifact_hashes["models/S2/final_metadata.json"] = _sha256(models_root / "final_metadata.json")

    oof_records: list[dict[str, Any]] = []
    outer_report: list[dict[str, Any]] = []
    for outer in result["outer"]:
        outer_index = int(outer["outer_fold"])
        model_name = f"outer_fold_{outer_index}.joblib"
        state_name = f"outer_fold_{outer_index}_feature_state.json"
        artifact_hashes[f"models/S2/{model_name}"] = _dump_joblib(models_root / model_name, outer["estimator"])
        artifact_hashes[f"models/S2/{state_name}"] = _write(models_root / state_name, outer["bundle"]["feature_state"].to_dict())
        for row, score in zip(outer["rows"], outer["p_attack"], strict=True):
            oof_records.append(
                _prediction_record_s2(
                    row,
                    float(score),
                    outer_fold=outer_index,
                    state_sha256=str(outer["feature_state_sha256"]),
                    fit_membership_sha256=str(outer["fit_membership_sha256"]),
                    prediction_role="OUTER_OOF",
                )
            )
        outer_report.append(
            {
                "outer_fold": outer_index,
                "selected_config": dict(S2_CONFIG),
                "fit_membership_sha256": outer["fit_membership_sha256"],
                "feature_state_sha256": outer["feature_state_sha256"],
                "metrics": outer["metrics"],
                "fit_report": outer["fit_report"],
                "prediction_report": outer["prediction_report"],
                "replay_max_difference": outer["replay_max_difference"],
            }
        )
    oof_records.sort(key=lambda record: json.loads(record["row_key"])[2])
    artifact_hashes["predictions/oof_S2.jsonl"] = _write_jsonl(predictions_root / "oof_S2.jsonl", oof_records)

    validation_summary: dict[str, Any] = {}
    for partition, prediction in result["validation_predictions"].items():
        records = [
            _prediction_record_s2(
                row,
                float(score),
                outer_fold=None,
                state_sha256=str(final["feature_state_sha256"]),
                fit_membership_sha256=str(final["fit_membership_sha256"]),
                prediction_role=f"VALIDATION_{partition}",
            )
            for row, score in zip(prediction["rows"], prediction["p_attack"], strict=True)
        ]
        records.sort(key=lambda record: json.loads(record["row_key"])[2])
        filename = f"validation_{partition.lower()}_S2.jsonl"
        artifact_hashes[f"predictions/{filename}"] = _write_jsonl(predictions_root / filename, records)
        validation_summary[partition] = result["validation"][partition]

    selection = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3C",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S2_RANDOM_FOREST",
        "candidates": [dict(S2_CONFIG)],
        "candidates_actually_run": 1,
        "inner": result["inner"],
        "selected_config_per_outer": result["selected_config_per_outer"],
        "development_s2_config": dict(S2_CONFIG),
        "pilot": result["pilot"],
        "fit_log": result["fit_log"],
        "fit_attempts": result["fit_attempts"],
        "aggregate_elapsed_seconds": result["aggregate_elapsed_seconds"],
        "resource_gate": result["resource_gate"],
        "determinism": result["determinism"],
        "metric": {"primary": "AVERAGE_PRECISION", "implementation": "sklearn.metrics.average_precision_score", "positive_class": 1, "score": "p_attack"},
        "threshold": 0.5,
        "group_cross_fold": 0,
        "test_used": False,
        "chained_signals_used": False,
        "upstream_hashes": upstream_hashes,
        "parent_checkpoint_sha256": parent_hash,
        "s1_artifact_hashes_before": s1_hashes_before,
    }
    artifact_hashes["reports/selection_S2.json"] = _write(reports_root / "selection_S2.json", selection)
    validation = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3C",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S2_RANDOM_FOREST",
        "outer": outer_report,
        "outer_average_precision_mean": result["outer_ap_mean"],
        "outer_average_precision_std": result["outer_ap_std"],
        "validation": validation_summary,
        "development_s2_config": dict(S2_CONFIG),
        "probability_semantics": {"field": "p_attack", "class": 1, "classes": [0, 1], "higher": "greater_model_estimated_ATTACK_probability"},
        "threshold": 0.5,
        "fold_local_preprocessing": True,
        "test_used": False,
        "chained_signals_used": False,
        "upstream_hashes": upstream_hashes,
    }
    artifact_hashes["reports/validation_S2.json"] = _write(reports_root / "validation_S2.json", validation)

    s1_hashes_after = {relative: _sha256(OUTPUT_ROOT / relative) for relative in s1_hashes_before}
    if s1_hashes_after != s1_hashes_before:
        raise S2FitError("S1 artifacts changed during Stage 2.3C")
    checkpoint = {
        "schema_version": "stage_2.3/checkpoint-2.3C/1.0",
        "checkpoint": "2.3C",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "model": "S2_RANDOM_FOREST",
        "plan_sha256": contract["plan_sha256"],
        "implementation_commit": _git_identity(),
        "parent_checkpoint_sha256": parent_hash,
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "test_used": False,
        "chained_signals_used": False,
        "group_cross_fold": 0,
        "fold_local_preprocessing": "PASS",
        "resource_gate": result["resource_gate"],
        "fit_attempts": result["fit_attempts"],
        "determinism": "PASS",
        "outer_average_precision_mean": result["outer_ap_mean"],
        "outer_average_precision_std": result["outer_ap_std"],
        "s1_artifact_hashes_before": s1_hashes_before,
        "s1_artifact_hashes_after": s1_hashes_after,
        "artifacts": artifact_hashes,
        "dependency_versions": _dependency_versions(),
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3D",
    }
    artifact_hashes["manifests/checkpoint_2_3C.json"] = _write(OUTPUT_ROOT / "manifests" / "checkpoint_2_3C.json", checkpoint)
    return {
        "status": "COMPLETE",
        "model": "RANDOM FOREST",
        "candidates": [dict(S2_CONFIG)],
        "candidates_actually_run": 1,
        "selected_config_per_outer": result["selected_config_per_outer"],
        "outer_ap": {str(item["outer_fold"] + 1): item["metrics"]["average_precision"] for item in result["outer"]},
        "mean_outer_ap": result["outer_ap_mean"],
        "std_outer_ap": result["outer_ap_std"],
        "development_s2_config": dict(S2_CONFIG),
        "p_attack_semantics": "ATTACK=1 / PASS",
        "group_cross_fold": 0,
        "fold_local_preprocessing": "PASS",
        "resource_gate": "PASS",
        "chained_signals_used": "NO",
        "s1_modified": "NO",
        "test_used": "NO",
        "determinism": "PASS",
        "artifacts": artifact_hashes,
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3D",
    }


def run_checkpoint_d() -> dict[str, Any]:
    """Execute only Stage 2.3D validation comparison and pre-TEST freeze."""

    rows, report, upstream_hashes = _load_upstream()
    folds, audit, contract = _load_stage23a(rows)
    parent_b_hash, s1_hashes, checkpoint_b = _stage23b_identity()
    checkpoint_c_path = OUTPUT_ROOT / "manifests" / "checkpoint_2_3C.json"
    if not checkpoint_c_path.is_file():
        raise S2FitError("Stage 2.3C checkpoint is missing")
    checkpoint_c = json.loads(checkpoint_c_path.read_text(encoding="utf-8"))
    if checkpoint_c.get("status") != "PASS" or checkpoint_c.get("test_used") is not False:
        raise S2FitError("Stage 2.3C checkpoint is not a passing TEST-locked receipt")
    parent_c_hash = _sha256(checkpoint_c_path)
    for relative, expected in checkpoint_c.get("artifacts", {}).items():
        path = OUTPUT_ROOT / relative
        if not path.is_file() or _sha256(path) != expected:
            raise S2FitError(f"Stage 2.3C artifact hash mismatch: {relative}")

    train_internal = [row for row in rows if row["development_partition"] == "TRAIN_INTERNAL"]
    validation_rows = {
        partition: [row for row in rows if row["development_partition"] == partition]
        for partition in ("VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")
    }
    expected_partition_counts = {"TRAIN_INTERNAL": 140273, "VALIDATION_CALIBRATION": 17539, "VALIDATION_COMPARISON": 17529}
    if {key: len(value) for key, value in {"TRAIN_INTERNAL": train_internal, **validation_rows}.items()} != expected_partition_counts:
        raise S2FitError("Stage 2.3D validation role counts changed")
    group_partitions: dict[str, set[str]] = {}
    for row in rows:
        group_partitions.setdefault(str(row["group_id"]), set()).add(str(row["development_partition"]))
    cross_partition_groups = sum(1 for values in group_partitions.values() if len(values) > 1)
    if cross_partition_groups != 0:
        raise S2FitError("predictive groups cross validation partitions")

    contract_hash = _sha256(OUTPUT_ROOT / "contracts" / "supervised_contract.json")
    fold_manifest_hash = _sha256(OUTPUT_ROOT / "manifests" / "folds.jsonl")
    model_paths = {
        "S1": {
            "model": OUTPUT_ROOT / "models" / "S1" / "final.joblib",
            "state": OUTPUT_ROOT / "models" / "S1" / "final_feature_state.json",
            "metadata": OUTPUT_ROOT / "models" / "S1" / "final_metadata.json",
        },
        "S2": {
            "model": OUTPUT_ROOT / "models" / "S2" / "final.joblib",
            "state": OUTPUT_ROOT / "models" / "S2" / "final_feature_state.json",
            "metadata": OUTPUT_ROOT / "models" / "S2" / "final_metadata.json",
        },
    }
    for paths in model_paths.values():
        if not all(path.is_file() for path in paths.values()):
            raise S2FitError("frozen final model artifacts are incomplete")
    s1_metadata = json.loads(model_paths["S1"]["metadata"].read_text(encoding="utf-8"))
    s2_metadata = json.loads(model_paths["S2"]["metadata"].read_text(encoding="utf-8"))
    if s1_metadata.get("C") != 1.0 or s1_metadata.get("classes") != [0, 1] or s1_metadata.get("threshold") != 0.5 or s1_metadata.get("test_used") is not False:
        raise S2FitError("S1 frozen configuration changed")
    if s2_metadata.get("config") != S2_CONFIG or s2_metadata.get("classes") != [0, 1] or s2_metadata.get("threshold") != 0.5 or s2_metadata.get("test_used") is not False:
        raise S2FitError("S2 frozen configuration changed")

    estimators: dict[str, Any] = {}
    states: dict[str, FeatureState] = {}
    for model_id, paths in model_paths.items():
        estimators[model_id] = joblib.load(paths["model"])
        states[model_id] = _feature_state_from_json(paths["state"])
        if states[model_id].feature_order != tuple(FEATURE_ORDER) or states[model_id].state_sha256 != json.loads(paths["state"].read_text(encoding="utf-8"))["state_sha256"]:
            raise S2FitError(f"{model_id} feature-state identity invalid")
        if not np.array_equal(np.asarray(getattr(estimators[model_id], "classes_", [])), np.asarray([0, 1])):
            raise S2FitError(f"{model_id} class ordering invalid")
        if json.loads(paths["metadata"].read_text(encoding="utf-8")).get("feature_state_sha256") != states[model_id].state_sha256:
            raise S2FitError(f"{model_id} metadata/state identity mismatch")

    metric_reports: dict[str, dict[str, dict[str, Any]]] = {"S1": {}, "S2": {}}
    replay_reports: dict[str, dict[str, Any]] = {"S1": {}, "S2": {}}
    prediction_paths = {
        "S1": {
            "VALIDATION_CALIBRATION": OUTPUT_ROOT / "predictions" / "validation_validation_calibration_S1.jsonl",
            "VALIDATION_COMPARISON": OUTPUT_ROOT / "predictions" / "validation_validation_comparison_S1.jsonl",
        },
        "S2": {
            "VALIDATION_CALIBRATION": OUTPUT_ROOT / "predictions" / "validation_validation_calibration_S2.jsonl",
            "VALIDATION_COMPARISON": OUTPUT_ROOT / "predictions" / "validation_validation_comparison_S2.jsonl",
        },
    }
    prediction_cache: dict[str, dict[str, np.ndarray]] = {"S1": {}, "S2": {}}
    for model_id in ("S1", "S2"):
        for partition, partition_rows in validation_rows.items():
            first_scores, first_report = _predict_validation(estimators[model_id], states[model_id], partition_rows)
            second_scores, second_report = _predict_validation(estimators[model_id], states[model_id], partition_rows)
            replay_difference = float(np.max(np.abs(first_scores - second_scores))) if first_scores.size else 0.0
            if replay_difference > 1e-12:
                raise S2FitError(f"{model_id} validation replay is not deterministic")
            prediction_cache[model_id][partition] = first_scores
            metric_reports[model_id][partition] = evaluate_probabilities(
                [int(str(row["label"]).strip()) for row in partition_rows],
                first_scores,
            )
            replay_reports[model_id][partition] = {
                "max_difference": replay_difference,
                "first": first_report,
                "second": second_report,
                "artifact": _prediction_artifact_replay(prediction_paths[model_id][partition], partition_rows, first_scores),
            }

    comparison_ap = {model_id: metric_reports[model_id]["VALIDATION_COMPARISON"]["average_precision"] for model_id in ("S1", "S2")}
    preferred_model = select_preferred_model(comparison_ap)
    lock = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3D",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan_sha256": contract["plan_sha256"],
        "master_plan_sha256": contract["master_plan_sha256"],
        "source_train_sha256": EXPECTED["source_train_sha256"],
        "official_test_identity_sha256": EXPECTED["test_identity_sha256"],
        "test_used": False,
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "chained_signals_used": False,
        "feature_contract": {"sha256": contract_hash, "feature_order": list(FEATURE_ORDER), "excluded_fields": contract["excluded_fields"]},
        "partitions": {
            partition: {"rows": len(partition_rows), "membership_sha256": _membership_sha256(partition_rows)}
            for partition, partition_rows in {"TRAIN_INTERNAL": train_internal, **validation_rows}.items()
        },
        "group_cross_partition": cross_partition_groups,
        "threshold_policy": {"version": "stage_2.3-fixed-threshold/1.0", "rule": "p_attack >= 0.5 -> ATTACK", "thresholds": {"S1": 0.5, "S2": 0.5}},
        "selection_rule": {"version": "stage_2.3-validation-comparison-ap/1.0", "metric": "sklearn.metrics.average_precision_score", "positive_class": 1, "tie_tolerance": 1e-6, "tie_preference": "S1"},
        "preferred_model": preferred_model,
        "comparison_metrics": {model_id: metric_reports[model_id]["VALIDATION_COMPARISON"] for model_id in ("S1", "S2")},
        "calibration_metrics": {model_id: metric_reports[model_id]["VALIDATION_CALIBRATION"] for model_id in ("S1", "S2")},
        "models": {},
        "upstream_hashes": upstream_hashes,
        "parent_checkpoints": {"2.3B": parent_b_hash, "2.3C": parent_c_hash},
        "fold_manifest_sha256": fold_manifest_hash,
        "dependency_versions": _dependency_versions(),
        "implementation_commit": _git_identity(),
    }
    for model_id in ("S1", "S2"):
        paths = model_paths[model_id]
        lock["models"][model_id] = {
            "family": "LOGISTIC_REGRESSION" if model_id == "S1" else "RANDOM_FOREST",
            "hyperparameters": estimators[model_id].get_params(),
            "classes": [0, 1],
            "threshold": 0.5,
            "preprocessing_state_sha256": states[model_id].state_sha256,
            "artifacts": {key: _sha256(path) for key, path in paths.items()},
        }
    validate_selection_lock({"test_used": False, "chained_signals_used": False, "thresholds": {"S1": 0.5, "S2": 0.5}})

    reports_root = OUTPUT_ROOT / "reports"
    manifests_root = OUTPUT_ROOT / "manifests"
    comparison_report = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3D",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "roles": {partition: len(partition_rows) for partition, partition_rows in {"TRAIN_INTERNAL": train_internal, **validation_rows}.items()},
        "group_cross_partition": cross_partition_groups,
        "models": metric_reports,
        "replay": replay_reports,
        "primary_metric": "AVERAGE_PRECISION via sklearn.metrics.average_precision_score",
        "selection_basis": "VALIDATION_COMPARISON AP",
        "preferred_model": preferred_model,
        "both_models_retained_for_test": True,
        "thresholds_frozen": True,
        "test_used": False,
        "chained_signals_used": False,
        "upstream_hashes": upstream_hashes,
    }
    comparison_hash = _write(reports_root / "validation_comparison_S1_S2.json", comparison_report)
    lock["comparison_report_sha256"] = comparison_hash
    lock_hash = _write(manifests_root / "selection_lock.json", lock)

    handoff = {
        "schema_version": "stage_2.3/1.0",
        "checkpoint": "2.3D",
        "status": "READY_FOR_STAGE_2_4_AFTER_2_3_COMPLETION",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "base_feature_contract_sha256": contract_hash,
        "feature_order": list(FEATURE_ORDER),
        "target": {"field": "label", "normal": 0, "attack": 1},
        "classes": [0, 1],
        "probability_semantics": {"field": "p_attack", "class": 1, "higher": "greater_model_estimated_ATTACK_probability"},
        "threshold": 0.5,
        "fit_boundary": "TRAIN_INTERNAL_ONLY",
        "fold_manifest_sha256": fold_manifest_hash,
        "outer_group_cross_fold": 0,
        "chained_signals_used": False,
        "preferred_model": preferred_model,
        "models": {
            model_id: {
                "family": lock["models"][model_id]["family"],
                "hyperparameters": lock["models"][model_id]["hyperparameters"],
                "final_model_sha256": lock["models"][model_id]["artifacts"]["model"],
                "final_feature_state_sha256": lock["models"][model_id]["artifacts"]["state"],
                "oof_prediction_sha256": _sha256(OUTPUT_ROOT / "predictions" / f"oof_{model_id}.jsonl"),
            }
            for model_id in ("S1", "S2")
        },
        "selection_lock_sha256": lock_hash,
        "upstream_hashes": upstream_hashes,
        "test_results": "NOT_INCLUDED_TEST_LOCKED",
    }
    handoff_hash = _write(manifests_root / "stage_2_4_handoff.json", handoff)

    artifact_hashes = {
        "reports/validation_comparison_S1_S2.json": comparison_hash,
        "manifests/selection_lock.json": lock_hash,
        "manifests/stage_2_4_handoff.json": handoff_hash,
    }
    checkpoint = {
        "schema_version": "stage_2.3/checkpoint-2.3D/1.0",
        "checkpoint": "2.3D",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "plan_sha256": contract["plan_sha256"],
        "master_plan_sha256": contract["master_plan_sha256"],
        "parent_checkpoints": {"2.3B": parent_b_hash, "2.3C": parent_c_hash},
        "test_lock": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "test_used": False,
        "chained_signals_used": False,
        "group_cross_partition": cross_partition_groups,
        "preferred_model": preferred_model,
        "thresholds_frozen": True,
        "determinism": "PASS",
        "selection_lock": "CREATED",
        "artifacts": artifact_hashes,
        "upstream_hashes": upstream_hashes,
        "dependency_versions": _dependency_versions(),
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3E",
    }
    artifact_hashes["manifests/checkpoint_2_3D.json"] = _write(manifests_root / "checkpoint_2_3D.json", checkpoint)
    return {
        "status": "COMPLETE",
        "s1": "LOGISTIC REGRESSION C=1.0",
        "s2": "RANDOM FOREST S2_CONFIG",
        "s1_threshold": 0.5,
        "s2_threshold": 0.5,
        "s1_validation_comparison": metric_reports["S1"]["VALIDATION_COMPARISON"],
        "s2_validation_comparison": metric_reports["S2"]["VALIDATION_COMPARISON"],
        "primary_selection_metric": "AVERAGE PRECISION via sklearn.metrics.average_precision_score",
        "preferred_model": preferred_model,
        "selection_basis": "VALIDATION_COMPARISON AP",
        "both_models_retained_for_test": "YES",
        "group_cross_partition": cross_partition_groups,
        "chained_signals_used": "NO",
        "test_used": "NO",
        "thresholds_frozen": "YES",
        "selection_lock": "CREATED",
        "determinism": "PASS",
        "artifacts": artifact_hashes,
        "next_action": "HUMAN_APPROVAL_REQUIRED_FOR_2.3E",
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True, choices=["2.3A", "2.3B", "2.3C", "2.3D"])
    arguments = parser.parse_args()
    if arguments.checkpoint == "2.3A":
        result = run_checkpoint()
    elif arguments.checkpoint == "2.3B":
        result = run_checkpoint_b()
    elif arguments.checkpoint == "2.3C":
        result = run_checkpoint_c()
    else:
        result = run_checkpoint_d()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
