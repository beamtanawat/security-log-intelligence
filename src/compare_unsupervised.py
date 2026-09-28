"""Stage 2.2A contract checkpoint CLI.

Checkpoint 2.2A materializes only the UNSW feature, split, and preprocessing
contracts. It never fits U1/U2 and never opens the official TEST CSV.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import pickle
import platform
import re
import resource
import subprocess
import time
from pathlib import Path
from typing import Any

import numpy as np
from threadpoolctl import threadpool_limits

from unsupervised.contracts import BRANCH_ID, DATASET_ID, build_feature_contract
from unsupervised.features import fit_features, transform_features
from unsupervised.models import U2Config, fit_u2, pilot_order, score_u2
from unsupervised.splits import SplitManifest, build_split_manifest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = PROJECT_ROOT / "data" / "unsw_nb15" / "raw" / "UNSW_NB15_training-set.csv"
ACQUISITION_MANIFEST = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_acquisition_manifest.json"
VALIDATION_SUMMARY = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "unsw_nb15_validation_summary.json"
OUTPUT_ROOT = PROJECT_ROOT / "data" / "unsw_nb15" / "processed" / "stage_2_2" / "v1"
U2_FEASIBILITY_PATH = OUTPUT_ROOT / "feasibility" / "unsw_u2_feasibility.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _write_json(path: Path, payload: Any) -> str:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _json_bytes(payload) + b"\n"
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> str:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"".join(_json_bytes(row) + b"\n" for row in rows)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _physical_memory_bytes() -> int:
    try:
        return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        try:
            output = subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("unable to measure physical memory") from exc
        match = re.search(r"Memory:\s*([0-9]+(?:\.[0-9]+)?)\s*(MB|GB|TB)", output)
        if not match:
            raise RuntimeError("unable to measure physical memory")
        value = float(match.group(1))
        multiplier = {"MB": 1024**2, "GB": 1024**3, "TB": 1024**4}[match.group(2)]
        return int(value * multiplier)


def _mac_peak_rss_bytes() -> int:
    # macOS reports ru_maxrss in bytes; this runner is macOS as required by the plan.
    if platform.system() != "Darwin":
        raise RuntimeError("U2 resource gate requires macOS RSS units")
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _feature_only_row(row: dict[str, object]) -> dict[str, object]:
    feature_contract = build_feature_contract()
    values = {field: row.get(field) for field in feature_contract["feature_order"]}
    values.update({
        "dataset_id": row["dataset_id"],
        "branch_id": row["branch_id"],
        "official_split": row["official_split"],
        "row_number": row["row_number"],
        "development_partition": row["development_partition"],
    })
    return values


def _load_stage_2_2a_precondition() -> tuple[list[dict[str, object]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not OUTPUT_ROOT.is_dir():
        raise RuntimeError("Stage 2.2A artifact root is missing")
    report = json.loads((OUTPUT_ROOT / "reports" / "unsw_split_audit.json").read_text(encoding="utf-8"))
    contract = json.loads((OUTPUT_ROOT / "contracts" / "unsw_feature_contract.json").read_text(encoding="utf-8"))
    publication = json.loads((OUTPUT_ROOT / "manifest.json").read_text(encoding="utf-8"))
    if len(contract["feature_order"]) != 28:
        raise RuntimeError("Stage 2.2A predictive feature count mismatch")
    if report["official_train_rows"] != 175341 or sum(report["partition_counts"].values()) != 175341:
        raise RuntimeError("Stage 2.2A row preservation invariant failed")
    if report["partition_counts"]["TRAIN_INTERNAL"] != 140273 or (
        report["partition_counts"]["VALIDATION_CALIBRATION"]
        + report["partition_counts"]["VALIDATION_COMPARISON"] != 35068
    ):
        raise RuntimeError("Stage 2.2A partition invariant failed")
    if report["exact_predictive_group_count"] != 88976 or report["target_conflict_groups"] != 273:
        raise RuntimeError("Stage 2.2A active reproducibility fingerprint failed")
    if report["target_conflict_rows"] != 6896 or report["target_conflict_normal"] != 2156 or report["target_conflict_attack"] != 4740:
        raise RuntimeError("Stage 2.2A conflict fingerprint failed")
    if report["exact_predictive_group_cross_split_count"] != 0:
        raise RuntimeError("Stage 2.2A predictive group cross-split invariant failed")
    if contract["fit_boundary"] != "TRAIN_INTERNAL_ONLY":
        raise RuntimeError("Stage 2.2A preprocessing fit boundary failed")
    if report["test_csv_opened"] or report["test_labels_read"] or publication["test_lock"] != "STRUCTURAL_ONLY_NO_TEST_CSV_OPENED":
        raise RuntimeError("Stage 2.2A TEST lock invariant failed")
    rows, _ = _load_train_rows()
    split_rows = [
        json.loads(line)
        for line in (OUTPUT_ROOT / "manifests" / "unsw_split_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    if len(split_rows) != len(rows) or len({entry["row_key"] for entry in split_rows}) != len(rows):
        raise RuntimeError("Stage 2.2A split manifest coverage failed")
    partition_by_number = {entry["row_number"]: entry["partition"] for entry in split_rows}
    for row in rows:
        row["development_partition"] = partition_by_number[row["row_number"]]
    return rows, report, contract, publication


def _pilot_report_hash(row_keys: list[str]) -> str:
    payload = json.dumps(row_keys, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def run_u2_feasibility() -> dict[str, Any]:
    rows, split_report, contract, publication = _load_stage_2_2a_precondition()
    train_rows = [row for row in rows if row["development_partition"] == "TRAIN_INTERNAL"]
    ordered_keys = pilot_order([json.dumps([DATASET_ID, "TRAIN", row["row_number"]], separators=(",", ":")) for row in train_rows], DATASET_ID)
    rows_by_key = {
        json.dumps([DATASET_ID, "TRAIN", row["row_number"]], separators=(",", ":")): row
        for row in train_rows
    }
    selected_keys = ordered_keys[: min(10000, len(ordered_keys))]
    if len(selected_keys) < 5072:
        raise RuntimeError("U2 pilot requires at least 3072 fitting rows and 2000 unseen rows")
    fitting_keys = selected_keys[:-2000]
    query_keys = selected_keys[-2000:]
    fitting_rows = [_feature_only_row(rows_by_key[key]) for key in fitting_keys]
    query_rows = [_feature_only_row(rows_by_key[key]) for key in query_keys]
    pilot_state = fit_features(fitting_rows, DATASET_ID)
    X_fit = transform_features(fitting_rows, pilot_state)
    X_query = transform_features(query_rows, pilot_state)
    memory_ceiling = min(4 * 1024**3, _physical_memory_bytes() // 2)
    estimated_peak = X_fit.nbytes + X_query.nbytes + (32 * X_fit.shape[1] * 8 * 2)
    if estimated_peak > memory_ceiling:
        raise RuntimeError("U2 pilot preflight exceeds memory ceiling")
    config = U2Config()
    runs: list[dict[str, Any]] = []
    score_batches: list[np.ndarray] = []
    for run_number in (1, 2):
        started = time.perf_counter()
        with threadpool_limits(limits=1):
            bundle = fit_u2(X_fit, fitting_keys, config)
            scores = score_u2(bundle, X_query)
        elapsed = time.perf_counter() - started
        serialized = pickle.dumps(bundle, protocol=pickle.HIGHEST_PROTOCOL)
        replay_bundle = pickle.loads(serialized)
        replay_scores = score_u2(replay_bundle, X_query)
        peak_rss = _mac_peak_rss_bytes()
        if not np.isfinite(scores).all() or np.ptp(scores) <= 0:
            raise RuntimeError("U2 pilot produced constant or non-finite scores")
        if not np.allclose(scores, replay_scores, rtol=1e-10, atol=1e-12):
            raise RuntimeError("U2 pilot serialization replay mismatch")
        score_batches.append(scores)
        runs.append({
            "run": run_number,
            "elapsed_seconds": elapsed,
            "peak_rss_bytes": peak_rss,
            "serialized_bytes": len(serialized),
            "query_rows": len(query_rows),
            "finite_scores": True,
            "nonconstant_scores": True,
            "serialization_replay": "PASS",
            "within_120_seconds": elapsed <= 120.0,
            "within_memory_ceiling": peak_rss <= memory_ceiling,
            "score_sha256": hashlib.sha256(scores.tobytes()).hexdigest(),
        })
    deterministic = np.allclose(score_batches[0], score_batches[1], rtol=1e-10, atol=1e-12)
    if not deterministic or not all(run["within_120_seconds"] and run["within_memory_ceiling"] for run in runs):
        raise RuntimeError("U2 bounded feasibility gate failed")
    report = {
        "schema_version": "stage_2.2b-u2-feasibility/1.0",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": "BRANCH_B_LABELED_BENCHMARK",
        "candidate": "MINIBATCHKMEANS_DISTANCE_SCORER",
        "configuration": config.to_dict(),
        "input_artifacts": {
            "stage_2_2a_public_manifest_sha256": _sha256(OUTPUT_ROOT / "manifest.json"),
            "stage_2_2a_split_report_sha256": _sha256(OUTPUT_ROOT / "reports" / "unsw_split_audit.json"),
            "feature_contract_sha256": _sha256(OUTPUT_ROOT / "contracts" / "unsw_feature_contract.json"),
            "feature_state_sha256": _sha256(OUTPUT_ROOT / "features" / "unsw_train_internal_feature_state.json"),
            "source_train_sha256": _sha256(TRAIN_PATH),
        },
        "pilot": {
            "eligible_train_internal_rows": len(train_rows),
            "selected_rows": len(selected_keys),
            "fit_rows": len(fitting_keys),
            "query_rows": len(query_keys),
            "order": "SHA256([s2.2-pilot-v1,dataset_id,row_key]),then,row_key",
            "selection_sha256": _pilot_report_hash(selected_keys),
            "preprocessing_state_sha256": pilot_state.state_sha256,
            "preprocessing_fit_boundary": "PILOT_FIT_ROWS_ONLY",
            "feature_count": X_fit.shape[1],
        },
        "runs": runs,
        "determinism": "PASS",
        "label_free_fit": True,
        "test_used": False,
        "score_semantics": "HIGHER_MORE_ANOMALOUS",
        "selected_u2": "MINIBATCHKMEANS_DISTANCE_SCORER",
        "selection_rationale": "SOLE_APPROVED_RUNNABLE_U2_RECIPE_PASSED_BOUNDED_GATE",
        "alternatives": {
            "LOF_NOVELTY": "NOT_RUN_PLAN_EXCLUDES_FROM_THIS_GATE",
            "ONE_CLASS_SVM": "NOT_RUN_PLAN_EXCLUDES_FROM_THIS_GATE",
            "ROBUST_COVARIANCE": "NOT_RUN_PLAN_EXCLUDES_FROM_THIS_GATE",
            "SGD_ONE_CLASS_SVM": "NOT_RUN_PLAN_EXCLUDES_FROM_THIS_GATE",
        },
        "stage_2_2a_unchanged": True,
        "test_lock": publication["test_lock"],
        "models_exported": False,
    }
    _write_json(U2_FEASIBILITY_PATH, report)
    return {
        "status": "PASS",
        "candidate": report["candidate"],
        "selected_u2": report["selected_u2"],
        "runs": len(runs),
        "determinism": report["determinism"],
        "test_used": report["test_used"],
        "artifact": str(U2_FEASIBILITY_PATH),
    }


def _load_train_rows() -> tuple[list[dict[str, object]], list[str]]:
    if not TRAIN_PATH.is_file():
        raise RuntimeError(f"missing official TRAIN CSV: {TRAIN_PATH}")
    with ACQUISITION_MANIFEST.open("r", encoding="utf-8") as stream:
        acquisition = json.load(stream)
    expected = next(item for item in acquisition["files"] if item["role"] == "TRAIN")
    observed_hash = _sha256(TRAIN_PATH)
    if observed_hash != expected["sha256"]:
        raise RuntimeError("official TRAIN SHA-256 differs from the closed acquisition manifest")
    expected_columns = acquisition["schema"]["columns"]
    rows: list[dict[str, object]] = []
    with TRAIN_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != expected_columns:
            raise RuntimeError("official TRAIN schema differs from the closed acquisition manifest")
        for number, row in enumerate(reader, 1):
            if None in row or any(value is None for value in row.values()):
                raise RuntimeError(f"malformed official TRAIN row {number}")
            row["dataset_id"] = DATASET_ID
            row["branch_id"] = BRANCH_ID
            row["official_split"] = "TRAIN"
            row["row_number"] = number
            rows.append(row)
    if len(rows) != expected["observed_row_count"]:
        raise RuntimeError("official TRAIN row count differs from the closed acquisition manifest")
    return rows, list(expected_columns)


def materialize_checkpoint() -> dict[str, Any]:
    """Build the 2.2A contract artifacts from official TRAIN only."""

    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"refusing to overwrite checkpoint root {OUTPUT_ROOT}")
    rows, source_columns = _load_train_rows()
    split: SplitManifest = build_split_manifest(rows, DATASET_ID)
    partition_by_number = {entry["row_number"]: entry["partition"] for entry in split.rows}
    train_internal = []
    validation_rows = []
    for row in rows:
        partition = partition_by_number[row["row_number"]]
        row["development_partition"] = partition
        if partition == "TRAIN_INTERNAL":
            train_internal.append(row)
        else:
            validation_rows.append(row)
    state = fit_features(train_internal, DATASET_ID)
    validation_matrix = transform_features(validation_rows[: min(128, len(validation_rows))], state)
    if validation_matrix.shape[1] != len(state.output_feature_names):
        raise RuntimeError("frozen validation transform feature dimension mismatch")

    acquisition_hash = _sha256(ACQUISITION_MANIFEST)
    validation_hash = _sha256(VALIDATION_SUMMARY)
    feature_contract = build_feature_contract()
    feature_contract.update({
        "source_columns": source_columns,
        "source_train_sha256": _sha256(TRAIN_PATH),
        "acquisition_manifest_sha256": acquisition_hash,
        "validation_summary_sha256": validation_hash,
        "split_manifest_sha256": split.manifest_sha256,
        "fit_row_count": len(train_internal),
        "validation_row_count": len(validation_rows),
        "output_feature_count": len(state.output_feature_names),
        "output_feature_names": list(state.output_feature_names),
    })
    contract_path = OUTPUT_ROOT / "contracts" / "unsw_feature_contract.json"
    split_path = OUTPUT_ROOT / "manifests" / "unsw_split_manifest.jsonl"
    report_path = OUTPUT_ROOT / "reports" / "unsw_split_audit.json"
    state_path = OUTPUT_ROOT / "features" / "unsw_train_internal_feature_state.json"
    contract_hash = _write_json(contract_path, feature_contract)
    split_hash = _write_jsonl(split_path, list(split.rows))
    report = dict(split.report)
    report.update({
        "feature_contract_sha256": contract_hash,
        "split_manifest_file_sha256": split_hash,
        "train_internal_feature_state_sha256": state.state_sha256,
        "validation_transform_sample_rows": min(128, len(validation_rows)),
        "test_csv_opened": False,
        "test_labels_read": False,
        "fortigate_state_reused": False,
        "dataset_rows_merged": False,
    })
    report_hash = _write_json(report_path, report)
    state_hash = _write_json(state_path, state.to_dict())
    publication = {
        "schema_version": "stage_2.2a-public-manifest/1.0",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "checkpoint": "2.2A",
        "source_train_sha256": _sha256(TRAIN_PATH),
        "acquisition_manifest_sha256": acquisition_hash,
        "validation_summary_sha256": validation_hash,
        "artifacts": {
            "contracts/unsw_feature_contract.json": contract_hash,
            "manifests/unsw_split_manifest.jsonl": split_hash,
            "reports/unsw_split_audit.json": report_hash,
            "features/unsw_train_internal_feature_state.json": state_hash,
        },
        "test_lock": "STRUCTURAL_ONLY_NO_TEST_CSV_OPENED",
        "models_fit": False,
    }
    manifest_hash = _write_json(OUTPUT_ROOT / "manifest.json", publication)
    publication["manifest_sha256"] = manifest_hash
    return {
        "status": "PASS",
        "train_rows": len(rows),
        "train_internal": len(train_internal),
        "validation_internal": len(validation_rows),
        "output_feature_count": len(state.output_feature_names),
        "split_manifest_sha256": split.manifest_sha256,
        "checkpoint_root": str(OUTPUT_ROOT),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True, choices=("2.2A", "2.2B"))
    args = parser.parse_args()
    result = materialize_checkpoint() if args.checkpoint == "2.2A" else run_u2_feasibility()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
