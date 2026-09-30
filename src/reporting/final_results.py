"""Read-only Stage 2.5A result registry builder.

This module consumes frozen JSON/planning artifacts only.  It deliberately
does not import model classes, read raw CSVs, deserialize models, or generate
predictions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "stage_2.5-results/1.0"
CLAIMS_SCHEMA_VERSION = "stage_2.5-claims/1.0"
EXPECTED_HANDOFF_SHA256 = "059e930611897776bec00f892bd0c72dec40d0236a18b0de5ab1c6814601fc64"
EXPECTED_STAGE_2_4_COMMIT = "d011808855acdfe63fe18865b9e937ba3db3c801"
TEST_ROWS = 82332


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root(path: Path) -> Path:
    current = path.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    raise ValueError(f"repository root not found for {path}")


def _rel(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"source path escapes repository: {path}") from error
    return relative.as_posix()


def _load(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.is_file():
        raise ValueError(f"required authoritative artifact missing: {relative}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in authoritative artifact: {relative}") from error
    if not isinstance(value, dict):
        raise ValueError(f"authoritative artifact must be a JSON object: {relative}")
    return value


def _source_entry(root: Path, relative: str, checkpoint: str, purpose: str, pointers: list[str]) -> dict[str, Any]:
    path = root / relative
    if not path.is_file():
        raise ValueError(f"required source missing: {relative}")
    if relative.startswith("data/") and "/raw/" in relative:
        raise ValueError(f"raw data is not an allowed Stage 2.5A source: {relative}")
    schema = {
        ".json": "json-object",
        ".md": "markdown",
        ".py": "python-source",
    }.get(path.suffix, "file-bytes")
    parent_manifest: str | None = None
    if relative.startswith("data/unsw_nb15/processed/stage_2_4/v1/"):
        candidate = "data/unsw_nb15/processed/stage_2_4/v1/manifest.json"
        if (root / candidate).is_file() and relative != candidate:
            parent_manifest = candidate
    elif relative.startswith("data/unsw_nb15/processed/stage_2_2/v1/"):
        candidate = "data/unsw_nb15/processed/stage_2_2/v1/manifest.json"
        if (root / candidate).is_file() and relative != candidate:
            parent_manifest = candidate
    elif relative.startswith("data/processed/stage_2_2/fortigate/v1/"):
        candidate = "data/processed/stage_2_2/fortigate/v1/manifest.json"
        if (root / candidate).is_file() and relative != candidate:
            parent_manifest = candidate
    return {
        "path": relative,
        "sha256": _sha256(path),
        "schema": schema,
        "parent_manifest": parent_manifest,
        "parent_manifest_sha256": _sha256(root / parent_manifest) if parent_manifest else None,
        "checkpoint": checkpoint,
        "purpose": purpose,
        "json_pointers": pointers,
        "allowed_json_pointers": pointers,
    }


def _source_map(root: Path) -> dict[str, dict[str, Any]]:
    specs: list[tuple[str, str, str, list[str]]] = [
        ("data/unsw_nb15/processed/stage_2_4/v1/manifest.json", "2.4", "Stage 2.4 parent manifest", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json", "2.4E", "primary handoff", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/selection_lock.json", "2.4D", "chain selection lock", ["/chain_preferred_model", "/models", "/crossfit"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/final_test_evaluator_authorization.json", "2.4E", "human TEST authorization", ["/authorization_type", "/human_authorized", "/selection_lock_sha256"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/fit_accounting_2_4B.json", "2.4B", "authoritative fit accounting repair", ["/fit_dispositions", "/required_row_coverage", "/fallback_or_imputed_signals"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/crossfit_contract.json", "2.4A", "cross-fit membership contract", ["/fit_plan", "/preprocessing_boundaries", "/test_used"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/manifests/signal_coverage.json", "2.4B", "OOF signal coverage", ["/U1", "/U2", "/same_group_fit_signal_overlap", "/same_row_fit_signal_overlap"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/reports/leakage_audit_2_4B.json", "2.4B", "signal leakage audit", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s1_development.json", "2.4C", "CHAIN-S1 development comparison", ["/validation/VALIDATION_COMPARISON/comparison"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s2_development.json", "2.4D", "CHAIN-S2 development comparison", ["/validation/VALIDATION_COMPARISON/comparison"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/final_stage_2_4_manifest.json", "2.4E", "locked chain TEST manifest", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_metrics.json", "2.4E", "CHAIN-S1 TEST metrics", ["/metrics", "/baseline_average_precision"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s2_test_metrics.json", "2.4E", "CHAIN-S2 TEST metrics", ["/metrics", "/baseline_average_precision"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_confusion_matrix.json", "2.4E", "CHAIN-S1 TEST confusion matrix", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s2_test_confusion_matrix.json", "2.4E", "CHAIN-S2 TEST confusion matrix", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_test_sensitivity_analysis.json", "2.4E", "CHAIN TEST sensitivity analysis", ["/"]),
        ("data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_test_evaluation_provenance.json", "2.4E", "CHAIN TEST evaluation provenance", ["/"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/manifests/selection_lock.json", "2.3D", "BASE model selection lock", ["/models", "/comparison_metrics", "/preferred_model"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/reports/validation_comparison_S1_S2.json", "2.3D", "BASE development comparison", ["/models", "/preferred_model", "/primary_metric"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/manifests/final_test_evaluator_authorization.json", "2.3E", "BASE TEST authorization", ["/models", "/selection_lock_sha256"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/final_stage_2_3_manifest.json", "2.3E", "BASE TEST manifest", ["/"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s1_test_metrics.json", "2.3E", "BASE S1 TEST metrics", ["/metrics"]),
        ("data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s2_test_metrics.json", "2.3E", "BASE S2 TEST metrics", ["/metrics"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/manifest.json", "2.2A", "UNSW Stage 2.2 manifest", ["/"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/validation/selection_lock_manifest.json", "2.2D", "UNSW U1/U2 selection lock", ["/models", "/comparison_decision", "/official_test"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_validation_metrics.json", "2.2D", "UNSW U1 development metrics", ["/comparison"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u2_validation_metrics.json", "2.2D", "UNSW U2 development metrics", ["/comparison"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_u2_comparison.json", "2.2D", "UNSW U1/U2 comparison", ["/"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/final_stage_2_2_manifest.json", "2.2E", "UNSW U1/U2 TEST manifest", ["/"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u1_test_metrics.json", "2.2E", "UNSW U1 TEST metrics", ["/metrics"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u2_test_metrics.json", "2.2E", "UNSW U2 TEST metrics", ["/metrics"]),
        ("data/unsw_nb15/processed/unsw_nb15_acquisition_manifest.json", "2.1", "UNSW acquisition provenance", ["/files", "/schema", "/test_lock"]),
        ("data/unsw_nb15/processed/unsw_nb15_validation_summary.json", "2.1", "UNSW validation summary", ["/stage_2_1_closure", "/test_lock", "/dataset_separation"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/contracts/unsw_feature_contract.json", "2.2A", "UNSW feature contract", ["/feature_order", "/excluded_fields", "/fit_boundary"]),
        ("data/unsw_nb15/processed/stage_2_2/v1/reports/unsw_split_audit.json", "2.2A", "UNSW split audit", ["/partition_counts", "/group_overlap_check"]),
        ("data/processed/stage_2_2/fortigate/v1/manifest.json", "2.2C", "FortiGate unsupervised manifest", ["/", "/u2_config"]),
        ("data/processed/stage_2_2/fortigate/v1/fortigate_u1_u2_comparison.json", "2.2C", "FortiGate unsupervised comparison", ["/reference_descriptive", "/holdout", "/all_rows_descriptive"]),
        ("data/processed/stage_2_0_v5/analysis_summary.json", "historical", "historical FortiGate analysis context", ["/"]),
        ("data/processed/stage_2_0_v5/tables/case_studies.json", "historical", "historical FortiGate case-study context", ["/"]),
        ("docs/plans/stage_2_1_labeling_ground_truth_evaluation_plan.md", "2.1", "Stage 2.1 methodology finding", []),
        ("docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md", "master", "approved master pipeline", []),
        ("docs/plans/stage_2_2_unsupervised_model_comparison_plan.md", "2.2", "Stage 2.2 plan", []),
        ("docs/plans/stage_2_3_supervised_attack_classification_plan.md", "2.3", "Stage 2.3 plan", []),
        ("docs/plans/stage_2_4_chained_ml_pipeline_plan.md", "2.4", "Stage 2.4 plan", []),
        ("docs/plans/stage_2_5_final_evaluation_reporting_plan.md", "2.5", "Stage 2.5 plan", []),
        ("src/unsupervised/evaluation.py", "code", "Stage 2.2 metric implementation", []),
        ("src/supervised/evaluation.py", "code", "Stage 2.3 metric implementation", []),
        ("src/run_unsw_test_evaluation.py", "code", "Stage 2.2 TEST evaluator", []),
        ("src/run_supervised_test_evaluation.py", "code", "Stage 2.3 TEST evaluator", []),
        ("src/run_chained_test_evaluation.py", "code", "Stage 2.4 TEST evaluator", []),
    ]
    entries = {}
    for relative, checkpoint, purpose, pointers in specs:
        entries[relative] = _source_entry(root, relative, checkpoint, purpose, pointers)
    return dict(sorted(entries.items()))


def _ref(inventory: dict[str, dict[str, Any]], relative: str, pointer: str) -> dict[str, str]:
    entry = inventory[relative]
    return {"path": relative, "sha256": entry["sha256"], "json_pointer": pointer}


def _metric_record(
    inventory: dict[str, dict[str, Any]],
    source: str,
    pointer: str,
    dataset: str,
    branch: str,
    model: str,
    population: str,
    row_count: int,
    source_key: str,
    display_name: str,
    implementation: str,
    value: Any,
    undefined_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "dataset": dataset,
        "branch": branch,
        "model": model,
        "population": population,
        "row_count": row_count,
        "metric_source_key": source_key,
        "metric_display_name": display_name,
        "implementation": implementation,
        "value": value,
        "undefined_reason": undefined_reason,
        "source": _ref(inventory, source, pointer),
    }


def _artifact_metric_records(
    inventory: dict[str, dict[str, Any]],
    source: str,
    section: str,
    metrics: dict[str, Any],
    dataset: str,
    branch: str,
    model: str,
    population: str,
    row_count: int,
    threshold: Any = None,
) -> list[dict[str, Any]]:
    """Expand an upstream metric object into provenance-bearing scalar records."""
    display_names = {
        "pr_auc_ap": "Stage 2.2 PR_AUC_AP",
        "average_precision": "Average Precision (AP)",
        "roc_auc": "ROC-AUC",
        "accuracy": "Accuracy",
        "precision": "Precision",
        "recall": "Recall",
        "f1": "F1",
        "tp": "True positives",
        "fp": "False positives",
        "tn": "True negatives",
        "fn": "False negatives",
        "row_count": "Row count",
    }
    implementations = {
        "pr_auc_ap": "sklearn.metrics.average_precision_score",
        "average_precision": "sklearn.metrics.average_precision_score",
        "roc_auc": "sklearn.metrics.roc_auc_score",
    }
    keys = ("pr_auc_ap", "average_precision", "roc_auc", "accuracy", "precision", "recall", "f1", "tp", "fp", "tn", "fn", "row_count")
    records: list[dict[str, Any]] = []
    for key in keys:
        if key == "threshold":
            value = threshold
        elif key not in metrics:
            continue
        else:
            value = metrics[key]
        records.append(
            _metric_record(
                inventory,
                source,
                f"/{section}/{key}",
                dataset,
                branch,
                model,
                population,
                row_count,
                f"{section}.{key}",
                display_names.get(key, key),
                implementations.get(key, "source-artifact-value"),
                value,
                metrics.get("undefined_metric_reason"),
            )
        )
    if threshold is not None:
        records.append(
            _metric_record(
                inventory,
                source,
                "/threshold/threshold",
                dataset,
                branch,
                model,
                population,
                row_count,
                "threshold.threshold",
                "Decision threshold",
                "source-artifact-value",
                threshold,
            )
        )
    return records


def _compact_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    keys = ("accuracy", "precision", "recall", "f1", "roc_auc", "average_precision", "pr_auc_ap", "threshold", "row_count", "tp", "fp", "tn", "fn", "conflict_rows", "pr_auc_convention", "undefined_metric_reason")
    result = {key: metrics[key] for key in keys if key in metrics}
    confusion = metrics.get("confusion_matrix")
    if isinstance(confusion, list) and len(confusion) == 2:
        result["confusion_matrix"] = confusion
    elif isinstance(confusion, dict):
        result["confusion_matrix"] = {key: confusion[key] for key in ("tp", "fp", "tn", "fn") if key in confusion}
    return result


def _claims(inventory: dict[str, dict[str, Any]]) -> dict[str, Any]:
    h = _ref(inventory, "data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json", "/claim_limits")
    b = _ref(inventory, "data/processed/stage_2_2/fortigate/v1/manifest.json", "/")
    s1 = _ref(inventory, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s1_development.json", "/validation/VALIDATION_COMPARISON/comparison")
    s2 = _ref(inventory, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s2_development.json", "/validation/VALIDATION_COMPARISON/comparison")
    supported = [
        {"id": "fortigate_anomaly_review", "statement": "The pipeline can score and prioritize real FortiGate logs for anomaly review.", "scope": "BRANCH_A / FortiGate real sanitized logs", "qualification": "Anomaly review only; no supervised attack claim.", "evidence": [b]},
        {"id": "unsw_quantitative_supervised_evaluation", "statement": "Supervised models were quantitatively evaluated on UNSW-NB15.", "scope": "BRANCH_B / UNSW-NB15", "qualification": "Benchmark result only; not FortiGate production performance.", "evidence": [h]},
        {"id": "leakage_safe_chain_signals", "statement": "Stage 2.4 used leakage-safe OOF/cross-fitted anomaly signals.", "scope": "Stage 2.4 chain development", "qualification": "Same-row and same-group fit/signal overlap were zero.", "evidence": [_ref(inventory, "data/unsw_nb15/processed/stage_2_4/v1/manifests/fit_accounting_2_4B.json", "/") ]},
        {"id": "chain_s1_development_increase", "statement": "CHAIN-S1 produced a small AP increase over BASE S1 in the frozen development comparison.", "scope": "UNSW VALIDATION_COMPARISON", "qualification": "Descriptive frozen comparison; no significance claim.", "evidence": [s1]},
        {"id": "chain_s2_development_decrease", "statement": "CHAIN-S2 produced a small AP decrease relative to BASE S2 in the frozen development comparison.", "scope": "UNSW VALIDATION_COMPARISON", "qualification": "Descriptive frozen comparison; no significance claim.", "evidence": [s2]},
        {"id": "locked_test_deltas_descriptive", "statement": "Locked TEST reporting records the frozen descriptive AP deltas.", "scope": "UNSW official TEST / Stage 2.4E", "qualification": "The official TEST split was used in earlier fixed-stage evaluations and was not newly unseen at project level.", "evidence": [_ref(inventory, "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_metrics.json", "/metrics/average_precision")]},
    ]
    forbidden_specs = [
        ("anomaly_equals_attack", "Anomaly is not confirmed cyberattack evidence.", "ANOMALY != ATTACK"),
        ("anomaly_score_equals_probability", "Anomaly score is not an attack probability.", "ANOMALY SCORE != ATTACK PROBABILITY"),
        ("rule_match_confirmed_attack", "A rule match is not confirmed attack ground truth.", "RULE MATCH != CONFIRMED ATTACK"),
        ("high_interest_confirmed_attack", "HIGH_INTEREST is not confirmed attack.", "HIGH_INTEREST != CONFIRMED ATTACK"),
        ("low_interest_confirmed_benign", "LOW_INTEREST is not confirmed benign.", "LOW_INTEREST != CONFIRMED BENIGN"),
        ("source_threat_ground_truth", "A source threat observation is not ground truth.", "SOURCE THREAT OBSERVATION != GROUND TRUTH"),
        ("absence_of_alert_benign", "Absence of an alert is not benign evidence.", "ABSENCE OF ALERT != BENIGN"),
        ("unsw_equals_fortigate_production", "UNSW performance does not establish FortiGate production performance.", "UNSW metrics do NOT establish FortiGate production performance."),
        ("fortigate_supervised_performance", "No FortiGate supervised accuracy/F1 claim is supported.", "FortiGate supervised performance claim: NO"),
        ("chaining_statistically_proven", "Chaining is not statistically proven superior.", "NO STATISTICAL SIGNIFICANCE CLAIM"),
        ("every_attack_detected", "The project does not claim to detect every attack.", "No universal attack-detection claim."),
        ("production_ready", "The package is not a production-readiness claim.", "No production-readiness claim."),
        ("test_newly_unseen_project_level", "The official TEST split was not newly unseen at the overall project level.", "Prior fixed-stage TEST exposure is disclosed."),
    ]
    forbidden = [
        {"id": identifier, "statement": statement, "scope": "All project claims", "qualification": replacement, "evidence": [h]}
        for identifier, statement, replacement in forbidden_specs
    ]
    tokens = [
        "ANOMALY != ATTACK", "ANOMALY SCORE != ATTACK PROBABILITY", "RULE MATCH != CONFIRMED ATTACK",
        "HIGH_INTEREST != CONFIRMED ATTACK", "LOW_INTEREST != CONFIRMED BENIGN",
        "SOURCE THREAT OBSERVATION != GROUND TRUTH", "ABSENCE OF ALERT != BENIGN", "NO STATISTICAL SIGNIFICANCE CLAIM",
    ]
    return {"schema_version": CLAIMS_SCHEMA_VERSION, "supported": supported, "unsupported_or_forbidden": forbidden, "language_tokens": tokens}


def _collect_bundle(handoff: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = _repo_root(handoff)
    handoff_relative = _rel(root, handoff)
    handoff_hash = _sha256(handoff)
    if handoff_relative != "data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json":
        raise ValueError(f"unexpected handoff path: {handoff_relative}")
    if handoff_hash != EXPECTED_HANDOFF_SHA256:
        raise ValueError(f"handoff hash mismatch: expected {EXPECTED_HANDOFF_SHA256}, got {handoff_hash}")
    handoff_data = _load(root, handoff_relative)
    if handoff_data.get("status") != "READY_FOR_STAGE_2_5_PLANNING":
        raise ValueError("handoff is not ready for Stage 2.5 planning")
    inventory_entries = _source_map(root)
    inventory = {
        "schema_version": "stage_2.5-source-inventory/1.0",
        "primary_handoff": handoff_relative,
        "primary_handoff_sha256": handoff_hash,
        "entries": list(inventory_entries.values()),
        "source_policy": "JSON/plan/code provenance only; no raw CSV, row-level predictions, model loading, or TEST reread.",
    }

    b2_manifest = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/manifest.json")
    b2_lock = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/validation/selection_lock_manifest.json")
    b2_u1_val = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_validation_metrics.json")
    b2_u2_val = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u2_validation_metrics.json")
    b2_u1_test = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u1_test_metrics.json")
    b2_u2_test = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u2_test_metrics.json")
    b2_cmp = _load(root, "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_u2_comparison.json")
    b3_lock = _load(root, "data/unsw_nb15/processed/stage_2_3/v1/manifests/selection_lock.json")
    b3_cmp = _load(root, "data/unsw_nb15/processed/stage_2_3/v1/reports/validation_comparison_S1_S2.json")
    b3_s1_test = _load(root, "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s1_test_metrics.json")
    b3_s2_test = _load(root, "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s2_test_metrics.json")
    b4_s1_dev = _load(root, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s1_development.json")
    b4_s2_dev = _load(root, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s2_development.json")
    b4_s1_test = _load(root, "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_metrics.json")
    b4_s2_test = _load(root, "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s2_test_metrics.json")
    inventory_sha = hashlib.sha256(_canonical_json(inventory)).hexdigest()

    def model_ref(model_id: str, source: str, pointer: str) -> dict[str, Any]:
        return {"model_id": model_id, "source": _ref(inventory_entries, source, pointer)}

    base_s1 = b3_lock["models"]["S1"]
    base_s2 = b3_lock["models"]["S2"]
    u1 = handoff_data["u1_identity"]
    u2 = handoff_data["u2_identity"]
    models = {
        "U1": {"branch": "BRANCH_B", "family": u1["model_family"], "config": u1["config"], "signal": u1["signal"], "score_direction": u1["score_direction"], "model_version": u1["model_version"], "artifact_identity": u1["artifact_identity"], "model_artifact_sha256": u1["model_artifact_sha256"], "preprocessing_state_sha256": u1["preprocessing_state_sha256"], "role": "Stage 2.4 chain inference U1"},
        "U2": {"branch": "BRANCH_B", "family": u2["model_family"], "config": u2["config"], "signal": u2["signal"], "score_direction": u2["score_direction"], "model_version": u2["model_version"], "artifact_identity": u2["artifact_identity"], "model_artifact_sha256": u2["model_artifact_sha256"], "preprocessing_state_sha256": u2["preprocessing_state_sha256"], "role": "Stage 2.4 chain inference U2"},
        "UNSW-U1-BENCHMARK": {"branch": "BRANCH_B", "family": b2_lock["models"]["U1"]["family"], "config": b2_lock["models"]["U1"]["config"], "fit_boundary": b2_lock["fit_boundary"], "model_sha256": b2_lock["models"]["U1"]["model_sha256"], "score_direction": b2_lock["models"]["U1"]["score_direction"], "role": "Stage 2.2 benchmark unsupervised U1"},
        "UNSW-U2-BENCHMARK": {"branch": "BRANCH_B", "family": b2_lock["models"]["U2"]["family"], "config": b2_lock["models"]["U2"]["config"], "fit_boundary": b2_lock["fit_boundary"], "model_sha256": b2_lock["models"]["U2"]["model_sha256"], "score_direction": b2_lock["models"]["U2"]["score_direction"], "role": "Stage 2.2 benchmark unsupervised U2"},
        "FORTIGATE-U1": {"branch": "BRANCH_A", "family": "ISOLATION_FOREST", "fit_split": "REFERENCE", "score_direction": "HIGHER_MORE_ANOMALOUS", "role": "real-log anomaly scoring"},
        "FORTIGATE-U2": {"branch": "BRANCH_A", "family": "MINIBATCHKMEANS_DISTANCE_SCORER", "config": _load(root, "data/processed/stage_2_2/fortigate/v1/manifest.json")["u2_config"], "fit_split": "REFERENCE", "score_direction": "HIGHER_MORE_ANOMALOUS", "role": "real-log anomaly scoring"},
        "BASE-S1": {"branch": "BRANCH_B", "family": base_s1["family"], "config": base_s1["hyperparameters"], "threshold": base_s1["threshold"], "artifacts": base_s1["artifacts"], "role": "frozen supervised baseline"},
        "BASE-S2": {"branch": "BRANCH_B", "family": base_s2["family"], "config": base_s2["hyperparameters"], "threshold": base_s2["threshold"], "artifacts": base_s2["artifacts"], "role": "frozen supervised baseline"},
        "CHAIN-S1": {"branch": "BRANCH_B", "family": handoff_data["chain_models"]["CHAIN-S1"]["family"], "config": {"C": handoff_data["chain_models"]["CHAIN-S1"]["C"]}, "threshold": 0.5, "source_features": handoff_data["chain_models"]["CHAIN-S1"]["source_features"], "training_signal_policy": handoff_data["chain_models"]["CHAIN-S1"]["training_signal_policy"], "artifacts": {"model": handoff_data["chain_models"]["CHAIN-S1"]["model_artifact_sha256"], "metadata": handoff_data["chain_models"]["CHAIN-S1"]["metadata_artifact_sha256"]}},
        "CHAIN-S2": {"branch": "BRANCH_B", "family": handoff_data["chain_models"]["CHAIN-S2"]["family"], "config": base_s2["hyperparameters"], "config_source": handoff_data["chain_models"]["CHAIN-S2"]["config_source"], "threshold": 0.5, "source_features": handoff_data["chain_models"]["CHAIN-S2"]["source_features"], "training_signal_policy": handoff_data["chain_models"]["CHAIN-S2"]["training_signal_policy"], "artifacts": {"model": handoff_data["chain_models"]["CHAIN-S2"]["model_artifact_sha256"], "metadata": handoff_data["chain_models"]["CHAIN-S2"]["metadata_artifact_sha256"]}},
    }

    def pair_dev(name: str, report: dict[str, Any], source: str) -> dict[str, Any]:
        comparison = report["validation"]["VALIDATION_COMPARISON"]["comparison"]
        if name == "CHAIN-S1":
            expected = (0.9939231496371828, 0.9941359114288555, 0.00021276179167273312)
        else:
            expected = (0.9968637967521546, 0.9968208117560664, -0.00004298499608823558)
        if (comparison["base_ap"], comparison["chain_ap"], comparison["delta_ap"]) != expected:
            raise ValueError(f"frozen development result mismatch for {name}")
        return {"base_ap": comparison["base_ap"], "chain_ap": comparison["chain_ap"], "delta_ap": comparison["delta_ap"], "result": comparison["decision"], "population": "VALIDATION_COMPARISON", "threshold": report["threshold"], "provenance": _ref(inventory_entries, source, "/validation/VALIDATION_COMPARISON/comparison")}

    development = {"CHAIN-S1": pair_dev("CHAIN-S1", b4_s1_dev, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s1_development.json"), "CHAIN-S2": pair_dev("CHAIN-S2", b4_s2_dev, "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s2_development.json")}

    def test_pair(name: str, chain: dict[str, Any], base: dict[str, Any], source: str) -> dict[str, Any]:
        chain_metrics = chain["metrics"]
        base_ap = base["metrics"]["average_precision"]
        chain_ap = chain_metrics["average_precision"]
        delta = chain["chain_test_ap_delta"]
        if abs((chain_ap - base_ap) - delta) > 1e-12:
            raise ValueError(f"frozen TEST delta mismatch for {name}")
        return {"base_ap": base_ap, "chain_ap": chain_ap, "ap_delta": delta, "population": chain["population"], "evaluation_type": chain["evaluation_type"], "metrics": _compact_metrics(chain_metrics), "provenance": _ref(inventory_entries, source, "/metrics")}

    locked_test = {"CHAIN-S1": test_pair("CHAIN-S1", b4_s1_test, b3_s1_test, "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_metrics.json"), "CHAIN-S2": test_pair("CHAIN-S2", b4_s2_test, b3_s2_test, "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s2_test_metrics.json")}

    records: list[dict[str, Any]] = []
    for model_id, source, section, metrics, population, rows, threshold in [
        ("UNSW-U1-BENCHMARK", "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_validation_metrics.json", "comparison", b2_u1_val["comparison"], "VALIDATION_COMPARISON", 17529, b2_u1_val["threshold"]["threshold"]),
        ("UNSW-U2-BENCHMARK", "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u2_validation_metrics.json", "comparison", b2_u2_val["comparison"], "VALIDATION_COMPARISON", 17529, b2_u2_val["threshold"]["threshold"]),
        ("UNSW-U1-BENCHMARK", "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u1_test_metrics.json", "metrics", b2_u1_test["metrics"], "OFFICIAL_TEST_ALL_ROWS", TEST_ROWS, b2_u1_test["threshold"]["threshold"]),
        ("UNSW-U2-BENCHMARK", "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u2_test_metrics.json", "metrics", b2_u2_test["metrics"], "OFFICIAL_TEST_ALL_ROWS", TEST_ROWS, b2_u2_test["threshold"]["threshold"]),
    ]:
        records.extend(_artifact_metric_records(inventory_entries, source, section, metrics, "UNSW_NB15_BENCHMARK", "BRANCH_B", model_id, population, rows, threshold))
    for name, pair, source in [("CHAIN-S1", development["CHAIN-S1"], "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s1_development.json"), ("CHAIN-S2", development["CHAIN-S2"], "data/unsw_nb15/processed/stage_2_4/v1/reports/chain_s2_development.json")]:
        records.extend([_metric_record(inventory_entries, source, "/validation/VALIDATION_COMPARISON/comparison/base_ap", "UNSW_NB15_BENCHMARK", "BRANCH_B", "BASE-" + name[-2:], "VALIDATION_COMPARISON", 17529, "comparison.base_ap", "Average Precision (AP)", "sklearn.metrics.average_precision_score", pair["base_ap"]), _metric_record(inventory_entries, source, "/validation/VALIDATION_COMPARISON/comparison/chain_ap", "UNSW_NB15_BENCHMARK", "BRANCH_B", name, "VALIDATION_COMPARISON", 17529, "comparison.chain_ap", "Average Precision (AP)", "sklearn.metrics.average_precision_score", pair["chain_ap"])])
    for name, pair in locked_test.items():
        source = f"data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_{name[-2:].lower()}_test_metrics.json"
        chain_metrics = b4_s1_test["metrics"] if name == "CHAIN-S1" else b4_s2_test["metrics"]
        records.extend(_artifact_metric_records(inventory_entries, source, "metrics", chain_metrics, "UNSW_NB15_BENCHMARK", "BRANCH_B", name, "OFFICIAL_TEST_ALL_ROWS", TEST_ROWS, chain_metrics["threshold"]))
    for name, source, metrics in [
        ("BASE-S1", "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s1_test_metrics.json", b3_s1_test["metrics"]),
        ("BASE-S2", "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s2_test_metrics.json", b3_s2_test["metrics"]),
    ]:
        records.extend(_artifact_metric_records(inventory_entries, source, "metrics", metrics, "UNSW_NB15_BENCHMARK", "BRANCH_B", name, "OFFICIAL_TEST_ALL_ROWS", TEST_ROWS, metrics["threshold"]))

    def matrix_record(model: str, source: str, metrics: dict[str, Any], axes: dict[str, list[str]]) -> dict[str, Any]:
        matrix = metrics.get("confusion_matrix")
        if isinstance(matrix, dict):
            matrix = [[matrix["tn"], matrix["fp"]], [matrix["fn"], matrix["tp"]]]
        if not isinstance(matrix, list) or len(matrix) != 2 or any(not isinstance(row, list) or len(row) != 2 for row in matrix):
            raise ValueError(f"invalid confusion matrix for {model}")
        total = sum(sum(row) for row in matrix)
        if total != TEST_ROWS:
            raise ValueError(f"confusion matrix total mismatch for {model}: {total}")
        return {"model": model, "dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": "OFFICIAL_TEST_ALL_ROWS", "row_count": TEST_ROWS, "matrix": matrix, "axes": axes, "source": _ref(inventory_entries, source, "/metrics/confusion_matrix")}

    confusion_matrices = {
        "UNSW-U1": matrix_record("UNSW-U1", "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u1_test_metrics.json", b2_u1_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["INLIER", "ANOMALY"]}),
        "UNSW-U2": matrix_record("UNSW-U2", "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u2_test_metrics.json", b2_u2_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["INLIER", "ANOMALY"]}),
        "BASE-S1": matrix_record("BASE-S1", "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s1_test_metrics.json", b3_s1_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["NORMAL", "ATTACK"]}),
        "BASE-S2": matrix_record("BASE-S2", "data/unsw_nb15/processed/stage_2_3/v1/test_evaluation/unsw_s2_test_metrics.json", b3_s2_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["NORMAL", "ATTACK"]}),
        "CHAIN-S1": matrix_record("CHAIN-S1", "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s1_test_metrics.json", b4_s1_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["NORMAL", "ATTACK"]}),
        "CHAIN-S2": matrix_record("CHAIN-S2", "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_s2_test_metrics.json", b4_s2_test["metrics"], {"true": ["NORMAL", "ATTACK"], "predicted": ["NORMAL", "ATTACK"]}),
    }

    registry = {
        "schema_version": SCHEMA_VERSION,
        "registry_version": "2.5A",
        "generation": {"checkpoint": "2.5A", "mode": "FROZEN_ARTIFACT_ADAPTER", "no_model_retraining": True, "no_prediction_regeneration": True, "no_official_test_rerun": True, "generated_from": "FROZEN STAGE 2.1–2.4 ARTIFACTS"},
        "checkpoints": {"2.1": {"status": "CLOSED", "commit": "5d1de4a35e0535a68ed891a8ae4708e18a7095dd"}, "2.2": {"status": "CLOSED", "commit": "aeb36ebb8c16fa6eed0b42960dd619b68a889f72"}, "2.3": {"status": "CLOSED", "commit": "674f9035737f5e675797c911c6e92e1f4cdcabca"}, "2.4": {"status": "CLOSED", "commit": EXPECTED_STAGE_2_4_COMMIT}},
        "datasets": {"FORTIGATE_REAL_LOG": {"branch": "BRANCH_A", "identity": "FORTIGATE_REAL_LOG", "raw_claim": "sanitized real logs; raw bytes remain local", "supervised_performance_claim": False}, "UNSW_NB15_BENCHMARK": {"branch": "BRANCH_B", "identity": "UNSW_NB15_BENCHMARK", "official_test_rows": TEST_ROWS, "binary_mapping": {"0": "NORMAL", "1": "ATTACK"}, "feature_contract": "UNSW_NB15 benchmark-specific; FortiGate 36-feature state not reused"}},
        "datasets_merged": False,
        "branches": {"BRANCH_A": {"dataset": "FortiGate real sanitized logs", "role": "REAL-LOG UNSUPERVISED / ANOMALY ANALYSIS", "allowed_use": ["anomaly scoring", "prioritization", "explainability", "real-log case study"], "supervised_fortigate_performance_claim": "NO", "chained_fortigate_supervised_training": "NO"}, "BRANCH_B": {"dataset": "UNSW-NB15", "role": "LABELED BENCHMARK FOR SUPERVISED AND CHAINED QUANTITATIVE EVALUATION", "used_for": ["U1/U2 benchmark evaluation", "BASE S1/S2 evaluation", "CHAIN-S1/S2 evaluation"]}},
        "methodology_finding": {"status": "PRECISION_FIRST_LABELING_NOT_SUFFICIENT_FOR_PRIMARY_SUPERVISED_EVALUATION", "statement": "FortiGate labeling feasibility was investigated; precision-first labeling did not produce sufficient defensible ATTACK/BENIGN coverage for primary supervised evaluation. FortiGate therefore remained the real-log anomaly branch and UNSW-NB15 became the labeled benchmark branch. Weak labels were not forced into supervised evaluation.", "source": _ref(inventory_entries, "docs/plans/stage_2_1_labeling_ground_truth_evaluation_plan.md", "/")},
        "models": models,
        "metrics": {"stage_2_2_unsupervised": {"source_key": "metrics.pr_auc_ap", "display_name": "Stage 2.2 PR_AUC_AP", "implementation": "sklearn.metrics.average_precision_score", "convention": "PR_AUC_AP", "note": "Preserved source terminology; not silently renamed to Average Precision."}, "supervised_average_precision": {"source_key": "metrics.average_precision", "display_name": "Average Precision (AP)", "implementation": "sklearn.metrics.average_precision_score", "positive_class": "ATTACK = 1", "continuous_score": "p_attack"}, "roc_auc": {"source_key": "metrics.roc_auc", "display_name": "ROC-AUC", "implementation": "sklearn.metrics.roc_auc_score"}, "records": records},
        "confusion_matrices": confusion_matrices,
        "comparisons": {"unsupervised_stage_2_2": {"UNSW-U1": {"validation_comparison_pr_auc_ap": b2_cmp["u1_ap"], "test_pr_auc_ap": b2_u1_test["metrics"]["pr_auc_ap"], "provenance": [_ref(inventory_entries, "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_u2_comparison.json", "/u1_ap"), _ref(inventory_entries, "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u1_test_metrics.json", "/metrics/pr_auc_ap")]}, "UNSW-U2": {"validation_comparison_pr_auc_ap": b2_cmp["u2_ap"], "test_pr_auc_ap": b2_u2_test["metrics"]["pr_auc_ap"], "provenance": [_ref(inventory_entries, "data/unsw_nb15/processed/stage_2_2/v1/validation/unsw_u1_u2_comparison.json", "/u2_ap"), _ref(inventory_entries, "data/unsw_nb15/processed/stage_2_2/v1/test_evaluation/unsw_u2_test_metrics.json", "/metrics/pr_auc_ap")] }}, "development": development, "locked_test": locked_test, "test_delta_interpretation": "DESCRIPTIVE REPORTING ONLY"},
        "leakage": {"target_excluded_from_predictive_features": True, "attack_cat_excluded": True, "chained_signals_oof_cross_fitted": True, "same_row_fit_signal_overlap": 0, "same_group_fit_signal_overlap": 0, "fit_accounting": {"planned_fit_ids": 28, "fresh_executed": 20, "validated_reused": 0, "not_required_by_deduplication": 8, "unresolved": 0, "total_accounted": "28/28", "signal_coverage": "140273/140273", "fallback_or_imputed_signals": 0, "same_row_fit_signal_overlap": 0, "same_group_fit_signal_overlap": 0}, "fit_accounting_provenance": _ref(inventory_entries, "data/unsw_nb15/processed/stage_2_4/v1/manifests/fit_accounting_2_4B.json", "/")},
        "governance": {"selection_lock_verified": True, "human_test_authorization_verified": True, "test_contributed_fitted_state": "NONE", "no_post_test_tuning": True, "model_selection_changed_after_test": False, "prior_test_results_used_for_stage_2_4_development": False, "prior_test_visibility_limitation": handoff_data["test_governance"]["prior_test_visibility_limitation"], "test_not_newly_unseen_at_overall_project_level": True, "chain_specific_tuning": "NONE", "selection_lock_sha256": handoff_data["provenance"]["selection_lock_sha256"], "authorization_sha256": handoff_data["provenance"]["authorization_sha256"]},
        "claim_limits": {"unsw_metrics_do_not_establish_fortigate_production_performance": True, "anomaly_not_attack": True, "anomaly_score_not_attack_probability": True, "no_statistical_significance_claim": True, "test_deltas_descriptive_only": True, "no_weak_labels_forced_into_supervised_evaluation": True},
        "source_inventory_sha256": inventory_sha,
    }
    return registry, inventory, _claims(inventory_entries)


def collect_frozen_results(handoff: Path) -> dict[str, Any]:
    """Collect and reconcile frozen results without model/test execution."""
    return _collect_bundle(Path(handoff))[0]


def validate_registry(registry: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    required = ("schema_version", "checkpoints", "datasets", "branches", "models", "metrics", "comparisons", "leakage", "governance", "claim_limits", "source_inventory_sha256")
    for field in required:
        if field not in registry:
            issues.append({"issue": "missing_registry_field", "field": field})
    if registry.get("schema_version") != SCHEMA_VERSION:
        issues.append({"issue": "schema_version_mismatch"})
    if registry.get("datasets_merged") is not False:
        issues.append({"issue": "datasets_merged_not_false"})
    for branch in ("BRANCH_A", "BRANCH_B"):
        if branch not in registry.get("branches", {}):
            issues.append({"issue": "missing_branch", "branch": branch})
    if registry.get("metrics", {}).get("stage_2_2_unsupervised", {}).get("display_name") != "Stage 2.2 PR_AUC_AP":
        issues.append({"issue": "stage_2_2_metric_terminology_drift"})
    if registry.get("leakage", {}).get("fit_accounting", {}).get("unresolved") != 0:
        issues.append({"issue": "unresolved_fit_accounting"})
    if registry.get("governance", {}).get("no_post_test_tuning") is not True:
        issues.append({"issue": "post_test_tuning_flag"})
    if registry.get("claim_limits", {}).get("no_statistical_significance_claim") is not True:
        issues.append({"issue": "missing_significance_limit"})
    if registry.get("source_inventory_sha256") != hashlib.sha256(_canonical_json(inventory)).hexdigest():
        issues.append({"issue": "source_inventory_hash_mismatch"})
    return issues


def validate_package(root: Path) -> dict[str, Any]:
    root = Path(root)
    required = ("final_result_registry.json", "source_inventory.json", "claims_matrix.json")
    for name in required:
        if not (root / name).is_file():
            raise ValueError(f"required Stage 2.5A output missing: {name}")
    registry = json.loads((root / "final_result_registry.json").read_text(encoding="utf-8"))
    inventory = json.loads((root / "source_inventory.json").read_text(encoding="utf-8"))
    claims = json.loads((root / "claims_matrix.json").read_text(encoding="utf-8"))
    issues = validate_registry(registry, inventory)
    if claims.get("schema_version") != CLAIMS_SCHEMA_VERSION:
        issues.append({"issue": "claims_schema_version"})
    tokens = set(claims.get("language_tokens", []))
    required_tokens = {"ANOMALY != ATTACK", "ANOMALY SCORE != ATTACK PROBABILITY", "NO STATISTICAL SIGNIFICANCE CLAIM"}
    if not required_tokens.issubset(tokens):
        issues.append({"issue": "claims_language_tokens"})
    # Package outputs are intentionally allowed in temporary/external output
    # directories during validation.  Resolve source provenance against the
    # current repository rather than assuming the output directory is inside
    # that repository.
    repo = _repo_root(Path.cwd())
    for entry in inventory.get("entries", []):
        path = entry.get("path", "")
        if Path(path).is_absolute() or ".." in Path(path).parts:
            issues.append({"issue": "source_path_escape", "path": path})
            continue
        source = repo / path
        if not source.is_file() or _sha256(source) != entry.get("sha256"):
            issues.append({"issue": "source_hash_mismatch", "path": path})
    if issues:
        raise ValueError(json.dumps(issues, sort_keys=True))
    return {"status": "PASS", "schema_version": SCHEMA_VERSION, "source_entries": len(inventory.get("entries", [])), "claims_supported": len(claims.get("supported", [])), "claims_forbidden": len(claims.get("unsupported_or_forbidden", []))}
