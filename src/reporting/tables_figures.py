"""Deterministic Stage 2.5B table and figure renderer.

Only the frozen Stage 2.5A registry and explicitly referenced immutable
artifacts are read.  No models, raw rows, or prediction generators are used.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import struct
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


TABLE_NAMES = (
    "01_dataset_roles.csv",
    "02_models.csv",
    "03_unsupervised_results.csv",
    "04_base_supervised_results.csv",
    "05_chain_development.csv",
    "06_chain_locked_test.csv",
    "07_leakage_governance.csv",
)
FIGURE_NAMES = (
    "01_two_branch_architecture.mmd",
    "02_fortigate_score_distribution.png",
    "03_paired_ap_deltas.png",
    "04_confusion_matrices.png",
)
PROVENANCE_NAME = "stage_2_5B_provenance.json"
FORTIGATE_FIGURE = "data/processed/stage_2_0_v5/graphs/01_score_distribution.png"
FORTIGATE_COMPARISON = "data/processed/stage_2_2/fortigate/v1/fortigate_u1_u2_comparison.json"
SENSITIVITY = "data/unsw_nb15/processed/stage_2_4/v1/test_evaluation/chained_test_sensitivity_analysis.json"
SELECTION_LOCK = "data/unsw_nb15/processed/stage_2_3/v1/manifests/selection_lock.json"


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root(path: Path) -> Path:
    for candidate in (path.resolve(), *path.resolve().parents):
        if (candidate / ".git").exists():
            return candidate
    raise ValueError(f"repository root not found for {path}")


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key, "")) for key in fieldnames})


def _csv_value(value: Any) -> Any:
    if isinstance(value, float):
        return format(Decimal(str(value)), "f")
    return value


def _json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _inventory_map(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in inventory.get("entries", [])}


def _load_source(root: Path, inventory: dict[str, Any], relative: str) -> tuple[dict[str, Any], dict[str, Any]]:
    entries = _inventory_map(inventory)
    if relative not in entries:
        raise ValueError(f"source is absent from Stage 2.5A inventory: {relative}")
    entry = entries[relative]
    path = root / relative
    if not path.is_file() or _sha256(path) != entry["sha256"]:
        raise ValueError(f"source hash mismatch: {relative}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"source must be an object: {relative}")
    return value, entry


def _source_ref(root: Path, inventory: dict[str, Any], relative: str) -> dict[str, str]:
    entries = _inventory_map(inventory)
    if relative in entries:
        return {"path": relative, "sha256": entries[relative]["sha256"]}
    path = root / relative
    if not path.is_file():
        raise ValueError(f"required Stage 2.5B source missing: {relative}")
    return {"path": relative, "sha256": _sha256(path)}


def _registry_context(registry_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    registry_path = Path(registry_path).resolve()
    root = _repo_root(registry_path)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    inventory_path = registry_path.parent / "source_inventory.json"
    if not inventory_path.is_file():
        raise ValueError("Stage 2.5A source inventory missing")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if registry.get("source_inventory_sha256") != hashlib.sha256(_canonical(inventory)).hexdigest():
        raise ValueError("Stage 2.5A source inventory hash mismatch")
    return root, registry, inventory


def _registry_records(registry: dict[str, Any], model: str, population: str | None = None) -> list[dict[str, Any]]:
    return [
        record
        for record in registry["metrics"]["records"]
        if record["model"] == model and (population is None or record["population"] == population)
    ]


def _metric(records: list[dict[str, Any]], key: str) -> Any:
    for record in records:
        if record["metric_source_key"].endswith(key):
            return record["value"]
    raise ValueError(f"metric missing from registry: {key}")


def _table_dataset_roles(registry: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["branch", "dataset", "role", "uses", "supervised_fortigate_performance_claim", "datasets_merged", "limitation"]
    branches = registry["branches"]
    rows = [
        {"branch": "BRANCH_A", "dataset": branches["BRANCH_A"]["dataset"], "role": branches["BRANCH_A"]["role"], "uses": _json_value(branches["BRANCH_A"]["allowed_use"]), "supervised_fortigate_performance_claim": branches["BRANCH_A"]["supervised_fortigate_performance_claim"], "datasets_merged": "NO", "limitation": "Anomaly analysis only; ANOMALY != ATTACK."},
        {"branch": "BRANCH_B", "dataset": branches["BRANCH_B"]["dataset"], "role": branches["BRANCH_B"]["role"], "uses": _json_value(branches["BRANCH_B"]["used_for"]), "supervised_fortigate_performance_claim": "NOT APPLICABLE", "datasets_merged": "NO", "limitation": "UNSW metrics do NOT establish FortiGate production performance."},
    ]
    return fields, rows


def _table_models(registry: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["model_id", "branch", "role", "family", "config", "source_features", "threshold", "signal", "score_direction", "model_version", "model_artifact_sha256", "preprocessing_state_sha256", "config_source"]
    order = ["FORTIGATE-U1", "FORTIGATE-U2", "UNSW-U1-BENCHMARK", "UNSW-U2-BENCHMARK", "BASE-S1", "BASE-S2", "CHAIN-S1", "CHAIN-S2", "U1", "U2"]
    rows = []
    for model_id in order:
        model = registry["models"][model_id]
        rows.append({"model_id": model_id, "branch": model.get("branch", ""), "role": model.get("role", ""), "family": model.get("family", ""), "config": _json_value(model.get("config", "")), "source_features": model.get("source_features", ""), "threshold": model.get("threshold", ""), "signal": model.get("signal", ""), "score_direction": model.get("score_direction", ""), "model_version": model.get("model_version", ""), "model_artifact_sha256": model.get("model_artifact_sha256", model.get("artifacts", {}).get("model", "")), "preprocessing_state_sha256": model.get("preprocessing_state_sha256", model.get("artifacts", {}).get("state", "")), "config_source": model.get("config_source", "")})
    return fields, rows


def _table_unsupervised(root: Path, registry: dict[str, Any], inventory: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]], list[dict[str, str]]]:
    fields = ["dataset", "branch", "population", "model", "metric", "value", "row_count", "interpretation", "source_path", "source_sha256"]
    comparison, entry = _load_source(root, inventory, FORTIGATE_COMPARISON)
    rows: list[dict[str, Any]] = []
    for population in ("reference_descriptive", "holdout", "all_rows_descriptive"):
        section = comparison[population]
        for model, key in (("FORTIGATE-U1", "u1_alert_fraction"), ("FORTIGATE-U2", "u2_alert_fraction")):
            rows.append({"dataset": "FORTIGATE_REAL_LOG", "branch": "BRANCH_A", "population": population.upper(), "model": model, "metric": "alert_fraction", "value": section[key], "row_count": section["row_count"], "interpretation": "Descriptive anomaly review aggregate; not attack probability." , "source_path": FORTIGATE_COMPARISON, "source_sha256": entry["sha256"]})
    for model, label in (("UNSW-U1-BENCHMARK", "UNSW-U1"), ("UNSW-U2-BENCHMARK", "UNSW-U2")):
        for record in _registry_records(registry, model):
            rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": record["population"], "model": label, "metric": record["metric_display_name"], "value": record["value"], "row_count": record["row_count"], "interpretation": "Benchmark anomaly evaluation; ANOMALY != ATTACK.", "source_path": record["source"]["path"], "source_sha256": record["source"]["sha256"]})
    return fields, rows, [_source_ref(root, inventory, FORTIGATE_COMPARISON)]


def _table_base_supervised(registry: dict[str, Any], root: Path, inventory: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["dataset", "branch", "population", "model", "metric", "value", "threshold", "implementation", "positive_class", "score", "frozen_preference", "source_path", "source_sha256"]
    rows: list[dict[str, Any]] = []
    development = registry["comparisons"]["development"]
    lock, _ = _load_source(root, inventory, SELECTION_LOCK)
    preferred = lock.get("preferred_model", "")
    for name, base_id in (("CHAIN-S1", "BASE-S1"), ("CHAIN-S2", "BASE-S2")):
        pair = development[name]
        rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": "VALIDATION_COMPARISON", "model": base_id, "metric": "Average Precision (AP)", "value": pair["base_ap"], "threshold": registry["models"][base_id]["threshold"], "implementation": "sklearn.metrics.average_precision_score", "positive_class": "ATTACK = 1", "score": "p_attack", "frozen_preference": preferred, "source_path": pair["provenance"]["path"], "source_sha256": pair["provenance"]["sha256"]})
    for model in ("BASE-S1", "BASE-S2"):
        for record in _registry_records(registry, model, "OFFICIAL_TEST_ALL_ROWS"):
            rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": "OFFICIAL_TEST_ALL_ROWS", "model": model, "metric": record["metric_display_name"], "value": record["value"], "threshold": registry["models"][model]["threshold"], "implementation": record["implementation"], "positive_class": "ATTACK = 1", "score": "p_attack", "frozen_preference": preferred, "source_path": record["source"]["path"], "source_sha256": record["source"]["sha256"]})
        source = next(record["source"]["path"] for record in _registry_records(registry, model, "OFFICIAL_TEST_ALL_ROWS"))
        artifact, entry = _load_source(root, inventory, source)
        for metric, value in artifact["metrics"]["confusion_matrix"].items():
            rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": "OFFICIAL_TEST_ALL_ROWS", "model": model, "metric": metric, "value": value, "threshold": registry["models"][model]["threshold"], "implementation": "source-artifact-value", "positive_class": "ATTACK = 1", "score": "p_attack", "frozen_preference": preferred, "source_path": source, "source_sha256": entry["sha256"]})
    return fields, rows


def _table_chain_development(registry: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["dataset", "branch", "population", "model", "base_ap", "chain_ap", "delta_ap", "result", "threshold", "source_path", "source_sha256"]
    rows = []
    for model in ("CHAIN-S1", "CHAIN-S2"):
        pair = registry["comparisons"]["development"][model]
        rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": pair["population"], "model": model, "base_ap": pair["base_ap"], "chain_ap": pair["chain_ap"], "delta_ap": pair["delta_ap"], "result": pair["result"], "threshold": pair["threshold"], "source_path": pair["provenance"]["path"], "source_sha256": pair["provenance"]["sha256"]})
    return fields, rows


def _table_chain_test(root: Path, registry: dict[str, Any], inventory: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["dataset", "branch", "population", "evaluation_type", "model", "metric", "value", "base_ap", "chain_ap", "ap_delta", "interpretation", "source_path", "source_sha256"]
    rows: list[dict[str, Any]] = []
    for model in ("CHAIN-S1", "CHAIN-S2"):
        pair = registry["comparisons"]["locked_test"][model]
        for metric in ("average_precision", "roc_auc", "tp", "fp", "tn", "fn", "accuracy", "precision", "recall", "f1"):
            value = pair["metrics"].get(metric)
            if value is None and metric in ("tp", "fp", "tn", "fn"):
                value = pair["metrics"].get("confusion_matrix", {}).get(metric)
            if isinstance(value, dict):
                continue
            rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": pair["population"], "evaluation_type": pair["evaluation_type"], "model": model, "metric": "Average Precision (AP)" if metric == "average_precision" else metric, "value": value, "base_ap": pair["base_ap"], "chain_ap": pair["chain_ap"], "ap_delta": pair["ap_delta"], "interpretation": "LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION; TEST delta descriptive only.", "source_path": pair["provenance"]["path"], "source_sha256": pair["provenance"]["sha256"]})
    sensitivity, entry = _load_source(root, inventory, SENSITIVITY)
    for model in ("CHAIN-S1", "CHAIN-S2"):
        for side in ("baseline", "chain"):
            for metric, value in sensitivity["metrics"][model][side].items():
                if isinstance(value, dict):
                    continue
                rows.append({"dataset": "UNSW_NB15_BENCHMARK", "branch": "BRANCH_B", "population": "SENSITIVITY ANALYSIS ONLY", "evaluation_type": sensitivity["label"], "model": f"{model}/{side}", "metric": metric, "value": value, "base_ap": "", "chain_ap": "", "ap_delta": "", "interpretation": "Sensitivity analysis only; not primary TEST reporting or model selection.", "source_path": SENSITIVITY, "source_sha256": entry["sha256"]})
    return fields, rows


def _table_governance(registry: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    fields = ["category", "item", "value", "scope_or_source"]
    leakage = registry["leakage"]
    fit = leakage["fit_accounting"]
    gov = registry["governance"]
    rows = [
        {"category": "leakage", "item": "TRAIN SIGNAL POLICY", "value": "OOF / CROSS-FITTED", "scope_or_source": "Stage 2.4 handoff"},
        {"category": "leakage", "item": "SAME-ROW FIT/SIGNAL OVERLAP", "value": leakage["same_row_fit_signal_overlap"], "scope_or_source": "Stage 2.4B audit"},
        {"category": "leakage", "item": "SAME-GROUP FIT/SIGNAL OVERLAP", "value": leakage["same_group_fit_signal_overlap"], "scope_or_source": "Stage 2.4B audit"},
        {"category": "leakage", "item": "FIT ACCOUNTING", "value": fit["total_accounted"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "FRESH_EXECUTED", "value": fit["fresh_executed"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "VALIDATED_REUSED", "value": fit["validated_reused"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "NOT_REQUIRED_BY_DEDUPLICATION", "value": fit["not_required_by_deduplication"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "UNRESOLVED", "value": fit["unresolved"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "SIGNAL COVERAGE", "value": fit["signal_coverage"], "scope_or_source": "Stage 2.4B"},
        {"category": "leakage", "item": "FALLBACK / IMPUTED SIGNALS", "value": fit["fallback_or_imputed_signals"], "scope_or_source": "Stage 2.4B"},
        {"category": "governance", "item": "SELECTION LOCK", "value": "VERIFIED" if gov["selection_lock_verified"] else "FAIL", "scope_or_source": "Stage 2.4D"},
        {"category": "governance", "item": "HUMAN TEST AUTHORIZATION", "value": "VERIFIED" if gov["human_test_authorization_verified"] else "FAIL", "scope_or_source": "Stage 2.4E"},
        {"category": "governance", "item": "TEST CONTRIBUTION TO FITTED STATE", "value": gov["test_contributed_fitted_state"], "scope_or_source": "Stage 2.4E"},
        {"category": "governance", "item": "POST-TEST TUNING", "value": "NONE" if gov["no_post_test_tuning"] else "FAIL", "scope_or_source": "Stage 2.4E"},
        {"category": "governance", "item": "TEST NEWLY UNSEEN AT PROJECT LEVEL", "value": "NO" if gov["test_not_newly_unseen_at_overall_project_level"] else "FAIL", "scope_or_source": "Stage 2.4 governance"},
        {"category": "governance", "item": "NO STATISTICAL SIGNIFICANCE CLAIM", "value": "YES" if registry["claim_limits"]["no_statistical_significance_claim"] else "FAIL", "scope_or_source": "Claims contract"},
    ]
    return fields, rows


def _architecture() -> str:
    return """flowchart TD
    I[INPUT PROJECT] --> A
    I --> B
    subgraph A[BRANCH A — FortiGate real sanitized logs]
      A1[REAL-LOG UNSUPERVISED / ANOMALY ANALYSIS]
      A2[anomaly scoring / prioritization / explainability]
      A3[real-log case study]
      A1 --> A2 --> A3
    end
    subgraph B[BRANCH B — UNSW-NB15 benchmark]
      B1[LABELED BENCHMARK QUANTITATIVE EVALUATION]
      B2[U1 / U2 benchmark]
      B3[BASE S1 / S2]
      B4[CHAIN-S1 / CHAIN-S2]
      B1 --> B2
      B1 --> B3
      B1 --> B4
    end
    N[DATASETS MERGED: NO]
    A -.-> N
    B -.-> N
"""


def _render_ap_deltas(registry: dict[str, Any], path: Path) -> None:
    development = registry["comparisons"]["development"]
    locked = registry["comparisons"]["locked_test"]
    labels = ["S1", "S2"]
    values = [[development["CHAIN-S1"]["delta_ap"], development["CHAIN-S2"]["delta_ap"]], [locked["CHAIN-S1"]["ap_delta"], locked["CHAIN-S2"]["ap_delta"]]]
    max_abs = max(abs(value) for panel in values for value in panel)
    limit = 1.1 * max_abs if max_abs else 1e-6
    fig, axes = plt.subplots(2, 1, figsize=(8, 6), sharex=True)
    for axis, title, panel in zip(axes, ("DEVELOPMENT — BASE vs CHAIN AP delta", "LOCKED TEST REPORTING — descriptive AP delta"), values):
        colors = ["#2c7fb8" if value >= 0 else "#d95f0e" for value in panel]
        bars = axis.bar(labels, panel, color=colors, width=0.55)
        axis.axhline(0, color="black", linewidth=0.9)
        axis.set_ylim(-limit, limit)
        axis.set_ylabel("AP delta")
        axis.set_title(title)
        axis.grid(axis="y", alpha=0.25)
        for bar, value in zip(bars, panel):
            axis.annotate(f"{value:+.18f}", (bar.get_x() + bar.get_width() / 2, value), xytext=(0, 5 if value >= 0 else -15), textcoords="offset points", ha="center", fontsize=8)
    axes[-1].set_xlabel("Model pair")
    fig.suptitle("UNSW-NB15 BASE vs CHAIN Average Precision\nTEST deltas are descriptive only")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(path, dpi=150, metadata={"Software": "Stage 2.5B frozen renderer", "Creation Time": None})
    plt.close(fig)


def _render_confusion_matrices(registry: dict[str, Any], path: Path) -> None:
    matrices = registry["confusion_matrices"]
    order = ("UNSW-U1", "UNSW-U2", "BASE-S1", "BASE-S2", "CHAIN-S1", "CHAIN-S2")
    vmax = max(max(max(row) for row in matrices[name]["matrix"]) for name in order)
    fig, axes = plt.subplots(2, 3, figsize=(13, 8), constrained_layout=True)
    image = None
    for axis, name in zip(axes.flat, order):
        item = matrices[name]
        image = axis.imshow(item["matrix"], cmap="Blues", vmin=0, vmax=vmax)
        axis.set_title(f"{name}\n{item['population']}")
        axis.set_xticks(range(2), item["axes"]["predicted"])
        axis.set_yticks(range(2), item["axes"]["true"])
        axis.set_xlabel("Predicted")
        axis.set_ylabel("True")
        for row in range(2):
            for column in range(2):
                axis.text(column, row, f"{item['matrix'][row][column]:,}", ha="center", va="center", color="white" if item["matrix"][row][column] > vmax * 0.55 else "black", fontsize=9)
    fig.colorbar(image, ax=axes.ravel().tolist(), shrink=0.8, label="Count")
    fig.suptitle("UNSW-NB15 official TEST confusion matrices\nU1/U2 anomaly labels are not ATTACK labels")
    fig.savefig(path, dpi=150, metadata={"Software": "Stage 2.5B frozen renderer", "Creation Time": None})
    plt.close(fig)


def _png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        if handle.read(8) != b"\x89PNG\r\n\x1a\n":
            raise ValueError(f"not a PNG: {path}")
        length = struct.unpack(">I", handle.read(4))[0]
        chunk = handle.read(4)
        if chunk != b"IHDR" or length < 8:
            raise ValueError(f"invalid PNG header: {path}")
        width, height = struct.unpack(">II", handle.read(8))
    return width, height


def build_package(registry_path: Path, output_dir: Path) -> dict[str, Any]:
    registry_path = Path(registry_path)
    root, registry, inventory = _registry_context(registry_path)
    output_dir = Path(output_dir)
    tables_dir = output_dir / "tables"
    figures_dir = output_dir / "figures"
    if tables_dir.exists() and any(tables_dir.iterdir()):
        raise ValueError(f"table output directory must be fresh: {tables_dir}")
    if figures_dir.exists() and any(figures_dir.iterdir()):
        raise ValueError(f"figure output directory must be fresh: {figures_dir}")
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    for name in ("final_result_registry.json", "source_inventory.json", "claims_matrix.json"):
        source = registry_path.parent / name
        destination = output_dir / name
        if not destination.exists():
            shutil.copyfile(source, destination)
        elif _sha256(destination) != _sha256(source):
            raise ValueError(f"Stage 2.5A artifact mismatch in output root: {name}")

    table_builders = [
        _table_dataset_roles,
        _table_models,
        lambda r: _table_unsupervised(root, r, inventory)[:2],
        lambda r: _table_base_supervised(r, root, inventory),
        _table_chain_development,
        lambda r: _table_chain_test(root, r, inventory),
        _table_governance,
    ]
    for name, builder in zip(TABLE_NAMES, table_builders):
        fields, rows = builder(registry)
        _write_csv(tables_dir / name, fields, rows)

    (figures_dir / "01_two_branch_architecture.mmd").write_text(_architecture(), encoding="utf-8")
    historical = root / FORTIGATE_FIGURE
    if not historical.is_file():
        raise ValueError(f"authoritative FortiGate figure missing: {FORTIGATE_FIGURE}")
    shutil.copyfile(historical, figures_dir / "02_fortigate_score_distribution.png")
    _render_ap_deltas(registry, figures_dir / "03_paired_ap_deltas.png")
    _render_confusion_matrices(registry, figures_dir / "04_confusion_matrices.png")

    code_path = root / "src/reporting/tables_figures.py"
    provenance = {
        "schema_version": "stage_2.5B-provenance/1.0",
        "stage": "2.5B",
        "registry": {"path": "docs/results/stage_2_5/final_result_registry.json", "sha256": _sha256(Path(registry_path))},
        "source_inventory_sha256": registry["source_inventory_sha256"],
        "generation_code": {"path": "src/reporting/tables_figures.py", "sha256": _sha256(code_path)},
        "rendering": {"backend": "Agg", "dpi": 150, "font": "matplotlib default sans-serif", "timestamp_metadata": "excluded"},
        "sources": {"fortigate_figure": _source_ref(root, inventory, FORTIGATE_FIGURE), "fortigate_analysis_summary": _source_ref(root, inventory, "data/processed/stage_2_0_v5/analysis_summary.json"), "fortigate_comparison": _source_ref(root, inventory, FORTIGATE_COMPARISON), "sensitivity_analysis": _source_ref(root, inventory, SENSITIVITY)},
        "fortigate_figure_context": {"score_identity": "historical Stage 2.0 relative anomaly score distribution; not an attack probability", "u1_model": registry["models"]["FORTIGATE-U1"], "u2_model": registry["models"]["FORTIGATE-U2"]},
        "outputs": {
            "tables": {
                name: {"path": f"tables/{name}", "sha256": _sha256(tables_dir / name), "source_sections": sections}
                for name, sections in {
                    "01_dataset_roles.csv": ["branches", "datasets", "datasets_merged"],
                    "02_models.csv": ["models"],
                    "03_unsupervised_results.csv": ["metrics.records", "FortiGate comparison artifact"],
                    "04_base_supervised_results.csv": ["metrics.records", "comparisons.development"],
                    "05_chain_development.csv": ["comparisons.development"],
                    "06_chain_locked_test.csv": ["comparisons.locked_test", "sensitivity analysis artifact"],
                    "07_leakage_governance.csv": ["leakage", "governance", "claim_limits"],
                }.items()
            },
            "figures": {
                name: {"path": f"figures/{name}", "sha256": _sha256(figures_dir / name), "source_sections": sections}
                for name, sections in {
                    "01_two_branch_architecture.mmd": ["branches", "models", "datasets_merged"],
                    "02_fortigate_score_distribution.png": ["historical FortiGate figure source"],
                    "03_paired_ap_deltas.png": ["comparisons.development", "comparisons.locked_test"],
                    "04_confusion_matrices.png": ["confusion_matrices"],
                }.items()
            },
        },
    }
    (output_dir / PROVENANCE_NAME).write_bytes(_canonical(provenance))
    return validate_package(output_dir)


def validate_package(output_dir: Path) -> dict[str, Any]:
    output_dir = Path(output_dir)
    tables_dir = output_dir / "tables"
    figures_dir = output_dir / "figures"
    if {path.name for path in tables_dir.iterdir()} != set(TABLE_NAMES):
        raise ValueError("Stage 2.5B table set mismatch")
    if {path.name for path in figures_dir.iterdir()} != set(FIGURE_NAMES):
        raise ValueError("Stage 2.5B figure set mismatch")
    provenance_path = output_dir / PROVENANCE_NAME
    if not provenance_path.is_file():
        raise ValueError("Stage 2.5B provenance manifest missing")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("schema_version") != "stage_2.5B-provenance/1.0":
        raise ValueError("Stage 2.5B provenance schema mismatch")
    registry_path = output_dir / "final_result_registry.json"
    if not registry_path.is_file():
        raise ValueError("Stage 2.5A registry missing beside Stage 2.5B outputs")
    if provenance["registry"]["sha256"] != _sha256(registry_path):
        raise ValueError("Stage 2.5B registry hash mismatch")
    for name in TABLE_NAMES:
        if not (tables_dir / name).read_text(encoding="utf-8").strip():
            raise ValueError(f"empty table: {name}")
        if provenance["outputs"]["tables"][name]["sha256"] != _sha256(tables_dir / name):
            raise ValueError(f"table provenance mismatch: {name}")
    for name in FIGURE_NAMES:
        if provenance["outputs"]["figures"][name]["sha256"] != _sha256(figures_dir / name):
            raise ValueError(f"figure provenance mismatch: {name}")
    architecture = (figures_dir / "01_two_branch_architecture.mmd").read_text(encoding="utf-8")
    if "DATASETS MERGED: NO" not in architecture or "FortiGate" not in architecture or "UNSW-NB15" not in architecture:
        raise ValueError("architecture branch separation missing")
    if "confirmed attack" in architecture.lower():
        raise ValueError("unsupported architecture claim")
    if _sha256(figures_dir / "02_fortigate_score_distribution.png") != provenance["sources"]["fortigate_figure"]["sha256"]:
        raise ValueError("historical FortiGate figure was not copied byte-for-byte")
    width, height = _png_dimensions(figures_dir / "02_fortigate_score_distribution.png")
    if width <= 0 or height <= 0:
        raise ValueError("invalid FortiGate figure dimensions")
    for name in ("03_paired_ap_deltas.png", "04_confusion_matrices.png"):
        width, height = _png_dimensions(figures_dir / name)
        if width <= 0 or height <= 0:
            raise ValueError(f"invalid generated figure dimensions: {name}")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    expected_rows = registry["datasets"]["UNSW_NB15_BENCHMARK"]["official_test_rows"]
    if any(sum(sum(row) for row in item["matrix"]) != expected_rows for item in registry["confusion_matrices"].values()):
        raise ValueError("confusion matrix total mismatch")
    return {"status": "PASS", "tables": len(TABLE_NAMES), "figures": len(FIGURE_NAMES), "registry_schema": registry["schema_version"]}
