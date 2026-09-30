from __future__ import annotations

import hashlib
import json
from pathlib import Path

from build_stage_2_5_tables_figures import build_package, validate_package


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs/results/stage_2_5/final_result_registry.json"
TABLE_NAMES = {
    "01_dataset_roles.csv",
    "02_models.csv",
    "03_unsupervised_results.csv",
    "04_base_supervised_results.csv",
    "05_chain_development.csv",
    "06_chain_locked_test.csv",
    "07_leakage_governance.csv",
}
FIGURE_NAMES = {
    "01_two_branch_architecture.mmd",
    "02_fortigate_score_distribution.png",
    "03_paired_ap_deltas.png",
    "04_confusion_matrices.png",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_builds_exact_final_tables_and_figures(tmp_path: Path) -> None:
    build_package(REGISTRY, tmp_path / "package")
    assert {p.name for p in (tmp_path / "package/tables").iterdir()} == TABLE_NAMES
    assert {p.name for p in (tmp_path / "package/figures").iterdir()} == FIGURE_NAMES
    assert validate_package(tmp_path / "package")["status"] == "PASS"


def test_tables_preserve_registry_values_and_metric_terminology(tmp_path: Path) -> None:
    build_package(REGISTRY, tmp_path / "package")
    package = tmp_path / "package"
    assert "Stage 2.2 PR_AUC_AP" in (package / "tables/03_unsupervised_results.csv").read_text()
    development = (package / "tables/05_chain_development.csv").read_text()
    assert "0.00021276179167273312" in development
    assert "-0.00004298499608823558" in development
    locked_test = (package / "tables/06_chain_locked_test.csv").read_text()
    assert "0.0009108507889732387" in locked_test
    assert "-0.00031530373781274434" in locked_test


def test_figures_are_claim_safe_and_confusion_matrices_reconcile(tmp_path: Path) -> None:
    build_package(REGISTRY, tmp_path / "package")
    package = tmp_path / "package"
    architecture = (package / "figures/01_two_branch_architecture.mmd").read_text()
    assert "DATASETS MERGED: NO" in architecture
    assert "FortiGate" in architecture and "UNSW-NB15" in architecture
    assert "confirmed attack" not in architecture.lower()
    registry = json.loads(REGISTRY.read_text())
    figure_data = registry["confusion_matrices"]
    assert len(figure_data) == 6
    assert all(sum(sum(row) for row in item["matrix"]) == 82332 for item in figure_data.values())


def test_generation_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_package(REGISTRY, first)
    build_package(REGISTRY, second)
    for relative in [*(f"tables/{name}" for name in TABLE_NAMES), *(f"figures/{name}" for name in FIGURE_NAMES), "stage_2_5B_provenance.json"]:
        assert _sha256(first / relative) == _sha256(second / relative)


def test_builder_source_has_no_model_or_prediction_execution() -> None:
    source = (ROOT / "src/reporting/tables_figures.py").read_text()
    assert ".fit(" not in source
    assert ".predict(" not in source
    assert ".score_samples(" not in source
    assert "read_csv" not in source
