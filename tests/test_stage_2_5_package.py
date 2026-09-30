from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from reporting.final_results import (
    collect_frozen_results,
    validate_package,
)
from build_stage_2_5_package import build_package


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_registry_binds_frozen_branches_models_metrics_and_governance(tmp_path: Path) -> None:
    build_package(HANDOFF, tmp_path / "package")
    registry = json.loads((tmp_path / "package/final_result_registry.json").read_text())

    assert registry["schema_version"] == "stage_2.5-results/1.0"
    assert registry["source_inventory_sha256"]
    assert registry["datasets_merged"] is False
    assert registry["branches"]["BRANCH_A"]["role"] == "REAL-LOG UNSUPERVISED / ANOMALY ANALYSIS"
    assert registry["branches"]["BRANCH_B"]["role"] == (
        "LABELED BENCHMARK FOR SUPERVISED AND CHAINED QUANTITATIVE EVALUATION"
    )
    assert set(registry["models"]) >= {"U1", "U2", "BASE-S1", "BASE-S2", "CHAIN-S1", "CHAIN-S2"}
    assert registry["metrics"]["stage_2_2_unsupervised"]["display_name"] == "Stage 2.2 PR_AUC_AP"
    assert registry["metrics"]["stage_2_2_unsupervised"]["source_key"] == "metrics.pr_auc_ap"
    assert registry["governance"]["test_contributed_fitted_state"] == "NONE"
    assert registry["governance"]["prior_test_visibility_limitation"]
    assert registry["governance"]["no_post_test_tuning"] is True


def test_registry_preserves_exact_frozen_results_and_leakage_accounting(tmp_path: Path) -> None:
    build_package(HANDOFF, tmp_path / "package")
    registry = json.loads((tmp_path / "package/final_result_registry.json").read_text())

    assert registry["comparisons"]["development"]["CHAIN-S1"]["chain_ap"] == 0.9941359114288555
    assert registry["comparisons"]["development"]["CHAIN-S2"]["chain_ap"] == 0.9968208117560664
    assert registry["comparisons"]["locked_test"]["CHAIN-S1"]["ap_delta"] == 0.0009108507889732387
    assert registry["comparisons"]["locked_test"]["CHAIN-S2"]["ap_delta"] == -0.00031530373781274434
    assert registry["leakage"]["fit_accounting"] == {
        "planned_fit_ids": 28,
        "fresh_executed": 20,
        "validated_reused": 0,
        "not_required_by_deduplication": 8,
        "unresolved": 0,
        "total_accounted": "28/28",
        "signal_coverage": "140273/140273",
        "fallback_or_imputed_signals": 0,
        "same_row_fit_signal_overlap": 0,
        "same_group_fit_signal_overlap": 0,
    }
    assert registry["comparisons"]["locked_test"]["CHAIN-S1"]["metrics"]["row_count"] == 82332


def test_registry_generation_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_package(HANDOFF, first)
    build_package(HANDOFF, second)
    for name in ("final_result_registry.json", "source_inventory.json", "claims_matrix.json"):
        assert _sha256(first / name) == _sha256(second / name)


def test_changed_handoff_hash_fails_closed(tmp_path: Path) -> None:
    handoff_copy = tmp_path / "handoff.json"
    payload = json.loads(HANDOFF.read_text())
    payload["status"] = "TAMPERED"
    handoff_copy.write_text(json.dumps(payload, sort_keys=True))
    with pytest.raises(ValueError, match="handoff"):
        collect_frozen_results(handoff_copy)


def test_validate_package_requires_stage_2_5_outputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="final_result_registry"):
        validate_package(tmp_path)
