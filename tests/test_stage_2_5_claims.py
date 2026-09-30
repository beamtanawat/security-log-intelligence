from __future__ import annotations

import json
from pathlib import Path

from build_stage_2_5_package import build_package


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json"


def test_claims_contract_contains_required_supported_and_forbidden_language(tmp_path: Path) -> None:
    build_package(HANDOFF, tmp_path / "package")
    claims = json.loads((tmp_path / "package/claims_matrix.json").read_text())
    supported = {entry["id"]: entry for entry in claims["supported"]}
    forbidden = {entry["id"]: entry for entry in claims["unsupported_or_forbidden"]}

    assert "fortigate_anomaly_review" in supported
    assert "unsw_quantitative_supervised_evaluation" in supported
    assert "chain_s1_development_increase" in supported
    assert "chain_s2_development_decrease" in supported
    assert "anomaly_equals_attack" in forbidden
    assert "unsw_equals_fortigate_production" in forbidden
    assert "test_newly_unseen_project_level" in forbidden
    required_tokens = {
        "ANOMALY != ATTACK",
        "ANOMALY SCORE != ATTACK PROBABILITY",
        "RULE MATCH != CONFIRMED ATTACK",
        "HIGH_INTEREST != CONFIRMED ATTACK",
        "LOW_INTEREST != CONFIRMED BENIGN",
        "SOURCE THREAT OBSERVATION != GROUND TRUTH",
        "ABSENCE OF ALERT != BENIGN",
        "NO STATISTICAL SIGNIFICANCE CLAIM",
    }
    assert required_tokens.issubset(set(claims["language_tokens"]))
    for entry in (*claims["supported"], *claims["unsupported_or_forbidden"]):
        assert entry["evidence"]
        assert entry["scope"]
        assert entry["qualification"]


def test_registry_builder_has_no_model_execution_hooks() -> None:
    source = (ROOT / "src/reporting/final_results.py").read_text()
    assert ".fit(" not in source
    assert ".predict(" not in source
    assert ".score_samples(" not in source
