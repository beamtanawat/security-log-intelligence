from __future__ import annotations

import pytest

from run_chained_test_evaluation import validate_authorization_boundary


def _auth() -> dict[str, object]:
    return {
        "schema_version": "stage_2.4-final-evaluator-authorization/1.0",
        "dataset_id": "UNSW-NB15",
        "artifact_dataset_id": "UNSW_NB15_BENCHMARK",
        "branch_id": "BRANCH_B_LABELED_BENCHMARK",
        "stage": "2.4E",
        "authorization_type": "PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION",
        "human_authorized": True,
        "selection_lock_sha256": "lock-hash",
        "chain_contract_sha256": "chain-hash",
        "crossfit_contract_sha256": "crossfit-hash",
        "chain_thresholds": {"CHAIN-S1": 0.5, "CHAIN-S2": 0.5},
        "test_role": "FINAL_EVALUATION_ONLY",
        "post_test_tuning_allowed": False,
        "evaluator_boundary_version": "S2.4-PUBLIC-FINAL-EVALUATOR-V1",
        "authorized_at_utc": "2026-09-30T10:01:47Z",
        "human_approval_reference": "human approval",
        "human_approval_sha256": "approval-hash",
        "prior_test_results_used_for_development": False,
        "test_used_for_development": False,
    }


def _lock() -> dict[str, object]:
    return {
        "status": "PASS",
        "dataset_id": "UNSW_NB15_BENCHMARK",
        "branch_id": "BRANCH_B_LABELED_BENCHMARK",
        "checkpoint": "2.4D",
        "test_used": False,
        "test_role": "LOCKED_FROM_DEVELOPMENT",
        "no_post_test_tuning": True,
        "chain_features": {"source_feature_count": 30},
        "threshold_policy": {"CHAIN-S1": 0.5, "CHAIN-S2": 0.5, "post_test_tuning_allowed": False},
        "crossfit": {"contract_sha256": "crossfit-hash"},
    }


def test_boundary_accepts_matching_authorization() -> None:
    result = validate_authorization_boundary(_lock(), _auth(), "lock-hash")
    assert result["status"] == "PASS"


@pytest.mark.parametrize(
    "field,value",
    [("human_authorized", False), ("selection_lock_sha256", "wrong"), ("post_test_tuning_allowed", True)],
)
def test_boundary_rejects_invalid_authorization(field: str, value: object) -> None:
    auth = _auth()
    auth[field] = value
    with pytest.raises(ValueError):
        validate_authorization_boundary(_lock(), auth, "lock-hash")


def test_boundary_rejects_placeholder() -> None:
    auth = _auth()
    auth["human_approval_reference"] = "<HUMAN_FILL>"
    with pytest.raises(ValueError):
        validate_authorization_boundary(_lock(), auth, "lock-hash")
