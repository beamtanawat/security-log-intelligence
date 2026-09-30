from __future__ import annotations

import copy

import pytest

from chained.contracts import (
    BASE_FEATURES,
    CHAIN_SOURCE_FEATURES,
    CHAIN_S1_CONFIG,
    CHAIN_S2_CONFIG,
    EXPECTED_FIT_ATTEMPTS,
    U1_CONFIG,
    U2_CONFIG,
    audit_signal_records,
    build_chain_contract,
    build_contexts,
    compare_pair,
    validate_cache_lineage,
    validate_nested_contexts,
    validate_preprocessing_boundaries,
    validate_upstream_artifacts,
)


def _folds() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(12):
        outer = index % 3
        rows.append(
            {
                "dataset_id": "UNSW_NB15_BENCHMARK",
                "branch_id": "BRANCH_B_LABELED_BENCHMARK",
                "row_key": f"r{index}",
                "group_id": f"g{index}",
                "upstream_split": "TRAIN_INTERNAL",
                "outer_fold": outer,
                "inner_fold_by_outer": {
                    str(context): (index // 3) % 2
                    for context in range(3)
                    if context != outer
                },
            }
        )
    return rows


def test_chain_contract_has_exact_continuous_source_features_and_frozen_models() -> None:
    contract = build_chain_contract()
    assert len(BASE_FEATURES) == 28
    assert contract["source_feature_count"] == 30
    assert tuple(contract["source_features"]) == CHAIN_SOURCE_FEATURES
    assert contract["signals"]["U1"]["binary_decision_included"] is False
    assert contract["signals"]["U2"]["binary_decision_included"] is False
    assert contract["models"]["CHAIN-S1"] == CHAIN_S1_CONFIG
    assert contract["models"]["CHAIN-S2"] == CHAIN_S2_CONFIG
    assert contract["fit_budget"]["expected_total_fit_attempts"] == EXPECTED_FIT_ATTEMPTS == 28
    assert U1_CONFIG["n_estimators"] == 200
    assert U2_CONFIG["n_clusters"] == 32
    assert "label" not in contract["source_features"]
    assert "attack_cat" not in contract["source_features"]


def test_contexts_preserve_groups_and_nested_fit_exclusions() -> None:
    contexts = build_contexts(_folds())
    assert len(contexts) == 10
    assert {item["kind"] for item in contexts} == {"INNER_SIGNAL", "OUTER_INFERENCE", "FINAL_INFERENCE"}
    assert validate_nested_contexts(contexts) is True
    for item in contexts:
        assert set(item["fit_group_ids"]).isdisjoint(item["score_group_ids"])
        if item["kind"] == "INNER_SIGNAL":
            assert set(item["excluded_outer_group_ids"]).isdisjoint(item["fit_group_ids"])


def test_same_group_fit_signal_overlap_fails_closed() -> None:
    contexts = build_contexts(_folds())
    context = next(item for item in contexts if item["kind"] == "INNER_SIGNAL")
    record = {
        "row_key": context["score_row_keys"][0],
        "group_id": context["score_group_ids"][0],
        "context_id": context["context_id"],
        "fit_group_ids": list(context["fit_group_ids"]),
        "score": 1.0,
        "score_direction": "HIGHER_MORE_ANOMALOUS",
    }
    bad = copy.deepcopy(record)
    bad["fit_group_ids"] = list(record["fit_group_ids"]) + [record["group_id"]]
    with pytest.raises(ValueError, match="group overlap"):
        audit_signal_records([bad], context)


def test_same_row_overlap_and_incomplete_coverage_fail_closed() -> None:
    contexts = build_contexts(_folds())
    context = next(item for item in contexts if item["kind"] == "INNER_SIGNAL")
    record = {
        "row_key": context["score_row_keys"][0],
        "group_id": context["score_group_ids"][0],
        "context_id": context["context_id"],
        "fit_row_keys": list(context["fit_row_keys"]),
        "fit_group_ids": list(context["fit_group_ids"]),
        "score": 1.0,
        "score_direction": "HIGHER_MORE_ANOMALOUS",
    }
    bad = copy.deepcopy(record)
    bad["fit_row_keys"] = list(record["fit_row_keys"]) + [record["row_key"]]
    with pytest.raises(ValueError, match="row overlap"):
        audit_signal_records([bad], context)
    with pytest.raises(ValueError, match="coverage"):
        audit_signal_records([], context)


def test_nested_contract_rejects_global_oof_training_signal_context() -> None:
    contexts = build_contexts(_folds())
    context = next(item for item in contexts if item["kind"] == "INNER_SIGNAL")
    bad = copy.deepcopy(context)
    bad["fit_group_ids"] = list(bad["fit_group_ids"]) + list(bad["excluded_outer_group_ids"])
    with pytest.raises(ValueError, match="outer held-out"):
        validate_nested_contexts([bad] + [item for item in contexts if item is not context])


def test_preprocessing_boundaries_and_cache_lineage_are_fail_closed() -> None:
    assert validate_preprocessing_boundaries(
        {
            "base": "AUTHORIZED_TRAINING_ROWS",
            "u1": "AUTHORIZED_U_FIT_ROWS",
            "u2": "AUTHORIZED_U_FIT_ROWS",
            "signal_scaling": "OOF_SIGNAL_TRAINING_ROWS_ONLY",
            "supervised": "AUTHORIZED_SUPERVISED_TRAINING_ROWS",
            "test_fit": False,
        }
    ) is True
    with pytest.raises(ValueError, match="TEST"):
        validate_preprocessing_boundaries({"base": "TEST", "test_fit": True})
    identity = {"dataset_id": "UNSW_NB15_BENCHMARK", "context_id": "x", "fit_membership_sha256": "a"}
    assert validate_cache_lineage(identity, identity) is True
    with pytest.raises(ValueError, match="lineage"):
        validate_cache_lineage(identity, {**identity, "fit_membership_sha256": "b"})


def test_upstream_artifact_validation_rejects_test_and_fortigate() -> None:
    artifacts = {
        "dataset_id": "UNSW_NB15_BENCHMARK",
        "branch_id": "BRANCH_B_LABELED_BENCHMARK",
        "test_policy": "LOCKED_NO_TEST_ACCESS_IN_DEVELOPMENT",
        "fold_manifest_sha256": "folds",
        "selection_lock_sha256": "lock",
        "baseline_preferred_model": "S2",
        "chained_signals_used": False,
    }
    assert validate_upstream_artifacts(artifacts) is True
    with pytest.raises(ValueError, match="TEST"):
        validate_upstream_artifacts({**artifacts, "test_policy": "TEST_READ"})
    with pytest.raises(ValueError, match="FortiGate"):
        validate_upstream_artifacts({**artifacts, "dataset_id": "FORTIGATE"})


def test_ap_comparison_uses_average_precision_and_one_e_6_tie_rule() -> None:
    result = compare_pair([0, 1, 1], [0.1, 0.8, 0.7], [0.1, 0.8, 0.7000005])
    assert result["metric"] == "AVERAGE_PRECISION"
    assert result["decision"] == "TIE"
    assert result["primary"] == "AP"
