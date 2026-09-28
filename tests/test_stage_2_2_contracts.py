from __future__ import annotations

import math

import numpy as np
import pytest

from unsupervised.contracts import (
    BRANCH_ID,
    DATASET_ID,
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    build_feature_contract,
    validate_input_identities,
)
from unsupervised.features import FeatureContractError, fit_features, transform_features
from unsupervised.splits import SplitBlocker, build_split_manifest, row_key


def _row(number: int, *, category: str = "tcp", state: str = "CON", value: str = "1", split: str = "TRAIN") -> dict[str, object]:
    row: dict[str, object] = {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "official_split": split,
        "development_partition": "TRAIN_INTERNAL",
        "row_number": number,
        "id": str(number),
        "label": "0",
        "attack_cat": "Normal",
        "proto": category,
        "service": "-",
        "state": state,
    }
    for field in NUMERIC_FEATURES:
        row[field] = value
    row["sbytes"] = str(number)
    return row


def test_feature_contract_has_exact_unsw_order_and_exclusions() -> None:
    contract = build_feature_contract()
    assert contract["numeric_features"] == list(NUMERIC_FEATURES)
    assert contract["categorical_features"] == list(CATEGORICAL_FEATURES)
    assert contract["feature_order"] == list(NUMERIC_FEATURES) + list(CATEGORICAL_FEATURES)
    assert {"id", "label", "attack_cat", "stcpb", "dtcpb"}.issubset(contract["excluded_fields"])
    assert "ct_state_ttl" in contract["excluded_fields"]
    assert "label" not in contract["feature_order"]
    assert "attack_cat" not in contract["feature_order"]


def test_row_key_and_split_replay_are_deterministic() -> None:
    rows = [_row(i, value=str(i)) for i in range(1, 4001)]
    first = build_split_manifest(rows, DATASET_ID)
    second = build_split_manifest(rows, DATASET_ID)
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.rows == second.rows
    assert row_key(DATASET_ID, "TRAIN", 1) == '["UNSW_NB15_BENCHMARK","TRAIN",1]'
    assert {entry["partition"] for entry in first.rows} <= {
        "TRAIN_INTERNAL",
        "VALIDATION_CALIBRATION",
        "VALIDATION_COMPARISON",
    }


def test_duplicate_group_cannot_cross_partitions_or_exceed_size_gate() -> None:
    rows = [_row(i) for i in range(1, 7)]
    for row in rows:
        row["sbytes"] = "1"
    with pytest.raises(SplitBlocker, match="20%"):
        build_split_manifest(rows, DATASET_ID)


def test_conflicting_predictive_targets_are_preserved_in_one_partition() -> None:
    rows = [_row(i, value=str(i)) for i in range(1, 4001)]
    for field in (*NUMERIC_FEATURES, *CATEGORICAL_FEATURES):
        rows[1][field] = rows[0][field]
    rows[1]["label"] = "1"
    manifest = build_split_manifest(rows, DATASET_ID)
    assert manifest.report["target_conflict_check"] == "PASS"
    assert manifest.report["target_conflict_groups"] == 1
    assert manifest.report["target_conflict_rows"] == 2
    assert manifest.report["target_conflict_normal"] == 1
    assert manifest.report["target_conflict_attack"] == 1
    conflict_rows = [entry for entry in manifest.rows if entry["row_number"] in {1, 2}]
    assert len({entry["partition"] for entry in conflict_rows}) == 1
    assert len(manifest.rows) == len(rows)


def test_split_membership_is_label_blind() -> None:
    rows = [_row(i, value=str(i)) for i in range(1, 4001)]
    first = build_split_manifest(rows, DATASET_ID)
    relabeled = [dict(row) for row in rows]
    for row in relabeled:
        row["label"] = "1" if row["label"] == "0" else "0"
    second = build_split_manifest(relabeled, DATASET_ID)
    assert first.manifest_sha256 == second.manifest_sha256
    assert [entry["partition"] for entry in first.rows] == [entry["partition"] for entry in second.rows]


def test_input_identity_rejects_test_and_cross_branch_rows() -> None:
    validate_input_identities([_row(1)], DATASET_ID, BRANCH_ID)
    test_row = _row(1, split="TEST")
    with pytest.raises(ValueError, match="TEST"):
        validate_input_identities([test_row], DATASET_ID, BRANCH_ID)
    wrong_branch = _row(1)
    wrong_branch["branch_id"] = "FORTIGATE_REAL_LOG"
    with pytest.raises(ValueError, match="branch"):
        validate_input_identities([wrong_branch], DATASET_ID, BRANCH_ID)


def test_features_fit_only_train_internal_and_transform_unknown_categories_without_state_mutation() -> None:
    train = [_row(1, category="tcp", state="CON"), _row(2, category="udp", state="FIN")]
    state = fit_features(train, DATASET_ID)
    before = state.state_sha256
    holdout = [_row(3, category="new-proto", state="NEW")]
    transformed = transform_features(holdout, state)
    assert transformed.shape[0] == 1
    assert transformed.shape[1] == len(state.output_feature_names)
    assert np.isfinite(transformed).all()
    assert state.state_sha256 == before


def test_feature_fit_requires_explicit_train_internal_boundary() -> None:
    row = _row(1)
    row.pop("development_partition")
    with pytest.raises(FeatureContractError, match="TRAIN_INTERNAL"):
        fit_features([row], DATASET_ID)


def test_all_missing_and_constant_numeric_values_are_finite_and_deterministic() -> None:
    first = _row(1, value="")
    second = _row(2, value="")
    first["sbytes"] = "4"
    second["sbytes"] = "4"
    state = fit_features([first, second], DATASET_ID)
    transformed = transform_features([first, second], state)
    assert np.isfinite(transformed).all()
    assert math.isclose(state.numeric_scales["sbytes"], 1.0)
    assert state.output_feature_names == tuple(state.output_feature_names)


@pytest.mark.parametrize("bad_value", ["-1", "NaN", "inf", "not-a-number"])
def test_invalid_numeric_values_are_rejected(bad_value: str) -> None:
    row = _row(1)
    row["sbytes"] = bad_value
    with pytest.raises(FeatureContractError, match="sbytes"):
        fit_features([row], DATASET_ID)


def test_test_labels_cannot_enter_feature_fit_or_transform() -> None:
    row = _row(1, split="TEST")
    with pytest.raises(FeatureContractError, match="TEST"):
        fit_features([row], DATASET_ID)
    train_state = fit_features([_row(1)], DATASET_ID)
    with pytest.raises(FeatureContractError, match="TEST labels"):
        transform_features([row], train_state)
