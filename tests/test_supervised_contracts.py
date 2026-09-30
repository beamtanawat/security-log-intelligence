from __future__ import annotations

import copy

import numpy as np
import pytest

from supervised.contracts import (
    ATTACK_LABEL,
    BRANCH_ID,
    DATASET_ID,
    FEATURE_ORDER,
    NUMERIC_FEATURES,
    build_supervised_contract,
    select_base_features,
    validate_development_rows,
)
from supervised.models import SupervisedContractError, fit_pipeline, prepare_xy, transform_pipeline
from unsupervised.splits import row_key


def _row(
    number: int,
    *,
    group_id: str = "g-1",
    label: str = "0",
    proto: str = "tcp",
    value: str = "1",
    category: str = "Normal",
) -> dict[str, object]:
    row: dict[str, object] = {
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "official_split": "TRAIN",
        "development_partition": "TRAIN_INTERNAL",
        "row_number": number,
        "row_key": row_key(DATASET_ID, "TRAIN", number),
        "group_id": group_id,
        "id": str(number),
        "label": label,
        "attack_cat": category,
        "proto": proto,
        "service": "-",
        "state": "CON",
    }
    for field in NUMERIC_FEATURES:
        row[field] = value
    return row


def test_supervised_contract_has_exact_28_features_and_denylist() -> None:
    contract = build_supervised_contract()
    assert len(FEATURE_ORDER) == 28
    assert contract["feature_order"] == list(FEATURE_ORDER)
    assert contract["target"] == {"field": "label", "normal": 0, "attack": 1}
    denied = set(contract["excluded_fields"])
    assert {"id", "label", "attack_cat", "group_id", "row_key"}.issubset(denied)
    assert {"anomaly_score", "anomaly_rank", "u1_score", "u2_score", "u1_decision", "u2_decision"}.issubset(denied)
    assert "label" not in contract["feature_order"]
    assert "attack_cat" not in contract["feature_order"]


def test_base_features_exclude_targets_ids_and_all_chained_signals() -> None:
    row = _row(1)
    row.update({"anomaly_score": 0.9, "u1_score": 0.8, "u2_decision": "ANOMALY", "target": 1})
    selected = select_base_features(row)
    assert tuple(selected) == FEATURE_ORDER
    assert set(selected) == set(FEATURE_ORDER)
    assert "label" not in selected and "attack_cat" not in selected
    assert "anomaly_score" not in selected and "u1_score" not in selected


def test_development_validation_preserves_conflicts_and_rejects_mixed_identity() -> None:
    rows = [_row(1, group_id="g-1", label="0"), _row(2, group_id="g-1", label="1")]
    report = validate_development_rows(rows)
    assert report["row_count"] == 2
    assert report["label_counts"] == {"0": 1, "1": 1}
    assert report["conflict_group_count"] == 1
    assert report["conflict_row_count"] == 2
    wrong = copy.deepcopy(rows[0])
    wrong["branch_id"] = "FORTIGATE_REAL_LOG"
    with pytest.raises(SupervisedContractError, match="branch"):
        validate_development_rows([wrong])


def test_fold_local_state_maps_held_out_category_to_unknown_and_ignores_extreme_values() -> None:
    train = [_row(1, group_id="g-1", proto="tcp", value="1"), _row(2, group_id="g-2", proto="udp", value="2")]
    bundle = fit_pipeline(train, frozenset(row["row_key"] for row in train), "S1", {"C": 1.0})
    before = bundle["feature_state"].state_sha256
    held_out = [_row(3, group_id="g-3", proto="only-held-out", value="999999999")]
    transformed = transform_pipeline(bundle, held_out)
    assert transformed.shape[0] == 1
    assert np.isfinite(transformed).all()
    assert bundle["feature_state"].state_sha256 == before
    unknown_columns = [
        index for index, name in enumerate(bundle["feature_state"].output_feature_names)
        if name == "cat::proto::reserved::UNKNOWN"
    ]
    assert unknown_columns and transformed[0, unknown_columns[0]] == 1.0


def test_invalid_numeric_and_duplicate_xy_keys_block() -> None:
    rows = [_row(1), _row(2, group_id="g-2")]
    invalid = copy.deepcopy(rows[0])
    invalid["sbytes"] = "NaN"
    with pytest.raises(SupervisedContractError, match="numeric"):
        fit_pipeline([invalid], frozenset({invalid["row_key"]}), "S1", {"C": 1.0})
    bundle = fit_pipeline(rows, frozenset(row["row_key"] for row in rows), "S1", {"C": 1.0})
    duplicate = [rows[0], dict(rows[0], row_number=3)]
    with pytest.raises(SupervisedContractError, match="one-to-one"):
        prepare_xy(bundle, duplicate)


def test_fit_membership_rejects_held_out_group_even_inside_train_internal() -> None:
    rows = [_row(1, group_id="same"), _row(2, group_id="same")]
    with pytest.raises(SupervisedContractError, match="group"):
        fit_pipeline([rows[0]], frozenset({rows[0]["row_key"]}), "S1", {"C": 1.0}, all_rows=rows)

