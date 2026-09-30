from __future__ import annotations

import copy

import pytest

from supervised.contracts import BRANCH_ID, DATASET_ID, NUMERIC_FEATURES
from supervised.folds import FoldBlocker, audit_folds, build_folds
from unsupervised.splits import row_key


def _rows(*, groups: int = 12, rows_per_group: int = 1024, single_class: bool = False) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    number = 1
    for group_index in range(groups):
        for offset in range(rows_per_group):
            label = "0" if single_class else str((offset + group_index) % 2)
            row: dict[str, object] = {
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "official_split": "TRAIN",
                "development_partition": "TRAIN_INTERNAL",
                "row_number": number,
                "row_key": row_key(DATASET_ID, "TRAIN", number),
                "group_id": f"g-{group_index}",
                "label": label,
            }
            for field in NUMERIC_FEATURES:
                row[field] = "1"
            rows.append(row)
            number += 1
    return rows


def test_outer_and_inner_fold_assignment_is_deterministic_and_label_blind() -> None:
    rows = _rows()
    first = build_folds(rows)
    second = build_folds(copy.deepcopy(rows))
    relabeled = copy.deepcopy(rows)
    for row in relabeled:
        row["label"] = "1" if row["label"] == "0" else "0"
    third = build_folds(relabeled)
    assert first == second == third
    report = audit_folds(rows, first)
    assert report["status"] == "PASS"
    assert report["outer_fold_count"] == 3
    assert report["inner_fold_count"] == 2


def test_exact_groups_are_atomic_and_do_not_cross_outer_or_inner_boundaries() -> None:
    rows = _rows()
    folds = build_folds(rows)
    audit = audit_folds(rows, folds)
    assert audit["outer_group_crossings"] == 0
    assert audit["inner_group_crossings"] == 0
    for group_id in {row["group_id"] for row in rows}:
        assignments = {item["outer_fold"] for item in folds if item["group_id"] == group_id}
        assert len(assignments) == 1


def test_large_group_remains_whole() -> None:
    rows = _rows(groups=12, rows_per_group=512)
    rows.extend(_rows(groups=1, rows_per_group=4096)[0:4096])
    for index, row in enumerate(rows[6144:], start=6145):
        row["row_number"] = index
        row["row_key"] = row_key(DATASET_ID, "TRAIN", index)
        row["group_id"] = "large-group"
    folds = build_folds(rows)
    assignments = {item["outer_fold"] for item in folds if item["group_id"] == "large-group"}
    assert len(assignments) == 1


def test_single_class_support_blocks_without_resplitting() -> None:
    rows = _rows(single_class=True)
    folds = build_folds(rows)
    with pytest.raises(FoldBlocker, match="class support"):
        audit_folds(rows, folds)


def test_mixed_identity_is_rejected_before_fold_assignment() -> None:
    rows = _rows()
    rows[0]["branch_id"] = "FORTIGATE_REAL_LOG"
    with pytest.raises(FoldBlocker, match="branch"):
        build_folds(rows)
