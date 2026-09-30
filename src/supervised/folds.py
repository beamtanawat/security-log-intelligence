"""Deterministic group-atomic Stage 2.3A nested fold manifests."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import BRANCH_ID, DATASET_ID, SupervisedContractError, labels_for_rows, validate_development_rows


class FoldBlocker(ValueError):
    """Raised when the approved group-safe fold contract cannot be met."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _namespace_digest(namespace: str, group_id: str) -> str:
    return hashlib.sha256(_json_bytes([namespace, group_id])).hexdigest()


def _group_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        group_id = str(row["group_id"])
        groups[group_id].append(index)
    return dict(groups)


def _assign_groups(group_ids: Sequence[str], group_sizes: Mapping[str, int], fold_count: int, namespace: str) -> dict[str, int]:
    counts = [0] * fold_count
    assignments: dict[str, int] = {}
    ordered = sorted(group_ids, key=lambda group: (-group_sizes[group], _namespace_digest(namespace, group), group.encode("utf-8")))
    for group_id in ordered:
        fold = min(range(fold_count), key=lambda index: (counts[index], index))
        assignments[group_id] = fold
        counts[fold] += group_sizes[group_id]
    return assignments


def build_folds(rows: Sequence[Mapping[str, object]]) -> list[dict[str, Any]]:
    """Build the frozen three outer/two inner whole-component assignments."""

    try:
        validate_development_rows(rows)
    except SupervisedContractError as exc:
        raise FoldBlocker(str(exc)) from exc
    if any(row.get("development_partition") != "TRAIN_INTERNAL" for row in rows):
        raise FoldBlocker("fold construction requires TRAIN_INTERNAL rows only")
    groups = _group_rows(rows)
    if len(groups) < 3:
        raise FoldBlocker("at least three predictive groups are required")
    sizes = {group: len(indices) for group, indices in groups.items()}
    outer_by_group = _assign_groups(tuple(groups), sizes, 3, "S2.3-OUTER-V1")
    inner_by_outer: dict[int, dict[str, int]] = {}
    for outer in range(3):
        eligible = [group for group, fold in outer_by_group.items() if fold != outer]
        inner_by_outer[outer] = _assign_groups(eligible, sizes, 2, f"S2.3-INNER-V1:{outer}")
    output: list[dict[str, Any]] = []
    for row in rows:
        group_id = str(row["group_id"])
        outer = outer_by_group[group_id]
        output.append(
            {
                "dataset_id": DATASET_ID,
                "branch_id": BRANCH_ID,
                "row_key": str(row["row_key"]),
                "group_id": group_id,
                "upstream_split": str(row.get("development_partition")),
                "outer_fold": outer,
                "inner_fold_by_outer": {
                    str(context): assignment[group_id]
                    for context, assignment in inner_by_outer.items()
                    if context != outer
                },
            }
        )
    return output


def _support(rows: Sequence[Mapping[str, object]], indices: Sequence[int]) -> dict[str, int]:
    labels = labels_for_rows([rows[index] for index in indices])
    return {"0": labels.count(0), "1": labels.count(1)}


def audit_folds(rows: Sequence[Mapping[str, object]], folds: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Reconcile fold membership, atomicity, deterministic support and hashes."""

    if len(rows) != len(folds):
        raise FoldBlocker("fold manifest row count mismatch")
    by_key = {str(row["row_key"]): index for index, row in enumerate(rows)}
    if len(by_key) != len(rows) or {str(item.get("row_key")) for item in folds} != set(by_key):
        raise FoldBlocker("fold manifest row keys are not one-to-one")
    outer_rows: dict[int, list[int]] = defaultdict(list)
    group_outer: dict[str, set[int]] = defaultdict(set)
    for item in folds:
        index = by_key[str(item["row_key"])]
        group_id = str(item["group_id"])
        if group_id != str(rows[index]["group_id"]):
            raise FoldBlocker("fold group identity mismatch")
        outer = int(item["outer_fold"])
        if outer not in {0, 1, 2}:
            raise FoldBlocker("invalid outer fold")
        outer_rows[outer].append(index)
        group_outer[group_id].add(outer)
    outer_crossings = sum(len(values) > 1 for values in group_outer.values())
    if outer_crossings:
        raise FoldBlocker("group crosses outer folds")
    outer_eval_sets = {outer: set(indices) for outer, indices in outer_rows.items()}
    outer_counts: dict[str, Any] = {}
    for outer in range(3):
        evaluation = outer_rows[outer]
        evaluation_set = outer_eval_sets[outer]
        training = [index for index in range(len(rows)) if index not in evaluation_set]
        if len(evaluation) < 4096 or len(training) < 4096:
            raise FoldBlocker("minimum rows support gate failed")
        eval_support = _support(rows, evaluation)
        train_support = _support(rows, training)
        if 0 in {eval_support["0"], eval_support["1"], train_support["0"], train_support["1"]}:
            raise FoldBlocker("class support gate failed")
        outer_counts[str(outer)] = {
            "row_count": len(evaluation),
            "group_count": len({str(rows[index]["group_id"]) for index in evaluation}),
            "label_counts": eval_support,
            "training_row_count": len(training),
            "training_label_counts": train_support,
        }
    inner_crossings = 0
    inner_counts: dict[str, Any] = {}
    for outer in range(3):
        eligible = [index for index in range(len(rows)) if index not in outer_eval_sets[outer]]
        context_items = [folds[index] for index in eligible]
        group_inner: dict[str, set[int]] = defaultdict(set)
        for item in context_items:
            group_id = str(item["group_id"])
            inner = int(item["inner_fold_by_outer"][str(outer)])
            group_inner[group_id].add(inner)
        inner_crossings += sum(len(assignment) > 1 for assignment in group_inner.values())
        context_report: dict[str, Any] = {}
        for inner in (0, 1):
            evaluation = [index for index in eligible if int(folds[index]["inner_fold_by_outer"][str(outer)]) == inner]
            training = [index for index in eligible if int(folds[index]["inner_fold_by_outer"][str(outer)]) != inner]
            if len(evaluation) < 4096 or len(training) < 4096:
                raise FoldBlocker("minimum rows support gate failed")
            eval_support = _support(rows, evaluation)
            train_support = _support(rows, training)
            if 0 in {eval_support["0"], eval_support["1"], train_support["0"], train_support["1"]}:
                raise FoldBlocker("class support gate failed")
            context_report[str(inner)] = {
                "row_count": len(evaluation),
                "group_count": len({str(rows[index]["group_id"]) for index in evaluation}),
                "label_counts": eval_support,
                "training_row_count": len(training),
                "training_label_counts": train_support,
            }
        inner_counts[str(outer)] = context_report
    if inner_crossings:
        raise FoldBlocker("group crosses inner folds")
    manifest_bytes = b"".join(_json_bytes(dict(item)) + b"\n" for item in folds)
    return {
        "schema_version": "stage_2.3-fold-audit/1.0",
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "row_count": len(rows),
        "group_count": len(group_outer),
        "outer_fold_count": 3,
        "inner_fold_count": 2,
        "outer_group_crossings": outer_crossings,
        "inner_group_crossings": inner_crossings,
        "outer": outer_counts,
        "inner_by_outer": inner_counts,
        "fold_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "allocation": {
            "outer_namespace": "S2.3-OUTER-V1",
            "inner_namespace": "S2.3-INNER-V1",
            "method": "WHOLE_COMPONENT_GREEDY_FEWEST_ROWS_TIE_LOW_INDEX",
            "label_blind": True,
        },
    }
