"""Deterministic UNSW TRAIN grouping and internal development split."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from typing import Any, Mapping, Sequence

from .contracts import (
    BRANCH_ID,
    CATEGORICAL_FEATURES,
    DATASET_ID,
    NUMERIC_FEATURES,
    validate_input_identities,
)


SOURCE_SHA256 = "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
PARTITIONS = ("TRAIN_INTERNAL", "VALIDATION_CALIBRATION", "VALIDATION_COMPARISON")
FULL_DIGEST_FIELDS = tuple(field for field in (*NUMERIC_FEATURES, *CATEGORICAL_FEATURES, "stcpb", "dtcpb", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "ct_state_ttl", "ct_srv_src", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_sm_ips_ports") if field not in {"id", "label", "attack_cat"})
ALLOWED_DIGEST_FIELDS = tuple((*NUMERIC_FEATURES, *CATEGORICAL_FEATURES))


class SplitBlocker(ValueError):
    """Raised when the approved development split cannot be materialized."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def row_key(dataset_id: str, official_split: str, one_based_row_number: int) -> str:
    return json.dumps([dataset_id, official_split, one_based_row_number], ensure_ascii=False, separators=(",", ":"))


def _canonical_number(value: object) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        decimal = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise SplitBlocker(f"malformed numeric value: {value!r}") from exc
    if not decimal.is_finite() or decimal < 0:
        raise SplitBlocker(f"invalid numeric value: {value!r}")
    if decimal == 0:
        return "0"
    return format(decimal.normalize(), "f")


def _canonical_value(field: str, value: object) -> object:
    if field in NUMERIC_FEATURES or field in {"stcpb", "dtcpb", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "ct_state_ttl", "ct_srv_src", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_sm_ips_ports"}:
        return _canonical_number(value)
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _digest(row: Mapping[str, object], fields: Sequence[str]) -> str:
    return hashlib.sha256(_json_bytes([_canonical_value(field, row.get(field)) for field in fields])).hexdigest()


def _near_digest(row: Mapping[str, object]) -> str:
    values: list[object] = []
    numeric = set(NUMERIC_FEATURES)
    for field in ALLOWED_DIGEST_FIELDS:
        value = _canonical_value(field, row.get(field))
        if field in numeric and value is not None:
            value = format(Decimal(str(value)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN), "f")
        values.append(value)
    return hashlib.sha256(_json_bytes(values)).hexdigest()


def _label(value: object, row_number: object) -> str:
    label = str(value).strip()
    if label not in {"0", "1"}:
        raise SplitBlocker(f"invalid binary label at row {row_number}")
    return label


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


@dataclass(frozen=True)
class SplitManifest:
    rows: tuple[dict[str, Any], ...]
    report: dict[str, Any]
    manifest_sha256: str


def _choose_boundaries(component_sizes: Sequence[int], total_rows: int) -> tuple[int, int, dict[str, int]]:
    """Choose the frozen nearest-feasible contiguous 80/10/10 allocation."""

    component_count = len(component_sizes)
    if component_count < 3:
        raise SplitBlocker("split allocation requires at least three components")
    prefix = [0]
    for size in component_sizes:
        prefix.append(prefix[-1] + size)
    best: tuple[tuple[int, int, int, int, int], int, int] | None = None
    # Integer form of the approved ±2 percentage-point constraints.
    train_min = 80 * total_rows - 2 * total_rows
    train_max = 80 * total_rows + 2 * total_rows
    cal_min = 10 * total_rows - 2 * total_rows
    cal_max = 10 * total_rows + 2 * total_rows
    cal_lower_rows = (cal_min + 99) // 100
    cal_upper_rows = cal_max // 100
    for first_boundary in range(1, component_count - 1):
        train_rows = prefix[first_boundary]
        if train_rows < 3072:
            continue
        if not train_min <= 100 * train_rows <= train_max:
            continue
        # Both validation constraints are monotone in the second boundary.
        lower_value = max(prefix[first_boundary] + cal_lower_rows, total_rows - cal_upper_rows)
        upper_value = min(prefix[first_boundary] + cal_upper_rows, total_rows - cal_lower_rows)
        lower = max(first_boundary + 1, bisect_left(prefix, lower_value, first_boundary + 1, component_count))
        upper = min(component_count - 1, bisect_right(prefix, upper_value, first_boundary + 1, component_count) - 1)
        if lower > upper:
            continue
        candidates = {lower, upper}
        target = prefix[first_boundary] + total_rows // 10
        insertion = bisect_left(prefix, target, lower, upper + 1)
        candidates.update({insertion - 1, insertion, insertion + 1})
        for second_boundary in sorted(candidates):
            if not first_boundary < second_boundary < component_count:
                continue
            train = prefix[first_boundary]
            calibration = prefix[second_boundary] - train
            comparison = total_rows - prefix[second_boundary]
            if not (cal_min <= 100 * calibration <= cal_max):
                continue
            if not (cal_min <= 100 * comparison <= cal_max):
                continue
            objective = (
                abs(100 * train - 80 * total_rows),
                abs(100 * calibration - 10 * total_rows),
                abs(100 * comparison - 10 * total_rows),
                first_boundary,
                second_boundary,
            )
            candidate = (objective, first_boundary, second_boundary)
            if best is None or candidate[0] < best[0]:
                best = candidate
    if best is None:
        raise SplitBlocker("SPLIT_ALLOCATION_BLOCKED: no feasible contiguous whole-group allocation")
    _, first_boundary, second_boundary = best
    counts = {
        "TRAIN_INTERNAL": prefix[first_boundary],
        "VALIDATION_CALIBRATION": prefix[second_boundary] - prefix[first_boundary],
        "VALIDATION_COMPARISON": total_rows - prefix[second_boundary],
    }
    return first_boundary, second_boundary, counts


def build_split_manifest(rows: Sequence[Mapping[str, object]], dataset_id: str = DATASET_ID) -> SplitManifest:
    if dataset_id != DATASET_ID:
        raise SplitBlocker("UNSW dataset identity required")
    if not rows:
        raise SplitBlocker("official TRAIN is empty")
    validate_input_identities(rows, dataset_id, BRANCH_ID)
    if any(row.get("official_split", "TRAIN") != "TRAIN" for row in rows):
        raise SplitBlocker("only official TRAIN may create development membership")
    for index, row in enumerate(rows):
        _label(row.get("label"), row.get("row_number", index + 1))
    uf = _UnionFind(len(rows))
    index_by_digest: dict[tuple[str, str], int] = {}
    full_digests: list[str] = []
    allowed_digests: list[str] = []
    near_digests: list[str] = []
    row_keys: list[str] = []
    for index, row in enumerate(rows):
        number = int(row.get("row_number", index + 1))
        key = row_key(dataset_id, "TRAIN", number)
        row_keys.append(key)
        full = _digest(row, FULL_DIGEST_FIELDS)
        allowed = _digest(row, ALLOWED_DIGEST_FIELDS)
        near = _near_digest(row)
        full_digests.append(full)
        allowed_digests.append(allowed)
        near_digests.append(near)
        for kind, digest in (("full", full), ("allowed", allowed), ("near", near)):
            previous = index_by_digest.get((kind, digest))
            if previous is None:
                index_by_digest[(kind, digest)] = index
            else:
                uf.union(index, previous)

    labels_by_predictive: dict[str, list[int]] = {}
    for index, digest in enumerate(allowed_digests):
        labels_by_predictive.setdefault(digest, []).append(index)
    conflict_groups: list[tuple[str, list[int]]] = []
    for digest, members in labels_by_predictive.items():
        labels = {_label(rows[index].get("label"), rows[index].get("row_number", index + 1)) for index in members}
        if len(labels) > 1:
            conflict_groups.append((digest, members))

    components: dict[int, list[int]] = {}
    for index in range(len(rows)):
        components.setdefault(uf.find(index), []).append(index)
    max_component = max(len(members) for members in components.values())
    if max_component > len(rows) * 0.20:
        raise SplitBlocker(f"group exceeds 20% of official TRAIN ({max_component}/{len(rows)})")

    ordered_components: list[tuple[str, int, list[int]]] = []
    group_ids: dict[int, str] = {}
    for root, members in components.items():
        minimum_key = min(row_keys[index] for index in members)
        group_id = hashlib.sha256(_json_bytes(["s2.2-unsw-group-v1", minimum_key])).hexdigest()
        group_ids[root] = group_id
        ordered_key = hashlib.sha256(_json_bytes(["s2.2-unsw-split-v1", group_id])).hexdigest()
        ordered_components.append((ordered_key, root, members))
    ordered_components.sort(key=lambda item: (item[0], group_ids[item[1]]))
    first_boundary, second_boundary, counts = _choose_boundaries(
        [len(members) for _, _, members in ordered_components], len(rows)
    )
    partition_by_component: dict[int, str] = {}
    for index, (_, root, _) in enumerate(ordered_components):
        partition_by_component[root] = (
            "TRAIN_INTERNAL" if index < first_boundary else
            "VALIDATION_CALIBRATION" if index < second_boundary else
            "VALIDATION_COMPARISON"
        )

    manifest_rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        group_id = group_ids[uf.find(index)]
        partition = partition_by_component[uf.find(index)]
        manifest_rows.append({
            "dataset_id": dataset_id,
            "branch_id": BRANCH_ID,
            "official_split": "TRAIN",
            "row_number": index + 1,
            "row_key": row_keys[index],
            "source_id": str(row.get("id", "")),
            "full_feature_digest": full_digests[index],
            "allowed_feature_digest": allowed_digests[index],
            "near_duplicate_digest": near_digests[index],
            "group_id": group_id,
            "partition": partition,
        })
    conflict_registry: list[dict[str, Any]] = []
    conflict_rows = conflict_normal = conflict_attack = 0
    for digest, members in sorted(conflict_groups):
        labels = [_label(rows[index].get("label"), rows[index].get("row_number", index + 1)) for index in members]
        roots = {uf.find(index) for index in members}
        if len(roots) != 1:
            raise SplitBlocker("predictive conflict group crosses allocation components")
        root = next(iter(roots))
        partition = partition_by_component[root]
        normal = labels.count("0")
        attack = labels.count("1")
        conflict_rows += len(members)
        conflict_normal += normal
        conflict_attack += attack
        conflict_registry.append({
            "predictive_group_key": digest,
            "component_id": group_ids[root],
            "partition": partition,
            "row_keys": [row_keys[index] for index in sorted(members)],
            "row_count": len(members),
            "normal_count": normal,
            "attack_count": attack,
            "flag": "TARGET_CONFLICT_GROUP",
        })
    if sum(counts.values()) != len(rows):
        raise SplitBlocker(f"partition row reconciliation failed: {counts}")
    exact_group_partition_values: dict[str, set[str]] = {}
    for digest, members in labels_by_predictive.items():
        exact_group_partition_values[digest] = {manifest_rows[index]["partition"] for index in members}
    crossing_groups = sum(len(partitions) > 1 for partitions in exact_group_partition_values.values())
    if crossing_groups:
        raise SplitBlocker(f"exact predictive groups cross partitions: {crossing_groups}")
    payload = {"schema_version": "stage_2.2a-split-manifest/1.0", "source_sha256": SOURCE_SHA256, "rows": manifest_rows}
    manifest_hash = hashlib.sha256(_json_bytes(payload)).hexdigest()
    report = {
        "schema_version": "stage_2.2a-split-report/1.0",
        "dataset_id": dataset_id,
        "branch_id": BRANCH_ID,
        "source_sha256": SOURCE_SHA256,
        "official_train_rows": len(rows),
        "group_count": len(components),
        "max_group_size": max_component,
        "max_group_share": max_component / len(rows),
        "partition_counts": counts,
        "group_overlap_check": "PASS",
        "target_conflict_check": "PASS",
        "target_conflict_groups": len(conflict_groups),
        "target_conflict_rows": conflict_rows,
        "target_conflict_normal": conflict_normal,
        "target_conflict_attack": conflict_attack,
        "target_conflict_registry": conflict_registry,
        "exact_predictive_group_count": len(exact_group_partition_values),
        "exact_predictive_group_cross_split_count": crossing_groups,
        "entity_session_time_guarantee": "NOT_AVAILABLE_IN_PREPARED_SCHEMA",
        "allocation": {
            "namespace": "s2.2-unsw-split-v1",
            "method": "ORDERED_COMPONENT_CONTIGUOUS_NEAREST_FEASIBLE",
            "ratio_targets": {"TRAIN_INTERNAL": 0.80, "VALIDATION_CALIBRATION": 0.10, "VALIDATION_COMPARISON": 0.10},
            "tolerance_percentage_points": 2,
            "first_boundary_component_count": first_boundary,
            "second_boundary_component_count": second_boundary,
            "ordered_component_count": len(ordered_components),
            "label_blind": True,
        },
        "manifest_sha256": manifest_hash,
    }
    return SplitManifest(tuple(manifest_rows), report, manifest_hash)
