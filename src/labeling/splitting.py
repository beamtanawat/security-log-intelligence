"""Deterministic Stage 2.1 group-aware split allocation primitives."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Mapping

from .identity import canonical_json_bytes, sha256_hex
from .sampling import STRATA


SPLIT_ORDER = ("TRAIN", "VALIDATION", "TEST")
SPLIT_TARGETS = {
    "TRAIN": Fraction(70, 100),
    "VALIDATION": Fraction(15, 100),
    "TEST": Fraction(15, 100),
}
SPLIT_NAMESPACE = "stage-2.1-split-v1"
SPLIT_SEED = 21012026

HARD_ALLOCATOR_ALGORITHM = "HARD_GROUP_STRATIFIED_GREEDY_REPAIR_V2"
HARD_ALLOCATOR_VERSION = "2.0"
HARD_ALLOCATOR_NAMESPACE = "stage-2.1-hard-group-stratified-v2"
HARD_ALLOCATOR_SEED = 21012026
HARD_REPAIR_MAX_ITERATIONS = 512
HARD_SWAP_FRONTIER_SIZE = 32
MINIMUM_GROUP_COUNT = 500
MINIMUM_SPLIT_GROUP_COUNT = 75
MINIMUM_HOLDOUT_ROWS = 1_500
MAX_GROUP_SHARE = Fraction(10, 100)
GLOBAL_SHARE_TOLERANCE = Fraction(2, 100)
STRATUM_SHARE_TOLERANCE = Fraction(5, 100)


def split_bucket(group_id: str) -> int:
    """Historical V1 hash bucket, retained only for predecessor diagnostics."""

    if not isinstance(group_id, str) or not group_id:
        raise ValueError("group_id must be a non-empty string")
    import hashlib

    digest = hashlib.sha256(canonical_json_bytes([SPLIT_NAMESPACE, SPLIT_SEED, group_id])).digest()
    return int.from_bytes(digest[:8], "big") % 10_000


def assign_group_split(group_id: str) -> str:
    """Historical V1 assignment, never used for amended HARD_GROUP_ONLY output."""

    bucket = split_bucket(group_id)
    if bucket <= 6_999:
        return "TRAIN"
    if bucket <= 8_499:
        return "VALIDATION"
    return "TEST"


def group_id(selected_tier: str, members: list[str]) -> str:
    if not selected_tier or not members:
        raise ValueError("selected tier and members are required")
    payload = {
        "group_contract": "stage-2.1-group-v1",
        "selected_tier": selected_tier,
        "members": sorted(members),
    }
    return f"G-{sha256_hex(payload)}"


@dataclass(frozen=True)
class HardGroupVector:
    """One indivisible hard group and its frozen pre-label stratum counts."""

    group_id: str
    group_size: int
    stratum_counts: Mapping[str, int]

    def __post_init__(self) -> None:
        if not isinstance(self.group_id, str) or not self.group_id:
            raise ValueError("group_id must be a non-empty string")
        if isinstance(self.group_size, bool) or not isinstance(self.group_size, int) or self.group_size < 1:
            raise ValueError("group_size must be a positive integer")
        counts = {name: self.stratum_counts.get(name, 0) for name in STRATA}
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts.values()):
            raise ValueError("stratum counts must be non-negative integers")
        if sum(counts.values()) != self.group_size:
            raise ValueError("stratum counts must sum to group_size")
        object.__setattr__(self, "stratum_counts", counts)

    @property
    def group_order_digest(self) -> str:
        return sha256_hex([HARD_ALLOCATOR_NAMESPACE, HARD_ALLOCATOR_SEED, self.group_id])


@dataclass(frozen=True)
class HardAllocationResult:
    status: str
    assignments: Mapping[str, str]
    initial_assignments: Mapping[str, str]
    final_split_counts: Mapping[str, int]
    final_split_group_counts: Mapping[str, int]
    final_stratum_split_counts: Mapping[str, Mapping[str, int]]
    repair_actions: tuple[Mapping[str, object], ...]
    repair_iterations: int
    termination_reason: str
    failed_criteria: tuple[str, ...]
    objective: tuple[object, ...]
    report: Mapping[str, object]


@dataclass
class _Counts:
    rows: dict[str, int]
    groups: dict[str, int]
    strata: dict[str, dict[str, int]]


def _empty_counts() -> _Counts:
    return _Counts(
        rows={split: 0 for split in SPLIT_ORDER},
        groups={split: 0 for split in SPLIT_ORDER},
        strata={stratum: {split: 0 for split in SPLIT_ORDER} for stratum in STRATA},
    )


def _copy_counts(counts: _Counts) -> _Counts:
    return _Counts(
        rows=dict(counts.rows),
        groups=dict(counts.groups),
        strata={key: dict(value) for key, value in counts.strata.items()},
    )


def _apply_vector(counts: _Counts, vector: HardGroupVector, split: str, sign: int) -> None:
    counts.rows[split] += sign * vector.group_size
    counts.groups[split] += sign
    for stratum in STRATA:
        counts.strata[stratum][split] += sign * vector.stratum_counts[stratum]


def _counts_from_assignments(vectors: Mapping[str, HardGroupVector], assignments: Mapping[str, str]) -> _Counts:
    counts = _empty_counts()
    for group, split in assignments.items():
        _apply_vector(counts, vectors[group], split, 1)
    return counts


def _max_group_size(vectors: Mapping[str, HardGroupVector]) -> int:
    return max((vector.group_size for vector in vectors.values()), default=0)


def _eligible_strata(stratum_totals: Mapping[str, int]) -> tuple[str, ...]:
    return tuple(stratum for stratum in STRATA if stratum_totals.get(stratum, 0) >= 100)


def _objective(
    counts: _Counts,
    *,
    total_rows: int,
    stratum_totals: Mapping[str, int],
    eligible_strata: tuple[str, ...],
) -> tuple[object, ...]:
    global_excesses = [
        max(Fraction(0), abs(Fraction(counts.rows[split], total_rows) - SPLIT_TARGETS[split]) - GLOBAL_SHARE_TOLERANCE)
        for split in SPLIT_ORDER
    ]
    stratum_excesses = [
        max(
            Fraction(0),
            abs(Fraction(counts.strata[stratum][split], stratum_totals[stratum]) - Fraction(counts.rows[split], total_rows))
            - STRATUM_SHARE_TOLERANCE,
        )
        for stratum in eligible_strata
        for split in SPLIT_ORDER
    ]
    minimum_failures = [counts.groups[split] < MINIMUM_SPLIT_GROUP_COUNT for split in SPLIT_ORDER]
    minimum_failures.extend(
        [counts.rows["VALIDATION"] < MINIMUM_HOLDOUT_ROWS, counts.rows["TEST"] < MINIMUM_HOLDOUT_ROWS]
    )
    m_amount = sum(
        (Fraction(max(0, MINIMUM_SPLIT_GROUP_COUNT - counts.groups[split]), MINIMUM_SPLIT_GROUP_COUNT) for split in SPLIT_ORDER),
        Fraction(0),
    )
    m_amount += Fraction(max(0, MINIMUM_HOLDOUT_ROWS - counts.rows["VALIDATION"]), MINIMUM_HOLDOUT_ROWS)
    m_amount += Fraction(max(0, MINIMUM_HOLDOUT_ROWS - counts.rows["TEST"]), MINIMUM_HOLDOUT_ROWS)
    residual = sum(
        (abs(Fraction(counts.rows[split], total_rows) - SPLIT_TARGETS[split]) for split in SPLIT_ORDER),
        Fraction(0),
    )
    if eligible_strata:
        residual += sum(
            (
                abs(Fraction(counts.strata[stratum][split], stratum_totals[stratum]) - SPLIT_TARGETS[split])
                for stratum in eligible_strata
                for split in SPLIT_ORDER
            ),
            Fraction(0),
        ) / len(eligible_strata)
    return (
        sum(minimum_failures),
        m_amount,
        sum(value > 0 for value in global_excesses),
        max(global_excesses, default=Fraction(0)),
        sum(global_excesses, Fraction(0)),
        sum(value > 0 for value in stratum_excesses),
        max(stratum_excesses, default=Fraction(0)),
        sum(stratum_excesses, Fraction(0)),
        residual,
    )


def _failed_criteria(
    counts: _Counts,
    *,
    total_rows: int,
    stratum_totals: Mapping[str, int],
    eligible_strata: tuple[str, ...],
) -> tuple[str, ...]:
    failed: list[str] = []
    for split in SPLIT_ORDER:
        if counts.groups[split] < MINIMUM_SPLIT_GROUP_COUNT:
            failed.append(f"MINIMUM_SPLIT_GROUP_COUNT_{split}")
    if counts.rows["VALIDATION"] < MINIMUM_HOLDOUT_ROWS:
        failed.append("MINIMUM_VALIDATION_ROWS")
    if counts.rows["TEST"] < MINIMUM_HOLDOUT_ROWS:
        failed.append("MINIMUM_TEST_ROWS")
    for split in SPLIT_ORDER:
        if abs(Fraction(counts.rows[split], total_rows) - SPLIT_TARGETS[split]) > GLOBAL_SHARE_TOLERANCE:
            failed.append(f"SPLIT_SHARE_{split}")
    for stratum in eligible_strata:
        denominator = stratum_totals[stratum]
        for split in SPLIT_ORDER:
            if abs(Fraction(counts.strata[stratum][split], denominator) - Fraction(counts.rows[split], total_rows)) > STRATUM_SHARE_TOLERANCE:
                failed.append(f"SAMPLING_STRATUM_SHARE_{stratum}_{split}")
    return tuple(sorted(failed))


def _rational(value: object) -> str | int:
    if isinstance(value, Fraction):
        return f"{value.numerator}/{value.denominator}"
    return value  # type: ignore[return-value]


def _objective_json(objective: tuple[object, ...]) -> list[object]:
    return [_rational(value) for value in objective]


def _parameters_payload() -> dict[str, object]:
    return {
        "algorithm": HARD_ALLOCATOR_ALGORITHM,
        "version": HARD_ALLOCATOR_VERSION,
        "namespace": HARD_ALLOCATOR_NAMESPACE,
        "seed": HARD_ALLOCATOR_SEED,
        "targets": {split: f"{SPLIT_TARGETS[split].numerator}/{SPLIT_TARGETS[split].denominator}" for split in SPLIT_ORDER},
        "global_tolerance": "2/100",
        "stratum_tolerance": "5/100",
        "minimum_group_count": MINIMUM_GROUP_COUNT,
        "minimum_split_group_count": MINIMUM_SPLIT_GROUP_COUNT,
        "minimum_holdout_rows": MINIMUM_HOLDOUT_ROWS,
        "swap_frontier_size": HARD_SWAP_FRONTIER_SIZE,
        "maximum_repair_iterations": HARD_REPAIR_MAX_ITERATIONS,
        "group_order": "max_share_desc,group_size_desc,group_order_digest_asc,group_id_utf8_asc",
    }


def _action_digest(*, iteration: int, action_type: str, group_ids: tuple[str, ...], source_splits: tuple[str, ...], destination_splits: tuple[str, ...]) -> str:
    return sha256_hex([HARD_ALLOCATOR_NAMESPACE, HARD_ALLOCATOR_SEED, iteration, action_type, list(group_ids), list(source_splits), list(destination_splits)])


def _make_result(
    *,
    status: str,
    assignments: Mapping[str, str],
    initial_assignments: Mapping[str, str],
    vectors: Mapping[str, HardGroupVector],
    total_rows: int,
    stratum_totals: Mapping[str, int],
    eligible_strata: tuple[str, ...],
    repair_actions: list[Mapping[str, object]],
    repair_iterations: int,
    termination_reason: str,
    extra_failed: tuple[str, ...] = (),
) -> HardAllocationResult:
    counts = _counts_from_assignments(vectors, assignments)
    failed = list(extra_failed)
    if len(vectors) >= MINIMUM_GROUP_COUNT:
        if Fraction(_max_group_size(vectors), total_rows) > MAX_GROUP_SHARE:
            failed.append("MAX_GROUP_SHARE")
    else:
        failed.append("MINIMUM_GROUP_COUNT")
    failed.extend(_failed_criteria(counts, total_rows=total_rows, stratum_totals=stratum_totals, eligible_strata=eligible_strata))
    objective = _objective(counts, total_rows=total_rows, stratum_totals=stratum_totals, eligible_strata=eligible_strata)
    final_strata = {stratum: dict(counts.strata[stratum]) for stratum in STRATA}
    params = _parameters_payload()
    vectors_payload = [{"group_id": group, "group_size": vector.group_size, "stratum_counts": dict(vector.stratum_counts)} for group, vector in sorted(vectors.items())]
    balance_payload = {"strata": list(eligible_strata), "totals": {stratum: stratum_totals.get(stratum, 0) for stratum in STRATA}}
    report: dict[str, object] = {
        "status": status,
        "allocation_algorithm": HARD_ALLOCATOR_ALGORITHM,
        "allocation_version": HARD_ALLOCATOR_VERSION,
        "allocation_namespace": HARD_ALLOCATOR_NAMESPACE,
        "allocation_seed": HARD_ALLOCATOR_SEED,
        "allocation_parameters_sha256": sha256_hex(params),
        "allocation_objective_sha256": sha256_hex({"objective": "J", "formula_version": "stage-2.1-hard-group-objective-v2"}),
        "balancing_strata_sha256": sha256_hex(balance_payload),
        "group_balance_vector_sha256": sha256_hex(vectors_payload),
        "balancing_strata": list(eligible_strata),
        "stratum_totals": dict(stratum_totals),
        "initial_split_counts": dict(_counts_from_assignments(vectors, initial_assignments).rows),
        "initial_split_group_counts": dict(_counts_from_assignments(vectors, initial_assignments).groups),
        "final_split_counts": dict(counts.rows),
        "final_split_group_counts": dict(counts.groups),
        "final_stratum_split_counts": final_strata,
        "final_split_shares": {split: counts.rows[split] / total_rows for split in SPLIT_ORDER},
        "objective": _objective_json(objective),
        "repair_actions": list(repair_actions),
        "repair_iterations": repair_iterations,
        "termination_reason": termination_reason,
        "failed_criteria": sorted(set(failed)),
    }
    return HardAllocationResult(
        status=status,
        assignments=dict(assignments),
        initial_assignments=dict(initial_assignments),
        final_split_counts=dict(counts.rows),
        final_split_group_counts=dict(counts.groups),
        final_stratum_split_counts=final_strata,
        repair_actions=tuple(repair_actions),
        repair_iterations=repair_iterations,
        termination_reason=termination_reason,
        failed_criteria=tuple(sorted(set(failed))),
        objective=objective,
        report=report,
    )


def allocate_hard_group_splits(vectors: list[HardGroupVector] | tuple[HardGroupVector, ...], *, total_rows: int, stratum_totals: Mapping[str, int]) -> HardAllocationResult:
    """Run approved V2 whole-group greedy allocation and bounded repair."""

    if isinstance(total_rows, bool) or not isinstance(total_rows, int) or total_rows < 1:
        raise ValueError("total_rows must be a positive integer")
    by_id: dict[str, HardGroupVector] = {}
    for vector in vectors:
        if vector.group_id in by_id:
            raise ValueError("duplicate hard group ID")
        by_id[vector.group_id] = vector
    if sum(vector.group_size for vector in by_id.values()) != total_rows:
        raise ValueError("hard-group sizes must sum to total_rows")
    totals = {stratum: int(stratum_totals.get(stratum, 0)) for stratum in STRATA}
    if any(value < 0 for value in totals.values()) or sum(totals.values()) != total_rows:
        raise ValueError("stratum totals must be non-negative and sum to total_rows")
    eligible = _eligible_strata(totals)
    max_size = _max_group_size(by_id)
    if len(by_id) < MINIMUM_GROUP_COUNT or Fraction(max_size, total_rows) > MAX_GROUP_SHARE:
        extra = ("MINIMUM_GROUP_COUNT",) if len(by_id) < MINIMUM_GROUP_COUNT else ("MAX_GROUP_SHARE",)
        return _make_result(status="INFEASIBLE", assignments={}, initial_assignments={}, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=[], repair_iterations=0, termination_reason="STRUCTURAL_PRECHECK", extra_failed=extra)

    ordered = sorted(
        by_id.values(),
        key=lambda vector: (
            -max([Fraction(vector.group_size, total_rows)] + [Fraction(vector.stratum_counts[stratum], totals[stratum]) for stratum in eligible]),
            -vector.group_size,
            vector.group_order_digest,
            vector.group_id.encode("utf-8"),
        ),
    )
    assignments: dict[str, str] = {}
    counts = _empty_counts()
    for index, vector in enumerate(ordered):
        candidates: list[tuple[tuple[object, ...], str, _Counts]] = []
        for split_index, split in enumerate(SPLIT_ORDER):
            candidate_counts = _copy_counts(counts)
            _apply_vector(candidate_counts, vector, split, 1)
            remaining_groups = len(ordered) - index - 1
            minimum_groups_needed = sum(max(0, MINIMUM_SPLIT_GROUP_COUNT - candidate_counts.groups[name]) for name in SPLIT_ORDER)
            remaining_rows = total_rows - sum(candidate_counts.rows.values())
            minimum_rows_needed = max(0, MINIMUM_HOLDOUT_ROWS - candidate_counts.rows["VALIDATION"]) + max(0, MINIMUM_HOLDOUT_ROWS - candidate_counts.rows["TEST"])
            if remaining_groups < minimum_groups_needed or remaining_rows < minimum_rows_needed:
                continue
            global_deviation = [abs(Fraction(candidate_counts.rows[name], total_rows) - SPLIT_TARGETS[name]) for name in SPLIT_ORDER]
            stratum_deviation = [abs(Fraction(candidate_counts.strata[stratum][name], totals[stratum]) - SPLIT_TARGETS[name]) for stratum in eligible for name in SPLIT_ORDER]
            tie_digest = sha256_hex([HARD_ALLOCATOR_NAMESPACE, HARD_ALLOCATOR_SEED, vector.group_id, split])
            key = (max(global_deviation, default=Fraction(0)), sum(global_deviation, Fraction(0)), max(stratum_deviation, default=Fraction(0)), sum(stratum_deviation, Fraction(0)), tie_digest, split_index)
            candidates.append((key, split, candidate_counts))
        if not candidates:
            return _make_result(status="INFEASIBLE", assignments=assignments, initial_assignments=assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=[], repair_iterations=0, termination_reason="GREEDY_NO_CANDIDATE")
        _, selected_split, selected_counts = min(candidates, key=lambda item: item[0])
        assignments[vector.group_id] = selected_split
        counts = selected_counts
    initial_assignments = dict(assignments)

    if not _failed_criteria(counts, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible):
        return _make_result(status="FEASIBLE", assignments=assignments, initial_assignments=initial_assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=[], repair_iterations=0, termination_reason="INITIAL_GREEDY_FEASIBLE")

    repair_actions: list[Mapping[str, object]] = []
    for iteration in range(1, HARD_REPAIR_MAX_ITERATIONS + 1):
        current_objective = _objective(counts, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible)
        action_candidates: list[tuple[tuple[object, ...], dict[str, object], _Counts]] = []
        groups_by_split = {split: [group for group, assigned in assignments.items() if assigned == split] for split in SPLIT_ORDER}
        move_cache: dict[tuple[str, str, tuple[int, ...]], tuple[tuple[object, ...], _Counts]] = {}

        def moved_counts(source: str, destination: str, group: str) -> tuple[tuple[object, ...], _Counts]:
            vector = by_id[group]
            signature = (vector.group_size, tuple(vector.stratum_counts[stratum] for stratum in STRATA))
            cache_key = (source, destination, signature)
            if cache_key not in move_cache:
                candidate_counts = _copy_counts(counts)
                _apply_vector(candidate_counts, vector, source, -1)
                _apply_vector(candidate_counts, vector, destination, 1)
                move_cache[cache_key] = (
                    _objective(candidate_counts, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible),
                    candidate_counts,
                )
            return move_cache[cache_key]

        for source in SPLIT_ORDER:
            for group in sorted(groups_by_split[source]):
                for destination in SPLIT_ORDER:
                    if destination == source:
                        continue
                    candidate_objective, candidate_counts = moved_counts(source, destination, group)
                    ids = (group,)
                    sources = (source,)
                    destinations = (destination,)
                    digest = _action_digest(iteration=iteration, action_type="MOVE", group_ids=ids, source_splits=sources, destination_splits=destinations)
                    action = {"action_type": "MOVE", "group_ids": list(ids), "source_splits": list(sources), "destination_splits": list(destinations), "action_sha256": digest}
                    key = (candidate_objective, digest, "MOVE", ids, sources, destinations)
                    action_candidates.append((key, action, candidate_counts))

        for left_index, left in enumerate(SPLIT_ORDER):
            for right in SPLIT_ORDER[left_index + 1 :]:
                def frontier(source: str, destination: str) -> list[str]:
                    candidates: list[tuple[tuple[object, ...], str]] = []
                    for group in groups_by_split[source]:
                        candidate_objective, _ = moved_counts(source, destination, group)
                        candidates.append(((candidate_objective, by_id[group].group_order_digest, group), group))
                    return [group for _, group in sorted(candidates)[:HARD_SWAP_FRONTIER_SIZE]]

                left_frontier = frontier(left, right)
                right_frontier = frontier(right, left)
                for left_group in left_frontier:
                    for right_group in right_frontier:
                        pair = sorted(((left_group, left), (right_group, right)))
                        ids = tuple(item[0] for item in pair)
                        sources = tuple(item[1] for item in pair)
                        destinations = tuple(right if item[1] == left else left for item in pair)
                        candidate_counts = _copy_counts(counts)
                        _apply_vector(candidate_counts, by_id[left_group], left, -1)
                        _apply_vector(candidate_counts, by_id[left_group], right, 1)
                        _apply_vector(candidate_counts, by_id[right_group], right, -1)
                        _apply_vector(candidate_counts, by_id[right_group], left, 1)
                        digest = _action_digest(iteration=iteration, action_type="SWAP", group_ids=ids, source_splits=sources, destination_splits=destinations)
                        action = {"action_type": "SWAP", "group_ids": list(ids), "source_splits": list(sources), "destination_splits": list(destinations), "action_sha256": digest}
                        key = (_objective(candidate_counts, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible), digest, "SWAP", ids, sources, destinations)
                        action_candidates.append((key, action, candidate_counts))

        if not action_candidates:
            return _make_result(status="INFEASIBLE", assignments=assignments, initial_assignments=initial_assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=repair_actions, repair_iterations=iteration - 1, termination_reason="NO_REPAIR_ACTION")
        best_key, best_action, best_counts = min(action_candidates, key=lambda item: item[0])
        if best_key[0] >= current_objective:
            return _make_result(status="INFEASIBLE", assignments=assignments, initial_assignments=initial_assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=repair_actions, repair_iterations=iteration - 1, termination_reason="NO_STRICT_IMPROVEMENT")
        for group, destination in zip(best_action["group_ids"], best_action["destination_splits"]):
            assignments[group] = destination
        counts = best_counts
        repair_actions.append({**best_action, "repair_iteration": iteration, "objective_before": _objective_json(current_objective), "objective_after": _objective_json(best_key[0])})
        if not _failed_criteria(counts, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible):
            return _make_result(status="FEASIBLE", assignments=assignments, initial_assignments=initial_assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=repair_actions, repair_iterations=iteration, termination_reason="REPAIR_FEASIBLE")
    return _make_result(status="INFEASIBLE", assignments=assignments, initial_assignments=initial_assignments, vectors=by_id, total_rows=total_rows, stratum_totals=totals, eligible_strata=eligible, repair_actions=repair_actions, repair_iterations=HARD_REPAIR_MAX_ITERATIONS, termination_reason="REPAIR_BUDGET_EXHAUSTED")


def build_hard_group_vectors(rows: object, selection: object, sampling_strata: Mapping[str, str]) -> tuple[list[HardGroupVector], dict[str, int]]:
    """Build V2 vectors from grouped rows and frozen pre-label strata."""

    if not hasattr(selection, "selected_tier") or selection.selected_tier != "HARD_GROUP_ONLY":
        raise ValueError("V2 vectors require HARD_GROUP_ONLY selection")
    row_by_identity = {row.source_record_identity_sha256: row for row in rows}
    if set(row_by_identity) != set(sampling_strata):
        raise ValueError("sampling strata must cover every source record identity")
    totals = {stratum: 0 for stratum in STRATA}
    vectors: list[HardGroupVector] = []
    for gid, members in sorted(selection.groups.items()):
        counts = {stratum: 0 for stratum in STRATA}
        for identity in members:
            stratum = sampling_strata[identity]
            if stratum not in counts:
                raise ValueError(f"unknown sampling stratum: {stratum}")
            counts[stratum] += 1
            totals[stratum] += 1
        vectors.append(HardGroupVector(gid, len(members), counts))
    return vectors, totals


def build_split_rows(rows: object, selection: object, *, allocation: HardAllocationResult | None = None, source_artifact_sha256s: Mapping[str, str] | None = None) -> list[dict[str, object]]:
    """Assign grouped source rows once; amended HARD output uses supplied V2 allocation."""

    if not hasattr(selection, "group_ids") or not hasattr(selection, "selected_tier"):
        raise ValueError("selection must be a TierSelection")
    if selection.selected_tier == "HARD_GROUP_ONLY" and allocation is None:
        raise ValueError("HARD_GROUP_ONLY requires the approved V2 allocation")
    final_actions: dict[str, Mapping[str, object]] = {}
    if allocation is not None:
        for action in allocation.repair_actions:
            for group in action["group_ids"]:
                final_actions[str(group)] = action
    output: list[dict[str, object]] = []
    for row in sorted(rows, key=lambda item: item.source_record_number):
        identity = row.source_record_identity_sha256
        selected_group = selection.group_ids[identity]
        if allocation is None:
            assigned_split = assign_group_split(selected_group)
            schema_version = "1.0"
            split_reason = "HASH_BUCKET_GROUP_ASSIGNMENT"
            namespace = SPLIT_NAMESPACE
            seed = SPLIT_SEED
            bucket = split_bucket(selected_group)
            allocation_fields: dict[str, object] = {}
        else:
            if allocation.status != "FEASIBLE":
                raise ValueError("cannot build split rows from an infeasible allocation")
            assigned_split = allocation.assignments[selected_group]
            schema_version = "1.1"
            split_reason = "HARD_GROUP_STRATIFIED_GREEDY_REPAIR"
            namespace = HARD_ALLOCATOR_NAMESPACE
            seed = HARD_ALLOCATOR_SEED
            bucket = None
            action = final_actions.get(selected_group)
            allocation_fields = {
                "plan_amendment_id": "S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2",
                "allocation_algorithm": HARD_ALLOCATOR_ALGORITHM,
                "allocation_version": HARD_ALLOCATOR_VERSION,
                "allocation_namespace": namespace,
                "allocation_seed": seed,
                "allocation_parameters_sha256": allocation.report["allocation_parameters_sha256"],
                "allocation_objective_sha256": allocation.report["allocation_objective_sha256"],
                "balancing_strata_sha256": allocation.report["balancing_strata_sha256"],
                "group_balance_vector_sha256": allocation.report["group_balance_vector_sha256"],
                "group_order_digest": sha256_hex([namespace, seed, selected_group]),
                "initial_split_assignment": allocation.initial_assignments[selected_group],
                "final_assignment_action": "INITIAL_GREEDY" if action is None else ("REPAIR_" + str(action["action_type"])),
                "repair_iteration": 0 if action is None else action["repair_iteration"],
                "assignment_action_sha256": sha256_hex([namespace, seed, "INITIAL", selected_group, allocation.initial_assignments[selected_group]]) if action is None else action["action_sha256"],
            }
        payload: dict[str, object] = {
            "schema_version": schema_version,
            "dataset_sha256": row.dataset_sha256,
            "source_record_number": row.source_record_number,
            "source_record_id": row.source_record_id,
            "source_record_identity_sha256": identity,
            "annotation_unit_id": f"AU-{identity}",
            "selected_group_tier": selection.selected_tier,
            "group_id": selected_group,
            "hard_component_id": selection.hard_component_ids[identity],
            "exact_duplicate_id": row.exact_duplicate_id,
            "near_duplicate_id": row.near_duplicate_id,
            "session_group_id": row.session_group_id,
            "entity_source_id": row.entity_source_id,
            "entity_destination_id": row.entity_destination_id,
            "entity_host_id": row.entity_host_id,
            "time_policy": "NON_TEMPORAL_UNVERIFIED_TIMESTAMPS",
            "time_value_present": row.time_value_present,
            "split_reason": split_reason,
            "allocation_namespace": namespace,
            "allocation_seed": seed,
            "sampling_frame_eligible": True,
            "leakage_check_status": "PASS",
            "split_assignment": assigned_split,
        }
        if allocation is None:
            payload["allocation_bucket"] = bucket
        if source_artifact_sha256s is not None:
            payload["source_artifact_sha256s"] = dict(source_artifact_sha256s)
        payload.update(allocation_fields)
        output.append(payload)
    return output
