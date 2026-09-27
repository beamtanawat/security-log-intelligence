from __future__ import annotations

from labeling.splitting import HardGroupVector, allocate_hard_group_splits


def _vectors(count: int = 1000, *, group_size: int = 40) -> list[HardGroupVector]:
    return [
        HardGroupVector(
            group_id=f"G-{index:04d}",
            group_size=group_size,
            stratum_counts={"HISTORICAL_BASE_0_50": group_size},
        )
        for index in range(count)
    ]


def test_v2_allocator_reaches_exact_balanced_split_without_splitting_groups() -> None:
    result = allocate_hard_group_splits(
        _vectors(),
        total_rows=40000,
        stratum_totals={"HISTORICAL_BASE_0_50": 40000},
    )

    assert result.status == "FEASIBLE"
    assert result.final_split_counts == {"TRAIN": 28000, "VALIDATION": 6000, "TEST": 6000}
    assert result.final_split_group_counts == {"TRAIN": 700, "VALIDATION": 150, "TEST": 150}
    assert all(result.assignments[group_id] in {"TRAIN", "VALIDATION", "TEST"} for group_id in result.assignments)
    assert result.repair_iterations <= 512


def test_v2_allocator_is_byte_deterministic_for_same_vectors() -> None:
    first = allocate_hard_group_splits(
        _vectors(),
        total_rows=40000,
        stratum_totals={"HISTORICAL_BASE_0_50": 40000},
    )
    second = allocate_hard_group_splits(
        _vectors(),
        total_rows=40000,
        stratum_totals={"HISTORICAL_BASE_0_50": 40000},
    )

    assert first.assignments == second.assignments
    assert first.initial_assignments == second.initial_assignments
    assert first.repair_actions == second.repair_actions
    assert first.report == second.report


def test_v2_allocator_rejects_structurally_infeasible_group_frame() -> None:
    result = allocate_hard_group_splits(
        _vectors(499, group_size=1),
        total_rows=499,
        stratum_totals={"HISTORICAL_BASE_0_50": 499},
    )

    assert result.status == "INFEASIBLE"
    assert result.termination_reason == "STRUCTURAL_PRECHECK"
    assert "MINIMUM_GROUP_COUNT" in result.failed_criteria
