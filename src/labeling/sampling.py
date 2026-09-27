"""Deterministic Stage 2.1 strata and sampling primitives."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .identity import canonical_json_bytes, digest_order


STRATA = (
    "SOURCE_OR_RULE_CONTEXT",
    "HISTORICAL_TOP_0_1",
    "HISTORICAL_TOP_1",
    "HISTORICAL_TOP_5",
    "HISTORICAL_MID_50_95",
    "HISTORICAL_BASE_0_50",
)
VALIDATION_PURPOSES = ("VALIDATION_U", "VALIDATION_S", "VALIDATION_CHAIN")


def classify_stratum(*, source_or_rule: bool, percentile: float | None) -> str:
    if source_or_rule:
        return STRATA[0]
    if percentile is None:
        return STRATA[-1]
    if percentile >= 99.9:
        return STRATA[1]
    if percentile >= 99.0:
        return STRATA[2]
    if percentile >= 95.0:
        return STRATA[3]
    if percentile >= 50.0:
        return STRATA[4]
    return STRATA[5]


def allocate_hybrid(frame_sizes: Mapping[str, int], budget: int) -> dict[str, int]:
    """Allocate a fixed budget with the approved 50/50 hybrid formula."""

    if isinstance(budget, bool) or budget < 0 or not isinstance(budget, int):
        raise ValueError("budget must be a non-negative integer")
    sizes: dict[str, int] = {}
    for key, value in frame_sizes.items():
        if not isinstance(key, str) or not key:
            raise ValueError("frame stratum names must be non-empty strings")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("frame stratum sizes must be non-negative integers")
        if value:
            sizes[key] = value
    if not sizes:
        return {}
    total = sum(sizes.values())
    target = min(budget, total)
    strata = [key for key in STRATA if key in sizes] + [key for key in sizes if key not in STRATA]
    h = len(strata)
    raw = {key: 0.5 * target * (sizes[key] / total) + 0.5 * target * (1 / h) for key in strata}
    allocation = {key: min(sizes[key], int(raw[key])) for key in strata}
    remaining = target - sum(allocation.values())
    while remaining:
        candidates = [key for key in strata if allocation[key] < sizes[key]]
        if not candidates:
            break
        candidates.sort(key=lambda key: (-(raw[key] - int(raw[key])), strata.index(key)))
        for key in candidates:
            if remaining == 0:
                break
            if allocation[key] < sizes[key]:
                allocation[key] += 1
                remaining -= 1
        raw = {key: raw[key] for key in strata}
    return allocation


def deterministic_selection_digest(namespace: str, seed: int, source_record_identity_sha256: str) -> str:
    return digest_order(namespace, seed, source_record_identity_sha256)[0]


def assign_validation_purpose(group_id: str) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(["stage-2.1-validation-purpose-v1", 21012102, group_id])
    ).digest()
    bucket = int.from_bytes(digest[:8], "big") % 10_000
    if bucket < 3_000:
        return "VALIDATION_U"
    if bucket < 6_500:
        return "VALIDATION_S"
    return "VALIDATION_CHAIN"
