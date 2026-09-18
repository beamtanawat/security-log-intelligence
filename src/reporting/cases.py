"""Deterministic, evidence based case-study selection for Stage 2.0."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def _specific(row: Mapping[str, object]) -> bool:
    behaviors = row.get("suspected_behaviors")
    return isinstance(behaviors, list) and any(value != "UNCLASSIFIED_ANOMALOUS_PATTERN" for value in behaviors)


def _pick(
    rows: Sequence[Mapping[str, object]],
    used: set[int],
    candidates: Sequence[Mapping[str, object]],
    requested: str,
) -> dict[str, object]:
    for row in candidates:
        number = int(row["source_record_number"])
        if number not in used:
            used.add(number)
            return {
                "case_number": len(used),
                "requested_category": requested,
                "actual_category": requested,
                "fallback_reason": None,
                "source_record_number": number,
                "source_record_id": row["source_record_id"],
                "row": dict(row),
            }
    for row in rows:
        number = int(row["source_record_number"])
        if number not in used:
            used.add(number)
            return {
                "case_number": len(used),
                "requested_category": requested,
                "actual_category": "FALLBACK_NEXT_UNUSED_RANK",
                "fallback_reason": f"No unused record matched {requested}.",
                "source_record_number": number,
                "source_record_id": row["source_record_id"],
                "row": dict(row),
            }
    raise ValueError("unable to select a unique case study")


def select_case_studies(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Select four unique rows in anomaly-rank order with explicit fallbacks."""

    ordered = sorted(rows, key=lambda row: int(row["anomaly_rank"]))
    used: set[int] = set()
    selected: list[dict[str, object]] = []
    selected.append(_pick(ordered, used, [row for row in ordered if int(row["anomaly_rank"]) <= 50 and bool(row.get("rule_observation_present"))], "TOP50_WITH_RULE_OBSERVATION"))
    selected.append(_pick(ordered, used, [row for row in ordered if int(row["anomaly_rank"]) <= 50 and not bool(row.get("rule_observation_present"))], "TOP50_WITHOUT_RULE_OBSERVATION"))
    selected.append(_pick(ordered, used, [row for row in ordered if int(row["anomaly_rank"]) > 50 and bool(row.get("rule_observation_present"))], "REFERENCE_OBSERVATION_OUTSIDE_TOP50"))
    selected.append(_pick(ordered, used, [row for row in ordered if int(row["anomaly_rank"]) > 50 and row.get("auto_triage") == "MEDIUM_INTEREST" and _specific(row)], "MEDIUM_INTEREST_SPECIFIC_BEHAVIOR"))
    return selected
