"""Stage 1.9 deterministic interpretation projection.

This module produces descriptive investigation context.  It deliberately does
not assert attacks, maliciousness, incidents, model confidence, or probability.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from ai_features.models import FeatureRow
from anomaly.models import AnomalyScoreRow

from .drivers import (
    FAMILY_ORDER,
    FeatureDriver,
    ReferenceDriverIndex,
    build_feature_drivers,
)


EXPLANATION_SCHEMA_VERSION = "1.0"
REASON_REGISTRY_VERSION = "1.0"
CANONICAL_BEHAVIORS = (
    "UNUSUAL_TRAFFIC_VOLUME",
    "UNUSUAL_TRAFFIC_DIRECTION",
    "UNUSUAL_SESSION_CHARACTERISTICS",
    "RARE_PORT_OR_SERVICE_CONTEXT",
    "UNUSUAL_PROTOCOL_CONTEXT",
)
_FAMILY_BEHAVIORS = dict(zip(FAMILY_ORDER, CANONICAL_BEHAVIORS, strict=True))
_DISPLAY_CONTEXT_KEYS = (
    "protocol_number",
    "protocol_name",
    "source_port",
    "destination_port",
    "service_source",
    "source_identifier",
    "destination_identifier",
    "sent_bytes",
    "received_bytes",
    "sent_packets",
    "received_packets",
    "duration_raw_value",
    "source_port_missing",
    "destination_port_missing",
    "service_missing",
    "sent_bytes_missing",
    "received_bytes_missing",
    "sent_packets_missing",
    "received_packets_missing",
    "duration_missing",
)


class InterpretationError(ValueError):
    """Raised when a Stage 1.9 interpretation contract cannot be met."""


def _require_matching_provenance(feature: FeatureRow, score: AnomalyScoreRow) -> None:
    if (
        feature.source_record_number != score.source_record_number
        or feature.source_record_id != score.source_record_id
        or feature.partition != score.partition
    ):
        raise InterpretationError("feature and score provenance does not reconcile")
    if score.analyst_review_selected != (score.anomaly_rank <= 50):
        raise InterpretationError("Stage 1.8 Top-50 selection does not match rank")


def _family_best_drivers(drivers: Sequence[FeatureDriver]) -> dict[str, FeatureDriver]:
    best: dict[str, FeatureDriver] = {}
    for driver in drivers:
        current = best.get(driver.family)
        if current is None or (-driver.extremeness, driver.feature_name) < (-current.extremeness, current.feature_name):
            best[driver.family] = driver
    return best


def _qualifying_families(drivers: Sequence[FeatureDriver]) -> tuple[str, ...]:
    """Return each family with an eligible non-missing E>=0.95 driver.

    A more extreme missingness flag may still be a top reason, but cannot mask
    a separate non-missing qualifying driver or decide the behavior taxonomy.
    """

    return tuple(
        family
        for family in FAMILY_ORDER
        if any(
            driver.family == family
            and not driver.is_missingness
            and driver.extremeness >= 0.95
            for driver in drivers
        )
    )


def _top_reasons(best: Mapping[str, FeatureDriver]) -> list[dict[str, object]]:
    candidates = [driver for driver in best.values() if driver.extremeness > 0.0]
    candidates.sort(key=lambda driver: (-driver.extremeness, FAMILY_ORDER.index(driver.family), driver.feature_name))
    return [driver.to_dict() for driver in candidates[:3]]


def _reference_context(context: Mapping[str, object]) -> dict[str, object]:
    rule_ids = context.get("matched_rule_ids", ())
    if not isinstance(rule_ids, Sequence) or isinstance(rule_ids, (str, bytes)):
        raise InterpretationError("matched_rule_ids must be a sequence")
    if any(not isinstance(item, str) or not item for item in rule_ids):
        raise InterpretationError("matched_rule_ids must contain non-empty strings")
    sorted_rule_ids = sorted(set(rule_ids))
    source_threat = bool(context.get("source_threat_observation_present"))
    return {
        "rule_ids": sorted_rule_ids,
        "rule_observation_present": bool(sorted_rule_ids),
        "source_threat_observation_present": source_threat,
        "anomaly_subtype_observation_present": bool(context.get("anomaly_subtype_observation_present")),
        "source_threat_type": context.get("source_threat_type"),
    }


def _display_context(context: Mapping[str, object]) -> dict[str, object]:
    missing = [key for key in _DISPLAY_CONTEXT_KEYS if key not in context]
    if missing:
        raise InterpretationError("operational display context is incomplete")
    return {key: context[key] for key in _DISPLAY_CONTEXT_KEYS}


def _evidence_strength(qualifying: Sequence[str], reference_observation_present: bool, is_top_50: bool) -> str | None:
    if not is_top_50:
        return None
    count = len(qualifying)
    if count >= 2 and reference_observation_present:
        return "HIGH"
    if count >= 1 and (count >= 2 or reference_observation_present):
        return "MEDIUM"
    if count >= 1:
        return "LOW"
    return None


def build_explanation(
    feature: FeatureRow,
    score: AnomalyScoreRow,
    feature_metadata: Mapping[str, object],
    operational_context: Mapping[str, object],
    *,
    reference_index: ReferenceDriverIndex | None = None,
) -> dict[str, object]:
    """Return one canonical, descriptive Stage 1.9 explanation projection."""

    _require_matching_provenance(feature, score)
    drivers = build_feature_drivers(
        feature,
        feature_metadata,
        operational_context,
        reference_index=reference_index,
    )
    best = _family_best_drivers(drivers)
    qualifying = _qualifying_families(drivers)
    selected = score.analyst_review_selected
    behaviors = [_FAMILY_BEHAVIORS[family] for family in qualifying]
    if selected and not behaviors:
        behaviors = ["UNCLASSIFIED_ANOMALOUS_PATTERN"]
    reference_context = _reference_context(operational_context)
    reference_observation_present = bool(
        reference_context["rule_observation_present"]
        or reference_context["source_threat_observation_present"]
    )
    port_or_protocol_qualifies = any(family in {"PORT_SERVICE", "PROTOCOL"} for family in qualifying)
    if not selected:
        attack_type: str | None = None
    elif reference_context["source_threat_type"] == "Reconnaissance" and port_or_protocol_qualifies:
        attack_type = "Possible reconnaissance activity"
    else:
        attack_type = "Unclassified suspicious behavior"
    priority = round(min(100.0, 0.90 * score.anomaly_score + 10.0 * int(reference_observation_present)), 6)
    output = {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "source_record_number": score.source_record_number,
        "source_record_id": score.source_record_id,
        "partition": score.partition,
        "model_score": score.model_score,
        "raw_abnormality": score.raw_abnormality,
        "anomaly_score": score.anomaly_score,
        "anomaly_rank": score.anomaly_rank,
        "anomaly_band": score.anomaly_band,
        "analyst_review_selected": selected,
        "investigation_priority_score": priority,
        "investigation_rank": 0,
        "suspected_behaviors": behaviors,
        "suspected_attack_type": attack_type,
        "evidence_strength": _evidence_strength(qualifying, reference_observation_present, selected),
        "explanation_status": "COMPLETE" if len(_top_reasons(best)) == 3 else "LIMITED",
        "top_reasons": _top_reasons(best),
        "reference_context": reference_context,
        "review_id": None,
        "display_context": _display_context(operational_context),
    }
    return output


def assign_investigation_ranks(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Assign deterministic priority ranks without changing Stage 1.8 rank/selection."""

    copied = [dict(row) for row in rows]
    numbers: set[int] = set()
    for row in copied:
        number = row.get("source_record_number")
        rank = row.get("anomaly_rank")
        priority = row.get("investigation_priority_score")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1 or number in numbers:
            raise InterpretationError("explanation source record numbers must be unique positive integers")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
            raise InterpretationError("explanation anomaly ranks must be positive integers")
        if isinstance(priority, bool) or not isinstance(priority, (int, float)) or not 0 <= float(priority) <= 100:
            raise InterpretationError("investigation priority must be a bounded finite number")
        numbers.add(number)
    ordered = sorted(copied, key=lambda row: (-float(row["investigation_priority_score"]), int(row["anomaly_rank"])))
    for rank, row in enumerate(ordered, start=1):
        row["investigation_rank"] = rank
    return sorted(ordered, key=lambda row: int(row["source_record_number"]))
