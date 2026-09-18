"""Build lossless Stage 2.0 exports from audited Stage 1.9 V3 rows."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class ReportingError(ValueError):
    """Raised when an upstream row cannot satisfy the final package contract."""


FINAL_JSON_FIELDS = (
    "schema_version", "anomaly_rank", "investigation_rank", "source_record_number",
    "source_record_id", "partition", "anomaly_score", "investigation_priority_score",
    "anomaly_band", "auto_triage", "analyst_review_selected", "suspected_behaviors",
    "suspected_attack_type", "evidence_strength", "explanation_status", "top_reasons",
    "rule_observation_present", "rule_ids", "source_threat_observation_present",
    "anomaly_subtype_observation_present", "source_threat_type", "display_context",
    "review_id", "analyst_label", "contextual_label", "review_status",
)

FINAL_CSV_FIELDS = (
    "schema_version", "anomaly_rank", "investigation_rank", "source_record_number",
    "source_record_id", "partition", "anomaly_score", "investigation_priority_score",
    "anomaly_band", "auto_triage", "analyst_review_selected", "suspected_behaviors",
    "suspected_attack_type", "evidence_strength", "explanation_status", "top_reasons",
    "rule_observation_present", "rule_ids", "source_threat_observation_present",
    "anomaly_subtype_observation_present", "source_threat_type", "destination_identifier",
    "destination_port", "destination_port_missing", "duration_missing", "duration_raw_value",
    "protocol_name", "protocol_number", "received_bytes", "received_bytes_missing",
    "received_packets", "received_packets_missing", "sent_bytes", "sent_bytes_missing",
    "sent_packets", "sent_packets_missing", "service_missing", "service_source",
    "source_identifier", "source_port", "source_port_missing", "review_id", "analyst_label",
    "contextual_label", "review_status",
)

CANONICAL_BEHAVIORS = (
    "UNUSUAL_TRAFFIC_VOLUME", "UNUSUAL_TRAFFIC_DIRECTION",
    "UNUSUAL_SESSION_CHARACTERISTICS", "RARE_PORT_OR_SERVICE_CONTEXT",
    "UNUSUAL_PROTOCOL_CONTEXT", "UNCLASSIFIED_ANOMALOUS_PATTERN",
)
ANOMALY_BANDS = ("TOP_0_1_PERCENT", "TOP_1_PERCENT", "TOP_5_PERCENT", "BASELINE")
TRIAGE_VALUES = ("HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST")
EVIDENCE_VALUES = ("HIGH", "MEDIUM", "LOW", None)
REVIEW_VALUES = ("NOT_SELECTED", "PENDING", "REVIEWED_RESOLVED", "REVIEWED_UNCERTAIN")
ATTACK_VALUES = ("Possible reconnaissance activity", "Unclassified suspicious behavior", None)
REFERENCE_CONTEXT_FIELDS = (
    "rule_observation_present",
    "rule_ids",
    "source_threat_observation_present",
    "anomaly_subtype_observation_present",
    "source_threat_type",
)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percent(count: int, total: int) -> float:
    return round((100.0 * count / total) if total else 0.0, 6)


def _require_number(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReportingError(f"{name} must be a positive integer")
    return value


def csv_cell_text(value: object) -> str:
    """Return the contract-preserving text representation for one CSV cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        text = canonical_json(value)
    else:
        text = str(value)
    if text.startswith("'") or (text and text[0] in "=+-@\t\r\n"):
        return "'" + text
    return text


def _display(row: Mapping[str, object], name: str) -> object:
    context = row.get("display_context")
    if not isinstance(context, Mapping):
        return None
    return context.get(name)


def build_final_row(explanation: Mapping[str, object], auto_row: Mapping[str, object]) -> dict[str, object]:
    number = _require_number(explanation.get("source_record_number"), "source_record_number")
    source_id = explanation.get("source_record_id")
    if not isinstance(source_id, str) or not source_id:
        raise ReportingError("source_record_id must be a non-empty string")
    if str(auto_row.get("source_record_number", number)) != str(number) or str(auto_row.get("source_record_id", source_id)) != source_id:
        raise ReportingError("Stage 1.9 explanation and auto-triage identities do not reconcile")
    triage = auto_row.get("auto_triage")
    status = auto_row.get("review_status")
    if triage not in TRIAGE_VALUES or status not in REVIEW_VALUES:
        raise ReportingError("Stage 1.9 auto-triage row has an invalid contract value")
    row = {name: explanation.get(name) for name in FINAL_JSON_FIELDS}
    reference_context = explanation.get("reference_context")
    if reference_context is not None:
        if not isinstance(reference_context, Mapping):
            raise ReportingError("Stage 1.9 reference_context must be an object")
        for name in REFERENCE_CONTEXT_FIELDS:
            row[name] = reference_context.get(name)
    row["source_record_number"] = number
    row["source_record_id"] = source_id
    row["auto_triage"] = triage
    row["review_status"] = status
    row["analyst_label"] = explanation.get("analyst_label")
    row["contextual_label"] = explanation.get("contextual_label")
    for name in ("suspected_behaviors", "top_reasons", "rule_ids"):
        if not isinstance(row[name], list):
            raise ReportingError(f"{name} must be a list")
    if row["suspected_attack_type"] is not None and not isinstance(row["suspected_attack_type"], str):
        raise ReportingError("suspected_attack_type must be a string or null")
    return row


def write_jsonl(path: str | Path, rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(canonical_json(dict(row)) + "\n")
            count += 1
    return count


def write_csv_row(writer: csv.writer, row: Mapping[str, object]) -> None:
    values: list[object] = []
    for name in FINAL_CSV_FIELDS:
        if name in FINAL_JSON_FIELDS:
            value = row.get(name)
        else:
            value = _display(row, name)
        values.append(csv_cell_text(value))
    writer.writerow(values)


def write_csv(path: str | Path, rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(FINAL_CSV_FIELDS)
        for row in rows:
            write_csv_row(writer, row)
            count += 1
    return count


def _distribution(order: Sequence[object], counts: Counter[object], total: int) -> list[dict[str, object]]:
    return [{"value": value, "count": counts[value], "percentage": percent(counts[value], total)} for value in order]


def _quantiles(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {name: None for name in ("min", "p25", "p50", "p75", "p90", "p95", "p99", "max")}
    ordered = sorted(values)
    def at(p: float) -> float:
        index = (len(ordered) - 1) * p
        low = math.floor(index)
        high = math.ceil(index)
        if low == high:
            return round(ordered[low], 6)
        return round(ordered[low] + (ordered[high] - ordered[low]) * (index - low), 6)
    return {"min": round(ordered[0], 6), "p25": at(.25), "p50": at(.50), "p75": at(.75), "p90": at(.90), "p95": at(.95), "p99": at(.99), "max": round(ordered[-1], 6)}


def aggregate_rows(rows: Sequence[Mapping[str, object]], *, feature_count: int) -> dict[str, object]:
    if not rows:
        raise ReportingError("final package requires at least one row")
    total = len(rows)
    partition = Counter(str(row["partition"]) for row in rows)
    triage = Counter(str(row["auto_triage"]) for row in rows)
    bands = Counter(str(row["anomaly_band"]) for row in rows)
    evidence = Counter(row.get("evidence_strength") for row in rows)
    reviews = Counter(str(row["review_status"]) for row in rows)
    attacks = Counter(row.get("suspected_attack_type") for row in rows)
    behaviors = Counter(behavior for row in rows for behavior in row["suspected_behaviors"])
    specific = sum(bool(row["suspected_behaviors"]) and row["suspected_behaviors"] != ["UNCLASSIFIED_ANOMALOUS_PATTERN"] for row in rows)
    fallback = sum("UNCLASSIFIED_ANOMALOUS_PATTERN" in row["suspected_behaviors"] for row in rows)
    any_explanation = sum(bool(row["suspected_behaviors"]) for row in rows)
    top_fallback = sum(int(row["anomaly_rank"]) <= 50 and "UNCLASSIFIED_ANOMALOUS_PATTERN" in row["suspected_behaviors"] for row in rows)
    return {
        "schema_version": "1.0",
        "record_count": total,
        "feature_count": feature_count,
        "partition_counts": {name: partition[name] for name in ("REFERENCE", "HOLDOUT")},
        "partition_distribution": _distribution(("REFERENCE", "HOLDOUT"), partition, total),
        "top_50_count": sum(int(row["anomaly_rank"]) <= 50 for row in rows),
        "auto_triage_counts": {name: triage[name] for name in TRIAGE_VALUES},
        "auto_triage_distribution": _distribution(TRIAGE_VALUES, triage, total),
        "anomaly_band_counts": {name: bands[name] for name in ANOMALY_BANDS},
        "anomaly_band_distribution": _distribution(ANOMALY_BANDS, bands, total),
        "evidence_strength_counts": {"HIGH": evidence["HIGH"], "MEDIUM": evidence["MEDIUM"], "LOW": evidence["LOW"], "NULL": evidence[None]},
        "evidence_strength_distribution": _distribution(EVIDENCE_VALUES, evidence, total),
        "suspected_behavior_counts": {name: behaviors[name] for name in CANONICAL_BEHAVIORS},
        "suspected_behavior_distribution": _distribution(CANONICAL_BEHAVIORS, behaviors, total),
        "suspected_attack_interpretation_counts": {"POSSIBLE_RECONNAISSANCE_ACTIVITY": attacks["Possible reconnaissance activity"], "UNCLASSIFIED_SUSPICIOUS_BEHAVIOR": attacks["Unclassified suspicious behavior"], "NULL": attacks[None]},
        "suspected_attack_interpretation_distribution": _distribution(ATTACK_VALUES, attacks, total),
        "review_counts": {name: reviews[name] for name in REVIEW_VALUES},
        "review_status_distribution": _distribution(REVIEW_VALUES, reviews, total),
        "score_quantiles": _quantiles([float(row["anomaly_score"]) for row in rows]),
        "priority_score_quantiles": _quantiles([float(row["investigation_priority_score"]) for row in rows]),
        "explanation_coverage": {"records_with_specific_suspected_behavior": specific, "records_with_suspected_behavior_or_fallback": any_explanation, "percentage": percent(any_explanation, total)},
        "top_50_fallback_count": top_fallback,
        "security_interpretation": ["ANOMALY != ATTACK", "ANOMALY SCORE != ATTACK PROBABILITY", "HIGH_INTEREST != CONFIRMED ATTACK", "LOW_INTEREST != CONFIRMED BENIGN", "suspected behavior != confirmed malicious behavior"],
        "analyst_review_metrics": {"value": None, "reason": "NO_HUMAN_GROUND_TRUTH"},
    }
