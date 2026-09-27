"""Deterministic Stage 2.1 precision-first proxy labeling.

This module uses only frozen source-record predicates. It never calls an AI
service, reads model outputs, or writes canonical labels.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ai_features.models import FEATURE_NAMES

from .identity import sha256_hex, source_record_identity


PRECISION_FIRST_POLICY_VERSION = "stage_2_1_precision_first_proxy_policy/1.0"
RULE_REGISTRY_VERSION = "stage_2_1_precision_first_rule_registry/1.0"
DRY_RUN_SCHEMA_VERSION = "stage_2_1_precision_first_dry_run/1.0"
LABEL_SOURCE_EXCLUSION_SCHEMA_VERSION = "stage_2_1_label_source_exclusion_manifest/1.0"
PRECISION_FIRST_PROVENANCE = "PRECISION_FIRST_PROXY_LABEL"
HIGH_CONFIDENCE_PROXY = "HIGH_CONFIDENCE_PROXY"

ATTACK_RULE_IDS = (
    "PF_ATTACK_CONTROL_CORROBORATION_V1",
    "PF_ATTACK_SIGNATURE_INTEGRITY_V1",
)
BENIGN_RULE_IDS = (
    "PF_BENIGN_SESSION_COMPLETION_V1",
    "PF_BENIGN_APPCTRL_CORROBORATION_V1",
)

_ATTACK_MESSAGE_SWEEP = re.compile(
    r"^anomaly: icmp_sweep, ([0-9]+) > threshold 100, repeats ([1-9][0-9]*) times since last log, pps ([1-9][0-9]*) of prior second$"
)
_ATTACK_MESSAGE_SESSION = re.compile(
    r"^anomaly: icmp_src_session, ([0-9]+) > threshold 300, repeats ([1-9][0-9]*) times since last log$"
)
_THREAT_FIELDS = (
    "threat_action",
    "threat_name",
    "threat_severity",
    "threat_type",
    "threat_pattern",
    "threat_id",
    "threat_ref",
)
_DISALLOWED_ACTIONS = frozenset({"deny", "timeout", "server-rst", "client-rst", "clear_session"})
_PROHIBITED_LABEL_KEYS = frozenset(
    {
        "anomaly_score",
        "raw_abnormality",
        "anomaly_rank",
        "top_n",
        "top_50",
        "anomaly_band",
        "stage_1_9_explanation",
        "stage_1_9_reason",
        "stage_1_9_suspected_behavior",
        "suspected_behavior",
        "suspected_behaviors",
        "suspected_attack_type",
        "auto_triage",
        "investigation_priority",
        "stage_2_prediction",
        "supervised_prediction",
        "feature_vector",
        "label",
        "label_provenance",
        "sampling_stratum",
        "selection_probability",
        "cohort",
        "split_assignment",
        "label_yield",
    }
)


def _normal_key(value: object) -> str:
    return str(value).lower().replace("-", "_").replace(" ", "_")


def _contains_prohibited(value: object, path: str = "") -> str | None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _normal_key(key) in _PROHIBITED_LABEL_KEYS:
                return f"{path}/{key}"
            found = _contains_prohibited(child, f"{path}/{key}")
            if found:
                return found
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            found = _contains_prohibited(child, f"{path}/{index}")
            if found:
                return found
    return None


def _source_record(record: Mapping[str, object]) -> Mapping[str, object]:
    source = record.get("source_record")
    return source if isinstance(source, Mapping) else {}


def _raw(record: Mapping[str, object], field: str) -> object:
    return _source_record(record).get(field)


def _text(record: Mapping[str, object], field: str) -> str:
    value = _raw(record, field)
    return value if isinstance(value, str) else "" if value is None else str(value)


def _nonempty(value: object) -> bool:
    return value is not None and str(value).strip() != ""


def _equal(record: Mapping[str, object], field: str, expected: str) -> bool:
    return _text(record, field) == expected


def _strict_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value):
        return int(value)
    return None


def _record_number(record: Mapping[str, object]) -> int | None:
    source = record.get("source")
    if not isinstance(source, Mapping):
        return None
    value = source.get("record_number")
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _source_id(record: Mapping[str, object]) -> str | None:
    event = record.get("event")
    if not isinstance(event, Mapping):
        return None
    value = event.get("source_record_id")
    return value if isinstance(value, str) and value else None


def _identity_check(
    record: Mapping[str, object],
    *,
    dataset_sha256: str,
    expected_identity: str | None = None,
) -> tuple[bool, str | None]:
    number = _record_number(record)
    source_id = _source_id(record)
    raw_id = _raw(record, "loguid")
    if number is None or source_id is None or raw_id != source_id:
        return False, None
    try:
        identity = source_record_identity(dataset_sha256, number, source_id)
    except (TypeError, ValueError):
        return False, None
    return expected_identity in (None, identity), identity


def _predicate_issue(record: Mapping[str, object], *, require_itime: bool = False) -> bool:
    issues = record.get("normalization_issues", [])
    if not isinstance(issues, list):
        return True
    for issue in issues:
        if not isinstance(issue, Mapping):
            return True
        code = issue.get("issue_code")
        if code == "MISSING_PORTS_EXPECTED_FOR_ICMP":
            continue
        if code == "ALL_SESSION_METRICS_MISSING":
            continue
        if code == "MISSING_ITIME" and not require_itime:
            continue
        return True
    return False


def _threat_present(record: Mapping[str, object]) -> bool:
    return any(_nonempty(_raw(record, field)) for field in _THREAT_FIELDS)


def _action_disallowed(record: Mapping[str, object]) -> bool:
    return _text(record, "event_action").lower() in _DISALLOWED_ACTIONS


def _attack_control(record: Mapping[str, object]) -> bool:
    expected = {
        "event_type": "utm",
        "event_subtype": "anomaly",
        "event_action": "clear_session",
        "event_severity": "alert",
        "threat_action": "blocked",
        "threat_severity": "medium",
        "threat_type": "Reconnaissance",
    }
    return all(_equal(record, field, value) for field, value in expected.items())


def _attack_signature(record: Mapping[str, object]) -> bool:
    if not _equal(record, "net_proto", "1") or not _equal(record, "app_service", "PING"):
        return False
    message = _text(record, "event_message")
    sweep = (
        _equal(record, "threat_name", "icmp_sweep")
        and _equal(record, "threat_pattern", "icmp_sweep")
        and _equal(record, "threat_id", "16777320")
        and _equal(record, "threat_ref", "http://www.fortinet.com/ids/VID16777320")
        and (match := _ATTACK_MESSAGE_SWEEP.fullmatch(message)) is not None
        and int(match.group(1)) > 100
    )
    session = (
        _equal(record, "threat_name", "icmp_src_session")
        and _equal(record, "threat_pattern", "icmp_src_session")
        and _equal(record, "threat_id", "16777321")
        and _equal(record, "threat_ref", "http://www.fortinet.com/ids/VID16777321")
        and (match := _ATTACK_MESSAGE_SESSION.fullmatch(message)) is not None
        and int(match.group(1)) > 300
    )
    return int(sweep) + int(session) == 1


def _time(record: Mapping[str, object]) -> int | None:
    return _strict_int(_raw(record, "itime"))


def _session_id(record: Mapping[str, object]) -> str:
    return _text(record, "net_sessionid")


def _port_equal(left: object, right: object, *, protocol: str) -> bool:
    if _nonempty(left) and _nonempty(right):
        return str(left) == str(right)
    return protocol == "1" and not _nonempty(left) and not _nonempty(right)


def _session_identity_equal(target: Mapping[str, object], context: Mapping[str, object]) -> bool:
    for field in ("src_ip", "dst_ip", "net_sessionid", "net_proto", "app_service"):
        left = _text(target, field)
        right = _text(context, field)
        if not left or left != right:
            return False
    protocol = _text(target, "net_proto")
    return _port_equal(_raw(target, "src_port"), _raw(context, "src_port"), protocol=protocol) and _port_equal(
        _raw(target, "dst_port"), _raw(context, "dst_port"), protocol=protocol
    )


def _start_shape(record: Mapping[str, object]) -> bool:
    return all(
        _equal(record, field, value)
        for field, value in {
            "event_type": "traffic",
            "event_subtype": "forward",
            "event_action": "start",
            "event_severity": "notice",
        }.items()
    )


def _appctrl_shape(record: Mapping[str, object]) -> bool:
    return all(
        _equal(record, field, value)
        for field, value in {
            "event_type": "utm",
            "event_subtype": "app-ctrl",
            "event_action": "pass",
            "event_severity": "information",
        }.items()
    )


def _target_accept_shape(record: Mapping[str, object]) -> bool:
    return all(
        _equal(record, field, value)
        for field, value in {
            "event_type": "traffic",
            "event_subtype": "forward",
            "event_action": "accept",
            "event_severity": "notice",
        }.items()
    )


def _benign_common_safety(records: Sequence[Mapping[str, object]]) -> bool:
    return all(
        not _threat_present(record)
        and not _action_disallowed(record)
        and _text(record, "event_subtype") in {"forward", "app-ctrl"}
        and not _predicate_issue(record, require_itime=True)
        for record in records
    )


def _benign_session(target: Mapping[str, object], context: Sequence[Mapping[str, object]]) -> bool:
    if not _target_accept_shape(target) or len(context) not in {1, 2}:
        return False
    if not _benign_common_safety([target, *context]):
        return False
    starts = [record for record in context if _start_shape(record)]
    appctrls = [record for record in context if _appctrl_shape(record)]
    if len(starts) != 1 or len(appctrls) > 1 or len(starts) + len(appctrls) != len(context):
        return False
    return all(_session_identity_equal(target, record) for record in context)


def _benign_appctrl(target: Mapping[str, object], context: Sequence[Mapping[str, object]]) -> bool:
    expected_target = {
        "net_proto": "17",
        "src_port": "123",
        "dst_port": "123",
        "app_service": "junos-ntp",
        "app_id": "16270",
        "app_name": "NTP",
        "app_cat": "Network.Service",
    }
    if not _target_accept_shape(target) or len(context) != 2:
        return False
    if not all(_equal(target, field, value) for field, value in expected_target.items()):
        return False
    if not _benign_common_safety([target, *context]):
        return False
    starts = [record for record in context if _start_shape(record)]
    appctrls = [record for record in context if _appctrl_shape(record)]
    if len(starts) != 1 or len(appctrls) != 1:
        return False
    appctrl = appctrls[0]
    expected_appctrl = {
        **expected_target,
        "event_message": "Network.Service: NTP",
    }
    if not all(_equal(appctrl, field, value) for field, value in expected_appctrl.items()):
        return False
    return all(_session_identity_equal(target, record) for record in context)


def _base_decision(
    record: Mapping[str, object],
    *,
    dataset_sha256: str,
    expected_identity: str | None,
) -> tuple[dict[str, object], bool, str | None]:
    prohibited = _contains_prohibited(record)
    identity_ok, identity = _identity_check(
        record,
        dataset_sha256=dataset_sha256,
        expected_identity=expected_identity,
    )
    invalid = prohibited is not None or not identity_ok
    return (
        {
            "schema_version": "1.0",
            "candidate_label": "UNCERTAIN",
            "label_quality_tier": None,
            "label_provenance": PRECISION_FIRST_PROVENANCE,
            "matched_rule_ids": [],
            "failed_rule_ids": list(ATTACK_RULE_IDS + BENIGN_RULE_IDS),
            "predicate_results": {
                "A_CONTROL": False,
                "A_SIGNATURE": False,
                "B_SESSION": False,
                "B_APPCTRL": False,
            },
            "context_record_identity_sha256s": [],
            "decision_reason_code": "INVALID_INPUT" if invalid else "INSUFFICIENT_EVIDENCE",
            "invalid": invalid,
            "conflict": False,
            "insufficient_evidence": not invalid,
            "source_record_identity_sha256": identity,
        },
        invalid,
        prohibited,
    )


def evaluate_record(
    record: Mapping[str, object],
    *,
    dataset_sha256: str,
    split_assignment: str,
    context_records: Sequence[Mapping[str, object]] = (),
    expected_identity: str | None = None,
) -> dict[str, object]:
    """Evaluate one record under frozen Section 16C predicates."""

    decision, invalid, _ = _base_decision(
        record,
        dataset_sha256=dataset_sha256,
        expected_identity=expected_identity,
    )
    if split_assignment not in {"TRAIN", "VALIDATION", "TEST"}:
        decision["invalid"] = True
        decision["insufficient_evidence"] = False
        decision["decision_reason_code"] = "INVALID_SPLIT"
        return decision
    if invalid:
        return decision

    ordered_context = sorted(
        context_records,
        key=lambda value: (_time(value) if _time(value) is not None else -10**30, _record_number(value) or 0),
    )
    context_identities: list[str] = []
    context_invalid = False
    for context in ordered_context:
        valid, identity = _identity_check(context, dataset_sha256=dataset_sha256)
        if not valid or identity is None:
            context_invalid = True
            continue
        if _contains_prohibited(context) is not None:
            context_invalid = True
            continue
        context_identities.append(identity)
    if context_invalid:
        decision["invalid"] = True
        decision["insufficient_evidence"] = False
        decision["decision_reason_code"] = "INVALID_CONTEXT"
        ordered_context = []
    decision["context_record_identity_sha256s"] = sorted(set(context_identities))

    a_control = _attack_control(record)
    a_signature = _attack_signature(record)
    b_session = _benign_session(record, ordered_context)
    b_appctrl = _benign_appctrl(record, ordered_context)
    predicates = decision["predicate_results"]
    predicates.update(
        {
            "A_CONTROL": a_control,
            "A_SIGNATURE": a_signature,
            "B_SESSION": b_session,
            "B_APPCTRL": b_appctrl,
        }
    )
    attack_complete = a_control and a_signature
    benign_complete = b_session and b_appctrl
    decision["conflict"] = attack_complete and benign_complete
    decision["insufficient_evidence"] = not decision["invalid"] and not decision["conflict"]
    if attack_complete and not b_session and not b_appctrl:
        decision["candidate_label"] = "ATTACK"
        decision["label_quality_tier"] = HIGH_CONFIDENCE_PROXY
        decision["matched_rule_ids"] = list(ATTACK_RULE_IDS)
        decision["failed_rule_ids"] = list(BENIGN_RULE_IDS)
        decision["decision_reason_code"] = "ATTACK_CONJUNCTION_MATCH"
        decision["insufficient_evidence"] = False
    elif benign_complete and not a_control and not a_signature:
        decision["candidate_label"] = "BENIGN"
        decision["label_quality_tier"] = HIGH_CONFIDENCE_PROXY
        decision["matched_rule_ids"] = list(BENIGN_RULE_IDS)
        decision["failed_rule_ids"] = list(ATTACK_RULE_IDS)
        decision["decision_reason_code"] = "BENIGN_CONJUNCTION_MATCH"
        decision["insufficient_evidence"] = False
    elif decision["conflict"]:
        decision["decision_reason_code"] = "RULE_CONFLICT"
        decision["insufficient_evidence"] = False
    elif not decision["invalid"]:
        decision["decision_reason_code"] = "INSUFFICIENT_EVIDENCE"
    return decision


def _context_records(
    target: Mapping[str, object],
    *,
    events: Mapping[int, Mapping[str, object]],
    rows: Mapping[int, Mapping[str, object]],
    split_assignment: str,
    session_group_splits: Mapping[str, set[str]],
    session_index: Mapping[tuple[str, str], Sequence[Mapping[str, object]]] | None = None,
) -> list[Mapping[str, object]]:
    session = _session_id(target)
    target_time = _time(target)
    target_number = _record_number(target)
    if not session or target_time is None or target_number is None:
        return []
    target_row = rows.get(target_number, {})
    group_id = target_row.get("session_group_id")
    if isinstance(group_id, str) and session_group_splits.get(group_id, {split_assignment}) != {split_assignment}:
        return []
    candidates: list[tuple[int, int, str, Mapping[str, object]]] = []
    candidate_events = (
        session_index.get((split_assignment, session), ())
        if session_index is not None
        else events.values()
    )
    for event in candidate_events:
        number = _record_number(event)
        if number is None or number == target_number:
            continue
        row = rows.get(number)
        if not isinstance(row, Mapping) or row.get("split_assignment") != split_assignment:
            continue
        if _session_id(event) != session:
            continue
        event_time = _time(event)
        if event_time is None or event_time >= target_time:
            continue
        source_id = _source_id(event) or ""
        candidates.append((-event_time, number, source_id, event))
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in candidates[:2]]


def _empty_invalid_decision() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "candidate_label": "UNCERTAIN",
        "label_quality_tier": None,
        "label_provenance": PRECISION_FIRST_PROVENANCE,
        "matched_rule_ids": [],
        "failed_rule_ids": list(ATTACK_RULE_IDS + BENIGN_RULE_IDS),
        "predicate_results": {"A_CONTROL": False, "A_SIGNATURE": False, "B_SESSION": False, "B_APPCTRL": False},
        "context_record_identity_sha256s": [],
        "decision_reason_code": "INVALID_INPUT",
        "invalid": True,
        "conflict": False,
        "insufficient_evidence": False,
        "source_record_identity_sha256": None,
    }


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 6) if denominator else 0.0


def run_dry_run(
    records: Sequence[Mapping[str, object]],
    split_rows: Sequence[Mapping[str, object]],
    *,
    dataset_sha256: str,
) -> dict[str, object]:
    """Run public TRAIN/VALIDATION dry run. TEST rows are never evaluated."""

    rows = {
        int(row["source_record_number"]): row
        for row in split_rows
        if isinstance(row.get("source_record_number"), int)
        and row.get("split_assignment") in {"TRAIN", "VALIDATION"}
    }
    all_rows = {
        int(row["source_record_number"]): row
        for row in split_rows
        if isinstance(row.get("source_record_number"), int)
    }
    events = {
        number: record
        for record in records
        if (number := _record_number(record)) in rows
    }
    session_index: dict[tuple[str, str], list[Mapping[str, object]]] = {}
    for number, event in events.items():
        row = rows[number]
        session = _session_id(event)
        if session:
            session_index.setdefault((str(row["split_assignment"]), session), []).append(event)
    session_group_splits: dict[str, set[str]] = {}
    for row in split_rows:
        group_id = row.get("session_group_id")
        split = row.get("split_assignment")
        if isinstance(group_id, str) and isinstance(split, str):
            session_group_splits.setdefault(group_id, set()).add(split)

    by_split: dict[str, list[dict[str, object]]] = {"TRAIN": [], "VALIDATION": []}
    for number in sorted(rows):
        row = rows[number]
        split = str(row["split_assignment"])
        event = events.get(number)
        if event is None:
            decision = _empty_invalid_decision()
        else:
            context = _context_records(
                event,
                events=events,
                rows=all_rows,
                split_assignment=split,
                session_group_splits=session_group_splits,
                session_index=session_index,
            )
            decision = evaluate_record(
                event,
                dataset_sha256=dataset_sha256,
                split_assignment=split,
                context_records=context,
                expected_identity=row.get("source_record_identity_sha256") if isinstance(row.get("source_record_identity_sha256"), str) else None,
            )
        decision["source_record_number"] = number
        decision["split_assignment"] = split
        decision["group_id"] = row.get("hard_component_id") or row.get("group_id")
        by_split[split].append(decision)

    summary: dict[str, object] = {
        "schema_version": DRY_RUN_SCHEMA_VERSION,
        "mode": "DRY_RUN",
        "policy_version": PRECISION_FIRST_POLICY_VERSION,
        "rule_registry_version": RULE_REGISTRY_VERSION,
        "test_label_sufficiency": "NOT_YET_AVAILABLE",
        "splits": {},
        "decisions": [decision for split in ("TRAIN", "VALIDATION") for decision in by_split[split]],
    }
    for split, decisions in by_split.items():
        counts = {label: sum(decision["candidate_label"] == label for decision in decisions) for label in ("ATTACK", "BENIGN", "UNCERTAIN")}
        attack_denominator = sum(
            bool(decision["predicate_results"]["A_CONTROL"] or decision["predicate_results"]["A_SIGNATURE"])
            for decision in decisions
        )
        benign_denominator = sum(
            bool(decision["predicate_results"]["B_SESSION"] or decision["predicate_results"]["B_APPCTRL"])
            for decision in decisions
        )
        split_summary = {
            "counts": counts,
            "total": len(decisions),
            "resolved_percentage": _pct(counts["ATTACK"] + counts["BENIGN"], len(decisions)),
            "uncertain_percentage": _pct(counts["UNCERTAIN"], len(decisions)),
            "attack_agreement": (
                _pct(
                    sum(decision["predicate_results"]["A_CONTROL"] and decision["predicate_results"]["A_SIGNATURE"] for decision in decisions),
                    attack_denominator,
                )
                if attack_denominator
                else None
            ),
            "benign_agreement": (
                _pct(
                    sum(decision["predicate_results"]["B_SESSION"] and decision["predicate_results"]["B_APPCTRL"] for decision in decisions),
                    benign_denominator,
                )
                if benign_denominator
                else None
            ),
            "conflicts": sum(bool(decision["conflict"]) for decision in decisions),
            "insufficient_evidence": sum(bool(decision["insufficient_evidence"]) for decision in decisions),
            "invalid_unclassifiable": sum(bool(decision["invalid"]) for decision in decisions),
        }
        summary["splits"][split] = split_summary
    return summary


def _metric_int(record: Mapping[str, object], field: str) -> int | None:
    session = record.get("session")
    if not isinstance(session, Mapping):
        return None
    value = session.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _feature_values_17_36(record: Mapping[str, object]) -> tuple[float, ...] | None:
    sent_bytes = _metric_int(record, "sent_bytes")
    received_bytes = _metric_int(record, "received_bytes")
    sent_packets = _metric_int(record, "sent_packets")
    received_packets = _metric_int(record, "received_packets")
    duration = _metric_int(record, "duration_raw_value")
    sb = sent_bytes or 0
    rb = received_bytes or 0
    sp = sent_packets or 0
    rp = received_packets or 0
    complete_bytes = sent_bytes is not None and received_bytes is not None
    complete_packets = sent_packets is not None and received_packets is not None
    total_bytes = sb + rb if complete_bytes else 0
    total_packets = sp + rp if complete_packets else 0
    try:
        values = (
            math.log1p(sb),
            math.log1p(rb),
            math.log1p(sp),
            math.log1p(rp),
            math.log1p(duration or 0),
            math.log1p(total_bytes),
            math.log1p(total_packets),
            float(sb / total_bytes) if complete_bytes and total_bytes > 0 else 0.5,
            float(sp / total_packets) if complete_packets and total_packets > 0 else 0.5,
            math.log1p(sb / sp) if sent_bytes is not None and sent_packets is not None and sp > 0 else 0.0,
            math.log1p(rb / rp) if received_bytes is not None and received_packets is not None and rp > 0 else 0.0,
            float(sent_bytes is None),
            float(received_bytes is None),
            float(sent_packets is None),
            float(received_packets is None),
            float(duration is None),
            float(complete_bytes and total_bytes == 0),
            float(complete_packets and total_packets == 0),
            float(sent_packets is not None and sp == 0),
            float(received_packets is not None and rp == 0),
        )
    except (OverflowError, ZeroDivisionError, ValueError):
        return None
    return values if all(math.isfinite(value) for value in values) else None


def _perfect_reconstruction(values: Sequence[tuple[float, str, str]]) -> bool:
    if not values:
        return False
    labels = {label for _, label, _ in values}
    if labels != {"ATTACK", "BENIGN"}:
        return False
    class_groups = {label: {group for _, current, group in values if current == label} for label in labels}
    if any(len(groups) < 2 for groups in class_groups.values()):
        return False
    unique = sorted({value for value, _, _ in values})
    candidates: list[tuple[str, float]] = [("EQ", value) for value in unique]
    candidates.extend(("LE", (left + right) / 2.0) for left, right in zip(unique, unique[1:]))
    for kind, threshold in candidates:
        for direction in ("ATTACK", "BENIGN"):
            predicted = {
                (value == threshold if kind == "EQ" else value <= threshold): direction
                for value, _, _ in values
            }
            if kind == "EQ":
                valid = all((value == threshold and label == direction) or (value != threshold and label != direction) for value, label, _ in values)
            else:
                valid = all((value <= threshold and label == direction) or (value > threshold and label != direction) for value, label, _ in values)
            if valid and predicted:
                return True
    return False


def audit_feature_leakage(
    records: Sequence[Mapping[str, object]],
    split_rows: Sequence[Mapping[str, object]],
    decisions: Sequence[Mapping[str, object]],
    *,
    dataset_sha256: str,
) -> dict[str, object]:
    """Audit all 36 features against resolved TRAIN proxy labels only."""

    row_by_number = {
        int(row["source_record_number"]): row
        for row in split_rows
        if isinstance(row.get("source_record_number"), int)
    }
    record_by_number = {
        number: record
        for record in records
        if (number := _record_number(record)) is not None
    }
    resolved: list[tuple[Mapping[str, object], str, str]] = []
    for decision in decisions:
        if decision.get("split_assignment") != "TRAIN" or decision.get("candidate_label") not in {"ATTACK", "BENIGN"}:
            continue
        number = decision.get("source_record_number")
        if not isinstance(number, int) or number not in record_by_number:
            continue
        row = row_by_number.get(number, {})
        group = row.get("hard_component_id") or row.get("group_id") or f"record:{number}"
        resolved.append((record_by_number[number], str(decision["candidate_label"]), str(group)))

    result: dict[str, object] = {
        "schema_version": LABEL_SOURCE_EXCLUSION_SCHEMA_VERSION,
        "status": "PASS",
        "features": {},
        "excluded_features": [],
        "review_required_features": [],
        "resolved_train_rows": len(resolved),
    }
    direct = set(FEATURE_NAMES[:12]) | {FEATURE_NAMES[15]}
    derived = set(FEATURE_NAMES[12:15])
    for index, name in enumerate(FEATURE_NAMES, start=1):
        if name in direct:
            classification = "EXCLUDED_LABEL_SOURCE"
            reason = "Feature derives directly from protocol, port, or service fields used by Section 16C predicates."
            allowed = False
        elif name in derived:
            classification = "EXCLUDED_DERIVED_FROM_LABEL_SOURCE"
            reason = "Feature is a rarity/derived statistic over protocol, port, or service label-source fields."
            allowed = False
        else:
            feature_index = index - 17
            values: list[tuple[float, str, str]] = []
            for record, label, group in resolved:
                vector = _feature_values_17_36(record)
                if vector is not None:
                    values.append((vector[feature_index], label, group))
            groups_by_label = {
                label: {group for _, current, group in values if current == label}
                for label in ("ATTACK", "BENIGN")
            }
            if len(groups_by_label["ATTACK"]) < 2 or len(groups_by_label["BENIGN"]) < 2:
                classification = "REQUIRES_REVIEW"
                reason = "TRAIN exact-reconstruction audit inconclusive with fewer than two independent groups per class; feature remains excluded."
                allowed = False
                result["review_required_features"].append(name)
            elif _perfect_reconstruction(values):
                classification = "EXCLUDED_DERIVED_FROM_LABEL_SOURCE"
                reason = "TRAIN exact-reconstruction audit found a perfect single-feature binary reconstruction."
                allowed = False
                result["excluded_features"].append(name)
            else:
                classification = "ALLOWED"
                reason = "No exact single-feature reconstruction found under the frozen TRAIN audit."
                allowed = True
        if not allowed and name not in result["review_required_features"] and name not in result["excluded_features"]:
            result["excluded_features"].append(name)
        result["features"][name] = {
            "position": index,
            "classification": classification,
            "allow": allowed,
            "reason": reason,
        }
    result["exclusion_manifest_sha256"] = sha256_hex(result["features"])
    return result
