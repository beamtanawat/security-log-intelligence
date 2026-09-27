"""Label-blind duplicate, session, and entity grouping for Stage 2.1."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .identity import sha256_hex, source_record_identity
from .splitting import group_id


def _read(value: object, *path: str) -> object:
    current = value
    for name in path:
        if isinstance(current, Mapping):
            current = current.get(name)
        else:
            current = getattr(current, name, None)
        if current is None:
            return None
    return current


def _source_fields(event: object) -> Mapping[str, object]:
    fields = _read(event, "source_record", "fields")
    if isinstance(fields, Mapping):
        return fields
    if isinstance(event, Mapping):
        return event
    return {}


def _record_number(event: object) -> int:
    value = _read(event, "source_record", "record_number")
    if value is None:
        value = _read(event, "source_record_number")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("source record number must be a positive integer")
    return value


def _record_id(event: object) -> str:
    value = _read(event, "event", "source_record_id")
    if value is None:
        value = _read(event, "source_record_id")
    if not isinstance(value, str) or not value:
        raise ValueError("source record ID must be a non-empty string")
    return value


def _token(event: object, fallback: str) -> object:
    paths = {
        "session": (("session", "identifier"), ("session",)),
        "src": (("network", "source", "identifier"), ("src",)),
        "dst": (("network", "destination", "identifier"), ("dst",)),
        "host": (("host", "identifier"), ("host",)),
    }
    for path in paths[fallback]:
        value = _read(event, *path)
        if value not in (None, ""):
            return value
    return None


def _near_projection(event: object) -> dict[str, object]:
    fields = _source_fields(event)
    if fields and "payload" in fields:
        return {"payload": fields["payload"]}
    return {
        "event.type_source": _read(event, "event", "type_source"),
        "event.subtype_source": _read(event, "event", "subtype_source"),
        "event.action_source": _read(event, "event", "action_source"),
        "event.severity_source": _read(event, "event", "severity_source"),
        "network.protocol_number": _read(event, "network", "protocol_number"),
        "network.source.identifier": _read(event, "network", "source", "identifier"),
        "network.source.port": _read(event, "network", "source", "port"),
        "network.destination.identifier": _read(event, "network", "destination", "identifier"),
        "network.destination.port": _read(event, "network", "destination", "port"),
        "application.service_source": _read(event, "application", "service_source"),
        "session.sent_bytes": _read(event, "session", "sent_bytes"),
        "session.received_bytes": _read(event, "session", "received_bytes"),
        "session.sent_packets": _read(event, "session", "sent_packets"),
        "session.received_packets": _read(event, "session", "received_packets"),
        "session.duration_raw_value": _read(event, "session", "duration_raw_value"),
        "host.identifier": _read(event, "host", "identifier"),
        "threat_observations.action_source": _read(event, "threat_observations", "action_source"),
        "threat_observations.name_source": _read(event, "threat_observations", "name_source"),
        "threat_observations.severity_source": _read(event, "threat_observations", "severity_source"),
        "threat_observations.type_source": _read(event, "threat_observations", "type_source"),
        "threat_observations.pattern_source": _read(event, "threat_observations", "pattern_source"),
        "threat_observations.id_raw": _read(event, "threat_observations", "id_raw"),
        "threat_observations.reference_source": _read(event, "threat_observations", "reference_source"),
    }


@dataclass(frozen=True)
class GroupRow:
    dataset_sha256: str
    source_record_number: int
    source_record_id: str
    source_record_identity_sha256: str
    exact_duplicate_id: str
    near_duplicate_id: str
    session_group_id: str | None
    entity_source_id: str | None
    entity_destination_id: str | None
    entity_host_id: str | None
    time_value_present: bool = False


@dataclass(frozen=True)
class TierSelection:
    selected_tier: str
    hard_component_ids: Mapping[str, str]
    group_ids: Mapping[str, str]
    groups: Mapping[str, tuple[str, ...]]


def _scoped_token(dataset_sha256: str, kind: str, value: object) -> str | None:
    if value in (None, ""):
        return None
    return sha256_hex(["stage-2.1-entity-v1", dataset_sha256, kind, value])


def build_group_rows(events: Iterable[object], *, dataset_sha256: str) -> list[GroupRow]:
    """Extract label-blind grouping identities without interpreting identifiers."""

    rows: list[GroupRow] = []
    seen: set[tuple[int, str]] = set()
    for event in events:
        number = _record_number(event)
        record_id = _record_id(event)
        key = (number, record_id)
        if key in seen:
            raise ValueError("duplicate source record identity")
        seen.add(key)
        identity = source_record_identity(dataset_sha256, number, record_id)
        exact = sha256_hex(["stage-2.1-exact-record-v1", _source_fields(event)])
        near = sha256_hex(["stage-2.1-near-duplicate-v1", _near_projection(event)])
        rows.append(
            GroupRow(
                dataset_sha256=dataset_sha256,
                source_record_number=number,
                source_record_id=record_id,
                source_record_identity_sha256=identity,
                exact_duplicate_id=exact,
                near_duplicate_id=near,
                session_group_id=_scoped_token(dataset_sha256, "session", _token(event, "session")),
                entity_source_id=_scoped_token(dataset_sha256, "source", _token(event, "src")),
                entity_destination_id=_scoped_token(dataset_sha256, "destination", _token(event, "dst")),
                entity_host_id=_scoped_token(dataset_sha256, "host", _token(event, "host")),
                time_value_present=_read(event, "time", "itime_raw") not in (None, ""),
            )
        )
    return sorted(rows, key=lambda row: row.source_record_number)


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _union_by_key(uf: _UnionFind, rows: Iterable[GroupRow], key: str) -> None:
    previous: dict[object, str] = {}
    for row in rows:
        value = getattr(row, key)
        if value is None:
            continue
        if value in previous:
            uf.union(row.source_record_identity_sha256, previous[value])
        else:
            previous[value] = row.source_record_identity_sha256


def _component_ids(uf: _UnionFind) -> dict[str, str]:
    members: dict[str, list[str]] = defaultdict(list)
    for value in uf.parent:
        members[uf.find(value)].append(value)
    result: dict[str, str] = {}
    for values in members.values():
        component = f"HC-{sha256_hex({'contract': 'stage-2.1-hard-v1', 'members': sorted(values)})}"
        result.update({value: component for value in values})
    return result


def build_hard_components(rows: Iterable[GroupRow]) -> dict[str, str]:
    rows = list(rows)
    uf = _UnionFind(row.source_record_identity_sha256 for row in rows)
    for key in ("exact_duplicate_id", "near_duplicate_id", "session_group_id"):
        _union_by_key(uf, rows, key)
    return _component_ids(uf)


def select_entity_tier(rows: Iterable[GroupRow], selected_tier: str) -> TierSelection:
    rows = list(rows)
    if selected_tier not in {"ENTITY_ALL_ENDPOINTS", "ENTITY_SOURCE_HOST", "HARD_GROUP_ONLY"}:
        raise ValueError("unknown entity tier")
    hard = build_hard_components(rows)
    uf = _UnionFind(row.source_record_identity_sha256 for row in rows)
    first_by_component: dict[str, str] = {}
    for value, component in hard.items():
        first_by_component.setdefault(component, value)
    for value, component in hard.items():
        uf.union(value, first_by_component[component])
    keys = ("entity_source_id", "entity_destination_id", "entity_host_id")
    if selected_tier == "ENTITY_SOURCE_HOST":
        keys = ("entity_source_id", "entity_host_id")
    if selected_tier != "HARD_GROUP_ONLY":
        for key in keys:
            _union_by_key(uf, rows, key)
    members: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        members[uf.find(row.source_record_identity_sha256)].append(row.source_record_identity_sha256)
    groups = {group_id(selected_tier, values): tuple(sorted(values)) for values in members.values()}
    mapping = {member: gid for gid, values in groups.items() for member in values}
    return TierSelection(selected_tier, hard, mapping, groups)


def evaluate_tier_feasibility(
    rows: Iterable[GroupRow],
    selection: TierSelection,
    *,
    assignment_by_group: Mapping[str, str] | None = None,
    sampling_strata: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Measure frozen Stage 2.1 criteria for V1 diagnostics or V2 allocation."""

    from .sampling import STRATA
    from .splitting import SPLIT_ORDER, SPLIT_TARGETS, assign_group_split

    rows = list(rows)
    if not rows:
        raise ValueError("cannot evaluate an empty frame")
    assignments = assignment_by_group or {
        group: assign_group_split(group) for group in selection.groups
    }
    split_rows: dict[str, list[GroupRow]] = defaultdict(list)
    for row in rows:
        group = selection.group_ids[row.source_record_identity_sha256]
        if group not in assignments:
            raise ValueError("assignment is missing a selected group")
        split_rows[assignments[group]].append(row)
    failed: list[str] = []
    criteria: dict[str, dict[str, object]] = {}
    if len(selection.groups) < 500:
        failed.append("MINIMUM_GROUP_COUNT")
        criteria["MINIMUM_GROUP_COUNT"] = {"status": "FAIL", "actual": len(selection.groups), "minimum": 500}
    else:
        criteria["MINIMUM_GROUP_COUNT"] = {"status": "PASS", "actual": len(selection.groups), "minimum": 500}
    split_group_counts = {
        name: len({selection.group_ids[row.source_record_identity_sha256] for row in split_rows.get(name, [])})
        for name in SPLIT_ORDER
    }
    for name in SPLIT_ORDER:
        key = f"MINIMUM_SPLIT_GROUP_COUNT_{name}"
        passed = split_group_counts[name] >= 75
        criteria[key] = {"status": "PASS" if passed else "FAIL", "actual": split_group_counts[name], "minimum": 75}
        if not passed:
            failed.append(key)
    split_counts = {name: len(split_rows.get(name, [])) for name in SPLIT_ORDER}
    for name in SPLIT_ORDER:
        key = f"SPLIT_SHARE_{name}"
        share = split_counts[name] / len(rows)
        passed = abs(share - float(SPLIT_TARGETS[name])) <= 0.02
        criteria[key] = {"status": "PASS" if passed else "FAIL", "actual": share, "target": float(SPLIT_TARGETS[name]), "tolerance": 0.02}
        if not passed:
            failed.append(key)
    for name in ("VALIDATION", "TEST"):
        key = f"MINIMUM_{name}_ROWS"
        passed = split_counts[name] >= 1_500
        criteria[key] = {"status": "PASS" if passed else "FAIL", "actual": split_counts[name], "minimum": 1_500}
        if not passed:
            failed.append(key)
    sizes = {group: len(members) for group, members in selection.groups.items()}
    largest = max(sizes.values(), default=0)
    largest_share = largest / len(rows)
    max_passed = largest_share <= 0.10
    criteria["MAX_GROUP_SHARE"] = {"status": "PASS" if max_passed else "FAIL", "actual": largest_share, "maximum": 0.10, "largest_group_size": largest}
    if not max_passed:
        failed.append("MAX_GROUP_SHARE")

    components: dict[str, dict[str, set[str]]] = {}
    for key in ("exact_duplicate_id", "near_duplicate_id", "session_group_id"):
        membership: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            value = getattr(row, key)
            if value is not None:
                membership[value].add(assignments[selection.group_ids[row.source_record_identity_sha256]])
        components[key] = membership
        cross_count = sum(len(splits) > 1 for splits in membership.values())
        criteria[f"{key.upper()}_CROSS_SPLIT"] = {"status": "PASS" if cross_count == 0 else "FAIL", "cross_component_count": cross_count}
        if cross_count:
            failed.append(f"{key.upper()}_CROSS_SPLIT")
    hard_membership: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        hard_membership[selection.hard_component_ids[row.source_record_identity_sha256]].add(assignments[selection.group_ids[row.source_record_identity_sha256]])
    hard_cross_count = sum(len(splits) > 1 for splits in hard_membership.values())
    criteria["HARD_COMPONENT_CROSS_SPLIT"] = {"status": "PASS" if hard_cross_count == 0 else "FAIL", "cross_component_count": hard_cross_count}
    if hard_cross_count:
        failed.append("HARD_COMPONENT_CROSS_SPLIT")

    entity_audit: dict[str, object] = {}
    for key in ("entity_source_id", "entity_destination_id", "entity_host_id"):
        membership = defaultdict(set)
        row_counts = defaultdict(int)
        for row in rows:
            value = getattr(row, key)
            if value is not None:
                split = assignments[selection.group_ids[row.source_record_identity_sha256]]
                membership[value].add(split)
                row_counts[value] += 1
        crossing = [value for value, splits in membership.items() if len(splits) > 1]
        entity_audit[key] = {
            "component_count": len(membership),
            "cross_split_component_count": len(crossing),
            "cross_split_row_count": sum(row_counts[value] for value in crossing),
        }

    stratum_audit: dict[str, object] = {}
    if sampling_strata is not None:
        if set(sampling_strata) != {row.source_record_identity_sha256 for row in rows}:
            raise ValueError("sampling strata must cover every row")
        totals = {stratum: sum(sampling_strata[row.source_record_identity_sha256] == stratum for row in rows) for stratum in STRATA}
        global_shares = {split: split_counts[split] / len(rows) for split in SPLIT_ORDER}
        for stratum in STRATA:
            counts = {split: sum(sampling_strata[row.source_record_identity_sha256] == stratum and assignments[selection.group_ids[row.source_record_identity_sha256]] == split for row in rows) for split in SPLIT_ORDER}
            if totals[stratum] < 100:
                stratum_audit[stratum] = {"row_count": totals[stratum], "eligible": False, "split_counts": counts, "status": "NOT_APPLICABLE"}
                continue
            failures = []
            for split in SPLIT_ORDER:
                difference = counts[split] / totals[stratum] - global_shares[split]
                if abs(difference) > 0.05:
                    failures.append(f"SAMPLING_STRATUM_SHARE_{stratum}_{split}")
            failed.extend(failures)
            stratum_audit[stratum] = {"row_count": totals[stratum], "eligible": True, "split_counts": counts, "split_shares": {split: counts[split] / totals[stratum] for split in SPLIT_ORDER}, "max_absolute_deviation": max(abs(counts[split] / totals[stratum] - global_shares[split]) for split in SPLIT_ORDER), "status": "FAIL" if failures else "PASS"}

    return {
        "status": "PASS" if not failed else "FAIL",
        "selected_tier": selection.selected_tier,
        "row_count": len(rows),
        "group_count": len(selection.groups),
        "split_counts": split_counts,
        "split_shares": {name: split_counts[name] / len(rows) for name in SPLIT_ORDER},
        "split_group_counts": split_group_counts,
        "largest_group_size": largest,
        "max_group_share": largest_share,
        "criteria": criteria,
        "sampling_strata": stratum_audit,
        "entity_overlap_audit": entity_audit,
        "hard_component_cross_split_count": hard_cross_count,
        "temporal_policy": "NON_TEMPORAL_UNVERIFIED_TIMESTAMPS",
        "temporal_checks": {"chronological_split": False, "future_information_used": False},
        "failed_criteria": sorted(set(failed)),
    }
