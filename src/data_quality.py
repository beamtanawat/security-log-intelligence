"""Field-inventory primitives for Stage 1.2 data-quality analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field as dataclass_field
from math import ceil
import re
from statistics import median
from typing import Any


@dataclass(frozen=True)
class FieldDefinition:
    """Cautious metadata for one known FortiGate CSV field."""

    group: str
    likely_meaning: str
    observed_representation: str
    nullable_behavior: str
    source_status: str
    confidence: str
    unresolved_question: str


def _field(
    group: str,
    likely_meaning: str,
    observed_representation: str,
    nullable_behavior: str,
    source_status: str,
    confidence: str,
    unresolved_question: str,
) -> FieldDefinition:
    return FieldDefinition(
        group=group,
        likely_meaning=likely_meaning,
        observed_representation=observed_representation,
        nullable_behavior=nullable_behavior,
        source_status=source_status,
        confidence=confidence,
        unresolved_question=unresolved_question,
    )


# Order matches the verified 58-column Stage 1.1 header.
FIELD_DEFINITIONS: dict[str, FieldDefinition] = {
    "itime": _field(
        "Timestamp",
        "FortiGate event time.",
        "Integer-like raw timestamp value.",
        "One missing value in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Confirm epoch-second interpretation and inspect the missing record context.",
    ),
    "adom_oid": _field(
        "Parser/Source Metadata",
        "FortiManager administrative-domain identifier or related source value.",
        "Integer-like source-specific value.",
        "No Stage 1.1 missingness issue recorded.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm authoritative FortiGate/FortiManager semantics.",
    ),
    "app_cat": _field(
        "Application",
        "Application category supplied by the source product.",
        "Categorical string.",
        "18 missing values; otherwise mostly unscanned in Stage 1.1.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Identify event contexts for blank and non-unscanned values.",
    ),
    "app_service": _field(
        "Application",
        "Service label supplied or inferred by the source product.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Check alignment with protocol and port without treating labels as ground truth.",
    ),
    "data_parsername": _field(
        "Parser/Source Metadata",
        "Name of the parser that produced the record.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "HIGH",
        "None currently; observed value identifies a FortiGate parser.",
    ),
    "data_sourceid": _field(
        "Parser/Source Metadata",
        "Source-system identifier supplied with the log.",
        "Opaque identifier string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm whether the value is a device, collector, or source identifier.",
    ),
    "data_sourcename": _field(
        "Parser/Source Metadata",
        "Sanitized source-device name.",
        "Opaque tokenized string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm source naming semantics without deanonymizing tokens.",
    ),
    "data_sourcetype": _field(
        "Parser/Source Metadata",
        "Log-source product type.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "None currently; observed value is FortiGate.",
    ),
    "data_timestamp": _field(
        "Timestamp",
        "Source-specific timestamp-related value.",
        "Integer-like raw value.",
        "No missing values; observed range is 0 to 731.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Determine whether this is a sequence, offset, relative time, or another value; do not assume epoch time.",
    ),
    "dst_geo": _field(
        "Destination",
        "Destination geography label supplied by the source product.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm lookup/enrichment semantics and coverage limitations.",
    ),
    "dst_intf": _field(
        "Destination",
        "Destination network-interface identifier.",
        "Opaque tokenized string.",
        "18 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Identify the event context for missing interface values.",
    ),
    "dst_ip": _field(
        "Destination",
        "Destination network identifier.",
        "Opaque sanitized identifier string; not validated as a literal IP address.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "None currently; retain token form without enrichment or decoding.",
    ),
    "dst_mac": _field(
        "Destination",
        "Destination link-layer identifier when supplied.",
        "Opaque sanitized identifier string; not validated as a literal MAC address.",
        "48,071 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine whether population depends on local network or event context.",
    ),
    "dst_port": _field(
        "Destination",
        "Destination transport-layer port when applicable.",
        "Integer-like raw value.",
        "27,447 missing values, matching the protocol-1 count; requires row-level confirmation.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "Verify port population by protocol without filling missing values.",
    ),
    "epid": _field(
        "Parser/Source Metadata",
        "Source-specific event or process identifier.",
        "Integer-like source-specific value.",
        "No Stage 1.1 missingness issue recorded.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm authoritative source semantics.",
    ),
    "euid": _field(
        "Parser/Source Metadata",
        "Source-specific event/user identifier.",
        "Integer-like source-specific value.",
        "No Stage 1.1 missingness issue recorded.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm authoritative source semantics.",
    ),
    "event_action": _field(
        "Event",
        "Action or lifecycle outcome recorded for the event.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "Determine lifecycle relationships for repeated sessions.",
    ),
    "event_id": _field(
        "Event",
        "Source event identifier.",
        "Integer-like raw value.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm mappings to FortiGate event families.",
    ),
    "event_severity": _field(
        "Event",
        "Severity label provided by the source product.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Confirm source severity scale; it is not an independent risk score.",
    ),
    "event_subtype": _field(
        "Event",
        "Source event subtype.",
        "Categorical string.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Confirm subtype semantics across traffic and UTM records.",
    ),
    "event_type": _field(
        "Event",
        "Top-level source event family.",
        "Categorical string.",
        "No missing values; traffic and UTM are observed values.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "None currently; retain source labels.",
    ),
    "host_ip": _field(
        "Host",
        "Host network identifier associated with the event.",
        "Opaque sanitized identifier string; not validated as a literal IP address.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Confirm relationship to source and destination roles by event context.",
    ),
    "host_location": _field(
        "Host",
        "Host location label supplied by the source product.",
        "Categorical or opaque string.",
        "No Stage 1.1 missingness issue recorded.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm whether it is a logical, physical, or inventory location.",
    ),
    "host_mac": _field(
        "Host",
        "Host link-layer identifier when supplied.",
        "Opaque sanitized identifier string; not validated as a literal MAC address.",
        "46,437 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine population context and relationship to source MAC.",
    ),
    "host_type": _field(
        "Host",
        "Source product's host-type value.",
        "Categorical string.",
        "46,437 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm host-type taxonomy and when it is populated.",
    ),
    "loguid": _field(
        "Event",
        "Log-record identifier.",
        "Opaque tokenized identifier string.",
        "No missing values; 100,000 unique values in Stage 1.1.",
        "SOURCE_SPECIFIC",
        "HIGH",
        "Confirm scope of uniqueness across exports or sources.",
    ),
    "net_proto": _field(
        "Network",
        "Network protocol number.",
        "Integer-like raw protocol identifier.",
        "No missing values; observed values include 1, 6, and 17.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "Derived names may be documented separately while preserving raw values.",
    ),
    "net_rcvdpkts": _field(
        "Session",
        "Packets received for the reported session record.",
        "Integer-like count.",
        "778 missing values; determine whether this shares the common session-metric mask.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Explain missingness by lifecycle or event context.",
    ),
    "net_recvbytes": _field(
        "Session",
        "Bytes received for the reported session record.",
        "Integer-like count.",
        "778 missing values; determine whether this shares the common session-metric mask.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Explain missingness by lifecycle or event context.",
    ),
    "net_sentbytes": _field(
        "Session",
        "Bytes sent for the reported session record.",
        "Integer-like count.",
        "778 missing values; determine whether this shares the common session-metric mask.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Explain missingness by lifecycle or event context.",
    ),
    "net_sentpkts": _field(
        "Session",
        "Packets sent for the reported session record.",
        "Integer-like count.",
        "778 missing values; determine whether this shares the common session-metric mask.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Explain missingness by lifecycle or event context.",
    ),
    "net_sessionduration": _field(
        "Session",
        "Session duration reported by the source product.",
        "Integer-like raw duration value.",
        "778 missing values; unit and lifecycle relationship require confirmation.",
        "POTENTIALLY_COMMON",
        "MEDIUM",
        "Confirm duration unit and common missing-row mask.",
    ),
    "net_sessionid": _field(
        "Session",
        "Source session identifier.",
        "Opaque identifier represented as an integer-like string.",
        "No missing values; repeated values are expected and not duplicates.",
        "SOURCE_SPECIFIC",
        "HIGH",
        "Characterize repeated-session lifecycle behavior without deduplication.",
    ),
    "src_geo": _field(
        "Source",
        "Source geography label supplied by the source product.",
        "Categorical string.",
        "No missing values; Reserved is observed for all Stage 1.1 records.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm lookup/enrichment semantics and Reserved meaning.",
    ),
    "src_intf": _field(
        "Source",
        "Source network-interface identifier.",
        "Opaque tokenized string.",
        "No missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm whether it is ingress interface context.",
    ),
    "src_ip": _field(
        "Source",
        "Source network identifier.",
        "Opaque sanitized identifier string; not validated as a literal IP address.",
        "No missing values in the Stage 1.1 baseline.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "None currently; retain token form without enrichment or decoding.",
    ),
    "src_mac": _field(
        "Source",
        "Source link-layer identifier when supplied.",
        "Opaque sanitized identifier string; not validated as a literal MAC address.",
        "46,437 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine population context and relationship to host MAC.",
    ),
    "src_port": _field(
        "Source",
        "Source transport-layer port when applicable.",
        "Integer-like raw value.",
        "27,447 missing values, matching the protocol-1 count; requires row-level confirmation.",
        "POTENTIALLY_COMMON",
        "HIGH",
        "Verify port population by protocol without filling missing values.",
    ),
    "event_profile": _field(
        "Event",
        "Source profile associated with selected events.",
        "Opaque tokenized string.",
        "99,769 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Identify event contexts for profile population.",
    ),
    "host_osver": _field(
        "Host",
        "Host operating-system version when supplied.",
        "Categorical or opaque string.",
        "86 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm inventory/enrichment source and population conditions.",
    ),
    "src_natip": _field(
        "NAT",
        "Source NAT network identifier when source NAT applies.",
        "Opaque sanitized identifier string; not validated as a literal IP address.",
        "98,350 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine whether presence is limited to source-NAT events.",
    ),
    "src_natport": _field(
        "NAT",
        "Source NAT port when source NAT applies.",
        "Integer-like raw value.",
        "98,350 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine whether presence is limited to source-NAT events and interpret zero carefully.",
    ),
    "host_hwvendor": _field(
        "Host",
        "Host hardware-vendor value when supplied.",
        "Categorical or opaque string.",
        "77,669 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm inventory source and population context.",
    ),
    "host_hwver": _field(
        "Host",
        "Host hardware-version value when supplied.",
        "Categorical or opaque string.",
        "77,669 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm inventory source and population context.",
    ),
    "host_osfamily": _field(
        "Host",
        "Host operating-system family when supplied.",
        "Categorical string.",
        "77,669 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm inventory/enrichment source and population conditions.",
    ),
    "host_osname": _field(
        "Host",
        "Host operating-system name when supplied.",
        "Categorical string.",
        "77,669 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm inventory/enrichment source and population conditions.",
    ),
    "host_name": _field(
        "Host",
        "Host-name value when supplied.",
        "Opaque tokenized string.",
        "79,300 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine relationship to host inventory and source domain values.",
    ),
    "src_domain": _field(
        "Source",
        "Source-domain value when supplied.",
        "Opaque tokenized string.",
        "79,300 missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Determine relationship to host inventory and host-name values.",
    ),
    "threat_action": _field(
        "Threat",
        "Action reported by the source product for a threat-related observation.",
        "Categorical string.",
        "25 non-missing values; sparse population is expected to require event context.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Describe only as a product observation, not ground-truth attack evidence.",
    ),
    "threat_name": _field(
        "Threat",
        "Threat-related name reported by the source product.",
        "Categorical string.",
        "25 non-missing values; sparse population is expected to require event context.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Describe only as a product observation, not ground-truth attack evidence.",
    ),
    "threat_severity": _field(
        "Threat",
        "Threat severity label reported by the source product.",
        "Categorical string.",
        "25 non-missing values; sparse population is expected to require event context.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Confirm source severity semantics; do not use as an independent risk score.",
    ),
    "threat_type": _field(
        "Threat",
        "Threat category reported by the source product.",
        "Categorical string.",
        "25 non-missing values; sparse population is expected to require event context.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Describe only as a product observation, not ground-truth attack evidence.",
    ),
    "app_id": _field(
        "Application",
        "Source product's application identifier when an application is identified.",
        "Integer-like raw value.",
        "129 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Identify relationship to app_name and app_cat without filling blanks.",
    ),
    "app_name": _field(
        "Application",
        "Application name when identified by the source product.",
        "Categorical string.",
        "129 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Identify relationship to app_id, app_cat, service, and event context.",
    ),
    "threat_pattern": _field(
        "Threat",
        "Source-specific threat pattern value when supplied.",
        "Categorical or opaque string.",
        "19 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm product semantics and relation to threat fields.",
    ),
    "event_message": _field(
        "Event",
        "Human-readable event message when supplied.",
        "Free-text string.",
        "30 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "MEDIUM",
        "Summarize only in bounded, non-sensitive aggregates or minimal examples.",
    ),
    "threat_id": _field(
        "Threat",
        "Source product's threat identifier when supplied.",
        "Integer-like raw value.",
        "18 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm relation to threat names and patterns.",
    ),
    "threat_ref": _field(
        "Threat",
        "Source-specific threat reference when supplied.",
        "Categorical or opaque string.",
        "18 non-missing values in the Stage 1.1 baseline.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        "Confirm reference semantics without external enrichment.",
    ),
}

KNOWN_FORTIGATE_COLUMNS = tuple(FIELD_DEFINITIONS)

SESSION_METRIC_FIELDS = (
    "net_rcvdpkts",
    "net_recvbytes",
    "net_sentbytes",
    "net_sentpkts",
    "net_sessionduration",
)

CONDITIONAL_MISSING_FIELDS = (
    "itime",
    "src_port",
    "dst_port",
    *SESSION_METRIC_FIELDS,
    "app_name",
    "threat_action",
    "src_natip",
)

CONDITIONAL_GROUPINGS = (
    ("event_type",),
    ("event_subtype",),
    ("event_action",),
    ("net_proto",),
    ("app_service",),
    ("threat_presence",),
    ("event_type", "event_action"),
)

OPTIONAL_CONTEXT_FIELDS = ("threat_action", "app_name", "src_natip")
THREAT_PRESENCE_FIELDS = (
    "threat_action",
    "threat_name",
    "threat_severity",
    "threat_type",
    "threat_pattern",
    "threat_id",
    "threat_ref",
)
MISSING_GROUP_VALUE = "<MISSING>"
DERIVED_PROTOCOL_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP"}
APPLICATION_FIELDS = ("app_cat", "app_name", "app_id")
NUMERIC_SERVICE_PATTERN = re.compile(r"^(tcp|udp)/(\d+)$", re.IGNORECASE)
SESSION_LIFECYCLE_FIELDS = ("event_type", "event_subtype", "event_action")
SESSION_MISSING_CONTEXT_FIELDS = (
    "event_type",
    "event_subtype",
    "event_action",
    "net_proto",
    "app_service",
    "threat_presence",
)
SESSION_SIZE_BUCKETS = (
    ("1", 1, 1),
    ("2", 2, 2),
    ("3-5", 3, 5),
    ("6-10", 6, 10),
    ("11+", 11, None),
)


def _unknown_definition(field: str) -> FieldDefinition:
    return _field(
        "Unknown",
        "Not documented by the current FortiGate field inventory.",
        "Unknown until measured from source values.",
        "Requires measurement; do not discard or fill values.",
        "SOURCE_SPECIFIC",
        "NEEDS VERIFICATION",
        f"Confirm the source semantics of unexpected column '{field}'.",
    )


def build_field_inventory(columns: Sequence[str]) -> list[dict[str, Any]]:
    """Return one cautious inventory entry for every supplied header column.

    The function validates no field values. In particular, sanitized IP- and
    MAC-like tokens remain opaque strings rather than literal addresses.
    """

    column_names = list(columns)
    if len(set(column_names)) != len(column_names):
        raise ValueError("CSV header contains duplicate column names")

    inventory: list[dict[str, Any]] = []
    for field in column_names:
        definition = FIELD_DEFINITIONS.get(field, _unknown_definition(field))
        entry = {"field": field, **asdict(definition)}
        inventory.append(entry)

    return inventory


def validate_inventory_complete(
    columns: Sequence[str], inventory: Sequence[dict[str, Any]]
) -> None:
    """Raise ValueError unless an inventory contains each header field once."""

    expected = list(columns)
    reported = [entry.get("field") for entry in inventory]
    if reported != expected:
        raise ValueError("inventory fields do not match the CSV header order")
    if len(set(reported)) != len(reported):
        raise ValueError("inventory contains duplicate fields")


def is_missing(value: str | None) -> bool:
    """Return True for a missing CSV value without changing the raw value."""

    return value is None or not value.strip()


def percentage(numerator: int, denominator: int) -> float:
    """Return a deterministic percentage and handle an empty group safely."""

    if denominator == 0:
        return 0.0
    return round(100 * numerator / denominator, 6)


def _group_value(value: str | None) -> str:
    return MISSING_GROUP_VALUE if is_missing(value) else value


def _row_group_value(row: Mapping[str, str | None], field: str) -> str:
    if field == "threat_presence":
        return (
            "present"
            if any(not is_missing(row.get(threat_field)) for threat_field in THREAT_PRESENCE_FIELDS)
            else "absent"
        )
    return _group_value(row.get(field))


def _group_sort_key(values: tuple[str, ...]) -> tuple[tuple[int, int | str], ...]:
    """Sort numeric-looking group values numerically and other values as text."""

    parts: list[tuple[int, int | str]] = []
    for value in values:
        try:
            parts.append((0, int(value)))
        except ValueError:
            parts.append((1, value))
    return tuple(parts)


def derived_protocol_name(protocol: str | None) -> str | None:
    """Return a clearly derived standard name while preserving the raw number."""

    if is_missing(protocol):
        return None
    return DERIVED_PROTOCOL_NAMES.get(protocol)


def _numeric_service_hint(service: str | None) -> tuple[str, str] | None:
    """Return a derived transport/port hint only for labels such as tcp/8080."""

    if is_missing(service):
        return None
    match = NUMERIC_SERVICE_PATTERN.fullmatch(service)
    if match is None:
        return None
    transport, port = match.groups()
    return transport.lower(), port


def _nearest_rank_percentile(
    values: Sequence[int], percentile: int
) -> int | None:
    """Return a deterministic nearest-rank percentile for integer group sizes."""

    if not values:
        return None
    if not 0 <= percentile <= 100:
        raise ValueError("percentile must be between 0 and 100")

    ordered_values = sorted(values)
    if percentile == 0:
        return ordered_values[0]
    rank = ceil(percentile / 100 * len(ordered_values))
    return ordered_values[rank - 1]


def _session_size_bucket(size: int) -> str:
    """Return one bounded distribution bucket for a records-per-session count."""

    for label, minimum, maximum in SESSION_SIZE_BUCKETS:
        if size >= minimum and (maximum is None or size <= maximum):
            return label
    raise ValueError("session size must be positive")


@dataclass
class _SessionStats:
    """Aggregate state for one opaque session identifier.

    It retains only counters, a first non-missing metric value, and a variation
    flag. It does not retain raw records or deduplicate them.
    """

    record_count: int = 0
    lifecycle_counts: dict[str, Counter[str]] = dataclass_field(
        default_factory=lambda: {
            field: Counter() for field in SESSION_LIFECYCLE_FIELDS
        }
    )
    metric_counts: dict[str, Counter[str]] = dataclass_field(
        default_factory=lambda: {field: Counter() for field in SESSION_METRIC_FIELDS}
    )
    first_non_missing_metric_values: dict[str, str] = dataclass_field(
        default_factory=dict
    )
    varying_metric_fields: set[str] = dataclass_field(default_factory=set)
    all_metrics_missing_record_count: int = 0


class SessionBehaviorAccumulator:
    """One-pass, aggregate session analysis for Stage 1.2D.

    Raw ``net_sessionid`` values are grouping keys only. Repeated keys retain all
    records and are never considered duplicate records by this accumulator.
    """

    def __init__(
        self,
        *,
        lifecycle_value_limit: int = 20,
        missing_context_value_limit: int = 20,
    ) -> None:
        if lifecycle_value_limit < 1 or missing_context_value_limit < 1:
            raise ValueError("session summary limits must be at least 1")
        self.lifecycle_value_limit = lifecycle_value_limit
        self.missing_context_value_limit = missing_context_value_limit
        self.row_count = 0
        self.missing_session_identifier_record_count = 0
        self._sessions: dict[str, _SessionStats] = {}
        self._all_metrics_missing_context: dict[str, Counter[str]] = {
            field: Counter() for field in SESSION_MISSING_CONTEXT_FIELDS
        }
        self._all_metrics_missing_event_type_action: Counter[tuple[str, str]] = Counter()

    def add_row(self, row: Mapping[str, str | None]) -> None:
        """Add one record without retaining the record or modifying any value."""

        self.row_count += 1
        raw_session_id = row.get("net_sessionid")
        if is_missing(raw_session_id):
            self.missing_session_identifier_record_count += 1
        session_id = _group_value(raw_session_id)
        stats = self._sessions.setdefault(session_id, _SessionStats())
        stats.record_count += 1

        for field in SESSION_LIFECYCLE_FIELDS:
            stats.lifecycle_counts[field][_group_value(row.get(field))] += 1

        missing_metric_fields = tuple(
            field for field in SESSION_METRIC_FIELDS if is_missing(row.get(field))
        )
        for field in SESSION_METRIC_FIELDS:
            raw_value = row.get(field)
            metric_counts = stats.metric_counts[field]
            if is_missing(raw_value):
                metric_counts["missing_count"] += 1
                continue

            metric_counts["non_missing_count"] += 1
            first_value = stats.first_non_missing_metric_values.setdefault(field, raw_value)
            if raw_value != first_value:
                stats.varying_metric_fields.add(field)

        if missing_metric_fields == SESSION_METRIC_FIELDS:
            stats.all_metrics_missing_record_count += 1
            self._add_all_metrics_missing_context(row)

    def _add_all_metrics_missing_context(self, row: Mapping[str, str | None]) -> None:
        for field, counts in self._all_metrics_missing_context.items():
            counts[_row_group_value(row, field)] += 1
        self._all_metrics_missing_event_type_action[
            (_group_value(row.get("event_type")), _group_value(row.get("event_action")))
        ] += 1

    def as_dict(self) -> dict[str, Any]:
        """Return bounded, JSON-ready session findings with explicit denominators."""

        session_sizes = [stats.record_count for stats in self._sessions.values()]
        repeated_sessions = [
            stats for stats in self._sessions.values() if stats.record_count > 1
        ]
        single_record_session_count = len(session_sizes) - len(repeated_sessions)
        repeated_record_count = sum(stats.record_count for stats in repeated_sessions)

        return {
            "interpretation": (
                "Records are grouped by raw net_sessionid without deduplication; "
                "a repeated session identifier is not an exact duplicate record."
            ),
            "record_count": self.row_count,
            "unique_session_count": len(session_sizes),
            "missing_session_identifier_record_count": self.missing_session_identifier_record_count,
            "single_record_session_count": single_record_session_count,
            "repeated_session_count": len(repeated_sessions),
            "single_record_session_record_count": single_record_session_count,
            "repeated_session_record_count": repeated_record_count,
            "session_group_size_statistics": self._group_size_statistics(session_sizes),
            "session_group_size_distribution": self._group_size_distribution(session_sizes),
            "repeated_session_lifecycle": self._repeated_lifecycle_result(
                repeated_sessions
            ),
            "repeated_session_metric_comparison": self._repeated_metric_result(
                repeated_sessions, repeated_record_count
            ),
            "all_metrics_missing_context": self._all_metrics_missing_context_result(),
        }

    def _group_size_statistics(self, session_sizes: Sequence[int]) -> dict[str, Any]:
        return {
            "denominator_session_count": len(session_sizes),
            "minimum_records_per_session": min(session_sizes) if session_sizes else None,
            "maximum_records_per_session": max(session_sizes) if session_sizes else None,
            "median_records_per_session": median(session_sizes) if session_sizes else None,
            "nearest_rank_percentiles": {
                "p50": _nearest_rank_percentile(session_sizes, 50),
                "p75": _nearest_rank_percentile(session_sizes, 75),
                "p90": _nearest_rank_percentile(session_sizes, 90),
                "p95": _nearest_rank_percentile(session_sizes, 95),
            },
        }

    def _group_size_distribution(
        self, session_sizes: Sequence[int]
    ) -> list[dict[str, Any]]:
        bucket_counts = Counter(_session_size_bucket(size) for size in session_sizes)
        return [
            {
                "records_per_session": label,
                "session_count": bucket_counts[label],
                "represented_record_count": sum(
                    size for size in session_sizes if _session_size_bucket(size) == label
                ),
                "percentage_of_sessions": percentage(bucket_counts[label], len(session_sizes)),
            }
            for label, _, _ in SESSION_SIZE_BUCKETS
            if bucket_counts[label]
        ]

    def _repeated_lifecycle_result(
        self, repeated_sessions: Sequence[_SessionStats]
    ) -> dict[str, Any]:
        field_summaries: list[dict[str, Any]] = []
        for field in SESSION_LIFECYCLE_FIELDS:
            sessions_per_value: Counter[str] = Counter()
            records_per_value: Counter[str] = Counter()
            for stats in repeated_sessions:
                for value, record_count in stats.lifecycle_counts[field].items():
                    sessions_per_value[value] += 1
                    records_per_value[value] += record_count

            ordered_values = sorted(
                sessions_per_value,
                key=lambda value: (-sessions_per_value[value], value),
            )
            selected_values = ordered_values[: self.lifecycle_value_limit]
            field_summaries.append(
                {
                    "field": field,
                    "reported_value_count": len(selected_values),
                    "omitted_value_count": len(ordered_values) - len(selected_values),
                    "values": [
                        {
                            "value": value,
                            "session_count": sessions_per_value[value],
                            "record_count": records_per_value[value],
                            "percentage_of_repeated_sessions": percentage(
                                sessions_per_value[value], len(repeated_sessions)
                            ),
                        }
                        for value in selected_values
                    ],
                }
            )

        multiple_actions = sum(
            len(stats.lifecycle_counts["event_action"]) > 1
            for stats in repeated_sessions
        )
        multiple_subtypes = sum(
            len(stats.lifecycle_counts["event_subtype"]) > 1
            for stats in repeated_sessions
        )
        return {
            "denominator_repeated_session_count": len(repeated_sessions),
            "sessions_with_multiple_event_actions_count": multiple_actions,
            "sessions_with_multiple_event_subtypes_count": multiple_subtypes,
            "field_value_presence": field_summaries,
        }

    def _repeated_metric_result(
        self,
        repeated_sessions: Sequence[_SessionStats],
        repeated_record_count: int,
    ) -> dict[str, Any]:
        fields: dict[str, dict[str, Any]] = {}
        for field in SESSION_METRIC_FIELDS:
            missing_record_count = 0
            non_missing_record_count = 0
            all_missing_session_count = 0
            all_populated_session_count = 0
            mixed_population_session_count = 0
            varying_value_session_count = 0
            for stats in repeated_sessions:
                counts = stats.metric_counts[field]
                missing_count = counts["missing_count"]
                non_missing_count = counts["non_missing_count"]
                missing_record_count += missing_count
                non_missing_record_count += non_missing_count
                if non_missing_count == 0:
                    all_missing_session_count += 1
                elif missing_count == 0:
                    all_populated_session_count += 1
                else:
                    mixed_population_session_count += 1
                if field in stats.varying_metric_fields:
                    varying_value_session_count += 1

            fields[field] = {
                "missing_record_count": missing_record_count,
                "non_missing_record_count": non_missing_record_count,
                "denominator_repeated_record_count": repeated_record_count,
                "all_missing_session_count": all_missing_session_count,
                "all_populated_session_count": all_populated_session_count,
                "mixed_population_session_count": mixed_population_session_count,
                "sessions_with_varying_non_missing_raw_values_count": varying_value_session_count,
            }
        return {
            "denominator_repeated_session_count": len(repeated_sessions),
            "denominator_repeated_record_count": repeated_record_count,
            "fields": fields,
        }

    def _all_metrics_missing_context_result(self) -> dict[str, Any]:
        all_missing_count = sum(self._all_metrics_missing_event_type_action.values())
        context: list[dict[str, Any]] = []
        for field, counts in self._all_metrics_missing_context.items():
            ordered_values = sorted(counts, key=lambda value: (-counts[value], value))
            selected_values = ordered_values[: self.missing_context_value_limit]
            context.append(
                {
                    "field": field,
                    "reported_value_count": len(selected_values),
                    "omitted_value_count": len(ordered_values) - len(selected_values),
                    "values": [
                        {
                            "value": value,
                            "row_count": counts[value],
                            "percentage_of_all_metrics_missing_rows": percentage(
                                counts[value], all_missing_count
                            ),
                        }
                        for value in selected_values
                    ],
                }
            )

        ordered_combinations = sorted(
            self._all_metrics_missing_event_type_action,
            key=lambda values: (-self._all_metrics_missing_event_type_action[values], values),
        )
        selected_combinations = ordered_combinations[: self.missing_context_value_limit]
        return {
            "all_metrics_missing_record_count": all_missing_count,
            "denominator_row_count": self.row_count,
            "data_quality_status": "UNKNOWN",
            "context": context,
            "event_type_action": [
                {
                    "event_type": event_type,
                    "event_action": event_action,
                    "row_count": self._all_metrics_missing_event_type_action[
                        (event_type, event_action)
                    ],
                    "percentage_of_all_metrics_missing_rows": percentage(
                        self._all_metrics_missing_event_type_action[
                            (event_type, event_action)
                        ],
                        all_missing_count,
                    ),
                }
                for event_type, event_action in selected_combinations
            ],
            "omitted_event_type_action_count": len(ordered_combinations)
            - len(selected_combinations),
        }


class ContextualMissingnessAccumulator:
    """Bounded-memory counters for one pass over valid CSV records."""

    def __init__(
        self,
        *,
        target_fields: Sequence[str] = CONDITIONAL_MISSING_FIELDS,
        groupings: Sequence[Sequence[str]] = CONDITIONAL_GROUPINGS,
        service_group_limit: int = 20,
        services_per_group: int = 10,
        numeric_service_label_limit: int = 20,
    ) -> None:
        if service_group_limit < 1 or services_per_group < 1 or numeric_service_label_limit < 1:
            raise ValueError("service-summary limits must be at least 1")
        self.target_fields = tuple(target_fields)
        self.groupings = tuple(tuple(grouping) for grouping in groupings)
        self.service_group_limit = service_group_limit
        self.services_per_group = services_per_group
        self.numeric_service_label_limit = numeric_service_label_limit
        self.row_count = 0
        self._conditional_counts: dict[
            tuple[str, ...], dict[tuple[str, ...], dict[str, Any]]
        ] = {grouping: {} for grouping in self.groupings}
        self._port_counts: dict[str, Counter[str]] = {}
        self._session_metric_patterns: Counter[tuple[str, ...]] = Counter()
        self._missing_itime_count = 0
        self._missing_itime_context: dict[str, Counter[str]] = {
            field: Counter()
            for field in (
                "event_type",
                "event_subtype",
                "event_action",
                "net_proto",
                "app_service",
                "data_sourcetype",
            )
        }
        self._optional_population: dict[str, dict[str, Counter[str]]] = {}
        self._services_by_protocol_port: dict[tuple[str, str], dict[str, Any]] = {}
        self._app_fields_by_protocol: dict[str, dict[str, Counter[str]]] = {}
        self._numeric_service_labels: dict[str, Counter[str]] = {}
        self._non_numeric_service_row_count = 0
        self._session_behavior = SessionBehaviorAccumulator()

    def add_row(self, row: Mapping[str, str | None]) -> None:
        """Add one parsed CSV row without retaining the full record."""

        self.row_count += 1
        self._add_conditional_counts(row)
        self._add_port_counts(row)
        self._add_session_metric_pattern(row)
        self._add_missing_itime_context(row)
        self._add_optional_population(row)
        self._add_application_relationships(row)
        self._session_behavior.add_row(row)

    def _add_conditional_counts(self, row: Mapping[str, str | None]) -> None:
        for grouping in self.groupings:
            group_values = tuple(_row_group_value(row, field) for field in grouping)
            grouping_counts = self._conditional_counts[grouping]
            group_stats = grouping_counts.setdefault(
                group_values,
                {
                    "row_count": 0,
                    "fields": {
                        field: {"missing_count": 0, "non_missing_count": 0}
                        for field in self.target_fields
                    },
                },
            )
            group_stats["row_count"] += 1
            for field in self.target_fields:
                count_name = "missing_count" if is_missing(row.get(field)) else "non_missing_count"
                group_stats["fields"][field][count_name] += 1

    def _add_port_counts(self, row: Mapping[str, str | None]) -> None:
        protocol = _group_value(row.get("net_proto"))
        counts = self._port_counts.setdefault(protocol, Counter())
        source_missing = is_missing(row.get("src_port"))
        destination_missing = is_missing(row.get("dst_port"))
        if source_missing and destination_missing:
            population = "both_missing"
        elif source_missing:
            population = "source_only_missing"
        elif destination_missing:
            population = "destination_only_missing"
        else:
            population = "both_populated"
        counts["row_count"] += 1
        counts[population] += 1

    def _add_session_metric_pattern(self, row: Mapping[str, str | None]) -> None:
        missing_fields = tuple(
            field for field in SESSION_METRIC_FIELDS if is_missing(row.get(field))
        )
        self._session_metric_patterns[missing_fields] += 1

    def _add_missing_itime_context(self, row: Mapping[str, str | None]) -> None:
        if not is_missing(row.get("itime")):
            return
        self._missing_itime_count += 1
        for field, counter in self._missing_itime_context.items():
            counter[_group_value(row.get(field))] += 1

    def _add_optional_population(self, row: Mapping[str, str | None]) -> None:
        event_type = _group_value(row.get("event_type"))
        event_counts = self._optional_population.setdefault(
            event_type,
            {field: Counter() for field in OPTIONAL_CONTEXT_FIELDS},
        )
        for field in OPTIONAL_CONTEXT_FIELDS:
            count_name = "missing_count" if is_missing(row.get(field)) else "non_missing_count"
            event_counts[field][count_name] += 1

    def _add_application_relationships(self, row: Mapping[str, str | None]) -> None:
        protocol = _group_value(row.get("net_proto"))
        destination_port = _group_value(row.get("dst_port"))
        service = row.get("app_service")

        if not is_missing(service):
            group_stats = self._services_by_protocol_port.setdefault(
                (protocol, destination_port),
                {"row_count": 0, "services": Counter()},
            )
            group_stats["row_count"] += 1
            group_stats["services"][service] += 1

            hint = _numeric_service_hint(service)
            if hint is None:
                self._non_numeric_service_row_count += 1
            else:
                self._add_numeric_service_alignment(
                    service, hint, protocol, row.get("dst_port")
                )

        protocol_app_counts = self._app_fields_by_protocol.setdefault(
            protocol,
            {field: Counter() for field in APPLICATION_FIELDS},
        )
        for field in APPLICATION_FIELDS:
            count_name = "missing_count" if is_missing(row.get(field)) else "non_missing_count"
            protocol_app_counts[field][count_name] += 1

    def _add_numeric_service_alignment(
        self,
        service: str,
        hint: tuple[str, str],
        protocol: str,
        destination_port: str | None,
    ) -> None:
        transport, expected_port = hint
        expected_protocol = "6" if transport == "tcp" else "17"
        counts = self._numeric_service_labels.setdefault(service, Counter())
        counts["row_count"] += 1

        protocol_matches = protocol == expected_protocol
        port_matches = (
            not is_missing(destination_port)
            and destination_port.isdigit()
            and int(destination_port) == int(expected_port)
        )
        if protocol_matches and port_matches:
            alignment = "matches_protocol_and_destination_port"
        elif is_missing(destination_port):
            alignment = "destination_port_missing"
        elif protocol_matches:
            alignment = "destination_port_mismatch"
        elif port_matches:
            alignment = "protocol_mismatch"
        else:
            alignment = "protocol_and_destination_port_mismatch"
        counts[alignment] += 1

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-ready aggregate results with explicit denominators."""

        return {
            "row_count": self.row_count,
            "conditional_missingness": self._conditional_missingness_result(),
            "protocol_port_population": self._protocol_port_result(),
            "application_field_population_by_protocol": self._app_field_population_result(),
            "service_protocol_port_summary": self._service_protocol_port_result(),
            "numeric_service_label_alignment": self._numeric_service_alignment_result(),
            "session_metric_missingness": self._session_metric_result(),
            "session_behavior": self._session_behavior.as_dict(),
            "missing_itime_context": self._missing_itime_result(),
            "optional_field_population_by_event_type": self._optional_population_result(),
        }

    def _conditional_missingness_result(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for grouping in self.groupings:
            groups: list[dict[str, Any]] = []
            for values, stats in sorted(
                self._conditional_counts[grouping].items(),
                key=lambda item: _group_sort_key(item[0]),
            ):
                row_count = stats["row_count"]
                fields = {
                    field: {
                        "missing_count": counts["missing_count"],
                        "non_missing_count": counts["non_missing_count"],
                        "denominator_row_count": row_count,
                        "missing_percentage_of_group": percentage(
                            counts["missing_count"], row_count
                        ),
                    }
                    for field, counts in stats["fields"].items()
                }
                groups.append(
                    {
                        "group": dict(zip(grouping, values, strict=True)),
                        "row_count": row_count,
                        "fields": fields,
                    }
                )
            results.append({"group_fields": list(grouping), "groups": groups})
        return results

    def _protocol_port_result(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for protocol, counts in sorted(
            self._port_counts.items(), key=lambda item: _group_sort_key((item[0],))
        ):
            row_count = counts["row_count"]
            both_missing = counts["both_missing"]
            if protocol == "1" and row_count and both_missing == row_count:
                status = "EXPECTED"
            elif protocol in {"1", "6", "17"}:
                status = "CONTEXT_DEPENDENT"
            else:
                status = "UNKNOWN"
            results.append(
                {
                    "net_proto_raw": protocol,
                    "derived_protocol_name": derived_protocol_name(protocol),
                    "row_count": row_count,
                    "both_missing_count": both_missing,
                    "source_only_missing_count": counts["source_only_missing"],
                    "destination_only_missing_count": counts["destination_only_missing"],
                    "both_populated_count": counts["both_populated"],
                    "both_missing_percentage": percentage(both_missing, row_count),
                    "data_quality_status": status,
                }
            )
        return results

    def _app_field_population_result(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for protocol, field_counts in sorted(
            self._app_fields_by_protocol.items(),
            key=lambda item: _group_sort_key((item[0],)),
        ):
            row_count = sum(field_counts[APPLICATION_FIELDS[0]].values())
            results.append(
                {
                    "net_proto_raw": protocol,
                    "derived_protocol_name": derived_protocol_name(protocol),
                    "row_count": row_count,
                    "fields": {
                        field: {
                            "missing_count": counts["missing_count"],
                            "non_missing_count": counts["non_missing_count"],
                            "denominator_row_count": row_count,
                            "non_missing_percentage_of_group": percentage(
                                counts["non_missing_count"], row_count
                            ),
                        }
                        for field, counts in field_counts.items()
                    },
                }
            )
        return results

    def _service_protocol_port_result(self) -> dict[str, Any]:
        ordered_groups = sorted(
            self._services_by_protocol_port.items(),
            key=lambda item: (-item[1]["row_count"], _group_sort_key(item[0])),
        )
        selected_groups = ordered_groups[: self.service_group_limit]
        groups: list[dict[str, Any]] = []
        for (protocol, destination_port), stats in selected_groups:
            services = [
                {
                    "app_service": service,
                    "row_count": count,
                    "percentage_of_protocol_port_group": percentage(
                        count, stats["row_count"]
                    ),
                }
                for service, count in sorted(
                    stats["services"].items(), key=lambda item: (-item[1], item[0])
                )[: self.services_per_group]
            ]
            groups.append(
                {
                    "net_proto_raw": protocol,
                    "derived_protocol_name": derived_protocol_name(protocol),
                    "dst_port_raw": destination_port,
                    "row_count": stats["row_count"],
                    "top_services": services,
                }
            )
        return {
            "service_group_limit": self.service_group_limit,
            "services_per_group": self.services_per_group,
            "reported_group_count": len(groups),
            "omitted_group_count": len(ordered_groups) - len(groups),
            "groups": groups,
        }

    def _numeric_service_alignment_result(self) -> dict[str, Any]:
        ordered_labels = sorted(
            self._numeric_service_labels.items(),
            key=lambda item: (-item[1]["row_count"], item[0]),
        )
        selected_labels = ordered_labels[: self.numeric_service_label_limit]
        labels: list[dict[str, Any]] = []
        for service, counts in selected_labels:
            transport, expected_port = _numeric_service_hint(service) or ("", "")
            expected_protocol = "6" if transport == "tcp" else "17"
            labels.append(
                {
                    "app_service": service,
                    "derived_transport": transport.upper(),
                    "derived_protocol_raw": expected_protocol,
                    "derived_protocol_name": derived_protocol_name(expected_protocol),
                    "derived_destination_port": expected_port,
                    "row_count": counts["row_count"],
                    "matches_protocol_and_destination_port_count": counts[
                        "matches_protocol_and_destination_port"
                    ],
                    "protocol_mismatch_count": counts["protocol_mismatch"],
                    "destination_port_mismatch_count": counts[
                        "destination_port_mismatch"
                    ],
                    "protocol_and_destination_port_mismatch_count": counts[
                        "protocol_and_destination_port_mismatch"
                    ],
                    "destination_port_missing_count": counts[
                        "destination_port_missing"
                    ],
                    "data_quality_status": (
                        "CONTEXT_DEPENDENT"
                        if counts["matches_protocol_and_destination_port"]
                        == counts["row_count"]
                        else "UNKNOWN"
                    ),
                }
            )
        return {
            "interpretation": "Protocol and port hints are derived only from numeric service labels such as tcp/8080.",
            "numeric_service_label_limit": self.numeric_service_label_limit,
            "reported_label_count": len(labels),
            "omitted_label_count": len(ordered_labels) - len(labels),
            "non_numeric_service_row_count": self._non_numeric_service_row_count,
            "labels": labels,
        }

    def _session_metric_result(self) -> dict[str, Any]:
        all_missing_pattern = tuple(SESSION_METRIC_FIELDS)
        all_missing_count = self._session_metric_patterns[all_missing_pattern]
        no_missing_count = self._session_metric_patterns[()]
        partial_missing_count = self.row_count - all_missing_count - no_missing_count
        if all_missing_count and not partial_missing_count:
            status = "CONTEXT_DEPENDENT"
        elif partial_missing_count:
            status = "UNKNOWN"
        else:
            status = "UNKNOWN"
        patterns = [
            {
                "missing_fields": list(missing_fields),
                "row_count": count,
                "percentage_of_rows": percentage(count, self.row_count),
            }
            for missing_fields, count in sorted(
                self._session_metric_patterns.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
        return {
            "metric_fields": list(SESSION_METRIC_FIELDS),
            "all_metrics_missing_count": all_missing_count,
            "all_metrics_populated_count": no_missing_count,
            "partial_metric_missing_count": partial_missing_count,
            "denominator_row_count": self.row_count,
            "data_quality_status": status,
            "patterns": patterns,
        }

    def _missing_itime_result(self) -> dict[str, Any]:
        context = {
            field: [
                {"value": value, "count": count}
                for value, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
            ]
            for field, counter in self._missing_itime_context.items()
        }
        return {
            "missing_count": self._missing_itime_count,
            "denominator_row_count": self.row_count,
            "missing_percentage": percentage(self._missing_itime_count, self.row_count),
            "data_quality_status": "UNKNOWN",
            "context": context,
        }

    def _optional_population_result(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for event_type, field_counts in sorted(self._optional_population.items()):
            row_count = sum(field_counts[OPTIONAL_CONTEXT_FIELDS[0]].values())
            results.append(
                {
                    "event_type": event_type,
                    "row_count": row_count,
                    "fields": {
                        field: {
                            "missing_count": counts["missing_count"],
                            "non_missing_count": counts["non_missing_count"],
                            "denominator_row_count": row_count,
                            "non_missing_percentage_of_group": percentage(
                                counts["non_missing_count"], row_count
                            ),
                            "data_quality_status": "UNKNOWN",
                        }
                        for field, counts in field_counts.items()
                    },
                }
            )
        return results


def analyze_rows(rows: Iterable[Mapping[str, str | None]]) -> dict[str, Any]:
    """Analyze parsed records in one pass without retaining raw rows."""

    accumulator = ContextualMissingnessAccumulator()
    for row in rows:
        accumulator.add_row(row)
    return accumulator.as_dict()
