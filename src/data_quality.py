"""Field-inventory primitives for Stage 1.2 data-quality analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
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


class ContextualMissingnessAccumulator:
    """Bounded-memory counters for one pass over valid CSV records."""

    def __init__(
        self,
        *,
        target_fields: Sequence[str] = CONDITIONAL_MISSING_FIELDS,
        groupings: Sequence[Sequence[str]] = CONDITIONAL_GROUPINGS,
    ) -> None:
        self.target_fields = tuple(target_fields)
        self.groupings = tuple(tuple(grouping) for grouping in groupings)
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

    def add_row(self, row: Mapping[str, str | None]) -> None:
        """Add one parsed CSV row without retaining the full record."""

        self.row_count += 1
        self._add_conditional_counts(row)
        self._add_port_counts(row)
        self._add_session_metric_pattern(row)
        self._add_missing_itime_context(row)
        self._add_optional_population(row)

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

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-ready aggregate results with explicit denominators."""

        return {
            "row_count": self.row_count,
            "conditional_missingness": self._conditional_missingness_result(),
            "protocol_port_population": self._protocol_port_result(),
            "session_metric_missingness": self._session_metric_result(),
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
