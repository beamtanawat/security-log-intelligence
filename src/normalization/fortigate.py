"""Pure FortiGate SourceRecord-to-NormalizedSecurityEvent transformation.

The normalizer implements only the approved Stage 1.3B mapping. It preserves the
raw SourceRecord, reports conversion/missingness issues, and makes no security
decision, dataset write, or record-to-record correlation.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

from .fortigate_mapping import FORTIGATE_FIELD_MAPPINGS, validate_fortigate_mapping_specification
from .models import FieldProvenance, NormalizationIssue, NormalizedSecurityEvent, SourceRecord
from .validation import validate_normalized_event


FORTIGATE_SOURCE_TYPE = "fortigate"
_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
_PORT_FIELDS = ("src_port", "dst_port")
_SESSION_METRIC_FIELDS = (
    "net_rcvdpkts",
    "net_recvbytes",
    "net_sentbytes",
    "net_sentpkts",
    "net_sessionduration",
)
_MAPPINGS_BY_FIELD = {
    mapping.source_field: mapping for mapping in FORTIGATE_FIELD_MAPPINGS
}


class FortiGateNormalizationError(ValueError):
    """Raised when a record cannot satisfy the approved FortiGate contract."""


def _is_missing(value: str | None) -> bool:
    return value is None or not value.strip()


def _canonical_string(value: str | None) -> str | None:
    """Represent missing source text as null without altering non-empty text."""

    return None if _is_missing(value) else value


def _set_path(section_values: dict[str, dict[str, object]], path: str, value: object) -> None:
    """Set one approved dotted canonical path in its top-level section."""

    section_name, *path_parts = path.split(".")
    target: dict[str, object] = section_values[section_name]
    for part in path_parts[:-1]:
        nested_value = target.setdefault(part, {})
        if not isinstance(nested_value, dict):
            raise FortiGateNormalizationError(
                f"canonical path conflicts with an existing value: {path}"
            )
        target = nested_value
    target[path_parts[-1]] = value


def _add_provenance(
    provenance: list[FieldProvenance],
    *,
    canonical_path: str,
    source_field: str,
    operation: str,
    interpretation_status: str,
    note: str | None = None,
) -> None:
    provenance.append(
        FieldProvenance(
            canonical_path=canonical_path,
            source_fields=(source_field,),
            operation=operation,
            interpretation_status=interpretation_status,
            note=note,
        )
    )


def _issue(
    issues: list[NormalizationIssue],
    *,
    source_field: str | None,
    issue_code: str,
    status: str,
    description: str,
) -> None:
    issues.append(
        NormalizationIssue(
            source_field=source_field,
            issue_code=issue_code,
            status=status,
            description=description,
        )
    )


def _parse_integer(value: str | None) -> int | None:
    """Convert non-missing integer text without changing the source value."""

    if _is_missing(value):
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _normalize_itime(
    raw_value: str | None,
    raw_path: str,
    derived_path: str,
    section_values: dict[str, dict[str, object]],
    provenance: list[FieldProvenance],
    issues: list[NormalizationIssue],
) -> None:
    raw_time = _canonical_string(raw_value)
    _set_path(section_values, raw_path, raw_time)
    _set_path(section_values, derived_path, None)
    _set_path(
        section_values,
        "time.itime_utc_interpretation_status",
        "NEEDS_VERIFICATION",
    )
    if raw_time is not None:
        _add_provenance(
            provenance,
            canonical_path=raw_path,
            source_field="itime",
            operation="COPIED",
            interpretation_status="NEEDS_VERIFICATION",
            note="Exact source text is retained; timestamp semantics are not verified.",
        )

    integer_time = _parse_integer(raw_value)
    if _is_missing(raw_value):
        _issue(
            issues,
            source_field="itime",
            issue_code="MISSING_ITIME",
            status="UNKNOWN",
            description="The optional source time value is missing.",
        )
        return
    if integer_time is None:
        _issue(
            issues,
            source_field="itime",
            issue_code="INVALID_ITIME_INTEGER",
            status="ACTUAL_INVALID",
            description="The non-empty source time value cannot be converted to an integer.",
        )
        return

    try:
        derived_utc = datetime.fromtimestamp(integer_time, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        _issue(
            issues,
            source_field="itime",
            issue_code="ITIME_UTC_DERIVATION_UNAVAILABLE",
            status="UNKNOWN",
            description="UTC derivation is unavailable for the source integer on this platform.",
        )
        return

    _set_path(
        section_values,
        derived_path,
        derived_utc.replace("+00:00", "Z"),
    )
    _add_provenance(
        provenance,
        canonical_path=derived_path,
        source_field="itime",
        operation="DERIVED",
        interpretation_status="NEEDS_VERIFICATION",
        note="Derived using an unverified Unix epoch-seconds and UTC assumption.",
    )


def _normalize_protocol(
    raw_value: str | None,
    raw_path: str,
    number_path: str,
    name_path: str,
    section_values: dict[str, dict[str, object]],
    provenance: list[FieldProvenance],
    issues: list[NormalizationIssue],
) -> int | None:
    raw_protocol = _canonical_string(raw_value)
    _set_path(section_values, raw_path, raw_protocol)
    _set_path(section_values, number_path, None)
    _set_path(section_values, name_path, None)
    if raw_protocol is not None:
        _add_provenance(
            provenance,
            canonical_path=raw_path,
            source_field="net_proto",
            operation="COPIED",
            interpretation_status="VERIFIED",
            note="Exact source protocol text is retained separately from derived views.",
        )

    protocol_number = _parse_integer(raw_value)
    if _is_missing(raw_value):
        _issue(
            issues,
            source_field="net_proto",
            issue_code="MISSING_PROTOCOL",
            status="UNKNOWN",
            description="The source protocol value is missing.",
        )
        return None
    if protocol_number is None:
        _issue(
            issues,
            source_field="net_proto",
            issue_code="INVALID_PROTOCOL_INTEGER",
            status="ACTUAL_INVALID",
            description="The non-empty source protocol value cannot be converted to an integer.",
        )
        return None

    _set_path(section_values, number_path, protocol_number)
    _add_provenance(
        provenance,
        canonical_path=number_path,
        source_field="net_proto",
        operation="CONVERTED",
        interpretation_status="VERIFIED",
    )
    protocol_name = _PROTOCOL_NAMES.get(protocol_number)
    if protocol_name is None:
        _issue(
            issues,
            source_field="net_proto",
            issue_code="UNKNOWN_PROTOCOL_NUMBER",
            status="UNKNOWN",
            description="The numeric source protocol has no approved derived standard name.",
        )
        return protocol_number

    _set_path(section_values, name_path, protocol_name)
    _add_provenance(
        provenance,
        canonical_path=name_path,
        source_field="net_proto",
        operation="DERIVED",
        interpretation_status="DERIVED",
        note="Derived from the numeric source protocol using the approved standard mapping.",
    )
    return protocol_number


def _normalize_port(
    source_field: str,
    raw_value: str | None,
    canonical_path: str,
    section_values: dict[str, dict[str, object]],
    provenance: list[FieldProvenance],
    issues: list[NormalizationIssue],
) -> None:
    port = _parse_integer(raw_value)
    _set_path(section_values, canonical_path, None)
    if _is_missing(raw_value):
        return
    if port is None or port < 0 or port > 65535:
        _issue(
            issues,
            source_field=source_field,
            issue_code="INVALID_PORT",
            status="ACTUAL_INVALID",
            description="The non-empty source port is not an integer from 0 through 65535.",
        )
        return
    _set_path(section_values, canonical_path, port)
    _add_provenance(
        provenance,
        canonical_path=canonical_path,
        source_field=source_field,
        operation="CONVERTED",
        interpretation_status="VERIFIED",
    )


def _normalize_session_metric(
    source_field: str,
    raw_value: str | None,
    canonical_path: str,
    interpretation_status: str,
    section_values: dict[str, dict[str, object]],
    provenance: list[FieldProvenance],
    issues: list[NormalizationIssue],
) -> None:
    metric = _parse_integer(raw_value)
    _set_path(section_values, canonical_path, None)
    if _is_missing(raw_value):
        return
    if metric is None or metric < 0:
        _issue(
            issues,
            source_field=source_field,
            issue_code="INVALID_NONNEGATIVE_INTEGER",
            status="ACTUAL_INVALID",
            description="The non-empty source value is not a non-negative integer.",
        )
        return
    _set_path(section_values, canonical_path, metric)
    _add_provenance(
        provenance,
        canonical_path=canonical_path,
        source_field=source_field,
        operation="CONVERTED",
        interpretation_status=interpretation_status,
    )


def _copy_mapping_value(
    source_field: str,
    raw_value: str | None,
    canonical_paths: tuple[str, ...],
    interpretation_status: str,
    section_values: dict[str, dict[str, object]],
    provenance: list[FieldProvenance],
) -> None:
    value = _canonical_string(raw_value)
    for canonical_path in canonical_paths:
        _set_path(section_values, canonical_path, value)
        if value is not None:
            _add_provenance(
                provenance,
                canonical_path=canonical_path,
                source_field=source_field,
                operation="COPIED",
                interpretation_status=interpretation_status,
            )


def _require_fortigate_source_record(record: SourceRecord) -> None:
    if not isinstance(record, SourceRecord):
        raise FortiGateNormalizationError("record must be a SourceRecord")
    if record.source_type != FORTIGATE_SOURCE_TYPE:
        raise FortiGateNormalizationError("record source_type must be 'fortigate'")
    missing_fields = [
        mapping.source_field
        for mapping in _MAPPINGS_BY_FIELD.values()
        if mapping.source_field not in record.fields
    ]
    if missing_fields:
        raise FortiGateNormalizationError(
            "record is missing required FortiGate fields: " + ", ".join(missing_fields)
        )


def normalize_fortigate_record(record: SourceRecord) -> NormalizedSecurityEvent:
    """Return one deterministic normalized event without mutating ``record``."""

    validate_fortigate_mapping_specification()
    _require_fortigate_source_record(record)

    section_values: dict[str, dict[str, object]] = {
        "source": {
            "adapter_type": record.source_type,
            "record_number": record.record_number,
        },
        "event": {},
        "time": {},
        "network": {},
        "application": {},
        "session": {},
        "host": {},
        "threat_observations": {},
    }
    provenance: list[FieldProvenance] = []
    issues: list[NormalizationIssue] = []

    itime_paths = _MAPPINGS_BY_FIELD["itime"].canonical_paths
    _normalize_itime(
        record.fields["itime"],
        itime_paths[0],
        itime_paths[1],
        section_values,
        provenance,
        issues,
    )

    conversion_fields = {"itime", "net_proto", *_PORT_FIELDS, *_SESSION_METRIC_FIELDS}
    for mapping in FORTIGATE_FIELD_MAPPINGS:
        source_field = mapping.source_field
        if source_field in conversion_fields:
            continue
        if mapping.mapping_category == "PRESERVED_UNMAPPED":
            continue
        _copy_mapping_value(
            source_field,
            record.fields[source_field],
            mapping.canonical_paths,
            mapping.interpretation_status,
            section_values,
            provenance,
        )

    protocol_number = _normalize_protocol(
        record.fields["net_proto"],
        *_MAPPINGS_BY_FIELD["net_proto"].canonical_paths,
        section_values,
        provenance,
        issues,
    )
    _normalize_port(
        "src_port",
        record.fields["src_port"],
        _MAPPINGS_BY_FIELD["src_port"].canonical_paths[0],
        section_values,
        provenance,
        issues,
    )
    _normalize_port(
        "dst_port",
        record.fields["dst_port"],
        _MAPPINGS_BY_FIELD["dst_port"].canonical_paths[0],
        section_values,
        provenance,
        issues,
    )

    source_port_missing = _is_missing(record.fields["src_port"])
    destination_port_missing = _is_missing(record.fields["dst_port"])
    if protocol_number == 1 and source_port_missing and destination_port_missing:
        _issue(
            issues,
            source_field=None,
            issue_code="MISSING_PORTS_EXPECTED_FOR_ICMP",
            status="EXPECTED",
            description="Both ports are absent for protocol 1 and remain canonical nulls.",
        )
    else:
        for source_field, is_missing in (
            ("src_port", source_port_missing),
            ("dst_port", destination_port_missing),
        ):
            if is_missing:
                _issue(
                    issues,
                    source_field=source_field,
                    issue_code="MISSING_CONTEXTUAL_PORT",
                    status="CONTEXT_DEPENDENT",
                    description="The optional source port is missing in this record context.",
                )

    for source_field in _SESSION_METRIC_FIELDS:
        interpretation_status = (
            "NEEDS_VERIFICATION"
            if source_field == "net_sessionduration"
            else "CONTEXT_DEPENDENT"
        )
        _normalize_session_metric(
            source_field,
            record.fields[source_field],
            _MAPPINGS_BY_FIELD[source_field].canonical_paths[0],
            interpretation_status,
            section_values,
            provenance,
            issues,
        )

    missing_session_metrics = [
        field for field in _SESSION_METRIC_FIELDS if _is_missing(record.fields[field])
    ]
    if len(missing_session_metrics) == len(_SESSION_METRIC_FIELDS):
        _issue(
            issues,
            source_field=None,
            issue_code="ALL_SESSION_METRICS_MISSING",
            status="CONTEXT_DEPENDENT",
            description="All optional session metrics are absent in this record context.",
        )
    else:
        for source_field in missing_session_metrics:
            _issue(
                issues,
                source_field=source_field,
                issue_code="MISSING_CONTEXTUAL_SESSION_METRIC",
                status="CONTEXT_DEPENDENT",
                description="The optional session metric is missing in this record context.",
            )

    unmapped_fields = {
        source_field: raw_value
        for source_field, raw_value in record.fields.items()
        if source_field not in _MAPPINGS_BY_FIELD
        or _MAPPINGS_BY_FIELD[source_field].mapping_category == "PRESERVED_UNMAPPED"
    }

    event = NormalizedSecurityEvent(
        source=section_values["source"],
        event=section_values["event"],
        time=section_values["time"],
        network=section_values["network"],
        application=section_values["application"],
        session=section_values["session"],
        host=section_values["host"],
        threat_observations=section_values["threat_observations"],
        source_record=record,
        unmapped_fields=unmapped_fields,
        provenance=provenance,
        normalization_issues=issues,
    )
    validation_issues = validate_normalized_event(event)
    if validation_issues:
        issue_codes = ", ".join(issue.issue_code for issue in validation_issues)
        raise FortiGateNormalizationError(
            "normalizer produced an invalid normalized event: " + issue_codes
        )
    return event
