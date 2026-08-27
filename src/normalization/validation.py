"""Contract checks for normalized FortiGate events.

The checks report structured issues rather than discarding evidence. They do not
parse CSV input or decide whether an event is a security incident.
"""

from __future__ import annotations

from collections.abc import Mapping

from .fortigate_mapping import FORTIGATE_FIELD_MAPPINGS
from .models import NormalizationIssue, NormalizedSecurityEvent


_MISSING = object()
_PROHIBITED_DECISION_KEYS = frozenset(
    {"is_attack", "is_malicious", "risk_score", "detection", "mitre"}
)


def _is_missing(value: str | None) -> bool:
    return value is None or not value.strip()


def _canonical_value(event: NormalizedSecurityEvent, path: str) -> object:
    """Return a canonical path value, or a sentinel when the path is absent."""

    section_name, *path_parts = path.split(".")
    value: object = getattr(event, section_name)
    for part in path_parts:
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _has_provenance(
    event: NormalizedSecurityEvent, path: str, source_field: str
) -> bool:
    return any(
        item.canonical_path == path and source_field in item.source_fields
        for item in event.provenance
    )


def _contains_prohibited_decision_key(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    for key, nested_value in value.items():
        if key in _PROHIBITED_DECISION_KEYS:
            return True
        if _contains_prohibited_decision_key(nested_value):
            return True
    return False


def validate_normalized_event(event: NormalizedSecurityEvent) -> list[NormalizationIssue]:
    """Return contract issues found in one already-constructed normalized event.

    The Stage 1.3A dataclasses enforce representation-level rules on construction.
    This function adds FortiGate mapping coverage checks for the Stage 1.3D output.
    """

    if not isinstance(event, NormalizedSecurityEvent):
        raise TypeError("event must be a NormalizedSecurityEvent")

    issues: list[NormalizationIssue] = []
    mapped_fields = {mapping.source_field: mapping for mapping in FORTIGATE_FIELD_MAPPINGS}

    for mapping in FORTIGATE_FIELD_MAPPINGS:
        source_field = mapping.source_field
        if source_field not in event.source_record.fields:
            issues.append(
                NormalizationIssue(
                    source_field=source_field,
                    issue_code="MISSING_BASELINE_SOURCE_FIELD",
                    status="ACTUAL_INVALID",
                    description="Required FortiGate source field is absent from source_record.",
                )
            )
            continue

        raw_value = event.source_record.fields[source_field]
        if mapping.mapping_category == "PRESERVED_UNMAPPED":
            if source_field not in event.unmapped_fields:
                issues.append(
                    NormalizationIssue(
                        source_field=source_field,
                        issue_code="UNMAPPED_FIELD_NOT_PRESERVED",
                        status="ACTUAL_INVALID",
                        description="A preserved-unmapped source field is missing from unmapped_fields.",
                    )
                )
            continue

        if _is_missing(raw_value):
            continue

        for canonical_path in mapping.canonical_paths:
            canonical_value = _canonical_value(event, canonical_path)
            if canonical_value is _MISSING:
                issues.append(
                    NormalizationIssue(
                        source_field=source_field,
                        issue_code="CANONICAL_PATH_MISSING",
                        status="ACTUAL_INVALID",
                        description="The approved canonical path is absent from the normalized event.",
                    )
                )
            elif canonical_value is not None and not _has_provenance(
                event, canonical_path, source_field
            ):
                issues.append(
                    NormalizationIssue(
                        source_field=source_field,
                        issue_code="PROVENANCE_MISSING",
                        status="ACTUAL_INVALID",
                        description="A populated canonical value has no matching source provenance.",
                    )
                )

    for source_field in event.source_record.fields:
        if source_field not in mapped_fields and source_field not in event.unmapped_fields:
            issues.append(
                NormalizationIssue(
                    source_field=source_field,
                    issue_code="UNKNOWN_FIELD_NOT_PRESERVED",
                    status="ACTUAL_INVALID",
                    description="An unknown source field is missing from unmapped_fields.",
                )
            )

    canonical_sections = (
        event.source,
        event.event,
        event.time,
        event.network,
        event.application,
        event.session,
        event.host,
        event.threat_observations,
    )
    if any(_contains_prohibited_decision_key(section) for section in canonical_sections):
        issues.append(
            NormalizationIssue(
                source_field=None,
                issue_code="PROHIBITED_SECURITY_DECISION",
                status="ACTUAL_INVALID",
                description="Normalized sections must not contain security decision keys.",
            )
        )

    return issues
