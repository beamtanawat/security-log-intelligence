"""Vendor-neutral data structures for normalized security events.

This module defines the Stage 1.3A contract only. It contains no source adapter,
source-field mapping, parsing, detection, or output-file behavior.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from math import isfinite
from typing import TypeAlias


SCHEMA_VERSION = "1.0"
MAPPING_OPERATIONS = frozenset(
    {"COPIED", "CONVERTED", "DERIVED", "PRESERVED_UNMAPPED"}
)
INTERPRETATION_STATUSES = frozenset(
    {
        "VERIFIED",
        "DERIVED",
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "CONTEXT_DEPENDENT",
    }
)
ISSUE_STATUSES = frozenset(
    {"EXPECTED", "CONTEXT_DEPENDENT", "UNKNOWN", "ACTUAL_INVALID"}
)
REQUIRED_EVENT_SECTIONS = (
    "schema_version",
    "source",
    "event",
    "time",
    "network",
    "application",
    "session",
    "host",
    "threat_observations",
    "source_record",
    "unmapped_fields",
    "provenance",
    "normalization_issues",
)

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class NormalizationContractError(ValueError):
    """Raised when a value cannot be represented by the normalization contract."""


def _require_non_empty_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise NormalizationContractError(f"{name} must be a non-empty string")


def _validate_status(value: str, allowed: frozenset[str], name: str) -> None:
    _require_non_empty_text(value, name)
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise NormalizationContractError(
            f"{name} must be one of: {allowed_values}"
        )


def _json_ready(value: object) -> JsonValue:
    """Return a deterministic JSON-compatible copy of a supported value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise NormalizationContractError("floating-point values must be finite")
        return value
    if isinstance(value, Mapping):
        prepared: dict[str, JsonValue] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise NormalizationContractError("JSON object keys must be strings")
            prepared[key] = _json_ready(value[key])
        return prepared
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    raise NormalizationContractError(
        f"value of type {type(value).__name__} is not JSON-compatible"
    )


def _json_mapping(value: Mapping[str, object], name: str) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise NormalizationContractError(f"{name} must be a mapping")
    prepared = _json_ready(value)
    if not isinstance(prepared, dict):
        raise NormalizationContractError(f"{name} must serialize as an object")
    return prepared


def _non_negative_count(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NormalizationContractError(f"{name} must be a non-negative integer")


def _count_mapping(value: Mapping[str, int], name: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise NormalizationContractError(f"{name} must be a mapping")
    prepared: dict[str, int] = {}
    for key in sorted(value):
        _require_non_empty_text(key, f"{name} key")
        count = value[key]
        _non_negative_count(count, f"{name}[{key!r}]")
        prepared[key] = count
    return prepared


@dataclass(frozen=True)
class SourceRecord:
    """A source-neutral, exact decoded source-record mapping."""

    source_type: str
    record_number: int
    fields: Mapping[str, str | None]

    def __post_init__(self) -> None:
        _require_non_empty_text(self.source_type, "source_type")
        if (
            isinstance(self.record_number, bool)
            or not isinstance(self.record_number, int)
            or self.record_number < 1
        ):
            raise NormalizationContractError(
                "record_number must be a positive integer"
            )
        if not isinstance(self.fields, Mapping) or not self.fields:
            raise NormalizationContractError("fields must be a non-empty mapping")

        preserved_fields: dict[str, str | None] = {}
        for field_name, raw_value in self.fields.items():
            _require_non_empty_text(field_name, "source field name")
            if raw_value is not None and not isinstance(raw_value, str):
                raise NormalizationContractError(
                    "source field values must be strings or null"
                )
            preserved_fields[field_name] = raw_value
        object.__setattr__(self, "fields", preserved_fields)

    def to_dict(self) -> dict[str, str | None]:
        """Return the exact decoded source mapping with deterministic key order."""

        return {field: self.fields[field] for field in sorted(self.fields)}


@dataclass(frozen=True)
class FieldProvenance:
    """Evidence describing how one canonical field was populated."""

    canonical_path: str
    source_fields: Sequence[str]
    operation: str
    interpretation_status: str
    note: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty_text(self.canonical_path, "canonical_path")
        if not self.source_fields:
            raise NormalizationContractError(
                "source_fields must contain at least one source field"
            )
        source_fields = tuple(self.source_fields)
        for source_field in source_fields:
            _require_non_empty_text(source_field, "source field")
        _validate_status(self.operation, MAPPING_OPERATIONS, "operation")
        _validate_status(
            self.interpretation_status,
            INTERPRETATION_STATUSES,
            "interpretation_status",
        )
        if self.note is not None:
            _require_non_empty_text(self.note, "note")
        object.__setattr__(self, "source_fields", source_fields)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return deterministic, JSON-compatible provenance data."""

        return {
            "canonical_path": self.canonical_path,
            "source_fields": list(self.source_fields),
            "operation": self.operation,
            "interpretation_status": self.interpretation_status,
            "note": self.note,
        }


@dataclass(frozen=True)
class NormalizationIssue:
    """A structured conversion, missingness, or contract observation."""

    source_field: str | None
    issue_code: str
    status: str
    description: str

    def __post_init__(self) -> None:
        if self.source_field is not None:
            _require_non_empty_text(self.source_field, "source_field")
        _require_non_empty_text(self.issue_code, "issue_code")
        _validate_status(self.status, ISSUE_STATUSES, "status")
        _require_non_empty_text(self.description, "description")

    def to_dict(self) -> dict[str, str | None]:
        """Return deterministic, JSON-compatible issue data."""

        return {
            "source_field": self.source_field,
            "issue_code": self.issue_code,
            "status": self.status,
            "description": self.description,
        }


@dataclass(frozen=True)
class NormalizationRunSummary:
    """Bounded aggregate information for one future normalization run."""

    source_type: str
    input_path: str
    output_path: str | None
    input_record_count: int
    valid_record_count: int
    malformed_record_count: int
    output_record_count: int
    mapping_coverage: Mapping[str, int] = field(default_factory=dict)
    issue_counts: Mapping[str, int] = field(default_factory=dict)
    unknown_field_names: Sequence[str] = field(default_factory=tuple)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty_text(self.source_type, "source_type")
        _require_non_empty_text(self.input_path, "input_path")
        if self.output_path is not None:
            _require_non_empty_text(self.output_path, "output_path")
        if self.schema_version != SCHEMA_VERSION:
            raise NormalizationContractError(
                f"schema_version must be {SCHEMA_VERSION!r}"
            )
        for name in (
            "input_record_count",
            "valid_record_count",
            "malformed_record_count",
            "output_record_count",
        ):
            _non_negative_count(getattr(self, name), name)

        object.__setattr__(
            self,
            "mapping_coverage",
            _count_mapping(self.mapping_coverage, "mapping_coverage"),
        )
        object.__setattr__(
            self,
            "issue_counts",
            _count_mapping(self.issue_counts, "issue_counts"),
        )
        unknown_fields = tuple(self.unknown_field_names)
        for field_name in unknown_fields:
            _require_non_empty_text(field_name, "unknown field name")
        object.__setattr__(self, "unknown_field_names", unknown_fields)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a deterministic, bounded run summary."""

        return {
            "schema_version": self.schema_version,
            "source_type": self.source_type,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "input_record_count": self.input_record_count,
            "valid_record_count": self.valid_record_count,
            "malformed_record_count": self.malformed_record_count,
            "output_record_count": self.output_record_count,
            "mapping_coverage": dict(self.mapping_coverage),
            "issue_counts": dict(self.issue_counts),
            "unknown_field_names": list(self.unknown_field_names),
        }


@dataclass(frozen=True)
class NormalizedSecurityEvent:
    """A minimal, source-neutral normalized event with retained evidence."""

    source: Mapping[str, object]
    event: Mapping[str, object]
    time: Mapping[str, object]
    network: Mapping[str, object]
    application: Mapping[str, object]
    session: Mapping[str, object]
    host: Mapping[str, object]
    threat_observations: Mapping[str, object]
    source_record: SourceRecord
    unmapped_fields: Mapping[str, str | None]
    provenance: Sequence[FieldProvenance]
    normalization_issues: Sequence[NormalizationIssue]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise NormalizationContractError(
                f"schema_version must be {SCHEMA_VERSION!r}"
            )
        if not isinstance(self.source_record, SourceRecord):
            raise NormalizationContractError("source_record must be a SourceRecord")

        for name in (
            "source",
            "event",
            "time",
            "network",
            "application",
            "session",
            "host",
            "threat_observations",
        ):
            object.__setattr__(self, name, _json_mapping(getattr(self, name), name))

        preserved_unmapped: dict[str, str | None] = {}
        if not isinstance(self.unmapped_fields, Mapping):
            raise NormalizationContractError("unmapped_fields must be a mapping")
        for field_name, raw_value in self.unmapped_fields.items():
            _require_non_empty_text(field_name, "unmapped field name")
            if field_name not in self.source_record.fields:
                raise NormalizationContractError(
                    "unmapped field must exist in source_record"
                )
            if raw_value != self.source_record.fields[field_name]:
                raise NormalizationContractError(
                    "unmapped field value must match source_record"
                )
            preserved_unmapped[field_name] = raw_value
        object.__setattr__(self, "unmapped_fields", preserved_unmapped)

        provenance = tuple(self.provenance)
        if not all(isinstance(item, FieldProvenance) for item in provenance):
            raise NormalizationContractError(
                "provenance entries must be FieldProvenance values"
            )
        paths = [item.canonical_path for item in provenance]
        if len(paths) != len(set(paths)):
            raise NormalizationContractError(
                "provenance contains duplicate canonical paths"
            )
        object.__setattr__(self, "provenance", provenance)

        issues = tuple(self.normalization_issues)
        if not all(isinstance(item, NormalizationIssue) for item in issues):
            raise NormalizationContractError(
                "normalization_issues entries must be NormalizationIssue values"
            )
        object.__setattr__(self, "normalization_issues", issues)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return all required contract sections in deterministic JSON-ready form."""

        return {
            "schema_version": self.schema_version,
            "source": dict(self.source),
            "event": dict(self.event),
            "time": dict(self.time),
            "network": dict(self.network),
            "application": dict(self.application),
            "session": dict(self.session),
            "host": dict(self.host),
            "threat_observations": dict(self.threat_observations),
            "source_record": self.source_record.to_dict(),
            "unmapped_fields": {
                field: self.unmapped_fields[field]
                for field in sorted(self.unmapped_fields)
            },
            "provenance": [item.to_dict() for item in self.provenance],
            "normalization_issues": [item.to_dict() for item in self.normalization_issues],
        }
