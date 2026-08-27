"""Immutable, deterministic contracts for Stage 1.4 detection findings.

These models define vocabulary and serialization only. They do not contain a
rule registry, rule condition, evaluation engine, JSONL reader, CLI, or any
security decision about a source event.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from math import isfinite
import re

from normalization.models import (
    INTERPRETATION_STATUSES,
    MAPPING_OPERATIONS,
    SCHEMA_VERSION,
    JsonValue,
)


DETECTION_FINDING_SCHEMA_VERSION = "1.0"
RULE_SEVERITIES = frozenset({"INFORMATIONAL", "LOW", "MEDIUM", "HIGH"})
RULE_CATEGORIES = frozenset({"SOURCE_PRODUCT_OBSERVATION"})
TIME_BASES = frozenset({"NOT_USED"})

_RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
_REASON_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
_FINDING_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


class DetectionContractError(ValueError):
    """Raised when a value cannot be represented by the detection contract."""


def _require_non_empty_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DetectionContractError(f"{name} must be a non-empty string")


def _require_positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DetectionContractError(f"{name} must be a positive integer")


def _require_non_negative_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DetectionContractError(f"{name} must be a non-negative integer")


def _validate_rule_id(value: str, name: str = "rule_id") -> None:
    _require_non_empty_text(value, name)
    if _RULE_ID_PATTERN.fullmatch(value) is None:
        raise DetectionContractError(
            f"{name} must be a lowercase dotted identifier"
        )


def _validate_version(value: str, name: str = "version") -> None:
    _require_non_empty_text(value, name)
    if _VERSION_PATTERN.fullmatch(value) is None:
        raise DetectionContractError(
            f"{name} must be a semantic version such as '1.0'"
        )


def _validate_reason_code(value: str) -> None:
    _require_non_empty_text(value, "reason_code")
    if _REASON_CODE_PATTERN.fullmatch(value) is None:
        raise DetectionContractError(
            "reason_code must be an uppercase underscore-separated identifier"
        )


def _validate_vocab(value: str, allowed: frozenset[str], name: str) -> None:
    _require_non_empty_text(value, name)
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise DetectionContractError(f"{name} must be one of: {allowed_values}")


def _json_ready(value: object) -> JsonValue:
    """Return a deterministic JSON-compatible copy of a supported value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise DetectionContractError("floating-point values must be finite")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise DetectionContractError("JSON object keys must be strings")
        return {key: _json_ready(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    raise DetectionContractError(
        f"value of type {type(value).__name__} is not JSON-compatible"
    )


def _text_sequence(
    value: Sequence[str],
    name: str,
    *,
    allow_empty: bool = False,
    sort_values: bool = False,
) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise DetectionContractError(f"{name} must be a sequence of strings")
    values = tuple(value)
    if not allow_empty and not values:
        raise DetectionContractError(f"{name} must contain at least one value")
    for item in values:
        _require_non_empty_text(item, f"{name} item")
    if len(values) != len(set(values)):
        raise DetectionContractError(f"{name} must not contain duplicate values")
    return tuple(sorted(values)) if sort_values else values


def _count_mapping(value: Mapping[str, int], name: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise DetectionContractError(f"{name} must be a mapping")
    counts: dict[str, int] = {}
    for key in sorted(value):
        _require_non_empty_text(key, f"{name} key")
        _require_non_negative_integer(value[key], f"{name}[{key!r}]")
        counts[key] = value[key]
    return counts


def _length_prefixed_utf8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded


def build_finding_id(
    *,
    rule_id: str,
    rule_version: str,
    source_type: str,
    normalized_schema_version: str,
    source_record_number: int,
    source_record_id: str | None,
) -> str:
    """Build the fixed Stage 1.4 deterministic finding identity.

    The SHA-256 input is a concatenation of length-prefixed UTF-8 values in the
    exact order documented by the Stage 1.4 plan. A missing source record ID is
    represented by the literal ``<MISSING>`` marker required by that plan.
    """

    _validate_rule_id(rule_id)
    _validate_version(rule_version, "rule_version")
    _require_non_empty_text(source_type, "source_type")
    _require_non_empty_text(normalized_schema_version, "normalized_schema_version")
    _require_positive_integer(source_record_number, "source_record_number")
    if source_record_id is not None:
        _require_non_empty_text(source_record_id, "source_record_id")

    components = (
        DETECTION_FINDING_SCHEMA_VERSION,
        rule_id,
        rule_version,
        source_type,
        normalized_schema_version,
        str(source_record_number),
        source_record_id if source_record_id is not None else "<MISSING>",
    )
    digest_input = b"".join(_length_prefixed_utf8(component) for component in components)
    return sha256(digest_input).hexdigest()


@dataclass(frozen=True)
class RuleMetadata:
    """Stable documentation and validation requirements for one future rule."""

    rule_id: str
    version: str
    name: str
    description: str
    category: str
    severity: str
    supported_source_types: Sequence[str]
    required_paths: Sequence[str]
    evidence_paths: Sequence[str]
    reason_code: str
    security_rationale: str
    false_positive_scenarios: Sequence[str]
    limitations: Sequence[str]

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        _validate_version(self.version)
        _require_non_empty_text(self.name, "name")
        _require_non_empty_text(self.description, "description")
        _validate_vocab(self.category, RULE_CATEGORIES, "category")
        _validate_vocab(self.severity, RULE_SEVERITIES, "severity")
        _validate_reason_code(self.reason_code)
        _require_non_empty_text(self.security_rationale, "security_rationale")
        object.__setattr__(
            self,
            "supported_source_types",
            _text_sequence(
                self.supported_source_types,
                "supported_source_types",
                sort_values=True,
            ),
        )
        object.__setattr__(
            self,
            "required_paths",
            _text_sequence(self.required_paths, "required_paths", sort_values=True),
        )
        object.__setattr__(
            self,
            "evidence_paths",
            _text_sequence(self.evidence_paths, "evidence_paths", sort_values=True),
        )
        object.__setattr__(
            self,
            "false_positive_scenarios",
            _text_sequence(self.false_positive_scenarios, "false_positive_scenarios"),
        )
        object.__setattr__(self, "limitations", _text_sequence(self.limitations, "limitations"))

    def to_dict(self) -> dict[str, JsonValue]:
        """Return deterministic, JSON-compatible rule metadata."""

        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "supported_source_types": list(self.supported_source_types),
            "required_paths": list(self.required_paths),
            "evidence_paths": list(self.evidence_paths),
            "reason_code": self.reason_code,
            "security_rationale": self.security_rationale,
            "false_positive_scenarios": list(self.false_positive_scenarios),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class FindingRuleReference:
    """The rule identity and review-priority fields retained in a finding."""

    rule_id: str
    version: str
    name: str
    category: str
    severity: str

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        _validate_version(self.version)
        _require_non_empty_text(self.name, "name")
        _validate_vocab(self.category, RULE_CATEGORIES, "category")
        _validate_vocab(self.severity, RULE_SEVERITIES, "severity")

    @classmethod
    def from_metadata(cls, metadata: RuleMetadata) -> "FindingRuleReference":
        """Create the limited finding reference from reviewed rule metadata."""

        if not isinstance(metadata, RuleMetadata):
            raise DetectionContractError("metadata must be a RuleMetadata")
        return cls(
            rule_id=metadata.rule_id,
            version=metadata.version,
            name=metadata.name,
            category=metadata.category,
            severity=metadata.severity,
        )

    def to_dict(self) -> dict[str, str]:
        """Return the exact rule reference written into a finding."""

        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class SourceEventReference:
    """Trace a finding to one normalized event without embedding raw evidence."""

    source_type: str
    normalized_schema_version: str
    source_record_number: int
    source_record_id: str | None

    def __post_init__(self) -> None:
        _require_non_empty_text(self.source_type, "source_type")
        if self.normalized_schema_version != SCHEMA_VERSION:
            raise DetectionContractError(
                f"normalized_schema_version must be {SCHEMA_VERSION!r}"
            )
        _require_positive_integer(self.source_record_number, "source_record_number")
        if self.source_record_id is not None:
            _require_non_empty_text(self.source_record_id, "source_record_id")

    def to_dict(self) -> dict[str, JsonValue]:
        """Return deterministic normalized-event traceability fields."""

        return {
            "source_type": self.source_type,
            "normalized_schema_version": self.normalized_schema_version,
            "source_record_number": self.source_record_number,
            "source_record_id": self.source_record_id,
        }


@dataclass(frozen=True)
class DetectionEvidence:
    """One observed canonical value with copied normalization provenance."""

    canonical_path: str
    observed_value: object
    source_fields: Sequence[str]
    mapping_operation: str
    interpretation_status: str

    def __post_init__(self) -> None:
        _require_non_empty_text(self.canonical_path, "canonical_path")
        _validate_vocab(self.mapping_operation, MAPPING_OPERATIONS, "mapping_operation")
        _validate_vocab(
            self.interpretation_status,
            INTERPRETATION_STATUSES,
            "interpretation_status",
        )
        object.__setattr__(self, "observed_value", _json_ready(self.observed_value))
        object.__setattr__(
            self,
            "source_fields",
            _text_sequence(self.source_fields, "source_fields"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Return deterministic evidence suitable for one finding."""

        return {
            "canonical_path": self.canonical_path,
            "observed_value": self.observed_value,
            "source_fields": list(self.source_fields),
            "mapping_operation": self.mapping_operation,
            "interpretation_status": self.interpretation_status,
        }


@dataclass(frozen=True)
class RuleEvaluation:
    """A future rule's neutral match result before finding construction."""

    reason_code: str
    summary: str
    evidence_paths: Sequence[str]
    uncertainties: Sequence[str]

    def __post_init__(self) -> None:
        _validate_reason_code(self.reason_code)
        _require_non_empty_text(self.summary, "summary")
        object.__setattr__(
            self,
            "evidence_paths",
            _text_sequence(self.evidence_paths, "evidence_paths", sort_values=True),
        )
        object.__setattr__(self, "uncertainties", _text_sequence(self.uncertainties, "uncertainties"))


@dataclass(frozen=True)
class DetectionFinding:
    """A deterministic record of one configured rule match.

    A finding records that a deterministic configured condition matched. It is not
    an attack, compromise, malicious/benign label, incident, confidence score, or
    risk decision.
    """

    finding_id: str
    rule: FindingRuleReference
    source_event: SourceEventReference
    reason_code: str
    summary: str
    evidence: Sequence[DetectionEvidence]
    time_basis: str
    uncertainties: Sequence[str]
    false_positive_note: str
    deterministic: bool = True
    finding_schema_version: str = DETECTION_FINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.finding_schema_version != DETECTION_FINDING_SCHEMA_VERSION:
            raise DetectionContractError(
                "finding_schema_version must be "
                f"{DETECTION_FINDING_SCHEMA_VERSION!r}"
            )
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise DetectionContractError("finding_id must be a lowercase SHA-256 hex digest")
        if not isinstance(self.rule, FindingRuleReference):
            raise DetectionContractError("rule must be a FindingRuleReference")
        if not isinstance(self.source_event, SourceEventReference):
            raise DetectionContractError("source_event must be a SourceEventReference")
        expected_id = build_finding_id(
            rule_id=self.rule.rule_id,
            rule_version=self.rule.version,
            source_type=self.source_event.source_type,
            normalized_schema_version=self.source_event.normalized_schema_version,
            source_record_number=self.source_event.source_record_number,
            source_record_id=self.source_event.source_record_id,
        )
        if self.finding_id != expected_id:
            raise DetectionContractError(
                "finding_id does not match the deterministic finding identity contract"
            )
        _validate_reason_code(self.reason_code)
        _require_non_empty_text(self.summary, "summary")
        _validate_vocab(self.time_basis, TIME_BASES, "time_basis")
        _require_non_empty_text(self.false_positive_note, "false_positive_note")
        if self.deterministic is not True:
            raise DetectionContractError("deterministic must be true for Stage 1.4 findings")

        evidence = tuple(self.evidence)
        if not evidence or not all(isinstance(item, DetectionEvidence) for item in evidence):
            raise DetectionContractError(
                "evidence must contain at least one DetectionEvidence value"
            )
        evidence_paths = tuple(item.canonical_path for item in evidence)
        if len(evidence_paths) != len(set(evidence_paths)):
            raise DetectionContractError("evidence must not contain duplicate canonical paths")
        if evidence_paths != tuple(sorted(evidence_paths)):
            raise DetectionContractError("evidence must be ordered by canonical path")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "uncertainties", _text_sequence(self.uncertainties, "uncertainties"))

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the complete deterministic finding contract representation."""

        return {
            "finding_schema_version": self.finding_schema_version,
            "finding_id": self.finding_id,
            "rule": self.rule.to_dict(),
            "source_event": self.source_event.to_dict(),
            "reason_code": self.reason_code,
            "summary": self.summary,
            "evidence": [item.to_dict() for item in self.evidence],
            "time_basis": self.time_basis,
            "uncertainties": list(self.uncertainties),
            "false_positive_note": self.false_positive_note,
            "deterministic": self.deterministic,
        }


@dataclass(frozen=True)
class FindingSample:
    """A bounded run-summary reference to one finding."""

    finding_id: str
    source_record_number: int

    def __post_init__(self) -> None:
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise DetectionContractError("finding_id must be a lowercase SHA-256 hex digest")
        _require_positive_integer(self.source_record_number, "source_record_number")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "finding_id": self.finding_id,
            "source_record_number": self.source_record_number,
        }


@dataclass(frozen=True)
class ActiveRuleVersion:
    """One ordered rule identity retained in a bounded run summary."""

    rule_id: str
    version: str

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        _validate_version(self.version)

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "version": self.version}


@dataclass(frozen=True)
class DetectionRunSummary:
    """Bounded aggregate information for one future detection evaluation run."""

    input_path: str
    output_path: str
    normalized_input_schema_version: str
    normalized_input_record_count: int
    evaluated_record_count: int
    invalid_input_count: int
    total_finding_count: int
    findings_by_rule_id: Mapping[str, int] = field(default_factory=dict)
    findings_by_rule_severity: Mapping[str, int] = field(default_factory=dict)
    unique_matched_source_record_count: int = 0
    sample_findings_by_rule: Mapping[str, Sequence[FindingSample]] = field(
        default_factory=dict
    )
    active_rules: Sequence[ActiveRuleVersion] = field(default_factory=tuple)
    finding_schema_version: str = DETECTION_FINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty_text(self.input_path, "input_path")
        _require_non_empty_text(self.output_path, "output_path")
        if self.normalized_input_schema_version != SCHEMA_VERSION:
            raise DetectionContractError(
                "normalized_input_schema_version must be " f"{SCHEMA_VERSION!r}"
            )
        if self.finding_schema_version != DETECTION_FINDING_SCHEMA_VERSION:
            raise DetectionContractError(
                "finding_schema_version must be "
                f"{DETECTION_FINDING_SCHEMA_VERSION!r}"
            )
        for name in (
            "normalized_input_record_count",
            "evaluated_record_count",
            "invalid_input_count",
            "total_finding_count",
            "unique_matched_source_record_count",
        ):
            _require_non_negative_integer(getattr(self, name), name)

        findings_by_rule_id = _count_mapping(
            self.findings_by_rule_id, "findings_by_rule_id"
        )
        findings_by_rule_severity = _count_mapping(
            self.findings_by_rule_severity, "findings_by_rule_severity"
        )
        for severity in findings_by_rule_severity:
            _validate_vocab(severity, RULE_SEVERITIES, "findings_by_rule_severity key")
        if sum(findings_by_rule_id.values()) != self.total_finding_count:
            raise DetectionContractError(
                "findings_by_rule_id must reconcile to total_finding_count"
            )
        if sum(findings_by_rule_severity.values()) != self.total_finding_count:
            raise DetectionContractError(
                "findings_by_rule_severity must reconcile to total_finding_count"
            )
        object.__setattr__(self, "findings_by_rule_id", findings_by_rule_id)
        object.__setattr__(self, "findings_by_rule_severity", findings_by_rule_severity)

        if not isinstance(self.sample_findings_by_rule, Mapping):
            raise DetectionContractError("sample_findings_by_rule must be a mapping")
        samples_by_rule: dict[str, tuple[FindingSample, ...]] = {}
        for rule_id in sorted(self.sample_findings_by_rule):
            _validate_rule_id(rule_id, "sample_findings_by_rule key")
            if rule_id not in findings_by_rule_id:
                raise DetectionContractError(
                    "sample_findings_by_rule keys must exist in findings_by_rule_id"
                )
            raw_samples = self.sample_findings_by_rule[rule_id]
            if isinstance(raw_samples, (str, bytes)) or not isinstance(
                raw_samples, Sequence
            ):
                raise DetectionContractError(
                    "sample finding values must be sequences of FindingSample values"
                )
            samples = tuple(raw_samples)
            if len(samples) > 5:
                raise DetectionContractError(
                    "sample_findings_by_rule may retain at most five samples per rule"
                )
            if len(samples) > findings_by_rule_id[rule_id]:
                raise DetectionContractError(
                    "sample finding count cannot exceed its rule finding count"
                )
            if not all(isinstance(sample, FindingSample) for sample in samples):
                raise DetectionContractError(
                    "sample findings must be FindingSample values"
                )
            samples_by_rule[rule_id] = samples
        object.__setattr__(self, "sample_findings_by_rule", samples_by_rule)

        active_rules = tuple(self.active_rules)
        if not all(isinstance(rule, ActiveRuleVersion) for rule in active_rules):
            raise DetectionContractError("active_rules must contain ActiveRuleVersion values")
        active_rule_ids = tuple(rule.rule_id for rule in active_rules)
        if len(active_rule_ids) != len(set(active_rule_ids)):
            raise DetectionContractError("active_rules must not contain duplicate rule IDs")
        if active_rule_ids != tuple(sorted(active_rule_ids)):
            raise DetectionContractError("active_rules must be ordered by rule_id")
        object.__setattr__(self, "active_rules", active_rules)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a deterministic, bounded detection-run summary."""

        return {
            "finding_schema_version": self.finding_schema_version,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "normalized_input_schema_version": self.normalized_input_schema_version,
            "normalized_input_record_count": self.normalized_input_record_count,
            "evaluated_record_count": self.evaluated_record_count,
            "invalid_input_count": self.invalid_input_count,
            "total_finding_count": self.total_finding_count,
            "findings_by_rule_id": dict(self.findings_by_rule_id),
            "findings_by_rule_severity": dict(self.findings_by_rule_severity),
            "unique_matched_source_record_count": self.unique_matched_source_record_count,
            "sample_findings_by_rule": {
                rule_id: [sample.to_dict() for sample in samples]
                for rule_id, samples in self.sample_findings_by_rule.items()
            },
            "active_rules": [rule.to_dict() for rule in self.active_rules],
        }
