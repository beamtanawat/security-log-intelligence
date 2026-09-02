"""Reviewed FortiGate source-observation rules for Stage 1.4D.

The two active rules evaluate one normalized event at a time. They use only
approved canonical values and surface source-product observations; neither rule
confirms an attack, compromise, incident, maliciousness, or benignness.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from normalization.models import NormalizedSecurityEvent

from .models import (
    RULE_CATEGORIES,
    RULE_SEVERITIES,
    RuleEvaluation,
    RuleMetadata,
)


_SUPPORTED_SOURCE_TYPES = frozenset({"fortigate"})


class RuleRegistryError(ValueError):
    """Raised when a rule registry does not satisfy the Stage 1.4B contract."""


@runtime_checkable
class DetectionRule(Protocol):
    """The future record-level rule interface.

    The Stage 1.4C engine will call this interface. Stage 1.4B supplies only
    inactive placeholders and does not evaluate any condition.
    """

    metadata: RuleMetadata

    def evaluate(self, event: NormalizedSecurityEvent) -> RuleEvaluation | None:
        """Return a neutral rule evaluation for a future matching event, or None."""


@dataclass(frozen=True)
class InactiveRulePlaceholder:
    """A no-match rule definition retained for registry validation tests."""

    metadata: RuleMetadata

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, RuleMetadata):
            raise RuleRegistryError("metadata must be a RuleMetadata")

    def evaluate(self, event: NormalizedSecurityEvent) -> None:
        """Return no match for a deliberately inactive test-only rule."""

        del event
        return None


def validate_rule_registry(
    rules: Sequence[DetectionRule],
) -> tuple[DetectionRule, ...]:
    """Validate immutable rule metadata and the required lexicographic order.

    The function deliberately does not execute rules or inspect source events.
    """

    if isinstance(rules, (str, bytes)) or not isinstance(rules, Sequence):
        raise RuleRegistryError("rules must be a sequence of DetectionRule values")
    prepared_rules = tuple(rules)
    if not prepared_rules:
        raise RuleRegistryError("rules must contain at least one rule")

    rule_ids: list[str] = []
    for rule in prepared_rules:
        if not isinstance(rule, DetectionRule):
            raise RuleRegistryError("each registry entry must implement DetectionRule")
        metadata = rule.metadata
        if metadata.category not in RULE_CATEGORIES:
            raise RuleRegistryError("rule metadata has an unsupported category")
        if metadata.severity not in RULE_SEVERITIES:
            raise RuleRegistryError("rule metadata has an unsupported severity")
        if not metadata.supported_source_types:
            raise RuleRegistryError("rule metadata must support at least one source type")
        unsupported_source_types = (
            set(metadata.supported_source_types) - _SUPPORTED_SOURCE_TYPES
        )
        if unsupported_source_types:
            raise RuleRegistryError("rule metadata has an unsupported source type")
        if not metadata.security_rationale:
            raise RuleRegistryError("rule metadata must include a security rationale")
        if not metadata.false_positive_scenarios:
            raise RuleRegistryError(
                "rule metadata must include false-positive scenarios"
            )
        if not metadata.limitations:
            raise RuleRegistryError("rule metadata must include limitations")
        rule_ids.append(metadata.rule_id)

    if len(rule_ids) != len(set(rule_ids)):
        raise RuleRegistryError("rule registry must not contain duplicate rule IDs")
    if tuple(rule_ids) != tuple(sorted(rule_ids)):
        raise RuleRegistryError("rule registry must be ordered by rule_id")
    return prepared_rules


_ANOMALY_SUBTYPE_METADATA = RuleMetadata(
    rule_id="fortigate.anomaly_subtype_observation",
    version="1.0",
    name="FortiGate anomaly subtype observation",
    description=(
        "Surfaces the exact FortiGate source subtype 'anomaly' for analyst review; "
        "it does not assert an attack."
    ),
    category="SOURCE_PRODUCT_OBSERVATION",
    severity="INFORMATIONAL",
    supported_source_types=("fortigate",),
    required_paths=("event.subtype_source",),
    evidence_paths=(
        "event.action_source",
        "event.severity_source",
        "event.subtype_source",
        "event.type_source",
    ),
    reason_code="SOURCE_ANOMALY_SUBTYPE_OBSERVED",
    security_rationale=(
        "FortiGate supplied an anomaly subtype observation that may deserve review."
    ),
    false_positive_scenarios=(
        "The source-product anomaly category may occur without malicious activity.",
    ),
    limitations=(
        "A source-product anomaly subtype is not proof of maliciousness, compromise, "
        "or attack.",
        "The rule does not use timestamps, thresholds, session history, or traffic volume.",
    ),
)

_SOURCE_THREAT_METADATA = RuleMetadata(
    rule_id="fortigate.source_threat_observation",
    version="1.0",
    name="FortiGate source threat observation",
    description=(
        "Surfaces populated FortiGate threat-observation values for analyst review; "
        "it does not assert an attack."
    ),
    category="SOURCE_PRODUCT_OBSERVATION",
    severity="INFORMATIONAL",
    supported_source_types=("fortigate",),
    required_paths=("threat_observations",),
    evidence_paths=(
        "threat_observations.action_source",
        "threat_observations.id_raw",
        "threat_observations.name_source",
        "threat_observations.pattern_source",
        "threat_observations.reference_source",
        "threat_observations.severity_source",
        "threat_observations.type_source",
    ),
    reason_code="SOURCE_THREAT_OBSERVATION_PRESENT",
    security_rationale=(
        "The source product emitted one or more threat-related observations that may "
        "deserve analyst visibility."
    ),
    false_positive_scenarios=(
        "A source-product observation may reflect policy, classification, scanning, "
        "or vendor logic rather than a confirmed attack.",
    ),
    limitations=(
        "Records without threat values are not labeled benign.",
        "The rule does not use timestamps, thresholds, session history, or traffic volume.",
    ),
)


def _is_populated(value: object) -> bool:
    """Return whether a canonical source-observation value is present."""

    return value is not None and (not isinstance(value, str) or bool(value.strip()))


def _canonical_value(event: NormalizedSecurityEvent, path: str) -> object | None:
    """Return one canonical value, or ``None`` when the declared path is absent."""

    section_name, *path_parts = path.split(".")
    if not path_parts or not hasattr(event, section_name):
        return None
    value: object = getattr(event, section_name)
    for path_part in path_parts:
        if not isinstance(value, Mapping) or path_part not in value:
            return None
        value = value[path_part]
    return value


def _populated_evidence_paths(
    event: NormalizedSecurityEvent, paths: Sequence[str]
) -> tuple[str, ...]:
    """Return populated declared paths in their already-canonical path order."""

    return tuple(path for path in paths if _is_populated(_canonical_value(event, path)))


def _is_fortigate_event(event: NormalizedSecurityEvent) -> bool:
    return event.source.get("adapter_type") == "fortigate"


@dataclass(frozen=True)
class FortiGateAnomalySubtypeObservationRule:
    """Surface the exact FortiGate ``anomaly`` source subtype for review."""

    metadata: RuleMetadata = _ANOMALY_SUBTYPE_METADATA

    def evaluate(self, event: NormalizedSecurityEvent) -> RuleEvaluation | None:
        if not _is_fortigate_event(event):
            return None
        if event.event.get("subtype_source") != "anomaly":
            return None
        return RuleEvaluation(
            reason_code=self.metadata.reason_code,
            summary="FortiGate reported the source subtype 'anomaly'.",
            evidence_paths=_populated_evidence_paths(
                event, self.metadata.evidence_paths
            ),
            uncertainties=self.metadata.limitations,
        )


@dataclass(frozen=True)
class FortiGateSourceThreatObservationRule:
    """Surface populated FortiGate threat-observation values for review."""

    metadata: RuleMetadata = _SOURCE_THREAT_METADATA

    def evaluate(self, event: NormalizedSecurityEvent) -> RuleEvaluation | None:
        if not _is_fortigate_event(event):
            return None
        evidence_paths = _populated_evidence_paths(event, self.metadata.evidence_paths)
        if not evidence_paths:
            return None
        return RuleEvaluation(
            reason_code=self.metadata.reason_code,
            summary="FortiGate reported populated source threat-observation values.",
            evidence_paths=evidence_paths,
            uncertainties=self.metadata.limitations,
        )


# Active definitions are fixed in ascending rule-ID order. The engine remains the
# only component that constructs findings from their record-level evaluations.
BUILT_IN_RULES: tuple[DetectionRule, ...] = (
    FortiGateAnomalySubtypeObservationRule(),
    FortiGateSourceThreatObservationRule(),
)

# The active registry is explicit, immutable, and contains only the two reviewed
# informational source-observation rules.
ACTIVE_RULES: tuple[DetectionRule, ...] = BUILT_IN_RULES

validate_rule_registry(ACTIVE_RULES)
