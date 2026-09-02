"""Deterministic record-level finding construction for synthetic rules.

This Stage 1.4C engine evaluates one already-normalized event at a time. It has
no JSON Lines writer, CLI, state, time window, or production rule activation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from normalization.models import FieldProvenance, NormalizedSecurityEvent

from .models import (
    DetectionEvidence,
    DetectionFinding,
    FindingRuleReference,
    RuleEvaluation,
    SourceEventReference,
    build_finding_id,
)
from .rules import DetectionRule, RuleRegistryError, validate_rule_registry


_MISSING = object()


class DetectionEngineError(ValueError):
    """Raised when a rule evaluation cannot safely become a finding."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _validated_rules(rules: Sequence[DetectionRule]) -> tuple[DetectionRule, ...]:
    if isinstance(rules, (str, bytes)) or not isinstance(rules, Sequence):
        raise DetectionEngineError("INVALID_RULE_REGISTRY", "rules must be a sequence.")
    if not rules:
        return ()
    try:
        return validate_rule_registry(rules)
    except RuleRegistryError as error:
        raise DetectionEngineError("INVALID_RULE_REGISTRY", str(error)) from error


def _source_event_reference(event: NormalizedSecurityEvent) -> SourceEventReference:
    source_type = event.source.get("adapter_type")
    record_number = event.source.get("record_number")
    source_record_id = event.event.get("source_record_id")
    if (
        not isinstance(source_type, str)
        or not source_type.strip()
        or isinstance(record_number, bool)
        or not isinstance(record_number, int)
        or record_number != event.source_record.record_number
        or (
            source_record_id is not None
            and (
                not isinstance(source_record_id, str)
                or not source_record_id.strip()
            )
        )
    ):
        raise DetectionEngineError(
            "INVALID_SOURCE_REFERENCE",
            "Normalized event does not provide a valid source reference.",
        )
    return SourceEventReference(
        source_type=source_type,
        normalized_schema_version=event.schema_version,
        source_record_number=record_number,
        source_record_id=source_record_id,
    )


def _canonical_value(event: NormalizedSecurityEvent, path: str) -> object:
    section_name, *path_parts = path.split(".")
    if not path_parts or not hasattr(event, section_name):
        return _MISSING
    value: object = getattr(event, section_name)
    for path_part in path_parts:
        if not isinstance(value, Mapping) or path_part not in value:
            return _MISSING
        value = value[path_part]
    return value


def _provenance_for_path(
    event: NormalizedSecurityEvent, path: str
) -> FieldProvenance | None:
    for item in event.provenance:
        if item.canonical_path == path:
            return item
    return None


def _evidence_for_evaluation(
    event: NormalizedSecurityEvent,
    rule: DetectionRule,
    evaluation: RuleEvaluation,
) -> tuple[DetectionEvidence, ...]:
    allowed_paths = set(rule.metadata.evidence_paths)
    evidence: list[DetectionEvidence] = []
    for path in evaluation.evidence_paths:
        if path not in allowed_paths:
            raise DetectionEngineError(
                "EVIDENCE_PATH_NOT_ALLOWED",
                "Rule evaluation contains a path not declared in its metadata.",
            )
        observed_value = _canonical_value(event, path)
        if observed_value is _MISSING:
            raise DetectionEngineError(
                "EVIDENCE_PATH_MISSING",
                "Rule evaluation references a canonical path that is absent.",
            )
        if observed_value is None:
            raise DetectionEngineError(
                "EVIDENCE_VALUE_MISSING",
                "Rule evaluation cannot emit null as positive evidence.",
            )
        provenance = _provenance_for_path(event, path)
        if provenance is None:
            raise DetectionEngineError(
                "EVIDENCE_PROVENANCE_MISSING",
                "Rule evaluation evidence has no matching normalization provenance.",
            )
        evidence.append(
            DetectionEvidence(
                canonical_path=path,
                observed_value=observed_value,
                source_fields=provenance.source_fields,
                mapping_operation=provenance.operation,
                interpretation_status=provenance.interpretation_status,
            )
        )
    return tuple(evidence)


def evaluate_event(
    event: NormalizedSecurityEvent,
    rules: Sequence[DetectionRule],
) -> tuple[DetectionFinding, ...]:
    """Evaluate one normalized event with an ordered set of record-level rules.

    Rules for an unsupported source type are not called. A matching synthetic
    rule can produce one provenance-preserving finding; no finding asserts an
    attack, incident, maliciousness, benignness, confidence, or risk score.
    """

    if not isinstance(event, NormalizedSecurityEvent):
        raise TypeError("event must be a NormalizedSecurityEvent")
    prepared_rules = _validated_rules(rules)
    source_event = _source_event_reference(event)
    findings: list[DetectionFinding] = []

    for rule in prepared_rules:
        if source_event.source_type not in rule.metadata.supported_source_types:
            continue
        evaluation = rule.evaluate(event)
        if evaluation is None:
            continue
        if not isinstance(evaluation, RuleEvaluation):
            raise DetectionEngineError(
                "INVALID_RULE_EVALUATION",
                "A matching rule must return RuleEvaluation or None.",
            )
        if evaluation.reason_code != rule.metadata.reason_code:
            raise DetectionEngineError(
                "REASON_CODE_MISMATCH",
                "Rule evaluation reason_code must match its metadata.",
            )

        evidence = _evidence_for_evaluation(event, rule, evaluation)
        rule_reference = FindingRuleReference.from_metadata(rule.metadata)
        findings.append(
            DetectionFinding(
                finding_id=build_finding_id(
                    rule_id=rule_reference.rule_id,
                    rule_version=rule_reference.version,
                    source_type=source_event.source_type,
                    normalized_schema_version=source_event.normalized_schema_version,
                    source_record_number=source_event.source_record_number,
                    source_record_id=source_event.source_record_id,
                ),
                rule=rule_reference,
                source_event=source_event,
                reason_code=evaluation.reason_code,
                summary=evaluation.summary,
                evidence=evidence,
                time_basis="NOT_USED",
                uncertainties=evaluation.uncertainties,
                false_positive_note=rule.metadata.false_positive_scenarios[0],
            )
        )
    return tuple(findings)
