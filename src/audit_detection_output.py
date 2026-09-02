"""Streaming audit for Stage 1.4 deterministic finding JSON Lines output.

The audit reads one finding at a time and, when given the run summary, streams
the referenced normalized input alongside it.  It validates finding identity,
ordering, reviewed metadata, evidence, provenance, counts, and Stage 1.4
interpretation boundaries without collecting either file in memory.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from detection.engine import DetectionEngineError, evaluate_event
from detection.input import DetectionInputError, iter_normalized_events
from detection.models import (
    ActiveRuleVersion,
    DetectionContractError,
    DetectionEvidence,
    DetectionFinding,
    DetectionRunSummary,
    FindingRuleReference,
    FindingSample,
    SourceEventReference,
)
from detection.rules import ACTIVE_RULES, DetectionRule, validate_rule_registry
from normalization.models import FieldProvenance, NormalizedSecurityEvent


_FINDING_KEYS = frozenset(
    {
        "finding_schema_version",
        "finding_id",
        "rule",
        "source_event",
        "reason_code",
        "summary",
        "evidence",
        "time_basis",
        "uncertainties",
        "false_positive_note",
        "deterministic",
    }
)
_RULE_REFERENCE_KEYS = frozenset({"rule_id", "version", "name", "category", "severity"})
_SOURCE_EVENT_KEYS = frozenset(
    {
        "source_type",
        "normalized_schema_version",
        "source_record_number",
        "source_record_id",
    }
)
_EVIDENCE_KEYS = frozenset(
    {
        "canonical_path",
        "observed_value",
        "source_fields",
        "mapping_operation",
        "interpretation_status",
    }
)
_PROHIBITED_DECISION_KEYS = frozenset(
    {
        "attack",
        "attack_label",
        "confirmed_attack",
        "incident",
        "incident_id",
        "malicious",
        "malicious_label",
        "benign",
        "benign_label",
        "risk",
        "risk_score",
        "confidence",
    }
)
_MISSING = object()
_MAX_SAMPLES_PER_RULE = 5


class DetectionOutputAuditError(ValueError):
    """Raised when a finding output violates the Stage 1.4 contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line_number: int | None = None,
        source_record_number: int | None = None,
    ) -> None:
        self.code = code
        self.line_number = line_number
        self.source_record_number = source_record_number
        super().__init__(message)


@dataclass(frozen=True)
class DetectionOutputAudit:
    """Bounded aggregate evidence produced by a finding-output audit."""

    finding_count: int
    findings_by_rule_id: Mapping[str, int]
    findings_by_rule_severity: Mapping[str, int]
    unique_matched_source_record_count: int
    sample_findings_by_rule: Mapping[str, Sequence[FindingSample]]

    def to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-compatible aggregate audit evidence."""

        return {
            "finding_count": self.finding_count,
            "findings_by_rule_id": dict(sorted(self.findings_by_rule_id.items())),
            "findings_by_rule_severity": dict(
                sorted(self.findings_by_rule_severity.items())
            ),
            "unique_matched_source_record_count": self.unique_matched_source_record_count,
            "sample_findings_by_rule": {
                rule_id: [sample.to_dict() for sample in samples]
                for rule_id, samples in sorted(self.sample_findings_by_rule.items())
            },
        }


@dataclass(frozen=True)
class _FindingLine:
    line_number: int
    finding: DetectionFinding


def _require_mapping(
    value: object,
    name: str,
    line_number: int,
    source_record_number: int | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DetectionOutputAuditError(
            "INVALID_FINDING_OBJECT",
            f"Detection finding {name} must be a JSON object.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    return value


def _require_exact_keys(
    value: object,
    expected_keys: frozenset[str],
    name: str,
    line_number: int,
    source_record_number: int | None = None,
) -> Mapping[str, object]:
    mapping = _require_mapping(value, name, line_number, source_record_number)
    if set(mapping) != expected_keys:
        raise DetectionOutputAuditError(
            "FINDING_SCHEMA_MISMATCH",
            f"Detection finding {name} does not contain exactly its contract fields.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    return mapping


def _prohibited_decision_key(value: object) -> str | None:
    """Return a prohibited security-decision key found in JSON-compatible data."""

    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.lower() in _PROHIBITED_DECISION_KEYS:
                return key
            nested_key = _prohibited_decision_key(nested_value)
            if nested_key is not None:
                return nested_key
    elif isinstance(value, list):
        for item in value:
            nested_key = _prohibited_decision_key(item)
            if nested_key is not None:
                return nested_key
    return None


def _as_detection_finding(payload: object, line_number: int) -> DetectionFinding:
    """Reconstruct one public finding contract without repairing it."""

    prohibited_key = _prohibited_decision_key(payload)
    if prohibited_key is not None:
        raise DetectionOutputAuditError(
            "PROHIBITED_DECISION_FIELD",
            "Detection finding contains a prohibited security-decision field.",
            line_number=line_number,
        )

    finding_data = _require_exact_keys(payload, _FINDING_KEYS, "root", line_number)
    source_event_data = _require_exact_keys(
        finding_data["source_event"], _SOURCE_EVENT_KEYS, "source_event", line_number
    )
    record_number = source_event_data.get("source_record_number")
    source_record_number = (
        record_number
        if isinstance(record_number, int) and not isinstance(record_number, bool)
        else None
    )
    rule_data = _require_exact_keys(
        finding_data["rule"], _RULE_REFERENCE_KEYS, "rule", line_number, source_record_number
    )
    evidence_data = finding_data["evidence"]
    uncertainties = finding_data["uncertainties"]
    if not isinstance(evidence_data, list) or not isinstance(uncertainties, list):
        raise DetectionOutputAuditError(
            "FINDING_COLLECTION_INVALID",
            "Detection finding evidence and uncertainties must be JSON arrays.",
            line_number=line_number,
            source_record_number=source_record_number,
        )

    try:
        evidence = tuple(
            DetectionEvidence(
                **_require_exact_keys(
                    item,
                    _EVIDENCE_KEYS,
                    "evidence entry",
                    line_number,
                    source_record_number,
                )
            )
            for item in evidence_data
        )
        return DetectionFinding(
            finding_schema_version=finding_data["finding_schema_version"],
            finding_id=finding_data["finding_id"],
            rule=FindingRuleReference(**rule_data),
            source_event=SourceEventReference(**source_event_data),
            reason_code=finding_data["reason_code"],
            summary=finding_data["summary"],
            evidence=evidence,
            time_basis=finding_data["time_basis"],
            uncertainties=uncertainties,
            false_positive_note=finding_data["false_positive_note"],
            deterministic=finding_data["deterministic"],
        )
    except (TypeError, DetectionContractError) as error:
        raise DetectionOutputAuditError(
            "FINDING_CONTRACT_INVALID",
            "Detection finding does not satisfy the Stage 1.4 contract.",
            line_number=line_number,
            source_record_number=source_record_number,
        ) from error


def _iter_detection_findings(path: Path) -> Iterator[_FindingLine]:
    """Yield strictly reconstructed findings without retaining output records."""

    try:
        with path.open("r", encoding="utf-8", newline="") as output_file:
            for line_number, line in enumerate(output_file, start=1):
                if not line.strip():
                    raise DetectionOutputAuditError(
                        "BLANK_JSONL_LINE",
                        "Detection finding output contains a blank line.",
                        line_number=line_number,
                    )
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as error:
                    raise DetectionOutputAuditError(
                        "INVALID_JSONL",
                        "Detection finding output is not valid JSON.",
                        line_number=line_number,
                    ) from error
                yield _FindingLine(line_number, _as_detection_finding(payload, line_number))
    except UnicodeDecodeError as error:
        raise DetectionOutputAuditError(
            "INVALID_OUTPUT_UTF8", "Detection finding output is not UTF-8 text."
        ) from error
    except OSError as error:
        raise DetectionOutputAuditError(
            "OUTPUT_READ_ERROR", "Detection finding output cannot be read."
        ) from error


def _active_rules_by_id() -> dict[str, DetectionRule]:
    """Return the reviewed fixed registry as a lookup for audit checks."""

    return {
        rule.metadata.rule_id: rule
        for rule in validate_rule_registry(ACTIVE_RULES)
    }


def _validate_registry_relationship(
    finding: DetectionFinding,
    rules_by_id: Mapping[str, DetectionRule],
    line_number: int,
) -> None:
    """Validate one finding against the fixed reviewed rule registry."""

    rule = rules_by_id.get(finding.rule.rule_id)
    if rule is None:
        raise DetectionOutputAuditError(
            "RULE_NOT_ACTIVE",
            "Detection finding references a rule outside the active registry.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    metadata = rule.metadata
    if finding.rule != FindingRuleReference.from_metadata(metadata):
        raise DetectionOutputAuditError(
            "RULE_METADATA_MISMATCH",
            "Detection finding rule metadata differs from the active registry.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    if finding.source_event.source_type not in metadata.supported_source_types:
        raise DetectionOutputAuditError(
            "RULE_SOURCE_MISMATCH",
            "Detection finding source type is not supported by its active rule.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    if finding.reason_code != metadata.reason_code:
        raise DetectionOutputAuditError(
            "RULE_REASON_CODE_MISMATCH",
            "Detection finding reason code differs from the active registry.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    if finding.false_positive_note != metadata.false_positive_scenarios[0]:
        raise DetectionOutputAuditError(
            "FALSE_POSITIVE_NOTE_MISMATCH",
            "Detection finding false-positive note differs from the active rule.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    if tuple(finding.uncertainties) != tuple(metadata.limitations):
        raise DetectionOutputAuditError(
            "UNCERTAINTY_MISMATCH",
            "Detection finding uncertainties differ from the active rule limitations.",
            line_number=line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    for evidence in finding.evidence:
        if evidence.canonical_path not in metadata.evidence_paths:
            raise DetectionOutputAuditError(
                "EVIDENCE_PATH_NOT_DECLARED",
                "Detection finding contains an undeclared evidence path.",
                line_number=line_number,
                source_record_number=finding.source_event.source_record_number,
            )
        if evidence.observed_value is None or (
            isinstance(evidence.observed_value, str)
            and not evidence.observed_value.strip()
        ):
            raise DetectionOutputAuditError(
                "POSITIVE_EVIDENCE_INVALID",
                "Detection finding contains missing positive evidence.",
                line_number=line_number,
                source_record_number=finding.source_event.source_record_number,
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
    for provenance in event.provenance:
        if provenance.canonical_path == path:
            return provenance
    return None


def _validate_event_relationship(
    finding: DetectionFinding,
    event: NormalizedSecurityEvent,
    expected_finding: DetectionFinding,
    line_number: int,
) -> None:
    """Validate exact input evidence/provenance and deterministic evaluation output."""

    source_record_number = finding.source_event.source_record_number
    expected_source_reference = expected_finding.source_event
    if finding.source_event != expected_source_reference:
        raise DetectionOutputAuditError(
            "SOURCE_REFERENCE_MISMATCH",
            "Detection finding does not reference the matching normalized event.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    if finding.finding_id != expected_finding.finding_id:
        raise DetectionOutputAuditError(
            "FINDING_ID_MISMATCH",
            "Detection finding identity differs from deterministic evaluation output.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    for evidence in finding.evidence:
        expected_value = _canonical_value(event, evidence.canonical_path)
        if expected_value is _MISSING or evidence.observed_value != expected_value:
            raise DetectionOutputAuditError(
                "EVIDENCE_VALUE_MISMATCH",
                "Detection evidence does not match the normalized canonical value.",
                line_number=line_number,
                source_record_number=source_record_number,
            )
        provenance = _provenance_for_path(event, evidence.canonical_path)
        if provenance is None or (
            evidence.source_fields != tuple(provenance.source_fields)
            or evidence.mapping_operation != provenance.operation
            or evidence.interpretation_status != provenance.interpretation_status
        ):
            raise DetectionOutputAuditError(
                "EVIDENCE_PROVENANCE_MISMATCH",
                "Detection evidence does not retain matching normalized provenance.",
                line_number=line_number,
                source_record_number=source_record_number,
            )
    if finding.to_dict() != expected_finding.to_dict():
        raise DetectionOutputAuditError(
            "FINDING_CONTENT_MISMATCH",
            "Detection finding differs from deterministic active-rule evaluation.",
            line_number=line_number,
            source_record_number=source_record_number,
        )


def _next_or_none(iterator: Iterator[_FindingLine]) -> _FindingLine | None:
    try:
        return next(iterator)
    except StopIteration:
        return None


def _append_finding(
    finding_line: _FindingLine,
    *,
    rules_by_id: Mapping[str, DetectionRule],
    previous_sort_key: tuple[int, str] | None,
    findings_by_rule_id: Counter[str],
    findings_by_rule_severity: Counter[str],
    sample_findings_by_rule: dict[str, list[FindingSample]],
) -> tuple[int, str]:
    """Validate one physical output record and add only bounded audit state."""

    finding = finding_line.finding
    sort_key = (finding.source_event.source_record_number, finding.rule.rule_id)
    if previous_sort_key is not None and sort_key <= previous_sort_key:
        raise DetectionOutputAuditError(
            "FINDING_ORDER_INVALID",
            "Detection findings must be ordered by source record number and rule ID.",
            line_number=finding_line.line_number,
            source_record_number=finding.source_event.source_record_number,
        )
    _validate_registry_relationship(finding, rules_by_id, finding_line.line_number)
    findings_by_rule_id[finding.rule.rule_id] += 1
    findings_by_rule_severity[finding.rule.severity] += 1
    samples = sample_findings_by_rule.setdefault(finding.rule.rule_id, [])
    if len(samples) < _MAX_SAMPLES_PER_RULE:
        samples.append(
            FindingSample(
                finding_id=finding.finding_id,
                source_record_number=finding.source_event.source_record_number,
            )
        )
    return sort_key


def _build_audit(
    *,
    finding_count: int,
    findings_by_rule_id: Counter[str],
    findings_by_rule_severity: Counter[str],
    unique_matched_source_record_count: int,
    sample_findings_by_rule: Mapping[str, Sequence[FindingSample]],
) -> DetectionOutputAudit:
    return DetectionOutputAudit(
        finding_count=finding_count,
        findings_by_rule_id=dict(findings_by_rule_id),
        findings_by_rule_severity=dict(findings_by_rule_severity),
        unique_matched_source_record_count=unique_matched_source_record_count,
        sample_findings_by_rule={
            rule_id: tuple(samples)
            for rule_id, samples in sample_findings_by_rule.items()
        },
    )


def _validate_summary_contract(
    output_path: Path,
    expected_summary: DetectionRunSummary,
    rules_by_id: Mapping[str, DetectionRule],
) -> None:
    """Validate the summary context needed for full input/output reconciliation."""

    if not isinstance(expected_summary, DetectionRunSummary):
        raise TypeError("expected_summary must be a DetectionRunSummary or None")
    if Path(expected_summary.output_path).resolve() != output_path.resolve():
        raise DetectionOutputAuditError(
            "SUMMARY_OUTPUT_PATH_MISMATCH",
            "Detection run summary does not reference the audited output path.",
        )
    expected_active_rules = tuple(
        ActiveRuleVersion(rule.metadata.rule_id, rule.metadata.version)
        for rule in rules_by_id.values()
    )
    if tuple(expected_summary.active_rules) != expected_active_rules:
        raise DetectionOutputAuditError(
            "SUMMARY_ACTIVE_RULES_MISMATCH",
            "Detection run summary does not retain the reviewed active registry.",
        )
    if expected_summary.invalid_input_count != 0:
        raise DetectionOutputAuditError(
            "SUMMARY_INVALID_INPUT_COUNT",
            "A successful detection output cannot report invalid input records.",
        )


def _validate_summary_counts(
    audit: DetectionOutputAudit, expected_summary: DetectionRunSummary
) -> None:
    """Confirm the bounded audit aggregates exactly reconcile to the run summary."""

    if audit.finding_count != expected_summary.total_finding_count:
        raise DetectionOutputAuditError(
            "SUMMARY_FINDING_COUNT_MISMATCH",
            "Detection finding count does not reconcile to the run summary.",
        )
    if dict(audit.findings_by_rule_id) != dict(expected_summary.findings_by_rule_id):
        raise DetectionOutputAuditError(
            "SUMMARY_RULE_COUNT_MISMATCH",
            "Detection findings by rule do not reconcile to the run summary.",
        )
    if dict(audit.findings_by_rule_severity) != dict(
        expected_summary.findings_by_rule_severity
    ):
        raise DetectionOutputAuditError(
            "SUMMARY_SEVERITY_COUNT_MISMATCH",
            "Detection findings by severity do not reconcile to the run summary.",
        )
    if (
        audit.unique_matched_source_record_count
        != expected_summary.unique_matched_source_record_count
    ):
        raise DetectionOutputAuditError(
            "SUMMARY_MATCHED_RECORD_COUNT_MISMATCH",
            "Matched source-record count does not reconcile to the run summary.",
        )
    if dict(audit.sample_findings_by_rule) != dict(
        expected_summary.sample_findings_by_rule
    ):
        raise DetectionOutputAuditError(
            "SUMMARY_SAMPLE_MISMATCH",
            "Bounded finding samples do not reconcile to the run summary.",
        )


def audit_detection_jsonl(
    path: str | Path,
    expected_summary: DetectionRunSummary | None = None,
) -> DetectionOutputAudit:
    """Stream and audit finding JSONL without retaining full input or output files.

    Without ``expected_summary``, the audit validates the self-contained output
    contract, ordering, registry metadata, positive evidence shape, and bounded
    counts.  With the summary from ``evaluate_detection_jsonl``, it additionally
    streams the referenced normalized input to validate exact evidence, provenance,
    source traceability, rule evaluation, and run-summary reconciliation.
    """

    output_path = Path(path).resolve()
    if not output_path.is_file():
        raise DetectionOutputAuditError(
            "OUTPUT_NOT_FOUND", "Detection finding output does not exist."
        )
    rules_by_id = _active_rules_by_id()
    if expected_summary is not None:
        _validate_summary_contract(output_path, expected_summary, rules_by_id)

    findings_by_rule_id: Counter[str] = Counter()
    findings_by_rule_severity: Counter[str] = Counter()
    sample_findings_by_rule: dict[str, list[FindingSample]] = {}
    finding_count = 0
    unique_matched_source_record_count = 0
    previous_sort_key: tuple[int, str] | None = None
    previous_record_number: int | None = None
    finding_iterator = _iter_detection_findings(output_path)

    if expected_summary is None:
        for finding_line in finding_iterator:
            previous_sort_key = _append_finding(
                finding_line,
                rules_by_id=rules_by_id,
                previous_sort_key=previous_sort_key,
                findings_by_rule_id=findings_by_rule_id,
                findings_by_rule_severity=findings_by_rule_severity,
                sample_findings_by_rule=sample_findings_by_rule,
            )
            finding_count += 1
            record_number = finding_line.finding.source_event.source_record_number
            if record_number != previous_record_number:
                unique_matched_source_record_count += 1
                previous_record_number = record_number
        return _build_audit(
            finding_count=finding_count,
            findings_by_rule_id=findings_by_rule_id,
            findings_by_rule_severity=findings_by_rule_severity,
            unique_matched_source_record_count=unique_matched_source_record_count,
            sample_findings_by_rule=sample_findings_by_rule,
        )

    pending_finding = _next_or_none(finding_iterator)
    normalized_input_record_count = 0
    evaluated_record_count = 0
    try:
        for event in iter_normalized_events(expected_summary.input_path):
            normalized_input_record_count += 1
            evaluated_record_count += 1
            record_number = event.source_record.record_number
            if (
                pending_finding is not None
                and pending_finding.finding.source_event.source_record_number < record_number
            ):
                raise DetectionOutputAuditError(
                    "FINDING_ORDER_OR_REFERENCE_INVALID",
                    "Detection output references a source record before the current input event.",
                    line_number=pending_finding.line_number,
                    source_record_number=(
                        pending_finding.finding.source_event.source_record_number
                    ),
                )
            try:
                expected_findings = evaluate_event(event, tuple(rules_by_id.values()))
            except DetectionEngineError as error:
                raise DetectionOutputAuditError(
                    "EVALUATION_RECONCILIATION_FAILED",
                    "The active registry could not be reconciled with normalized input.",
                    source_record_number=record_number,
                ) from error

            for expected_finding in expected_findings:
                if pending_finding is None:
                    raise DetectionOutputAuditError(
                        "FINDING_MISSING",
                        "Detection output is missing a configured rule match.",
                        source_record_number=record_number,
                    )
                previous_sort_key = _append_finding(
                    pending_finding,
                    rules_by_id=rules_by_id,
                    previous_sort_key=previous_sort_key,
                    findings_by_rule_id=findings_by_rule_id,
                    findings_by_rule_severity=findings_by_rule_severity,
                    sample_findings_by_rule=sample_findings_by_rule,
                )
                _validate_event_relationship(
                    pending_finding.finding,
                    event,
                    expected_finding,
                    pending_finding.line_number,
                )
                finding_count += 1
                if previous_record_number != record_number:
                    unique_matched_source_record_count += 1
                    previous_record_number = record_number
                pending_finding = _next_or_none(finding_iterator)

            if (
                pending_finding is not None
                and pending_finding.finding.source_event.source_record_number <= record_number
            ):
                raise DetectionOutputAuditError(
                    "UNEXPECTED_FINDING",
                    "Detection output contains an extra or out-of-order finding.",
                    line_number=pending_finding.line_number,
                    source_record_number=(
                        pending_finding.finding.source_event.source_record_number
                    ),
                )
    except DetectionInputError as error:
        raise DetectionOutputAuditError(
            "NORMALIZED_INPUT_INVALID",
            "The normalized input referenced by the run summary cannot be audited.",
            line_number=error.line_number,
            source_record_number=error.source_record_number,
        ) from error

    if pending_finding is not None:
        raise DetectionOutputAuditError(
            "UNEXPECTED_FINDING",
            "Detection output contains a finding without a matching normalized event.",
            line_number=pending_finding.line_number,
            source_record_number=pending_finding.finding.source_event.source_record_number,
        )

    audit = _build_audit(
        finding_count=finding_count,
        findings_by_rule_id=findings_by_rule_id,
        findings_by_rule_severity=findings_by_rule_severity,
        unique_matched_source_record_count=unique_matched_source_record_count,
        sample_findings_by_rule=sample_findings_by_rule,
    )
    if normalized_input_record_count != expected_summary.normalized_input_record_count or (
        evaluated_record_count != expected_summary.evaluated_record_count
    ):
        raise DetectionOutputAuditError(
            "SUMMARY_INPUT_COUNT_MISMATCH",
            "Normalized input record counts do not reconcile to the run summary.",
        )
    _validate_summary_counts(audit, expected_summary)
    return audit
