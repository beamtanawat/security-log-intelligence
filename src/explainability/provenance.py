"""Stage 1.9 immutable-input identity checks.

This module keeps Stage 1.4 finding-to-event joins bound to both stable source
identity components.  It does not interpret findings as security truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detection.models import DetectionFinding


APPROVED_STAGE_1_3_NORMALIZED_SHA256 = (
    "c195c6322665530d56f1bd5390b6b1c20728881a21ee36352c7c46e0a7138976"
)
APPROVED_STAGE_1_4_FINDINGS_SHA256 = (
    "5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc"
)
APPROVED_STAGE_1_4_SUMMARY_SHA256 = (
    "d3585bf577cb1b16aca2a8afb65d18959941e28fc2b9cd6c396c35cf03dd16fe"
)


class FindingIdentityError(ValueError):
    """Raised when a Stage 1.4 finding cannot be safely joined to an event."""


def _require_identity_component(record_number: object, source_record_id: object) -> tuple[int, str]:
    if isinstance(record_number, bool) or not isinstance(record_number, int) or record_number < 1:
        raise FindingIdentityError("source record number must be a positive integer")
    if not isinstance(source_record_id, str) or not source_record_id:
        raise FindingIdentityError("source record ID must be a non-empty string")
    return record_number, source_record_id


def validate_stage_1_4_identities(
    *,
    normalized_sha256: str,
    findings_sha256: str,
    summary_sha256: str,
) -> None:
    """Fail closed unless every immutable Stage 1.4 input has its approved hash."""

    expected = {
        "normalized input": APPROVED_STAGE_1_3_NORMALIZED_SHA256,
        "Stage 1.4 findings": APPROVED_STAGE_1_4_FINDINGS_SHA256,
        "Stage 1.4 summary": APPROVED_STAGE_1_4_SUMMARY_SHA256,
    }
    actual = {
        "normalized input": normalized_sha256,
        "Stage 1.4 findings": findings_sha256,
        "Stage 1.4 summary": summary_sha256,
    }
    for name, expected_hash in expected.items():
        value = actual[name]
        if not isinstance(value, str) or value.lower() != expected_hash:
            raise FindingIdentityError(f"{name} SHA-256 does not match the approved identity")


@dataclass
class FindingRuleIdentityIndex:
    """Collect finding rules while enforcing number-and-ID provenance joins."""

    _record_id_by_number: dict[int, str] = field(default_factory=dict)
    _rule_ids_by_identity: dict[tuple[int, str], set[str]] = field(default_factory=dict)
    _matched_identities: set[tuple[int, str]] = field(default_factory=set)

    def add(self, finding: DetectionFinding) -> None:
        if not isinstance(finding, DetectionFinding):
            raise FindingIdentityError("finding must satisfy the Stage 1.4 detection contract")
        record_number, source_record_id = _require_identity_component(
            finding.source_event.source_record_number,
            finding.source_event.source_record_id,
        )
        existing_id = self._record_id_by_number.get(record_number)
        if existing_id is not None and existing_id != source_record_id:
            raise FindingIdentityError("findings disagree on source record identity")
        self._record_id_by_number[record_number] = source_record_id
        key = (record_number, source_record_id)
        rules = self._rule_ids_by_identity.setdefault(key, set())
        if finding.rule.rule_id in rules:
            raise FindingIdentityError("findings duplicate a rule for one source record identity")
        rules.add(finding.rule.rule_id)

    def rule_ids_for(self, source_record_number: object, source_record_id: object) -> tuple[str, ...]:
        record_number, identifier = _require_identity_component(source_record_number, source_record_id)
        existing_id = self._record_id_by_number.get(record_number)
        if existing_id is not None and existing_id != identifier:
            raise FindingIdentityError("finding source record ID does not match normalized event identity")
        key = (record_number, identifier)
        if key in self._rule_ids_by_identity:
            self._matched_identities.add(key)
        return tuple(sorted(self._rule_ids_by_identity.get(key, ())))

    def assert_all_matched(self) -> None:
        if self._matched_identities != set(self._rule_ids_by_identity):
            raise FindingIdentityError("finding references a normalized record that was not reconciled")
