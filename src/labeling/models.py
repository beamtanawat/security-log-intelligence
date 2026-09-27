"""Validated Stage 2.1 label and review vocabulary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

from .identity import annotation_unit_id, require_sha256, sha256_hex, source_record_identity


class LabelValue(StrEnum):
    ATTACK = "ATTACK"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"


class ResolutionStatus(StrEnum):
    RESOLVED = "RESOLVED"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    REVIEWER_NONRESPONSE = "REVIEWER_NONRESPONSE"
    DISAGREEMENT_UNRESOLVED = "DISAGREEMENT_UNRESOLVED"
    REVIEW_INCOMPLETE = "REVIEW_INCOMPLETE"


class Provenance(StrEnum):
    EXTERNAL_CONFIRMED = "EXTERNAL_CONFIRMED"
    HUMAN_ANALYST_ADJUDICATED = "HUMAN_ANALYST_ADJUDICATED"
    AI_ASSISTED_HUMAN_VERIFIED = "AI_ASSISTED_HUMAN_VERIFIED"
    DETECTOR_DERIVED_PROXY = "DETECTOR_DERIVED_PROXY"
    AI_ASSISTED_PROXY_LABEL = "AI_ASSISTED_PROXY_LABEL"


PRIMARY_PROVENANCE = frozenset(
    {
        Provenance.EXTERNAL_CONFIRMED,
        Provenance.HUMAN_ANALYST_ADJUDICATED,
        Provenance.AI_ASSISTED_HUMAN_VERIFIED,
    }
)


def _text(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _sorted_unique(values: object, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple, set, frozenset)):
        raise ValueError(f"{name} must be a sequence")
    prepared = tuple(_text(item, f"{name} item") for item in values)
    if len(prepared) != len(set(prepared)):
        raise ValueError(f"{name} must not contain duplicates")
    return tuple(sorted(prepared))


@dataclass(frozen=True)
class LabelRecord:
    """One immutable resolved or unresolved label projection."""

    label_record_id: str
    dataset_sha256: str
    annotation_contract_sha256: str
    source_record_number: int
    source_record_id: str
    source_record_identity_sha256: str
    annotation_unit_type: str
    annotation_unit_id: str
    unit_mapping_sha256: str
    label: LabelValue | None
    resolution_status: ResolutionStatus
    decision_status: str
    label_provenance: Provenance | None
    human_verified: bool
    review_decision_ids: tuple[str, ...]
    finalized_by_actor_type: str
    finalized_by_id: str
    adjudication_status: str
    adjudication_decision_id: str | None
    evidence_package_id: str
    evidence_source_ids: tuple[str, ...]
    evidence_viewed: tuple[str, ...]
    evidence_window: Mapping[str, object]
    decision_reason: str | None
    review_completed_at: str | None
    label_version: int
    parent_label_record_id: str | None
    supersedes_label_record_id: str | None
    sampling_manifest_row_id: str
    sampling_stratum: str
    sampling_phase: str
    intended_cohort: str
    split_assignment: str
    primary_training_eligible: bool
    primary_validation_eligible: bool
    primary_test_eligible: bool | None
    secondary_sensitivity_eligible: bool
    eligibility_reason_codes: tuple[str, ...]
    exclusion_reason_codes: tuple[str, ...]
    ai_assistance: Mapping[str, object]
    source_artifact_fingerprints: Mapping[str, str]
    created_at: str

    def __post_init__(self) -> None:
        require_sha256(self.dataset_sha256, "dataset_sha256")
        require_sha256(self.annotation_contract_sha256, "annotation_contract_sha256")
        require_sha256(self.source_record_identity_sha256, "source_record_identity_sha256")
        require_sha256(self.unit_mapping_sha256, "unit_mapping_sha256")
        _text(self.source_record_id, "source_record_id")
        _text(self.annotation_unit_id, "annotation_unit_id")
        if self.annotation_unit_id != annotation_unit_id(self.source_record_identity_sha256):
            raise ValueError("annotation_unit_id does not match source identity")
        if isinstance(self.source_record_number, bool) or not isinstance(self.source_record_number, int) or self.source_record_number < 1:
            raise ValueError("source_record_number must be a positive integer")
        if self.annotation_unit_type != "SOURCE_RECORD":
            raise ValueError("annotation_unit_type must be SOURCE_RECORD")
        if not isinstance(self.label, (LabelValue, type(None))):
            raise ValueError("label must be ATTACK, BENIGN, UNCERTAIN, or null")
        if not isinstance(self.resolution_status, ResolutionStatus):
            raise ValueError("invalid resolution_status")
        if self.resolution_status is ResolutionStatus.RESOLVED and self.label is None:
            raise ValueError("RESOLVED label record requires label")
        if self.resolution_status is not ResolutionStatus.RESOLVED and self.label is not None:
            raise ValueError("unresolved label record must have null label")
        if self.label is not None and not isinstance(self.label_provenance, Provenance):
            raise ValueError("resolved label requires provenance")
        if isinstance(self.label_version, bool) or not isinstance(self.label_version, int) or self.label_version < 1:
            raise ValueError("label_version must be a positive integer")
        if self.label_version == 1 and self.parent_label_record_id is not None:
            raise ValueError("version 1 cannot have a parent")
        if self.label_version > 1 and not self.parent_label_record_id:
            raise ValueError("correction version requires a parent")
        if not isinstance(self.human_verified, bool):
            raise ValueError("human_verified must be boolean")
        object.__setattr__(self, "review_decision_ids", _sorted_unique(self.review_decision_ids, "review_decision_ids"))
        object.__setattr__(self, "evidence_source_ids", _sorted_unique(self.evidence_source_ids, "evidence_source_ids"))
        object.__setattr__(self, "evidence_viewed", _sorted_unique(self.evidence_viewed, "evidence_viewed"))
        object.__setattr__(self, "eligibility_reason_codes", _sorted_unique(self.eligibility_reason_codes, "eligibility_reason_codes"))
        object.__setattr__(self, "exclusion_reason_codes", _sorted_unique(self.exclusion_reason_codes, "exclusion_reason_codes"))
        if self.primary_test_eligible and self.split_assignment != "TEST":
            raise ValueError("primary_test_eligible requires TEST split")
        if self.split_assignment == "TEST" and self.primary_test_eligible is None:
            raise ValueError("TEST record requires private primary_test_eligible")

    @classmethod
    def new(
        cls,
        *,
        dataset_sha256: str,
        annotation_unit_id: str,
        label: LabelValue,
        resolution_status: ResolutionStatus = ResolutionStatus.RESOLVED,
        provenance: Provenance = Provenance.HUMAN_ANALYST_ADJUDICATED,
        parent_label_record_id: str | None = None,
        label_version: int = 1,
        review_decision_ids: tuple[str, ...] = (),
        source_record_number: int = 1,
        source_record_id: str = "SOURCE_RECORD_TEST",
    ) -> "LabelRecord":
        """Create a record from already-existing review decisions.

        This constructor does not infer or generate a security label. Callers
        must supply the human/evidence result and may bind it to a history.
        """

        contract_hash = sha256_hex(["stage-2.1-annotation-contract-v1"])
        identity_hash = annotation_unit_id.removeprefix("AU-")
        require_sha256(identity_hash, "source_record_identity_sha256")
        if identity_hash != source_record_identity(dataset_sha256, source_record_number, source_record_id):
            raise ValueError("annotation_unit_id does not match source record identity inputs")
        payload = [
            "stage-2.1-label-record-v1",
            dataset_sha256,
            annotation_unit_id,
            label_version,
            parent_label_record_id,
            sorted(review_decision_ids),
            None,
        ]
        return cls(
            label_record_id=f"LR-{sha256_hex(payload)}",
            dataset_sha256=dataset_sha256,
            annotation_contract_sha256=contract_hash,
            source_record_number=source_record_number,
            source_record_id=source_record_id,
            source_record_identity_sha256=identity_hash,
            annotation_unit_type="SOURCE_RECORD",
            annotation_unit_id=annotation_unit_id,
            unit_mapping_sha256=sha256_hex({"annotation_unit_id": annotation_unit_id, "source_record_identities": [identity_hash]}),
            label=label,
            resolution_status=resolution_status,
            decision_status="RESOLVED" if resolution_status is ResolutionStatus.RESOLVED else "CLOSED_UNRESOLVED",
            label_provenance=provenance if resolution_status is ResolutionStatus.RESOLVED else None,
            human_verified=True,
            review_decision_ids=tuple(review_decision_ids),
            finalized_by_actor_type="HUMAN_ADJUDICATOR",
            finalized_by_id="TEST_ACTOR",
            adjudication_status="RESOLVED",
            adjudication_decision_id=None,
            evidence_package_id="EP-TEST",
            evidence_source_ids=(),
            evidence_viewed=(),
            evidence_window={"window_basis": "RECORD_ONLY", "prediction_cutoff": "SOURCE_RECORD_OBSERVATION"},
            decision_reason="test fixture decision",
            review_completed_at=datetime.now(timezone.utc).isoformat(),
            label_version=label_version,
            parent_label_record_id=parent_label_record_id,
            supersedes_label_record_id=parent_label_record_id,
            sampling_manifest_row_id="SM-TEST",
            sampling_stratum="HISTORICAL_BASE_0_50",
            sampling_phase="TRAIN_P0_PILOT",
            intended_cohort="TRAIN_ENRICHED",
            split_assignment="TRAIN",
            primary_training_eligible=provenance in PRIMARY_PROVENANCE,
            primary_validation_eligible=False,
            primary_test_eligible=False,
            secondary_sensitivity_eligible=True,
            eligibility_reason_codes=("PRIMARY_PROVENANCE",) if provenance in PRIMARY_PROVENANCE else (),
            exclusion_reason_codes=() if provenance in PRIMARY_PROVENANCE else ("PROXY_PROVENANCE",),
            ai_assistance={"used": False},
            source_artifact_fingerprints={"normalized_input": dataset_sha256},
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, object]:
        result = dict(self.__dict__)
        for name in ("label", "resolution_status", "label_provenance"):
            value = result[name]
            result[name] = value.value if isinstance(value, StrEnum) else value
        for name in ("review_decision_ids", "evidence_source_ids", "evidence_viewed", "eligibility_reason_codes", "exclusion_reason_codes"):
            result[name] = list(result[name])
        return result
