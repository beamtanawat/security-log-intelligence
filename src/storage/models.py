"""Immutable Stage 1.5 storage contracts.

These types define bounded storage-facing values only. They do not parse finding
artifacts, import a detection run, execute SQL, or make a security decision.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from detection.models import RULE_SEVERITIES


STORAGE_SCHEMA_VERSION = "1.0"
STORAGE_USER_VERSION = 1
DEFAULT_QUERY_LIMIT = 50
MAX_QUERY_LIMIT = 500

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
_REASON_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")


class StorageContractError(ValueError):
    """Raised when a value violates the Stage 1.5 storage contract."""


def _require_non_empty_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise StorageContractError(f"{name} must be a non-empty string")


def _require_non_negative_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StorageContractError(f"{name} must be a non-negative integer")


def _require_positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StorageContractError(f"{name} must be a positive integer")


def _require_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise StorageContractError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_optional_text(value: str | None, name: str) -> None:
    if value is not None:
        _require_non_empty_text(value, name)


def _require_optional_sha256(value: str | None, name: str) -> None:
    if value is not None:
        _require_sha256(value, name)


def _require_optional_rule_id(value: str | None, name: str) -> None:
    if value is not None:
        _require_non_empty_text(value, name)
        if _RULE_ID_PATTERN.fullmatch(value) is None:
            raise StorageContractError(f"{name} must be a lowercase dotted identifier")


def _require_optional_version(value: str | None, name: str) -> None:
    if value is not None:
        _require_non_empty_text(value, name)
        if _VERSION_PATTERN.fullmatch(value) is None:
            raise StorageContractError(f"{name} must be a semantic version such as '1.0'")


def _require_optional_reason_code(value: str | None, name: str) -> None:
    if value is not None:
        _require_non_empty_text(value, name)
        if _REASON_CODE_PATTERN.fullmatch(value) is None:
            raise StorageContractError(
                f"{name} must be an uppercase underscore-separated identifier"
            )


@dataclass(frozen=True)
class StorageImportSummary:
    """Bounded, deterministic identity and count summary for a future import."""

    run_id: str
    findings_sha256: str
    summary_sha256: str
    finding_count: int
    evidence_count: int
    rule_count: int
    storage_schema_version: str = STORAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_sha256(self.run_id, "run_id")
        _require_sha256(self.findings_sha256, "findings_sha256")
        _require_sha256(self.summary_sha256, "summary_sha256")
        if self.run_id != self.findings_sha256:
            raise StorageContractError("run_id must equal findings_sha256")
        for name in ("finding_count", "evidence_count", "rule_count"):
            _require_non_negative_integer(getattr(self, name), name)
        if self.storage_schema_version != STORAGE_SCHEMA_VERSION:
            raise StorageContractError(
                f"storage_schema_version must be {STORAGE_SCHEMA_VERSION!r}"
            )

    def to_dict(self) -> dict[str, str | int]:
        """Return deterministic JSON-ready import metadata."""

        return {
            "storage_schema_version": self.storage_schema_version,
            "run_id": self.run_id,
            "findings_sha256": self.findings_sha256,
            "summary_sha256": self.summary_sha256,
            "finding_count": self.finding_count,
            "evidence_count": self.evidence_count,
            "rule_count": self.rule_count,
        }


@dataclass(frozen=True)
class StorageAuditResult:
    """Bounded deterministic result shape for a future independent audit."""

    run_id: str
    findings_sha256: str
    summary_sha256: str
    logical_export_sha256: str
    reconstructed_findings_sha256: str
    finding_count: int
    evidence_count: int
    rule_count: int
    storage_schema_version: str = STORAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_sha256(self.run_id, "run_id")
        _require_sha256(self.findings_sha256, "findings_sha256")
        _require_sha256(self.summary_sha256, "summary_sha256")
        _require_sha256(self.logical_export_sha256, "logical_export_sha256")
        _require_sha256(
            self.reconstructed_findings_sha256,
            "reconstructed_findings_sha256",
        )
        if self.run_id != self.findings_sha256:
            raise StorageContractError("run_id must equal findings_sha256")
        if self.reconstructed_findings_sha256 != self.findings_sha256:
            raise StorageContractError(
                "reconstructed_findings_sha256 must equal findings_sha256"
            )
        for name in ("finding_count", "evidence_count", "rule_count"):
            _require_non_negative_integer(getattr(self, name), name)
        if self.storage_schema_version != STORAGE_SCHEMA_VERSION:
            raise StorageContractError(
                f"storage_schema_version must be {STORAGE_SCHEMA_VERSION!r}"
            )

    def to_dict(self) -> dict[str, str | int]:
        """Return deterministic JSON-ready audit metadata."""

        return {
            "storage_schema_version": self.storage_schema_version,
            "run_id": self.run_id,
            "findings_sha256": self.findings_sha256,
            "summary_sha256": self.summary_sha256,
            "logical_export_sha256": self.logical_export_sha256,
            "reconstructed_findings_sha256": self.reconstructed_findings_sha256,
            "finding_count": self.finding_count,
            "evidence_count": self.evidence_count,
            "rule_count": self.rule_count,
        }


@dataclass(frozen=True)
class FindingQuery:
    """Allowlisted filter values for the bounded read-only query interface."""

    run_id: str | None = None
    finding_id: str | None = None
    rule_id: str | None = None
    rule_version: str | None = None
    severity: str | None = None
    reason_code: str | None = None
    source_type: str | None = None
    source_record_number: int | None = None
    evidence_path: str | None = None
    limit: int = DEFAULT_QUERY_LIMIT

    def __post_init__(self) -> None:
        _require_optional_sha256(self.run_id, "run_id")
        _require_optional_sha256(self.finding_id, "finding_id")
        _require_optional_rule_id(self.rule_id, "rule_id")
        _require_optional_version(self.rule_version, "rule_version")
        if self.severity is not None:
            _require_non_empty_text(self.severity, "severity")
            if self.severity not in RULE_SEVERITIES:
                allowed = ", ".join(sorted(RULE_SEVERITIES))
                raise StorageContractError(f"severity must be one of: {allowed}")
        _require_optional_reason_code(self.reason_code, "reason_code")
        _require_optional_text(self.source_type, "source_type")
        _require_optional_text(self.evidence_path, "evidence_path")
        if self.source_record_number is not None:
            _require_positive_integer(
                self.source_record_number,
                "source_record_number",
            )
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise StorageContractError("limit must be an integer")
        if not 1 <= self.limit <= MAX_QUERY_LIMIT:
            raise StorageContractError(
                f"limit must be between 1 and {MAX_QUERY_LIMIT}"
            )


@dataclass(frozen=True)
class EvidenceQuery:
    """Allowlisted bounded lookup for one finding's stored evidence."""

    run_id: str
    finding_id: str
    limit: int = DEFAULT_QUERY_LIMIT

    def __post_init__(self) -> None:
        _require_sha256(self.run_id, "run_id")
        _require_sha256(self.finding_id, "finding_id")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise StorageContractError("limit must be an integer")
        if not 1 <= self.limit <= MAX_QUERY_LIMIT:
            raise StorageContractError(
                f"limit must be between 1 and {MAX_QUERY_LIMIT}"
            )


@dataclass(frozen=True)
class StoredDetectionRun:
    """Typed, bounded projection of one stored detection run."""

    run_id: str
    findings_sha256: str
    summary_sha256: str
    finding_artifact_path: str
    summary_artifact_path: str
    finding_schema_version: str
    normalized_input_schema_version: str
    normalized_input_record_count: int
    evaluated_record_count: int
    invalid_input_count: int
    total_finding_count: int
    unique_matched_source_record_count: int

    def to_dict(self) -> dict[str, str | int]:
        """Return stored metadata without reading upstream artifacts."""

        return {
            "run_id": self.run_id,
            "findings_sha256": self.findings_sha256,
            "summary_sha256": self.summary_sha256,
            "finding_artifact_path": self.finding_artifact_path,
            "summary_artifact_path": self.summary_artifact_path,
            "finding_schema_version": self.finding_schema_version,
            "normalized_input_schema_version": self.normalized_input_schema_version,
            "normalized_input_record_count": self.normalized_input_record_count,
            "evaluated_record_count": self.evaluated_record_count,
            "invalid_input_count": self.invalid_input_count,
            "total_finding_count": self.total_finding_count,
            "unique_matched_source_record_count": self.unique_matched_source_record_count,
        }


@dataclass(frozen=True)
class StoredFinding:
    """Typed stored finding projection with its unchanged canonical JSON text."""

    run_id: str
    finding_id: str
    finding_schema_version: str
    rule_id: str
    rule_version: str
    rule_name: str
    rule_category: str
    rule_severity: str
    source_type: str
    normalized_schema_version: str
    source_record_number: int
    source_record_id: str | None
    reason_code: str
    summary: str
    time_basis: str
    uncertainties_json: str
    false_positive_note: str
    deterministic: bool
    canonical_finding_json: str

    def to_dict(self) -> dict[str, str | int | bool | None]:
        """Return stored fields without parsing or reserializing canonical JSON."""

        return {
            "run_id": self.run_id,
            "finding_id": self.finding_id,
            "finding_schema_version": self.finding_schema_version,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_name": self.rule_name,
            "rule_category": self.rule_category,
            "rule_severity": self.rule_severity,
            "source_type": self.source_type,
            "normalized_schema_version": self.normalized_schema_version,
            "source_record_number": self.source_record_number,
            "source_record_id": self.source_record_id,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "time_basis": self.time_basis,
            "uncertainties_json": self.uncertainties_json,
            "false_positive_note": self.false_positive_note,
            "deterministic": self.deterministic,
            "canonical_finding_json": self.canonical_finding_json,
        }


@dataclass(frozen=True)
class StoredFindingEvidence:
    """Typed stored evidence/provenance projection for one finding."""

    run_id: str
    finding_id: str
    ordinal: int
    canonical_path: str
    observed_value_json: str
    source_fields_json: str
    mapping_operation: str
    interpretation_status: str

    def to_dict(self) -> dict[str, str | int]:
        """Return the stored projection without dereferencing upstream evidence."""

        return {
            "run_id": self.run_id,
            "finding_id": self.finding_id,
            "ordinal": self.ordinal,
            "canonical_path": self.canonical_path,
            "observed_value_json": self.observed_value_json,
            "source_fields_json": self.source_fields_json,
            "mapping_operation": self.mapping_operation,
            "interpretation_status": self.interpretation_status,
        }
