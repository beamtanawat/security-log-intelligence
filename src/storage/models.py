"""Immutable Stage 1.5 storage contracts.

These types define bounded storage-facing values only. They do not parse finding
artifacts, import a detection run, execute a query, or make a security decision.
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
    """Allowlisted filter values for a future bounded read-only query interface."""

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
