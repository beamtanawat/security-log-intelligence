"""Strict, bounded readers for approved Stage 1.4 detection artifacts.

This module validates a finding JSON Lines file and its bounded detection summary
before a later checkpoint is allowed to import them into SQLite.  It never opens
raw CSV data or normalized-event JSON Lines data, creates no database, and does
not make a security decision.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

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


PROJECT_ROOT = Path(__file__).resolve().parents[2]

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
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
_SUMMARY_KEYS = frozenset(
    {
        "finding_schema_version",
        "input_path",
        "output_path",
        "normalized_input_schema_version",
        "normalized_input_record_count",
        "evaluated_record_count",
        "invalid_input_count",
        "total_finding_count",
        "findings_by_rule_id",
        "findings_by_rule_severity",
        "unique_matched_source_record_count",
        "sample_findings_by_rule",
        "active_rules",
    }
)
_ACTIVE_RULE_KEYS = frozenset({"rule_id", "version"})
_FINDING_SAMPLE_KEYS = frozenset({"finding_id", "source_record_number"})
_PROHIBITED_DECISION_KEYS = frozenset(
    {
        "attack",
        "attack_label",
        "attack_probability",
        "benign",
        "benign_label",
        "compromised",
        "confidence",
        "confidence_score",
        "confirmed_attack",
        "confirmed_incident",
        "incident",
        "incident_id",
        "is_attack",
        "is_malicious",
        "malicious",
        "malicious_label",
        "risk",
        "risk_score",
    }
)


class StorageInputValidationError(ValueError):
    """Raised when an input artifact violates the strict Stage 1.5B boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line_number: int | None = None,
    ) -> None:
        self.code = code
        self.line_number = line_number
        super().__init__(message)


@dataclass(frozen=True)
class ApprovedArtifactIdentity:
    """Expected byte identities for one approved finding JSONL and summary pair."""

    findings_sha256: str
    summary_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.findings_sha256, "findings_sha256")
        _require_sha256(self.summary_sha256, "summary_sha256")


@dataclass(frozen=True)
class ValidatedDetectionArtifacts:
    """Bounded result of strict Stage 1.4 finding and summary validation."""

    run_id: str
    findings_sha256: str
    summary_sha256: str
    finding_count: int
    evidence_count: int
    rule_count: int
    summary: DetectionRunSummary

    def __post_init__(self) -> None:
        _require_sha256(self.run_id, "run_id")
        _require_sha256(self.findings_sha256, "findings_sha256")
        _require_sha256(self.summary_sha256, "summary_sha256")
        if self.run_id != self.findings_sha256:
            raise StorageInputValidationError(
                "RUN_ID_MISMATCH", "run_id must equal findings_sha256."
            )
        for name in ("finding_count", "evidence_count", "rule_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StorageInputValidationError(
                    "INVALID_VALIDATION_COUNT",
                    f"{name} must be a non-negative integer.",
                )
        if not isinstance(self.summary, DetectionRunSummary):
            raise StorageInputValidationError(
                "INVALID_SUMMARY_MODEL", "summary must be a DetectionRunSummary."
            )


@dataclass(frozen=True)
class _FindingStatistics:
    """Bounded aggregate state collected while streaming a finding artifact."""

    findings_sha256: str
    finding_count: int
    evidence_count: int
    findings_by_rule_id: Mapping[str, int]
    findings_by_rule_severity: Mapping[str, int]
    unique_matched_source_record_count: int
    sample_findings_by_rule: Mapping[str, tuple[FindingSample, ...]]


def _require_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise StorageInputValidationError(
            "INVALID_EXPECTED_HASH",
            f"{name} must be a lowercase SHA-256 hexadecimal digest.",
        )


def _prohibited_decision_key(value: object) -> str | None:
    """Return the first prohibited security-decision key in JSON-compatible data."""

    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.lower() in _PROHIBITED_DECISION_KEYS:
                return key
            prohibited_key = _prohibited_decision_key(nested_value)
            if prohibited_key is not None:
                return prohibited_key
    elif isinstance(value, list):
        for item in value:
            prohibited_key = _prohibited_decision_key(item)
            if prohibited_key is not None:
                return prohibited_key
    return None


def _require_exact_object(
    value: object,
    expected_keys: frozenset[str],
    name: str,
    *,
    line_number: int | None = None,
    code: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise StorageInputValidationError(
            code,
            f"{name} must be a JSON object.",
            line_number=line_number,
        )
    if set(value) != expected_keys:
        raise StorageInputValidationError(
            code,
            f"{name} does not contain exactly its contract fields.",
            line_number=line_number,
        )
    return value


def _require_json_array(
    value: object,
    name: str,
    *,
    line_number: int | None = None,
    code: str,
) -> list[object]:
    if not isinstance(value, list):
        raise StorageInputValidationError(
            code,
            f"{name} must be a JSON array.",
            line_number=line_number,
        )
    return value


def _canonical_finding_line(finding: DetectionFinding) -> bytes:
    """Return the exact Stage 1.4 canonical JSONL representation for one finding."""

    return (
        json.dumps(
            finding.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _path_is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _resolve_input_path(value: str | Path, label: str) -> Path:
    """Resolve an artifact path without opening an upstream source artifact."""

    try:
        resolved_path = Path(value).resolve()
    except (OSError, TypeError) as error:
        raise StorageInputValidationError(
            "INVALID_ARTIFACT_PATH", f"{label} path cannot be resolved."
        ) from error

    raw_directory = (PROJECT_ROOT / "data" / "raw").resolve()
    normalized_event_path = (
        PROJECT_ROOT / "data" / "processed" / "stage_1_3f_normalized_events.jsonl"
    ).resolve()
    if _path_is_within(resolved_path, raw_directory) or resolved_path == normalized_event_path:
        raise StorageInputValidationError(
            "UPSTREAM_ARTIFACT_FORBIDDEN",
            "Stage 1.5 input validation must not open raw or normalized artifacts.",
        )
    if not resolved_path.is_file():
        raise StorageInputValidationError(
            "ARTIFACT_NOT_FOUND", f"{label} must be an existing regular file."
        )
    return resolved_path


def _sha256_file(path: Path) -> str:
    """Return one file's SHA-256 without loading its content into memory."""

    digest = sha256()
    try:
        with path.open("rb") as artifact_file:
            while chunk := artifact_file.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise StorageInputValidationError(
            "ARTIFACT_READ_ERROR", "Artifact cannot be read for SHA-256 validation."
        ) from error
    return digest.hexdigest()


def calculate_artifact_identity(
    findings_path: str | Path,
    summary_path: str | Path,
) -> ApprovedArtifactIdentity:
    """Safely hash the two Stage 1.4 artifacts before strict parsing begins."""

    resolved_findings_path = _resolve_input_path(findings_path, "findings_path")
    resolved_summary_path = _resolve_input_path(summary_path, "summary_path")
    if resolved_findings_path == resolved_summary_path:
        raise StorageInputValidationError(
            "ARTIFACT_PATHS_EQUAL",
            "Finding and summary artifact paths must be different.",
        )
    return ApprovedArtifactIdentity(
        findings_sha256=_sha256_file(resolved_findings_path),
        summary_sha256=_sha256_file(resolved_summary_path),
    )


def _as_detection_finding(payload: object, line_number: int) -> DetectionFinding:
    """Strictly reconstruct one public Stage 1.4 DetectionFinding."""

    prohibited_key = _prohibited_decision_key(payload)
    if prohibited_key is not None:
        raise StorageInputValidationError(
            "PROHIBITED_DECISION_FIELD",
            "Detection finding contains a prohibited security-decision field.",
            line_number=line_number,
        )

    finding_data = _require_exact_object(
        payload,
        _FINDING_KEYS,
        "Detection finding",
        line_number=line_number,
        code="FINDING_SCHEMA_MISMATCH",
    )
    rule_data = _require_exact_object(
        finding_data["rule"],
        _RULE_REFERENCE_KEYS,
        "Detection finding rule",
        line_number=line_number,
        code="FINDING_SCHEMA_MISMATCH",
    )
    source_event_data = _require_exact_object(
        finding_data["source_event"],
        _SOURCE_EVENT_KEYS,
        "Detection finding source_event",
        line_number=line_number,
        code="FINDING_SCHEMA_MISMATCH",
    )
    evidence_data = _require_json_array(
        finding_data["evidence"],
        "Detection finding evidence",
        line_number=line_number,
        code="FINDING_COLLECTION_INVALID",
    )
    uncertainties = _require_json_array(
        finding_data["uncertainties"],
        "Detection finding uncertainties",
        line_number=line_number,
        code="FINDING_COLLECTION_INVALID",
    )

    evidence: list[DetectionEvidence] = []
    for item in evidence_data:
        evidence_item = _require_exact_object(
            item,
            _EVIDENCE_KEYS,
            "Detection finding evidence entry",
            line_number=line_number,
            code="FINDING_SCHEMA_MISMATCH",
        )
        _require_json_array(
            evidence_item["source_fields"],
            "Detection finding evidence source_fields",
            line_number=line_number,
            code="FINDING_COLLECTION_INVALID",
        )
        try:
            evidence.append(DetectionEvidence(**evidence_item))
        except (DetectionContractError, TypeError) as error:
            raise StorageInputValidationError(
                "FINDING_CONTRACT_INVALID",
                "Detection finding evidence does not satisfy the Stage 1.4 contract.",
                line_number=line_number,
            ) from error

    try:
        return DetectionFinding(
            finding_schema_version=finding_data["finding_schema_version"],
            finding_id=finding_data["finding_id"],
            rule=FindingRuleReference(**rule_data),
            source_event=SourceEventReference(**source_event_data),
            reason_code=finding_data["reason_code"],
            summary=finding_data["summary"],
            evidence=tuple(evidence),
            time_basis=finding_data["time_basis"],
            uncertainties=uncertainties,
            false_positive_note=finding_data["false_positive_note"],
            deterministic=finding_data["deterministic"],
        )
    except (DetectionContractError, TypeError) as error:
        raise StorageInputValidationError(
            "FINDING_CONTRACT_INVALID",
            "Detection finding does not satisfy the Stage 1.4 contract.",
            line_number=line_number,
        ) from error


def _as_detection_summary(payload: object) -> DetectionRunSummary:
    """Strictly reconstruct the bounded public Stage 1.4 run summary."""

    prohibited_key = _prohibited_decision_key(payload)
    if prohibited_key is not None:
        raise StorageInputValidationError(
            "PROHIBITED_DECISION_FIELD",
            "Detection summary contains a prohibited security-decision field.",
        )

    summary_data = _require_exact_object(
        payload,
        _SUMMARY_KEYS,
        "Detection summary",
        code="SUMMARY_SCHEMA_MISMATCH",
    )
    active_rules_data = _require_json_array(
        summary_data["active_rules"],
        "Detection summary active_rules",
        code="SUMMARY_COLLECTION_INVALID",
    )
    sample_findings_data = summary_data["sample_findings_by_rule"]
    if not isinstance(sample_findings_data, Mapping):
        raise StorageInputValidationError(
            "SUMMARY_COLLECTION_INVALID",
            "Detection summary sample_findings_by_rule must be a JSON object.",
        )
    if not isinstance(summary_data["findings_by_rule_id"], Mapping) or not isinstance(
        summary_data["findings_by_rule_severity"], Mapping
    ):
        raise StorageInputValidationError(
            "SUMMARY_COLLECTION_INVALID",
            "Detection summary count collections must be JSON objects.",
        )

    active_rules: list[ActiveRuleVersion] = []
    for item in active_rules_data:
        rule_data = _require_exact_object(
            item,
            _ACTIVE_RULE_KEYS,
            "Detection summary active rule",
            code="SUMMARY_SCHEMA_MISMATCH",
        )
        try:
            active_rules.append(ActiveRuleVersion(**rule_data))
        except (DetectionContractError, TypeError) as error:
            raise StorageInputValidationError(
                "SUMMARY_CONTRACT_INVALID",
                "Detection summary active rule is invalid.",
            ) from error

    samples_by_rule: dict[str, tuple[FindingSample, ...]] = {}
    for rule_id, raw_samples in sample_findings_data.items():
        samples = _require_json_array(
            raw_samples,
            "Detection summary finding samples",
            code="SUMMARY_COLLECTION_INVALID",
        )
        parsed_samples: list[FindingSample] = []
        for sample in samples:
            sample_data = _require_exact_object(
                sample,
                _FINDING_SAMPLE_KEYS,
                "Detection summary finding sample",
                code="SUMMARY_SCHEMA_MISMATCH",
            )
            try:
                parsed_samples.append(FindingSample(**sample_data))
            except (DetectionContractError, TypeError) as error:
                raise StorageInputValidationError(
                    "SUMMARY_CONTRACT_INVALID",
                    "Detection summary finding sample is invalid.",
                ) from error
        samples_by_rule[rule_id] = tuple(parsed_samples)

    try:
        return DetectionRunSummary(
            finding_schema_version=summary_data["finding_schema_version"],
            input_path=summary_data["input_path"],
            output_path=summary_data["output_path"],
            normalized_input_schema_version=summary_data[
                "normalized_input_schema_version"
            ],
            normalized_input_record_count=summary_data["normalized_input_record_count"],
            evaluated_record_count=summary_data["evaluated_record_count"],
            invalid_input_count=summary_data["invalid_input_count"],
            total_finding_count=summary_data["total_finding_count"],
            findings_by_rule_id=summary_data["findings_by_rule_id"],
            findings_by_rule_severity=summary_data["findings_by_rule_severity"],
            unique_matched_source_record_count=summary_data[
                "unique_matched_source_record_count"
            ],
            sample_findings_by_rule=samples_by_rule,
            active_rules=tuple(active_rules),
        )
    except (DetectionContractError, TypeError) as error:
        raise StorageInputValidationError(
            "SUMMARY_CONTRACT_INVALID",
            "Detection summary does not satisfy the Stage 1.4 contract.",
        ) from error


def _read_summary(
    summary_path: Path,
    expected_sha256: str,
) -> tuple[DetectionRunSummary, str]:
    """Read the intentionally bounded summary and verify its exact byte identity."""

    try:
        summary_bytes = summary_path.read_bytes()
    except OSError as error:
        raise StorageInputValidationError(
            "SUMMARY_READ_ERROR", "Detection summary cannot be read."
        ) from error

    actual_sha256 = sha256(summary_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        raise StorageInputValidationError(
            "SUMMARY_HASH_MISMATCH",
            "Detection summary SHA-256 does not match the approved identity.",
        )
    try:
        payload = json.loads(summary_bytes.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise StorageInputValidationError(
            "INVALID_SUMMARY_UTF8", "Detection summary is not valid UTF-8 text."
        ) from error
    except json.JSONDecodeError as error:
        raise StorageInputValidationError(
            "INVALID_SUMMARY_JSON", "Detection summary is not valid JSON."
        ) from error
    return _as_detection_summary(payload), actual_sha256


def _validate_summary_context(
    summary: DetectionRunSummary,
    findings_path: Path,
) -> tuple[ActiveRuleVersion, ...]:
    """Check bounded summary metadata without opening its normalized input path."""

    try:
        summary_output_path = Path(summary.output_path).resolve()
    except OSError as error:
        raise StorageInputValidationError(
            "SUMMARY_OUTPUT_PATH_INVALID",
            "Detection summary output_path cannot be resolved.",
        ) from error
    if summary_output_path != findings_path:
        raise StorageInputValidationError(
            "SUMMARY_OUTPUT_PATH_MISMATCH",
            "Detection summary does not reference the validated finding artifact.",
        )

    if summary.invalid_input_count != 0:
        raise StorageInputValidationError(
            "SUMMARY_INVALID_INPUT_COUNT",
            "A completed detection output cannot report invalid input records.",
        )
    if summary.normalized_input_record_count != summary.evaluated_record_count:
        raise StorageInputValidationError(
            "SUMMARY_RECORD_COUNT_MISMATCH",
            "Detection summary input and evaluated record counts must match.",
        )

    declared_rules = tuple(summary.active_rules)
    active_rule_ids = {rule.rule_id for rule in declared_rules}
    if not set(summary.findings_by_rule_id).issubset(active_rule_ids):
        raise StorageInputValidationError(
            "SUMMARY_RULE_COUNT_MISMATCH",
            "Detection summary includes counts for an undeclared active rule.",
        )
    return declared_rules


def _validate_finding_summary_relationship(
    finding: DetectionFinding,
    *,
    declared_rule_identities: frozenset[tuple[str, str]],
    line_number: int,
) -> None:
    """Ensure one finding rule/version is declared by this artifact's summary."""

    rule_identity = (finding.rule.rule_id, finding.rule.version)
    if rule_identity not in declared_rule_identities:
        raise StorageInputValidationError(
            "UNDECLARED_RULE_VERSION",
            "Detection finding references a rule/version absent from the summary.",
            line_number=line_number,
        )


def _stream_findings(
    findings_path: Path,
    expected_sha256: str,
    *,
    declared_rules: tuple[ActiveRuleVersion, ...],
    on_finding: Callable[[DetectionFinding], None] | None = None,
) -> _FindingStatistics:
    """Validate one canonical finding line at a time and retain bounded aggregates."""

    digest = sha256()
    finding_count = 0
    evidence_count = 0
    findings_by_rule_id: Counter[str] = Counter()
    findings_by_rule_severity: Counter[str] = Counter()
    sample_findings_by_rule: dict[str, list[FindingSample]] = {}
    previous_sort_key: tuple[int, str] | None = None
    previous_finding_id: str | None = None
    previous_source_record_number: int | None = None
    unique_matched_source_record_count = 0
    declared_rule_identities = frozenset(
        (rule.rule_id, rule.version) for rule in declared_rules
    )

    try:
        with findings_path.open("rb") as findings_file:
            for line_number, raw_line in enumerate(findings_file, start=1):
                digest.update(raw_line)
                if not raw_line.strip():
                    raise StorageInputValidationError(
                        "BLANK_JSONL_LINE",
                        "Detection finding JSONL contains a blank line.",
                        line_number=line_number,
                    )
                try:
                    payload = json.loads(raw_line.decode("utf-8"))
                except UnicodeDecodeError as error:
                    raise StorageInputValidationError(
                        "INVALID_FINDING_UTF8",
                        "Detection finding JSONL is not valid UTF-8 text.",
                        line_number=line_number,
                    ) from error
                except json.JSONDecodeError as error:
                    raise StorageInputValidationError(
                        "INVALID_JSONL",
                        "Detection finding JSONL contains invalid JSON.",
                        line_number=line_number,
                    ) from error

                finding = _as_detection_finding(payload, line_number)
                if raw_line != _canonical_finding_line(finding):
                    raise StorageInputValidationError(
                        "NONCANONICAL_FINDING",
                        "Detection finding JSONL must use Stage 1.4 canonical JSON bytes.",
                        line_number=line_number,
                    )
                if finding.finding_id == previous_finding_id:
                    raise StorageInputValidationError(
                        "DUPLICATE_FINDING_ID",
                        "Detection finding JSONL contains a duplicate finding_id.",
                        line_number=line_number,
                    )

                sort_key = (
                    finding.source_event.source_record_number,
                    finding.rule.rule_id,
                )
                if previous_sort_key is not None and sort_key <= previous_sort_key:
                    raise StorageInputValidationError(
                        "FINDING_ORDER_INVALID",
                        "Detection findings must be ordered by source record number and rule ID.",
                        line_number=line_number,
                    )
                _validate_finding_summary_relationship(
                    finding,
                    declared_rule_identities=declared_rule_identities,
                    line_number=line_number,
                )
                if on_finding is not None:
                    on_finding(finding)

                finding_count += 1
                evidence_count += len(finding.evidence)
                findings_by_rule_id[finding.rule.rule_id] += 1
                findings_by_rule_severity[finding.rule.severity] += 1
                samples = sample_findings_by_rule.setdefault(finding.rule.rule_id, [])
                if len(samples) < 5:
                    samples.append(
                        FindingSample(
                            finding_id=finding.finding_id,
                            source_record_number=finding.source_event.source_record_number,
                        )
                    )
                if previous_source_record_number != finding.source_event.source_record_number:
                    unique_matched_source_record_count += 1
                previous_sort_key = sort_key
                previous_finding_id = finding.finding_id
                previous_source_record_number = finding.source_event.source_record_number
    except OSError as error:
        raise StorageInputValidationError(
            "FINDINGS_READ_ERROR", "Detection finding JSONL cannot be read."
        ) from error

    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise StorageInputValidationError(
            "FINDINGS_HASH_MISMATCH",
            "Detection finding JSONL SHA-256 does not match the approved identity.",
        )
    return _FindingStatistics(
        findings_sha256=actual_sha256,
        finding_count=finding_count,
        evidence_count=evidence_count,
        findings_by_rule_id=dict(findings_by_rule_id),
        findings_by_rule_severity=dict(findings_by_rule_severity),
        unique_matched_source_record_count=unique_matched_source_record_count,
        sample_findings_by_rule={
            rule_id: tuple(samples)
            for rule_id, samples in sample_findings_by_rule.items()
        },
    )


def _reconcile_summary(
    summary: DetectionRunSummary,
    statistics: _FindingStatistics,
) -> None:
    """Reject any difference between bounded summary values and streamed findings."""

    if statistics.finding_count != summary.total_finding_count:
        raise StorageInputValidationError(
            "SUMMARY_FINDING_COUNT_MISMATCH",
            "Detection summary finding count does not reconcile to finding JSONL.",
        )
    if dict(statistics.findings_by_rule_id) != dict(summary.findings_by_rule_id):
        raise StorageInputValidationError(
            "SUMMARY_RULE_COUNT_MISMATCH",
            "Detection summary rule counts do not reconcile to finding JSONL.",
        )
    if dict(statistics.findings_by_rule_severity) != dict(
        summary.findings_by_rule_severity
    ):
        raise StorageInputValidationError(
            "SUMMARY_SEVERITY_COUNT_MISMATCH",
            "Detection summary severity counts do not reconcile to finding JSONL.",
        )
    if (
        statistics.unique_matched_source_record_count
        != summary.unique_matched_source_record_count
    ):
        raise StorageInputValidationError(
            "SUMMARY_MATCHED_RECORD_COUNT_MISMATCH",
            "Detection summary matched-record count does not reconcile to finding JSONL.",
        )
    if dict(statistics.sample_findings_by_rule) != dict(
        summary.sample_findings_by_rule
    ):
        raise StorageInputValidationError(
            "SUMMARY_SAMPLE_MISMATCH",
            "Detection summary samples do not reconcile to finding JSONL.",
        )


def validate_detection_artifacts(
    findings_path: str | Path,
    summary_path: str | Path,
    expected_identity: ApprovedArtifactIdentity,
    *,
    on_finding: Callable[[DetectionFinding], None] | None = None,
) -> ValidatedDetectionArtifacts:
    """Validate one approved Stage 1.4 finding/summary pair with bounded memory.

    The finding file is read as binary JSON Lines one physical line at a time so its
    SHA-256 is calculated from the exact bytes being validated.  The summary is
    intentionally bounded Stage 1.4 metadata and is read as one JSON object.
    """

    if not isinstance(expected_identity, ApprovedArtifactIdentity):
        raise StorageInputValidationError(
            "INVALID_EXPECTED_IDENTITY",
            "expected_identity must be an ApprovedArtifactIdentity.",
        )
    resolved_findings_path = _resolve_input_path(findings_path, "findings_path")
    resolved_summary_path = _resolve_input_path(summary_path, "summary_path")
    if resolved_findings_path == resolved_summary_path:
        raise StorageInputValidationError(
            "ARTIFACT_PATHS_EQUAL",
            "Finding and summary artifact paths must be different.",
        )

    summary, summary_sha256 = _read_summary(
        resolved_summary_path,
        expected_identity.summary_sha256,
    )
    declared_rules = _validate_summary_context(
        summary,
        resolved_findings_path,
    )
    statistics = _stream_findings(
        resolved_findings_path,
        expected_identity.findings_sha256,
        declared_rules=declared_rules,
        on_finding=on_finding,
    )
    _reconcile_summary(summary, statistics)
    return ValidatedDetectionArtifacts(
        run_id=statistics.findings_sha256,
        findings_sha256=statistics.findings_sha256,
        summary_sha256=summary_sha256,
        finding_count=statistics.finding_count,
        evidence_count=statistics.evidence_count,
        rule_count=len(declared_rules),
        summary=summary,
    )
