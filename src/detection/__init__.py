"""Stage 1.4 detection contracts.

This package currently exposes only immutable contract models. It contains no
rule registry, rule conditions, evaluation engine, JSONL reader, or CLI.
"""

from .models import (
    DETECTION_FINDING_SCHEMA_VERSION,
    RULE_CATEGORIES,
    RULE_SEVERITIES,
    TIME_BASES,
    ActiveRuleVersion,
    DetectionContractError,
    DetectionEvidence,
    DetectionFinding,
    DetectionRunSummary,
    FindingRuleReference,
    FindingSample,
    RuleEvaluation,
    RuleMetadata,
    SourceEventReference,
    build_finding_id,
)

__all__ = [
    "DETECTION_FINDING_SCHEMA_VERSION",
    "RULE_CATEGORIES",
    "RULE_SEVERITIES",
    "TIME_BASES",
    "ActiveRuleVersion",
    "DetectionContractError",
    "DetectionEvidence",
    "DetectionFinding",
    "DetectionRunSummary",
    "FindingRuleReference",
    "FindingSample",
    "RuleEvaluation",
    "RuleMetadata",
    "SourceEventReference",
    "build_finding_id",
]
