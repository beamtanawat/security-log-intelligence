"""Synthetic contract tests for Stage 1.4A detection terminology and models."""

from __future__ import annotations

import json
import sys
import unittest
from dataclasses import fields, replace
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detection.models import (  # noqa: E402
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
from detection.rules import (  # noqa: E402
    ACTIVE_RULES,
    BUILT_IN_RULES,
    InactiveRulePlaceholder,
    RuleRegistryError,
    validate_rule_registry,
)


def build_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id="fortigate.example_observation",
        version="1.0",
        name="Example source observation",
        description="Surfaces a source-product observation for analyst review.",
        category="SOURCE_PRODUCT_OBSERVATION",
        severity="INFORMATIONAL",
        supported_source_types=("fortigate",),
        required_paths=("event.subtype_source",),
        evidence_paths=("event.subtype_source", "threat_observations.name_source"),
        reason_code="EXAMPLE_SOURCE_OBSERVATION",
        security_rationale="A source-product observation may deserve review.",
        false_positive_scenarios=("The source product can classify legitimate activity.",),
        limitations=("A match is not a confirmed attack.",),
    )


def build_source_event() -> SourceEventReference:
    return SourceEventReference(
        source_type="fortigate",
        normalized_schema_version="1.0",
        source_record_number=7,
        source_record_id="LOGUID_OPAQUE_7",
    )


def build_evidence(path: str = "event.subtype_source") -> DetectionEvidence:
    return DetectionEvidence(
        canonical_path=path,
        observed_value="anomaly" if path.startswith("event.") else "source-name",
        source_fields=("event_subtype",),
        mapping_operation="COPIED",
        interpretation_status="VERIFIED",
    )


def build_finding() -> DetectionFinding:
    metadata = build_metadata()
    rule = FindingRuleReference.from_metadata(metadata)
    source_event = build_source_event()
    return DetectionFinding(
        finding_id=build_finding_id(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            source_type=source_event.source_type,
            normalized_schema_version=source_event.normalized_schema_version,
            source_record_number=source_event.source_record_number,
            source_record_id=source_event.source_record_id,
        ),
        rule=rule,
        source_event=source_event,
        reason_code=metadata.reason_code,
        summary="The configured source-product observation is present.",
        evidence=(build_evidence(),),
        time_basis="NOT_USED",
        uncertainties=("The source observation is not ground truth.",),
        false_positive_note="Legitimate source-product classifications can match.",
    )


class DetectionContractTests(unittest.TestCase):
    def test_rule_metadata_is_immutable_and_deterministically_serialized(self) -> None:
        metadata = build_metadata()

        self.assertEqual(metadata.to_dict(), metadata.to_dict())
        self.assertEqual(metadata.supported_source_types, ("fortigate",))
        self.assertEqual(
            metadata.evidence_paths,
            ("event.subtype_source", "threat_observations.name_source"),
        )
        with self.assertRaises(AttributeError):
            metadata.name = "Changed"  # type: ignore[misc]

    def test_rule_metadata_rejects_invalid_identifiers_vocabularies_and_documentation(self) -> None:
        values = build_metadata().to_dict()
        values["rule_id"] = "UPPERCASE"
        with self.assertRaises(DetectionContractError):
            RuleMetadata(**values)

        values = build_metadata().to_dict()
        values["severity"] = "CRITICAL"
        with self.assertRaises(DetectionContractError):
            RuleMetadata(**values)

        values = build_metadata().to_dict()
        values["evidence_paths"] = ["event.subtype_source", "event.subtype_source"]
        with self.assertRaises(DetectionContractError):
            RuleMetadata(**values)

        values = build_metadata().to_dict()
        values["false_positive_scenarios"] = []
        with self.assertRaises(DetectionContractError):
            RuleMetadata(**values)

    def test_evidence_preserves_json_ready_value_and_stage_1_3_provenance(self) -> None:
        evidence = DetectionEvidence(
            canonical_path="threat_observations.name_source",
            observed_value={"b": [1, None], "a": True},
            source_fields=("threat_name",),
            mapping_operation="COPIED",
            interpretation_status="CONTEXT_DEPENDENT",
        )

        self.assertEqual(evidence.to_dict()["observed_value"], {"a": True, "b": [1, None]})
        with self.assertRaises(DetectionContractError):
            DetectionEvidence(
                canonical_path="event.invalid",
                observed_value={"not": {"json"}},
                source_fields=("event_type",),
                mapping_operation="COPIED",
                interpretation_status="VERIFIED",
            )
        with self.assertRaises(DetectionContractError):
            DetectionEvidence(
                canonical_path="event.invalid",
                observed_value="value",
                source_fields=("event_type",),
                mapping_operation="UNKNOWN_OPERATION",
                interpretation_status="VERIFIED",
            )

    def test_finding_id_uses_all_required_identity_components(self) -> None:
        source_event = build_source_event()
        first = build_finding_id(
            rule_id="fortigate.example_observation",
            rule_version="1.0",
            source_type=source_event.source_type,
            normalized_schema_version=source_event.normalized_schema_version,
            source_record_number=source_event.source_record_number,
            source_record_id=source_event.source_record_id,
        )
        second = build_finding_id(
            rule_id="fortigate.example_observation",
            rule_version="1.0",
            source_type=source_event.source_type,
            normalized_schema_version=source_event.normalized_schema_version,
            source_record_number=source_event.source_record_number,
            source_record_id=source_event.source_record_id,
        )
        missing_identifier = build_finding_id(
            rule_id="fortigate.example_observation",
            rule_version="1.0",
            source_type=source_event.source_type,
            normalized_schema_version=source_event.normalized_schema_version,
            source_record_number=source_event.source_record_number,
            source_record_id=None,
        )

        self.assertEqual(first, second)
        self.assertNotEqual(first, missing_identifier)
        self.assertEqual(len(first), 64)

    def test_finding_is_traceable_deterministic_and_separate_from_source_severity(self) -> None:
        finding = build_finding()
        serialized = finding.to_dict()

        self.assertEqual(serialized, finding.to_dict())
        self.assertEqual(serialized["rule"]["severity"], "INFORMATIONAL")
        self.assertEqual(serialized["source_event"]["source_record_id"], "LOGUID_OPAQUE_7")
        self.assertEqual(serialized["time_basis"], "NOT_USED")
        self.assertNotIn("event_severity", serialized["rule"])
        self.assertNotIn("risk_score", serialized)
        self.assertEqual(json.dumps(serialized, sort_keys=True), json.dumps(finding.to_dict(), sort_keys=True))

    def test_finding_rejects_wrong_identity_unordered_evidence_and_prohibited_fields(self) -> None:
        finding = build_finding()
        values = finding.to_dict()
        with self.assertRaises(DetectionContractError):
            DetectionFinding(
                finding_id="0" * 64,
                rule=finding.rule,
                source_event=finding.source_event,
                reason_code=finding.reason_code,
                summary=finding.summary,
                evidence=finding.evidence,
                time_basis=finding.time_basis,
                uncertainties=finding.uncertainties,
                false_positive_note=finding.false_positive_note,
            )

        with self.assertRaises(DetectionContractError):
            DetectionFinding(
                finding_id=finding.finding_id,
                rule=finding.rule,
                source_event=finding.source_event,
                reason_code=finding.reason_code,
                summary=finding.summary,
                evidence=(
                    build_evidence("threat_observations.name_source"),
                    build_evidence("event.subtype_source"),
                ),
                time_basis=finding.time_basis,
                uncertainties=finding.uncertainties,
                false_positive_note=finding.false_positive_note,
            )

        with self.assertRaises(TypeError):
            DetectionFinding(
                finding_id=finding.finding_id,
                rule=finding.rule,
                source_event=finding.source_event,
                reason_code=finding.reason_code,
                summary=finding.summary,
                evidence=finding.evidence,
                time_basis=finding.time_basis,
                uncertainties=finding.uncertainties,
                false_positive_note=finding.false_positive_note,
                risk_score=1,  # type: ignore[call-arg]
            )
        self.assertNotIn("attack", values)

    def test_rule_evaluation_keeps_only_neutral_pre_finding_information(self) -> None:
        evaluation = RuleEvaluation(
            reason_code="EXAMPLE_SOURCE_OBSERVATION",
            summary="A configured source observation is present.",
            evidence_paths=("threat_observations.name_source", "event.subtype_source"),
            uncertainties=("Source meaning remains context-dependent.",),
        )

        self.assertEqual(
            evaluation.evidence_paths,
            ("event.subtype_source", "threat_observations.name_source"),
        )
        with self.assertRaises(DetectionContractError):
            RuleEvaluation(
                reason_code="not_uppercase",
                summary="Summary",
                evidence_paths=("event.subtype_source",),
                uncertainties=("Boundary",),
            )

    def test_run_summary_is_bounded_and_deterministically_serialized(self) -> None:
        finding = build_finding()
        summary = DetectionRunSummary(
            input_path="data/processed/input.jsonl",
            output_path="data/processed/output.jsonl",
            normalized_input_schema_version="1.0",
            normalized_input_record_count=2,
            evaluated_record_count=2,
            invalid_input_count=0,
            total_finding_count=1,
            findings_by_rule_id={finding.rule.rule_id: 1},
            findings_by_rule_severity={"INFORMATIONAL": 1},
            unique_matched_source_record_count=1,
            sample_findings_by_rule={
                finding.rule.rule_id: (
                    FindingSample(finding.finding_id, finding.source_event.source_record_number),
                )
            },
            active_rules=(ActiveRuleVersion(finding.rule.rule_id, finding.rule.version),),
        )

        self.assertEqual(summary.to_dict(), summary.to_dict())
        self.assertEqual(summary.to_dict()["active_rules"], [{"rule_id": finding.rule.rule_id, "version": "1.0"}])

    def test_run_summary_rejects_more_than_five_samples_and_unsorted_rules(self) -> None:
        finding = build_finding()
        samples = tuple(
            FindingSample(finding.finding_id, index + 1) for index in range(6)
        )
        with self.assertRaises(DetectionContractError):
            DetectionRunSummary(
                input_path="input.jsonl",
                output_path="output.jsonl",
                normalized_input_schema_version="1.0",
                normalized_input_record_count=6,
                evaluated_record_count=6,
                invalid_input_count=0,
                total_finding_count=6,
                findings_by_rule_id={finding.rule.rule_id: 6},
                findings_by_rule_severity={"INFORMATIONAL": 6},
                unique_matched_source_record_count=6,
                sample_findings_by_rule={finding.rule.rule_id: samples},
            )

        with self.assertRaises(DetectionContractError):
            DetectionRunSummary(
                input_path="input.jsonl",
                output_path="output.jsonl",
                normalized_input_schema_version="1.0",
                normalized_input_record_count=1,
                evaluated_record_count=1,
                invalid_input_count=0,
                total_finding_count=1,
                findings_by_rule_id={finding.rule.rule_id: 1},
                findings_by_rule_severity={"INFORMATIONAL": 0},
            )

        with self.assertRaises(DetectionContractError):
            DetectionRunSummary(
                input_path="input.jsonl",
                output_path="output.jsonl",
                normalized_input_schema_version="1.0",
                normalized_input_record_count=0,
                evaluated_record_count=0,
                invalid_input_count=0,
                total_finding_count=0,
                active_rules=(
                    ActiveRuleVersion("fortigate.z_rule", "1.0"),
                    ActiveRuleVersion("fortigate.a_rule", "1.0"),
                ),
            )


class RuleRegistryTests(unittest.TestCase):
    def test_builtin_registry_is_ordered_unique_and_inactive(self) -> None:
        rule_ids = tuple(rule.metadata.rule_id for rule in BUILT_IN_RULES)

        self.assertEqual(rule_ids, tuple(sorted(rule_ids)))
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(ACTIVE_RULES, ())
        self.assertTrue(
            all(rule.evaluate(None) is None for rule in BUILT_IN_RULES)  # type: ignore[arg-type]
        )

    def test_registry_rejects_duplicate_and_unsorted_rule_ids(self) -> None:
        duplicate = InactiveRulePlaceholder(BUILT_IN_RULES[0].metadata)
        with self.assertRaises(RuleRegistryError):
            validate_rule_registry((BUILT_IN_RULES[0], duplicate))
        with self.assertRaises(RuleRegistryError):
            validate_rule_registry(tuple(reversed(BUILT_IN_RULES)))

        unsupported_source = InactiveRulePlaceholder(
            replace(
                BUILT_IN_RULES[0].metadata,
                supported_source_types=("unsupported_source",),
            )
        )
        with self.assertRaises(RuleRegistryError):
            validate_rule_registry((unsupported_source,))

    def test_initial_metadata_matches_the_approved_rule_specifications(self) -> None:
        expected = {
            "fortigate.anomaly_subtype_observation": {
                "version": "1.0",
                "category": "SOURCE_PRODUCT_OBSERVATION",
                "severity": "INFORMATIONAL",
                "supported_source_types": ("fortigate",),
                "required_paths": ("event.subtype_source",),
                "evidence_paths": (
                    "event.action_source",
                    "event.severity_source",
                    "event.subtype_source",
                    "event.type_source",
                ),
                "reason_code": "SOURCE_ANOMALY_SUBTYPE_OBSERVED",
            },
            "fortigate.source_threat_observation": {
                "version": "1.0",
                "category": "SOURCE_PRODUCT_OBSERVATION",
                "severity": "INFORMATIONAL",
                "supported_source_types": ("fortigate",),
                "required_paths": ("threat_observations",),
                "evidence_paths": (
                    "threat_observations.action_source",
                    "threat_observations.id_raw",
                    "threat_observations.name_source",
                    "threat_observations.pattern_source",
                    "threat_observations.reference_source",
                    "threat_observations.severity_source",
                    "threat_observations.type_source",
                ),
                "reason_code": "SOURCE_THREAT_OBSERVATION_PRESENT",
            },
        }
        actual = {
            rule.metadata.rule_id: {
                "version": rule.metadata.version,
                "category": rule.metadata.category,
                "severity": rule.metadata.severity,
                "supported_source_types": rule.metadata.supported_source_types,
                "required_paths": rule.metadata.required_paths,
                "evidence_paths": rule.metadata.evidence_paths,
                "reason_code": rule.metadata.reason_code,
            }
            for rule in BUILT_IN_RULES
        }

        self.assertEqual(actual, expected)

    def test_initial_metadata_is_fortigate_only_informational_and_has_no_threshold_fields(self) -> None:
        metadata_field_names = {item.name for item in fields(RuleMetadata)}
        prohibited_field_names = {"threshold", "window", "confidence", "risk_score", "enabled"}

        self.assertTrue(all(rule.metadata.supported_source_types == ("fortigate",) for rule in BUILT_IN_RULES))
        self.assertTrue(all(rule.metadata.severity == "INFORMATIONAL" for rule in BUILT_IN_RULES))
        self.assertEqual(metadata_field_names & prohibited_field_names, set())

        rules_source = (PROJECT_ROOT / "src" / "detection" / "rules.py").read_text(
            encoding="utf-8"
        )
        for prohibited_token in ("importlib", "eval(", "exec("):
            self.assertNotIn(prohibited_token, rules_source)

    def test_documented_registry_catalog_matches_metadata(self) -> None:
        document = (
            PROJECT_ROOT / "docs" / "initial_detection_rules.md"
        ).read_text(encoding="utf-8")
        rows = documented_registry_catalog(document)
        expected_rows = {
            rule.metadata.rule_id: (
                rule.metadata.version,
                rule.metadata.category,
                rule.metadata.severity,
                "; ".join(rule.metadata.supported_source_types),
                "; ".join(rule.metadata.required_paths),
                "; ".join(rule.metadata.evidence_paths),
                rule.metadata.reason_code,
                "No",
            )
            for rule in BUILT_IN_RULES
        }

        self.assertEqual(rows, expected_rows)
        self.assertEqual(document.count("| Review item | Approved answer |"), 2)
        self.assertIn("Rule Match != Confirmed Attack", document)


def documented_registry_catalog(document: str) -> dict[str, tuple[str, ...]]:
    """Read the checked-in 1.4B catalog without evaluating any rule."""

    rows: dict[str, tuple[str, ...]] = {}
    in_catalog = False
    for line in document.splitlines():
        if line == "## Registry Catalog":
            in_catalog = True
            continue
        if in_catalog and line.startswith("## "):
            break
        if not in_catalog or not line.startswith("| "):
            continue
        cells = tuple(cell.strip().replace("`", "") for cell in line.strip().split("|")[1:-1])
        if cells[0] == "Rule ID" or set(cells[0]) == {"-"}:
            continue
        rows[cells[0]] = cells[1:]
    return rows
