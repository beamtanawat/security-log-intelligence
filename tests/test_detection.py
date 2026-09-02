"""Synthetic contract tests for Stage 1.4A detection terminology and models."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, fields, replace
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
from detection.engine import DetectionEngineError, evaluate_event  # noqa: E402
from detection.input import DetectionInputError, iter_normalized_events  # noqa: E402
from evaluate_detections import (  # noqa: E402
    PROCESSED_DATA_DIRECTORY as DETECTION_PROCESSED_DATA_DIRECTORY,
    DetectionRunError,
    evaluate_detection_jsonl,
    main as evaluate_detections_main,
)
from audit_detection_output import (  # noqa: E402
    DetectionOutputAuditError,
    audit_detection_jsonl,
)
from normalization.fortigate import normalize_fortigate_record  # noqa: E402
from normalization.models import SourceRecord  # noqa: E402
from parsers.fortigate import (  # noqa: E402
    BASELINE_FORTIGATE_FIELDS,
    FORTIGATE_SOURCE_TYPE,
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


def build_detection_event(
    *,
    record_number: int = 1,
    overrides: dict[str, str | None] | None = None,
):
    """Build one valid, in-memory FortiGate normalized event for detection tests."""

    fields = {field: "" for field in BASELINE_FORTIGATE_FIELDS}
    fields.update(
        {
            "itime": "1700000000",
            "src_ip": "SRCIP_OPAQUE",
            "dst_ip": "DSTIP_OPAQUE",
            "host_ip": "HOSTIP_OPAQUE",
            "src_port": "51515",
            "dst_port": "443",
            "net_proto": "6",
            "net_sessionid": "SESSION_REPEATED",
            "loguid": f"LOGUID_OPAQUE_{record_number}",
            "event_action": "accept",
            "event_subtype": "synthetic",
            "event_type": "traffic",
        }
    )
    if overrides:
        fields.update(overrides)
    return normalize_fortigate_record(
        SourceRecord(
            source_type=FORTIGATE_SOURCE_TYPE,
            record_number=record_number,
            fields=fields,
        )
    )


@dataclass(frozen=True)
class SyntheticRule:
    """A test-only record-level rule used to exercise the 1.4C engine."""

    metadata: RuleMetadata
    matches: bool = True

    def evaluate(self, event):  # type: ignore[no-untyped-def]
        del event
        if not self.matches:
            return None
        return RuleEvaluation(
            reason_code=self.metadata.reason_code,
            summary="A synthetic source observation is present.",
            evidence_paths=("event.subtype_source",),
            uncertainties=("Synthetic rules do not establish attack truth.",),
        )


def build_synthetic_rule(rule_id: str, *, matches: bool = True) -> SyntheticRule:
    return SyntheticRule(
        metadata=RuleMetadata(
            rule_id=rule_id,
            version="1.0",
            name="Synthetic source observation",
            description="A test-only source observation without an attack claim.",
            category="SOURCE_PRODUCT_OBSERVATION",
            severity="INFORMATIONAL",
            supported_source_types=("fortigate",),
            required_paths=("event.subtype_source",),
            evidence_paths=("event.subtype_source",),
            reason_code="SYNTHETIC_SOURCE_OBSERVATION",
            security_rationale="Exercises deterministic evidence handling in tests.",
            false_positive_scenarios=("Synthetic input can model benign activity.",),
            limitations=("This test-only rule does not establish an attack.",),
        ),
        matches=matches,
    )


def write_normalized_jsonl(path: Path, events: tuple) -> None:  # type: ignore[type-arg]
    path.write_text(
        "".join(
            json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
            for event in events
        ),
        encoding="utf-8",
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
    def test_builtin_registry_is_ordered_unique_and_active(self) -> None:
        rule_ids = tuple(rule.metadata.rule_id for rule in BUILT_IN_RULES)

        self.assertEqual(rule_ids, tuple(sorted(rule_ids)))
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(ACTIVE_RULES, BUILT_IN_RULES)
        self.assertTrue(
            all(not isinstance(rule, InactiveRulePlaceholder) for rule in BUILT_IN_RULES)
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
                "Yes",
            )
            for rule in BUILT_IN_RULES
        }

        self.assertEqual(rows, expected_rows)
        self.assertEqual(document.count("| Review item | Approved answer |"), 2)
        self.assertIn("Rule Match != Confirmed Attack", document)


class InitialSourceObservationRuleTests(unittest.TestCase):
    def rule(self, rule_id: str):  # type: ignore[no-untyped-def]
        return next(rule for rule in ACTIVE_RULES if rule.metadata.rule_id == rule_id)

    def test_source_threat_observation_matches_only_populated_threat_leaves(self) -> None:
        rule = self.rule("fortigate.source_threat_observation")

        self.assertIsNone(rule.evaluate(build_detection_event()))
        partial_event = build_detection_event(
            overrides={
                "threat_action": "blocked",
                "threat_id": "THREAT_IDENTIFIER_OPAQUE",
                "threat_name": "source-observation",
            }
        )
        evaluation = rule.evaluate(partial_event)

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual(
            evaluation.evidence_paths,
            (
                "threat_observations.action_source",
                "threat_observations.id_raw",
                "threat_observations.name_source",
            ),
        )
        self.assertEqual(
            evaluation.reason_code, "SOURCE_THREAT_OBSERVATION_PRESENT"
        )

    def test_anomaly_subtype_condition_is_exact_case_sensitive_and_handles_missing_context(self) -> None:
        rule = self.rule("fortigate.anomaly_subtype_observation")

        self.assertIsNone(rule.evaluate(build_detection_event()))
        self.assertIsNone(
            rule.evaluate(build_detection_event(overrides={"event_subtype": "Anomaly"}))
        )
        self.assertIsNone(
            rule.evaluate(build_detection_event(overrides={"event_subtype": "unknown"}))
        )

        anomaly_event = build_detection_event(
            overrides={"event_subtype": "anomaly", "event_action": "", "event_type": ""}
        )
        evaluation = rule.evaluate(anomaly_event)

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual(evaluation.evidence_paths, ("event.subtype_source",))
        self.assertEqual(
            evaluation.reason_code, "SOURCE_ANOMALY_SUBTYPE_OBSERVED"
        )

    def test_both_rules_emit_independent_informational_findings_in_order(self) -> None:
        event = build_detection_event(
            overrides={"event_subtype": "anomaly", "threat_name": "source-observation"}
        )

        findings = evaluate_event(event, ACTIVE_RULES)

        self.assertEqual(
            tuple(finding.rule.rule_id for finding in findings),
            (
                "fortigate.anomaly_subtype_observation",
                "fortigate.source_threat_observation",
            ),
        )
        self.assertTrue(all(finding.rule.severity == "INFORMATIONAL" for finding in findings))
        self.assertEqual(
            tuple(finding.reason_code for finding in findings),
            (
                "SOURCE_ANOMALY_SUBTYPE_OBSERVED",
                "SOURCE_THREAT_OBSERVATION_PRESENT",
            ),
        )
        self.assertEqual(findings, evaluate_event(event, ACTIVE_RULES))
        expected_false_positive_notes = {
            rule.metadata.rule_id: rule.metadata.false_positive_scenarios[0]
            for rule in ACTIVE_RULES
        }
        self.assertEqual(
            {
                finding.rule.rule_id: finding.false_positive_note
                for finding in findings
            },
            expected_false_positive_notes,
        )

    def test_rules_skip_unsupported_source_types(self) -> None:
        event = build_detection_event(
            overrides={"event_subtype": "anomaly", "threat_name": "source-observation"}
        )
        unsupported_source_event = replace(
            event,
            source={**event.source, "adapter_type": "unsupported_source"},
            source_record=SourceRecord(
                source_type="unsupported_source",
                record_number=event.source_record.record_number,
                fields=event.source_record.fields,
            ),
        )

        self.assertTrue(all(rule.evaluate(unsupported_source_event) is None for rule in ACTIVE_RULES))
        self.assertEqual(evaluate_event(unsupported_source_event, ACTIVE_RULES), ())


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


class DetectionInputAndEngineTests(unittest.TestCase):
    def test_input_reader_streams_valid_events_in_source_record_order(self) -> None:
        first = build_detection_event(record_number=1)
        second = build_detection_event(record_number=2)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "normalized.jsonl"
            write_normalized_jsonl(path, (first, second))

            records = iter_normalized_events(path)
            self.assertEqual(next(records).source_record.record_number, 1)
            self.assertEqual(next(records).source_record.record_number, 2)
            with self.assertRaises(StopIteration):
                next(records)

    def test_input_reader_rejects_invalid_json_root_blank_and_schema(self) -> None:
        event_payload = build_detection_event().to_dict()
        invalid_cases = (
            ("invalid-json", "{not JSON}\n", "INVALID_JSONL"),
            ("root-array", "[]\n", "INVALID_EVENT_OBJECT"),
            ("blank", "\n", "BLANK_JSONL_LINE"),
            (
                "unsupported-schema",
                json.dumps({**event_payload, "schema_version": "2.0"}) + "\n",
                "UNSUPPORTED_SCHEMA_VERSION",
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            for case_name, contents, expected_code in invalid_cases:
                with self.subTest(case_name):
                    path = Path(temporary_directory) / f"{case_name}.jsonl"
                    path.write_text(contents, encoding="utf-8")
                    with self.assertRaises(DetectionInputError) as caught:
                        tuple(iter_normalized_events(path))
                    self.assertEqual(caught.exception.code, expected_code)
                    self.assertEqual(caught.exception.line_number, 1)

    def test_input_reader_rejects_invalid_provenance_order_and_utf8(self) -> None:
        first = build_detection_event(record_number=1)
        second = build_detection_event(record_number=2)
        invalid_provenance = first.to_dict()
        invalid_provenance["provenance"] = []

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)

            provenance_path = temporary_path / "invalid-provenance.jsonl"
            provenance_path.write_text(
                json.dumps(invalid_provenance) + "\n", encoding="utf-8"
            )
            with self.assertRaises(DetectionInputError) as caught:
                tuple(iter_normalized_events(provenance_path))
            self.assertEqual(caught.exception.code, "NORMALIZED_EVENT_VALIDATION_FAILED")
            self.assertEqual(caught.exception.source_record_number, 1)

            order_path = temporary_path / "invalid-order.jsonl"
            write_normalized_jsonl(order_path, (second, first))
            with self.assertRaises(DetectionInputError) as caught:
                tuple(iter_normalized_events(order_path))
            self.assertEqual(caught.exception.code, "RECORD_ORDER_INVALID")
            self.assertEqual(caught.exception.line_number, 2)
            self.assertEqual(caught.exception.source_record_number, 1)

            utf8_path = temporary_path / "invalid-utf8.jsonl"
            utf8_path.write_bytes(b"\xff\n")
            with self.assertRaises(DetectionInputError) as caught:
                tuple(iter_normalized_events(utf8_path))
            self.assertEqual(caught.exception.code, "INVALID_INPUT_UTF8")

    def test_engine_builds_deterministic_provenance_preserving_finding(self) -> None:
        event = build_detection_event()
        rule = build_synthetic_rule("fortigate.synthetic_observation")

        findings = evaluate_event(event, (rule,))

        self.assertEqual(findings, evaluate_event(event, (rule,)))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule.rule_id, rule.metadata.rule_id)
        self.assertEqual(finding.reason_code, rule.metadata.reason_code)
        self.assertEqual(finding.source_event.source_record_number, 1)
        self.assertEqual(finding.source_event.source_record_id, "LOGUID_OPAQUE_1")
        self.assertEqual(finding.time_basis, "NOT_USED")
        self.assertEqual(len(finding.evidence), 1)
        self.assertEqual(finding.evidence[0].canonical_path, "event.subtype_source")
        self.assertEqual(finding.evidence[0].observed_value, "synthetic")
        self.assertEqual(finding.evidence[0].source_fields, ("event_subtype",))
        self.assertEqual(finding.evidence[0].mapping_operation, "COPIED")
        self.assertEqual(finding.evidence[0].interpretation_status, "VERIFIED")

    def test_engine_uses_stable_rule_order_and_rejects_unsorted_rules(self) -> None:
        event = build_detection_event()
        alpha_rule = build_synthetic_rule("fortigate.alpha_observation")
        beta_rule = build_synthetic_rule("fortigate.beta_observation")

        findings = evaluate_event(event, (alpha_rule, beta_rule))

        self.assertEqual(
            tuple(finding.rule.rule_id for finding in findings),
            ("fortigate.alpha_observation", "fortigate.beta_observation"),
        )
        with self.assertRaises(DetectionEngineError) as caught:
            evaluate_event(event, (beta_rule, alpha_rule))
        self.assertEqual(caught.exception.code, "INVALID_RULE_REGISTRY")

    def test_engine_keeps_repeated_sessions_independent_and_skips_unsupported_sources(self) -> None:
        rule = build_synthetic_rule("fortigate.synthetic_observation")
        first = build_detection_event(record_number=1)
        second = build_detection_event(record_number=2)

        first_finding = evaluate_event(first, (rule,))[0]
        second_finding = evaluate_event(second, (rule,))[0]
        self.assertEqual(first.session["identifier"], second.session["identifier"])
        self.assertNotEqual(first_finding.finding_id, second_finding.finding_id)
        self.assertEqual(first_finding.source_event.source_record_number, 1)
        self.assertEqual(second_finding.source_event.source_record_number, 2)

        unsupported_source_event = replace(
            first,
            source={**first.source, "adapter_type": "unsupported_source"},
            source_record=SourceRecord(
                source_type="unsupported_source",
                record_number=first.source_record.record_number,
                fields=first.source_record.fields,
            ),
        )
        self.assertEqual(evaluate_event(unsupported_source_event, (rule,)), ())
        self.assertEqual(evaluate_event(first, (build_synthetic_rule("fortigate.no_match", matches=False),)), ())
        self.assertEqual(evaluate_event(first, ()), ())

    def test_engine_rejects_mismatched_reason_codes_and_missing_evidence_provenance(self) -> None:
        event = build_detection_event()
        rule = build_synthetic_rule("fortigate.synthetic_observation")

        @dataclass(frozen=True)
        class WrongReasonRule:
            metadata: RuleMetadata

            def evaluate(self, input_event):  # type: ignore[no-untyped-def]
                del input_event
                return RuleEvaluation(
                    reason_code="WRONG_REASON_CODE",
                    summary="A synthetic source observation is present.",
                    evidence_paths=("event.subtype_source",),
                    uncertainties=("Synthetic rule only.",),
                )

        with self.assertRaises(DetectionEngineError) as caught:
            evaluate_event(event, (WrongReasonRule(rule.metadata),))
        self.assertEqual(caught.exception.code, "REASON_CODE_MISMATCH")

        missing_provenance_event = replace(
            event,
            provenance=tuple(
                item
                for item in event.provenance
                if item.canonical_path != "event.subtype_source"
            ),
        )
        with self.assertRaises(DetectionEngineError) as caught:
            evaluate_event(missing_provenance_event, (rule,))
        self.assertEqual(caught.exception.code, "EVIDENCE_PROVENANCE_MISSING")


class StreamingDetectionOutputTests(unittest.TestCase):
    """Synthetic end-to-end tests for the Stage 1.4E output boundary."""

    def setUp(self) -> None:
        self._input_directory = tempfile.TemporaryDirectory()
        self._output_directory = tempfile.TemporaryDirectory(
            dir=DETECTION_PROCESSED_DATA_DIRECTORY
        )
        self.input_directory = Path(self._input_directory.name)
        self.output_directory = Path(self._output_directory.name)

    def tearDown(self) -> None:
        self._input_directory.cleanup()
        self._output_directory.cleanup()

    def write_input(self, filename: str, events: tuple) -> Path:  # type: ignore[type-arg]
        path = self.input_directory / filename
        write_normalized_jsonl(path, events)
        return path

    @staticmethod
    def json_lines(path: Path) -> list[dict[str, object]]:
        return [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]

    def test_streaming_evaluation_preserves_order_counts_and_audits_output(self) -> None:
        input_path = self.write_input(
            "events.jsonl",
            (
                build_detection_event(
                    record_number=1,
                    overrides={
                        "event_subtype": "anomaly",
                        "threat_name": "source-observation",
                    },
                ),
                build_detection_event(
                    record_number=2, overrides={"threat_name": "source-observation"}
                ),
                build_detection_event(record_number=3),
            ),
        )
        output_path = self.output_directory / "findings.jsonl"

        summary = evaluate_detection_jsonl(input_path, output_path, ACTIVE_RULES)
        output_records = self.json_lines(output_path)
        audit = audit_detection_jsonl(output_path, summary)

        self.assertEqual(summary.normalized_input_record_count, 3)
        self.assertEqual(summary.evaluated_record_count, 3)
        self.assertEqual(summary.invalid_input_count, 0)
        self.assertEqual(summary.total_finding_count, 3)
        self.assertEqual(summary.unique_matched_source_record_count, 2)
        self.assertEqual(
            [
                (record["source_event"]["source_record_number"], record["rule"]["rule_id"])
                for record in output_records
            ],
            [
                (1, "fortigate.anomaly_subtype_observation"),
                (1, "fortigate.source_threat_observation"),
                (2, "fortigate.source_threat_observation"),
            ],
        )
        self.assertEqual(audit.finding_count, summary.total_finding_count)
        self.assertEqual(
            dict(audit.findings_by_rule_id), dict(summary.findings_by_rule_id)
        )
        self.assertEqual(
            audit.unique_matched_source_record_count,
            summary.unique_matched_source_record_count,
        )
        self.assertEqual(audit_detection_jsonl(output_path).finding_count, 3)

    def test_streaming_output_is_byte_for_byte_deterministic(self) -> None:
        input_path = self.write_input(
            "deterministic-events.jsonl",
            (
                build_detection_event(
                    record_number=1,
                    overrides={
                        "event_subtype": "anomaly",
                        "threat_name": "source-observation",
                    },
                ),
                build_detection_event(
                    record_number=2, overrides={"threat_name": "source-observation"}
                ),
            ),
        )
        first_output = self.output_directory / "first.jsonl"
        second_output = self.output_directory / "second.jsonl"

        evaluate_detection_jsonl(input_path, first_output, ACTIVE_RULES)
        evaluate_detection_jsonl(input_path, second_output, ACTIVE_RULES)

        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())

    def test_empty_input_produces_empty_auditable_output(self) -> None:
        input_path = self.input_directory / "empty.jsonl"
        input_path.write_text("", encoding="utf-8")
        output_path = self.output_directory / "empty-findings.jsonl"

        summary = evaluate_detection_jsonl(input_path, output_path, ACTIVE_RULES)
        audit = audit_detection_jsonl(output_path, summary)

        self.assertEqual(output_path.read_bytes(), b"")
        self.assertEqual(summary.total_finding_count, 0)
        self.assertEqual(summary.findings_by_rule_id, {})
        self.assertEqual(audit.finding_count, 0)

    def test_output_path_checks_and_input_failure_leave_no_partial_final_output(self) -> None:
        input_path = self.write_input(
            "valid.jsonl", (build_detection_event(record_number=1),)
        )

        with self.assertRaises(DetectionRunError) as outside_error:
            evaluate_detection_jsonl(
                input_path, self.input_directory / "outside.jsonl", ACTIVE_RULES
            )
        self.assertEqual(outside_error.exception.code, "OUTPUT_OUTSIDE_PROCESSED")

        missing_parent_output = self.output_directory / "missing-parent" / "output.jsonl"
        with self.assertRaises(DetectionRunError) as missing_parent_error:
            evaluate_detection_jsonl(input_path, missing_parent_output, ACTIVE_RULES)
        self.assertEqual(missing_parent_error.exception.code, "OUTPUT_PARENT_UNAVAILABLE")

        same_path = self.output_directory / "same.jsonl"
        write_normalized_jsonl(same_path, (build_detection_event(record_number=1),))
        with self.assertRaises(DetectionRunError) as same_path_error:
            evaluate_detection_jsonl(same_path, same_path, ACTIVE_RULES)
        self.assertEqual(same_path_error.exception.code, "INPUT_OUTPUT_SAME")

        existing_output = self.output_directory / "existing.jsonl"
        existing_output.write_text("existing content", encoding="utf-8")
        with self.assertRaises(DetectionRunError) as existing_error:
            evaluate_detection_jsonl(input_path, existing_output, ACTIVE_RULES)
        self.assertEqual(existing_error.exception.code, "OUTPUT_EXISTS")
        self.assertEqual(existing_output.read_text(encoding="utf-8"), "existing content")

        invalid_input = self.input_directory / "invalid.jsonl"
        invalid_input.write_text(
            json.dumps(build_detection_event(record_number=1).to_dict()) + "\n{not JSON}\n",
            encoding="utf-8",
        )
        failed_output = self.output_directory / "failed.jsonl"
        with self.assertRaises(DetectionInputError):
            evaluate_detection_jsonl(invalid_input, failed_output, ACTIVE_RULES)
        self.assertFalse(failed_output.exists())
        self.assertEqual(
            list(self.output_directory.glob(f".{failed_output.stem}.*.tmp")), []
        )

    def test_audit_rejects_tampered_contract_evidence_provenance_metadata_order_and_count(self) -> None:
        events = (
            build_detection_event(
                record_number=1,
                overrides={
                    "event_subtype": "anomaly",
                    "threat_name": "source-observation",
                },
            ),
            build_detection_event(
                record_number=2, overrides={"threat_name": "source-observation"}
            ),
        )
        input_path = self.write_input("tamper-events.jsonl", events)

        for case_name in (
            "finding-id",
            "evidence-value",
            "evidence-provenance",
            "rule-metadata",
            "order",
            "count",
            "prohibited-field",
        ):
            with self.subTest(case_name):
                output_path = self.output_directory / f"tampered-{case_name}.jsonl"
                summary = evaluate_detection_jsonl(input_path, output_path, ACTIVE_RULES)
                output_records = self.json_lines(output_path)
                if case_name == "finding-id":
                    output_records[0]["finding_id"] = "0" * 64
                elif case_name == "evidence-value":
                    output_records[0]["evidence"][0]["observed_value"] = "tampered"
                elif case_name == "evidence-provenance":
                    output_records[0]["evidence"][0]["source_fields"] = ["wrong_field"]
                elif case_name == "rule-metadata":
                    output_records[0]["rule"]["name"] = "tampered"
                elif case_name == "order":
                    output_records[0], output_records[1] = output_records[1], output_records[0]
                elif case_name == "count":
                    output_records.pop()
                else:
                    output_records[0]["risk_score"] = 1
                output_path.write_text(
                    "".join(
                        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                        for record in output_records
                    ),
                    encoding="utf-8",
                )

                with self.assertRaises(DetectionOutputAuditError):
                    audit_detection_jsonl(output_path, summary)

    def test_run_summary_is_bounded_and_cli_errors_remain_concise(self) -> None:
        input_path = self.write_input(
            "many-findings.jsonl",
            tuple(
                build_detection_event(
                    record_number=record_number,
                    overrides={"threat_name": "source-observation"},
                )
                for record_number in range(1, 8)
            ),
        )
        output_path = self.output_directory / "many-findings.jsonl"

        summary = evaluate_detection_jsonl(input_path, output_path, ACTIVE_RULES)
        samples = summary.sample_findings_by_rule[
            "fortigate.source_threat_observation"
        ]
        self.assertEqual(summary.total_finding_count, 7)
        self.assertEqual(len(samples), 5)
        self.assertEqual(
            [sample.source_record_number for sample in samples], [1, 2, 3, 4, 5]
        )

        stderr = io.StringIO()
        missing_output = self.output_directory / "cli-failure.jsonl"
        with redirect_stderr(stderr):
            exit_code = evaluate_detections_main(
                [
                    "--input",
                    str(self.input_directory / "missing.jsonl"),
                    "--output",
                    str(missing_output),
                ]
            )
        self.assertEqual(exit_code, 1)
        self.assertFalse(missing_output.exists())
        self.assertEqual(stderr.getvalue(), "detection failed: Normalized JSON Lines input does not exist.\n")

        cli_output = self.output_directory / "cli-success.jsonl"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = evaluate_detections_main(
                ["--input", str(input_path), "--output", str(cli_output)]
            )
        self.assertEqual(exit_code, 0)
        printed_summary = json.loads(stdout.getvalue())
        self.assertEqual(printed_summary["total_finding_count"], 7)
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
