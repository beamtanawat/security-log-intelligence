"""Synthetic contract tests for the Stage 1.3 normalization foundation."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from normalization.models import (  # noqa: E402
    REQUIRED_EVENT_SECTIONS,
    FieldProvenance,
    NormalizationContractError,
    NormalizationIssue,
    NormalizationRunSummary,
    NormalizedSecurityEvent,
    SourceRecord,
)


def build_event() -> NormalizedSecurityEvent:
    """Build a generic synthetic event with optional canonical null values."""

    source_fields = {
        "example_identifier": "OPAQUE_TOKEN",
        "example_optional_value": "",
        "example_numeric_text": "42",
    }
    return NormalizedSecurityEvent(
        source={"source_type": "example_source", "record_number": 1},
        event={"source_record_id": "example-record"},
        time={"raw_value": None, "derived_value": None},
        network={"source_identifier": "OPAQUE_TOKEN", "source_port": None},
        application={},
        session={},
        host={},
        threat_observations={},
        source_record=SourceRecord(
            source_type="example_source",
            record_number=1,
            fields=source_fields,
        ),
        unmapped_fields={"example_optional_value": ""},
        provenance=(
            FieldProvenance(
                canonical_path="network.source_identifier",
                source_fields=("example_identifier",),
                operation="COPIED",
                interpretation_status="VERIFIED",
                note="Opaque source-defined identifier.",
            ),
        ),
        normalization_issues=(),
    )


class NormalizationContractTests(unittest.TestCase):
    def test_event_serialization_is_complete_deterministic_and_json_compatible(self) -> None:
        event = build_event()

        first = event.to_dict()
        second = event.to_dict()
        self.assertEqual(first, second)
        self.assertEqual(tuple(first), REQUIRED_EVENT_SECTIONS)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(first["time"]["raw_value"], None)
        self.assertEqual(first["network"]["source_port"], None)
        self.assertEqual(first["source_record"]["example_optional_value"], "")

    def test_source_record_copies_input_mapping_without_changing_raw_values(self) -> None:
        original_fields = {"z_field": "  value  ", "a_field": ""}
        record = SourceRecord(
            source_type="example_source",
            record_number=3,
            fields=original_fields,
        )
        original_fields["a_field"] = "changed after construction"

        self.assertEqual(record.to_dict(), {"a_field": "", "z_field": "  value  "})

    def test_unmapped_fields_must_match_the_preserved_source_record(self) -> None:
        event = build_event()
        self.assertEqual(event.to_dict()["unmapped_fields"], {"example_optional_value": ""})

        with self.assertRaisesRegex(NormalizationContractError, "must exist"):
            NormalizedSecurityEvent(
                source=event.source,
                event=event.event,
                time=event.time,
                network=event.network,
                application=event.application,
                session=event.session,
                host=event.host,
                threat_observations=event.threat_observations,
                source_record=event.source_record,
                unmapped_fields={"not_in_source_record": ""},
                provenance=event.provenance,
                normalization_issues=event.normalization_issues,
            )

    def test_status_vocabularies_reject_unknown_or_prohibited_names(self) -> None:
        with self.assertRaisesRegex(NormalizationContractError, "operation must be one"):
            FieldProvenance(
                canonical_path="network.example",
                source_fields=("example_field",),
                operation="ATTACK",
                interpretation_status="VERIFIED",
            )
        with self.assertRaisesRegex(NormalizationContractError, "status must be one"):
            NormalizationIssue(
                source_field="example_field",
                issue_code="EXAMPLE",
                status="RISK",
                description="Synthetic unsupported status.",
            )
        with self.assertRaisesRegex(
            NormalizationContractError, "interpretation_status must be one"
        ):
            FieldProvenance(
                canonical_path="network.example",
                source_fields=("example_field",),
                operation="COPIED",
                interpretation_status="UNSUPPORTED",
            )

    def test_run_summary_uses_null_for_optional_output_and_sorted_aggregates(self) -> None:
        summary = NormalizationRunSummary(
            source_type="example_source",
            input_path="input.csv",
            output_path=None,
            input_record_count=2,
            valid_record_count=2,
            malformed_record_count=0,
            output_record_count=2,
            mapping_coverage={"unmapped": 1, "mapped": 2},
            issue_counts={"Z_CODE": 1, "A_CODE": 2},
            unknown_field_names=("z_field", "a_field"),
        )

        result = summary.to_dict()
        self.assertEqual(result["output_path"], None)
        self.assertEqual(result["mapping_coverage"], {"mapped": 2, "unmapped": 1})
        self.assertEqual(result["issue_counts"], {"A_CODE": 2, "Z_CODE": 1})
        self.assertEqual(result["unknown_field_names"], ["z_field", "a_field"])

    def test_generic_contract_has_no_source_mapping_or_security_decision_fields(self) -> None:
        rendered = json.dumps(build_event().to_dict()).lower()
        for prohibited_field in (
            "is_attack",
            "is_malicious",
            "risk_score",
            "detection",
            "mitre",
        ):
            self.assertNotIn(prohibited_field, rendered)


if __name__ == "__main__":
    unittest.main()
