"""Synthetic Stage 1.7 feature-contract tests.

These tests intentionally use normalized synthetic events rather than the local
real dataset.  They specify the leakage-safe, deterministic feature foundation
required before any Stage 1.8 model work.
"""

from __future__ import annotations

import json
import hashlib
import importlib
import importlib.util
import math
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ai_features.artifact import (  # noqa: E402
    FeatureArtifactError,
    read_feature_rows,
)
from ai_features.models import (  # noqa: E402
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    FeatureContractError,
    FeatureRow,
)
from ai_features.transform import (  # noqa: E402
    FeatureObservation,
    FeatureTransformError,
    build_feature_values,
    build_reference_maps,
    extract_feature_observation,
    split_partition,
)
from audit_ai_features import AIFeatureAuditError, audit_ai_feature_bundle  # noqa: E402
from build_ai_features import (  # noqa: E402
    AIFeatureBuildError,
    build_ai_feature_bundle,
)
from normalization.fortigate import normalize_fortigate_record  # noqa: E402
from normalization.models import SourceRecord  # noqa: E402
from parsers.fortigate import BASELINE_FORTIGATE_FIELDS, FORTIGATE_SOURCE_TYPE  # noqa: E402


EXPECTED_FEATURE_NAMES = (
    "protocol_icmp",
    "protocol_tcp",
    "protocol_udp",
    "protocol_other",
    "src_port_present",
    "dst_port_present",
    "src_port_well_known",
    "src_port_registered",
    "src_port_dynamic",
    "dst_port_well_known",
    "dst_port_registered",
    "dst_port_dynamic",
    "src_port_rarity",
    "dst_port_rarity",
    "service_rarity",
    "service_missing",
    "log_sent_bytes",
    "log_received_bytes",
    "log_sent_packets",
    "log_received_packets",
    "log_duration",
    "log_total_bytes",
    "log_total_packets",
    "sent_byte_share",
    "sent_packet_share",
    "log_sent_bytes_per_packet",
    "log_received_bytes_per_packet",
    "sent_bytes_missing",
    "received_bytes_missing",
    "sent_packets_missing",
    "received_packets_missing",
    "duration_missing",
    "zero_total_bytes",
    "zero_total_packets",
    "zero_sent_packets",
    "zero_received_packets",
)

EXPECTED_FEATURE_DEFINITION_CORE = (
    ("protocol_icmp", ("network.protocol_number",), "protocol_equals_1_indicator", "protocol", "always_after_protocol_validation", False),
    ("protocol_tcp", ("network.protocol_number",), "protocol_equals_6_indicator", "protocol", "always_after_protocol_validation", False),
    ("protocol_udp", ("network.protocol_number",), "protocol_equals_17_indicator", "protocol", "always_after_protocol_validation", False),
    ("protocol_other", ("network.protocol_number",), "protocol_other_valid_indicator", "protocol", "always_after_protocol_validation", False),
    ("src_port_present", ("network.source.port",), "present_indicator", "source_port", "always", False),
    ("dst_port_present", ("network.destination.port",), "present_indicator", "destination_port", "always", False),
    ("src_port_well_known", ("network.source.port",), "well_known_0_1023_indicator", "source_port", "always_contextual_missing_as_zero", False),
    ("src_port_registered", ("network.source.port",), "registered_1024_49151_indicator", "source_port", "always_contextual_missing_as_zero", False),
    ("src_port_dynamic", ("network.source.port",), "dynamic_49152_65535_indicator", "source_port", "always_contextual_missing_as_zero", False),
    ("dst_port_well_known", ("network.destination.port",), "well_known_0_1023_indicator", "destination_port", "always_contextual_missing_as_zero", False),
    ("dst_port_registered", ("network.destination.port",), "registered_1024_49151_indicator", "destination_port", "always_contextual_missing_as_zero", False),
    ("dst_port_dynamic", ("network.destination.port",), "dynamic_49152_65535_indicator", "destination_port", "always_contextual_missing_as_zero", False),
    ("src_port_rarity", ("network.protocol_number", "network.source.port"), "reference_rarity_1_minus_count_over_present_protocol_denominator", "source_port", "source_port_present", False),
    ("dst_port_rarity", ("network.protocol_number", "network.destination.port"), "reference_rarity_1_minus_count_over_present_protocol_denominator", "destination_port", "destination_port_present", False),
    ("service_rarity", ("network.protocol_number", "application.service_source"), "reference_rarity_1_minus_count_over_present_protocol_denominator", "service", "service_present", False),
    ("service_missing", ("application.service_source",), "missing_indicator", "service", "always", True),
    ("log_sent_bytes", ("session.sent_bytes",), "natural_log1p_nonnegative_or_zero_if_missing", "session_metric", "sent_bytes_present", False),
    ("log_received_bytes", ("session.received_bytes",), "natural_log1p_nonnegative_or_zero_if_missing", "session_metric", "received_bytes_present", False),
    ("log_sent_packets", ("session.sent_packets",), "natural_log1p_nonnegative_or_zero_if_missing", "session_metric", "sent_packets_present", False),
    ("log_received_packets", ("session.received_packets",), "natural_log1p_nonnegative_or_zero_if_missing", "session_metric", "received_packets_present", False),
    ("log_duration", ("session.duration_raw_value",), "unit_neutral_natural_log1p_or_zero_if_missing", "session_duration", "duration_present", False),
    ("log_total_bytes", ("session.sent_bytes", "session.received_bytes"), "natural_log1p_sum_when_both_present_else_zero", "derived_byte_metric", "both_byte_metrics_present", False),
    ("log_total_packets", ("session.sent_packets", "session.received_packets"), "natural_log1p_sum_when_both_present_else_zero", "derived_packet_metric", "both_packet_metrics_present", False),
    ("sent_byte_share", ("session.sent_bytes", "session.received_bytes"), "sent_over_total_when_both_present_and_total_positive_else_0_5", "derived_byte_metric", "both_byte_metrics_present_and_total_positive", False),
    ("sent_packet_share", ("session.sent_packets", "session.received_packets"), "sent_over_total_when_both_present_and_total_positive_else_0_5", "derived_packet_metric", "both_packet_metrics_present_and_total_positive", False),
    ("log_sent_bytes_per_packet", ("session.sent_bytes", "session.sent_packets"), "natural_log1p_ratio_when_both_present_and_packets_positive_else_zero", "derived_byte_packet_metric", "sent_bytes_and_packets_present_and_packets_positive", False),
    ("log_received_bytes_per_packet", ("session.received_bytes", "session.received_packets"), "natural_log1p_ratio_when_both_present_and_packets_positive_else_zero", "derived_byte_packet_metric", "received_bytes_and_packets_present_and_packets_positive", False),
    ("sent_bytes_missing", ("session.sent_bytes",), "missing_indicator", "session_metric_missingness", "always", True),
    ("received_bytes_missing", ("session.received_bytes",), "missing_indicator", "session_metric_missingness", "always", True),
    ("sent_packets_missing", ("session.sent_packets",), "missing_indicator", "session_metric_missingness", "always", True),
    ("received_packets_missing", ("session.received_packets",), "missing_indicator", "session_metric_missingness", "always", True),
    ("duration_missing", ("session.duration_raw_value",), "missing_indicator", "session_metric_missingness", "always", True),
    ("zero_total_bytes", ("session.sent_bytes", "session.received_bytes"), "observed_zero_sum_indicator_when_both_present", "derived_byte_metric", "both_byte_metrics_present", False),
    ("zero_total_packets", ("session.sent_packets", "session.received_packets"), "observed_zero_sum_indicator_when_both_present", "derived_packet_metric", "both_packet_metrics_present", False),
    ("zero_sent_packets", ("session.sent_packets",), "observed_zero_indicator", "session_metric", "sent_packets_present", False),
    ("zero_received_packets", ("session.received_packets",), "observed_zero_indicator", "session_metric", "received_packets_present", False),
)

EXPECTED_FEATURE_EXCLUSIONS = (
    "No raw identifiers, timestamps, labels, findings, threats, source-product "
    "decision fields, or constant data_sourcetype."
)


def build_event(
    record_number: int,
    *,
    session_id: str | None = "SESSION_OPAQUE",
    overrides: dict[str, str | None] | None = None,
):
    """Create one valid normalized FortiGate event for a synthetic test."""

    fields = {field: "" for field in BASELINE_FORTIGATE_FIELDS}
    fields.update(
        {
            "itime": "1700000000",
            "loguid": f"LOGUID_OPAQUE_{record_number}",
            "src_ip": f"SRCIP_OPAQUE_{record_number}",
            "dst_ip": f"DSTIP_OPAQUE_{record_number}",
            "host_ip": "HOSTIP_OPAQUE",
            "net_proto": "6",
            "src_port": "51515",
            "dst_port": "443",
            "net_sentbytes": "100",
            "net_recvbytes": "300",
            "net_sentpkts": "2",
            "net_rcvdpkts": "6",
            "net_sessionduration": "40",
            "net_sessionid": session_id or "",
            "app_service": "HTTPS",
            "event_action": "accept",
            "event_subtype": "traffic",
            "event_type": "traffic",
            "event_severity": "information",
            "threat_type": "Reconnaissance",
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


def write_normalized_jsonl(path: Path, events: tuple[object, ...]) -> None:
    path.write_text(
        "".join(
            json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
            for event in events
        ),
        encoding="utf-8",
        newline="\n",
    )


def session_for_partition(partition: str) -> str:
    for index in range(1, 10_000):
        identifier = f"SESSION_SPLIT_{index}"
        if split_partition(identifier, index) == partition:
            return identifier
    raise AssertionError(f"could not find a synthetic {partition} session")


class FeatureContractTests(unittest.TestCase):
    def test_feature_manifest_is_exact_and_ordered(self) -> None:
        self.assertEqual(FEATURE_SCHEMA_VERSION, "1.0")
        self.assertEqual(FEATURE_NAMES, EXPECTED_FEATURE_NAMES)
        self.assertEqual(len(FEATURE_NAMES), 36)

    def test_feature_definition_contract_is_exact_and_ordered(self) -> None:
        specification = importlib.util.find_spec("ai_features.contract")
        self.assertIsNotNone(
            specification,
            "Stage 1.7 must define its metadata contract outside builder orchestration",
        )
        contract = importlib.import_module("ai_features.contract")
        definitions = contract.FEATURE_DEFINITIONS

        self.assertEqual(len(definitions), 36)
        self.assertEqual(
            {key for definition in definitions for key in definition},
            {
                "position",
                "name",
                "source_paths",
                "transform",
                "family",
                "eligible_when",
                "missingness_flag",
                "exclusions",
            },
        )
        actual_core = tuple(
            (
                definition["name"],
                tuple(definition["source_paths"]),
                definition["transform"],
                definition["family"],
                definition["eligible_when"],
                definition["missingness_flag"],
            )
            for definition in definitions
        )
        self.assertEqual(actual_core, EXPECTED_FEATURE_DEFINITION_CORE)
        self.assertEqual(
            tuple(definition["position"] for definition in definitions),
            tuple(range(1, 37)),
        )
        self.assertTrue(
            all(
                definition["exclusions"] == EXPECTED_FEATURE_EXCLUSIONS
                for definition in definitions
            )
        )

    def test_split_is_deterministic_and_keeps_one_session_together(self) -> None:
        first = split_partition("SESSION_REPEATED", 1)
        second = split_partition("SESSION_REPEATED", 999)
        self.assertEqual(first, second)
        self.assertIn(first, {"REFERENCE", "HOLDOUT"})
        self.assertIn(split_partition(None, 7), {"REFERENCE", "HOLDOUT"})
        self.assertNotEqual(
            split_partition("", 7),
            split_partition(" ", 7),
            "opaque split tokens must not be stripped or case-normalized",
        )

    def test_split_matches_the_locked_canonical_hash_vector(self) -> None:
        identifier = "SESSION_opaque-01"
        canonical = json.dumps(
            ["stage-1.7-split-v1", "session", identifier],
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        bucket = int.from_bytes(hashlib.sha256(canonical).digest()[:8], "big") % 10
        expected = "REFERENCE" if bucket <= 7 else "HOLDOUT"
        self.assertEqual(split_partition(identifier, 999), expected)

    def test_feature_row_requires_exact_finite_36_float_values(self) -> None:
        row = FeatureRow(
            source_record_number=1,
            source_record_id="LOGUID_OPAQUE",
            partition="REFERENCE",
            values=tuple(0.0 for _ in FEATURE_NAMES),
        )
        self.assertEqual(row.to_dict()["values"], [0.0] * 36)

        with self.assertRaises(FeatureContractError):
            FeatureRow(1, "LOGUID_OPAQUE", "REFERENCE", (0.0,) * 35)
        with self.assertRaises(FeatureContractError):
            FeatureRow(1, "LOGUID_OPAQUE", "REFERENCE", (float("nan"),) * 36)
        with self.assertRaises(FeatureContractError):
            FeatureRow(1, "LOGUID_OPAQUE", "REFERENCE", (0,) * 36)

    def test_protocol_and_port_boundaries_are_encoded_without_port_magnitudes(self) -> None:
        event = build_event(
            1,
            session_id=session_for_partition("REFERENCE"),
            overrides={"net_proto": "17", "src_port": "1023", "dst_port": "49152"},
        )
        observation = extract_feature_observation(event)
        maps = build_reference_maps((observation,))
        values, _ = build_feature_values(observation, maps)

        self.assertEqual(values[:4], (0.0, 0.0, 1.0, 0.0))
        self.assertEqual(values[4:13], (1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0))
        self.assertNotIn(1023.0, values)
        self.assertNotIn(49152.0, values)

    def test_unknown_valid_protocol_is_other_but_null_protocol_is_rejected(self) -> None:
        other = extract_feature_observation(build_event(1, overrides={"net_proto": "255"}))
        values, _ = build_feature_values(other, build_reference_maps((other,)))
        self.assertEqual(values[:4], (0.0, 0.0, 0.0, 1.0))

        missing = build_event(2, overrides={"net_proto": ""})
        with self.assertRaises(FeatureTransformError):
            extract_feature_observation(missing)

    def test_all_port_class_boundaries_are_exact(self) -> None:
        expected_classes = {
            0: (1.0, 0.0, 0.0),
            1023: (1.0, 0.0, 0.0),
            1024: (0.0, 1.0, 0.0),
            49151: (0.0, 1.0, 0.0),
            49152: (0.0, 0.0, 1.0),
            65535: (0.0, 0.0, 1.0),
        }
        for port, expected in expected_classes.items():
            with self.subTest(port=port):
                observation = FeatureObservation(
                    source_record_number=port + 1,
                    source_record_id=f"LOGUID_PORT_{port}",
                    session_identifier="SESSION_REFERENCE",
                    partition="REFERENCE",
                    protocol_number=6,
                    source_port=port,
                    destination_port=None,
                    service=None,
                    sent_bytes=0,
                    received_bytes=0,
                    sent_packets=0,
                    received_packets=0,
                    duration=0,
                )
                values, _ = build_feature_values(
                    observation, build_reference_maps((observation,))
                )
                self.assertEqual(values[6:9], expected)

    def test_icmp_port_absence_is_contextual_not_an_error_or_port_zero(self) -> None:
        event = build_event(
            1,
            session_id=session_for_partition("REFERENCE"),
            overrides={"net_proto": "1", "src_port": "", "dst_port": ""},
        )
        observation = extract_feature_observation(event)
        values, _ = build_feature_values(observation, build_reference_maps((observation,)))

        self.assertEqual(values[:4], (1.0, 0.0, 0.0, 0.0))
        self.assertEqual(values[4:15], (0.0,) * 11)

    def test_metric_missingness_zero_and_ratio_safety_are_distinguishable(self) -> None:
        event = build_event(
            1,
            overrides={
                "net_sentbytes": "",
                "net_recvbytes": "0",
                "net_sentpkts": "0",
                "net_rcvdpkts": "",
                "net_sessionduration": "",
            },
        )
        observation = extract_feature_observation(event)
        values, _ = build_feature_values(observation, build_reference_maps((observation,)))

        self.assertEqual(values[23], 0.5)
        self.assertEqual(values[24], 0.5)
        self.assertEqual(values[27:32], (1.0, 0.0, 0.0, 1.0, 1.0))
        self.assertEqual(values[32:36], (0.0, 0.0, 1.0, 0.0))

    def test_bytes_per_packet_features_use_natural_log1p_and_safe_fallbacks(self) -> None:
        positive = extract_feature_observation(
            build_event(
                1,
                overrides={
                    "net_sentbytes": "300",
                    "net_sentpkts": "3",
                    "net_recvbytes": "21",
                    "net_rcvdpkts": "2",
                },
            )
        )
        positive_values, _ = build_feature_values(
            positive, build_reference_maps((positive,))
        )
        self.assertAlmostEqual(positive_values[25], math.log1p(100.0))
        self.assertAlmostEqual(positive_values[26], math.log1p(10.5))
        self.assertTrue(all(math.isfinite(value) for value in positive_values))

        zero_bytes = extract_feature_observation(
            build_event(
                2,
                overrides={"net_sentbytes": "0", "net_sentpkts": "4"},
            )
        )
        zero_packet = extract_feature_observation(
            build_event(
                3,
                overrides={"net_recvbytes": "21", "net_rcvdpkts": "0"},
            )
        )
        missing_packet = extract_feature_observation(
            build_event(
                4,
                overrides={"net_sentbytes": "300", "net_sentpkts": ""},
            )
        )
        missing_bytes = extract_feature_observation(
            build_event(
                5,
                overrides={"net_recvbytes": "", "net_rcvdpkts": "2"},
            )
        )
        for observation, feature_index in (
            (zero_bytes, 25),
            (zero_packet, 26),
            (missing_packet, 25),
            (missing_bytes, 26),
        ):
            with self.subTest(record_number=observation.source_record_number):
                values, _ = build_feature_values(
                    observation, build_reference_maps((observation,))
                )
                self.assertEqual(values[feature_index], 0.0)
                self.assertTrue(all(math.isfinite(value) for value in values))

    def test_reference_rarity_excludes_holdout_values_and_unseen_is_one(self) -> None:
        reference_session = session_for_partition("REFERENCE")
        holdout_session = session_for_partition("HOLDOUT")
        reference = extract_feature_observation(
            build_event(1, session_id=reference_session, overrides={"dst_port": "443"})
        )
        holdout = extract_feature_observation(
            build_event(2, session_id=holdout_session, overrides={"dst_port": "65000"})
        )
        maps = build_reference_maps((reference, holdout))
        values, _ = build_feature_values(holdout, maps)

        self.assertNotIn((6, 65000), maps.destination_port_counts)
        self.assertEqual(values[13], 1.0)

        changed_holdout = extract_feature_observation(
            build_event(3, session_id=holdout_session, overrides={"dst_port": "65001"})
        )
        self.assertEqual(
            build_reference_maps((reference, holdout)),
            build_reference_maps((reference, changed_holdout)),
        )

    def test_opaque_endpoint_tokens_are_not_used_as_model_features(self) -> None:
        reference_session = session_for_partition("REFERENCE")
        first = extract_feature_observation(build_event(1, session_id=reference_session))
        second = extract_feature_observation(
            build_event(
                2,
                session_id=reference_session,
                overrides={"src_ip": "SRCIP_DIFFERENT", "dst_ip": "DSTIP_DIFFERENT"},
            )
        )
        maps = build_reference_maps((first, second))
        first_values, _ = build_feature_values(first, maps)
        second_values, _ = build_feature_values(second, maps)
        self.assertEqual(first_values, second_values)

    def test_actual_invalid_normalized_port_or_metric_is_rejected(self) -> None:
        invalid_port = build_event(1, overrides={"src_port": "not-a-port"})
        with self.assertRaises(FeatureTransformError):
            extract_feature_observation(invalid_port)

        invalid_metric = build_event(2, overrides={"net_sentbytes": "-1"})
        with self.assertRaises(FeatureTransformError):
            extract_feature_observation(invalid_metric)


class FeatureBundleIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_root = Path(
            tempfile.mkdtemp(
                prefix=".stage_1_7_test.",
                dir=PROJECT_ROOT / "data" / "processed",
            )
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary_root, ignore_errors=True)

    def _input_path(self, events: tuple[object, ...]) -> Path:
        input_path = self.temporary_root / "normalized.jsonl"
        write_normalized_jsonl(input_path, events)
        return input_path

    def _events_with_both_partitions(self) -> tuple[object, ...]:
        reference_session = session_for_partition("REFERENCE")
        holdout_session = session_for_partition("HOLDOUT")
        return tuple(
            build_event(
                record_number,
                session_id=(reference_session if record_number % 2 else holdout_session),
            )
            for record_number in range(1, 41)
        )

    def test_builder_and_auditor_publish_and_reconcile_a_complete_bundle(self) -> None:
        input_path = self._input_path(self._events_with_both_partitions())
        bundle = self.temporary_root / "bundle"

        summary = build_ai_feature_bundle(input_path, bundle)
        audit = audit_ai_feature_bundle(bundle, input_path)

        self.assertEqual(summary.row_count, 40)
        self.assertEqual(audit.row_count, 40)
        self.assertEqual(audit.feature_count, 36)
        rows = tuple(read_feature_rows(bundle / "stage_1_7_ai_features.jsonl"))
        self.assertEqual([row.source_record_number for row in rows], list(range(1, 41)))
        self.assertTrue(all(math.isfinite(value) for row in rows for value in row.values))

    def test_identical_builds_have_identical_feature_and_metadata_payloads(self) -> None:
        input_path = self._input_path(self._events_with_both_partitions())
        first = self.temporary_root / "first"
        second = self.temporary_root / "second"

        build_ai_feature_bundle(input_path, first)
        build_ai_feature_bundle(input_path, second)

        self.assertEqual(
            (first / "stage_1_7_ai_features.jsonl").read_bytes(),
            (second / "stage_1_7_ai_features.jsonl").read_bytes(),
        )
        self.assertEqual(
            (first / "stage_1_7_ai_feature_metadata.json").read_bytes(),
            (second / "stage_1_7_ai_feature_metadata.json").read_bytes(),
        )

    def test_holdout_changes_do_not_alter_reference_fitted_metadata(self) -> None:
        reference_session = session_for_partition("REFERENCE")
        holdout_session = session_for_partition("HOLDOUT")
        baseline_events = tuple(
            build_event(
                record_number,
                session_id=(reference_session if record_number % 2 else holdout_session),
            )
            for record_number in range(1, 41)
        )
        changed_events = tuple(
            build_event(
                record_number,
                session_id=(reference_session if record_number % 2 else holdout_session),
                overrides=(
                    None
                    if record_number % 2
                    else {
                        "dst_port": "65000",
                        "app_service": "HOLDOUT_ONLY_SERVICE",
                        "net_sentbytes": "9999",
                        "net_recvbytes": "1",
                        "net_sentpkts": "3",
                        "net_rcvdpkts": "1",
                    }
                ),
            )
            for record_number in range(1, 41)
        )
        baseline_input = self.temporary_root / "baseline.jsonl"
        changed_input = self.temporary_root / "changed.jsonl"
        write_normalized_jsonl(baseline_input, baseline_events)
        write_normalized_jsonl(changed_input, changed_events)
        baseline_bundle = self.temporary_root / "baseline-bundle"
        changed_bundle = self.temporary_root / "changed-bundle"

        build_ai_feature_bundle(baseline_input, baseline_bundle)
        build_ai_feature_bundle(changed_input, changed_bundle)
        baseline_metadata = json.loads(
            (baseline_bundle / "stage_1_7_ai_feature_metadata.json").read_text(
                encoding="utf-8"
            )
        )
        changed_metadata = json.loads(
            (changed_bundle / "stage_1_7_ai_feature_metadata.json").read_text(
                encoding="utf-8"
            )
        )

        for key in (
            "rarity_maps",
            "reference_distributions",
            "eligible_reference_distributions",
            "reference_constant_features",
        ):
            with self.subTest(metadata_key=key):
                self.assertEqual(baseline_metadata[key], changed_metadata[key])
        self.assertNotEqual(
            (baseline_bundle / "stage_1_7_ai_features.jsonl").read_bytes(),
            (changed_bundle / "stage_1_7_ai_features.jsonl").read_bytes(),
            "record-local HOLDOUT values should be allowed to change",
        )

    def test_audit_failure_prevents_publication_and_cleans_owned_temporary_bundle(self) -> None:
        input_path = self._input_path(self._events_with_both_partitions())
        bundle = self.temporary_root / "bundle"
        inspected_temporary_bundles: list[Path] = []

        def reject_completed_bundle(bundle_path: str | Path, normalized_input: str | Path) -> None:
            temporary_bundle = Path(bundle_path)
            inspected_temporary_bundles.append(temporary_bundle)
            self.assertEqual(Path(normalized_input).resolve(), input_path.resolve())
            self.assertEqual(
                {path.name for path in temporary_bundle.iterdir()},
                {
                    "stage_1_7_ai_features.jsonl",
                    "stage_1_7_ai_feature_metadata.json",
                },
            )
            self.assertGreater(
                (temporary_bundle / "stage_1_7_ai_features.jsonl").stat().st_size,
                0,
            )
            raise AIFeatureAuditError("synthetic completed-bundle audit rejection")

        with patch(
            "audit_ai_features.audit_ai_feature_bundle",
            side_effect=reject_completed_bundle,
        ):
            with self.assertRaises(AIFeatureBuildError):
                build_ai_feature_bundle(input_path, bundle)

        self.assertEqual(len(inspected_temporary_bundles), 1)
        self.assertFalse(bundle.exists())
        self.assertFalse(inspected_temporary_bundles[0].exists())
        self.assertEqual(list(self.temporary_root.glob(".bundle.*.tmp")), [])

    def test_late_invalid_input_publishes_no_final_bundle(self) -> None:
        input_path = self.temporary_root / "invalid.jsonl"
        write_normalized_jsonl(input_path, (build_event(1),))
        with input_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("{not-json}\n")
        bundle = self.temporary_root / "bundle"

        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(input_path, bundle)
        self.assertFalse(bundle.exists())
        self.assertEqual(list(self.temporary_root.glob(".bundle.*.tmp")), [])

    def test_duplicate_input_json_keys_fail_closed(self) -> None:
        input_path = self.temporary_root / "duplicate-key.jsonl"
        input_path.write_text('{"x":1,"x":2}\n', encoding="utf-8", newline="\n")
        bundle = self.temporary_root / "bundle"
        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(input_path, bundle)
        self.assertFalse(bundle.exists())

    def test_duplicate_source_record_id_and_reordered_records_fail_closed(self) -> None:
        duplicate = build_event(2, overrides={"loguid": "LOGUID_OPAQUE_1"})
        duplicate_path = self._input_path((build_event(1), duplicate))
        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(duplicate_path, self.temporary_root / "duplicate")

        reordered_path = self.temporary_root / "reordered.jsonl"
        write_normalized_jsonl(reordered_path, (build_event(2), build_event(1)))
        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(reordered_path, self.temporary_root / "reordered")

    def test_existing_output_and_output_alias_are_rejected(self) -> None:
        input_path = self._input_path(self._events_with_both_partitions())
        existing = self.temporary_root / "existing"
        existing.mkdir()
        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(input_path, existing)
        with self.assertRaises(AIFeatureBuildError):
            build_ai_feature_bundle(input_path, input_path)

    def test_auditor_rejects_tampered_feature_row(self) -> None:
        input_path = self._input_path(self._events_with_both_partitions())
        bundle = self.temporary_root / "bundle"
        build_ai_feature_bundle(input_path, bundle)

        feature_path = bundle / "stage_1_7_ai_features.jsonl"
        rows = feature_path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(rows[0])
        payload["values"][0] = 1.0 - payload["values"][0]
        rows[0] = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        feature_path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

        with self.assertRaises(AIFeatureAuditError):
            audit_ai_feature_bundle(bundle, input_path)

    def test_feature_reader_rejects_extra_or_nonfinite_contract_data(self) -> None:
        feature_path = self.temporary_root / "features.jsonl"
        payload = FeatureRow(1, "LOGUID_OPAQUE", "REFERENCE", (0.0,) * 36).to_dict()
        payload["unexpected"] = "value"
        feature_path.write_text(json.dumps(payload) + "\n", encoding="utf-8", newline="\n")
        with self.assertRaises(FeatureArtifactError):
            tuple(read_feature_rows(feature_path))

        feature_path.write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}\n',
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaises(FeatureArtifactError):
            tuple(read_feature_rows(feature_path))


if __name__ == "__main__":
    unittest.main()
