"""Neutral Stage 1.7 metadata contract shared by builder and auditor.

This module owns descriptive feature metadata only.  It does not build,
publish, audit, train, or score artifacts.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .models import FEATURE_NAMES
from .transform import RarityMaps


EVALUATION_PROTOCOL_VERSION = "1.0"
METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "normalized_input",
        "feature_artifact",
        "feature_names",
        "feature_definitions",
        "split",
        "rarity_maps",
        "reference_distributions",
        "reference_constant_features",
        "eligible_reference_distributions",
        "runtime",
        "evaluation_protocol_version",
    }
)
FEATURE_EXCLUSIONS = (
    "No raw identifiers, timestamps, labels, findings, threats, source-product "
    "decision fields, or constant data_sourcetype."
)


def _definition(
    position: int,
    name: str,
    source_paths: tuple[str, ...],
    transform: str,
    family: str,
    eligible_when: str,
    *,
    missingness_flag: bool = False,
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "position": position,
            "name": name,
            "source_paths": source_paths,
            "transform": transform,
            "family": family,
            "eligible_when": eligible_when,
            "missingness_flag": missingness_flag,
            "exclusions": FEATURE_EXCLUSIONS,
        }
    )


FEATURE_DEFINITIONS = (
    _definition(
        1,
        "protocol_icmp",
        ("network.protocol_number",),
        "protocol_equals_1_indicator",
        "protocol",
        "always_after_protocol_validation",
    ),
    _definition(
        2,
        "protocol_tcp",
        ("network.protocol_number",),
        "protocol_equals_6_indicator",
        "protocol",
        "always_after_protocol_validation",
    ),
    _definition(
        3,
        "protocol_udp",
        ("network.protocol_number",),
        "protocol_equals_17_indicator",
        "protocol",
        "always_after_protocol_validation",
    ),
    _definition(
        4,
        "protocol_other",
        ("network.protocol_number",),
        "protocol_other_valid_indicator",
        "protocol",
        "always_after_protocol_validation",
    ),
    _definition(
        5,
        "src_port_present",
        ("network.source.port",),
        "present_indicator",
        "source_port",
        "always",
    ),
    _definition(
        6,
        "dst_port_present",
        ("network.destination.port",),
        "present_indicator",
        "destination_port",
        "always",
    ),
    _definition(
        7,
        "src_port_well_known",
        ("network.source.port",),
        "well_known_0_1023_indicator",
        "source_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        8,
        "src_port_registered",
        ("network.source.port",),
        "registered_1024_49151_indicator",
        "source_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        9,
        "src_port_dynamic",
        ("network.source.port",),
        "dynamic_49152_65535_indicator",
        "source_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        10,
        "dst_port_well_known",
        ("network.destination.port",),
        "well_known_0_1023_indicator",
        "destination_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        11,
        "dst_port_registered",
        ("network.destination.port",),
        "registered_1024_49151_indicator",
        "destination_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        12,
        "dst_port_dynamic",
        ("network.destination.port",),
        "dynamic_49152_65535_indicator",
        "destination_port",
        "always_contextual_missing_as_zero",
    ),
    _definition(
        13,
        "src_port_rarity",
        ("network.protocol_number", "network.source.port"),
        "reference_rarity_1_minus_count_over_present_protocol_denominator",
        "source_port",
        "source_port_present",
    ),
    _definition(
        14,
        "dst_port_rarity",
        ("network.protocol_number", "network.destination.port"),
        "reference_rarity_1_minus_count_over_present_protocol_denominator",
        "destination_port",
        "destination_port_present",
    ),
    _definition(
        15,
        "service_rarity",
        ("network.protocol_number", "application.service_source"),
        "reference_rarity_1_minus_count_over_present_protocol_denominator",
        "service",
        "service_present",
    ),
    _definition(
        16,
        "service_missing",
        ("application.service_source",),
        "missing_indicator",
        "service",
        "always",
        missingness_flag=True,
    ),
    _definition(
        17,
        "log_sent_bytes",
        ("session.sent_bytes",),
        "natural_log1p_nonnegative_or_zero_if_missing",
        "session_metric",
        "sent_bytes_present",
    ),
    _definition(
        18,
        "log_received_bytes",
        ("session.received_bytes",),
        "natural_log1p_nonnegative_or_zero_if_missing",
        "session_metric",
        "received_bytes_present",
    ),
    _definition(
        19,
        "log_sent_packets",
        ("session.sent_packets",),
        "natural_log1p_nonnegative_or_zero_if_missing",
        "session_metric",
        "sent_packets_present",
    ),
    _definition(
        20,
        "log_received_packets",
        ("session.received_packets",),
        "natural_log1p_nonnegative_or_zero_if_missing",
        "session_metric",
        "received_packets_present",
    ),
    _definition(
        21,
        "log_duration",
        ("session.duration_raw_value",),
        "unit_neutral_natural_log1p_or_zero_if_missing",
        "session_duration",
        "duration_present",
    ),
    _definition(
        22,
        "log_total_bytes",
        ("session.sent_bytes", "session.received_bytes"),
        "natural_log1p_sum_when_both_present_else_zero",
        "derived_byte_metric",
        "both_byte_metrics_present",
    ),
    _definition(
        23,
        "log_total_packets",
        ("session.sent_packets", "session.received_packets"),
        "natural_log1p_sum_when_both_present_else_zero",
        "derived_packet_metric",
        "both_packet_metrics_present",
    ),
    _definition(
        24,
        "sent_byte_share",
        ("session.sent_bytes", "session.received_bytes"),
        "sent_over_total_when_both_present_and_total_positive_else_0_5",
        "derived_byte_metric",
        "both_byte_metrics_present_and_total_positive",
    ),
    _definition(
        25,
        "sent_packet_share",
        ("session.sent_packets", "session.received_packets"),
        "sent_over_total_when_both_present_and_total_positive_else_0_5",
        "derived_packet_metric",
        "both_packet_metrics_present_and_total_positive",
    ),
    _definition(
        26,
        "log_sent_bytes_per_packet",
        ("session.sent_bytes", "session.sent_packets"),
        "natural_log1p_ratio_when_both_present_and_packets_positive_else_zero",
        "derived_byte_packet_metric",
        "sent_bytes_and_packets_present_and_packets_positive",
    ),
    _definition(
        27,
        "log_received_bytes_per_packet",
        ("session.received_bytes", "session.received_packets"),
        "natural_log1p_ratio_when_both_present_and_packets_positive_else_zero",
        "derived_byte_packet_metric",
        "received_bytes_and_packets_present_and_packets_positive",
    ),
    _definition(
        28,
        "sent_bytes_missing",
        ("session.sent_bytes",),
        "missing_indicator",
        "session_metric_missingness",
        "always",
        missingness_flag=True,
    ),
    _definition(
        29,
        "received_bytes_missing",
        ("session.received_bytes",),
        "missing_indicator",
        "session_metric_missingness",
        "always",
        missingness_flag=True,
    ),
    _definition(
        30,
        "sent_packets_missing",
        ("session.sent_packets",),
        "missing_indicator",
        "session_metric_missingness",
        "always",
        missingness_flag=True,
    ),
    _definition(
        31,
        "received_packets_missing",
        ("session.received_packets",),
        "missing_indicator",
        "session_metric_missingness",
        "always",
        missingness_flag=True,
    ),
    _definition(
        32,
        "duration_missing",
        ("session.duration_raw_value",),
        "missing_indicator",
        "session_metric_missingness",
        "always",
        missingness_flag=True,
    ),
    _definition(
        33,
        "zero_total_bytes",
        ("session.sent_bytes", "session.received_bytes"),
        "observed_zero_sum_indicator_when_both_present",
        "derived_byte_metric",
        "both_byte_metrics_present",
    ),
    _definition(
        34,
        "zero_total_packets",
        ("session.sent_packets", "session.received_packets"),
        "observed_zero_sum_indicator_when_both_present",
        "derived_packet_metric",
        "both_packet_metrics_present",
    ),
    _definition(
        35,
        "zero_sent_packets",
        ("session.sent_packets",),
        "observed_zero_indicator",
        "session_metric",
        "sent_packets_present",
    ),
    _definition(
        36,
        "zero_received_packets",
        ("session.received_packets",),
        "observed_zero_indicator",
        "session_metric",
        "received_packets_present",
    ),
)

if tuple(definition["name"] for definition in FEATURE_DEFINITIONS) != FEATURE_NAMES:
    raise RuntimeError("Stage 1.7 feature definitions do not match the feature manifest")


def feature_definitions_payload() -> list[dict[str, object]]:
    """Return a JSON-safe copy of the immutable ordered definitions."""

    return [
        {
            **definition,
            "source_paths": list(definition["source_paths"]),
        }
        for definition in FEATURE_DEFINITIONS
    ]


def _typed_count_arrays(
    counts: Mapping[tuple[int, int | str], int],
) -> list[list[object]]:
    return [
        [protocol, value, counts[(protocol, value)]]
        for protocol, value in sorted(counts)
    ]


def _denominator_arrays(counts: Mapping[int, int]) -> list[list[int]]:
    return [[protocol, counts[protocol]] for protocol in sorted(counts)]


def rarity_maps_to_metadata(rarity_maps: RarityMaps) -> dict[str, object]:
    """Return the neutral sorted JSON representation of REFERENCE rarity maps."""

    return {
        "source_port": {
            "counts": _typed_count_arrays(rarity_maps.source_port_counts),
            "protocol_denominators": _denominator_arrays(
                rarity_maps.source_port_denominators
            ),
        },
        "destination_port": {
            "counts": _typed_count_arrays(rarity_maps.destination_port_counts),
            "protocol_denominators": _denominator_arrays(
                rarity_maps.destination_port_denominators
            ),
        },
        "service": {
            "counts": _typed_count_arrays(rarity_maps.service_counts),
            "protocol_denominators": _denominator_arrays(
                rarity_maps.service_denominators
            ),
        },
    }
