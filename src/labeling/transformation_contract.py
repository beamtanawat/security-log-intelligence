"""Frozen Stage 2.1 shared feature-transformation contract."""

from __future__ import annotations

from enum import StrEnum


FEATURE_NAMES = (
    "protocol_icmp", "protocol_tcp", "protocol_udp", "protocol_other",
    "src_port_present", "dst_port_present", "src_port_well_known",
    "src_port_registered", "src_port_dynamic", "dst_port_well_known",
    "dst_port_registered", "dst_port_dynamic", "src_port_rarity",
    "dst_port_rarity", "service_rarity", "service_missing", "log_sent_bytes",
    "log_received_bytes", "log_sent_packets", "log_received_packets", "log_duration",
    "log_total_bytes", "log_total_packets", "sent_byte_share", "sent_packet_share",
    "log_sent_bytes_per_packet", "log_received_bytes_per_packet", "sent_bytes_missing",
    "received_bytes_missing", "sent_packets_missing", "received_packets_missing",
    "duration_missing", "zero_total_bytes", "zero_total_packets", "zero_sent_packets",
    "zero_received_packets",
)


class FitScope(StrEnum):
    TRAIN_FULL = "TRAIN_FULL"
    OUTER_TRAIN = "OUTER_TRAIN"
    INNER_TRAIN = "INNER_TRAIN"
    FINAL_TRAIN_CROSSFIT = "FINAL_TRAIN_CROSSFIT"


FORBIDDEN_FIT_SCOPES = frozenset({"FULL_DATASET", "TRAIN_PLUS_VALIDATION", "TEST"})


def validate_fit_scope(scope: str | FitScope) -> None:
    value = scope.value if isinstance(scope, FitScope) else scope
    if value in FORBIDDEN_FIT_SCOPES:
        raise ValueError(f"forbidden fit scope: {value}")
    if value not in {item.value for item in FitScope}:
        raise ValueError(f"unknown fit scope: {value}")


def transformation_protocol() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "protocol_id": "stage-2.1-transformation-v1",
        "feature_names": list(FEATURE_NAMES),
        "forbidden_fit_scopes": sorted(FORBIDDEN_FIT_SCOPES),
        "allowed_fit_scopes": [item.value for item in FitScope],
        "population_state": ["src_port_rarity", "dst_port_rarity", "service_rarity", "constant_features"],
    }
