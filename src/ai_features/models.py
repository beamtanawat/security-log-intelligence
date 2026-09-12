"""Public Stage 1.7 feature-row contract.

This module deliberately defines feature data only.  It does not train,
score, rank, label, or otherwise make security decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping


FEATURE_SCHEMA_VERSION = "1.0"
REFERENCE_PARTITION = "REFERENCE"
HOLDOUT_PARTITION = "HOLDOUT"
PARTITIONS = frozenset({REFERENCE_PARTITION, HOLDOUT_PARTITION})

FEATURE_NAMES = (
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


class FeatureContractError(ValueError):
    """Raised when a Stage 1.7 feature contract value is invalid."""


def _require_positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise FeatureContractError(f"{name} must be a positive integer")
    return value


def _require_non_empty_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FeatureContractError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class FeatureRow:
    """One validated, unlabeled, model-ready feature vector.

    Source identifiers are retained strictly for joins and auditability.  They
    are not values in the feature vector.
    """

    source_record_number: int
    source_record_id: str
    partition: str
    values: tuple[float, ...]
    schema_version: str = FEATURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_positive_int(self.source_record_number, "source_record_number")
        _require_non_empty_text(self.source_record_id, "source_record_id")
        if self.partition not in PARTITIONS:
            raise FeatureContractError("partition must be REFERENCE or HOLDOUT")
        if self.schema_version != FEATURE_SCHEMA_VERSION:
            raise FeatureContractError(
                f"schema_version must be {FEATURE_SCHEMA_VERSION!r}"
            )
        values = tuple(self.values)
        if len(values) != len(FEATURE_NAMES):
            raise FeatureContractError(
                f"values must contain exactly {len(FEATURE_NAMES)} feature values"
            )
        for value in values:
            if isinstance(value, bool) or not isinstance(value, float) or not isfinite(value):
                raise FeatureContractError("feature values must be finite floats")
        object.__setattr__(self, "values", values)

    def to_dict(self) -> dict[str, object]:
        """Return the exact deterministic JSON row object."""

        return {
            "schema_version": self.schema_version,
            "source_record_number": self.source_record_number,
            "source_record_id": self.source_record_id,
            "partition": self.partition,
            "values": list(self.values),
        }

    @classmethod
    def from_dict(cls, value: object) -> "FeatureRow":
        """Reconstruct one row while rejecting unknown or missing fields."""

        if not isinstance(value, Mapping):
            raise FeatureContractError("feature row must be a JSON object")
        expected = {
            "schema_version",
            "source_record_number",
            "source_record_id",
            "partition",
            "values",
        }
        if set(value) != expected:
            raise FeatureContractError("feature row does not contain exactly its contract fields")
        raw_values = value["values"]
        if not isinstance(raw_values, list):
            raise FeatureContractError("feature row values must be a JSON array")
        return cls(
            source_record_number=value["source_record_number"],
            source_record_id=value["source_record_id"],
            partition=value["partition"],
            values=tuple(raw_values),
            schema_version=value["schema_version"],
        )
