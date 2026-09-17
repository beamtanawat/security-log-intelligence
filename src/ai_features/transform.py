"""Pure leakage-safe Stage 1.7 feature transforms.

The transforms work on one validated normalized event at a time.  They never
inspect raw CSV records, detection findings, timestamps, endpoint identifiers,
or analyst/model outputs.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from normalization.models import NormalizedSecurityEvent

from .models import FEATURE_NAMES, HOLDOUT_PARTITION, REFERENCE_PARTITION


SPLIT_NAMESPACE = "stage-1.7-split-v1"
SPLIT_HASH_ALGORITHM = "sha256-first-8-bytes-unsigned-big-endian-modulo-10"
_INVALID_SOURCE_FIELDS = frozenset(
    {
        "net_proto",
        "src_port",
        "dst_port",
        "net_sentbytes",
        "net_recvbytes",
        "net_sentpkts",
        "net_rcvdpkts",
        "net_sessionduration",
    }
)


class FeatureTransformError(ValueError):
    """Raised when a normalized event cannot safely enter Stage 1.7."""


@dataclass(frozen=True)
class FeatureObservation:
    """Minimal allowed input state for one unlabeled feature vector."""

    source_record_number: int
    source_record_id: str
    session_identifier: str | None
    partition: str
    protocol_number: int
    source_port: int | None
    destination_port: int | None
    service: str | None
    sent_bytes: int | None
    received_bytes: int | None
    sent_packets: int | None
    received_packets: int | None
    duration: int | None


@dataclass(frozen=True)
class RarityMaps:
    """Reference-only count maps and denominators for three rarity features."""

    source_port_counts: Mapping[tuple[int, int], int] = field(default_factory=dict)
    destination_port_counts: Mapping[tuple[int, int], int] = field(default_factory=dict)
    service_counts: Mapping[tuple[int, str], int] = field(default_factory=dict)
    source_port_denominators: Mapping[int, int] = field(default_factory=dict)
    destination_port_denominators: Mapping[int, int] = field(default_factory=dict)
    service_denominators: Mapping[int, int] = field(default_factory=dict)


def split_partition(session_identifier: str | None, source_record_number: int) -> str:
    """Assign one deterministic split without normalizing opaque identifiers."""

    if isinstance(session_identifier, str) and session_identifier:
        components: list[object] = [SPLIT_NAMESPACE, "session", session_identifier]
    else:
        if (
            isinstance(source_record_number, bool)
            or not isinstance(source_record_number, int)
            or source_record_number < 1
        ):
            raise FeatureTransformError("source record number must be a positive integer")
        components = [SPLIT_NAMESPACE, "record", source_record_number]
    encoded = json.dumps(
        components, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    bucket = int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big") % 10
    return REFERENCE_PARTITION if bucket <= 7 else HOLDOUT_PARTITION


def _mapping_value(mapping: Mapping[str, object], name: str) -> object:
    if name not in mapping:
        raise FeatureTransformError(f"normalized event is missing {name}")
    return mapping[name]


def _optional_nonnegative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FeatureTransformError(f"{field_name} must be a non-negative integer or null")
    return value


def _optional_port(value: object, field_name: str) -> int | None:
    port = _optional_nonnegative_int(value, field_name)
    if port is not None and port > 65535:
        raise FeatureTransformError(f"{field_name} must be an integer from 0 through 65535")
    return port


def share_feature_is_eligible(left: int | None, right: int | None) -> bool:
    """Return whether a derived sent-share value is a real observed ratio.

    Stage 1.7 represents an unavailable ratio with the neutral value ``0.5``.
    That fallback is not eligible for reference-distribution comparison.
    """

    if left is None or right is None:
        return False
    if (
        isinstance(left, bool)
        or not isinstance(left, int)
        or left < 0
        or isinstance(right, bool)
        or not isinstance(right, int)
        or right < 0
    ):
        raise FeatureTransformError("share feature inputs must be non-negative integers or null")
    return left + right > 0


def _actual_invalid_source_fields(event: NormalizedSecurityEvent) -> set[str]:
    return {
        issue.source_field
        for issue in event.normalization_issues
        if issue.status == "ACTUAL_INVALID"
        and issue.source_field is not None
        and issue.source_field in _INVALID_SOURCE_FIELDS
    }


def extract_feature_observation(event: NormalizedSecurityEvent) -> FeatureObservation:
    """Extract only explicitly approved fields and reject invalid source values."""

    invalid_fields = _actual_invalid_source_fields(event)
    if invalid_fields:
        names = ", ".join(sorted(invalid_fields))
        raise FeatureTransformError(
            f"normalized event has invalid Stage 1.7 source values: {names}"
        )

    source = event.source
    event_section = event.event
    network = event.network
    application = event.application
    session = event.session
    record_number = _mapping_value(source, "record_number")
    if isinstance(record_number, bool) or not isinstance(record_number, int) or record_number < 1:
        raise FeatureTransformError("source.record_number must be a positive integer")
    source_record_id = _mapping_value(event_section, "source_record_id")
    if not isinstance(source_record_id, str) or not source_record_id:
        raise FeatureTransformError("event.source_record_id must be a non-empty string")

    protocol_number = _mapping_value(network, "protocol_number")
    if (
        isinstance(protocol_number, bool)
        or not isinstance(protocol_number, int)
        or not 0 <= protocol_number <= 255
    ):
        raise FeatureTransformError(
            "network.protocol_number must be a present integer from 0 through 255"
        )
    source_network = _mapping_value(network, "source")
    destination_network = _mapping_value(network, "destination")
    if not isinstance(source_network, Mapping) or not isinstance(destination_network, Mapping):
        raise FeatureTransformError("network source and destination must be objects")
    source_port = _optional_port(_mapping_value(source_network, "port"), "network.source.port")
    destination_port = _optional_port(
        _mapping_value(destination_network, "port"), "network.destination.port"
    )

    service = _mapping_value(application, "service_source")
    if service == "":
        service = None
    if service is not None and not isinstance(service, str):
        raise FeatureTransformError("application.service_source must be a string or null")
    session_identifier = _mapping_value(session, "identifier")
    if session_identifier == "":
        session_identifier = None
    if session_identifier is not None and not isinstance(session_identifier, str):
        raise FeatureTransformError("session.identifier must be a string or null")

    observation = FeatureObservation(
        source_record_number=record_number,
        source_record_id=source_record_id,
        session_identifier=session_identifier,
        partition=split_partition(session_identifier, record_number),
        protocol_number=protocol_number,
        source_port=source_port,
        destination_port=destination_port,
        service=service,
        sent_bytes=_optional_nonnegative_int(
            _mapping_value(session, "sent_bytes"), "session.sent_bytes"
        ),
        received_bytes=_optional_nonnegative_int(
            _mapping_value(session, "received_bytes"), "session.received_bytes"
        ),
        sent_packets=_optional_nonnegative_int(
            _mapping_value(session, "sent_packets"), "session.sent_packets"
        ),
        received_packets=_optional_nonnegative_int(
            _mapping_value(session, "received_packets"), "session.received_packets"
        ),
        duration=_optional_nonnegative_int(
            _mapping_value(session, "duration_raw_value"), "session.duration_raw_value"
        ),
    )
    return observation


def build_reference_maps(observations: Iterable[FeatureObservation]) -> RarityMaps:
    """Build count maps from REFERENCE observations only, never holdout rows."""

    source_ports: Counter[tuple[int, int]] = Counter()
    destination_ports: Counter[tuple[int, int]] = Counter()
    services: Counter[tuple[int, str]] = Counter()
    source_denominators: Counter[int] = Counter()
    destination_denominators: Counter[int] = Counter()
    service_denominators: Counter[int] = Counter()
    for observation in observations:
        if observation.partition != REFERENCE_PARTITION:
            continue
        protocol = observation.protocol_number
        if observation.source_port is not None:
            key = (protocol, observation.source_port)
            source_ports[key] += 1
            source_denominators[protocol] += 1
        if observation.destination_port is not None:
            key = (protocol, observation.destination_port)
            destination_ports[key] += 1
            destination_denominators[protocol] += 1
        if observation.service is not None:
            key = (protocol, observation.service)
            services[key] += 1
            service_denominators[protocol] += 1
    return RarityMaps(
        source_port_counts=dict(source_ports),
        destination_port_counts=dict(destination_ports),
        service_counts=dict(services),
        source_port_denominators=dict(source_denominators),
        destination_port_denominators=dict(destination_denominators),
        service_denominators=dict(service_denominators),
    )


def _port_class(port: int | None) -> tuple[float, float, float]:
    if port is None:
        return (0.0, 0.0, 0.0)
    if port <= 1023:
        return (1.0, 0.0, 0.0)
    if port <= 49151:
        return (0.0, 1.0, 0.0)
    return (0.0, 0.0, 1.0)


def _rarity(
    protocol: int,
    value: int | str | None,
    counts: Mapping[tuple[int, object], int],
    denominators: Mapping[int, int],
) -> float:
    if value is None:
        return 0.0
    denominator = denominators.get(protocol, 0)
    if denominator == 0:
        return 1.0
    return float(1.0 - (counts.get((protocol, value), 0) / denominator))


def _log1p(value: int) -> float:
    try:
        result = float(math.log1p(value))
    except (OverflowError, ValueError) as error:
        raise FeatureTransformError("metric log1p cannot be represented as a finite float") from error
    if not math.isfinite(result):
        raise FeatureTransformError("metric log1p cannot be represented as a finite float")
    return result


def _log1p_ratio(numerator: int, denominator: int) -> float:
    """Return finite natural log1p(numerator / denominator)."""

    try:
        result = float(math.log1p(numerator / denominator))
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise FeatureTransformError(
            "metric log1p ratio cannot be represented as a finite float"
        ) from error
    if not math.isfinite(result):
        raise FeatureTransformError(
            "metric log1p ratio cannot be represented as a finite float"
        )
    return result


def build_feature_values(
    observation: FeatureObservation, rarity_maps: RarityMaps
) -> tuple[tuple[float, ...], tuple[bool, ...]]:
    """Return the immutable 36-vector and per-feature eligible flags.

    `eligible` is used only for reference-distribution metadata; it does not
    remove or alter any values in the published feature vector.
    """

    protocol = observation.protocol_number
    protocol_values = (
        float(protocol == 1),
        float(protocol == 6),
        float(protocol == 17),
        float(protocol not in {1, 6, 17}),
    )
    source_class = _port_class(observation.source_port)
    destination_class = _port_class(observation.destination_port)
    sent_bytes_missing = observation.sent_bytes is None
    received_bytes_missing = observation.received_bytes is None
    sent_packets_missing = observation.sent_packets is None
    received_packets_missing = observation.received_packets is None
    duration_missing = observation.duration is None
    sent_bytes = observation.sent_bytes or 0
    received_bytes = observation.received_bytes or 0
    sent_packets = observation.sent_packets or 0
    received_packets = observation.received_packets or 0
    duration = observation.duration or 0

    complete_bytes = not sent_bytes_missing and not received_bytes_missing
    complete_packets = not sent_packets_missing and not received_packets_missing
    total_bytes = sent_bytes + received_bytes if complete_bytes else 0
    total_packets = sent_packets + received_packets if complete_packets else 0
    byte_share_eligible = share_feature_is_eligible(
        observation.sent_bytes, observation.received_bytes
    )
    packet_share_eligible = share_feature_is_eligible(
        observation.sent_packets, observation.received_packets
    )
    sent_per_packet_eligible = not sent_bytes_missing and not sent_packets_missing and sent_packets > 0
    received_per_packet_eligible = (
        not received_bytes_missing and not received_packets_missing and received_packets > 0
    )

    values = (
        *protocol_values,
        float(observation.source_port is not None),
        float(observation.destination_port is not None),
        *source_class,
        *destination_class,
        _rarity(
            protocol,
            observation.source_port,
            rarity_maps.source_port_counts,
            rarity_maps.source_port_denominators,
        ),
        _rarity(
            protocol,
            observation.destination_port,
            rarity_maps.destination_port_counts,
            rarity_maps.destination_port_denominators,
        ),
        _rarity(
            protocol,
            observation.service,
            rarity_maps.service_counts,
            rarity_maps.service_denominators,
        ),
        float(observation.service is None),
        _log1p(sent_bytes),
        _log1p(received_bytes),
        _log1p(sent_packets),
        _log1p(received_packets),
        _log1p(duration),
        _log1p(total_bytes),
        _log1p(total_packets),
        float(sent_bytes / total_bytes) if byte_share_eligible else 0.5,
        float(sent_packets / total_packets) if packet_share_eligible else 0.5,
        _log1p_ratio(sent_bytes, sent_packets) if sent_per_packet_eligible else 0.0,
        _log1p_ratio(received_bytes, received_packets)
        if received_per_packet_eligible
        else 0.0,
        float(sent_bytes_missing),
        float(received_bytes_missing),
        float(sent_packets_missing),
        float(received_packets_missing),
        float(duration_missing),
        float(complete_bytes and total_bytes == 0),
        float(complete_packets and total_packets == 0),
        float(not sent_packets_missing and sent_packets == 0),
        float(not received_packets_missing and received_packets == 0),
    )
    if len(values) != len(FEATURE_NAMES) or not all(math.isfinite(value) for value in values):
        raise FeatureTransformError("feature transform did not produce 36 finite values")
    eligible = (
        *(True for _ in range(12)),
        observation.source_port is not None,
        observation.destination_port is not None,
        observation.service is not None,
        True,
        not sent_bytes_missing,
        not received_bytes_missing,
        not sent_packets_missing,
        not received_packets_missing,
        not duration_missing,
        complete_bytes,
        complete_packets,
        byte_share_eligible,
        packet_share_eligible,
        sent_per_packet_eligible,
        received_per_packet_eligible,
        *(True for _ in range(5)),
        complete_bytes,
        complete_packets,
        not sent_packets_missing,
        not received_packets_missing,
    )
    if len(eligible) != len(FEATURE_NAMES):
        raise FeatureTransformError("feature eligibility did not produce 36 values")
    return tuple(float(value) for value in values), tuple(eligible)
