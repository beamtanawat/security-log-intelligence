"""Pure Stage 1.9 feature-deviation calculations.

The functions in this module describe where a Stage 1.7 feature lies in its
eligible REFERENCE distribution.  They do not attribute model behavior, make
security decisions, read artifacts, or interpret opaque identifiers.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from math import isfinite
from typing import Mapping, Sequence

from ai_features.contract import FEATURE_DEFINITIONS
from ai_features.models import FEATURE_NAMES, FeatureRow


class DriverError(ValueError):
    """Raised when an explanation driver cannot be derived safely."""


FAMILY_ORDER = (
    "VOLUME",
    "DIRECTION",
    "SESSION_CHARACTERISTICS",
    "PORT_SERVICE",
    "PROTOCOL",
)

_FAMILY_POSITIONS = {
    "VOLUME": (17, 18, 19, 20, 22, 23),
    "DIRECTION": (24, 25),
    "SESSION_CHARACTERISTICS": (21, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36),
    "PORT_SERVICE": tuple(range(5, 17)),
    "PROTOCOL": (1, 2, 3, 4),
}
_FEATURE_FAMILIES = {
    FEATURE_NAMES[position - 1]: family
    for family, positions in _FAMILY_POSITIONS.items()
    for position in positions
}
_RARITY_FEATURES = frozenset({"src_port_rarity", "dst_port_rarity", "service_rarity"})
_MISSING_FEATURES = frozenset(
    {
        "service_missing",
        "sent_bytes_missing",
        "received_bytes_missing",
        "sent_packets_missing",
        "received_packets_missing",
        "duration_missing",
    }
)
_ONE_HOT_FEATURES = frozenset(
    {
        "protocol_icmp",
        "protocol_tcp",
        "protocol_udp",
        "protocol_other",
        "src_port_well_known",
        "src_port_registered",
        "src_port_dynamic",
        "dst_port_well_known",
        "dst_port_registered",
        "dst_port_dynamic",
    }
)
_FLAG_FEATURES = frozenset(
    {
        "src_port_present",
        "dst_port_present",
        "service_missing",
        "sent_bytes_missing",
        "received_bytes_missing",
        "sent_packets_missing",
        "received_packets_missing",
        "duration_missing",
        "zero_total_bytes",
        "zero_total_packets",
        "zero_sent_packets",
        "zero_received_packets",
    }
)
_DEFINITION_BY_NAME = {str(item["name"]): item for item in FEATURE_DEFINITIONS}


@dataclass(frozen=True)
class FeatureDriver:
    """One descriptive deviation reason with enough input provenance to audit."""

    family: str
    feature_name: str
    observed_value: float
    source_paths: tuple[str, ...]
    raw_observed_values: Mapping[str, object]
    reference_n: int
    less_count: int
    equal_count: int
    extremeness: float
    template_text: str
    is_missingness: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "feature_name": self.feature_name,
            "observed_value": self.observed_value,
            "source_paths": list(self.source_paths),
            "raw_observed_values": dict(self.raw_observed_values),
            "reference_n": self.reference_n,
            "less_count": self.less_count,
            "equal_count": self.equal_count,
            "extremeness": self.extremeness,
            "template_text": self.template_text,
        }


@dataclass(frozen=True)
class _ReferenceDistributionIndex:
    """One immutable sorted distribution with cumulative reference counts."""

    values: tuple[float, ...]
    cumulative_counts: tuple[int, ...]

    @property
    def total(self) -> int:
        return 0 if not self.cumulative_counts else self.cumulative_counts[-1]

    def counts_for(self, observed: float) -> tuple[int, int, int]:
        """Return reference values strictly below/equal to ``observed`` in O(log R)."""

        left = bisect_left(self.values, observed)
        right = bisect_right(self.values, observed)
        less = 0 if left == 0 else self.cumulative_counts[left - 1]
        equal = 0 if right == left else self.cumulative_counts[right - 1] - less
        return less, equal, self.total


@dataclass(frozen=True)
class ReferenceDriverIndex:
    """Prevalidated lookup structures for every Stage 1.7 feature distribution."""

    distributions: Mapping[str, _ReferenceDistributionIndex]


def _validated_distribution(value: object, name: str) -> tuple[tuple[float, int], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise DriverError(f"{name} reference distribution is invalid")
    parsed: list[tuple[float, int]] = []
    previous: float | None = None
    for item in value:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes)) or len(item) != 2:
            raise DriverError(f"{name} reference distribution is invalid")
        raw_number, count = item
        if isinstance(raw_number, bool) or not isinstance(raw_number, (int, float)):
            raise DriverError(f"{name} reference distribution is invalid")
        number = float(raw_number)
        if not isfinite(number) or isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise DriverError(f"{name} reference distribution is invalid")
        if previous is not None and number <= previous:
            raise DriverError(f"{name} reference distribution must be strictly ordered")
        parsed.append((number, count))
        previous = number
    return tuple(parsed)


def _counts(value: float, distribution: Sequence[tuple[float, int]]) -> tuple[int, int, int]:
    less = sum(count for reference, count in distribution if reference < value)
    equal = sum(count for reference, count in distribution if reference == value)
    return less, equal, sum(count for _, count in distribution)


def numeric_extremeness(
    observed_value: float, distribution: Sequence[tuple[float, int]]
) -> tuple[float, int, int, int]:
    """Return two-sided midrank extremeness and the supporting counts."""

    if isinstance(observed_value, bool) or not isinstance(observed_value, (int, float)):
        raise DriverError("observed numeric feature must be finite")
    observed = float(observed_value)
    if not isfinite(observed):
        raise DriverError("observed numeric feature must be finite")
    values = _validated_distribution(distribution, "numeric")
    less, equal, total = _counts(observed, values)
    if total == 0:
        return 0.0, less, equal, total
    if len(values) == 1:
        return (0.0 if equal else 1.0), less, equal, total
    midrank = (less + 0.5 * equal) / total
    return float(2.0 * abs(midrank - 0.5)), less, equal, total


def rarity_extremeness(
    observed_value: float, distribution: Sequence[tuple[float, int]]
) -> tuple[float, int, int, int]:
    """Return upper-tail-only midrank extremeness for frozen rarity features."""

    if isinstance(observed_value, bool) or not isinstance(observed_value, (int, float)):
        raise DriverError("observed rarity feature must be finite")
    observed = float(observed_value)
    if not isfinite(observed):
        raise DriverError("observed rarity feature must be finite")
    values = _validated_distribution(distribution, "rarity")
    less, equal, total = _counts(observed, values)
    if total == 0:
        return 0.0, less, equal, total
    if len(values) == 1:
        return (1.0 if observed > values[0][0] else 0.0), less, equal, total
    midrank = (less + 0.5 * equal) / total
    return float(max(0.0, 2.0 * midrank - 1.0)), less, equal, total


def _distribution_by_name(metadata: Mapping[str, object]) -> dict[str, tuple[tuple[float, int], ...]]:
    raw_distributions = metadata.get("eligible_reference_distributions")
    if not isinstance(raw_distributions, Sequence) or isinstance(raw_distributions, (str, bytes)):
        raise DriverError("eligible_reference_distributions is required")
    distributions: dict[str, tuple[tuple[float, int], ...]] = {}
    for raw_item in raw_distributions:
        if not isinstance(raw_item, Mapping) or set(raw_item) != {"name", "values", "eligible_count"}:
            raise DriverError("eligible reference distribution contract is invalid")
        name = raw_item["name"]
        if not isinstance(name, str) or name not in FEATURE_NAMES or name in distributions:
            raise DriverError("eligible reference distribution name is invalid")
        distribution = _validated_distribution(raw_item["values"], name)
        if raw_item["eligible_count"] != sum(count for _, count in distribution):
            raise DriverError("eligible reference distribution count does not reconcile")
        distributions[name] = distribution
    if set(distributions) != set(FEATURE_NAMES):
        raise DriverError("eligible reference distributions must cover the feature manifest")
    return distributions


def _compile_distribution(
    distribution: Sequence[tuple[float, int]],
) -> _ReferenceDistributionIndex:
    values = tuple(reference for reference, _ in distribution)
    cumulative: list[int] = []
    total = 0
    for _, count in distribution:
        total += count
        cumulative.append(total)
    return _ReferenceDistributionIndex(values=values, cumulative_counts=tuple(cumulative))


def compile_reference_index(metadata: Mapping[str, object]) -> ReferenceDriverIndex:
    """Validate and compile Stage 1.7 reference distributions once per run.

    The compiled cumulative counts preserve the exact midrank inputs used by
    the public formulas while avoiding a full reference-distribution scan for
    every record and feature.
    """

    distributions = _distribution_by_name(metadata)
    return ReferenceDriverIndex(
        distributions={
            name: _compile_distribution(distribution)
            for name, distribution in distributions.items()
        }
    )


def _indexed_extremeness(
    observed: float,
    distribution: _ReferenceDistributionIndex,
    *,
    upper_tail_only: bool,
) -> tuple[float, int, int, int]:
    less, equal, total = distribution.counts_for(observed)
    if total == 0:
        return 0.0, less, equal, total
    if len(distribution.values) == 1:
        if upper_tail_only:
            return (1.0 if observed > distribution.values[0] else 0.0), less, equal, total
        return (0.0 if equal else 1.0), less, equal, total
    midrank = (less + 0.5 * equal) / total
    if upper_tail_only:
        return float(max(0.0, 2.0 * midrank - 1.0)), less, equal, total
    return float(2.0 * abs(midrank - 0.5)), less, equal, total


def _eligible_feature(name: str, values: tuple[float, ...], context: Mapping[str, object]) -> bool:
    if name in _MISSING_FEATURES:
        return values[FEATURE_NAMES.index(name)] == 1.0
    if name in _ONE_HOT_FEATURES or name in _FLAG_FEATURES:
        return values[FEATURE_NAMES.index(name)] == 1.0
    missing = {
        "log_sent_bytes": "sent_bytes_missing",
        "log_received_bytes": "received_bytes_missing",
        "log_sent_packets": "sent_packets_missing",
        "log_received_packets": "received_packets_missing",
        "log_duration": "duration_missing",
    }
    if name in missing:
        return not bool(context[missing[name]])
    if name in {"log_total_bytes", "sent_byte_share"}:
        return not bool(context["sent_bytes_missing"]) and not bool(context["received_bytes_missing"])
    if name in {"log_total_packets", "sent_packet_share"}:
        return not bool(context["sent_packets_missing"]) and not bool(context["received_packets_missing"])
    if name == "log_sent_bytes_per_packet":
        return not bool(context["sent_bytes_missing"]) and not bool(context["sent_packets_missing"]) and int(context["sent_packets"] or 0) > 0
    if name == "log_received_bytes_per_packet":
        return not bool(context["received_bytes_missing"]) and not bool(context["received_packets_missing"]) and int(context["received_packets"] or 0) > 0
    if name in _RARITY_FEATURES:
        counterpart = {
            "src_port_rarity": "source_port_missing",
            "dst_port_rarity": "destination_port_missing",
            "service_rarity": "service_missing",
        }[name]
        return not bool(context[counterpart])
    return True


def _raw_values(source_paths: tuple[str, ...], context: Mapping[str, object]) -> dict[str, object]:
    path_to_context = {
        "network.protocol_number": "protocol_number",
        "network.source.port": "source_port",
        "network.destination.port": "destination_port",
        "application.service_source": "service_source",
        "session.sent_bytes": "sent_bytes",
        "session.received_bytes": "received_bytes",
        "session.sent_packets": "sent_packets",
        "session.received_packets": "received_packets",
        "session.duration_raw_value": "duration_raw_value",
    }
    return {path: context.get(path_to_context.get(path)) for path in source_paths}


def _template(name: str, observed: float, extremeness: float, less: int, equal: int, total: int, missing: bool) -> str:
    if missing:
        field = name.removesuffix("_missing")
        return f"{field}: absent in this record; reference absence frequency {equal}/{total}; descriptive extremeness {extremeness:.6f}"
    if name in _RARITY_FEATURES:
        return f"{name}: observed in {equal}/{total} reference records of this protocol; descriptive extremeness {extremeness:.6f}"
    if name in _ONE_HOT_FEATURES or name in _FLAG_FEATURES:
        return f"{name}: observed {observed}; reference frequency {equal}/{total}; descriptive extremeness {extremeness:.6f}"
    direction = "higher" if less + equal / 2 >= total / 2 else "lower"
    return f"{name}: observed {observed}; {direction} relative to {total} eligible reference records; descriptive extremeness {extremeness:.6f}"


def build_feature_drivers(
    feature: FeatureRow,
    metadata: Mapping[str, object],
    context: Mapping[str, object],
    *,
    reference_index: ReferenceDriverIndex | None = None,
) -> tuple[FeatureDriver, ...]:
    """Build all eligible, evidence-bounded feature drivers in manifest order."""

    if not isinstance(feature, FeatureRow):
        raise DriverError("feature must be a FeatureRow")
    reference_driver_index = (
        compile_reference_index(metadata) if reference_index is None else reference_index
    )
    if (
        not isinstance(reference_driver_index, ReferenceDriverIndex)
        or set(reference_driver_index.distributions) != set(FEATURE_NAMES)
    ):
        raise DriverError("reference driver index does not cover the feature manifest")
    drivers: list[FeatureDriver] = []
    for feature_index, name in enumerate(FEATURE_NAMES):
        if not _eligible_feature(name, feature.values, context):
            continue
        observed = feature.values[feature_index]
        distribution = reference_driver_index.distributions[name]
        if name in _RARITY_FEATURES:
            extremeness, less, equal, total = _indexed_extremeness(
                observed,
                distribution,
                upper_tail_only=True,
            )
        else:
            extremeness, less, equal, total = _indexed_extremeness(
                observed,
                distribution,
                upper_tail_only=False,
            )
        if total == 0:
            continue
        definition = _DEFINITION_BY_NAME[name]
        source_paths = tuple(str(item) for item in definition["source_paths"])
        missing = name in _MISSING_FEATURES
        drivers.append(
            FeatureDriver(
                family=_FEATURE_FAMILIES[name],
                feature_name=name,
                observed_value=observed,
                source_paths=source_paths,
                raw_observed_values=_raw_values(source_paths, context),
                reference_n=total,
                less_count=less,
                equal_count=equal,
                extremeness=extremeness,
                template_text=_template(name, observed, extremeness, less, equal, total, missing),
                is_missingness=missing,
            )
        )
    return tuple(drivers)
