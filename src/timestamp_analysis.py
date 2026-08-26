"""Read-only timestamp aggregates for Stage 1.2E data-quality analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


MISSING_GROUP_VALUE = "<MISSING>"
MISSING_ITIME_CONTEXT_FIELDS = (
    "event_type",
    "event_subtype",
    "event_action",
    "net_proto",
    "app_service",
    "data_sourcetype",
)


def _is_missing(value: str | None) -> bool:
    return value is None or not value.strip()


def _group_value(value: str | None) -> str:
    return MISSING_GROUP_VALUE if _is_missing(value) else value


@dataclass
class _TimestampFieldStats:
    """One-pass numeric and file-order statistics for one raw timestamp field."""

    frequency_limit: int
    track_value_frequencies: bool
    missing_count: int = 0
    non_missing_count: int = 0
    valid_integer_count: int = 0
    conversion_failure_count: int = 0
    minimum: int | None = None
    maximum: int | None = None
    _unique_values: set[int] = field(default_factory=set)
    _repeat_extra_occurrences: Counter[int] = field(default_factory=Counter)
    _value_frequencies: Counter[int] = field(default_factory=Counter)
    _previous_valid_row_value: int | None = None
    _adjacent_increase_count: int = 0
    _adjacent_equal_count: int = 0
    _adjacent_decrease_count: int = 0

    def add(self, raw_value: str | None) -> int | None:
        """Measure one raw value and return its integer conversion when valid."""

        if _is_missing(raw_value):
            self.missing_count += 1
            self._previous_valid_row_value = None
            return None

        self.non_missing_count += 1
        try:
            numeric_value = int(raw_value)
        except ValueError:
            self.conversion_failure_count += 1
            self._previous_valid_row_value = None
            return None

        self.valid_integer_count += 1
        if self.minimum is None or numeric_value < self.minimum:
            self.minimum = numeric_value
        if self.maximum is None or numeric_value > self.maximum:
            self.maximum = numeric_value

        if numeric_value in self._unique_values:
            self._repeat_extra_occurrences[numeric_value] += 1
        else:
            self._unique_values.add(numeric_value)
        if self.track_value_frequencies:
            self._value_frequencies[numeric_value] += 1

        previous_value = self._previous_valid_row_value
        if previous_value is not None:
            if numeric_value > previous_value:
                self._adjacent_increase_count += 1
            elif numeric_value == previous_value:
                self._adjacent_equal_count += 1
            else:
                self._adjacent_decrease_count += 1
        self._previous_valid_row_value = numeric_value
        return numeric_value

    def as_dict(self) -> dict[str, Any]:
        """Return deterministic, aggregate statistics without changing raw values."""

        ordered_repeats = sorted(
            self._repeat_extra_occurrences.items(), key=lambda item: (-item[1], item[0])
        )
        selected_repeats = ordered_repeats[: self.frequency_limit]
        adjacent_comparable_pair_count = (
            self._adjacent_increase_count
            + self._adjacent_equal_count
            + self._adjacent_decrease_count
        )
        result = {
            "missing_count": self.missing_count,
            "non_missing_count": self.non_missing_count,
            "valid_integer_count": self.valid_integer_count,
            "conversion_failure_count": self.conversion_failure_count,
            "minimum_numeric_value": self.minimum,
            "maximum_numeric_value": self.maximum,
            "observed_numeric_span": (
                self.maximum - self.minimum
                if self.minimum is not None and self.maximum is not None
                else None
            ),
            "unique_valid_integer_count": len(self._unique_values),
            "repeated_valid_integer_occurrence_count": (
                self.valid_integer_count - len(self._unique_values)
            ),
            "repeated_value_summary": {
                "value_limit": self.frequency_limit,
                "reported_value_count": len(selected_repeats),
                "omitted_value_count": len(ordered_repeats) - len(selected_repeats),
                "values": [
                    {
                        "numeric_value": value,
                        "total_occurrence_count": extra_occurrences + 1,
                    }
                    for value, extra_occurrences in selected_repeats
                ],
            },
            "file_order": {
                "adjacent_valid_row_pair_count": adjacent_comparable_pair_count,
                "adjacent_increase_count": self._adjacent_increase_count,
                "adjacent_equal_count": self._adjacent_equal_count,
                "adjacent_decrease_count": self._adjacent_decrease_count,
            },
        }
        if self.track_value_frequencies:
            ordered_frequencies = sorted(
                self._value_frequencies.items(), key=lambda item: (-item[1], item[0])
            )
            selected_frequencies = ordered_frequencies[: self.frequency_limit]
            result["value_frequency_summary"] = {
                "value_limit": self.frequency_limit,
                "reported_value_count": len(selected_frequencies),
                "omitted_value_count": len(ordered_frequencies) - len(selected_frequencies),
                "top_values": [
                    {
                        "numeric_value": value,
                        "row_count": count,
                        "percentage_of_valid_integer_rows": _percentage(
                            count, self.valid_integer_count
                        ),
                    }
                    for value, count in selected_frequencies
                ],
            }
        return result


@dataclass
class _TimestampRelationshipStats:
    """Aggregate numeric comparisons where both raw timestamp fields are valid."""

    both_valid_row_count: int = 0
    difference_minimum: int | None = None
    difference_maximum: int | None = None
    _first_difference: int | None = None
    _has_varying_difference: bool = False

    def add(self, itime_value: int | None, data_timestamp_value: int | None) -> None:
        if itime_value is None or data_timestamp_value is None:
            return

        difference = itime_value - data_timestamp_value
        self.both_valid_row_count += 1
        if self.difference_minimum is None or difference < self.difference_minimum:
            self.difference_minimum = difference
        if self.difference_maximum is None or difference > self.difference_maximum:
            self.difference_maximum = difference
        if self._first_difference is None:
            self._first_difference = difference
        elif difference != self._first_difference:
            self._has_varying_difference = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "both_valid_row_count": self.both_valid_row_count,
            "itime_minus_data_timestamp_minimum": self.difference_minimum,
            "itime_minus_data_timestamp_maximum": self.difference_maximum,
            "constant_difference_observed": (
                None
                if self.both_valid_row_count == 0
                else not self._has_varying_difference
            ),
            "semantic_status": "UNKNOWN",
            "interpretation": (
                "This is a numeric comparison only; it does not establish the "
                "source semantics or unit of data_timestamp."
            ),
        }


def _percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(100 * numerator / denominator, 6)


class TimestampAnalysisAccumulator:
    """Bounded, read-only timestamp analysis for one pass over parsed CSV rows."""

    def __init__(
        self,
        *,
        value_frequency_limit: int = 20,
        missing_context_value_limit: int = 20,
    ) -> None:
        if value_frequency_limit < 1 or missing_context_value_limit < 1:
            raise ValueError("timestamp summary limits must be at least 1")
        self.row_count = 0
        self.value_frequency_limit = value_frequency_limit
        self.missing_context_value_limit = missing_context_value_limit
        self._itime = _TimestampFieldStats(value_frequency_limit, False)
        self._data_timestamp = _TimestampFieldStats(value_frequency_limit, True)
        self._relationship = _TimestampRelationshipStats()
        self._missing_itime_context: dict[str, Counter[str]] = {
            field: Counter() for field in MISSING_ITIME_CONTEXT_FIELDS
        }
        self._epoch_second_convertible_count = 0
        self._epoch_second_conversion_failure_count = 0
        self._derived_utc_minimum: datetime | None = None
        self._derived_utc_maximum: datetime | None = None

    def add_row(self, row: Mapping[str, str | None]) -> None:
        """Add one row without retaining it or changing either raw timestamp."""

        self.row_count += 1
        raw_itime = row.get("itime")
        itime_value = self._itime.add(raw_itime)
        data_timestamp_value = self._data_timestamp.add(row.get("data_timestamp"))
        self._relationship.add(itime_value, data_timestamp_value)

        if _is_missing(raw_itime):
            for field, counts in self._missing_itime_context.items():
                counts[_group_value(row.get(field))] += 1
        if itime_value is not None:
            self._add_derived_utc_value(itime_value)

    def _add_derived_utc_value(self, itime_value: int) -> None:
        """Create a derived UTC value only for analysis, retaining raw itime."""

        try:
            derived_utc = datetime.fromtimestamp(itime_value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            self._epoch_second_conversion_failure_count += 1
            return

        self._epoch_second_convertible_count += 1
        if self._derived_utc_minimum is None or derived_utc < self._derived_utc_minimum:
            self._derived_utc_minimum = derived_utc
        if self._derived_utc_maximum is None or derived_utc > self._derived_utc_maximum:
            self._derived_utc_maximum = derived_utc

    def as_dict(self) -> dict[str, Any]:
        """Return timestamp findings with raw and derived values clearly separated."""

        itime_result = self._itime.as_dict()
        itime_result["missing_context"] = self._missing_itime_context_result()
        itime_result["derived_utc_epoch_seconds"] = {
            "label": "DERIVED",
            "assumption": (
                "Valid integer itime values are interpreted as Unix epoch seconds "
                "only for this UTC representation."
            ),
            "timezone": "UTC",
            "convertible_value_count": self._epoch_second_convertible_count,
            "conversion_failure_count": self._epoch_second_conversion_failure_count,
            "derived_minimum_utc": self._isoformat_or_none(self._derived_utc_minimum),
            "derived_maximum_utc": self._isoformat_or_none(self._derived_utc_maximum),
            "interpretation_status": "NEEDS VERIFICATION",
        }

        data_timestamp_result = self._data_timestamp.as_dict()
        data_timestamp_result["semantic_status"] = "UNKNOWN"
        data_timestamp_result["interpretation"] = (
            "Numeric distribution and file-order behavior are reported without "
            "assuming that data_timestamp is Unix time, an offset, or a sequence."
        )

        return {
            "row_count": self.row_count,
            "itime": itime_result,
            "data_timestamp": data_timestamp_result,
            "itime_data_timestamp_relationship": self._relationship.as_dict(),
        }

    def _missing_itime_context_result(self) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for field, counts in self._missing_itime_context.items():
            ordered_values = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            selected_values = ordered_values[: self.missing_context_value_limit]
            summaries.append(
                {
                    "field": field,
                    "reported_value_count": len(selected_values),
                    "omitted_value_count": len(ordered_values) - len(selected_values),
                    "values": [
                        {"value": value, "row_count": count}
                        for value, count in selected_values
                    ],
                }
            )
        return summaries

    @staticmethod
    def _isoformat_or_none(value: datetime | None) -> str | None:
        return value.isoformat() if value is not None else None
