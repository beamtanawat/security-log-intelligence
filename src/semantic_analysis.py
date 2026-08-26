"""Read-only Event, Application, Threat, Identifier, and numeric summaries."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from statistics import median
from typing import Any


MISSING_GROUP_VALUE = "<MISSING>"
EVENT_FIELDS = ("event_type", "event_subtype", "event_action", "event_severity")
APPLICATION_FIELDS = ("app_cat", "app_service", "app_id", "app_name")
THREAT_FIELDS = (
    "threat_action",
    "threat_name",
    "threat_severity",
    "threat_type",
    "threat_pattern",
    "threat_id",
    "threat_ref",
)
IDENTIFIER_FIELDS = ("src_ip", "dst_ip", "host_ip", "loguid", "net_sessionid")
SELECTED_NUMERIC_FIELDS = (
    "src_port",
    "dst_port",
    "net_rcvdpkts",
    "net_recvbytes",
    "net_sentbytes",
    "net_sentpkts",
    "net_sessionduration",
)
EVENT_COMBINATIONS = (
    ("event_type", "event_action"),
    ("event_subtype", "event_action"),
    ("event_type", "event_severity"),
)
APPLICATION_COMBINATIONS = (("app_cat", "app_service"), ("app_id", "app_name"))
IDENTIFIER_OCCURRENCE_BUCKETS = (
    ("1", 1, 1),
    ("2", 2, 2),
    ("3-5", 3, 5),
    ("6-10", 6, 10),
    ("11+", 11, None),
)


def _is_missing(value: str | None) -> bool:
    return value is None or not value.strip()


def _group_value(value: str | None) -> str:
    return MISSING_GROUP_VALUE if _is_missing(value) else value


def _percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(100 * numerator / denominator, 6)


def _nearest_rank_percentile(values: Sequence[int], percentile: int) -> int | None:
    if not values:
        return None
    if not 0 <= percentile <= 100:
        raise ValueError("percentile must be between 0 and 100")

    ordered_values = sorted(values)
    if percentile == 0:
        return ordered_values[0]
    rank = (percentile * len(ordered_values) + 99) // 100
    return ordered_values[rank - 1]


def _identifier_occurrence_bucket(occurrence_count: int) -> str:
    for label, minimum, maximum in IDENTIFIER_OCCURRENCE_BUCKETS:
        if occurrence_count >= minimum and (
            maximum is None or occurrence_count <= maximum
        ):
            return label
    raise ValueError("identifier occurrence count must be positive")


@dataclass
class _NumericFieldStats:
    """Aggregate values required for descriptive numeric summary statistics."""

    missing_count: int = 0
    non_missing_count: int = 0
    valid_integer_count: int = 0
    conversion_failure_count: int = 0
    zero_count: int = 0
    nonzero_count: int = 0
    values: list[int] = field(default_factory=list)

    def add(self, raw_value: str | None) -> None:
        if _is_missing(raw_value):
            self.missing_count += 1
            return

        self.non_missing_count += 1
        try:
            numeric_value = int(raw_value)
        except ValueError:
            self.conversion_failure_count += 1
            return

        self.valid_integer_count += 1
        if numeric_value == 0:
            self.zero_count += 1
        else:
            self.nonzero_count += 1
        self.values.append(numeric_value)

    def as_dict(self, row_count: int) -> dict[str, Any]:
        return {
            "missing_count": self.missing_count,
            "non_missing_count": self.non_missing_count,
            "valid_integer_count": self.valid_integer_count,
            "conversion_failure_count": self.conversion_failure_count,
            "denominator_row_count": row_count,
            "zero_count": self.zero_count,
            "nonzero_count": self.nonzero_count,
            "minimum": min(self.values) if self.values else None,
            "maximum": max(self.values) if self.values else None,
            "median": median(self.values) if self.values else None,
            "nearest_rank_percentiles": {
                "p50": _nearest_rank_percentile(self.values, 50),
                "p95": _nearest_rank_percentile(self.values, 95),
                "p99": _nearest_rank_percentile(self.values, 99),
            },
        }


class SemanticAnalysisAccumulator:
    """One-pass bounded descriptive analysis for Stage 1.2F.

    It preserves source values, omits high-cardinality identifier values from all
    output, and does not generate security labels, risk scores, or detections.
    """

    def __init__(
        self,
        *,
        top_value_limit: int = 20,
        combination_limit: int = 20,
        rare_combination_limit: int = 10,
    ) -> None:
        if min(top_value_limit, combination_limit, rare_combination_limit) < 1:
            raise ValueError("semantic summary limits must be at least 1")
        self.top_value_limit = top_value_limit
        self.combination_limit = combination_limit
        self.rare_combination_limit = rare_combination_limit
        self.row_count = 0
        self._event_values = {field: Counter() for field in EVENT_FIELDS}
        self._event_combinations = {
            fields: Counter() for fields in EVENT_COMBINATIONS
        }
        self._application_values = {field: Counter() for field in APPLICATION_FIELDS}
        self._application_population = {
            field: Counter() for field in APPLICATION_FIELDS
        }
        self._application_by_event_context: dict[
            tuple[str, str], dict[str, Counter[str]]
        ] = {}
        self._application_combinations = {
            fields: Counter() for fields in APPLICATION_COMBINATIONS
        }
        self._threat_values = {field: Counter() for field in THREAT_FIELDS}
        self._threat_population = {field: Counter() for field in THREAT_FIELDS}
        self._threat_present_field_population = {
            field: Counter() for field in THREAT_FIELDS
        }
        self._threat_present_record_count = 0
        self._threat_context = Counter()
        self._identifier_counts = {field: Counter() for field in IDENTIFIER_FIELDS}
        self._identifier_missing_counts = {field: 0 for field in IDENTIFIER_FIELDS}
        self._numeric_fields = {
            field: _NumericFieldStats() for field in SELECTED_NUMERIC_FIELDS
        }

    def add_row(self, row: Mapping[str, str | None]) -> None:
        """Measure one parsed row without retaining the complete row."""

        self.row_count += 1
        self._add_event_values(row)
        self._add_application_values(row)
        self._add_threat_values(row)
        self._add_identifier_values(row)
        self._add_numeric_values(row)

    def _add_event_values(self, row: Mapping[str, str | None]) -> None:
        for field, counts in self._event_values.items():
            raw_value = row.get(field)
            if not _is_missing(raw_value):
                counts[raw_value] += 1
        for fields, counts in self._event_combinations.items():
            counts[tuple(_group_value(row.get(field)) for field in fields)] += 1

    def _add_application_values(self, row: Mapping[str, str | None]) -> None:
        event_context = (_group_value(row.get("event_type")), _group_value(row.get("event_action")))
        context_population = self._application_by_event_context.setdefault(
            event_context,
            {field: Counter() for field in APPLICATION_FIELDS},
        )
        for field in APPLICATION_FIELDS:
            raw_value = row.get(field)
            count_name = "missing_count" if _is_missing(raw_value) else "non_missing_count"
            self._application_population[field][count_name] += 1
            context_population[field][count_name] += 1
            if not _is_missing(raw_value):
                self._application_values[field][raw_value] += 1
        for fields, counts in self._application_combinations.items():
            counts[tuple(_group_value(row.get(field)) for field in fields)] += 1

    def _add_threat_values(self, row: Mapping[str, str | None]) -> None:
        threat_present = any(not _is_missing(row.get(field)) for field in THREAT_FIELDS)
        for field in THREAT_FIELDS:
            raw_value = row.get(field)
            count_name = "missing_count" if _is_missing(raw_value) else "non_missing_count"
            self._threat_population[field][count_name] += 1
            if not _is_missing(raw_value):
                self._threat_values[field][raw_value] += 1
            if threat_present:
                self._threat_present_field_population[field][count_name] += 1

        if threat_present:
            self._threat_present_record_count += 1
            context = (
                _group_value(row.get("event_type")),
                _group_value(row.get("event_action")),
                _group_value(row.get("net_proto")),
                _group_value(row.get("app_service")),
            )
            self._threat_context[context] += 1

    def _add_identifier_values(self, row: Mapping[str, str | None]) -> None:
        for field, counts in self._identifier_counts.items():
            raw_value = row.get(field)
            if _is_missing(raw_value):
                self._identifier_missing_counts[field] += 1
            else:
                counts[raw_value] += 1

    def _add_numeric_values(self, row: Mapping[str, str | None]) -> None:
        for field, stats in self._numeric_fields.items():
            stats.add(row.get(field))

    def as_dict(self) -> dict[str, Any]:
        """Return deterministic aggregate semantics, not security conclusions."""

        return {
            "row_count": self.row_count,
            "event_semantics": self._event_result(),
            "application_semantics": self._application_result(),
            "threat_semantics": self._threat_result(),
            "identifier_cardinality": self._identifier_result(),
            "selected_numeric_fields": {
                field: stats.as_dict(self.row_count)
                for field, stats in self._numeric_fields.items()
            },
        }

    def _event_result(self) -> dict[str, Any]:
        return {
            "field_frequencies": {
                field: self._frequency_result(counts, self.row_count)
                for field, counts in self._event_values.items()
            },
            "combinations": [
                self._combination_result(fields, counts, self.row_count)
                for fields, counts in self._event_combinations.items()
            ],
        }

    def _application_result(self) -> dict[str, Any]:
        ordered_contexts = sorted(
            self._application_by_event_context.items(),
            key=lambda item: (-sum(item[1][APPLICATION_FIELDS[0]].values()), item[0]),
        )
        selected_contexts = ordered_contexts[: self.combination_limit]
        contexts = []
        for values, field_counts in selected_contexts:
            context_row_count = sum(field_counts[APPLICATION_FIELDS[0]].values())
            contexts.append(
                {
                    "event_type": values[0],
                    "event_action": values[1],
                    "row_count": context_row_count,
                    "fields": {
                        field: self._population_result(counts, context_row_count)
                        for field, counts in field_counts.items()
                    },
                }
            )
        return {
            "field_population": {
                field: self._population_result(counts, self.row_count)
                for field, counts in self._application_population.items()
            },
            "field_frequencies": {
                field: self._frequency_result(counts, self.row_count)
                for field, counts in self._application_values.items()
            },
            "population_by_event_type_action": {
                "context_limit": self.combination_limit,
                "reported_context_count": len(contexts),
                "omitted_context_count": len(ordered_contexts) - len(contexts),
                "contexts": contexts,
            },
            "field_combinations": [
                self._combination_result(fields, counts, self.row_count)
                for fields, counts in self._application_combinations.items()
            ],
        }

    def _threat_result(self) -> dict[str, Any]:
        return {
            "interpretation": (
                "Threat field values are FortiGate source-product observations; "
                "they are not security ground-truth labels."
            ),
            "threat_present_record_count": self._threat_present_record_count,
            "denominator_row_count": self.row_count,
            "threat_present_percentage_of_rows": _percentage(
                self._threat_present_record_count, self.row_count
            ),
            "field_population": {
                field: self._population_result(counts, self.row_count)
                for field, counts in self._threat_population.items()
            },
            "field_completeness_when_threat_present": {
                field: self._population_result(
                    counts, self._threat_present_record_count
                )
                for field, counts in self._threat_present_field_population.items()
            },
            "field_frequencies": {
                field: self._frequency_result(
                    counts, self._threat_present_record_count
                )
                for field, counts in self._threat_values.items()
            },
            "present_record_context": self._threat_context_result(),
        }

    def _identifier_result(self) -> dict[str, Any]:
        results = {}
        for field, counts in self._identifier_counts.items():
            occurrence_buckets = Counter(
                _identifier_occurrence_bucket(count) for count in counts.values()
            )
            results[field] = {
                "missing_count": self._identifier_missing_counts[field],
                "non_missing_count": sum(counts.values()),
                "unique_value_count": len(counts),
                "repeated_occurrence_count": sum(counts.values()) - len(counts),
                "identifier_values_reported": False,
                "occurrence_distribution": [
                    {
                        "occurrences_per_identifier": label,
                        "identifier_count": occurrence_buckets[label],
                        "percentage_of_unique_identifiers": _percentage(
                            occurrence_buckets[label], len(counts)
                        ),
                    }
                    for label, _, _ in IDENTIFIER_OCCURRENCE_BUCKETS
                    if occurrence_buckets[label]
                ],
            }
        return results

    def _frequency_result(
        self, counts: Counter[str], denominator: int
    ) -> dict[str, Any]:
        ordered_values = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        selected_values = ordered_values[: self.top_value_limit]
        return {
            "non_missing_count": sum(counts.values()),
            "unique_value_count": len(counts),
            "denominator_row_count": denominator,
            "value_limit": self.top_value_limit,
            "reported_value_count": len(selected_values),
            "omitted_value_count": len(ordered_values) - len(selected_values),
            "top_values": [
                {
                    "value": value,
                    "row_count": count,
                    "percentage_of_denominator": _percentage(count, denominator),
                }
                for value, count in selected_values
            ],
        }

    def _population_result(
        self, counts: Counter[str], denominator: int
    ) -> dict[str, Any]:
        return {
            "missing_count": counts["missing_count"],
            "non_missing_count": counts["non_missing_count"],
            "denominator_row_count": denominator,
            "non_missing_percentage_of_denominator": _percentage(
                counts["non_missing_count"], denominator
            ),
        }

    def _combination_result(
        self,
        fields: Sequence[str],
        counts: Counter[tuple[str, ...]],
        denominator: int,
    ) -> dict[str, Any]:
        ordered_common = sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )
        ordered_rare = sorted(counts.items(), key=lambda item: (item[1], item[0]))
        return {
            "fields": list(fields),
            "denominator_row_count": denominator,
            "unique_combination_count": len(counts),
            "common_combination_limit": self.combination_limit,
            "common_combinations": self._combination_values(
                fields, ordered_common[: self.combination_limit], denominator
            ),
            "omitted_common_combination_count": max(
                len(ordered_common) - self.combination_limit, 0
            ),
            "rare_combination_limit": self.rare_combination_limit,
            "rare_combinations": self._combination_values(
                fields, ordered_rare[: self.rare_combination_limit], denominator
            ),
            "omitted_rare_combination_count": max(
                len(ordered_rare) - self.rare_combination_limit, 0
            ),
        }

    def _combination_values(
        self,
        fields: Sequence[str],
        combinations: Sequence[tuple[tuple[str, ...], int]],
        denominator: int,
    ) -> list[dict[str, Any]]:
        return [
            {
                "values": dict(zip(fields, values, strict=True)),
                "row_count": count,
                "percentage_of_denominator": _percentage(count, denominator),
            }
            for values, count in combinations
        ]

    def _threat_context_result(self) -> dict[str, Any]:
        fields = ("event_type", "event_action", "net_proto", "app_service")
        ordered_context = sorted(
            self._threat_context.items(), key=lambda item: (-item[1], item[0])
        )
        selected_context = ordered_context[: self.combination_limit]
        return {
            "fields": list(fields),
            "denominator_threat_present_record_count": self._threat_present_record_count,
            "reported_context_count": len(selected_context),
            "omitted_context_count": len(ordered_context) - len(selected_context),
            "contexts": self._combination_values(
                fields, selected_context, self._threat_present_record_count
            ),
        }
