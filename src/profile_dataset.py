"""Read-only, single-pass profiling for CSV security-log datasets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any


DEFAULT_DATASET = (
    Path(__file__).resolve().parents[1] / "data" / "raw" / "network_log_SAFE.csv"
)

IMPORTANT_CATEGORICAL_FIELDS = (
    "data_parsername",
    "data_sourcetype",
    "event_action",
    "event_severity",
    "event_subtype",
    "event_type",
    "src_geo",
    "dst_geo",
    "src_intf",
    "dst_intf",
    "net_proto",
    "app_cat",
    "app_service",
    "app_name",
    "event_profile",
    "threat_action",
    "threat_name",
    "threat_severity",
    "threat_type",
)

IMPORTANT_NUMERIC_FIELDS = (
    "itime",
    "data_timestamp",
    "dst_port",
    "src_port",
    "src_natport",
    "net_rcvdpkts",
    "net_recvbytes",
    "net_sentbytes",
    "net_sentpkts",
    "net_sessionduration",
    "app_id",
    "threat_id",
    "epid",
    "euid",
)

IMPORTANT_IDENTIFIER_FIELDS = (
    "loguid",
    "net_sessionid",
    "src_ip",
    "dst_ip",
    "host_ip",
)


class DatasetProfileError(ValueError):
    """Raised when a CSV cannot produce a trustworthy profile."""


def _is_missing(value: str) -> bool:
    """Return True for an empty or whitespace-only CSV value."""

    return not value.strip()


def _row_signature(row: Sequence[str]) -> bytes:
    """Create a bounded-memory, collision-resistant signature for one record."""

    digest = hashlib.sha256()
    for value in row:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, byteorder="big"))
        digest.update(encoded)
    return digest.digest()


def _validate_header(columns: list[str]) -> None:
    if not columns or all(_is_missing(column) for column in columns):
        raise DatasetProfileError("CSV header is missing or blank")
    if any(_is_missing(column) for column in columns):
        raise DatasetProfileError("CSV header contains a blank column name")
    if len(set(columns)) != len(columns):
        raise DatasetProfileError("CSV header contains duplicate column names")


def profile_csv(
    path: str | Path,
    *,
    top_n: int = 10,
    categorical_fields: Sequence[str] = IMPORTANT_CATEGORICAL_FIELDS,
    numeric_fields: Sequence[str] = IMPORTANT_NUMERIC_FIELDS,
    identifier_fields: Sequence[str] = IMPORTANT_IDENTIFIER_FIELDS,
) -> dict[str, Any]:
    """Profile a CSV in one pass without changing the source file.

    Missing threat fields and sanitized identifiers are measured as supplied. They
    are not classified as failures. ``data_timestamp`` is treated only as a
    numeric field; no timestamp meaning or unit is inferred.
    """

    if top_n < 1:
        raise ValueError("top_n must be at least 1")

    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise DatasetProfileError(f"CSV file does not exist: {dataset_path}")

    initial_stat = dataset_path.stat()
    if initial_stat.st_size == 0:
        raise DatasetProfileError("CSV file is empty")

    try:
        csv_file = dataset_path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise DatasetProfileError(f"CSV file cannot be opened: {exc}") from exc

    with csv_file:
        reader = csv.reader(csv_file, strict=True)
        try:
            columns = next(reader)
        except StopIteration as exc:
            raise DatasetProfileError("CSV file is empty") from exc
        except csv.Error as exc:
            raise DatasetProfileError(f"CSV header cannot be parsed: {exc}") from exc

        _validate_header(columns)
        column_indexes = {column: index for index, column in enumerate(columns)}

        selected_categories = [
            field for field in categorical_fields if field in column_indexes
        ]
        selected_numerics = [
            field for field in numeric_fields if field in column_indexes
        ]
        selected_identifiers = [
            field for field in identifier_fields if field in column_indexes
        ]

        missing_counts = {column: 0 for column in columns}
        category_counts = {field: Counter() for field in selected_categories}
        numeric_stats: dict[str, dict[str, int | None]] = {
            field: {
                "non_missing_count": 0,
                "valid_numeric_count": 0,
                "conversion_failure_count": 0,
                "min": None,
                "max": None,
            }
            for field in selected_numerics
        }
        identifier_values = {field: set() for field in selected_identifiers}
        identifier_non_missing = {field: 0 for field in selected_identifiers}
        seen_row_signatures: set[bytes] = set()

        row_count = 0
        valid_record_count = 0
        malformed_record_count = 0
        exact_duplicate_row_count = 0

        try:
            for row in reader:
                row_count += 1
                if len(row) != len(columns):
                    malformed_record_count += 1
                    continue

                valid_record_count += 1

                signature = _row_signature(row)
                if signature in seen_row_signatures:
                    exact_duplicate_row_count += 1
                else:
                    seen_row_signatures.add(signature)

                for index, column in enumerate(columns):
                    if _is_missing(row[index]):
                        missing_counts[column] += 1

                for field in selected_categories:
                    value = row[column_indexes[field]]
                    if not _is_missing(value):
                        category_counts[field][value] += 1

                for field in selected_numerics:
                    value = row[column_indexes[field]]
                    if _is_missing(value):
                        continue

                    stats = numeric_stats[field]
                    stats["non_missing_count"] += 1
                    try:
                        numeric_value = int(value)
                    except ValueError:
                        stats["conversion_failure_count"] += 1
                        continue

                    stats["valid_numeric_count"] += 1
                    current_min = stats["min"]
                    current_max = stats["max"]
                    if current_min is None or numeric_value < current_min:
                        stats["min"] = numeric_value
                    if current_max is None or numeric_value > current_max:
                        stats["max"] = numeric_value

                for field in selected_identifiers:
                    value = row[column_indexes[field]]
                    if not _is_missing(value):
                        identifier_non_missing[field] += 1
                        identifier_values[field].add(value)
        except csv.Error as exc:
            raise DatasetProfileError(
                f"CSV parsing failed near physical line {reader.line_num}: {exc}"
            ) from exc
        except UnicodeDecodeError as exc:
            raise DatasetProfileError("CSV is not valid UTF-8 text") from exc

    if row_count == 0:
        raise DatasetProfileError("CSV contains a header but no data rows")
    if valid_record_count == 0:
        raise DatasetProfileError("CSV contains no structurally valid data rows")

    final_stat = dataset_path.stat()
    if (
        final_stat.st_size != initial_stat.st_size
        or final_stat.st_mtime_ns != initial_stat.st_mtime_ns
    ):
        raise DatasetProfileError("CSV changed while it was being profiled")

    missing_values = {
        column: {
            "count": missing_counts[column],
            "percentage": round(
                100 * missing_counts[column] / valid_record_count, 6
            ),
        }
        for column in columns
    }

    categorical_frequencies: dict[str, dict[str, Any]] = {}
    for field in selected_categories:
        counter = category_counts[field]
        non_missing_count = sum(counter.values())
        top_values = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[
            :top_n
        ]
        categorical_frequencies[field] = {
            "non_missing_count": non_missing_count,
            "unique_count": len(counter),
            "top_values": [
                {
                    "value": value,
                    "count": count,
                    "percentage_of_valid_rows": round(
                        100 * count / valid_record_count, 6
                    ),
                }
                for value, count in top_values
            ],
        }

    identifier_cardinality = {}
    for field in selected_identifiers:
        non_missing_count = identifier_non_missing[field]
        unique_count = len(identifier_values[field])
        identifier_cardinality[field] = {
            "non_missing_count": non_missing_count,
            "unique_count": unique_count,
            "repeated_occurrence_count": non_missing_count - unique_count,
        }

    return {
        "source_path": str(dataset_path.resolve()),
        "file_size_bytes": initial_stat.st_size,
        "row_count": row_count,
        "valid_record_count": valid_record_count,
        "malformed_record_count": malformed_record_count,
        "column_count": len(columns),
        "column_names": columns,
        "missing_values": missing_values,
        "categorical_frequencies": categorical_frequencies,
        "numeric_fields": numeric_stats,
        "exact_duplicate_row_count": exact_duplicate_row_count,
        "identifier_cardinality": identifier_cardinality,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dataset",
        nargs="?",
        type=Path,
        default=DEFAULT_DATASET,
        help=f"CSV to profile (default: {DEFAULT_DATASET})",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="maximum number of common values shown per categorical field",
    )
    args = parser.parse_args(argv)

    try:
        profile = profile_csv(args.dataset, top_n=args.top)
    except (DatasetProfileError, OSError, ValueError) as exc:
        parser.exit(status=1, message=f"profile error: {exc}\n")

    print(json.dumps(profile, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
