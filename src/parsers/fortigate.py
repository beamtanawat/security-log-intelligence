"""Read-only, streaming CSV adapter for verified FortiGate source records.

This checkpoint validates CSV structure and preserves decoded field strings. It
does not map canonical values, convert values, normalize events, or write output.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from normalization.fortigate_mapping import (
    FORTIGATE_FIELD_MAPPINGS,
    validate_fortigate_mapping_specification,
)
from normalization.models import SourceRecord


FORTIGATE_SOURCE_TYPE = "fortigate"
BASELINE_FORTIGATE_FIELDS = tuple(
    mapping.source_field for mapping in FORTIGATE_FIELD_MAPPINGS
)


class FortiGateAdapterError(ValueError):
    """A structured source-file or CSV-structure error from this adapter."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        record_number: int | None = None,
    ) -> None:
        self.code = code
        self.record_number = record_number
        super().__init__(message)


def _file_signature(path: Path) -> tuple[int, int]:
    """Return the size and nanosecond modification time used for change checks."""

    try:
        status = path.stat()
    except FileNotFoundError as error:
        raise FortiGateAdapterError("SOURCE_NOT_FOUND", f"CSV file does not exist: {path}") from error
    except OSError as error:
        raise FortiGateAdapterError("SOURCE_STAT_ERROR", f"Cannot inspect CSV file: {path}") from error
    return status.st_size, status.st_mtime_ns


def _initial_file_signature(path: Path) -> tuple[int, int]:
    """Verify that the source path names a readable file before opening it."""

    if not path.exists():
        raise FortiGateAdapterError("SOURCE_NOT_FOUND", f"CSV file does not exist: {path}")
    if not path.is_file():
        raise FortiGateAdapterError("SOURCE_NOT_FILE", f"CSV path is not a file: {path}")
    return _file_signature(path)


def _ensure_file_unchanged(path: Path, initial_signature: tuple[int, int]) -> None:
    """Reject a run when the input file changes while it is being read."""

    try:
        current_signature = _file_signature(path)
    except FortiGateAdapterError as error:
        raise FortiGateAdapterError(
            "SOURCE_CHANGED",
            f"CSV changed or became unavailable while it was being read: {path}",
        ) from error
    if current_signature != initial_signature:
        raise FortiGateAdapterError(
            "SOURCE_CHANGED",
            f"CSV changed while it was being read: {path}",
        )


def _validate_header(header: list[str]) -> tuple[str, ...]:
    """Validate the complete FortiGate header without changing its order or text."""

    if not header:
        raise FortiGateAdapterError("EMPTY_HEADER", "CSV header is empty")
    if any(not name.strip() for name in header):
        raise FortiGateAdapterError("BLANK_HEADER", "CSV header contains a blank field name")
    if len(set(header)) != len(header):
        raise FortiGateAdapterError(
            "DUPLICATE_HEADER", "CSV header contains duplicate field names"
        )

    missing_fields = [field for field in BASELINE_FORTIGATE_FIELDS if field not in header]
    if missing_fields:
        raise FortiGateAdapterError(
            "MISSING_BASELINE_FIELDS",
            "CSV header is missing required FortiGate fields: "
            + ", ".join(missing_fields),
        )
    return tuple(header)


def iter_fortigate_records(path: str | Path) -> Iterator[SourceRecord]:
    """Yield exact decoded FortiGate source records in input order.

    The adapter reads with ``utf-8-sig`` so a UTF-8 byte-order mark does not become
    part of the first header name. Every valid source row yields one SourceRecord;
    it does not infer types, drop records, or deduplicate session identifiers.
    """

    validate_fortigate_mapping_specification()
    source_path = Path(path)
    initial_signature = _initial_file_signature(source_path)
    record_number = 0

    try:
        with source_path.open("r", encoding="utf-8-sig", newline="") as source_file:
            reader = csv.reader(source_file, strict=True)
            try:
                header = _validate_header(next(reader))
            except StopIteration as error:
                raise FortiGateAdapterError("EMPTY_CSV", "CSV file is empty") from error

            for row in reader:
                _ensure_file_unchanged(source_path, initial_signature)
                record_number += 1
                if len(row) != len(header):
                    raise FortiGateAdapterError(
                        "ROW_WIDTH_MISMATCH",
                        "CSV row width does not match the header width: "
                        f"expected {len(header)}, received {len(row)}",
                        record_number=record_number,
                    )
                yield SourceRecord(
                    source_type=FORTIGATE_SOURCE_TYPE,
                    record_number=record_number,
                    fields=dict(zip(header, row)),
                )
    except UnicodeDecodeError as error:
        raise FortiGateAdapterError(
            "INVALID_UTF8", "CSV file is not valid UTF-8 text"
        ) from error
    except csv.Error as error:
        raise FortiGateAdapterError("CSV_PARSE_ERROR", "CSV parsing failed") from error
    except OSError as error:
        raise FortiGateAdapterError("SOURCE_READ_ERROR", f"Cannot read CSV file: {source_path}") from error

    _ensure_file_unchanged(source_path, initial_signature)
    if record_number == 0:
        raise FortiGateAdapterError(
            "HEADER_ONLY_CSV", "CSV contains a header but no data rows"
        )
