"""Strict streaming reader for Stage 1.3 normalized JSON Lines input.

The reader reconstructs public normalized-event contracts one line at a time.
It does not repair malformed input, read raw CSV data, or evaluate rules.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path

from normalization.models import (
    REQUIRED_EVENT_SECTIONS,
    SCHEMA_VERSION,
    FieldProvenance,
    NormalizationContractError,
    NormalizationIssue,
    NormalizedSecurityEvent,
    SourceRecord,
)
from normalization.validation import validate_normalized_event


class DetectionInputError(ValueError):
    """Raised when normalized JSON Lines input violates the Stage 1.3 contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line_number: int | None = None,
        source_record_number: int | None = None,
    ) -> None:
        self.code = code
        self.line_number = line_number
        self.source_record_number = source_record_number
        super().__init__(message)


def _require_mapping(
    value: object,
    name: str,
    line_number: int,
    source_record_number: int | None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DetectionInputError(
            "INVALID_EVENT_OBJECT",
            f"Normalized event {name} must be a JSON object.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    return value


def _payload_record_number(payload: object) -> int | None:
    """Return a valid source record number when it is available in a payload."""

    if not isinstance(payload, Mapping):
        return None
    source = payload.get("source")
    if not isinstance(source, Mapping):
        return None
    record_number = source.get("record_number")
    if isinstance(record_number, int) and not isinstance(record_number, bool):
        return record_number
    return None


def _reconstruct_event(payload: object, line_number: int) -> NormalizedSecurityEvent:
    """Rebuild one public Stage 1.3 event without silently changing its values."""

    source_record_number = _payload_record_number(payload)
    event_data = _require_mapping(
        payload, "root", line_number, source_record_number
    )
    if set(event_data) != set(REQUIRED_EVENT_SECTIONS):
        raise DetectionInputError(
            "EVENT_SECTION_MISMATCH",
            "Normalized event does not contain exactly the required contract sections.",
            line_number=line_number,
            source_record_number=source_record_number,
        )
    if event_data["schema_version"] != SCHEMA_VERSION:
        raise DetectionInputError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"Normalized event schema_version must be {SCHEMA_VERSION!r}.",
            line_number=line_number,
            source_record_number=source_record_number,
        )

    source = _require_mapping(
        event_data["source"], "source", line_number, source_record_number
    )
    adapter_type = source.get("adapter_type")
    record_number = source.get("record_number")
    if (
        not isinstance(adapter_type, str)
        or not adapter_type.strip()
        or isinstance(record_number, bool)
        or not isinstance(record_number, int)
    ):
        raise DetectionInputError(
            "SOURCE_CONTEXT_INVALID",
            "Normalized event source must retain a non-empty adapter_type and record_number.",
            line_number=line_number,
            source_record_number=source_record_number,
        )

    source_record_data = _require_mapping(
        event_data["source_record"],
        "source_record",
        line_number,
        record_number,
    )
    provenance_data = event_data["provenance"]
    issues_data = event_data["normalization_issues"]
    if not isinstance(provenance_data, list) or not isinstance(issues_data, list):
        raise DetectionInputError(
            "INVALID_AUDIT_SECTIONS",
            "provenance and normalization_issues must be JSON arrays.",
            line_number=line_number,
            source_record_number=record_number,
        )

    try:
        event = NormalizedSecurityEvent(
            schema_version=event_data["schema_version"],
            source=source,
            event=_require_mapping(
                event_data["event"], "event", line_number, record_number
            ),
            time=_require_mapping(
                event_data["time"], "time", line_number, record_number
            ),
            network=_require_mapping(
                event_data["network"], "network", line_number, record_number
            ),
            application=_require_mapping(
                event_data["application"],
                "application",
                line_number,
                record_number,
            ),
            session=_require_mapping(
                event_data["session"], "session", line_number, record_number
            ),
            host=_require_mapping(
                event_data["host"], "host", line_number, record_number
            ),
            threat_observations=_require_mapping(
                event_data["threat_observations"],
                "threat_observations",
                line_number,
                record_number,
            ),
            source_record=SourceRecord(
                source_type=adapter_type,
                record_number=record_number,
                fields=source_record_data,
            ),
            unmapped_fields=_require_mapping(
                event_data["unmapped_fields"],
                "unmapped_fields",
                line_number,
                record_number,
            ),
            provenance=tuple(FieldProvenance(**item) for item in provenance_data),
            normalization_issues=tuple(
                NormalizationIssue(**item) for item in issues_data
            ),
        )
    except (KeyError, TypeError, NormalizationContractError) as error:
        raise DetectionInputError(
            "CONTRACT_RECONSTRUCTION_FAILED",
            "Normalized event cannot be reconstructed under the Stage 1.3 contract.",
            line_number=line_number,
            source_record_number=record_number,
        ) from error

    if event.source_record.record_number != event.source["record_number"]:
        raise DetectionInputError(
            "SOURCE_RECORD_NUMBER_MISMATCH",
            "Normalized source record numbers must agree.",
            line_number=line_number,
            source_record_number=record_number,
        )

    validation_issues = validate_normalized_event(event)
    if validation_issues:
        raise DetectionInputError(
            "NORMALIZED_EVENT_VALIDATION_FAILED",
            "Normalized event fails Stage 1.3 mapping or provenance validation.",
            line_number=line_number,
            source_record_number=record_number,
        )
    return event


def iter_normalized_events(path: str | Path) -> Iterator[NormalizedSecurityEvent]:
    """Yield validated Stage 1.3 events in JSON Lines order.

    The file is opened read-only and only one decoded line and one reconstructed
    event are retained at a time.
    """

    input_path = Path(path)
    if not input_path.is_file():
        raise DetectionInputError(
            "INPUT_NOT_FOUND", "Normalized JSON Lines input does not exist."
        )

    previous_record_number = 0
    try:
        with input_path.open("r", encoding="utf-8", newline="") as input_file:
            for line_number, line in enumerate(input_file, start=1):
                if not line.strip():
                    raise DetectionInputError(
                        "BLANK_JSONL_LINE",
                        "Normalized JSON Lines input contains a blank line.",
                        line_number=line_number,
                    )
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as error:
                    raise DetectionInputError(
                        "INVALID_JSONL",
                        "Normalized JSON Lines input is not valid JSON.",
                        line_number=line_number,
                    ) from error

                event = _reconstruct_event(payload, line_number)
                record_number = event.source_record.record_number
                if record_number <= previous_record_number:
                    raise DetectionInputError(
                        "RECORD_ORDER_INVALID",
                        "Normalized source record numbers must be strictly increasing.",
                        line_number=line_number,
                        source_record_number=record_number,
                    )
                previous_record_number = record_number
                yield event
    except UnicodeDecodeError as error:
        raise DetectionInputError(
            "INVALID_INPUT_UTF8", "Normalized JSON Lines input is not UTF-8 text."
        ) from error
    except OSError as error:
        raise DetectionInputError(
            "INPUT_READ_ERROR", "Normalized JSON Lines input cannot be read."
        ) from error
