"""Read-only normalized-input boundary for Stage 1.7."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from detection.input import DetectionInputError, _reconstruct_event
from normalization.models import NormalizedSecurityEvent


class AIFeatureInputError(ValueError):
    """Raised when Stage 1.3 normalized input cannot enter Stage 1.7 safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class _DuplicateJsonKeyError(ValueError):
    """Internal strict-decoder signal for a duplicate JSON object key."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    object_value: dict[str, object] = {}
    for key, value in pairs:
        if key in object_value:
            raise _DuplicateJsonKeyError("JSON object contains a duplicate key")
        object_value[key] = value
    return object_value


def _require_unique_provenance_paths(event: NormalizedSecurityEvent) -> None:
    paths: set[str] = set()
    for item in event.provenance:
        if item.canonical_path in paths:
            raise AIFeatureInputError(
                "DUPLICATE_PROVENANCE_KEY",
                "Normalized JSON Lines input contains a duplicate provenance canonical path.",
            )
        paths.add(item.canonical_path)


def iter_feature_events(path: str | Path) -> Iterator[NormalizedSecurityEvent]:
    """Yield strict Stage 1.3 events without rewriting or repairing input.

    The Stage 1.3 reconstruction and validation logic is reused directly while
    this boundary additionally rejects duplicate JSON keys before Python can
    silently overwrite one.  At most one decoded line/event is retained.
    """

    input_path = Path(path)
    if not input_path.is_file():
        raise AIFeatureInputError("INPUT_NOT_FOUND", "Normalized JSON Lines input does not exist.")
    previous_record_number = 0
    try:
        with input_path.open("r", encoding="utf-8", newline="") as input_file:
            for line_number, line in enumerate(input_file, start=1):
                if not line.strip():
                    raise AIFeatureInputError(
                        "BLANK_JSONL_LINE", "Normalized JSON Lines input contains a blank line."
                    )
                try:
                    payload = json.loads(line, object_pairs_hook=_strict_json_object)
                except _DuplicateJsonKeyError as error:
                    raise AIFeatureInputError(
                        "DUPLICATE_JSON_KEY", "Normalized JSON Lines input contains a duplicate JSON key."
                    ) from error
                except json.JSONDecodeError as error:
                    raise AIFeatureInputError(
                        "INVALID_JSONL", "Normalized JSON Lines input is not valid JSON."
                    ) from error
                event = _reconstruct_event(payload, line_number)
                _require_unique_provenance_paths(event)
                record_number = event.source_record.record_number
                if record_number <= previous_record_number:
                    raise AIFeatureInputError(
                        "RECORD_ORDER_INVALID",
                        "Normalized source record numbers must be strictly increasing.",
                    )
                previous_record_number = record_number
                yield event
    except DetectionInputError as error:
        raise AIFeatureInputError(error.code, str(error)) from error
    except UnicodeDecodeError as error:
        raise AIFeatureInputError("INVALID_INPUT_UTF8", "Normalized JSON Lines input is not UTF-8 text.") from error
    except OSError as error:
        raise AIFeatureInputError("INPUT_READ_ERROR", "Normalized JSON Lines input cannot be read.") from error
