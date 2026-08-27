"""Streaming audit for Stage 1.3 normalized JSON Lines output.

This module validates already-written normalized events.  It does not read CSV
input, normalize records, write output, or make security decisions.  The Stage
1.3F PowerShell validator uses it to audit one JSON Lines file without loading
the full file into memory.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from normalization.fortigate_mapping import FORTIGATE_FIELD_MAPPINGS
from normalization.models import (
    REQUIRED_EVENT_SECTIONS,
    FieldProvenance,
    NormalizationContractError,
    NormalizationIssue,
    NormalizedSecurityEvent,
    SourceRecord,
)
from normalization.validation import validate_normalized_event


_MAPPINGS_BY_FIELD = {
    mapping.source_field: mapping for mapping in FORTIGATE_FIELD_MAPPINGS
}
_MAX_UNKNOWN_FIELD_NAMES = 20
_PROHIBITED_DURATION_KEYS = frozenset(
    {"duration_seconds", "duration_milliseconds", "duration_unit"}
)


class NormalizedOutputAuditError(ValueError):
    """Raised when a normalized JSON Lines file violates the Stage 1.3 contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line_number: int | None = None,
    ) -> None:
        self.code = code
        self.line_number = line_number
        super().__init__(message)


@dataclass(frozen=True)
class NormalizedOutputAudit:
    """Bounded aggregate evidence collected from one normalized JSON Lines file."""

    output_record_count: int
    mapping_coverage: Mapping[str, int]
    issue_counts: Mapping[str, int]
    unknown_field_names: Sequence[str]

    def to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-compatible aggregate audit evidence."""

        return {
            "output_record_count": self.output_record_count,
            "mapping_coverage": dict(sorted(self.mapping_coverage.items())),
            "issue_counts": dict(sorted(self.issue_counts.items())),
            "unknown_field_names": list(self.unknown_field_names),
        }


def _require_mapping(value: object, name: str, line_number: int) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise NormalizedOutputAuditError(
            "INVALID_EVENT_OBJECT",
            f"Normalized event {name} must be a JSON object.",
            line_number=line_number,
        )
    return value


def _as_normalized_event(
    payload: object, line_number: int
) -> NormalizedSecurityEvent:
    """Reconstruct one contract value so existing validation remains authoritative."""

    event_data = _require_mapping(payload, "root", line_number)
    if set(event_data) != set(REQUIRED_EVENT_SECTIONS):
        raise NormalizedOutputAuditError(
            "EVENT_SECTION_MISMATCH",
            "Normalized event does not contain exactly the required contract sections.",
            line_number=line_number,
        )

    source = _require_mapping(event_data["source"], "source", line_number)
    source_record_data = _require_mapping(
        event_data["source_record"], "source_record", line_number
    )
    adapter_type = source.get("adapter_type")
    record_number = source.get("record_number")
    if adapter_type != "fortigate" or not isinstance(record_number, int):
        raise NormalizedOutputAuditError(
            "SOURCE_CONTEXT_MISMATCH",
            "Normalized event does not retain the expected FortiGate source context.",
            line_number=line_number,
        )

    try:
        provenance_data = event_data["provenance"]
        issues_data = event_data["normalization_issues"]
        if not isinstance(provenance_data, list) or not isinstance(issues_data, list):
            raise NormalizationContractError(
                "provenance and normalization_issues must be JSON arrays"
            )
        event = NormalizedSecurityEvent(
            schema_version=event_data["schema_version"],
            source=source,
            event=_require_mapping(event_data["event"], "event", line_number),
            time=_require_mapping(event_data["time"], "time", line_number),
            network=_require_mapping(event_data["network"], "network", line_number),
            application=_require_mapping(
                event_data["application"], "application", line_number
            ),
            session=_require_mapping(event_data["session"], "session", line_number),
            host=_require_mapping(event_data["host"], "host", line_number),
            threat_observations=_require_mapping(
                event_data["threat_observations"], "threat_observations", line_number
            ),
            source_record=SourceRecord(
                source_type=adapter_type,
                record_number=record_number,
                fields=source_record_data,
            ),
            unmapped_fields=_require_mapping(
                event_data["unmapped_fields"], "unmapped_fields", line_number
            ),
            provenance=tuple(FieldProvenance(**item) for item in provenance_data),
            normalization_issues=tuple(
                NormalizationIssue(**item) for item in issues_data
            ),
        )
    except (KeyError, TypeError, NormalizationContractError) as error:
        raise NormalizedOutputAuditError(
            "CONTRACT_RECONSTRUCTION_FAILED",
            "Normalized event cannot be reconstructed under the Stage 1.3 contract.",
            line_number=line_number,
        ) from error
    return event


def _validate_stage_boundaries(event: NormalizedSecurityEvent, line_number: int) -> None:
    """Confirm the completed Stage 1.3 uncertainty and preservation boundaries."""

    source_fields = event.source_record.fields
    expected_unmapped_fields = {
        source_field
        for source_field in source_fields
        if source_field not in _MAPPINGS_BY_FIELD
        or _MAPPINGS_BY_FIELD[source_field].mapping_category == "PRESERVED_UNMAPPED"
    }
    if set(event.unmapped_fields) != expected_unmapped_fields:
        raise NormalizedOutputAuditError(
            "UNMAPPED_FIELD_PRESERVATION_MISMATCH",
            "Normalized event does not preserve exactly its unmapped source fields.",
            line_number=line_number,
        )

    if "data_timestamp" in event.time or (
        event.unmapped_fields.get("data_timestamp")
        != source_fields.get("data_timestamp")
    ):
        raise NormalizedOutputAuditError(
            "DATA_TIMESTAMP_BOUNDARY_VIOLATION",
            "data_timestamp must remain preserved and semantically unresolved.",
            line_number=line_number,
        )

    source_itime = source_fields.get("itime")
    canonical_itime = source_itime if source_itime and source_itime.strip() else None
    if event.time.get("itime_raw") != canonical_itime or (
        event.time.get("itime_utc_interpretation_status") != "NEEDS_VERIFICATION"
    ):
        raise NormalizedOutputAuditError(
            "ITIME_BOUNDARY_VIOLATION",
            "itime raw evidence or its required uncertainty status is not preserved.",
            line_number=line_number,
        )

    for source_field, canonical_path in (
        ("src_ip", ("source", "identifier")),
        ("dst_ip", ("destination", "identifier")),
        ("host_ip", ("identifier",)),
    ):
        section: object = event.network if source_field != "host_ip" else event.host
        for path_part in canonical_path:
            if not isinstance(section, Mapping):
                raise NormalizedOutputAuditError(
                    "OPAQUE_IDENTIFIER_PRESERVATION_MISMATCH",
                    "An opaque identifier canonical path is unavailable.",
                    line_number=line_number,
                )
            section = section.get(path_part)
        expected_value = source_fields.get(source_field)
        expected_value = expected_value if expected_value and expected_value.strip() else None
        if section != expected_value:
            raise NormalizedOutputAuditError(
                "OPAQUE_IDENTIFIER_PRESERVATION_MISMATCH",
                "An opaque identifier is not preserved exactly in its canonical role.",
                line_number=line_number,
            )

    if event.session.get("identifier") != source_fields.get("net_sessionid"):
        raise NormalizedOutputAuditError(
            "SESSION_IDENTIFIER_PRESERVATION_MISMATCH",
            "The source session identifier is not preserved in the normalized event.",
            line_number=line_number,
        )
    if any(key in event.session for key in _PROHIBITED_DURATION_KEYS):
        raise NormalizedOutputAuditError(
            "SESSION_DURATION_UNIT_VIOLATION",
            "The normalized event introduces an undocumented session-duration unit.",
            line_number=line_number,
        )

    validation_issues = validate_normalized_event(event)
    if validation_issues:
        raise NormalizedOutputAuditError(
            "MAPPING_OR_PROVENANCE_VALIDATION_FAILED",
            "Normalized event fails the established mapping or provenance validation.",
            line_number=line_number,
        )


def audit_normalized_jsonl(
    path: str | Path, *, expected_record_count: int | None = None
) -> NormalizedOutputAudit:
    """Stream and validate a normalized JSON Lines file without retaining records."""

    output_path = Path(path)
    if not output_path.is_file():
        raise NormalizedOutputAuditError(
            "OUTPUT_NOT_FOUND", "Normalized JSON Lines output does not exist."
        )
    if expected_record_count is not None and expected_record_count < 0:
        raise ValueError("expected_record_count must be non-negative")

    mapping_coverage: Counter[str] = Counter(
        {
            "known_mapped_field_values": 0,
            "known_preserved_unmapped_field_values": 0,
            "unexpected_source_field_values": 0,
        }
    )
    issue_counts: Counter[str] = Counter()
    unknown_field_names: set[str] = set()
    output_record_count = 0

    try:
        with output_path.open("r", encoding="utf-8", newline="") as output_file:
            for line_number, line in enumerate(output_file, start=1):
                if not line.strip():
                    raise NormalizedOutputAuditError(
                        "BLANK_JSONL_LINE",
                        "Normalized JSON Lines output contains a blank line.",
                        line_number=line_number,
                    )
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as error:
                    raise NormalizedOutputAuditError(
                        "INVALID_JSONL", "Normalized JSON Lines output is not valid JSON.",
                        line_number=line_number,
                    ) from error

                event = _as_normalized_event(payload, line_number)
                expected_logical_number = output_record_count + 1
                if event.source["record_number"] != expected_logical_number:
                    raise NormalizedOutputAuditError(
                        "RECORD_ORDER_MISMATCH",
                        "Normalized logical record numbers are not contiguous and ordered.",
                        line_number=line_number,
                    )
                _validate_stage_boundaries(event, line_number)

                output_record_count += 1
                for issue in event.normalization_issues:
                    issue_counts[issue.issue_code] += 1
                for source_field in event.source_record.fields:
                    mapping = _MAPPINGS_BY_FIELD.get(source_field)
                    if mapping is None:
                        mapping_coverage["unexpected_source_field_values"] += 1
                        if len(unknown_field_names) < _MAX_UNKNOWN_FIELD_NAMES:
                            unknown_field_names.add(source_field)
                    elif mapping.mapping_category == "PRESERVED_UNMAPPED":
                        mapping_coverage[
                            "known_preserved_unmapped_field_values"
                        ] += 1
                    else:
                        mapping_coverage["known_mapped_field_values"] += 1
    except UnicodeDecodeError as error:
        raise NormalizedOutputAuditError(
            "INVALID_OUTPUT_UTF8", "Normalized JSON Lines output is not UTF-8 text."
        ) from error
    except OSError as error:
        raise NormalizedOutputAuditError(
            "OUTPUT_READ_ERROR", "Normalized JSON Lines output cannot be read."
        ) from error

    if expected_record_count is not None and output_record_count != expected_record_count:
        raise NormalizedOutputAuditError(
            "OUTPUT_RECORD_COUNT_MISMATCH",
            "Normalized JSON Lines record count does not match the expected count."
        )

    return NormalizedOutputAudit(
        output_record_count=output_record_count,
        mapping_coverage=dict(mapping_coverage),
        issue_counts=dict(issue_counts),
        unknown_field_names=tuple(sorted(unknown_field_names)),
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit one normalized Stage 1.3 JSON Lines output file."
    )
    parser.add_argument("--input", required=True, help="Path to normalized JSON Lines")
    parser.add_argument(
        "--expected-record-count",
        type=int,
        required=True,
        help="Required normalized record count",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the streaming audit and print only its bounded JSON summary."""

    arguments = _argument_parser().parse_args(argv)
    try:
        audit = audit_normalized_jsonl(
            arguments.input, expected_record_count=arguments.expected_record_count
        )
    except (NormalizedOutputAuditError, ValueError) as error:
        print(f"normalized-output audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(audit.to_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
