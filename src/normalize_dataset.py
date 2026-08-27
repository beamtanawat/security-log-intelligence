"""Streaming FortiGate normalization command-line interface for Stage 1.3E."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Sequence

from normalization.fortigate import (
    FortiGateNormalizationError,
    normalize_fortigate_record,
)
from normalization.fortigate_mapping import FORTIGATE_FIELD_MAPPINGS
from normalization.models import NormalizationRunSummary
from parsers.fortigate import FortiGateAdapterError, iter_fortigate_records


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"
_MAPPINGS_BY_FIELD = {
    mapping.source_field: mapping for mapping in FORTIGATE_FIELD_MAPPINGS
}
_KNOWN_MAPPED_FIELD_COUNT = sum(
    mapping.mapping_category != "PRESERVED_UNMAPPED"
    for mapping in FORTIGATE_FIELD_MAPPINGS
)
_KNOWN_PRESERVED_UNMAPPED_FIELD_COUNT = sum(
    mapping.mapping_category == "PRESERVED_UNMAPPED"
    for mapping in FORTIGATE_FIELD_MAPPINGS
)
_MAX_UNKNOWN_FIELD_NAMES = 20


class NormalizationRunError(ValueError):
    """A concise, structured run or output-path error."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _resolve_paths(input_path: str | Path, output_path: str | Path) -> tuple[Path, Path]:
    """Return checked absolute input and final output paths."""

    resolved_input = Path(input_path).resolve()
    resolved_output = Path(output_path).resolve()
    processed_directory = PROCESSED_DATA_DIRECTORY.resolve()

    if resolved_input == resolved_output:
        raise NormalizationRunError(
            "INPUT_OUTPUT_SAME", "Input and output paths must be different."
        )
    if not processed_directory.is_dir():
        raise NormalizationRunError(
            "PROCESSED_DIRECTORY_UNAVAILABLE",
            f"Processed-data directory is unavailable: {processed_directory}",
        )
    if not resolved_output.is_relative_to(processed_directory):
        raise NormalizationRunError(
            "OUTPUT_OUTSIDE_PROCESSED",
            "Output path must resolve beneath data/processed.",
        )
    if not resolved_output.parent.is_dir():
        raise NormalizationRunError(
            "OUTPUT_PARENT_UNAVAILABLE", "Output parent directory does not exist."
        )
    if resolved_output.exists():
        raise NormalizationRunError(
            "OUTPUT_EXISTS", "Final output already exists; overwrite is not supported."
        )
    return resolved_input, resolved_output


def _write_json_line(output_file: object, value: object) -> None:
    """Write one compact deterministic JSON Lines record."""

    output_file.write(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    )


def normalize_fortigate_csv(
    input_path: str | Path, output_path: str | Path
) -> NormalizationRunSummary:
    """Stream FortiGate records into a new deterministic JSON Lines file.

    The final output is published only after every source record has been read and
    normalized successfully. A failure removes the uniquely named temporary file
    and leaves any existing final file untouched.
    """

    resolved_input, resolved_output = _resolve_paths(input_path, output_path)
    temporary_path: Path | None = None
    input_record_count = 0
    valid_record_count = 0
    output_record_count = 0
    unexpected_source_field_count = 0
    unknown_field_names: set[str] = set()
    issue_counts: Counter[str] = Counter()

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=PROCESSED_DATA_DIRECTORY,
            prefix=f".{resolved_output.stem}.",
            suffix=".tmp",
            delete=False,
        ) as output_file:
            temporary_path = Path(output_file.name)
            for record in iter_fortigate_records(resolved_input):
                input_record_count += 1
                normalized_event = normalize_fortigate_record(record)
                _write_json_line(output_file, normalized_event.to_dict())
                valid_record_count += 1
                output_record_count += 1

                for issue in normalized_event.normalization_issues:
                    issue_counts[issue.issue_code] += 1
                for source_field in record.fields:
                    if source_field not in _MAPPINGS_BY_FIELD:
                        unexpected_source_field_count += 1
                        if len(unknown_field_names) < _MAX_UNKNOWN_FIELD_NAMES:
                            unknown_field_names.add(source_field)

        if resolved_output.exists():
            raise NormalizationRunError(
                "OUTPUT_EXISTS", "Final output already exists; overwrite is not supported."
            )
        temporary_path.rename(resolved_output)
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return NormalizationRunSummary(
        source_type="fortigate",
        input_path=str(resolved_input),
        output_path=str(resolved_output),
        input_record_count=input_record_count,
        valid_record_count=valid_record_count,
        malformed_record_count=0,
        output_record_count=output_record_count,
        mapping_coverage={
            "known_mapped_field_values": _KNOWN_MAPPED_FIELD_COUNT
            * valid_record_count,
            "known_preserved_unmapped_field_values": _KNOWN_PRESERVED_UNMAPPED_FIELD_COUNT
            * valid_record_count,
            "unexpected_source_field_values": unexpected_source_field_count,
        },
        issue_counts=issue_counts,
        unknown_field_names=tuple(sorted(unknown_field_names)),
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stream a FortiGate CSV file to a normalized JSON Lines file."
    )
    parser.add_argument("--source", required=True, help="Supported value: fortigate")
    parser.add_argument("--input", required=True, help="Path to the source CSV file")
    parser.add_argument(
        "--output",
        required=True,
        help="New JSON Lines path beneath data/processed",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the PowerShell-compatible CLI and return a concise process exit code."""

    arguments = _argument_parser().parse_args(argv)
    if arguments.source != "fortigate":
        print("normalization failed: --source must be 'fortigate'", file=sys.stderr)
        return 2

    try:
        summary = normalize_fortigate_csv(arguments.input, arguments.output)
    except (FortiGateAdapterError, FortiGateNormalizationError, NormalizationRunError) as error:
        print(f"normalization failed: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            summary.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
