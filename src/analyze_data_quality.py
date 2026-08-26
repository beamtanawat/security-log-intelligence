"""Read-only CLI for Stage 1.2B contextual missingness analysis."""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from data_quality import ContextualMissingnessAccumulator


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "data" / "raw" / "network_log_SAFE.csv"
PROCESSED_DIRECTORY = (PROJECT_ROOT / "data" / "processed").resolve()
RAW_DIRECTORY = (PROJECT_ROOT / "data" / "raw").resolve()


class DataQualityAnalysisError(ValueError):
    """Raised when a CSV cannot be analyzed safely."""


def _validate_header(columns: list[str]) -> None:
    if not columns or any(not column.strip() for column in columns):
        raise DataQualityAnalysisError("CSV header is missing or contains blank names")
    if len(set(columns)) != len(columns):
        raise DataQualityAnalysisError("CSV header contains duplicate column names")


def validate_output_path(path: str | Path) -> Path:
    """Allow explicit analysis output only beneath data/processed/."""

    output_path = Path(path).resolve()
    if output_path.is_relative_to(RAW_DIRECTORY):
        raise DataQualityAnalysisError("analysis output must never be written under data/raw")
    if not output_path.is_relative_to(PROCESSED_DIRECTORY):
        raise DataQualityAnalysisError("analysis output must be located under data/processed")
    return output_path


def analyze_csv(path: str | Path) -> dict[str, Any]:
    """Read a CSV once and return aggregate Stage 1.2B findings."""

    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise DataQualityAnalysisError(f"CSV file does not exist: {dataset_path}")

    initial_stat = dataset_path.stat()
    if initial_stat.st_size == 0:
        raise DataQualityAnalysisError("CSV file is empty")

    record_count = 0
    valid_record_count = 0
    malformed_record_count = 0
    accumulator = ContextualMissingnessAccumulator()

    try:
        with dataset_path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.reader(csv_file, strict=True)
            try:
                columns = next(reader)
            except StopIteration as exc:
                raise DataQualityAnalysisError("CSV file is empty") from exc
            _validate_header(columns)

            for values in reader:
                record_count += 1
                if len(values) != len(columns):
                    malformed_record_count += 1
                    continue
                valid_record_count += 1
                accumulator.add_row(dict(zip(columns, values, strict=True)))
    except csv.Error as exc:
        raise DataQualityAnalysisError(f"CSV parsing failed: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise DataQualityAnalysisError("CSV is not valid UTF-8 text") from exc

    if valid_record_count == 0:
        raise DataQualityAnalysisError("CSV contains no structurally valid data rows")

    final_stat = dataset_path.stat()
    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
    ):
        raise DataQualityAnalysisError("CSV changed while it was being analyzed")

    return {
        "source_path": str(dataset_path.resolve()),
        "file_size_bytes": initial_stat.st_size,
        "row_count": record_count,
        "valid_record_count": valid_record_count,
        "malformed_record_count": malformed_record_count,
        "analysis": accumulator.as_dict(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional JSON output path beneath data/processed/",
    )
    args = parser.parse_args(argv)

    try:
        result = analyze_csv(args.dataset)
        if args.output is not None:
            output_path = validate_output_path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        else:
            print(json.dumps(result, indent=2))
    except (DataQualityAnalysisError, OSError, ValueError) as exc:
        parser.exit(status=1, message=f"analysis error: {exc}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
