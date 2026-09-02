"""Safe streaming command-line evaluation for Stage 1.4 detection findings.

This module reads validated normalized JSON Lines records one at a time, applies
the reviewed built-in rule registry, and publishes a new deterministic finding
JSON Lines file only after the complete run succeeds.  It does not read raw CSV
data, add rules, infer attacks, or retain all input records or findings in memory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from detection.engine import DetectionEngineError, evaluate_event
from detection.input import DetectionInputError, iter_normalized_events
from detection.models import (
    ActiveRuleVersion,
    DetectionFinding,
    DetectionRunSummary,
    FindingSample,
)
from detection.rules import ACTIVE_RULES, DetectionRule, RuleRegistryError, validate_rule_registry


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"
_MAX_SAMPLES_PER_RULE = 5


class DetectionRunError(ValueError):
    """Raised for concise, structured detection-run safety failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _resolve_paths(input_path: str | Path, output_path: str | Path) -> tuple[Path, Path]:
    """Resolve and validate the read-only input and new final output paths."""

    resolved_input = Path(input_path).resolve()
    resolved_output = Path(output_path).resolve()
    processed_directory = PROCESSED_DATA_DIRECTORY.resolve()

    if resolved_input == resolved_output:
        raise DetectionRunError(
            "INPUT_OUTPUT_SAME", "Input and output paths must be different."
        )
    if not resolved_input.is_file():
        raise DetectionRunError(
            "INPUT_NOT_FOUND", "Normalized JSON Lines input does not exist."
        )
    if not processed_directory.is_dir():
        raise DetectionRunError(
            "PROCESSED_DIRECTORY_UNAVAILABLE",
            "The processed-data directory is unavailable.",
        )
    if not resolved_output.is_relative_to(processed_directory):
        raise DetectionRunError(
            "OUTPUT_OUTSIDE_PROCESSED",
            "Output path must resolve beneath data/processed.",
        )
    if not resolved_output.parent.is_dir():
        raise DetectionRunError(
            "OUTPUT_PARENT_UNAVAILABLE", "Output parent directory does not exist."
        )
    if resolved_output.exists():
        raise DetectionRunError(
            "OUTPUT_EXISTS", "Final output already exists; overwrite is not supported."
        )
    return resolved_input, resolved_output


def _validated_rules(rules: Sequence[DetectionRule]) -> tuple[DetectionRule, ...]:
    """Return the reviewed, ordered registry or a concise run error."""

    try:
        return validate_rule_registry(rules)
    except RuleRegistryError as error:
        raise DetectionRunError("INVALID_RULE_REGISTRY", str(error)) from error


def _write_json_line(output_file: TextIO, finding: DetectionFinding) -> None:
    """Write one compact, deterministic UTF-8 JSON Lines finding."""

    output_file.write(
        json.dumps(
            finding.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        + "\n"
    )


def _publish_temporary_output(temporary_path: Path, output_path: Path) -> None:
    """Publish a completed temporary file without replacing an existing output.

    The temporary file is created in the final output directory, so creating a
    hard link is an atomic same-filesystem publication step.  Unlike a POSIX
    rename, ``os.link`` fails if another process created the final path first.
    """

    try:
        os.link(temporary_path, output_path)
    except FileExistsError as error:
        raise DetectionRunError(
            "OUTPUT_EXISTS", "Final output already exists; overwrite is not supported."
        ) from error
    except OSError as error:
        raise DetectionRunError(
            "OUTPUT_PUBLISH_FAILED", "Final output could not be published safely."
        ) from error
    temporary_path.unlink()


def evaluate_detection_jsonl(
    input_path: str | Path,
    output_path: str | Path,
    rules: Sequence[DetectionRule],
) -> DetectionRunSummary:
    """Evaluate normalized JSON Lines safely with bounded memory.

    The input is read through the strict detection-side reader.  Final output is
    published by rename only after every input record and rule evaluation succeeds.
    On any failure, this function removes only the temporary file it created.
    """

    resolved_input, resolved_output = _resolve_paths(input_path, output_path)
    active_rules = _validated_rules(rules)
    temporary_path: Path | None = None
    normalized_input_record_count = 0
    evaluated_record_count = 0
    total_finding_count = 0
    unique_matched_source_record_count = 0
    findings_by_rule_id: Counter[str] = Counter()
    findings_by_rule_severity: Counter[str] = Counter()
    sample_findings_by_rule: dict[str, list[FindingSample]] = {}

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=resolved_output.parent,
            prefix=f".{resolved_output.stem}.",
            suffix=".tmp",
            delete=False,
        ) as output_file:
            temporary_path = Path(output_file.name)
            for event in iter_normalized_events(resolved_input):
                normalized_input_record_count += 1
                findings = evaluate_event(event, active_rules)
                evaluated_record_count += 1
                if findings:
                    unique_matched_source_record_count += 1

                for finding in findings:
                    _write_json_line(output_file, finding)
                    total_finding_count += 1
                    findings_by_rule_id[finding.rule.rule_id] += 1
                    findings_by_rule_severity[finding.rule.severity] += 1
                    samples = sample_findings_by_rule.setdefault(
                        finding.rule.rule_id, []
                    )
                    if len(samples) < _MAX_SAMPLES_PER_RULE:
                        samples.append(
                            FindingSample(
                                finding_id=finding.finding_id,
                                source_record_number=(
                                    finding.source_event.source_record_number
                                ),
                            )
                        )

        _publish_temporary_output(temporary_path, resolved_output)
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return DetectionRunSummary(
        input_path=str(resolved_input),
        output_path=str(resolved_output),
        normalized_input_schema_version="1.0",
        normalized_input_record_count=normalized_input_record_count,
        evaluated_record_count=evaluated_record_count,
        invalid_input_count=0,
        total_finding_count=total_finding_count,
        findings_by_rule_id=findings_by_rule_id,
        findings_by_rule_severity=findings_by_rule_severity,
        unique_matched_source_record_count=unique_matched_source_record_count,
        sample_findings_by_rule=sample_findings_by_rule,
        active_rules=tuple(
            ActiveRuleVersion(rule.metadata.rule_id, rule.metadata.version)
            for rule in active_rules
        ),
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate normalized security events with reviewed built-in rules."
    )
    parser.add_argument("--input", required=True, help="Path to normalized JSON Lines")
    parser.add_argument(
        "--output",
        required=True,
        help="New finding JSON Lines path beneath data/processed",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the built-in registry and print only its bounded JSON summary."""

    arguments = _argument_parser().parse_args(argv)
    try:
        summary = evaluate_detection_jsonl(arguments.input, arguments.output, ACTIVE_RULES)
    except (
        DetectionEngineError,
        DetectionInputError,
        DetectionRunError,
        OSError,
    ) as error:
        print(f"detection failed: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            summary.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
