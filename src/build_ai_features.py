"""Build one deterministic, leakage-safe Stage 1.7 feature bundle.

The command consumes only Stage 1.3 normalized JSONL and writes a standalone
two-file artifact beneath ``data/processed``.  It does not train or score a
model and it never reads raw CSV, Stage 1.4 findings, or SQLite data.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import audit_ai_features
from ai_features.artifact import (
    FEATURE_ARTIFACT_NAME,
    METADATA_ARTIFACT_NAME,
    FeatureArtifactError,
    canonical_json,
    file_identity,
    write_feature_row,
)
from ai_features.contract import (
    EVALUATION_PROTOCOL_VERSION,
    METADATA_FIELDS,
    feature_definitions_payload,
    rarity_maps_to_metadata,
)
from ai_features.input import AIFeatureInputError, iter_feature_events
from ai_features.models import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    HOLDOUT_PARTITION,
    REFERENCE_PARTITION,
    FeatureRow,
)
from ai_features.transform import (
    SPLIT_HASH_ALGORITHM,
    SPLIT_NAMESPACE,
    FeatureObservation,
    FeatureTransformError,
    RarityMaps,
    build_feature_values,
    extract_feature_observation,
)
from normalization.models import SCHEMA_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DATA_DIRECTORY = PROJECT_ROOT / "data" / "processed"


class AIFeatureBuildError(ValueError):
    """Raised when a Stage 1.7 bundle cannot be safely built."""


@dataclass(frozen=True)
class AIFeatureBuildSummary:
    """Bounded result for a successful Stage 1.7 build."""

    bundle_path: str
    row_count: int
    reference_row_count: int
    holdout_row_count: int
    feature_count: int
    feature_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "row_count": self.row_count,
            "reference_row_count": self.reference_row_count,
            "holdout_row_count": self.holdout_row_count,
            "feature_count": self.feature_count,
            "feature_sha256": self.feature_sha256,
        }


def _resolve_paths(input_path: str | Path, output_dir: str | Path) -> tuple[Path, Path]:
    resolved_input = Path(input_path).resolve()
    resolved_output = Path(output_dir).resolve()
    processed_directory = PROCESSED_DATA_DIRECTORY.resolve()
    if not resolved_input.is_file():
        raise AIFeatureBuildError("normalized input JSONL does not exist")
    if resolved_input == resolved_output:
        raise AIFeatureBuildError("input and output paths must be different")
    if not processed_directory.is_dir():
        raise AIFeatureBuildError("data/processed is unavailable")
    if not resolved_output.is_relative_to(processed_directory):
        raise AIFeatureBuildError("output directory must resolve beneath data/processed")
    if not resolved_output.parent.is_dir():
        raise AIFeatureBuildError("output directory parent does not exist")
    if resolved_output.exists():
        raise AIFeatureBuildError("final output directory already exists; overwrite is not supported")
    return resolved_input, resolved_output


def _empty_distribution_counters() -> list[Counter[float]]:
    return [Counter() for _ in FEATURE_NAMES]


def _increment_rarity_maps(
    observation: FeatureObservation,
    source_port_counts: Counter[tuple[int, int]],
    destination_port_counts: Counter[tuple[int, int]],
    service_counts: Counter[tuple[int, str]],
    source_port_denominators: Counter[int],
    destination_port_denominators: Counter[int],
    service_denominators: Counter[int],
) -> None:
    if observation.partition != REFERENCE_PARTITION:
        return
    protocol = observation.protocol_number
    if observation.source_port is not None:
        source_port_counts[(protocol, observation.source_port)] += 1
        source_port_denominators[protocol] += 1
    if observation.destination_port is not None:
        destination_port_counts[(protocol, observation.destination_port)] += 1
        destination_port_denominators[protocol] += 1
    if observation.service is not None:
        service_counts[(protocol, observation.service)] += 1
        service_denominators[protocol] += 1


def _pass_one(input_path: Path) -> tuple[RarityMaps, dict[str, int], dict[str, int], int]:
    """Stream input once for split invariants and reference-only rarity maps."""

    source_ports: Counter[tuple[int, int]] = Counter()
    destination_ports: Counter[tuple[int, int]] = Counter()
    services: Counter[tuple[int, str]] = Counter()
    source_denominators: Counter[int] = Counter()
    destination_denominators: Counter[int] = Counter()
    service_denominators: Counter[int] = Counter()
    partition_counts: Counter[str] = Counter()
    distinct_groups: dict[str, set[tuple[str, str | int]]] = {
        REFERENCE_PARTITION: set(),
        HOLDOUT_PARTITION: set(),
    }
    session_partitions: dict[str, str] = {}
    source_record_ids: set[str] = set()
    row_count = 0

    for event in iter_feature_events(input_path):
        observation = extract_feature_observation(event)
        if observation.source_record_id in source_record_ids:
            raise AIFeatureBuildError("normalized input contains a duplicate source record ID")
        source_record_ids.add(observation.source_record_id)
        if observation.session_identifier is not None:
            previous_partition = session_partitions.setdefault(
                observation.session_identifier, observation.partition
            )
            if previous_partition != observation.partition:
                raise AIFeatureBuildError("one non-empty session crosses split partitions")
            group = ("session", observation.session_identifier)
        else:
            group = ("record", observation.source_record_number)
        distinct_groups[observation.partition].add(group)
        partition_counts[observation.partition] += 1
        row_count += 1
        _increment_rarity_maps(
            observation,
            source_ports,
            destination_ports,
            services,
            source_denominators,
            destination_denominators,
            service_denominators,
        )

    if row_count == 0:
        raise AIFeatureBuildError("normalized input contains no records")
    if not partition_counts[REFERENCE_PARTITION] or not partition_counts[HOLDOUT_PARTITION]:
        raise AIFeatureBuildError("both REFERENCE and HOLDOUT partitions must be non-empty")
    return (
        RarityMaps(
            source_port_counts=dict(source_ports),
            destination_port_counts=dict(destination_ports),
            service_counts=dict(services),
            source_port_denominators=dict(source_denominators),
            destination_port_denominators=dict(destination_denominators),
            service_denominators=dict(service_denominators),
        ),
        {
            REFERENCE_PARTITION: partition_counts[REFERENCE_PARTITION],
            HOLDOUT_PARTITION: partition_counts[HOLDOUT_PARTITION],
        },
        {
            REFERENCE_PARTITION: len(distinct_groups[REFERENCE_PARTITION]),
            HOLDOUT_PARTITION: len(distinct_groups[HOLDOUT_PARTITION]),
        },
        row_count,
    )


def _distribution_metadata(counters: Iterable[Counter[float]], eligible_counts: list[int] | None = None) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for index, counter in enumerate(counters):
        item: dict[str, object] = {
            "name": FEATURE_NAMES[index],
            "values": [[value, counter[value]] for value in sorted(counter)],
        }
        if eligible_counts is not None:
            item["eligible_count"] = eligible_counts[index]
        output.append(item)
    return output


def _metadata(
    input_identity: dict[str, object],
    feature_identity: dict[str, object],
    row_count: int,
    partition_counts: dict[str, int],
    distinct_group_counts: dict[str, int],
    rarity_maps: RarityMaps,
    distributions: list[Counter[float]],
    eligible_distributions: list[Counter[float]],
    eligible_counts: list[int],
) -> dict[str, object]:
    constants = [
        FEATURE_NAMES[index]
        for index, counter in enumerate(distributions)
        if len(counter) == 1
    ]
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "normalized_input": {
            **input_identity,
            "schema_version": SCHEMA_VERSION,
        },
        "feature_artifact": {
            "path": FEATURE_ARTIFACT_NAME,
            "size_bytes": feature_identity["size_bytes"],
            "sha256": feature_identity["sha256"],
            "row_count": row_count,
        },
        "feature_names": list(FEATURE_NAMES),
        "feature_definitions": feature_definitions_payload(),
        "split": {
            "namespace": SPLIT_NAMESPACE,
            "hash_algorithm": SPLIT_HASH_ALGORITHM,
            "bucket_rule": "0..7=REFERENCE;8..9=HOLDOUT",
            "counts": partition_counts,
            "distinct_group_counts": distinct_group_counts,
        },
        "rarity_maps": rarity_maps_to_metadata(rarity_maps),
        "reference_distributions": _distribution_metadata(distributions),
        "reference_constant_features": constants,
        "eligible_reference_distributions": _distribution_metadata(
            eligible_distributions, eligible_counts
        ),
        "runtime": {"python_version": sys.version},
        "evaluation_protocol_version": EVALUATION_PROTOCOL_VERSION,
    }


def _write_metadata(path: Path, metadata: dict[str, object]) -> None:
    if set(metadata) != METADATA_FIELDS:
        raise AIFeatureBuildError("generated metadata does not contain exactly its contract fields")
    path.write_text(canonical_json(metadata) + "\n", encoding="utf-8", newline="\n")


def build_ai_feature_bundle(
    input_path: str | Path, output_dir: str | Path
) -> AIFeatureBuildSummary:
    """Publish a complete new Stage 1.7 bundle only after two safe passes.

    Pass one derives REFERENCE-only maps.  Pass two creates rows and reference
    distributions.  No event list, raw record, or holdout-derived fitting state
    is retained in memory.
    """

    resolved_input, resolved_output = _resolve_paths(input_path, output_dir)
    try:
        input_identity_before = file_identity(resolved_input)
        rarity_maps, partition_counts, distinct_group_counts, row_count = _pass_one(
            resolved_input
        )
        temporary_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{resolved_output.name}.", suffix=".tmp", dir=resolved_output.parent
            )
        )
    except (AIFeatureInputError, FeatureArtifactError, FeatureTransformError, OSError) as error:
        raise AIFeatureBuildError(str(error)) from error

    published = False
    try:
        feature_path = temporary_dir / FEATURE_ARTIFACT_NAME
        distributions = _empty_distribution_counters()
        eligible_distributions = _empty_distribution_counters()
        eligible_counts = [0 for _ in FEATURE_NAMES]
        source_record_ids: set[str] = set()
        second_pass_rows = 0
        with feature_path.open("w", encoding="utf-8", newline="\n") as feature_file:
            for event in iter_feature_events(resolved_input):
                observation = extract_feature_observation(event)
                if observation.source_record_id in source_record_ids:
                    raise AIFeatureBuildError("normalized input contains a duplicate source record ID")
                source_record_ids.add(observation.source_record_id)
                values, eligible = build_feature_values(observation, rarity_maps)
                row = FeatureRow(
                    source_record_number=observation.source_record_number,
                    source_record_id=observation.source_record_id,
                    partition=observation.partition,
                    values=values,
                )
                write_feature_row(feature_file, row)
                second_pass_rows += 1
                if row.partition == REFERENCE_PARTITION:
                    for index, value in enumerate(values):
                        distributions[index][value] += 1
                        if eligible[index]:
                            eligible_distributions[index][value] += 1
                            eligible_counts[index] += 1
        if second_pass_rows != row_count:
            raise AIFeatureBuildError("normalized input changed while feature bundle was built")
        input_identity_after = file_identity(resolved_input)
        if input_identity_after != input_identity_before:
            raise AIFeatureBuildError("normalized input changed while feature bundle was built")
        feature_identity = file_identity(feature_path)
        metadata = _metadata(
            input_identity_before,
            feature_identity,
            row_count,
            partition_counts,
            distinct_group_counts,
            rarity_maps,
            distributions,
            eligible_distributions,
            eligible_counts,
        )
        _write_metadata(temporary_dir / METADATA_ARTIFACT_NAME, metadata)
        try:
            audit_ai_features.audit_ai_feature_bundle(temporary_dir, resolved_input)
        except audit_ai_features.AIFeatureAuditError as error:
            raise AIFeatureBuildError(
                "completed temporary feature bundle failed its pre-publication audit"
            ) from error
        if resolved_output.exists():
            raise AIFeatureBuildError("final output directory appeared during build")
        # Windows' MoveFile-based rename refuses an existing destination.  The
        # approved local execution environment is Windows; fail closed rather
        # than silently accepting POSIX replacement semantics for directories.
        if os.name != "nt":
            raise AIFeatureBuildError(
                "atomic no-replace directory publication is unavailable on this platform"
            )
        try:
            os.rename(temporary_dir, resolved_output)
        except FileExistsError as error:
            raise AIFeatureBuildError("final output directory appeared during build") from error
        published = True
        return AIFeatureBuildSummary(
            bundle_path=str(resolved_output),
            row_count=row_count,
            reference_row_count=partition_counts[REFERENCE_PARTITION],
            holdout_row_count=partition_counts[HOLDOUT_PARTITION],
            feature_count=len(FEATURE_NAMES),
            feature_sha256=str(feature_identity["sha256"]),
        )
    except (AIFeatureInputError, FeatureArtifactError, FeatureTransformError, OSError) as error:
        raise AIFeatureBuildError(str(error)) from error
    finally:
        if not published and temporary_dir.exists():
            shutil.rmtree(temporary_dir)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Stage 1.7 AI feature bundle from normalized JSONL."
    )
    parser.add_argument("--input", required=True, help="Stage 1.3 normalized JSONL path")
    parser.add_argument(
        "--output-dir", required=True, help="New output directory beneath data/processed"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        summary = build_ai_feature_bundle(arguments.input, arguments.output_dir)
    except AIFeatureBuildError as error:
        print(f"Stage 1.7 feature build failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
