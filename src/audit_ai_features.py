"""Independent read-only reconciliation for a Stage 1.7 feature bundle."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Sequence

from ai_features.artifact import (
    FEATURE_ARTIFACT_NAME,
    METADATA_ARTIFACT_NAME,
    FeatureArtifactError,
    canonical_json,
    file_identity,
    read_exact_json_object,
    read_feature_rows,
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
    FeatureTransformError,
    RarityMaps,
    build_feature_values,
    extract_feature_observation,
)
from normalization.models import SCHEMA_VERSION


class AIFeatureAuditError(ValueError):
    """Raised when a feature bundle does not reconcile to its normalized input."""


@dataclass(frozen=True)
class AIFeatureAuditSummary:
    """Bounded result for a successful independent feature-bundle audit."""

    row_count: int
    feature_count: int
    reference_row_count: int
    holdout_row_count: int

    def to_dict(self) -> dict[str, int]:
        return {
            "row_count": self.row_count,
            "feature_count": self.feature_count,
            "reference_row_count": self.reference_row_count,
            "holdout_row_count": self.holdout_row_count,
        }


def _require_exact_bundle(bundle: Path) -> tuple[Path, Path]:
    if not bundle.is_dir():
        raise AIFeatureAuditError("Stage 1.7 feature bundle directory does not exist")
    names = {child.name for child in bundle.iterdir()}
    expected = {FEATURE_ARTIFACT_NAME, METADATA_ARTIFACT_NAME}
    if names != expected:
        raise AIFeatureAuditError("Stage 1.7 bundle must contain exactly its two artifact files")
    return bundle / FEATURE_ARTIFACT_NAME, bundle / METADATA_ARTIFACT_NAME


def _increment_maps(
    observation: object,
    source_counts: Counter[tuple[int, int]],
    destination_counts: Counter[tuple[int, int]],
    service_counts: Counter[tuple[int, str]],
    source_denominators: Counter[int],
    destination_denominators: Counter[int],
    service_denominators: Counter[int],
) -> None:
    # The object comes only from extract_feature_observation; explicit attributes
    # keep this audit independent from builder orchestration.
    if observation.partition != REFERENCE_PARTITION:
        return
    protocol = observation.protocol_number
    if observation.source_port is not None:
        source_counts[(protocol, observation.source_port)] += 1
        source_denominators[protocol] += 1
    if observation.destination_port is not None:
        destination_counts[(protocol, observation.destination_port)] += 1
        destination_denominators[protocol] += 1
    if observation.service is not None:
        service_counts[(protocol, observation.service)] += 1
        service_denominators[protocol] += 1


def _recompute_first_pass(input_path: Path) -> tuple[RarityMaps, dict[str, int], dict[str, int], int]:
    source_counts: Counter[tuple[int, int]] = Counter()
    destination_counts: Counter[tuple[int, int]] = Counter()
    service_counts: Counter[tuple[int, str]] = Counter()
    source_denominators: Counter[int] = Counter()
    destination_denominators: Counter[int] = Counter()
    service_denominators: Counter[int] = Counter()
    partition_counts: Counter[str] = Counter()
    groups: dict[str, set[tuple[str, str | int]]] = {
        REFERENCE_PARTITION: set(),
        HOLDOUT_PARTITION: set(),
    }
    session_partitions: dict[str, str] = {}
    identifiers: set[str] = set()
    row_count = 0
    for event in iter_feature_events(input_path):
        observation = extract_feature_observation(event)
        if observation.source_record_id in identifiers:
            raise AIFeatureAuditError("normalized input contains a duplicate source record ID")
        identifiers.add(observation.source_record_id)
        if observation.session_identifier is not None:
            previous = session_partitions.setdefault(
                observation.session_identifier, observation.partition
            )
            if previous != observation.partition:
                raise AIFeatureAuditError("one non-empty session crosses split partitions")
            group = ("session", observation.session_identifier)
        else:
            group = ("record", observation.source_record_number)
        groups[observation.partition].add(group)
        partition_counts[observation.partition] += 1
        row_count += 1
        _increment_maps(
            observation,
            source_counts,
            destination_counts,
            service_counts,
            source_denominators,
            destination_denominators,
            service_denominators,
        )
    if row_count == 0 or not partition_counts[REFERENCE_PARTITION] or not partition_counts[HOLDOUT_PARTITION]:
        raise AIFeatureAuditError("normalized input does not satisfy Stage 1.7 partition requirements")
    return (
        RarityMaps(
            source_port_counts=dict(source_counts),
            destination_port_counts=dict(destination_counts),
            service_counts=dict(service_counts),
            source_port_denominators=dict(source_denominators),
            destination_port_denominators=dict(destination_denominators),
            service_denominators=dict(service_denominators),
        ),
        {
            REFERENCE_PARTITION: partition_counts[REFERENCE_PARTITION],
            HOLDOUT_PARTITION: partition_counts[HOLDOUT_PARTITION],
        },
        {
            REFERENCE_PARTITION: len(groups[REFERENCE_PARTITION]),
            HOLDOUT_PARTITION: len(groups[HOLDOUT_PARTITION]),
        },
        row_count,
    )


def _distribution_payload(
    counters: list[Counter[float]], eligible_counts: list[int] | None = None
) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for index, counter in enumerate(counters):
        item: dict[str, object] = {
            "name": FEATURE_NAMES[index],
            "values": [[value, counter[value]] for value in sorted(counter)],
        }
        if eligible_counts is not None:
            item["eligible_count"] = eligible_counts[index]
        payload.append(item)
    return payload


def _check_metadata_static(metadata: object) -> dict[str, object]:
    if not isinstance(metadata, dict) or set(metadata) != METADATA_FIELDS:
        raise AIFeatureAuditError("metadata does not contain exactly its contract fields")
    if metadata.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise AIFeatureAuditError("metadata has an unsupported feature schema version")
    if metadata.get("evaluation_protocol_version") != EVALUATION_PROTOCOL_VERSION:
        raise AIFeatureAuditError("metadata has an unsupported evaluation protocol version")
    if metadata.get("feature_names") != list(FEATURE_NAMES):
        raise AIFeatureAuditError("metadata feature names do not match the immutable manifest")
    if metadata.get("feature_definitions") != feature_definitions_payload():
        raise AIFeatureAuditError("metadata feature definitions do not match the immutable contract")
    runtime = metadata.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {"python_version"} or not isinstance(runtime["python_version"], str) or not runtime["python_version"]:
        raise AIFeatureAuditError("metadata runtime does not contain a Python version")
    return metadata


def audit_ai_feature_bundle(
    bundle_path: str | Path, normalized_input: str | Path
) -> AIFeatureAuditSummary:
    """Recompute and reconcile every feature row without modifying either input."""

    bundle = Path(bundle_path).resolve()
    input_path = Path(normalized_input).resolve()
    try:
        feature_path, metadata_path = _require_exact_bundle(bundle)
        metadata = _check_metadata_static(
            read_exact_json_object(metadata_path, set(METADATA_FIELDS))
        )
        input_identity = file_identity(input_path)
        expected_input_identity = {
            **input_identity,
            "schema_version": SCHEMA_VERSION,
        }
        if metadata["normalized_input"] != expected_input_identity:
            raise AIFeatureAuditError("metadata normalized-input identity does not reconcile")
        actual_feature_identity = file_identity(feature_path)
        expected_feature_identity = {
            "path": FEATURE_ARTIFACT_NAME,
            "size_bytes": actual_feature_identity["size_bytes"],
            "sha256": actual_feature_identity["sha256"],
        }
        feature_metadata = metadata["feature_artifact"]
        if not isinstance(feature_metadata, dict) or set(feature_metadata) != {
            "path", "size_bytes", "sha256", "row_count"
        }:
            raise AIFeatureAuditError("metadata feature-artifact identity has invalid fields")
        if {key: feature_metadata[key] for key in expected_feature_identity} != expected_feature_identity:
            raise AIFeatureAuditError("metadata feature-artifact identity does not reconcile")
        expected_maps, counts, distinct_groups, expected_row_count = _recompute_first_pass(input_path)
        if metadata["rarity_maps"] != rarity_maps_to_metadata(expected_maps):
            raise AIFeatureAuditError("metadata rarity maps include non-reference or incorrect values")
        if metadata["split"] != {
            "namespace": SPLIT_NAMESPACE,
            "hash_algorithm": SPLIT_HASH_ALGORITHM,
            "bucket_rule": "0..7=REFERENCE;8..9=HOLDOUT",
            "counts": counts,
            "distinct_group_counts": distinct_groups,
        }:
            raise AIFeatureAuditError("metadata split state does not reconcile")
        if feature_metadata["row_count"] != expected_row_count:
            raise AIFeatureAuditError("metadata row count does not reconcile")

        distributions = [Counter() for _ in FEATURE_NAMES]
        eligible_distributions = [Counter() for _ in FEATURE_NAMES]
        eligible_counts = [0 for _ in FEATURE_NAMES]
        actual_rows = read_feature_rows(feature_path)
        expected_events = iter_feature_events(input_path)
        row_count = 0
        sentinel = object()
        for event, actual_row in zip_longest(expected_events, actual_rows, fillvalue=sentinel):
            if event is sentinel or actual_row is sentinel:
                raise AIFeatureAuditError("feature rows do not have a one-to-one normalized-input join")
            observation = extract_feature_observation(event)
            expected_values, eligible = build_feature_values(observation, expected_maps)
            expected_row = FeatureRow(
                source_record_number=observation.source_record_number,
                source_record_id=observation.source_record_id,
                partition=observation.partition,
                values=expected_values,
            )
            if actual_row != expected_row:
                raise AIFeatureAuditError("feature row does not reproduce from normalized input")
            row_count += 1
            if actual_row.partition == REFERENCE_PARTITION:
                for index, value in enumerate(actual_row.values):
                    distributions[index][value] += 1
                    if eligible[index]:
                        eligible_distributions[index][value] += 1
                        eligible_counts[index] += 1
        if row_count != expected_row_count:
            raise AIFeatureAuditError("feature row count does not reconcile")
        if metadata["reference_distributions"] != _distribution_payload(distributions):
            raise AIFeatureAuditError("reference distributions do not reconcile")
        if metadata["eligible_reference_distributions"] != _distribution_payload(
            eligible_distributions, eligible_counts
        ):
            raise AIFeatureAuditError("eligible reference distributions do not reconcile")
        constants = [
            FEATURE_NAMES[index]
            for index, counter in enumerate(distributions)
            if len(counter) == 1
        ]
        if metadata["reference_constant_features"] != constants:
            raise AIFeatureAuditError("reference constant features do not reconcile")
        return AIFeatureAuditSummary(
            row_count=row_count,
            feature_count=len(FEATURE_NAMES),
            reference_row_count=counts[REFERENCE_PARTITION],
            holdout_row_count=counts[HOLDOUT_PARTITION],
        )
    except (
        AIFeatureInputError,
        AIFeatureAuditError,
        FeatureArtifactError,
        FeatureTransformError,
        OSError,
    ) as error:
        if isinstance(error, AIFeatureAuditError):
            raise
        raise AIFeatureAuditError(str(error)) from error


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only audit of a Stage 1.7 feature bundle against normalized JSONL."
    )
    parser.add_argument("--bundle", required=True, help="Stage 1.7 feature bundle directory")
    parser.add_argument("--normalized", required=True, help="Normalized input JSONL path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        summary = audit_ai_feature_bundle(arguments.bundle, arguments.normalized)
    except AIFeatureAuditError as error:
        print(f"Stage 1.7 feature audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
