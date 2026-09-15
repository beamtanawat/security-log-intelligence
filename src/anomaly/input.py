"""Strict Stage 1.7 feature-bundle input boundary for Stage 1.8."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ai_features.artifact import (
    FEATURE_ARTIFACT_NAME,
    METADATA_ARTIFACT_NAME,
    FeatureArtifactError,
    canonical_json,
    file_sha256,
    read_exact_json_object,
    read_feature_rows,
)
from ai_features.contract import (
    EVALUATION_PROTOCOL_VERSION,
    METADATA_FIELDS,
    feature_definitions_payload,
)
from ai_features.models import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    HOLDOUT_PARTITION,
    REFERENCE_PARTITION,
    FeatureRow,
)


EXPECTED_STAGE_1_7_FEATURE_SHA256 = (
    "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1"
)


class AnomalyInputError(ValueError):
    """Raised when an immutable Stage 1.7 feature bundle is incompatible."""


@dataclass(frozen=True)
class FeatureBundle:
    """Validated Stage 1.7 feature rows and immutable upstream identities."""

    directory: Path
    rows: tuple[FeatureRow, ...]
    metadata: Mapping[str, object]
    feature_artifact_identity: Mapping[str, object]
    feature_metadata_identity: Mapping[str, object]
    feature_contract_sha256: str
    reference_count: int
    holdout_count: int


def _identity(path: Path, artifact_name: str) -> dict[str, object]:
    try:
        return {
            "path": artifact_name,
            "size_bytes": path.stat().st_size,
            "sha256": file_sha256(path),
        }
    except (FeatureArtifactError, OSError) as error:
        raise AnomalyInputError("Stage 1.7 artifact identity cannot be read") from error


def _require_exact_object(value: object, expected: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AnomalyInputError(f"{name} does not contain exactly its contract fields")
    return value


def _require_nonnegative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnomalyInputError(f"{name} must be a non-negative integer")
    return value


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise AnomalyInputError(f"{name} must be a SHA-256 hex string")
    try:
        int(value, 16)
    except ValueError as error:
        raise AnomalyInputError(f"{name} must be a SHA-256 hex string") from error
    return value.lower()


def _validate_metadata(
    metadata: Mapping[str, object], feature_identity: Mapping[str, object]
) -> tuple[int, int, int]:
    if metadata.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise AnomalyInputError("Stage 1.7 feature schema version is incompatible")
    if metadata.get("evaluation_protocol_version") != EVALUATION_PROTOCOL_VERSION:
        raise AnomalyInputError("Stage 1.7 evaluation protocol version is incompatible")
    if metadata.get("feature_names") != list(FEATURE_NAMES):
        raise AnomalyInputError("Stage 1.7 feature names/order are incompatible")
    if metadata.get("feature_definitions") != feature_definitions_payload():
        raise AnomalyInputError("Stage 1.7 feature definitions are incompatible")

    normalized_input = _require_exact_object(
        metadata.get("normalized_input"),
        {"path", "size_bytes", "sha256", "schema_version"},
        "Stage 1.7 normalized_input",
    )
    if not isinstance(normalized_input["path"], str) or not normalized_input["path"]:
        raise AnomalyInputError("Stage 1.7 normalized_input path is invalid")
    _require_nonnegative_int(normalized_input["size_bytes"], "normalized input size")
    _require_sha256(normalized_input["sha256"], "normalized input hash")
    if normalized_input["schema_version"] != "1.0":
        raise AnomalyInputError("Stage 1.7 normalized input schema version is incompatible")

    feature_artifact = _require_exact_object(
        metadata.get("feature_artifact"),
        {"path", "size_bytes", "sha256", "row_count"},
        "Stage 1.7 feature_artifact",
    )
    expected_feature_artifact = {
        **feature_identity,
        "row_count": feature_artifact.get("row_count"),
    }
    if feature_artifact != expected_feature_artifact:
        raise AnomalyInputError("Stage 1.7 feature artifact identity is incompatible")
    feature_row_count = _require_nonnegative_int(
        feature_artifact["row_count"], "feature artifact row count"
    )

    split = _require_exact_object(
        metadata.get("split"),
        {
            "namespace",
            "hash_algorithm",
            "bucket_rule",
            "counts",
            "distinct_group_counts",
        },
        "Stage 1.7 split",
    )
    expected_split = {
        "namespace": "stage-1.7-split-v1",
        "hash_algorithm": "sha256-first-8-bytes-unsigned-big-endian-modulo-10",
        "bucket_rule": "0..7=REFERENCE;8..9=HOLDOUT",
    }
    for key, expected in expected_split.items():
        if split[key] != expected:
            raise AnomalyInputError("Stage 1.7 split contract is incompatible")
    counts = _require_exact_object(
        split["counts"], {REFERENCE_PARTITION, HOLDOUT_PARTITION}, "Stage 1.7 split counts"
    )
    reference_count = _require_nonnegative_int(counts[REFERENCE_PARTITION], "reference count")
    holdout_count = _require_nonnegative_int(counts[HOLDOUT_PARTITION], "holdout count")
    return reference_count, holdout_count, feature_row_count


def _feature_contract_sha256(metadata: Mapping[str, object]) -> str:
    """Hash the ordered schema/definition manifest without hashing a file itself."""

    contract = {
        "schema_version": metadata["schema_version"],
        "evaluation_protocol_version": metadata["evaluation_protocol_version"],
        "feature_names": metadata["feature_names"],
        "feature_definitions": metadata["feature_definitions"],
    }
    return hashlib.sha256(canonical_json(contract).encode("utf-8")).hexdigest()


def load_feature_bundle(
    features_dir: str | Path,
    *,
    expected_feature_sha256: str | None = EXPECTED_STAGE_1_7_FEATURE_SHA256,
) -> FeatureBundle:
    """Load exactly one compatible Stage 1.7 feature bundle without fitting.

    Normal execution supplies the approved real Stage 1.7 feature hash.  Tests
    and isolated contract checks may supply a different explicit expected hash.
    """

    supplied_directory = Path(features_dir)
    try:
        if supplied_directory.is_symlink() or not supplied_directory.is_dir():
            raise AnomalyInputError("Stage 1.7 feature directory is unavailable or unsafe")
        directory = supplied_directory.resolve()
        expected_names = {FEATURE_ARTIFACT_NAME, METADATA_ARTIFACT_NAME}
        if {child.name for child in directory.iterdir()} != expected_names:
            raise AnomalyInputError("Stage 1.7 feature bundle must contain exactly two artifacts")
        feature_path = directory / FEATURE_ARTIFACT_NAME
        metadata_path = directory / METADATA_ARTIFACT_NAME
        if feature_path.is_symlink() or metadata_path.is_symlink():
            raise AnomalyInputError("Stage 1.7 feature artifact path is unsafe")
        feature_identity = _identity(feature_path, FEATURE_ARTIFACT_NAME)
        metadata_identity = _identity(metadata_path, METADATA_ARTIFACT_NAME)
        if expected_feature_sha256 is not None:
            expected_hash = _require_sha256(expected_feature_sha256, "expected Stage 1.7 feature hash")
            if feature_identity["sha256"] != expected_hash:
                raise AnomalyInputError("Stage 1.7 feature SHA-256 does not match the approved identity")
        metadata = read_exact_json_object(metadata_path, set(METADATA_FIELDS))
        reference_count, holdout_count, feature_row_count = _validate_metadata(
            metadata, feature_identity
        )
        rows = tuple(read_feature_rows(feature_path))
        if len(rows) != feature_row_count:
            raise AnomalyInputError("Stage 1.7 feature row count does not reconcile")
        actual_reference_count = sum(row.partition == REFERENCE_PARTITION for row in rows)
        actual_holdout_count = sum(row.partition == HOLDOUT_PARTITION for row in rows)
        if (actual_reference_count, actual_holdout_count) != (reference_count, holdout_count):
            raise AnomalyInputError("Stage 1.7 partition counts do not reconcile")
        if reference_count == 0 or holdout_count == 0:
            raise AnomalyInputError("Stage 1.7 requires non-empty REFERENCE and HOLDOUT partitions")
        # Hash a second time after parsing so a mutation cannot be silently
        # accepted between identity validation and model construction.
        if _identity(feature_path, FEATURE_ARTIFACT_NAME) != feature_identity:
            raise AnomalyInputError("Stage 1.7 feature artifact changed while it was read")
        if _identity(metadata_path, METADATA_ARTIFACT_NAME) != metadata_identity:
            raise AnomalyInputError("Stage 1.7 metadata artifact changed while it was read")
        return FeatureBundle(
            directory=directory,
            rows=rows,
            metadata=metadata,
            feature_artifact_identity=feature_identity,
            feature_metadata_identity=metadata_identity,
            feature_contract_sha256=_feature_contract_sha256(metadata),
            reference_count=reference_count,
            holdout_count=holdout_count,
        )
    except (AnomalyInputError, FeatureArtifactError, OSError) as error:
        if isinstance(error, AnomalyInputError):
            raise
        raise AnomalyInputError(str(error)) from error
