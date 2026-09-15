"""Strict Stage 1.8 anomaly-artifact serialization and trusted model loading."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final

import joblib

from ai_features.artifact import FeatureArtifactError, canonical_json, file_sha256
from ai_features.models import FEATURE_NAMES

from .models import (
    MANIFEST_SCHEMA_VERSION,
    MODEL_KIND,
    PRIMARY_RANDOM_STATE,
    RANKING_SEMANTICS_VERSION,
    SCORE_SEMANTICS_VERSION,
    TRAINING_PARTITION,
    AnomalyContractError,
    AnomalyScoreRow,
    collect_runtime_versions,
    model_config_payload,
    validate_runtime_versions,
)


MODEL_ARTIFACT_NAME: Final = "stage_1_8_isolation_forest.joblib"
SCORE_ARTIFACT_NAME: Final = "stage_1_8_anomaly_scores.jsonl"
MODEL_METADATA_ARTIFACT_NAME: Final = "stage_1_8_model_metadata.json"
MANIFEST_ARTIFACT_NAME: Final = "stage_1_8_manifest.json"
ANOMALY_ARTIFACT_NAMES: Final = frozenset(
    {
        MODEL_ARTIFACT_NAME,
        SCORE_ARTIFACT_NAME,
        MODEL_METADATA_ARTIFACT_NAME,
        MANIFEST_ARTIFACT_NAME,
    }
)

MODEL_METADATA_FIELDS: Final = frozenset(
    {
        "schema_version",
        "model_kind",
        "model_config",
        "feature_metadata_identity",
        "feature_artifact_identity",
        "normalized_input_identity",
        "feature_names",
        "matrix_dtype",
        "reference_count",
        "holdout_count",
        "score_semantics_version",
        "reference_raw_score_distribution",
        "score_artifact_identity",
        "model_artifact_identity",
        "dependency_versions",
        "partition_diagnostics",
        "determinism_result",
        "seed_sensitivity",
        "ranking_semantics_version",
    }
)
MANIFEST_FIELDS: Final = frozenset(
    {
        "schema_version",
        "stage_1_7_feature_sha256",
        "stage_1_7_feature_count",
        "reference_row_count",
        "holdout_row_count",
        "feature_names",
        "feature_contract_sha256",
        "model_kind",
        "model_config",
        "random_state",
        "training_partition",
        "runtime_versions",
        "model_artifact_sha256",
        "model_metadata_sha256",
        "score_artifact_sha256",
        "score_semantics_version",
        "ranking_semantics_version",
    }
)


class AnomalyArtifactError(ValueError):
    """Raised when a Stage 1.8 artifact is unsafe, malformed, or incompatible."""


class _DuplicateJsonKeyError(ValueError):
    """Internal strict-JSON decoder signal."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError("JSON object contains a duplicate key")
        value[key] = item
    return value


def _require_exact_object(value: object, expected: frozenset[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AnomalyArtifactError(f"{name} does not contain exactly its contract fields")
    return value


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise AnomalyArtifactError(f"{name} must be a SHA-256 hex string")
    try:
        int(value, 16)
    except ValueError as error:
        raise AnomalyArtifactError(f"{name} must be a SHA-256 hex string") from error
    return value.lower()


def _require_positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AnomalyArtifactError(f"{name} must be a positive integer")
    return value


def read_exact_json_object(path: str | Path, expected_fields: frozenset[str]) -> Mapping[str, object]:
    """Read one exact UTF-8 JSON object with duplicate-key rejection."""

    object_path = Path(path)
    if not object_path.is_file() or object_path.is_symlink():
        raise AnomalyArtifactError("JSON artifact path is unavailable or unsafe")
    try:
        with object_path.open("r", encoding="utf-8", newline="") as handle:
            value = json.load(handle, object_pairs_hook=_strict_json_object)
    except (OSError, UnicodeDecodeError, _DuplicateJsonKeyError, json.JSONDecodeError) as error:
        raise AnomalyArtifactError("JSON artifact cannot be read as strict UTF-8 JSON") from error
    return _require_exact_object(value, expected_fields, "JSON artifact")


def artifact_identity(path: str | Path, artifact_name: str, *, row_count: int | None = None) -> dict[str, object]:
    """Return a relative-path identity for a completed artifact."""

    artifact_path = Path(path)
    if artifact_path.name != artifact_name or artifact_path.is_symlink():
        raise AnomalyArtifactError("artifact path is unsafe or has an unexpected name")
    try:
        identity: dict[str, object] = {
            "path": artifact_name,
            "size_bytes": artifact_path.stat().st_size,
            "sha256": file_sha256(artifact_path),
        }
    except (FeatureArtifactError, OSError) as error:
        raise AnomalyArtifactError("artifact identity cannot be read") from error
    if row_count is not None:
        identity["row_count"] = _require_positive_int(row_count, "artifact row count")
    return identity


def write_score_row(output_file: object, row: AnomalyScoreRow) -> None:
    """Append one canonical score row in immutable source-record order."""

    output_file.write(canonical_json(row.to_dict()) + "\n")


def read_score_rows(path: str | Path) -> Iterator[AnomalyScoreRow]:
    """Yield exact score rows with strict JSON, order, and provenance validation."""

    score_path = Path(path)
    if not score_path.is_file() or score_path.is_symlink():
        raise AnomalyArtifactError("score JSONL artifact path is unavailable or unsafe")
    previous_record_number = 0
    identifiers: set[str] = set()
    try:
        with score_path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise AnomalyArtifactError("score JSONL contains a blank line")
                try:
                    payload = json.loads(line, object_pairs_hook=_strict_json_object)
                    row = AnomalyScoreRow.from_dict(payload)
                except (_DuplicateJsonKeyError, json.JSONDecodeError, AnomalyContractError) as error:
                    raise AnomalyArtifactError(
                        f"score JSONL row {line_number} violates the score contract"
                    ) from error
                if row.source_record_number <= previous_record_number:
                    raise AnomalyArtifactError("score rows are not in source-record order")
                if row.source_record_id in identifiers:
                    raise AnomalyArtifactError("score rows contain a duplicate source record ID")
                previous_record_number = row.source_record_number
                identifiers.add(row.source_record_id)
                yield row
    except UnicodeDecodeError as error:
        raise AnomalyArtifactError("score JSONL is not valid UTF-8") from error
    except OSError as error:
        raise AnomalyArtifactError("score JSONL cannot be read") from error


def build_manifest_payload(
    *,
    feature_sha256: str,
    feature_count: int,
    reference_count: int,
    holdout_count: int,
    feature_contract_sha256: str,
    model_artifact_sha256: str,
    model_metadata_sha256: str,
    score_artifact_sha256: str,
    runtime_versions: Mapping[str, object],
) -> dict[str, object]:
    """Build the non-self-referential Stage 1.8 trust manifest payload."""

    validated_versions = validate_runtime_versions(runtime_versions)
    payload: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "stage_1_7_feature_sha256": _require_sha256(feature_sha256, "feature hash"),
        "stage_1_7_feature_count": _require_positive_int(feature_count, "feature count"),
        "reference_row_count": _require_positive_int(reference_count, "reference row count"),
        "holdout_row_count": _require_positive_int(holdout_count, "holdout row count"),
        "feature_names": list(FEATURE_NAMES),
        "feature_contract_sha256": _require_sha256(
            feature_contract_sha256, "feature contract hash"
        ),
        "model_kind": MODEL_KIND,
        "model_config": model_config_payload(),
        "random_state": PRIMARY_RANDOM_STATE,
        "training_partition": TRAINING_PARTITION,
        "runtime_versions": validated_versions,
        "model_artifact_sha256": _require_sha256(model_artifact_sha256, "model hash"),
        "model_metadata_sha256": _require_sha256(
            model_metadata_sha256, "model metadata hash"
        ),
        "score_artifact_sha256": _require_sha256(score_artifact_sha256, "score hash"),
        "score_semantics_version": SCORE_SEMANTICS_VERSION,
        "ranking_semantics_version": RANKING_SEMANTICS_VERSION,
    }
    _require_exact_object(payload, MANIFEST_FIELDS, "generated manifest")
    return payload


def write_manifest(path: str | Path, payload: Mapping[str, object]) -> None:
    """Write one canonical manifest after exact schema validation."""

    _validate_manifest(payload)
    manifest_path = Path(path)
    if manifest_path.name != MANIFEST_ARTIFACT_NAME or manifest_path.is_symlink():
        raise AnomalyArtifactError("manifest path is unsafe or has an unexpected name")
    try:
        manifest_path.write_text(canonical_json(dict(payload)) + "\n", encoding="utf-8", newline="\n")
    except OSError as error:
        raise AnomalyArtifactError("manifest cannot be written") from error


def _validate_manifest(value: Mapping[str, object]) -> Mapping[str, object]:
    manifest = _require_exact_object(value, MANIFEST_FIELDS, "manifest")
    if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise AnomalyArtifactError("manifest schema version is incompatible")
    _require_sha256(manifest["stage_1_7_feature_sha256"], "manifest feature hash")
    if _require_positive_int(manifest["stage_1_7_feature_count"], "manifest feature count") != len(FEATURE_NAMES):
        raise AnomalyArtifactError("manifest feature count is incompatible")
    _require_positive_int(manifest["reference_row_count"], "manifest reference count")
    _require_positive_int(manifest["holdout_row_count"], "manifest holdout count")
    if manifest["feature_names"] != list(FEATURE_NAMES):
        raise AnomalyArtifactError("manifest feature names/order are incompatible")
    _require_sha256(manifest["feature_contract_sha256"], "manifest feature contract hash")
    if manifest["model_kind"] != MODEL_KIND:
        raise AnomalyArtifactError("manifest model type is incompatible")
    if manifest["model_config"] != model_config_payload():
        raise AnomalyArtifactError("manifest model configuration is incompatible")
    if manifest["random_state"] != PRIMARY_RANDOM_STATE:
        raise AnomalyArtifactError("manifest random state is incompatible")
    if manifest["training_partition"] != TRAINING_PARTITION:
        raise AnomalyArtifactError("manifest training partition is incompatible")
    try:
        validate_runtime_versions(manifest["runtime_versions"])
    except AnomalyContractError as error:
        raise AnomalyArtifactError("manifest runtime versions are incompatible") from error
    for field in (
        "model_artifact_sha256",
        "model_metadata_sha256",
        "score_artifact_sha256",
    ):
        _require_sha256(manifest[field], field)
    if manifest["score_semantics_version"] != SCORE_SEMANTICS_VERSION:
        raise AnomalyArtifactError("manifest score contract is incompatible")
    if manifest["ranking_semantics_version"] != RANKING_SEMANTICS_VERSION:
        raise AnomalyArtifactError("manifest ranking contract is incompatible")
    return manifest


def read_manifest(path: str | Path) -> Mapping[str, object]:
    """Read and validate the static manifest before it is trusted for loading."""

    return _validate_manifest(read_exact_json_object(path, MANIFEST_FIELDS))


def _trusted_bundle_paths(bundle_path: str | Path) -> tuple[Path, dict[str, Path]]:
    supplied = Path(bundle_path)
    if supplied.is_symlink() or not supplied.is_dir():
        raise AnomalyArtifactError("Stage 1.8 bundle directory is unavailable or unsafe")
    bundle = supplied.resolve()
    processed_root = (Path(__file__).resolve().parents[2] / "data" / "processed").resolve()
    if bundle == processed_root or processed_root not in bundle.parents:
        raise AnomalyArtifactError("trusted model bundle must be beneath data/processed")
    try:
        if {item.name for item in bundle.iterdir()} != ANOMALY_ARTIFACT_NAMES:
            raise AnomalyArtifactError("Stage 1.8 bundle must contain exactly its four artifacts")
    except OSError as error:
        raise AnomalyArtifactError("Stage 1.8 bundle cannot be inspected") from error
    paths = {name: bundle / name for name in ANOMALY_ARTIFACT_NAMES}
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        raise AnomalyArtifactError("Stage 1.8 bundle contains an unsafe artifact path")
    return bundle, paths


def load_trusted_model(bundle_path: str | Path, *, approved_manifest_sha256: str) -> object:
    """Load Joblib only after an externally approved manifest trust chain passes."""

    _, paths = _trusted_bundle_paths(bundle_path)
    approved_hash = _require_sha256(approved_manifest_sha256, "approved manifest hash")
    if file_sha256(paths[MANIFEST_ARTIFACT_NAME]) != approved_hash:
        raise AnomalyArtifactError("manifest SHA-256 does not match external approval")
    manifest = read_manifest(paths[MANIFEST_ARTIFACT_NAME])
    expected_hashes = {
        MODEL_ARTIFACT_NAME: manifest["model_artifact_sha256"],
        MODEL_METADATA_ARTIFACT_NAME: manifest["model_metadata_sha256"],
        SCORE_ARTIFACT_NAME: manifest["score_artifact_sha256"],
    }
    for name, expected_hash in expected_hashes.items():
        if file_sha256(paths[name]) != expected_hash:
            raise AnomalyArtifactError(f"{name} SHA-256 does not match the trusted manifest")
    try:
        runtime_versions = validate_runtime_versions(collect_runtime_versions())
    except AnomalyContractError as error:
        raise AnomalyArtifactError("required runtime package versions are incompatible") from error
    if manifest["runtime_versions"] != runtime_versions:
        raise AnomalyArtifactError("trusted manifest runtime versions do not match this runtime")
    # Every path, hash, schema, and runtime check above must succeed before
    # deserialization.  Joblib models remain unsafe outside this entry point.
    return joblib.load(paths[MODEL_ARTIFACT_NAME])
