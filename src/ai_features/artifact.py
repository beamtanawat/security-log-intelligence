"""Deterministic Stage 1.7 JSON artifact helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path

from .models import FeatureContractError, FeatureRow


FEATURE_ARTIFACT_NAME = "stage_1_7_ai_features.jsonl"
METADATA_ARTIFACT_NAME = "stage_1_7_ai_feature_metadata.json"


class FeatureArtifactError(ValueError):
    """Raised when a Stage 1.7 artifact is absent, malformed, or unsafe."""


class _DuplicateJsonKeyError(ValueError):
    """Internal strict-decoder signal for duplicate artifact object keys."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    object_value: dict[str, object] = {}
    for key, value in pairs:
        if key in object_value:
            raise _DuplicateJsonKeyError("JSON object contains a duplicate key")
        object_value[key] = value
    return object_value


def canonical_json(value: object) -> str:
    """Serialize JSON deterministically and reject non-finite numbers."""

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def file_sha256(path: str | Path) -> str:
    """Return the SHA-256 of a file without loading it into memory."""

    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise FeatureArtifactError("artifact cannot be read for hashing") from error
    return digest.hexdigest()


def file_identity(path: str | Path) -> dict[str, object]:
    """Return a bounded immutable identity for a finished file."""

    artifact_path = Path(path)
    try:
        return {
            "path": str(artifact_path.resolve()),
            "size_bytes": artifact_path.stat().st_size,
            "sha256": file_sha256(artifact_path),
        }
    except OSError as error:
        raise FeatureArtifactError("artifact identity cannot be read") from error


def write_feature_row(output_file: object, row: FeatureRow) -> None:
    """Append one compact, canonical feature JSONL row."""

    output_file.write(canonical_json(row.to_dict()) + "\n")


def read_feature_rows(path: str | Path) -> Iterator[FeatureRow]:
    """Yield strict rows in order; reject malformed JSON and contract drift."""

    feature_path = Path(path)
    if not feature_path.is_file():
        raise FeatureArtifactError("feature JSONL artifact does not exist")
    previous_record_number = 0
    identifiers: set[str] = set()
    try:
        with feature_path.open("r", encoding="utf-8", newline="") as feature_file:
            for line_number, line in enumerate(feature_file, start=1):
                if not line.strip():
                    raise FeatureArtifactError("feature JSONL contains a blank line")
                try:
                    payload = json.loads(line, object_pairs_hook=_strict_json_object)
                except (_DuplicateJsonKeyError, json.JSONDecodeError) as error:
                    raise FeatureArtifactError("feature JSONL contains invalid JSON") from error
                try:
                    row = FeatureRow.from_dict(payload)
                except FeatureContractError as error:
                    raise FeatureArtifactError("feature JSONL row violates the feature contract") from error
                if row.source_record_number <= previous_record_number:
                    raise FeatureArtifactError("feature rows must be strictly ordered by source record number")
                if row.source_record_id in identifiers:
                    raise FeatureArtifactError("feature rows contain a duplicate source record ID")
                previous_record_number = row.source_record_number
                identifiers.add(row.source_record_id)
                yield row
    except UnicodeDecodeError as error:
        raise FeatureArtifactError("feature JSONL is not valid UTF-8") from error
    except OSError as error:
        raise FeatureArtifactError("feature JSONL cannot be read") from error


def read_exact_json_object(path: str | Path, expected_fields: set[str]) -> Mapping[str, object]:
    """Read one UTF-8 JSON object with exact top-level fields."""

    object_path = Path(path)
    if not object_path.is_file():
        raise FeatureArtifactError("JSON artifact does not exist")
    try:
        with object_path.open("r", encoding="utf-8", newline="") as object_file:
            payload = json.load(object_file, object_pairs_hook=_strict_json_object)
    except (OSError, UnicodeDecodeError, _DuplicateJsonKeyError, json.JSONDecodeError) as error:
        raise FeatureArtifactError("JSON artifact cannot be read as UTF-8 JSON") from error
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise FeatureArtifactError("JSON artifact does not contain exactly its contract fields")
    return payload
