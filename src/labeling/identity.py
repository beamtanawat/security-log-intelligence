"""Canonical identities used by Stage 2.1 artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class IdentityError(ValueError):
    """Raised when a Stage 2.1 identity input is invalid."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one JSON value under the repository canonical JSON contract."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise IdentityError("value is not finite, JSON-compatible data") from error
    return encoded.encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Hash canonical JSON and return a full lowercase SHA-256 digest."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def require_sha256(value: object, name: str = "sha256") -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IdentityError(f"{name} must be a full lowercase SHA-256 digest")
    return value


def source_record_identity(
    dataset_sha256: str,
    source_record_number: int,
    source_record_id: str,
) -> str:
    """Return the plan-defined identity for one normalized source record."""

    require_sha256(dataset_sha256, "dataset_sha256")
    if isinstance(source_record_number, bool) or not isinstance(source_record_number, int) or source_record_number < 1:
        raise IdentityError("source_record_number must be a positive integer")
    if not isinstance(source_record_id, str) or not source_record_id:
        raise IdentityError("source_record_id must be a non-empty string")
    return sha256_hex(
        [
            "stage-2.1-source-record-v1",
            dataset_sha256,
            source_record_number,
            source_record_id,
        ]
    )


def annotation_unit_id(source_identity_sha256: str) -> str:
    require_sha256(source_identity_sha256, "source_record_identity_sha256")
    return f"AU-{source_identity_sha256}"


def unit_mapping_sha256(annotation_id: str, source_identity_sha256: str) -> str:
    if not isinstance(annotation_id, str) or not annotation_id:
        raise IdentityError("annotation_unit_id must be non-empty")
    require_sha256(source_identity_sha256, "source_record_identity_sha256")
    return sha256_hex(
        {
            "annotation_unit_id": annotation_id,
            "source_record_identities": [source_identity_sha256],
        }
    )


def digest_order(namespace: str, seed: int, value: object) -> tuple[str, int]:
    """Return digest and first-eight-byte unsigned bucket for stable ordering."""

    if not isinstance(namespace, str) or not namespace:
        raise IdentityError("namespace must be non-empty")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise IdentityError("seed must be an integer")
    digest = hashlib.sha256(canonical_json_bytes([namespace, seed, value])).hexdigest()
    bucket = int(digest[:16], 16)
    return digest, bucket
