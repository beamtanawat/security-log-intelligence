"""No-replace publication and public/private bundle checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from .identity import canonical_json_bytes, sha256_hex


PUBLIC_BUNDLE_ROOT = "stage_2_1_public_v1"
PRIVATE_MARKERS = ("private", "labels/test_", "sampling/test_", "review/test_", "test_label", "test_sampling", "test_review", "custodian://")


def _ensure_relative(path: Path) -> None:
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact path must be relative to bundle root")


def write_bytes_no_replace(path: str | Path, payload: bytes) -> None:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ValueError("artifact parent cannot be a symlink")
    with destination.open("xb") as stream:
        stream.write(payload)


def write_json_no_replace(path: str | Path, payload: Any) -> None:
    write_bytes_no_replace(path, canonical_json_bytes(payload) + b"\n")


def write_jsonl_no_replace(path: str | Path, rows: Iterable[Any]) -> None:
    payload = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    write_bytes_no_replace(path, payload)


def validate_public_bundle(root: str | Path) -> dict[str, object]:
    """Fail closed on private/test-derived content in a public bundle."""

    bundle = Path(root)
    if not bundle.is_dir():
        raise ValueError("public bundle does not exist")
    files: list[str] = []
    for path in bundle.rglob("*"):
        relative = path.relative_to(bundle)
        _ensure_relative(relative)
        if path.is_symlink():
            raise ValueError(f"public bundle contains symlink: {relative}")
        if path.is_file():
            name = str(relative).replace(os.sep, "/").lower()
            if any(marker in name for marker in PRIVATE_MARKERS):
                raise ValueError(f"public bundle exposes TEST/private artifact: {relative}")
            files.append(str(relative).replace(os.sep, "/"))
    return {"status": "PASS", "file_count": len(files), "files": sorted(files)}


def build_manifest(root: str | Path, *, bundle_id: str, source_identities: dict[str, str], created_at: str) -> dict[str, object]:
    """Build a manifest without hashing the manifest itself."""

    bundle = Path(root)
    entries: list[dict[str, object]] = []
    for path in sorted(path for path in bundle.rglob("*") if path.is_file() and path.name != "stage_2_1_public_manifest.json"):
        relative = path.relative_to(bundle).as_posix()
        data = path.read_bytes()
        entries.append({"logical_id": relative, "relative_path": relative, "byte_size": len(data), "sha256": __import__("hashlib").sha256(data).hexdigest(), "schema_version": "1.0", "row_count": None, "confidentiality": "PUBLIC"})
    payload = {"schema_version": "1.0", "bundle_id": bundle_id, "logical_root": bundle.name, "created_at": created_at, "source_identities": dict(sorted(source_identities.items())), "artifacts": entries}
    payload["manifest_id"] = f"PM-{sha256_hex(payload)}"
    return payload
