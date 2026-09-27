"""Fail-closed Stage 2.1 contract for the separate UNSW-NB15 branch.

This module defines the acquisition and validation boundary only.  It does not
download, parse, split, label, or model any benchmark data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping


DATASET_ID = "UNSW_NB15_BENCHMARK"
BRANCH_ID = "BRANCH_B_LABELED_BENCHMARK"
CONTRACT_VERSION = "1.0"
BINARY_TARGET_FIELD = "label"
ATTACK_CATEGORY_FIELD = "attack_cat"
TARGET_VALUES = ("NORMAL", "ATTACK")
BINARY_TARGET_MAPPING = {
    "0": "NORMAL",
    "1": "ATTACK",
    "NORMAL": "NORMAL",
    "ATTACK": "ATTACK",
}
RAW_ROOT = Path("data/raw/unsw_nb15")
PROCESSED_ROOT = Path("data/processed/unsw_nb15")
TEST_POLICY = "LOCKED_FROM_MODEL_SELECTION"

# These are the two official split artifacts expected from the approved source.
# Their presence, bytes, and source identity still require acquisition-time
# validation; this module never downloads them.
EXPECTED_OFFICIAL_FILES = {
    "TRAIN": "UNSW_NB15_training-set.csv",
    "TEST": "UNSW_NB15_testing-set.csv",
}

FEATURE_DENYLIST = (
    "label",
    "attack_cat",
    "target",
    "binary_target",
    "is_attack",
    "attack_label",
    "split",
    "split_id",
    "source_split",
    "row_id",
    "record_id",
    "post_outcome",
    "predicted_label",
    "prediction",
    "anomaly_score",
    "anomaly_rank",
    "top_n_membership",
    "anomaly_band",
    "auto_triage",
    "suspected_behavior",
    "suspected_attack_type",
    "stage_1_9_explanation",
)


def build_contract_template() -> dict[str, Any]:
    """Return the public contract template without data or acquired hashes."""

    return {
        "schema_version": CONTRACT_VERSION,
        "contract_id": "S2.1-UNSW-NB15-CONTRACT-V1",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "source": {
            "source_name": "<HUMAN_APPROVED_SOURCE>",
            "source_version": "<HUMAN_APPROVED_VERSION>",
            "source_uri": "<HUMAN_APPROVED_URI>",
            "license_record": "<HUMAN_APPROVED_LICENSE_RECORD>",
            "human_approved": False,
        },
        "raw_root": RAW_ROOT.as_posix(),
        "processed_root": PROCESSED_ROOT.as_posix(),
        "files": [
            {
                "split": split,
                "filename": filename,
                "raw_relative_path": f"{RAW_ROOT.as_posix()}/{filename}",
                "sha256": "<SHA256_FROM_ACQUISITION>",
                "byte_size": "<BYTE_SIZE_FROM_ACQUISITION>",
                "row_count": "<ROW_COUNT_FROM_VALIDATION>",
                "labels_quarantined": split == "TEST",
            }
            for split, filename in EXPECTED_OFFICIAL_FILES.items()
        ],
        "schema": {
            "binary_target_field": BINARY_TARGET_FIELD,
            "binary_target_values": list(TARGET_VALUES),
            "binary_target_mapping": dict(BINARY_TARGET_MAPPING),
            "attack_category_field": ATTACK_CATEGORY_FIELD,
            "attack_category_policy": "PRESERVE_RAW_SEPARATE_NON_FEATURE",
            "unknown_source_fields": "PRESERVE_UNLESS_DENIED_BY_LEAKAGE_AUDIT",
            "coercion_policy": "REJECT_SILENT_COERCION",
        },
        "feature_denylist": list(FEATURE_DENYLIST),
        "leakage_policy": {
            "exact_duplicate": "AUDIT",
            "target_conflicting_duplicate": "BLOCK",
            "near_duplicate": "AUDIT_AND_REPORT",
            "stable_entity_or_flow_key_overlap": "AUDIT_AND_REPORT",
            "cross_split_overlap": "BLOCK_INGESTION",
            "silent_delete_or_move": False,
        },
        "duplicate_policy": {
            "exact_decoded_row": "AUDIT",
            "canonical_feature_row_digest": "AUDIT",
            "cross_split_overlap": "BLOCK_INGESTION",
            "target_conflict": "BLOCK",
            "silent_delete_or_move": False,
        },
        "preprocessing_fit_scope": "TRAIN_OR_FOLD_LOCAL_ONLY",
        "test_policy": TEST_POLICY,
        "test_label_access": "QUARANTINED_FROM_STAGE_2_2_TO_2_4_SELECTION",
        "validation_policy": {
            "development_source": "OFFICIAL_TRAIN_ONLY",
            "deterministic": True,
            "membership_manifest_required": True,
        },
        "checksum_policy": {
            "algorithm": "SHA-256",
            "hash_scope": "RAW_FILE_BYTES",
            "manifest_immutable": True,
        },
    }


def canonical_binary_target(value: object) -> str:
    """Map only the approved UNSW binary target values."""

    if isinstance(value, bool):
        raise ValueError("target must be NORMAL or ATTACK")
    if isinstance(value, int):
        mapping = {0: "NORMAL", 1: "ATTACK"}
        if value in mapping:
            return mapping[value]
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in {"0", "NORMAL"}:
            return "NORMAL"
        if normalized in {"1", "ATTACK"}:
            return "ATTACK"
    raise ValueError("target must be NORMAL or ATTACK")


def validate_feature_allowlist(features: Iterable[str]) -> dict[str, Any]:
    """Reject direct targets, categories, identifiers, and derived proxies."""

    normalized = [str(feature).strip().lower() for feature in features]
    denied = sorted(set(normalized).intersection(FEATURE_DENYLIST))
    if denied:
        raise ValueError(f"feature denylist violation: {', '.join(denied)}")
    if len(normalized) != len(set(normalized)):
        raise ValueError("feature allowlist contains duplicates")
    if not all(normalized):
        raise ValueError("feature allowlist contains an empty name")
    return {"status": "PASS", "features": normalized}


def validate_contract(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the contract structure without touching benchmark data."""

    required = {
        "schema_version",
        "contract_id",
        "dataset_id",
        "branch_id",
        "source",
        "raw_root",
        "processed_root",
        "files",
        "schema",
        "feature_denylist",
        "leakage_policy",
        "duplicate_policy",
        "preprocessing_fit_scope",
        "test_policy",
        "test_label_access",
        "validation_policy",
        "checksum_policy",
    }
    missing = sorted(required.difference(payload))
    if missing:
        raise ValueError(f"contract missing fields: {', '.join(missing)}")
    if payload["schema_version"] != CONTRACT_VERSION:
        raise ValueError("unsupported contract schema_version")
    if payload["dataset_id"] != DATASET_ID:
        raise ValueError("dataset_id must be UNSW_NB15_BENCHMARK")
    if payload["branch_id"] != BRANCH_ID:
        raise ValueError("branch_id must be BRANCH_B_LABELED_BENCHMARK")
    if payload["raw_root"] == payload["processed_root"]:
        raise ValueError("raw and processed roots must be separate")

    source = payload["source"]
    if not isinstance(source, Mapping):
        raise ValueError("source must be an object")
    for field in ("source_name", "source_version", "source_uri", "license_record", "human_approved"):
        if field not in source:
            raise ValueError(f"source missing field: {field}")
    if source["human_approved"] is not True:
        raise ValueError("source requires explicit human approval")

    schema = payload["schema"]
    if schema.get("binary_target_field") != BINARY_TARGET_FIELD:
        raise ValueError("binary target field must be label")
    if tuple(schema.get("binary_target_values", ())) != TARGET_VALUES:
        raise ValueError("binary target values must be NORMAL and ATTACK")
    if schema.get("binary_target_mapping") != BINARY_TARGET_MAPPING:
        raise ValueError("binary target mapping must be frozen to NORMAL/ATTACK")
    if schema.get("attack_category_field") != ATTACK_CATEGORY_FIELD:
        raise ValueError("attack category field must be attack_cat")
    if schema.get("attack_category_policy") != "PRESERVE_RAW_SEPARATE_NON_FEATURE":
        raise ValueError("attack category must remain separate and non-feature")

    files = payload["files"]
    if not isinstance(files, list) or len(files) != len(EXPECTED_OFFICIAL_FILES):
        raise ValueError("exactly official TRAIN and TEST files are required")
    seen_splits: set[str] = set()
    seen_names: set[str] = set()
    for entry in files:
        if not isinstance(entry, Mapping):
            raise ValueError("file manifest entries must be objects")
        split = entry.get("split")
        filename = entry.get("filename")
        if split not in EXPECTED_OFFICIAL_FILES:
            raise ValueError("file manifest split must be TRAIN or TEST")
        if filename != EXPECTED_OFFICIAL_FILES[split]:
            raise ValueError("unexpected official UNSW filename")
        expected_relative_path = f"{RAW_ROOT.as_posix()}/{filename}"
        if entry.get("raw_relative_path") != expected_relative_path:
            raise ValueError("file must remain under the dedicated UNSW raw root")
        if split in seen_splits or filename in seen_names:
            raise ValueError("duplicate official file manifest entry")
        seen_splits.add(split)
        seen_names.add(filename)
        if not isinstance(entry.get("sha256"), str) or not _is_sha256(entry["sha256"]):
            raise ValueError("file sha256 must be a lowercase SHA-256 digest")
        if not isinstance(entry.get("byte_size"), int) or entry["byte_size"] <= 0:
            raise ValueError("file byte_size must be a positive integer")
        if not isinstance(entry.get("row_count"), int) or entry["row_count"] <= 0:
            raise ValueError("file row_count must be a positive integer")
        if entry.get("labels_quarantined") is not (split == "TEST"):
            raise ValueError("TEST labels must be quarantined and TRAIN labels must not")
    if seen_splits != set(EXPECTED_OFFICIAL_FILES):
        raise ValueError("TRAIN and TEST official files are both required")

    if payload["test_policy"] != TEST_POLICY:
        raise ValueError("official TEST must remain locked from model selection")
    if payload["preprocessing_fit_scope"] != "TRAIN_OR_FOLD_LOCAL_ONLY":
        raise ValueError("preprocessing must fit on TRAIN or fold-local data only")
    if payload["checksum_policy"].get("algorithm") != "SHA-256":
        raise ValueError("checksum algorithm must be SHA-256")
    denylist = {str(name).strip().lower() for name in payload["feature_denylist"]}
    if not {BINARY_TARGET_FIELD, ATTACK_CATEGORY_FIELD}.issubset(denylist):
        raise ValueError("target and attack category must be in the feature denylist")
    if payload["duplicate_policy"].get("cross_split_overlap") != "BLOCK_INGESTION":
        raise ValueError("cross-split overlap must block ingestion")
    if payload["leakage_policy"].get("target_conflicting_duplicate") != "BLOCK":
        raise ValueError("target-conflicting duplicates must block")
    validate_feature_allowlist([])
    return {
        "status": "PASS",
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "official_splits": sorted(seen_splits),
        "test_policy": TEST_POLICY,
    }


def acquisition_readiness(payload: Mapping[str, Any], root: str | Path) -> dict[str, Any]:
    """Report whether acquired bytes satisfy the frozen manifest."""

    try:
        validate_contract(payload)
    except ValueError as error:
        return {"status": "BLOCKED", "reason": str(error)}
    source = payload["source"]
    if any(str(source[field]).startswith("<") for field in ("source_name", "source_version", "source_uri", "license_record")):
        return {"status": "BLOCKED", "reason": "approved source metadata is not populated"}
    raw_root = Path(root)
    missing: list[str] = []
    for entry in payload["files"]:
        path = raw_root / str(entry["filename"])
        if not path.is_file():
            missing.append(str(path))
    if missing:
        return {"status": "BLOCKED", "reason": "required official files missing", "missing": missing}
    return {"status": "READY", "reason": "manifest files are present; run byte/hash/schema validation"}


def validate_acquired_files(payload: Mapping[str, Any], root: str | Path) -> dict[str, Any]:
    """Verify exact file bytes and reject unexpected files; read-only."""

    validate_contract(payload)
    raw_root = Path(root)
    expected = {str(entry["filename"]) for entry in payload["files"]}
    actual = {path.name for path in raw_root.iterdir() if path.is_file()} if raw_root.is_dir() else set()
    unexpected = sorted(actual.difference(expected))
    missing = sorted(expected.difference(actual))
    if missing or unexpected:
        return {"status": "BLOCKED", "missing": missing, "unexpected": unexpected}
    mismatches: list[str] = []
    for entry in payload["files"]:
        path = raw_root / str(entry["filename"])
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            mismatches.append(str(entry["filename"]))
    if mismatches:
        return {"status": "BLOCKED", "sha256_mismatches": mismatches}
    return {"status": "PASS", "files": sorted(expected)}


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
