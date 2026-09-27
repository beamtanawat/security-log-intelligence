"""Strict validators for the approved Stage 2.1 human-input templates."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .identity import sha256_hex


class HumanInputValidationError(ValueError):
    """Raised when a Stage 2.1 human-input contract is invalid."""


REVIEWER_REGISTRY_SCHEMA = "stage_2_1_reviewer_registry/1.0"
EXTERNAL_EVIDENCE_SCHEMA = "stage_2_1_external_evidence_registry/1.0"
NO_EVIDENCE_SCHEMA = "stage_2_1_no_independent_evidence_declaration/1.0"
CUSTODIAN_ACK_SCHEMA = "stage_2_1_test_custodian_acknowledgement/1.0"

REVIEWER_ROLES = frozenset({"PRIMARY_REVIEWER", "ADJUDICATOR"})
CONFLICT_STATUSES = frozenset({"NO_CONFLICT", "NON_BLOCKING_DISCLOSED", "BLOCKING"})
EVIDENCE_TYPES = frozenset(
    {
        "INCIDENT_CASE_RECORD",
        "VERIFIED_IOC_RECORD",
        "DOCUMENTED_SIMULATION",
        "SYNTHETIC_GENERATOR_GROUND_TRUTH",
    }
)
OBSERVATION_TIME_SEMANTICS = frozenset(
    {
        "EVENT_OBSERVED_AT",
        "INDICATOR_EFFECTIVE_AT",
        "SIMULATION_EXECUTED_AT",
        "SYNTHETIC_GENERATOR_EVENT_TIME",
        "UNKNOWN",
    }
)
TARGET_TYPES = frozenset(
    {"SOURCE_RECORD_IDENTITY", "SOURCE_EVENT_ID", "SYNTHETIC_GENERATOR_RECORD"}
)
LINKAGE_METHODS = frozenset(
    {"EXACT_SOURCE_RECORD_KEYS", "EXACT_SOURCE_EVENT_ID", "SYNTHETIC_GENERATOR_MAPPING"}
)
AVAILABILITY_CLASSIFICATIONS = frozenset(
    {"AVAILABLE_TO_REVIEWERS", "RESTRICTED_CUSTODIAN_MEDIATED", "UNAVAILABLE"}
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PLACEHOLDER = re.compile(r"^<HUMAN_FILL(?:_[A-Z0-9]+)*>$")

_REVIEWER_TOP_FIELDS = frozenset(
    {"schema_version", "registry_version", "registry_id", "approved_by_human", "approval_timestamp", "reviewers"}
)
_REVIEWER_FIELDS = frozenset(
    {
        "reviewer_id",
        "person_binding_id",
        "registry_version",
        "role",
        "training_acknowledged",
        "training_acknowledged_at",
        "conflict_status",
        "conflict_declaration",
        "independence_acknowledged",
        "active",
        "approved_by_human",
        "approval_timestamp",
    }
)
_EVIDENCE_TOP_FIELDS = frozenset(
    {"schema_version", "registry_version", "registry_id", "approved_by_human", "approval_timestamp", "evidence_items"}
)
_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_type",
        "issuer",
        "report_created_at",
        "observation_time",
        "observation_time_semantics",
        "target_type",
        "target_id",
        "source_record_linkage",
        "artifact_sha256",
        "availability_classification",
        "restricted_storage_reference",
        "approved_by_human",
        "approval_timestamp",
        "registry_version",
    }
)
_LINKAGE_FIELDS = frozenset(
    {"dataset_sha256", "source_record_number", "source_record_id", "source_record_identity_sha256", "linkage_method", "linkage_verified"}
)
_NO_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "declaration_version",
        "declaration_type",
        "independent_external_evidence_available",
        "declared_by",
        "declared_at",
        "scope",
        "statement",
        "acknowledgement",
        "approved_by_human",
        "approval_timestamp",
        "dataset_sha256",
        "evidence_policy_sha256",
        "plan_amendment_id",
        "declaration_payload_sha256",
    }
)
_CUSTODIAN_FIELDS = frozenset(
    {
        "schema_version",
        "custodian_id",
        "private_bundle_id",
        "setup_completed",
        "private_storage_verified",
        "owner_only_permissions_verified",
        "backup_policy_acknowledged",
        "seed_generated",
        "seed_commitment_sha256",
        "seed_not_disclosed",
        "independence_acknowledged",
        "opening_policy_acknowledged",
        "opening_policy_sha256",
        "opening_state",
        "private_location_disclosed",
        "hash_algorithm",
        "canonicalization",
        "acknowledged_at",
        "approved_by_human",
        "approval_timestamp",
    }
)


def _fail(message: str) -> None:
    raise HumanInputValidationError(message)


def _is_placeholder(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return _PLACEHOLDER.fullmatch(value) is not None or (
        "<HUMAN_FILL" in value and value.endswith(">")
    )


def _keys(payload: object, expected: frozenset[str], path: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        _fail(f"{path} must be an object")
    actual = set(payload)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        _fail(f"{path} missing fields: {sorted(missing)}")
    if unknown:
        _fail(f"{path} unknown fields: {sorted(unknown)}")
    return payload  # type: ignore[return-value]


def _string(value: object, path: str, *, allow_placeholder: bool = False) -> str:
    if allow_placeholder and _is_placeholder(value):
        return value
    if not isinstance(value, str) or not value:
        _fail(f"{path} must be a nonempty string")
    return value


def _timestamp(value: object, path: str, *, allow_placeholder: bool = False) -> None:
    if allow_placeholder and _is_placeholder(value):
        return
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        _fail(f"{path} must be RFC 3339 with an offset")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        _fail(f"{path} is not a valid RFC 3339 timestamp: {error}")


def _sha(value: object, path: str, *, allow_placeholder: bool = False) -> None:
    if allow_placeholder and _is_placeholder(value):
        return
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{path} must be lowercase 64-hex SHA-256")


def _boolean(value: object, path: str, *, required: bool | None = None) -> None:
    if not isinstance(value, bool):
        _fail(f"{path} must be boolean")
    if required is True and value is not True:
        _fail(f"{path} must be true")
    if required is False and value is not False:
        _fail(f"{path} must be false")


def _enum(value: object, allowed: frozenset[str], path: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        _fail(f"{path} has invalid enum value")


def _forbidden_secret_content(value: object, path: str = "") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"seed", "test_seed", "private_root", "private_path", "credentials", "password", "token"}:
                _fail(f"{path}/{key} is forbidden secret content")
            _forbidden_secret_content(child, f"{path}/{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _forbidden_secret_content(child, f"{path}/{index}")
    elif isinstance(value, str):
        if "SLI_STAGE_2_1_TEST_PRIVATE_ROOT" in value or "/Users/" in value or re.search(r"(^|\s)[A-Za-z]:[\\/]", value):
            _fail(f"{path} contains a private physical path")
        if "-----BEGIN" in value:
            _fail(f"{path} contains credential material")


def validate_reviewer_registry(payload: Mapping[str, Any], *, allow_placeholders: bool = False) -> None:
    """Validate the exact reviewer-registry contract."""

    data = _keys(payload, _REVIEWER_TOP_FIELDS, "reviewer_registry")
    _forbidden_secret_content(data)
    if data["schema_version"] != "1.0" or data["registry_version"] != "1.0":
        _fail("reviewer registry schema/version must be 1.0")
    _boolean(data["approved_by_human"], "approved_by_human", required=True)
    _timestamp(data["approval_timestamp"], "approval_timestamp", allow_placeholder=allow_placeholders)
    registry_id = _string(data["registry_id"], "registry_id", allow_placeholder=allow_placeholders)
    if not (allow_placeholders and _is_placeholder(registry_id)):
        if not registry_id.startswith("RR-") or not _SHA256.fullmatch(registry_id[3:]):
            _fail("registry_id must be RR- plus SHA-256")
        expected = f"RR-{sha256_hex({key: value for key, value in data.items() if key != 'registry_id'})}"
        if registry_id != expected:
            _fail("registry_id hash mismatch")
    reviewers = data["reviewers"]
    if not isinstance(reviewers, list) or len(reviewers) < 3:
        _fail("reviewers must contain at least three records")
    reviewer_ids: set[str] = set()
    person_bindings: set[str] = set()
    eligible_roles: list[str] = []
    for index, item in enumerate(reviewers):
        record = _keys(item, _REVIEWER_FIELDS, f"reviewers[{index}]")
        reviewer_id = _string(record["reviewer_id"], f"reviewers[{index}].reviewer_id", allow_placeholder=allow_placeholders)
        person_binding = _string(record["person_binding_id"], f"reviewers[{index}].person_binding_id", allow_placeholder=allow_placeholders)
        if reviewer_id in reviewer_ids:
            _fail("duplicate reviewer_id")
        if person_binding in person_bindings:
            _fail("duplicate person_binding_id")
        reviewer_ids.add(reviewer_id)
        person_bindings.add(person_binding)
        if record["registry_version"] != data["registry_version"]:
            _fail("reviewer registry_version mismatch")
        _enum(record["role"], REVIEWER_ROLES, f"reviewers[{index}].role")
        _enum(record["conflict_status"], CONFLICT_STATUSES, f"reviewers[{index}].conflict_status")
        _boolean(record["training_acknowledged"], f"reviewers[{index}].training_acknowledged")
        _boolean(record["independence_acknowledged"], f"reviewers[{index}].independence_acknowledged")
        _boolean(record["active"], f"reviewers[{index}].active")
        _boolean(record["approved_by_human"], f"reviewers[{index}].approved_by_human")
        if record["conflict_status"] == "NO_CONFLICT":
            if record["conflict_declaration"] is not None:
                _fail("NO_CONFLICT requires null conflict_declaration")
        else:
            _string(record["conflict_declaration"], f"reviewers[{index}].conflict_declaration", allow_placeholder=allow_placeholders)
        if record["training_acknowledged"]:
            _timestamp(record["training_acknowledged_at"], f"reviewers[{index}].training_acknowledged_at", allow_placeholder=allow_placeholders)
        elif record["training_acknowledged_at"] is not None:
            _fail("unacknowledged reviewer must have null training timestamp")
        if record["approved_by_human"]:
            _timestamp(record["approval_timestamp"], f"reviewers[{index}].approval_timestamp", allow_placeholder=allow_placeholders)
        elif record["approval_timestamp"] is not None:
            _fail("unapproved reviewer must have null approval timestamp")
        if record["active"] and record["approved_by_human"] and record["training_acknowledged"] and record["independence_acknowledged"] and record["conflict_status"] != "BLOCKING":
            eligible_roles.append(record["role"])
    if eligible_roles.count("PRIMARY_REVIEWER") != 2:
        _fail("exactly two eligible PRIMARY_REVIEWER records are required")
    if eligible_roles.count("ADJUDICATOR") < 1:
        _fail("at least one eligible ADJUDICATOR is required")


def validate_external_evidence_registry(payload: Mapping[str, Any], *, allow_placeholders: bool = False) -> None:
    """Validate the exact external-evidence registry contract."""

    data = _keys(payload, _EVIDENCE_TOP_FIELDS, "external_evidence_registry")
    _forbidden_secret_content(data)
    if data["schema_version"] != "1.0" or data["registry_version"] != "1.0":
        _fail("external evidence schema/version must be 1.0")
    _boolean(data["approved_by_human"], "approved_by_human", required=True)
    _timestamp(data["approval_timestamp"], "approval_timestamp", allow_placeholder=allow_placeholders)
    registry_id = _string(data["registry_id"], "registry_id", allow_placeholder=allow_placeholders)
    if not (allow_placeholders and _is_placeholder(registry_id)):
        if not registry_id.startswith("ER-") or not _SHA256.fullmatch(registry_id[3:]):
            _fail("registry_id must be ER- plus SHA-256")
        expected = f"ER-{sha256_hex({key: value for key, value in data.items() if key != 'registry_id'})}"
        if registry_id != expected:
            _fail("registry_id hash mismatch")
    items = data["evidence_items"]
    if not isinstance(items, list) or not items:
        _fail("evidence_items must be nonempty")
    evidence_ids: set[str] = set()
    for index, item in enumerate(items):
        record = _keys(item, _EVIDENCE_FIELDS, f"evidence_items[{index}]")
        evidence_id = _string(record["evidence_id"], f"evidence_items[{index}].evidence_id", allow_placeholder=allow_placeholders)
        if evidence_id in evidence_ids:
            _fail("duplicate evidence_id")
        evidence_ids.add(evidence_id)
        _enum(record["evidence_type"], EVIDENCE_TYPES, f"evidence_items[{index}].evidence_type")
        _string(record["issuer"], f"evidence_items[{index}].issuer", allow_placeholder=allow_placeholders)
        _timestamp(record["report_created_at"], f"evidence_items[{index}].report_created_at", allow_placeholder=allow_placeholders)
        observation_time = record["observation_time"]
        if observation_time is not None:
            _timestamp(observation_time, f"evidence_items[{index}].observation_time", allow_placeholder=allow_placeholders)
        _enum(record["observation_time_semantics"], OBSERVATION_TIME_SEMANTICS, f"evidence_items[{index}].observation_time_semantics")
        if record["observation_time_semantics"] == "UNKNOWN" and observation_time is not None:
            _fail("UNKNOWN observation_time_semantics requires null observation_time")
        _enum(record["target_type"], TARGET_TYPES, f"evidence_items[{index}].target_type")
        _string(record["target_id"], f"evidence_items[{index}].target_id", allow_placeholder=allow_placeholders)
        linkage = _keys(record["source_record_linkage"], _LINKAGE_FIELDS, f"evidence_items[{index}].source_record_linkage")
        _sha(linkage["dataset_sha256"], "dataset_sha256", allow_placeholder=allow_placeholders)
        if isinstance(linkage["source_record_number"], bool) or not isinstance(linkage["source_record_number"], int) or linkage["source_record_number"] < 1:
            _fail("source_record_number must be a positive integer")
        _string(linkage["source_record_id"], "source_record_id", allow_placeholder=allow_placeholders)
        _sha(linkage["source_record_identity_sha256"], "source_record_identity_sha256", allow_placeholder=allow_placeholders)
        _enum(linkage["linkage_method"], LINKAGE_METHODS, "linkage_method")
        _boolean(linkage["linkage_verified"], "linkage_verified")
        _sha(record["artifact_sha256"], f"evidence_items[{index}].artifact_sha256", allow_placeholder=allow_placeholders)
        _enum(record["availability_classification"], AVAILABILITY_CLASSIFICATIONS, f"evidence_items[{index}].availability_classification")
        restricted = record["restricted_storage_reference"]
        if record["availability_classification"] == "RESTRICTED_CUSTODIAN_MEDIATED":
            if restricted is not None:
                restricted = _string(restricted, "restricted_storage_reference", allow_placeholder=allow_placeholders)
                if not (allow_placeholders and _is_placeholder(restricted)) and not restricted.startswith("evidence://"):
                    _fail("restricted storage reference must be evidence://")
            else:
                _fail("restricted evidence requires restricted_storage_reference")
        elif restricted is not None:
            _fail("restricted_storage_reference must be null unless evidence is restricted")
        _boolean(record["approved_by_human"], f"evidence_items[{index}].approved_by_human", required=True)
        _timestamp(record["approval_timestamp"], f"evidence_items[{index}].approval_timestamp", allow_placeholder=allow_placeholders)
        if record["registry_version"] != data["registry_version"]:
            _fail("evidence registry_version mismatch")


def validate_no_evidence_declaration(payload: Mapping[str, Any], *, allow_placeholders: bool = False) -> None:
    """Validate the explicit no-independent-evidence declaration."""

    data = _keys(payload, _NO_EVIDENCE_FIELDS, "no_evidence_declaration")
    _forbidden_secret_content(data)
    if data["schema_version"] != "1.0" or data["declaration_version"] != "1.0":
        _fail("no-evidence schema/version must be 1.0")
    if data["declaration_type"] != "NO_INDEPENDENT_EXTERNAL_EVIDENCE":
        _fail("invalid declaration_type")
    _boolean(data["independent_external_evidence_available"], "independent_external_evidence_available", required=False)
    _string(data["declared_by"], "declared_by", allow_placeholder=allow_placeholders)
    _timestamp(data["declared_at"], "declared_at", allow_placeholder=allow_placeholders)
    if data["scope"] != "STAGE_2_1_PRIMARY_ADJUDICATION":
        _fail("invalid no-evidence scope")
    if data["statement"] != "No independent external evidence is available for Stage 2.1 primary adjudication beyond the evidence sources explicitly permitted elsewhere.":
        _fail("invalid no-evidence statement")
    if data["acknowledgement"] != "HUMAN_ACKNOWLEDGED":
        _fail("invalid no-evidence acknowledgement")
    _boolean(data["approved_by_human"], "approved_by_human", required=True)
    _timestamp(data["approval_timestamp"], "approval_timestamp", allow_placeholder=allow_placeholders)
    _sha(data["dataset_sha256"], "dataset_sha256", allow_placeholder=allow_placeholders)
    _sha(data["evidence_policy_sha256"], "evidence_policy_sha256", allow_placeholder=allow_placeholders)
    if data["plan_amendment_id"] != "S2.1-AMEND-2026-09-26-HUMAN-INPUT-CONTRACTS-V1":
        _fail("invalid plan_amendment_id")
    _sha(data["declaration_payload_sha256"], "declaration_payload_sha256", allow_placeholder=allow_placeholders)
    if not (allow_placeholders and _is_placeholder(data["declaration_payload_sha256"])):
        expected = sha256_hex({key: value for key, value in data.items() if key != "declaration_payload_sha256"})
        if data["declaration_payload_sha256"] != expected:
            _fail("declaration_payload_sha256 mismatch")


def validate_custodian_acknowledgement(payload: Mapping[str, Any], *, allow_placeholders: bool = False) -> None:
    """Validate the public, secret-free Custodian acknowledgement contract."""

    data = _keys(payload, _CUSTODIAN_FIELDS, "custodian_acknowledgement")
    _forbidden_secret_content(data)
    if data["schema_version"] != "1.0":
        _fail("Custodian acknowledgement schema_version must be 1.0")
    if data["custodian_id"] != "CUSTODIAN_TANAWAT_V1":
        _fail("invalid custodian_id")
    if data["private_bundle_id"] != "custodian://security-log-intelligence/stage_2_1/test/v1":
        _fail("invalid private_bundle_id")
    for field in (
        "setup_completed",
        "private_storage_verified",
        "owner_only_permissions_verified",
        "backup_policy_acknowledged",
        "seed_generated",
        "seed_not_disclosed",
        "independence_acknowledged",
        "opening_policy_acknowledged",
        "approved_by_human",
    ):
        _boolean(data[field], field, required=True)
    _sha(data["seed_commitment_sha256"], "seed_commitment_sha256", allow_placeholder=allow_placeholders)
    _sha(data["opening_policy_sha256"], "opening_policy_sha256", allow_placeholder=allow_placeholders)
    if data["opening_state"] != "SEALED":
        _fail("opening_state must be SEALED")
    _boolean(data["private_location_disclosed"], "private_location_disclosed", required=False)
    if data["hash_algorithm"] != "SHA-256":
        _fail("hash_algorithm must be SHA-256")
    if data["canonicalization"] != "UTF-8_SORTED_KEYS_COMPACT_LF":
        _fail("invalid canonicalization")
    _timestamp(data["acknowledged_at"], "acknowledged_at", allow_placeholder=allow_placeholders)
    _timestamp(data["approval_timestamp"], "approval_timestamp", allow_placeholder=allow_placeholders)


_VALIDATORS: dict[str, Callable[..., None]] = {
    "reviewer_registry.json": validate_reviewer_registry,
    "external_evidence_registry.json": validate_external_evidence_registry,
    "no_independent_evidence_declaration.json": validate_no_evidence_declaration,
    "test_custodian_acknowledgement.json": validate_custodian_acknowledgement,
}


def validate_template_file(path: str | Path) -> None:
    """Validate one approved placeholder template by its fixed filename."""

    file_path = Path(path)
    validator = _VALIDATORS.get(file_path.name)
    if validator is None:
        _fail(f"unknown human-input template: {file_path.name}")
    import json

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"cannot read template {file_path}: {error}")
    validator(payload, allow_placeholders=True)
