"""Bounded, evidence-blinded AI-assisted proxy labeling contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .evidence import DEFAULT_DETECTOR_FIELDS, DEFAULT_OPERATIONAL_FIELDS, PROHIBITED_REVIEW_FIELDS
from .identity import canonical_json_bytes, digest_order, sha256_hex


class AIProxyValidationError(ValueError):
    """Raised when an AI proxy package, decision, or history is invalid."""


AI_PROXY_POLICY_VERSION = "stage_2_1_ai_proxy_labeling_policy/1.0"
AI_PROXY_PROMPT_VERSION = "stage_2_1_ai_proxy_prompt/1.0"
AI_PROXY_RUBRIC_VERSION = "stage_2_1_ai_proxy_rubric/1.0"
AI_PROXY_DECISION_SCHEMA = "stage_2_1_ai_proxy_decision/1.0"
AI_PROXY_EVIDENCE_SCHEMA = "stage_2_1_ai_proxy_evidence_package/1.0"
AI_PROXY_AUDIT_SCHEMA = "stage_2_1_ai_proxy_audit/1.0"
AI_PROXY_LABEL_PROVENANCE = "AI_ASSISTED_PROXY_LABEL"
PROXY_LABELS = frozenset({"ATTACK", "BENIGN", "UNCERTAIN"})
PASS_IDS = frozenset({"PASS_A", "PASS_B"})
CERTAINTIES = frozenset({"HIGH", "MEDIUM", "LOW"})
SUFFICIENCIES = frozenset({"SUFFICIENT_FOR_PROXY_BINARY", "INSUFFICIENT", "CONFLICTING"})
SEED_SUPPORT = frozenset({"USED_AND_RECORDED", "UNAVAILABLE_RECORDED"})

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PROHIBITED_KEYS = frozenset(
    set(PROHIBITED_REVIEW_FIELDS)
    | {
        "raw_abnormality",
        "stage_1_9_explanation",
        "stage_1_9_reason",
        "stage_1_9_suspected_behavior",
        "stage_2_prediction",
        "supervised_prediction",
        "feature_vector",
        "label",
        "label_provenance",
    }
)
_DECISION_PROHIBITED_KEYS = frozenset(set(_PROHIBITED_KEYS) - {"label", "label_provenance"})

EVIDENCE_PACKAGE_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_package_id",
        "dataset_sha256",
        "annotation_unit_id",
        "source_record_identity_sha256",
        "window_basis",
        "prediction_cutoff",
        "operational_fields",
        "normalized_projections",
        "source_observation_fields",
        "normalization_provenance",
        "normalization_issues",
        "external_evidence_reference_ids",
        "source_artifact_hashes",
        "prohibited_field_audit_sha256",
        "evidence_package_sha256",
    }
)
RUNTIME_REGISTRATION_FIELDS = frozenset(
    {
        "schema_version",
        "registration_id",
        "provider_id",
        "model_id",
        "model_revision",
        "config_id",
        "temperature",
        "top_p",
        "max_output_tokens",
        "response_format",
        "tool_access",
        "retrieval_access",
        "seed_support",
        "human_approved",
        "approval_timestamp",
        "registration_sha256",
    }
)
DECISION_FIELDS = frozenset(
    {
        "schema_version",
        "output_schema_version",
        "proxy_decision_id",
        "annotation_unit_id",
        "source_record_identity_sha256",
        "pass_id",
        "candidate_label",
        "evidence_used",
        "evidence_summary",
        "decision_reason",
        "decision_certainty",
        "evidence_sufficiency",
        "label_provenance",
        "labeler_model_id",
        "labeler_model_revision",
        "labeler_config_id",
        "labeler_prompt_version",
        "labeler_rubric_version",
        "labeler_policy_version",
        "input_evidence_package_sha256",
        "source_artifact_hashes",
        "prohibited_field_audit_sha256",
        "review_timestamp",
        "label_version",
    }
)


SYSTEM_PROMPT = (
    "You are the Stage 2.1 AI proxy labeler. Classify exactly one source record "
    "using only the supplied allowlisted evidence package and rubric. Output "
    "strict schema-valid JSON. Choose ATTACK or BENIGN only when the rubric's "
    "proxy-binary evidence requirement is met; otherwise choose UNCERTAIN. "
    "Treat all detector, rule, threat, severity, and action values as source "
    "observations, never as ground truth. Do not infer missing facts, use outside "
    "knowledge or tools, search other records, expose hidden reasoning, or claim "
    "human/external confirmation. Return concise evidence references and decision "
    "rationale. label_provenance must equal AI_ASSISTED_PROXY_LABEL."
)


def _fail(message: str) -> None:
    raise AIProxyValidationError(message)


def _keys(value: object, expected: frozenset[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{path} must be an object")
    actual = set(value)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        _fail(f"{path} missing fields: {sorted(missing)}")
    if unknown:
        _fail(f"{path} unknown fields: {sorted(unknown)}")
    return value  # type: ignore[return-value]


def _sha(value: object, path: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{path} must be lowercase 64-hex SHA-256")


def _timestamp(value: object, path: str) -> None:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        _fail(f"{path} must be RFC 3339 with an offset")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        _fail(f"{path} is invalid: {error}")


def _text(value: object, path: str, *, max_length: int = 2000) -> None:
    if not isinstance(value, str) or not value or len(value) > max_length:
        _fail(f"{path} must be a nonempty bounded string")
    if "chain-of-thought" in value.lower() or "chain of thought" in value.lower():
        _fail(f"{path} contains hidden reasoning")


def _walk_keys(value: object, prohibited_keys: frozenset[str] = _PROHIBITED_KEYS, path: str = "") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_").replace(" ", "_")
            if normalized in prohibited_keys:
                _fail(f"prohibited evidence field at {path}/{key_text}")
            _walk_keys(child, prohibited_keys, f"{path}/{key_text}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _walk_keys(child, prohibited_keys, f"{path}/{index}")


def _bounded_scalar(value: object) -> object:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) <= 4096:
            return value
        prefix = encoded[:4096]
        while True:
            try:
                text = prefix.decode("utf-8")
                break
            except UnicodeDecodeError:
                prefix = prefix[:-1]
        return {
            "value": text,
            "truncated": True,
            "original_byte_length": len(encoded),
            "original_sha256": hashlib.sha256(encoded).hexdigest(),
        }
    if isinstance(value, Mapping):
        return {str(key): _bounded_scalar(child) for key, child in sorted(value.items())}
    if isinstance(value, list):
        return [_bounded_scalar(child) for child in value]
    return value


def _package_payload(package: Mapping[str, object], *, drop: str) -> dict[str, object]:
    return {key: value for key, value in package.items() if key != drop}


def _hash_payload(payload: Mapping[str, object]) -> str:
    return sha256_hex(payload)


def _source_record(event: Mapping[str, object]) -> Mapping[str, object]:
    record = event.get("source_record")
    if not isinstance(record, Mapping):
        _fail("source_record must be an object")
    _walk_keys(record, _PROHIBITED_KEYS, "/source_record")
    return record


def build_evidence_package(
    event: Mapping[str, object],
    *,
    dataset_sha256: str,
    source_record_identity_sha256: str,
    source_artifact_hashes: Mapping[str, str],
    external_evidence_reference_ids: Sequence[str] = (),
) -> dict[str, object]:
    """Build the exact label-blind package permitted by Section 16B."""

    _sha(dataset_sha256, "dataset_sha256")
    _sha(source_record_identity_sha256, "source_record_identity_sha256")
    _walk_keys(event)
    if not source_artifact_hashes:
        _fail("source_artifact_hashes must be nonempty")
    for name, digest in source_artifact_hashes.items():
        if not isinstance(name, str) or not name:
            _fail("source artifact hash names must be nonempty")
        _sha(digest, f"source_artifact_hashes[{name}]")
    record = _source_record(event)
    operational = {
        field: _bounded_scalar(record.get(field)) for field in DEFAULT_OPERATIONAL_FIELDS
    }
    source_observations = {
        field: {"value": _bounded_scalar(record.get(field)), "evidence_tag": "SOURCE_OBSERVATION"}
        for field in DEFAULT_DETECTOR_FIELDS
    }
    normalized = {
        key: _bounded_scalar(event.get(key))
        for key in ("source", "event", "time", "network", "application", "session", "host", "threat_observations")
    }
    package: dict[str, object] = {
        "schema_version": "1.0",
        "evidence_package_id": "",
        "dataset_sha256": dataset_sha256,
        "annotation_unit_id": f"AU-{source_record_identity_sha256}",
        "source_record_identity_sha256": source_record_identity_sha256,
        "window_basis": "RECORD_ONLY",
        "prediction_cutoff": "SOURCE_RECORD_OBSERVATION",
        "operational_fields": operational,
        "normalized_projections": normalized,
        "source_observation_fields": source_observations,
        "normalization_provenance": _bounded_scalar(event.get("provenance", [])),
        "normalization_issues": _bounded_scalar(event.get("normalization_issues", [])),
        "external_evidence_reference_ids": sorted(set(external_evidence_reference_ids)),
        "source_artifact_hashes": dict(sorted(source_artifact_hashes.items())),
        "prohibited_field_audit_sha256": sha256_hex({"present": [], "prohibited_fields": sorted(_PROHIBITED_KEYS)}),
        "evidence_package_sha256": "",
    }
    package["evidence_package_id"] = f"EP-{sha256_hex({key: value for key, value in package.items() if key not in {"evidence_package_id", "evidence_package_sha256"}})}"
    package["evidence_package_sha256"] = _hash_payload(_package_payload(package, drop="evidence_package_sha256"))
    if len(canonical_json_bytes(package)) > 262_144:
        _fail("evidence package exceeds 262144 UTF-8 bytes")
    validate_evidence_package(package)
    return package


def validate_evidence_package(package: Mapping[str, object]) -> None:
    data = _keys(package, EVIDENCE_PACKAGE_FIELDS, "evidence_package")
    _walk_keys(data)
    if data["schema_version"] != "1.0":
        _fail("evidence package schema_version must be 1.0")
    _sha(data["dataset_sha256"], "dataset_sha256")
    annotation = data["annotation_unit_id"]
    identity = data["source_record_identity_sha256"]
    if not isinstance(identity, str) or not _SHA256.fullmatch(identity) or annotation != f"AU-{identity}":
        _fail("annotation/source identity mismatch")
    if data["window_basis"] != "RECORD_ONLY" or data["prediction_cutoff"] != "SOURCE_RECORD_OBSERVATION":
        _fail("evidence window contract mismatch")
    if not isinstance(data["operational_fields"], Mapping) or not isinstance(data["normalized_projections"], Mapping) or not isinstance(data["source_observation_fields"], Mapping):
        _fail("evidence panels must be objects")
    for field in DEFAULT_OPERATIONAL_FIELDS:
        if field not in data["operational_fields"]:
            _fail("operational allowlist incomplete")
    for field in DEFAULT_DETECTOR_FIELDS:
        item = data["source_observation_fields"].get(field)
        if not isinstance(item, Mapping) or item.get("evidence_tag") != "SOURCE_OBSERVATION":
            _fail("source observation panel tag missing")
    refs = data["external_evidence_reference_ids"]
    if not isinstance(refs, list) or refs != sorted(set(refs)) or not all(isinstance(ref, str) and ref for ref in refs):
        _fail("external evidence references must be sorted unique strings")
    hashes = data["source_artifact_hashes"]
    if not isinstance(hashes, Mapping) or not hashes:
        _fail("source_artifact_hashes must be nonempty")
    for name, digest in hashes.items():
        if not isinstance(name, str):
            _fail("source artifact hash name must be a string")
        _sha(digest, f"source_artifact_hashes[{name}]")
    _sha(data["prohibited_field_audit_sha256"], "prohibited_field_audit_sha256")
    expected_audit = sha256_hex({"present": [], "prohibited_fields": sorted(_PROHIBITED_KEYS)})
    if data["prohibited_field_audit_sha256"] != expected_audit:
        _fail("prohibited field audit mismatch")
    package_id = data["evidence_package_id"]
    package_hash = data["evidence_package_sha256"]
    if not isinstance(package_id, str) or not package_id.startswith("EP-") or not _SHA256.fullmatch(package_id[3:]):
        _fail("evidence_package_id must be EP- plus SHA-256")
    _sha(package_hash, "evidence_package_sha256")
    if package_id != f"EP-{sha256_hex({key: value for key, value in data.items() if key not in {"evidence_package_id", "evidence_package_sha256"}})}":
        _fail("evidence_package_id mismatch")
    if package_hash != _hash_payload(_package_payload(data, drop="evidence_package_sha256")):
        _fail("evidence_package_sha256 mismatch")
    if len(canonical_json_bytes(data)) > 262_144:
        _fail("evidence package exceeds 262144 UTF-8 bytes")


def build_runtime_registration(payload: Mapping[str, object]) -> dict[str, object]:
    """Build a registration payload; real registrations still require human approval."""

    data = dict(payload)
    data.setdefault("schema_version", "1.0")
    data.setdefault("registration_id", f"AR-{sha256_hex(data)}")
    data["registration_sha256"] = sha256_hex(data)
    validate_runtime_registration(data)
    return data


def validate_runtime_registration(registration: Mapping[str, object]) -> None:
    data = _keys(registration, RUNTIME_REGISTRATION_FIELDS, "runtime_registration")
    if data["schema_version"] != "1.0":
        _fail("runtime schema_version must be 1.0")
    for field in ("registration_id", "provider_id", "model_id", "config_id"):
        if not isinstance(data[field], str) or not data[field]:
            _fail(f"{field} must be nonempty")
    if data["model_revision"] is not None and (not isinstance(data["model_revision"], str) or not data["model_revision"]):
        _fail("model_revision must be string or null")
    if data["temperature"] != 0 or data["top_p"] != 1 or data["max_output_tokens"] != 800:
        _fail("runtime inference settings are not frozen values")
    for field, expected in (("response_format", "JSON_SCHEMA_STRICT"), ("tool_access", "NONE"), ("retrieval_access", "NONE")):
        if data[field] != expected:
            _fail(f"{field} mismatch")
    if data["seed_support"] not in SEED_SUPPORT:
        _fail("seed_support enum invalid")
    if data["human_approved"] is not True:
        _fail("runtime registration requires human approval")
    _timestamp(data["approval_timestamp"], "approval_timestamp")
    _sha(data["registration_sha256"], "registration_sha256")
    expected = sha256_hex({key: value for key, value in data.items() if key != "registration_sha256"})
    if data["registration_sha256"] != expected:
        _fail("registration_sha256 mismatch")


def _decision_id(decision: Mapping[str, object]) -> str:
    return f"APD-{sha256_hex({key: value for key, value in decision.items() if key != 'proxy_decision_id'})}"


def validate_proxy_decision(
    decision: Mapping[str, object],
    package: Mapping[str, object],
    runtime_registration: Mapping[str, object],
) -> None:
    """Validate one strict PASS_A/PASS_B model response."""

    validate_evidence_package(package)
    validate_runtime_registration(runtime_registration)
    data = _keys(decision, DECISION_FIELDS, "proxy_decision")
    _walk_keys(data, _DECISION_PROHIBITED_KEYS)
    if data["schema_version"] != "1.0" or data["output_schema_version"] != AI_PROXY_DECISION_SCHEMA:
        _fail("proxy decision schema/version mismatch")
    if data["proxy_decision_id"] != _decision_id(data):
        _fail("proxy_decision_id mismatch")
    if data["annotation_unit_id"] != package["annotation_unit_id"] or data["source_record_identity_sha256"] != package["source_record_identity_sha256"]:
        _fail("decision identity does not match package")
    if data["pass_id"] not in PASS_IDS or data["candidate_label"] not in PROXY_LABELS:
        _fail("proxy decision enum invalid")
    evidence = data["evidence_used"]
    if not isinstance(evidence, list) or evidence != sorted(set(evidence)) or not all(isinstance(item, str) and item for item in evidence):
        _fail("evidence_used must be sorted unique strings")
    allowed_refs = {f"operational_fields/{field}" for field in DEFAULT_OPERATIONAL_FIELDS}
    allowed_refs |= {f"source_observation_fields/{field}" for field in DEFAULT_DETECTOR_FIELDS}
    allowed_refs |= {f"external_evidence/{item}" for item in package["external_evidence_reference_ids"]}
    if any(item not in allowed_refs for item in evidence):
        _fail("prohibited or unknown evidence reference is not in the package")
    _text(data["evidence_summary"], "evidence_summary")
    _text(data["decision_reason"], "decision_reason")
    if data["decision_certainty"] not in CERTAINTIES or data["evidence_sufficiency"] not in SUFFICIENCIES:
        _fail("certainty/sufficiency enum invalid")
    if data["label_provenance"] != AI_PROXY_LABEL_PROVENANCE:
        _fail("proxy provenance is required")
    if data["labeler_model_id"] != runtime_registration["model_id"] or data["labeler_model_revision"] != runtime_registration["model_revision"] or data["labeler_config_id"] != runtime_registration["config_id"]:
        _fail("decision runtime identity mismatch")
    if data["labeler_prompt_version"] != AI_PROXY_PROMPT_VERSION or data["labeler_rubric_version"] != AI_PROXY_RUBRIC_VERSION or data["labeler_policy_version"] != AI_PROXY_POLICY_VERSION:
        _fail("decision contract version mismatch")
    if data["input_evidence_package_sha256"] != package["evidence_package_sha256"] or data["prohibited_field_audit_sha256"] != package["prohibited_field_audit_sha256"]:
        _fail("decision package/audit hash mismatch")
    source_hashes = data["source_artifact_hashes"]
    if not isinstance(source_hashes, Mapping) or not source_hashes:
        _fail("decision source_artifact_hashes must be nonempty")
    for name, digest in source_hashes.items():
        if not isinstance(name, str):
            _fail("decision source artifact name must be a string")
        _sha(digest, f"decision source_artifact_hashes[{name}]")
    _timestamp(data["review_timestamp"], "review_timestamp")
    if isinstance(data["label_version"], bool) or not isinstance(data["label_version"], int) or data["label_version"] < 1:
        _fail("label_version must be integer >= 1")
    if data["candidate_label"] in {"ATTACK", "BENIGN"}:
        if not evidence or data["evidence_sufficiency"] != "SUFFICIENT_FOR_PROXY_BINARY" or data["decision_certainty"] not in {"HIGH", "MEDIUM"}:
            _fail("binary proxy labels require sufficient evidence and HIGH/MEDIUM certainty")
        if all(item.startswith("source_observation_fields/") for item in evidence):
            _fail("source observation alone cannot create a binary proxy label")
    if data["candidate_label"] == "UNCERTAIN":
        if data["evidence_sufficiency"] == "SUFFICIENT_FOR_PROXY_BINARY" or data["decision_certainty"] == "HIGH":
            _fail("UNCERTAIN cannot claim sufficient binary evidence")
    if data["decision_certainty"] == "LOW" and data["candidate_label"] != "UNCERTAIN":
        _fail("LOW certainty requires UNCERTAIN")
    if not evidence and data["candidate_label"] != "UNCERTAIN":
        _fail("empty evidence is allowed only for UNCERTAIN")


class AIProxyReviewer:
    """Run exactly two independently submitted model responses and finalize mechanically."""

    def __init__(self, *, runtime_registration: Mapping[str, object], model_call: Callable[[str, Mapping[str, object]], Mapping[str, object]]):
        validate_runtime_registration(runtime_registration)
        self.runtime_registration = dict(runtime_registration)
        self.model_call = model_call

    def review(self, package: Mapping[str, object]) -> dict[str, object]:
        validate_evidence_package(package)
        decisions: list[dict[str, object]] = []
        for pass_id in ("PASS_A", "PASS_B"):
            try:
                response = dict(self.model_call(pass_id, package))
                response["pass_id"] = pass_id
                validate_proxy_decision(response, package, self.runtime_registration)
                decisions.append(response)
            except (AIProxyValidationError, TypeError, ValueError) as error:
                return self._incomplete(package, decisions, str(error))
        first, second = decisions
        if first["candidate_label"] == second["candidate_label"] and first["candidate_label"] in {"ATTACK", "BENIGN"}:
            label = first["candidate_label"]
            resolution = "RESOLVED"
            reason = "Both independent proxy passes satisfied the frozen binary rubric."
        elif first["candidate_label"] == second["candidate_label"] == "UNCERTAIN":
            label = "UNCERTAIN"
            resolution = "RESOLVED"
            reason = "Both independent proxy passes returned UNCERTAIN."
        else:
            label = "UNCERTAIN"
            resolution = "RESOLVED"
            reason = "AI_PASS_DISAGREEMENT; conservative UNCERTAIN finalization."
        return self._label_record(package, decisions, label, resolution, reason)

    def _incomplete(self, package: Mapping[str, object], decisions: list[dict[str, object]], reason: str) -> dict[str, object]:
        return self._label_record(package, decisions, None, "REVIEW_INCOMPLETE", reason)

    def _label_record(self, package: Mapping[str, object], decisions: list[dict[str, object]], label: str | None, resolution: str, reason: str) -> dict[str, object]:
        ids = sorted(str(item["proxy_decision_id"]) for item in decisions)
        eligible = label in {"ATTACK", "BENIGN"} and resolution == "RESOLVED" and len(ids) == 2
        payload: dict[str, object] = {
            "schema_version": "1.1",
            "label": label,
            "resolution_status": resolution,
            "source_record_identity_sha256": package["source_record_identity_sha256"],
            "annotation_unit_id": package["annotation_unit_id"],
            "evidence_package_id": package["evidence_package_id"],
            "evidence_package_sha256": package["evidence_package_sha256"],
            "proxy_decision_ids": ids,
            "label_provenance": AI_PROXY_LABEL_PROVENANCE,
            "human_verified": False,
            "finalized_by_actor_type": "AI_PROXY_WORKFLOW",
            "adjudication_status": "NOT_APPLICABLE_AI_PROXY",
            "decision_reason": reason,
            "proxy_supervised_training_eligible": eligible,
            "primary_training_eligible": eligible and False,
            "reference_label_scope": "AI_PROXY_REFERENCE",
            "label_version": 1,
        }
        payload["label_record_id"] = f"LR-{sha256_hex(payload)}"
        return payload

    @staticmethod
    def validate_final_label(record: Mapping[str, object]) -> None:
        if record.get("label_provenance") != AI_PROXY_LABEL_PROVENANCE:
            _fail("AI proxy final label provenance cannot be upgraded")
        if record.get("human_verified") is not False:
            _fail("AI proxy final label cannot claim human verification")
        if record.get("finalized_by_actor_type") != "AI_PROXY_WORKFLOW":
            _fail("AI proxy finalizer must be AI_PROXY_WORKFLOW")
        if record.get("adjudication_status") != "NOT_APPLICABLE_AI_PROXY":
            _fail("AI proxy labels cannot claim human adjudication")
        if record.get("label") not in {"ATTACK", "BENIGN", "UNCERTAIN", None}:
            _fail("invalid final proxy label")


def append_proxy_label_history(path: str | Path, record: Mapping[str, object]) -> None:
    """Append one immutable record; duplicate lineage cannot overwrite history."""

    AIProxyReviewer.validate_final_label(record)
    destination = Path(path)
    existing: list[dict[str, object]] = []
    if destination.exists():
        try:
            existing = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines() if line]
        except (OSError, json.JSONDecodeError) as error:
            _fail(f"immutable label history is unreadable: {error}")
        if any(item.get("label_record_id") == record.get("label_record_id") for item in existing):
            _fail("immutable label history cannot be overwritten")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def select_train_pilot_records(rows: Sequence[Mapping[str, object]], *, seed: int = 21012100, limit: int = 20) -> list[Mapping[str, object]]:
    """Select a label-blind deterministic TRAIN-only pilot by source identity/order."""

    if limit < 1 or limit > 20:
        _fail("pilot limit must be between 1 and 20")
    candidates = [row for row in rows if row.get("split_assignment") == "TRAIN"]
    ordered: list[tuple[str, Mapping[str, object]]] = []
    for row in candidates:
        identity = row.get("source_record_identity_sha256")
        if not isinstance(identity, str) or not _SHA256.fullmatch(identity):
            number = row.get("source_record_number")
            if not isinstance(number, int) or isinstance(number, bool) or number < 1:
                _fail("pilot rows require source identity or positive record number")
            identity = f"record:{number}"
        ordered.append((digest_order("stage-2.1-train-pilot-v1", seed, identity)[0], row))
    ordered.sort(key=lambda item: item[0])
    return [row for _, row in ordered[:limit]]
