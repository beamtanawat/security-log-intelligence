from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from labeling.human_inputs import (
    HumanInputValidationError,
    validate_custodian_acknowledgement,
    validate_external_evidence_registry,
    validate_no_evidence_declaration,
    validate_reviewer_registry,
)


TEMPLATE_ROOT = (
    Path(__file__).parents[1]
    / "data"
    / "processed"
    / "stage_2_1_human_input_templates_v1"
    / "contracts"
)


def _template(name: str) -> dict[str, object]:
    return json.loads((TEMPLATE_ROOT / name).read_text(encoding="utf-8"))


def test_all_four_human_input_templates_validate_with_placeholders() -> None:
    validate_reviewer_registry(_template("reviewer_registry.json"), allow_placeholders=True)
    validate_external_evidence_registry(
        _template("external_evidence_registry.json"), allow_placeholders=True
    )
    validate_no_evidence_declaration(
        _template("no_independent_evidence_declaration.json"), allow_placeholders=True
    )
    validate_custodian_acknowledgement(
        _template("test_custodian_acknowledgement.json"), allow_placeholders=True
    )


def test_reviewer_registry_rejects_unknown_role_and_duplicate_bindings() -> None:
    payload = _template("reviewer_registry.json")
    payload["reviewers"][0]["role"] = "REVIEWER"  # type: ignore[index]
    with pytest.raises(HumanInputValidationError, match="role"):
        validate_reviewer_registry(payload, allow_placeholders=True)

    duplicate = _template("reviewer_registry.json")
    duplicate["reviewers"][1]["person_binding_id"] = duplicate["reviewers"][0][  # type: ignore[index]
        "person_binding_id"
    ]
    with pytest.raises(HumanInputValidationError, match="person_binding_id"):
        validate_reviewer_registry(duplicate, allow_placeholders=True)


def test_external_evidence_registry_rejects_closed_enum_violation() -> None:
    payload = _template("external_evidence_registry.json")
    payload["evidence_items"][0]["availability_classification"] = "PUBLIC"  # type: ignore[index]
    with pytest.raises(HumanInputValidationError, match="availability_classification"):
        validate_external_evidence_registry(payload, allow_placeholders=True)


def test_no_evidence_declaration_rejects_true_availability() -> None:
    payload = _template("no_independent_evidence_declaration.json")
    payload["independent_external_evidence_available"] = True
    with pytest.raises(HumanInputValidationError, match="independent_external_evidence_available"):
        validate_no_evidence_declaration(payload, allow_placeholders=True)


def test_custodian_template_contains_no_secret_field_or_private_path() -> None:
    payload = _template("test_custodian_acknowledgement.json")
    serialized = json.dumps(payload, sort_keys=True)
    assert "seed" not in payload
    assert "SLI_STAGE_2_1_TEST_PRIVATE_ROOT" not in serialized
    assert "/Users/" not in serialized
    assert "-----BEGIN" not in serialized
    validate_custodian_acknowledgement(payload, allow_placeholders=True)


def test_custodian_validator_rejects_secret_field() -> None:
    payload = _template("test_custodian_acknowledgement.json")
    secret_payload = copy.deepcopy(payload)
    secret_payload["seed"] = "not-a-real-seed"
    with pytest.raises(HumanInputValidationError, match="unknown field|secret"):
        validate_custodian_acknowledgement(secret_payload, allow_placeholders=True)

