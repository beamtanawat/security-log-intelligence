from __future__ import annotations

import copy
from pathlib import Path

import pytest

from labeling.ai_proxy import (
    AIProxyValidationError,
    AIProxyReviewer,
    append_proxy_label_history,
    build_evidence_package,
    build_runtime_registration,
    select_train_pilot_records,
    validate_proxy_decision,
)
from labeling.identity import sha256_hex, source_record_identity


DATASET_SHA256 = "c" * 64
PROMPT_VERSION = "stage_2_1_ai_proxy_prompt/1.0"
RUBRIC_VERSION = "stage_2_1_ai_proxy_rubric/1.0"
POLICY_VERSION = "stage_2_1_ai_proxy_labeling_policy/1.0"


def _event(record_number: int = 1) -> dict[str, object]:
    source_id = f"LOG_{record_number}"
    return {
        "schema_version": "1.0",
        "source": {"record_number": record_number, "adapter_type": "fortigate"},
        "event": {"action_source": "allow", "type_source": "traffic"},
        "time": {"itime_raw": "1729335721"},
        "network": {"protocol_name": "TCP", "source": {"port": 443}, "destination": {"port": 80}},
        "application": {"service_source": "HTTP"},
        "session": {"sent_bytes": 10, "received_bytes": 20},
        "host": {"identifier": "HOST_1"},
        "threat_observations": {"name_source": None},
        "source_record": {
            "loguid": source_id,
            "event_action": "allow",
            "event_type": "traffic",
            "src_ip": "SRC_1",
            "dst_ip": "DST_1",
            "app_service": "HTTP",
        },
        "unmapped_fields": {},
        "provenance": [],
        "normalization_issues": [],
    }


def _package(record_number: int = 1) -> dict[str, object]:
    identity = source_record_identity(DATASET_SHA256, record_number, f"LOG_{record_number}")
    return build_evidence_package(
        _event(record_number),
        dataset_sha256=DATASET_SHA256,
        source_record_identity_sha256=identity,
        source_artifact_hashes={"normalized_input": "d" * 64, "split_manifest": "e" * 64},
    )


def _registration() -> dict[str, object]:
    payload = {
        "schema_version": "1.0",
        "provider_id": "synthetic-test-provider",
        "model_id": "synthetic-test-model",
        "model_revision": "test-revision",
        "config_id": "synthetic-test-config",
        "temperature": 0,
        "top_p": 1,
        "max_output_tokens": 800,
        "response_format": "JSON_SCHEMA_STRICT",
        "tool_access": "NONE",
        "retrieval_access": "NONE",
        "seed_support": "UNAVAILABLE_RECORDED",
        "human_approved": True,
        "approval_timestamp": "2026-09-26T00:00:00+00:00",
    }
    return build_runtime_registration(payload)


def _decision(package: dict[str, object], label: str, *, evidence: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "output_schema_version": "stage_2_1_ai_proxy_decision/1.0",
        "proxy_decision_id": "APD-" + "0" * 64,
        "annotation_unit_id": package["annotation_unit_id"],
        "source_record_identity_sha256": package["source_record_identity_sha256"],
        "pass_id": "PASS_A",
        "candidate_label": label,
        "evidence_used": evidence if evidence is not None else ["operational_fields/app_service"],
        "evidence_summary": "Permitted record evidence was reviewed.",
        "decision_reason": "The frozen proxy rubric was applied conservatively.",
        "decision_certainty": "MEDIUM" if label != "UNCERTAIN" else "LOW",
        "evidence_sufficiency": "SUFFICIENT_FOR_PROXY_BINARY" if label != "UNCERTAIN" else "INSUFFICIENT",
        "label_provenance": "AI_ASSISTED_PROXY_LABEL",
        "labeler_model_id": "synthetic-test-model",
        "labeler_model_revision": "test-revision",
        "labeler_config_id": "synthetic-test-config",
        "labeler_prompt_version": PROMPT_VERSION,
        "labeler_rubric_version": RUBRIC_VERSION,
        "labeler_policy_version": POLICY_VERSION,
        "input_evidence_package_sha256": package["evidence_package_sha256"],
        "source_artifact_hashes": {"normalized_input": "d" * 64, "split_manifest": "e" * 64},
        "prohibited_field_audit_sha256": package["prohibited_field_audit_sha256"],
        "review_timestamp": "2026-09-26T00:00:00+00:00",
        "label_version": 1,
    }


def _reseal_decision(decision: dict[str, object]) -> dict[str, object]:
    decision["proxy_decision_id"] = "APD-" + sha256_hex(
        {key: value for key, value in decision.items() if key != "proxy_decision_id"}
    )
    return decision


def _reviewer(label: str, package: dict[str, object]) -> AIProxyReviewer:
    decisions = []

    def model_call(pass_id: str, _: dict[str, object]) -> dict[str, object]:
        item = _decision(package, label)
        item["pass_id"] = pass_id
        item["proxy_decision_id"] = "APD-" + sha256_hex(
            {key: value for key, value in item.items() if key != "proxy_decision_id"}
        )
        decisions.append(item)
        return item

    return AIProxyReviewer(runtime_registration=_registration(), model_call=model_call)


def test_valid_attack_proxy_output_preserves_ai_provenance() -> None:
    package = _package()
    result = _reviewer("ATTACK", package).review(package)
    assert result["label"] == "ATTACK"
    assert result["label_provenance"] == "AI_ASSISTED_PROXY_LABEL"
    assert len(result["proxy_decision_ids"]) == 2


def test_valid_benign_proxy_output_is_not_confirmatory() -> None:
    result = _reviewer("BENIGN", _package()).review(_package())
    assert result["label"] == "BENIGN"
    assert result["label_provenance"] == "AI_ASSISTED_PROXY_LABEL"
    assert result["human_verified"] is False


def test_valid_uncertain_output_is_low_certainty_and_not_binary_eligible() -> None:
    package = _package()
    result = _reviewer("UNCERTAIN", package).review(package)
    assert result["label"] == "UNCERTAIN"
    assert result["proxy_supervised_training_eligible"] is False


def test_prohibited_evidence_is_rejected_before_inference() -> None:
    event = _event()
    event["source_record"]["anomaly_rank"] = "1"  # type: ignore[index]
    with pytest.raises(AIProxyValidationError, match="prohibited"):
        build_evidence_package(
            event,
            dataset_sha256=DATASET_SHA256,
            source_record_identity_sha256=source_record_identity(DATASET_SHA256, 1, "LOG_1"),
            source_artifact_hashes={"normalized_input": "d" * 64},
        )


def test_anomaly_rank_cannot_be_used_as_evidence() -> None:
    package = _package()
    decision = _reseal_decision(_decision(package, "UNCERTAIN", evidence=["operational_fields/anomaly_rank"]))
    with pytest.raises(AIProxyValidationError, match="prohibited"):
        validate_proxy_decision(decision, package, _registration())


def test_source_threat_observation_alone_cannot_create_attack() -> None:
    package = _package()
    decision = _reseal_decision(_decision(package, "ATTACK", evidence=["source_observation_fields/threat_name"]))
    with pytest.raises(AIProxyValidationError, match="source observation"):
        validate_proxy_decision(decision, package, _registration())


def test_missing_evidence_can_produce_uncertain() -> None:
    package = _package()
    decision = _decision(package, "UNCERTAIN", evidence=[])
    decision["proxy_decision_id"] = "APD-" + sha256_hex(
        {key: value for key, value in decision.items() if key != "proxy_decision_id"}
    )
    validate_proxy_decision(decision, package, _registration())


def test_ai_proxy_uncertain_is_ineligible_for_binary_fitting() -> None:
    package = _package()
    result = _reviewer("UNCERTAIN", package).review(package)
    assert result["proxy_supervised_training_eligible"] is False
    assert result["primary_training_eligible"] is False


def test_ai_provenance_cannot_be_upgraded() -> None:
    package = _package()
    result = _reviewer("ATTACK", package).review(package)
    result["label_provenance"] = "HUMAN_ANALYST_ADJUDICATED"
    with pytest.raises(AIProxyValidationError, match="provenance"):
        AIProxyReviewer.validate_final_label(result)


def test_label_history_rerun_cannot_overwrite_immutable_history(tmp_path: Path) -> None:
    package = _package()
    result = _reviewer("BENIGN", package).review(package)
    history = tmp_path / "label_history.jsonl"
    append_proxy_label_history(history, result)
    with pytest.raises(AIProxyValidationError, match="immutable"):
        append_proxy_label_history(history, result)


def test_train_pilot_selection_is_deterministic_and_capped_at_twenty() -> None:
    rows = [{"source_record_number": n, "split_assignment": "TRAIN"} for n in range(1, 40)]
    rows.extend({"source_record_number": n, "split_assignment": "VALIDATION"} for n in range(40, 45))
    first = select_train_pilot_records(rows, seed=21012100, limit=20)
    second = select_train_pilot_records(rows, seed=21012100, limit=20)
    assert first == second
    assert len(first) == 20
    assert all(row["split_assignment"] == "TRAIN" for row in first)
