from __future__ import annotations

import json

import pytest

from labeling.evidence import DEFAULT_OPERATIONAL_FIELDS, build_blinded_review_payload
from labeling.artifact import write_json_no_replace, validate_public_bundle
from labeling.contracts import build_contracts
from labeling.grouping import build_group_rows, build_hard_components, evaluate_tier_feasibility, select_entity_tier
from labeling.history import append_label_version, resolve_label_history
from labeling.identity import annotation_unit_id, canonical_json_bytes, source_record_identity
from labeling.models import LabelRecord, LabelValue, Provenance, ResolutionStatus
from labeling.sampling import allocate_hybrid, assign_validation_purpose
from labeling.splitting import assign_group_split, build_split_rows
from labeling.transformation_contract import FEATURE_NAMES, FitScope, validate_fit_scope
from labeling.workflow import InvalidTransition, transition
from prepare_stage_2_1 import Stage21Blocker, check_execution_preconditions


def test_source_identity_uses_full_sha256_and_typed_canonical_values() -> None:
    digest = source_record_identity(
        "a" * 64,
        1,
        "LOG_1",
    )
    assert len(digest) == 64
    assert digest == source_record_identity("a" * 64, 1, "LOG_1")
    assert annotation_unit_id(digest) == f"AU-{digest}"
    assert canonical_json_bytes(["x", 1]) == b'["x",1]'


def test_primary_blinded_payload_excludes_model_and_sampling_fields() -> None:
    payload = build_blinded_review_payload(
        annotation_unit_id="AU-" + "a" * 64,
        evidence_package_id="EP-1",
        operational_fields={"src_ip": "SRCIP_x", "net_proto": 6},
        detector_panel_available=True,
        external_evidence_reference_ids=[],
    )
    assert set(payload["allowed_operational_fields"]) == set(DEFAULT_OPERATIONAL_FIELDS)
    forbidden = json.dumps(payload)
    assert "anomaly_score" not in forbidden
    assert "sampling_stratum" not in forbidden
    assert "split_assignment" not in forbidden


def test_label_history_correction_is_append_only_and_resolves_latest_version() -> None:
    dataset = "a" * 64
    identity = source_record_identity(dataset, 1, "SOURCE_RECORD_TEST")
    first = LabelRecord.new(
        dataset_sha256=dataset,
        annotation_unit_id=annotation_unit_id(identity),
        label=LabelValue.ATTACK,
        resolution_status=ResolutionStatus.RESOLVED,
        provenance=Provenance.HUMAN_ANALYST_ADJUDICATED,
        parent_label_record_id=None,
    )
    second = append_label_version(first, label=LabelValue.UNCERTAIN)
    assert second.label_version == 2
    assert second.parent_label_record_id == first.label_record_id
    assert resolve_label_history([first, second]) == second
    with pytest.raises(ValueError, match="parent"):
        append_label_version(first, label=LabelValue.BENIGN, version=3)


def test_invalid_review_transition_is_rejected() -> None:
    with pytest.raises(InvalidTransition):
        transition("PENDING", "RESOLVED", actor_type="PRIMARY_REVIEWER")


def test_sampling_allocation_and_validation_purpose_are_deterministic() -> None:
    allocation = allocate_hybrid({"a": 80, "b": 20}, 10)
    assert allocation == {"a": 7, "b": 3}
    assert assign_validation_purpose("group-1") == assign_validation_purpose("group-1")
    assert assign_validation_purpose("group-1") in {
        "VALIDATION_U",
        "VALIDATION_S",
        "VALIDATION_CHAIN",
    }


def test_group_split_is_deterministic_and_uses_frozen_bucket_boundaries() -> None:
    assert assign_group_split("G-1") == assign_group_split("G-1")
    assert assign_group_split("G-1") in {"TRAIN", "VALIDATION", "TEST"}


def test_transformation_protocol_rejects_held_out_fit_scope() -> None:
    assert len(FEATURE_NAMES) == 36
    assert validate_fit_scope(FitScope.TRAIN_FULL) is None
    with pytest.raises(ValueError, match="forbidden"):
        validate_fit_scope("FULL_DATASET")


def test_grouping_unions_same_session_and_exact_near_duplicate_components() -> None:
    rows = build_group_rows(
        [
            {"source_record_number": 1, "source_record_id": "R1", "session": "S1", "src": "SRC1", "dst": "DST1", "host": "H1", "payload": "same"},
            {"source_record_number": 2, "source_record_id": "R2", "session": "S1", "src": "SRC2", "dst": "DST2", "host": "H2", "payload": "other"},
            {"source_record_number": 3, "source_record_id": "R3", "session": "S3", "src": "SRC3", "dst": "DST3", "host": "H3", "payload": "different"},
        ],
        dataset_sha256="c" * 64,
    )
    components = build_hard_components(rows)
    assert components[rows[0].source_record_identity_sha256] == components[rows[1].source_record_identity_sha256]
    assert components[rows[0].source_record_identity_sha256] != components[rows[2].source_record_identity_sha256]
    selected = select_entity_tier(rows, "HARD_GROUP_ONLY")
    assert selected.selected_tier == "HARD_GROUP_ONLY"
    assert len(selected.groups) == 2


def test_split_rows_assign_each_group_once_and_preserve_members() -> None:
    rows = build_group_rows(
        [
            {"source_record_number": 1, "source_record_id": "R1", "session": "S1", "src": "SRC1", "dst": "DST1", "host": "H1", "payload": "x"},
            {"source_record_number": 2, "source_record_id": "R2", "session": "S1", "src": "SRC2", "dst": "DST2", "host": "H2", "payload": "y"},
        ],
        dataset_sha256="d" * 64,
    )
    selected = select_entity_tier(rows, "ENTITY_SOURCE_HOST")
    split_rows = build_split_rows(rows, selected)
    assert len(split_rows) == 2
    assert split_rows[0]["split_assignment"] == split_rows[1]["split_assignment"]
    assert split_rows[0]["group_id"] == split_rows[1]["group_id"]


def test_group_feasibility_reports_measured_split_support_without_moving_rows() -> None:
    rows = build_group_rows(
        [
            {"source_record_number": 1, "source_record_id": "R1", "session": "S1", "src": "SRC1", "dst": "DST1", "host": "H1", "payload": "x"},
            {"source_record_number": 2, "source_record_id": "R2", "session": "S2", "src": "SRC2", "dst": "DST2", "host": "H2", "payload": "y"},
            {"source_record_number": 3, "source_record_id": "R3", "session": "S3", "src": "SRC3", "dst": "DST3", "host": "H3", "payload": "z"},
        ],
        dataset_sha256="f" * 64,
    )
    selected = select_entity_tier(rows, "HARD_GROUP_ONLY")
    report = evaluate_tier_feasibility(rows, selected)
    assert report["row_count"] == 3
    assert report["selected_tier"] == "HARD_GROUP_ONLY"
    assert report["status"] == "FAIL"
    assert "MINIMUM_GROUP_COUNT" in report["failed_criteria"]


def test_contract_payloads_bind_approved_plan_and_frozen_feature_definition() -> None:
    contracts = build_contracts("e" * 64)
    assert contracts["evaluation_charter"]["schema_version"] == "1.0"
    assert contracts["evaluation_charter"]["primary_estimand_id"] == "WEIGHTED_AVERAGE_PRECISION_RESOLVED_ELIGIBLE_TEST"
    assert contracts["transformation_protocol"]["feature_names"] == list(FEATURE_NAMES)
    assert contracts["annotation_contract"]["master_plan_sha256"] == "2465a29e52174c679d88c1f88128e14b34d2a56b79d6495f7096602af33b69a7"


def test_public_bundle_writer_refuses_replacement_and_test_label_files(tmp_path) -> None:
    destination = tmp_path / "bundle"
    destination.mkdir()
    write_json_no_replace(destination / "contracts" / "x.json", {"ok": True})
    with pytest.raises(FileExistsError):
        write_json_no_replace(destination / "contracts" / "x.json", {"ok": True})
    (destination / "labels").mkdir()
    (destination / "labels" / "test_resolved_labels.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="TEST"):
        validate_public_bundle(destination)


def test_stage_2_1_execution_blocks_before_review_without_custodian_and_reviewers(tmp_path) -> None:
    with pytest.raises(Stage21Blocker, match="reviewer"):
        check_execution_preconditions(
            private_root=tmp_path / "private",
            reviewer_registry=None,
            external_evidence_registry=None,
        )
