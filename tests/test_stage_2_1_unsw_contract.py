from __future__ import annotations

import pytest

from benchmarks.unsw_contract import (
    BINARY_TARGET_FIELD,
    BRANCH_ID,
    DATASET_ID,
    EXPECTED_OFFICIAL_FILES,
    PROCESSED_ROOT,
    RAW_ROOT,
    TEST_POLICY,
    acquisition_readiness,
    build_contract_template,
    canonical_binary_target,
    validate_contract,
    validate_feature_allowlist,
)


def _complete_contract() -> dict[str, object]:
    payload = build_contract_template()
    payload["source"] = {
        "source_name": "<HUMAN_APPROVED_SOURCE>",
        "source_version": "<HUMAN_APPROVED_VERSION>",
        "source_uri": "<HUMAN_APPROVED_URI>",
        "license_record": "<HUMAN_APPROVED_LICENSE_RECORD>",
        "human_approved": True,
    }
    for entry in payload["files"]:  # type: ignore[index]
        entry["sha256"] = "a" * 64
        entry["byte_size"] = 1
        entry["row_count"] = 1
    return payload


def test_template_freezes_identity_paths_files_and_test_lock() -> None:
    payload = build_contract_template()
    assert payload["dataset_id"] == DATASET_ID == "UNSW_NB15_BENCHMARK"
    assert payload["branch_id"] == BRANCH_ID == "BRANCH_B_LABELED_BENCHMARK"
    assert payload["raw_root"] == RAW_ROOT.as_posix()
    assert payload["processed_root"] == PROCESSED_ROOT.as_posix()
    assert payload["test_policy"] == TEST_POLICY == "LOCKED_FROM_MODEL_SELECTION"
    assert [item["filename"] for item in payload["files"]] == list(EXPECTED_OFFICIAL_FILES.values())  # type: ignore[index]
    assert payload["preprocessing_fit_scope"] == "TRAIN_OR_FOLD_LOCAL_ONLY"


def test_contract_requires_approved_source_and_sha256_file_manifest() -> None:
    with pytest.raises(ValueError, match="source"):
        validate_contract(build_contract_template())
    payload = _complete_contract()
    assert validate_contract(payload)["status"] == "PASS"
    payload["files"][0]["sha256"] = "not-a-sha"  # type: ignore[index]
    with pytest.raises(ValueError, match="sha256"):
        validate_contract(payload)


def test_binary_target_mapping_is_only_normal_or_attack() -> None:
    assert canonical_binary_target(0) == "NORMAL"
    assert canonical_binary_target("1") == "ATTACK"
    assert canonical_binary_target("NORMAL") == "NORMAL"
    with pytest.raises(ValueError, match="target"):
        canonical_binary_target("UNKNOWN")


def test_target_and_attack_category_are_denied_as_features() -> None:
    assert validate_feature_allowlist(["srcip", "dur"])["status"] == "PASS"
    with pytest.raises(ValueError, match="denylist"):
        validate_feature_allowlist(["srcip", BINARY_TARGET_FIELD])
    with pytest.raises(ValueError, match="denylist"):
        validate_feature_allowlist(["attack_cat"])


def test_contract_rejects_cross_branch_or_unlocked_test_changes() -> None:
    payload = _complete_contract()
    payload["dataset_id"] = "FORTIGATE_REAL_LOG"
    with pytest.raises(ValueError, match="dataset_id"):
        validate_contract(payload)
    payload = _complete_contract()
    payload["test_policy"] = "OPEN"
    with pytest.raises(ValueError, match="TEST"):
        validate_contract(payload)


def test_contract_declares_duplicate_and_leakage_fail_closed_policies() -> None:
    payload = build_contract_template()
    assert payload["duplicate_policy"]["cross_split_overlap"] == "BLOCK_INGESTION"  # type: ignore[index]
    assert payload["duplicate_policy"]["silent_delete_or_move"] is False  # type: ignore[index]
    assert "attack_cat" in payload["feature_denylist"]  # type: ignore[operator]
    assert payload["leakage_policy"]["target_conflicting_duplicate"] == "BLOCK"  # type: ignore[index]


def test_acquisition_readiness_blocks_until_official_files_exist(tmp_path) -> None:
    payload = _complete_contract()
    payload["source"] = {
        "source_name": "approved-test-source",
        "source_version": "approved-test-version",
        "source_uri": "approved-test-uri",
        "license_record": "approved-test-license-record",
        "human_approved": True,
    }
    result = acquisition_readiness(payload, tmp_path)
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "required official files missing"
