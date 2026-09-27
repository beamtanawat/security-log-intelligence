"""Machine-readable Stage 2.1 contract payloads."""

from __future__ import annotations

from .evidence import DEFAULT_DETECTOR_FIELDS, DEFAULT_OPERATIONAL_FIELDS, PROHIBITED_REVIEW_FIELDS
from .identity import sha256_hex
from .transformation_contract import FEATURE_NAMES, transformation_protocol


MASTER_PLAN_SHA256 = "2465a29e52174c679d88c1f88128e14b34d2a56b79d6495f7096602af33b69a7"
STAGE_PLAN_SHA256 = "a94a59ad681d2ee478123dd8b23fed63beb2640aa55edc40583e451026d6a6f8"


def _bind(payload: dict[str, object], key: str) -> dict[str, object]:
    payload = dict(payload)
    payload[key] = f"{key.upper()}-{sha256_hex(payload)}"
    return payload


def build_contracts(dataset_sha256: str) -> dict[str, dict[str, object]]:
    """Return deterministic contract payloads; no label or sample is created."""

    annotation = _bind(
        {
            "schema_version": "1.0",
            "master_plan_sha256": MASTER_PLAN_SHA256,
            "stage_plan_sha256": STAGE_PLAN_SHA256,
            "dataset_sha256": dataset_sha256,
            "annotation_unit": {
                "type": "SOURCE_RECORD",
                "prediction_point": "SOURCE_RECORD_OBSERVATION",
                "propagation": "NONE",
            },
            "identity_rules": {
                "source_record_identity": "stage-2.1-source-record-v1",
                "annotation_unit_prefix": "AU-",
                "hash_algorithm": "SHA-256",
            },
            "label_values": ["ATTACK", "BENIGN", "UNCERTAIN"],
            "resolution_statuses": ["RESOLVED", "EVIDENCE_UNAVAILABLE", "REVIEWER_NONRESPONSE", "DISAGREEMENT_UNRESOLVED", "REVIEW_INCOMPLETE"],
            "provenance_values": ["EXTERNAL_CONFIRMED", "HUMAN_ANALYST_ADJUDICATED", "AI_ASSISTED_HUMAN_VERIFIED", "DETECTOR_DERIVED_PROXY", "AI_ASSISTED_PROXY_LABEL"],
            "primary_provenance": ["EXTERNAL_CONFIRMED", "HUMAN_ANALYST_ADJUDICATED", "AI_ASSISTED_HUMAN_VERIFIED"],
            "workflow_states": ["PENDING", "IN_REVIEW", "REVIEWED", "NEEDS_ADJUDICATION", "ADJUDICATING", "RESOLVED", "CLOSED_UNRESOLVED", "SUPERSEDED"],
            "forbidden_automatic_label_sources": ["anomaly_score", "anomaly_rank", "auto_triage", "rule_match", "threat_status", "absence_of_alert"],
        },
        "contract_id",
    )
    evidence = _bind(
        {
            "schema_version": "1.0",
            "master_plan_sha256": MASTER_PLAN_SHA256,
            "stage_plan_sha256": STAGE_PLAN_SHA256,
            "dataset_sha256": dataset_sha256,
            "prediction_point": "SOURCE_RECORD_OBSERVATION",
            "window_basis": "RECORD_ONLY",
            "operational_field_allowlist": list(DEFAULT_OPERATIONAL_FIELDS),
            "detector_field_allowlist": list(DEFAULT_DETECTOR_FIELDS),
            "prohibited_field_registry": sorted(PROHIBITED_REVIEW_FIELDS),
            "future_information_rule": "NO_POST_CUTOFF_OR_ADJACENT_RECORD_EVIDENCE",
            "missing_evidence_rule": "UNCERTAIN_OR_EVIDENCE_UNAVAILABLE",
            "primary_blinding": True,
        },
        "policy_id",
    )
    charter = _bind(
        {
            "schema_version": "1.0",
            "master_plan_sha256": MASTER_PLAN_SHA256,
            "stage_plan_sha256": STAGE_PLAN_SHA256,
            "dataset_sha256": dataset_sha256,
            "primary_estimand_id": "WEIGHTED_AVERAGE_PRECISION_RESOLVED_ELIGIBLE_TEST",
            "target_population": "DETERMINISTIC_LOCKED_TEST_SPLIT",
            "evaluation_population": "PROBABILITY_SELECTED_RESOLVED_PRIMARY_ELIGIBLE_TEST",
            "primary_metric": "DESIGN_WEIGHTED_AVERAGE_PRECISION",
            "primary_comparison": "S1_CHAIN_MINUS_BASELINE_IDENTICAL_ROWS",
            "secondary_metrics": ["precision", "recall", "f1", "accuracy", "roc_auc", "tp", "fp", "tn", "fn", "confusion_matrix", "predicted_positive_rate", "coverage"],
            "eligible_provenance": ["EXTERNAL_CONFIRMED", "HUMAN_ANALYST_ADJUDICATED", "AI_ASSISTED_HUMAN_VERIFIED"],
            "weighting": "RAW_RECIPROCAL_COMBINED_REVIEW_INCLUSION_PROBABILITY",
            "uncertainty": {"unit": "SPLIT_GROUP_WITHIN_STRATUM", "method": "PAIRED_STRATIFIED_GROUP_BOOTSTRAP", "replicates": 2000, "seed": 21012500},
            "validation_design": {"purposes": ["VALIDATION_U", "VALIDATION_S", "VALIDATION_CHAIN"], "one_batch_each": True},
            "threshold_policy": "MAXIMIZE_WEIGHTED_F1_TIE_RECALL_PRECISION_RATE_THRESHOLD_CONFIG_HASH",
            "calibration_policy": ["NONE", "SIGMOID_PLATT_TRAIN_FOLDS_ONLY"],
            "test_policy": "ONE_CUSTODIAN_AUTHORIZED_OPENING_AFTER_HASH_FREEZE",
            "tuning_budgets": {"u2_families": 3, "u2_configurations": 12, "s1_families": 2, "s1_configurations": 24, "s2_families": 2, "s2_configurations": 24, "development_cv_folds": 5},
        },
        "charter_id",
    )
    transformation = transformation_protocol()
    transformation.update({"master_plan_sha256": MASTER_PLAN_SHA256, "stage_plan_sha256": STAGE_PLAN_SHA256, "dataset_sha256": dataset_sha256})
    transformation["protocol_id"] = f"stage-2.1-transformation-{sha256_hex(transformation)[:16]}"
    allowlists = _bind(
        {
            "schema_version": "1.0",
            "master_plan_sha256": MASTER_PLAN_SHA256,
            "stage_plan_sha256": STAGE_PLAN_SHA256,
            "dataset_sha256": dataset_sha256,
            "common": [
                "contracts/evaluation_charter.json", "contracts/transformation_protocol.json", "contracts/annotation_contract.json", "contracts/test_seal.json", "manifests/split_manifest.jsonl", "reports/group_leakage_audit.json", "reports/sufficiency_public.json", "manifests/stage_2_1_public_manifest.json",
            ],
            "stage_2_2": ["labels/validation_u_resolved_labels.jsonl", "sampling/validation_u_sampling_manifest.jsonl"],
            "stage_2_3": ["labels/train_resolved_labels.jsonl", "labels/validation_s_resolved_labels.jsonl", "sampling/train_sampling_manifest.jsonl", "sampling/validation_s_sampling_manifest.jsonl"],
            "stage_2_4": ["labels/train_resolved_labels.jsonl", "labels/validation_chain_resolved_labels.jsonl", "sampling/train_sampling_manifest.jsonl", "sampling/validation_chain_sampling_manifest.jsonl"],
            "forbidden": ["private_manifest", "test_label", "test_sampling", "test_review", "sufficiency_test_private", "custodian://"],
        },
        "allowlist_id",
    )
    return {
        "annotation_contract": annotation,
        "evidence_policy": evidence,
        "evaluation_charter": charter,
        "transformation_protocol": transformation,
        "consumer_allowlists": allowlists,
    }


def build_json_schemas() -> dict[str, dict[str, object]]:
    """Return strict root schemas for the public Stage 2.1 contracts."""

    return {
        "annotation_unit.schema.json": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": False, "required": ["schema_version", "contract_id", "dataset_sha256"], "properties": {"schema_version": {"const": "1.0"}, "contract_id": {"type": "string"}, "dataset_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}},
        "label_record.schema.json": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": False, "required": ["schema_version", "label_record_id", "dataset_sha256", "annotation_unit_id", "label", "resolution_status"], "properties": {"schema_version": {"const": "1.0"}, "label_record_id": {"type": "string", "pattern": "^LR-[0-9a-f]{64}$"}, "dataset_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "annotation_unit_id": {"type": "string", "pattern": "^AU-[0-9a-f]{64}$"}, "label": {"type": ["string", "null"], "enum": ["ATTACK", "BENIGN", "UNCERTAIN", None]}, "resolution_status": {"type": "string"}}},
        "sampling_manifest.schema.json": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": False, "required": ["schema_version", "sampling_manifest_row_id", "dataset_sha256", "source_record_number", "split_assignment"], "properties": {"schema_version": {"const": "1.0"}, "sampling_manifest_row_id": {"type": "string", "pattern": "^SM-[0-9a-f]{64}$"}, "dataset_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "source_record_number": {"type": "integer", "minimum": 1}, "split_assignment": {"enum": ["TRAIN", "VALIDATION", "TEST"]}}},
        "split_manifest.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schema_version", "plan_amendment_id", "dataset_sha256", "source_record_number",
                "source_record_id", "source_record_identity_sha256", "annotation_unit_id", "split_assignment",
                "selected_group_tier", "group_id", "hard_component_id", "exact_duplicate_id", "near_duplicate_id",
                "session_group_id", "entity_source_id", "entity_destination_id", "entity_host_id", "time_policy",
                "time_value_present", "split_reason", "allocation_algorithm", "allocation_version",
                "allocation_namespace", "allocation_seed", "allocation_parameters_sha256",
                "allocation_objective_sha256", "balancing_strata_sha256", "group_balance_vector_sha256",
                "group_order_digest", "initial_split_assignment", "final_assignment_action", "repair_iteration",
                "assignment_action_sha256", "sampling_frame_eligible", "leakage_check_status", "source_artifact_sha256s",
            ],
            "properties": {
                "schema_version": {"const": "1.1"},
                "plan_amendment_id": {"const": "S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2"},
                "dataset_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "source_record_number": {"type": "integer", "minimum": 1},
                "source_record_id": {"type": "string", "minLength": 1},
                "source_record_identity_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "annotation_unit_id": {"type": "string", "pattern": "^AU-[0-9a-f]{64}$"},
                "split_assignment": {"enum": ["TRAIN", "VALIDATION", "TEST"]},
                "selected_group_tier": {"const": "HARD_GROUP_ONLY"},
                "group_id": {"type": "string", "minLength": 1},
                "hard_component_id": {"type": "string", "minLength": 1},
                "exact_duplicate_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "near_duplicate_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "session_group_id": {"type": ["string", "null"]},
                "entity_source_id": {"type": ["string", "null"]},
                "entity_destination_id": {"type": ["string", "null"]},
                "entity_host_id": {"type": ["string", "null"]},
                "time_policy": {"const": "NON_TEMPORAL_UNVERIFIED_TIMESTAMPS"},
                "time_value_present": {"type": "boolean"},
                "split_reason": {"const": "HARD_GROUP_STRATIFIED_GREEDY_REPAIR"},
                "allocation_algorithm": {"const": "HARD_GROUP_STRATIFIED_GREEDY_REPAIR_V2"},
                "allocation_version": {"const": "2.0"},
                "allocation_namespace": {"const": "stage-2.1-hard-group-stratified-v2"},
                "allocation_seed": {"const": 21012026},
                "allocation_parameters_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "allocation_objective_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "balancing_strata_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "group_balance_vector_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "group_order_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "initial_split_assignment": {"enum": ["TRAIN", "VALIDATION", "TEST"]},
                "final_assignment_action": {"enum": ["INITIAL_GREEDY", "REPAIR_MOVE", "REPAIR_SWAP"]},
                "repair_iteration": {"type": "integer", "minimum": 0},
                "assignment_action_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "sampling_frame_eligible": {"const": True},
                "leakage_check_status": {"const": "PASS"},
                "source_artifact_sha256s": {"type": "object"},
            },
        },
    }
