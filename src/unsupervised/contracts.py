"""Stage 2.2A UNSW identity and feature-contract definitions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


DATASET_ID = "UNSW_NB15_BENCHMARK"
BRANCH_ID = "BRANCH_B_LABELED_BENCHMARK"
CONTRACT_VERSION = "stage_2.2a-unsw-contract/1.0"
SOURCE_SPLIT = "TRAIN"

NUMERIC_FEATURES = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
)
CATEGORICAL_FEATURES = ("proto", "service", "state")
FEATURE_ORDER = NUMERIC_FEATURES + CATEGORICAL_FEATURES
EXCLUDED_FIELDS = (
    "id",
    "label",
    "attack_cat",
    "stcpb",
    "dtcpb",
    "is_ftp_login",
    "is_sm_ips_ports",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_src_ltm",
    "ct_srv_dst",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "row_id",
    "source_record_id",
    "official_split",
    "development_partition",
    "split_id",
    "target",
    "binary_target",
    "predicted_label",
    "anomaly_score",
    "anomaly_rank",
    "auto_triage",
    "post_outcome",
)


def build_feature_contract() -> dict[str, Any]:
    """Return the frozen UNSW 2.2A feature/exclusion specification."""

    return {
        "schema_version": CONTRACT_VERSION,
        "dataset_id": DATASET_ID,
        "branch_id": BRANCH_ID,
        "numeric_features": list(NUMERIC_FEATURES),
        "categorical_features": list(CATEGORICAL_FEATURES),
        "feature_order": list(FEATURE_ORDER),
        "excluded_fields": list(EXCLUDED_FIELDS),
        "target_field": "label",
        "attack_category_field": "attack_cat",
        "target_policy": "EXCLUDED_FROM_UNSUPERVISED_FEATURES",
        "attack_category_policy": "PRESERVE_RAW_SEPARATE_NON_FEATURE",
        "identifier_policy": "SOURCE_ID_AUDIT_ONLY",
        "unknown_field_policy": "REJECT",
        "numeric_policy": {
            "blank": "MISSING",
            "invalid_nan_inf_negative": "BLOCK",
            "transform": "LOG1P",
            "imputation": "TRAIN_INTERNAL_MEDIAN_LOG_SPACE_ALL_MISSING_ZERO",
            "scaling": "STANDARD_SCALER_POPULATION_VARIANCE_ZERO_SCALE_ONE",
            "missing_indicator": "APPEND_UNSCALED_IN_NUMERIC_ORDER",
        },
        "categorical_policy": {
            "vocabulary": "SORTED_TRAIN_INTERNAL_VALUES",
            "reserved_channels": ["MISSING", "UNKNOWN"],
            "unseen": "UNKNOWN",
            "encoding": "ONE_HOT_NO_DUMMY_DROP_NO_SCALING",
        },
        "fit_boundary": "TRAIN_INTERNAL_ONLY",
        "test_policy": "STRUCTURAL_ONLY_UNTIL_ISOLATED_LOCKED_READER",
        "max_output_columns": 512,
    }


def validate_input_identities(
    rows: Iterable[Mapping[str, object]],
    dataset_id: str,
    branch_id: str,
) -> None:
    """Reject mixed branches and any TEST rows at a development boundary."""

    for row in rows:
        if row.get("dataset_id") != dataset_id:
            raise ValueError("dataset identity mismatch")
        if row.get("branch_id") != branch_id:
            raise ValueError("branch identity mismatch")
        official_split = row.get("official_split")
        if official_split == "TEST":
            raise ValueError("official TEST rows are not available to development code")
        if official_split not in {None, SOURCE_SPLIT}:
            raise ValueError(f"unsupported official split: {official_split}")
