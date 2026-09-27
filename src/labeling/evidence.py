"""Stage 2.1 evidence allowlists and primary-review blinding."""

from __future__ import annotations

from collections.abc import Mapping

from .identity import sha256_hex


DEFAULT_OPERATIONAL_FIELDS = (
    "itime", "data_timestamp", "data_parsername", "data_sourceid",
    "data_sourcename", "data_sourcetype", "src_geo", "src_intf", "src_ip",
    "src_mac", "src_port", "src_natip", "src_natport", "src_domain",
    "dst_geo", "dst_intf", "dst_ip", "dst_mac", "dst_port", "net_proto",
    "net_rcvdpkts", "net_recvbytes", "net_sentbytes", "net_sentpkts",
    "net_sessionduration", "net_sessionid", "app_cat", "app_service", "app_id",
    "app_name", "host_ip", "host_location", "host_mac", "host_type",
    "host_hwvendor", "host_hwver", "host_osfamily", "host_osname", "host_osver",
    "host_name", "epid", "euid", "adom_oid",
)
DEFAULT_DETECTOR_FIELDS = (
    "event_action", "event_id", "event_severity", "event_subtype", "event_type",
    "event_profile", "event_message", "threat_action", "threat_name",
    "threat_severity", "threat_type", "threat_pattern", "threat_id", "threat_ref",
    "stage_1_4_rule_ids", "stage_1_4_source_threat_observation",
)
PROHIBITED_REVIEW_FIELDS = frozenset(
    {
        "anomaly_score", "raw_abnormality", "anomaly_rank", "anomaly_band",
        "top_50", "suspected_behaviors", "suspected_attack_type", "evidence_strength",
        "auto_triage", "investigation_priority", "review_label", "sampling_stratum",
        "selection_probability", "split_assignment", "cohort", "label_yield",
    }
)


class BlindingError(ValueError):
    """Raised when a primary review payload exposes prohibited evidence."""


def build_blinded_review_payload(
    *,
    annotation_unit_id: str,
    evidence_package_id: str,
    operational_fields: Mapping[str, object],
    detector_panel_available: bool,
    external_evidence_reference_ids: list[str],
) -> dict[str, object]:
    """Build reviewer-visible payload with only approved operational fields."""

    if not isinstance(operational_fields, Mapping):
        raise BlindingError("operational_fields must be a mapping")
    unknown = set(operational_fields) - set(DEFAULT_OPERATIONAL_FIELDS)
    if unknown:
        raise BlindingError(f"operational field not allowlisted: {sorted(unknown)!r}")
    if any(field in PROHIBITED_REVIEW_FIELDS for field in operational_fields):
        raise BlindingError("prohibited model or sampling field exposed")
    fields = {name: operational_fields.get(name) for name in DEFAULT_OPERATIONAL_FIELDS}
    payload = {
        "schema_version": "1.0",
        "annotation_unit_id": annotation_unit_id,
        "evidence_package_id": evidence_package_id,
        "allowed_operational_fields": fields,
        "detector_panel_available": bool(detector_panel_available),
        "external_evidence_reference_ids": sorted(set(external_evidence_reference_ids)),
    }
    payload["forbidden_field_audit_sha256"] = sha256_hex(
        {"prohibited_fields": sorted(PROHIBITED_REVIEW_FIELDS), "present": []}
    )
    return payload


def assert_blinded_payload(payload: Mapping[str, object]) -> None:
    """Reject model/sampling fields anywhere in a reviewer payload."""

    def walk(value: object, path: str = "") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in PROHIBITED_REVIEW_FIELDS:
                    raise BlindingError(f"prohibited field exposed at {path}/{key}")
                walk(child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}")

    walk(payload)
