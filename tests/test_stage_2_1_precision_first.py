from __future__ import annotations

from copy import deepcopy

from labeling.identity import source_record_identity
from labeling.precision_first import (
    BENIGN_RULE_IDS,
    ATTACK_RULE_IDS,
    audit_feature_leakage,
    evaluate_record,
    run_dry_run,
)


DATASET_SHA256 = "c" * 64


def _record(
    number: int,
    *,
    itime: str = "10",
    session: str = "SESSION-1",
    event_type: str = "traffic",
    event_subtype: str = "forward",
    event_action: str = "start",
    event_severity: str = "notice",
    event_message: str = "",
    app_service: str = "HTTP",
    app_id: str = "",
    app_name: str = "",
    app_cat: str = "",
    net_proto: str = "6",
    src_port: str = "1000",
    dst_port: str = "80",
    threat_action: str = "",
    threat_name: str = "",
    threat_severity: str = "",
    threat_type: str = "",
    threat_pattern: str = "",
    threat_id: str = "",
    threat_ref: str = "",
) -> dict[str, object]:
    source_id = f"LOG_{number}"
    return {
        "schema_version": "1.0",
        "source": {"record_number": number, "source_type": "FortiGate"},
        "event": {
            "source_record_id": source_id,
            "action_source": event_action,
            "source_event_id": "13",
            "severity_source": event_severity,
            "subtype_source": event_subtype,
            "type_source": event_type,
            "message_source": event_message or None,
        },
        "time": {"itime_raw": itime},
        "network": {
            "protocol_number": int(net_proto),
            "source": {"port": int(src_port) if src_port else None},
            "destination": {"port": int(dst_port) if dst_port else None},
        },
        "application": {
            "service_source": app_service,
            "id_raw": app_id or None,
            "name_source": app_name or None,
            "category_source": app_cat or None,
        },
        "session": {
            "identifier": session,
            "sent_bytes": 10,
            "received_bytes": 20,
            "sent_packets": 1,
            "received_packets": 2,
            "duration_raw_value": 1,
        },
        "source_record": {
            "loguid": source_id,
            "itime": itime,
            "net_sessionid": session,
            "event_type": event_type,
            "event_subtype": event_subtype,
            "event_action": event_action,
            "event_severity": event_severity,
            "event_message": event_message,
            "app_service": app_service,
            "app_id": app_id,
            "app_name": app_name,
            "app_cat": app_cat,
            "net_proto": net_proto,
            "src_ip": "SRC-1",
            "dst_ip": "DST-1",
            "src_port": src_port,
            "dst_port": dst_port,
            "threat_action": threat_action,
            "threat_name": threat_name,
            "threat_severity": threat_severity,
            "threat_type": threat_type,
            "threat_pattern": threat_pattern,
            "threat_id": threat_id,
            "threat_ref": threat_ref,
        },
        "normalization_issues": [],
        "provenance": [],
    }


def _attack(number: int = 1) -> dict[str, object]:
    return _record(
        number,
        session="SESSION-ATTACK",
        event_type="utm",
        event_subtype="anomaly",
        event_action="clear_session",
        event_severity="alert",
        event_message="anomaly: icmp_sweep, 101 > threshold 100, repeats 1 times since last log, pps 1 of prior second",
        app_service="PING",
        net_proto="1",
        src_port="",
        dst_port="",
        threat_action="blocked",
        threat_name="icmp_sweep",
        threat_severity="medium",
        threat_type="Reconnaissance",
        threat_pattern="icmp_sweep",
        threat_id="16777320",
        threat_ref="http://www.fortinet.com/ids/VID16777320",
    )


def _benign_triplet() -> tuple[dict[str, object], list[dict[str, object]]]:
    start = _record(2, itime="10", event_action="start", app_service="junos-ntp", net_proto="17", src_port="123", dst_port="123")
    appctrl = _record(
        3,
        itime="20",
        event_type="utm",
        event_subtype="app-ctrl",
        event_action="pass",
        event_severity="information",
        event_message="Network.Service: NTP",
        app_service="junos-ntp",
        app_id="16270",
        app_name="NTP",
        app_cat="Network.Service",
        net_proto="17",
        src_port="123",
        dst_port="123",
    )
    target = _record(
        4,
        itime="30",
        event_action="accept",
        event_severity="notice",
        app_service="junos-ntp",
        app_id="16270",
        app_name="NTP",
        app_cat="Network.Service",
        net_proto="17",
        src_port="123",
        dst_port="123",
    )
    return target, [start, appctrl]


def _split_row(record: dict[str, object], split: str = "TRAIN") -> dict[str, object]:
    number = int(record["source"]["record_number"])
    source_id = str(record["event"]["source_record_id"])
    return {
        "source_record_number": number,
        "source_record_id": source_id,
        "source_record_identity_sha256": source_record_identity(DATASET_SHA256, number, source_id),
        "dataset_sha256": DATASET_SHA256,
        "split_assignment": split,
        "hard_component_id": f"HC-{number}",
        "session_group_id": f"SG-{record['session']['identifier']}",
    }


def test_attack_requires_both_conjunctive_blocks() -> None:
    decision = evaluate_record(_attack(), dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    assert decision["candidate_label"] == "ATTACK"
    assert decision["matched_rule_ids"] == list(ATTACK_RULE_IDS)
    assert decision["label_provenance"] == "PRECISION_FIRST_PROXY_LABEL"


def test_benign_requires_session_and_appctrl_corrobation() -> None:
    target, context = _benign_triplet()
    decision = evaluate_record(target, context_records=context, dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    assert decision["candidate_label"] == "BENIGN"
    assert decision["matched_rule_ids"] == list(BENIGN_RULE_IDS)


def test_insufficient_evidence_is_uncertain_not_benign() -> None:
    target = _record(5, itime="20", event_action="accept", event_severity="notice")
    context = [_record(6, itime="10", event_action="start")]
    decision = evaluate_record(target, context_records=context, dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    assert decision["candidate_label"] == "UNCERTAIN"
    assert decision["label_quality_tier"] is None


def test_prohibited_label_source_is_invalid() -> None:
    record = _attack()
    record["source_record"]["anomaly_rank"] = "1"  # type: ignore[index]
    decision = evaluate_record(record, dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    assert decision["candidate_label"] == "UNCERTAIN"
    assert decision["invalid"] is True


def test_dry_run_counts_and_replay_are_deterministic() -> None:
    target, context = _benign_triplet()
    records = [_attack(), *context, target, _record(7, event_action="deny")]
    rows = [_split_row(record) for record in records]
    first = run_dry_run(records, rows, dataset_sha256=DATASET_SHA256)
    second = run_dry_run(records, rows, dataset_sha256=DATASET_SHA256)
    assert first == second
    assert first["splits"]["TRAIN"]["counts"] == {"ATTACK": 1, "BENIGN": 1, "UNCERTAIN": 3}


def test_feature_leakage_audit_denies_rule_source_features() -> None:
    attack = _attack()
    rows = [_split_row(attack)]
    decision = evaluate_record(attack, dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    audit = audit_feature_leakage([attack], rows, [decision], dataset_sha256=DATASET_SHA256)
    assert audit["features"]["protocol_icmp"]["classification"] == "EXCLUDED_LABEL_SOURCE"
    assert audit["features"]["service_rarity"]["classification"] == "EXCLUDED_DERIVED_FROM_LABEL_SOURCE"
    assert audit["status"] == "PASS"


def test_no_mutation_of_input_record_during_evaluation() -> None:
    record = _attack()
    before = deepcopy(record)
    evaluate_record(record, dataset_sha256=DATASET_SHA256, split_assignment="TRAIN")
    assert record == before
