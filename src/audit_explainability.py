"""Independent read-only audit for Stage 1.9 explanation and review artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import Iterator, Mapping, Sequence

from ai_features.artifact import canonical_json, file_sha256
from anomaly.artifact import (
    MANIFEST_ARTIFACT_NAME,
    MODEL_METADATA_ARTIFACT_NAME,
    SCORE_ARTIFACT_NAME,
    read_score_rows,
)
from detection.input import iter_normalized_events
from explainability.interpretation import CANONICAL_BEHAVIORS, EXPLANATION_SCHEMA_VERSION
from evaluation.review import QUEUE_COLUMNS, read_blind_labels
from storage.input import (
    StorageInputValidationError,
    calculate_artifact_identity,
    validate_detection_artifacts,
)


EXPLANATION_ARTIFACT_NAME = "stage_1_9_explained_anomalies.jsonl"
QUEUE_ARTIFACT_NAME = "stage_1_9_analyst_review_queue.csv"
METADATA_ARTIFACT_NAME = "stage_1_9_explanation_metadata.json"
EXPLANATION_BUNDLE_NAMES = frozenset(
    {EXPLANATION_ARTIFACT_NAME, QUEUE_ARTIFACT_NAME, METADATA_ARTIFACT_NAME}
)
EXPLANATION_ROW_FIELDS = frozenset(
    {
        "schema_version",
        "source_record_number",
        "source_record_id",
        "partition",
        "model_score",
        "raw_abnormality",
        "anomaly_score",
        "anomaly_rank",
        "anomaly_band",
        "analyst_review_selected",
        "investigation_priority_score",
        "investigation_rank",
        "suspected_behaviors",
        "suspected_attack_type",
        "evidence_strength",
        "explanation_status",
        "top_reasons",
        "reference_context",
        "review_id",
        "display_context",
    }
)
METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "upstream_identities",
        "row_count",
        "explanation_artifact_identity",
        "queue_identity",
        "selection_protocol_version",
        "reason_registry_version",
        "stratum_counts",
        "top_50_identity",
    }
)
_REVIEW_ID_PATTERN = re.compile(r"R-[0-9a-f]{64}")


class ExplainabilityAuditError(ValueError):
    """Raised when a Stage 1.9 pre-review bundle cannot be reconciled."""


@dataclass(frozen=True)
class ExplainabilityAuditSummary:
    row_count: int
    top_50_count: int
    review_queue_count: int
    explanation_sha256: str
    queue_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "row_count": self.row_count,
            "top_50_count": self.top_50_count,
            "review_queue_count": self.review_queue_count,
            "explanation_sha256": self.explanation_sha256,
            "queue_sha256": self.queue_sha256,
        }


class _DuplicateJsonKeyError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError("JSON object has a duplicate key")
        result[key] = value
    return result


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ExplainabilityAuditError(f"{name} must be a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as error:
        raise ExplainabilityAuditError(f"{name} must be a SHA-256 digest") from error
    return value.lower()


def _read_metadata(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as error:
        raise ExplainabilityAuditError("explanation metadata cannot be read as strict UTF-8 JSON") from error
    if not isinstance(payload, Mapping) or set(payload) != METADATA_FIELDS:
        raise ExplainabilityAuditError("explanation metadata does not contain exactly its contract fields")
    if payload["schema_version"] != EXPLANATION_SCHEMA_VERSION:
        raise ExplainabilityAuditError("explanation metadata schema version is incompatible")
    return payload


def _identity(path: Path, name: str, *, row_count: int | None = None) -> dict[str, object]:
    identity: dict[str, object] = {
        "path": name,
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }
    if row_count is not None:
        identity["row_count"] = row_count
    return identity


def _validate_row(row: object, previous_number: int, identifiers: set[str]) -> dict[str, object]:
    if not isinstance(row, dict) or set(row) != EXPLANATION_ROW_FIELDS:
        raise ExplainabilityAuditError("explanation row does not contain exactly its contract fields")
    if row["schema_version"] != EXPLANATION_SCHEMA_VERSION:
        raise ExplainabilityAuditError("explanation row schema version is incompatible")
    number = row["source_record_number"]
    identifier = row["source_record_id"]
    rank = row["anomaly_rank"]
    investigation_rank = row["investigation_rank"]
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number <= previous_number
        or not isinstance(identifier, str)
        or not identifier
        or identifier in identifiers
        or isinstance(rank, bool)
        or not isinstance(rank, int)
        or rank < 1
        or isinstance(investigation_rank, bool)
        or not isinstance(investigation_rank, int)
        or investigation_rank < 1
    ):
        raise ExplainabilityAuditError("explanation provenance/order is invalid")
    selected = row["analyst_review_selected"]
    if not isinstance(selected, bool) or selected != (rank <= 50):
        raise ExplainabilityAuditError("explanation Top-50 membership changed from Stage 1.8")
    for name in ("model_score", "raw_abnormality", "anomaly_score", "investigation_priority_score"):
        value = row[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(float(value)):
            raise ExplainabilityAuditError("explanation contains a non-finite numeric value")
    if not 0.0 <= float(row["investigation_priority_score"]) <= 100.0:
        raise ExplainabilityAuditError("investigation priority is outside its bounded heuristic range")
    behaviors = row["suspected_behaviors"]
    if not isinstance(behaviors, list) or len(behaviors) != len(set(behaviors)):
        raise ExplainabilityAuditError("suspected behaviors are invalid")
    approved = list(CANONICAL_BEHAVIORS)
    fallback = "UNCLASSIFIED_ANOMALOUS_PATTERN"
    if any(item not in {*approved, fallback} for item in behaviors):
        raise ExplainabilityAuditError("suspected behaviors contain an unapproved tag")
    if fallback in behaviors and (not selected or behaviors != [fallback]):
        raise ExplainabilityAuditError("unclassified behavior fallback violates its Top-50-only rule")
    if [item for item in approved if item in behaviors] != [item for item in behaviors if item != fallback]:
        raise ExplainabilityAuditError("suspected behaviors violate the canonical order")
    attack_type = row["suspected_attack_type"]
    if not selected and attack_type is not None:
        raise ExplainabilityAuditError("non-Top-50 records must have null suspected_attack_type")
    if selected and attack_type not in {"Possible reconnaissance activity", "Unclassified suspicious behavior"}:
        raise ExplainabilityAuditError("Top-50 suspected attack type is invalid")
    if row["evidence_strength"] not in {"HIGH", "MEDIUM", "LOW", None}:
        raise ExplainabilityAuditError("evidence strength is invalid")
    if not selected and row["evidence_strength"] is not None:
        raise ExplainabilityAuditError("non-Top-50 records must have null evidence strength")
    if row["explanation_status"] not in {"COMPLETE", "LIMITED"}:
        raise ExplainabilityAuditError("explanation status is invalid")
    reasons = row["top_reasons"]
    if not isinstance(reasons, list) or len(reasons) > 3:
        raise ExplainabilityAuditError("top reasons are invalid")
    reason_fields = {
        "family", "feature_name", "observed_value", "source_paths",
        "raw_observed_values", "reference_n", "less_count", "equal_count",
        "extremeness", "template_text",
    }
    if any(not isinstance(reason, Mapping) or set(reason) != reason_fields for reason in reasons):
        raise ExplainabilityAuditError("top reason does not contain exactly its contract fields")
    context = row["reference_context"]
    context_fields = {
        "rule_ids", "rule_observation_present", "source_threat_observation_present",
        "anomaly_subtype_observation_present", "source_threat_type",
    }
    if (
        not isinstance(context, Mapping)
        or set(context) != context_fields
        or not isinstance(context["rule_ids"], list)
        or context["rule_ids"] != sorted(set(context["rule_ids"]))
        or any(not isinstance(rule_id, str) or not rule_id for rule_id in context["rule_ids"])
        or any(not isinstance(context[name], bool) for name in context_fields - {"rule_ids", "source_threat_type"})
        or context["source_threat_type"] is not None and not isinstance(context["source_threat_type"], str)
    ):
        raise ExplainabilityAuditError("reference context does not contain its strict contract")
    display_context = row["display_context"]
    if not isinstance(display_context, Mapping) or set(display_context) != set(QUEUE_COLUMNS[1:]):
        raise ExplainabilityAuditError("display context does not contain its strict queue contract")
    review_id = row["review_id"]
    if review_id is not None and (not isinstance(review_id, str) or _REVIEW_ID_PATTERN.fullmatch(review_id) is None):
        raise ExplainabilityAuditError("explanation review ID is invalid")
    return row


def iter_explanation_rows(path: str | Path) -> Iterator[dict[str, object]]:
    """Yield canonical explanation rows in source-record order."""

    explanation_path = Path(path)
    previous = 0
    identifiers: set[str] = set()
    try:
        with explanation_path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise ExplainabilityAuditError("explanation JSONL contains a blank line")
                try:
                    payload = json.loads(line, object_pairs_hook=_strict_object)
                except (_DuplicateJsonKeyError, json.JSONDecodeError) as error:
                    raise ExplainabilityAuditError("explanation JSONL contains invalid JSON") from error
                row = _validate_row(payload, previous, identifiers)
                canonical = canonical_json(row) + "\n"
                if line != canonical:
                    raise ExplainabilityAuditError("explanation JSONL is not canonically serialized")
                previous = int(row["source_record_number"])
                identifiers.add(str(row["source_record_id"]))
                yield row
    except UnicodeDecodeError as error:
        raise ExplainabilityAuditError("explanation JSONL is not valid UTF-8") from error
    except OSError as error:
        raise ExplainabilityAuditError("explanation JSONL cannot be read") from error


def audit_explanation_bundle(bundle_dir: str | Path) -> ExplainabilityAuditSummary:
    """Audit a completed pre-review bundle without reading raw data or models."""

    bundle = Path(bundle_dir)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ExplainabilityAuditError("explanation bundle directory is unavailable or unsafe")
    if {item.name for item in bundle.iterdir()} != EXPLANATION_BUNDLE_NAMES:
        raise ExplainabilityAuditError("explanation bundle contains unexpected artifacts")
    explanation_path = bundle / EXPLANATION_ARTIFACT_NAME
    queue_path = bundle / QUEUE_ARTIFACT_NAME
    metadata_path = bundle / METADATA_ARTIFACT_NAME
    if any(path.is_symlink() or not path.is_file() for path in (explanation_path, queue_path, metadata_path)):
        raise ExplainabilityAuditError("explanation bundle contains unsafe artifact paths")
    rows = list(iter_explanation_rows(explanation_path))
    if not rows:
        raise ExplainabilityAuditError("explanation bundle contains no rows")
    metadata = _read_metadata(metadata_path)
    if metadata["row_count"] != len(rows):
        raise ExplainabilityAuditError("metadata row count does not reconcile")
    if metadata["explanation_artifact_identity"] != _identity(explanation_path, EXPLANATION_ARTIFACT_NAME, row_count=len(rows)):
        raise ExplainabilityAuditError("metadata explanation identity does not reconcile")
    review_rows = [row for row in rows if row["review_id"] is not None]
    if len(review_rows) != 100 or len({str(row["review_id"]) for row in review_rows}) != 100:
        raise ExplainabilityAuditError("review ID publication must contain exactly 100 unique queue records")
    if any(not isinstance(row["review_id"], str) or _REVIEW_ID_PATTERN.fullmatch(str(row["review_id"])) is None for row in review_rows):
        raise ExplainabilityAuditError("review ID publication contains an invalid review ID")
    top_50 = [row for row in rows if row["analyst_review_selected"]]
    if len(top_50) != 50:
        raise ExplainabilityAuditError("explanation Top-50 count does not reconcile")
    if any(row["review_id"] is None for row in top_50) or len([row for row in review_rows if not row["analyst_review_selected"]]) != 50:
        raise ExplainabilityAuditError("review queue must retain all Top-50 rows plus 50 comparisons")
    top_numbers = [int(row["source_record_number"]) for row in top_50]
    expected_top_identity = {
        "row_count": 50,
        "sha256": hashlib.sha256(canonical_json(top_numbers).encode("utf-8")).hexdigest(),
    }
    if metadata["top_50_identity"] != expected_top_identity:
        raise ExplainabilityAuditError("metadata Top-50 identity does not reconcile")
    investigation_ranks = [int(row["investigation_rank"]) for row in rows]
    if sorted(investigation_ranks) != list(range(1, len(rows) + 1)):
        raise ExplainabilityAuditError("investigation ranks are not unique and complete")
    try:
        with queue_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != QUEUE_COLUMNS:
                raise ExplainabilityAuditError("review queue columns are incompatible")
            queue_rows = list(reader)
    except UnicodeDecodeError as error:
        raise ExplainabilityAuditError("review queue is not valid UTF-8") from error
    except OSError as error:
        raise ExplainabilityAuditError("review queue cannot be read") from error
    if len(queue_rows) != 100 or {row["review_id"] for row in queue_rows} != {str(row["review_id"]) for row in review_rows}:
        raise ExplainabilityAuditError("review queue IDs do not reconcile to explanation rows")
    if metadata["queue_identity"] != _identity(queue_path, QUEUE_ARTIFACT_NAME, row_count=len(queue_rows)):
        raise ExplainabilityAuditError("metadata queue identity does not reconcile")
    return ExplainabilityAuditSummary(
        row_count=len(rows),
        top_50_count=len(top_50),
        review_queue_count=len(queue_rows),
        explanation_sha256=file_sha256(explanation_path),
        queue_sha256=file_sha256(queue_path),
    )


def audit_auto_triage_bundle(
    explanations_dir: str | Path,
    auto_triage_dir: str | Path,
) -> dict[str, object]:
    """Independently reconcile a no-human-label Stage 1.9 triage bundle."""

    from auto_triage import (
        AUTO_TRIAGE_ARTIFACT_NAME,
        AUTO_TRIAGE_BUNDLE_NAMES,
        AUTO_TRIAGE_COLUMNS,
        SUMMARY_ARTIFACT_NAME,
        SUMMARY_FIELDS,
        TOP_ANOMALIES_ARTIFACT_NAME,
        _csv_cell,
        build_auto_triage_summary,
        project_auto_triage_row,
    )

    pre_bundle = Path(explanations_dir)
    pre_summary = audit_explanation_bundle(pre_bundle)
    bundle = Path(auto_triage_dir)
    if bundle.is_symlink() or not bundle.is_dir() or {item.name for item in bundle.iterdir()} != AUTO_TRIAGE_BUNDLE_NAMES:
        raise ExplainabilityAuditError("auto-triage bundle must contain exactly its contract artifacts")
    triage_path = bundle / AUTO_TRIAGE_ARTIFACT_NAME
    top_path = bundle / TOP_ANOMALIES_ARTIFACT_NAME
    summary_path = bundle / SUMMARY_ARTIFACT_NAME
    if any(path.is_symlink() or not path.is_file() for path in (triage_path, top_path, summary_path)):
        raise ExplainabilityAuditError("auto-triage bundle contains unsafe artifact paths")
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as error:
        raise ExplainabilityAuditError("auto-triage summary cannot be read as strict UTF-8 JSON") from error
    if not isinstance(summary, Mapping) or set(summary) != SUMMARY_FIELDS:
        raise ExplainabilityAuditError("auto-triage summary does not contain exactly its contract fields")
    rows = list(iter_explanation_rows(pre_bundle / EXPLANATION_ARTIFACT_NAME))
    try:
        expected_rows = [project_auto_triage_row(row) for row in rows]
        expected_summary = build_auto_triage_summary(rows)
    except ValueError as error:
        raise ExplainabilityAuditError("auto-triage projection cannot be independently reconstructed") from error
    for name, expected in expected_summary.items():
        if summary[name] != expected:
            raise ExplainabilityAuditError(f"auto-triage summary {name} does not reconcile")
    if any(name in summary for name in ("precision", "recall", "f1", "accuracy", "confusion_matrix")):
        raise ExplainabilityAuditError("auto-triage summary must not contain supervised classification metrics")
    if summary["pre_review_metadata_identity"] != _identity(pre_bundle / METADATA_ARTIFACT_NAME, METADATA_ARTIFACT_NAME):
        raise ExplainabilityAuditError("auto-triage pre-review metadata identity does not reconcile")
    if summary["explanation_artifact_identity"] != _identity(
        pre_bundle / EXPLANATION_ARTIFACT_NAME,
        EXPLANATION_ARTIFACT_NAME,
        row_count=pre_summary.row_count,
    ):
        raise ExplainabilityAuditError("auto-triage explanation identity does not reconcile")
    if summary["auto_triage_artifact_identity"] != _identity(triage_path, AUTO_TRIAGE_ARTIFACT_NAME, row_count=len(rows)):
        raise ExplainabilityAuditError("auto-triage CSV identity does not reconcile")
    expected_top = sorted(
        (row for row in expected_rows if int(row["anomaly_rank"]) <= 50),
        key=lambda row: int(row["anomaly_rank"]),
    )
    if summary["top_anomalies_artifact_identity"] != _identity(top_path, TOP_ANOMALIES_ARTIFACT_NAME, row_count=len(expected_top)):
        raise ExplainabilityAuditError("top-anomalies CSV identity does not reconcile")

    def read_rows(path: Path) -> list[dict[str, str]]:
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                if tuple(reader.fieldnames or ()) != AUTO_TRIAGE_COLUMNS:
                    raise ExplainabilityAuditError("auto-triage CSV columns are incompatible")
                return list(reader)
        except UnicodeDecodeError as error:
            raise ExplainabilityAuditError("auto-triage CSV is not UTF-8") from error
        except OSError as error:
            raise ExplainabilityAuditError("auto-triage CSV cannot be read") from error

    def expected_csv_rows(items: Sequence[Mapping[str, object]]) -> list[dict[str, str]]:
        return [
            {
                name: "" if _csv_cell(row[name]) is None else str(_csv_cell(row[name]))
                for name in AUTO_TRIAGE_COLUMNS
            }
            for row in items
        ]

    if read_rows(triage_path) != expected_csv_rows(expected_rows):
        raise ExplainabilityAuditError("auto-triage CSV rows do not reconcile")
    if read_rows(top_path) != expected_csv_rows(expected_top):
        raise ExplainabilityAuditError("top-anomalies CSV rows do not reconcile")
    if (
        summary["row_count"] != len(rows)
        or summary["top_50_count"] != 50
        or sum(summary["auto_triage_counts"].values()) != len(rows)
        or summary["review_status_counts"]["REVIEWED_RESOLVED"] != 0
        or summary["review_status_counts"]["REVIEWED_UNCERTAIN"] != 0
    ):
        raise ExplainabilityAuditError("auto-triage aggregate invariants do not reconcile")
    return {
        "row_count": len(rows),
        "top_50_count": 50,
        "auto_triage_sha256": file_sha256(triage_path),
        "summary_sha256": file_sha256(summary_path),
    }


def audit_evaluation_bundle(
    explanations_dir: str | Path,
    evaluation_dir: str | Path,
    *,
    labels_path: str | Path | None = None,
) -> dict[str, object]:
    """Independently reconcile the Stage 1.9 evaluation/status projection.

    The audit derives statuses and reviewed-sample metrics only from the
    persisted blind labels in the evaluation projection.  It never treats rule
    observations, threat fields, scores, or ranks as human truth.
    """

    from evaluate_analyst_review import EVALUATION_ARTIFACT_NAME, EVALUATION_FIELDS, _reference_agreement
    from evaluation.metrics import evaluate_review_mapping

    pre_bundle = Path(explanations_dir)
    pre_summary = audit_explanation_bundle(pre_bundle)
    evaluation = Path(evaluation_dir)
    if evaluation.is_symlink() or not evaluation.is_dir() or {item.name for item in evaluation.iterdir()} != {EVALUATION_ARTIFACT_NAME}:
        raise ExplainabilityAuditError("evaluation bundle must contain exactly its summary artifact")
    summary_path = evaluation / EVALUATION_ARTIFACT_NAME
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as error:
        raise ExplainabilityAuditError("evaluation summary cannot be read as strict UTF-8 JSON") from error
    if not isinstance(summary, Mapping) or set(summary) != EVALUATION_FIELDS or summary.get("schema_version") != "1.0":
        raise ExplainabilityAuditError("evaluation summary does not contain exactly its contract fields")
    metadata = _read_metadata(pre_bundle / METADATA_ARTIFACT_NAME)
    if summary["upstream_identities"] != metadata["upstream_identities"]:
        raise ExplainabilityAuditError("evaluation upstream identities do not reconcile")
    expected_metadata_identity = _identity(pre_bundle / METADATA_ARTIFACT_NAME, METADATA_ARTIFACT_NAME)
    if summary["pre_review_metadata_identity"] != expected_metadata_identity or summary["queue_identity"] != metadata["queue_identity"]:
        raise ExplainabilityAuditError("evaluation pre-review identities do not reconcile")
    rows = list(iter_explanation_rows(pre_bundle / EXPLANATION_ARTIFACT_NAME))
    records: list[dict[str, object]] = []
    expected_mapping: list[dict[str, object]] = []
    labels: dict[str, dict[str, str]] = {}
    actual_results = summary["record_review_results"]
    if not isinstance(actual_results, list) or len(actual_results) != len(rows):
        raise ExplainabilityAuditError("evaluation record review results do not reconcile")
    for row, actual in zip(rows, actual_results, strict=True):
        if not isinstance(actual, Mapping) or set(actual) != {
            "source_record_number", "review_id", "analyst_review_selected", "review_membership",
            "blind_label", "contextual_label", "review_status",
        }:
            raise ExplainabilityAuditError("evaluation record review result is incompatible")
        membership = "TOP_50" if row["analyst_review_selected"] else ("COMPARISON" if row["review_id"] is not None else "NOT_SELECTED")
        if (
            actual["source_record_number"] != row["source_record_number"]
            or actual["review_id"] != row["review_id"]
            or actual["analyst_review_selected"] != row["analyst_review_selected"]
            or actual["review_membership"] != membership
        ):
            raise ExplainabilityAuditError("evaluation review provenance does not reconcile")
        records.append(
            {
                "source_record_number": row["source_record_number"],
                "anomaly_rank": row["anomaly_rank"],
                "review_id": row["review_id"],
                "review_membership": membership,
                "analyst_review_selected": row["analyst_review_selected"],
            }
        )
        if row["review_id"] is not None:
            review_id = str(row["review_id"])
            if actual["blind_label"] not in {"SUSPICIOUS", "NOT_SUSPICIOUS", "UNCERTAIN"}:
                raise ExplainabilityAuditError("evaluation selected review is missing an accepted blind label")
            labels[review_id] = {"blind_label": str(actual["blind_label"])}
            expected_mapping.append(
                {
                    "review_id": review_id,
                    "source_record_number": row["source_record_number"],
                    "review_membership": membership,
                }
            )
    recomputed = evaluate_review_mapping(records, labels)
    expected_results = recomputed["record_review_results"]
    for expected, actual in zip(expected_results, actual_results, strict=True):
        if actual["contextual_label"] not in {None, "SUSPICIOUS", "NOT_SUSPICIOUS", "UNCERTAIN"}:
            raise ExplainabilityAuditError("evaluation contextual label is invalid")
        expected["contextual_label"] = actual["contextual_label"]
    for name in (
        "review_status_counts", "resolved_matrix", "uncertain_counts_by_ai_decision",
        "resolved_review_count", "metrics", "precision_at_k",
    ):
        if summary[name] != recomputed[name]:
            raise ExplainabilityAuditError("evaluation metrics/status projection does not reconcile")
    if summary["record_review_results"] != expected_results or summary["review_mapping"] != expected_mapping:
        raise ExplainabilityAuditError("evaluation record review mapping does not reconcile")
    if summary["reference_agreement"] != _reference_agreement(rows):
        raise ExplainabilityAuditError("evaluation reference agreement does not reconcile")
    if summary["selection_protocol_version"] != metadata["selection_protocol_version"] or summary["stratum_counts"] != metadata["stratum_counts"]:
        raise ExplainabilityAuditError("evaluation selection metadata does not reconcile")
    if not isinstance(summary["frozen_blind_label_identity"], Mapping) or not isinstance(summary["contextual_label_identity"], (Mapping, type(None))):
        raise ExplainabilityAuditError("evaluation label identities are invalid")
    if labels_path is not None:
        label_file = Path(labels_path)
        if label_file.is_symlink() or not label_file.is_file():
            raise ExplainabilityAuditError("blind label input is unavailable or unsafe")
        label_identity = _identity(label_file, label_file.name)
        if summary["frozen_blind_label_identity"] != label_identity:
            raise ExplainabilityAuditError("evaluation frozen blind-label identity does not reconcile")
        expected_ids = {str(row["review_id"]) for row in rows if row["review_id"] is not None}
        try:
            supplied_reviews = read_blind_labels(label_file, expected_ids)
        except ValueError as error:
            raise ExplainabilityAuditError("blind label input fails the review contract") from error
        for result in actual_results:
            review_id = result["review_id"]
            if isinstance(review_id, str) and result["blind_label"] != supplied_reviews[review_id]["blind_label"]:
                raise ExplainabilityAuditError("evaluation blind labels do not match the frozen input")
    return {
        "row_count": pre_summary.row_count,
        "reviewed_count": len(labels),
        "resolved_review_count": recomputed["resolved_review_count"],
        "evaluation_sha256": file_sha256(summary_path),
    }


def audit_explanation_upstream(
    bundle_dir: str | Path,
    *,
    features_dir: str | Path,
    scores_dir: str | Path,
    normalized_path: str | Path,
    findings_path: str | Path,
    summary_path: str | Path,
) -> dict[str, object]:
    """Reconcile pre-review rows to their immutable Stage 1.3/1.7/1.8/1.4 inputs.

    This reads score rows and hashes declared inputs but never deserializes the
    Stage 1.8 model, opens the raw CSV, or treats a source observation as a
    review label.
    """

    summary = audit_explanation_bundle(bundle_dir)
    bundle = Path(bundle_dir)
    metadata = _read_metadata(bundle / METADATA_ARTIFACT_NAME)
    upstream = metadata["upstream_identities"]
    if not isinstance(upstream, Mapping) or set(upstream) != {
        "feature_artifact", "feature_metadata", "score_artifact", "score_metadata",
        "manifest", "normalized", "findings", "summary",
    }:
        raise ExplainabilityAuditError("explanation upstream identity contract is invalid")
    features = Path(features_dir)
    scores = Path(scores_dir)
    normalized = Path(normalized_path)
    findings = Path(findings_path)
    detection_summary = Path(summary_path)
    paths = (features, scores, normalized, findings, detection_summary)
    if any(path.is_symlink() or not path.exists() for path in paths):
        raise ExplainabilityAuditError("declared immutable upstream artifact is unavailable or unsafe")
    feature_path = features / "stage_1_7_ai_features.jsonl"
    feature_metadata_path = features / "stage_1_7_ai_feature_metadata.json"
    score_path = scores / SCORE_ARTIFACT_NAME
    score_metadata_path = scores / MODEL_METADATA_ARTIFACT_NAME
    manifest_path = scores / MANIFEST_ARTIFACT_NAME
    for path in (feature_path, feature_metadata_path, score_path, score_metadata_path, manifest_path):
        if path.is_symlink() or not path.is_file():
            raise ExplainabilityAuditError("declared upstream bundle artifact is unavailable or unsafe")
    findings_by_record: dict[int, list[str]] = {}

    def capture_finding(finding: object) -> None:
        findings_by_record.setdefault(finding.source_event.source_record_number, []).append(finding.rule.rule_id)

    try:
        score_rows = tuple(read_score_rows(score_path))
        detection_identity = calculate_artifact_identity(findings, detection_summary)
        validate_detection_artifacts(
            findings,
            detection_summary,
            detection_identity,
            on_finding=capture_finding,
        )
        expected = {
            "feature_artifact": _identity(feature_path, feature_path.name),
            "feature_metadata": _identity(feature_metadata_path, feature_metadata_path.name),
            "score_artifact": _identity(score_path, score_path.name, row_count=len(score_rows)),
            "score_metadata": _identity(score_metadata_path, score_metadata_path.name),
            "manifest": _identity(manifest_path, manifest_path.name),
            "normalized": {
                "path": str(normalized.resolve()),
                "size_bytes": normalized.stat().st_size,
                "sha256": file_sha256(normalized),
                "schema_version": "1.0",
            },
            "findings": {"path": findings.name, "sha256": detection_identity.findings_sha256},
            "summary": {"path": detection_summary.name, "sha256": detection_identity.summary_sha256},
        }
    except (OSError, StorageInputValidationError, ValueError) as error:
        raise ExplainabilityAuditError("declared upstream artifact cannot be read or validated") from error
    if dict(upstream) != expected:
        raise ExplainabilityAuditError("explanation upstream identities do not match declared artifacts")
    rows = list(iter_explanation_rows(bundle / EXPLANATION_ARTIFACT_NAME))
    if len(rows) != len(score_rows):
        raise ExplainabilityAuditError("explanation row count does not reconcile to Stage 1.8 scores")
    event_iterator = iter_normalized_events(normalized)
    try:
        joined = zip(rows, score_rows, event_iterator, strict=True)
        for explanation, score, event in joined:
            expected_rule_ids = sorted(set(findings_by_record.get(score.source_record_number, [])))
            expected_source_threat = "fortigate.source_threat_observation" in expected_rule_ids
            expected_anomaly_subtype = "fortigate.anomaly_subtype_observation" in expected_rule_ids
            context = explanation["reference_context"]
            threats = event.threat_observations
            if (
                event.source_record.record_number != score.source_record_number
                or event.event.get("source_record_id") != score.source_record_id
                or context["rule_ids"] != expected_rule_ids
                or context["rule_observation_present"] != bool(expected_rule_ids)
                or context["source_threat_observation_present"] != expected_source_threat
                or context["anomaly_subtype_observation_present"] != expected_anomaly_subtype
                or context["source_threat_type"] != threats.get("type_source")
            ):
                raise ExplainabilityAuditError("explanation reference context does not reconcile to immutable inputs")
            if (
                explanation["source_record_number"] != score.source_record_number
                or explanation["source_record_id"] != score.source_record_id
                or explanation["partition"] != score.partition
                or explanation["anomaly_rank"] != score.anomaly_rank
                or explanation["analyst_review_selected"] != score.analyst_review_selected
                or explanation["anomaly_score"] != score.anomaly_score
                or explanation["raw_abnormality"] != score.raw_abnormality
            ):
                raise ExplainabilityAuditError("explanation row changed immutable Stage 1.8 score/rank/Top-50 fields")
    except (KeyError, OSError, TypeError, ValueError) as error:
        if isinstance(error, ExplainabilityAuditError):
            raise
        raise ExplainabilityAuditError("normalized provenance input cannot be read or reconciled") from error
    return {
        "row_count": summary.row_count,
        "top_50_count": summary.top_50_count,
        "score_sha256": expected["score_artifact"]["sha256"],
        "feature_sha256": expected["feature_artifact"]["sha256"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit one Stage 1.9 explanation bundle.")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--evaluation-dir")
    parser.add_argument("--auto-triage-dir")
    parser.add_argument("--labels")
    parser.add_argument("--features-dir")
    parser.add_argument("--scores-dir")
    parser.add_argument("--normalized")
    parser.add_argument("--findings")
    parser.add_argument("--summary")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        upstream_values = (
            arguments.features_dir,
            arguments.scores_dir,
            arguments.normalized,
            arguments.findings,
            arguments.summary,
        )
        if any(upstream_values) and not all(upstream_values):
            raise ExplainabilityAuditError("all upstream audit arguments must be supplied together")
        if arguments.labels and not arguments.evaluation_dir:
            raise ExplainabilityAuditError("--labels requires --evaluation-dir")
        if arguments.evaluation_dir and arguments.auto_triage_dir:
            raise ExplainabilityAuditError("evaluation and auto-triage bundles must be audited separately")
        if arguments.auto_triage_dir:
            if any(upstream_values):
                audit_explanation_upstream(
                    arguments.bundle,
                    features_dir=arguments.features_dir,
                    scores_dir=arguments.scores_dir,
                    normalized_path=arguments.normalized,
                    findings_path=arguments.findings,
                    summary_path=arguments.summary,
                )
            print(canonical_json(audit_auto_triage_bundle(arguments.bundle, arguments.auto_triage_dir)))
        elif arguments.evaluation_dir:
            if any(upstream_values):
                audit_explanation_upstream(
                    arguments.bundle,
                    features_dir=arguments.features_dir,
                    scores_dir=arguments.scores_dir,
                    normalized_path=arguments.normalized,
                    findings_path=arguments.findings,
                    summary_path=arguments.summary,
                )
            print(canonical_json(audit_evaluation_bundle(arguments.bundle, arguments.evaluation_dir, labels_path=arguments.labels)))
        elif any(upstream_values):
            print(canonical_json(audit_explanation_upstream(
                arguments.bundle,
                features_dir=arguments.features_dir,
                scores_dir=arguments.scores_dir,
                normalized_path=arguments.normalized,
                findings_path=arguments.findings,
                summary_path=arguments.summary,
            )))
        else:
            print(canonical_json(audit_explanation_bundle(arguments.bundle).to_dict()))
    except ExplainabilityAuditError as error:
        print(f"Stage 1.9 explanation audit failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
