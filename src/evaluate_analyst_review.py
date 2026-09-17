"""Publish the separate Stage 1.9 reviewed-sample evaluation bundle."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import audit_explainability
from ai_features.artifact import canonical_json, file_sha256
from audit_explainability import METADATA_ARTIFACT_NAME, iter_explanation_rows
from evaluation.metrics import EvaluationError, evaluate_review_mapping
from evaluation.review import (
    BLIND_LABELS,
    CONTEXTUAL_LABEL_COLUMNS,
    REVIEW_SELECTION_PROTOCOL_VERSION,
    ReviewError,
    _parse_review_timestamp,
    read_blind_labels,
)


EVALUATION_SCHEMA_VERSION = "1.0"
EVALUATION_ARTIFACT_NAME = "stage_1_9_evaluation_summary.json"
EVALUATION_FIELDS = frozenset(
    {
        "schema_version",
        "upstream_identities",
        "pre_review_metadata_identity",
        "queue_identity",
        "frozen_blind_label_identity",
        "contextual_label_identity",
        "selection_protocol_version",
        "stratum_counts",
        "review_mapping",
        "record_review_results",
        "review_status_counts",
        "resolved_matrix",
        "uncertain_counts_by_ai_decision",
        "resolved_review_count",
        "metrics",
        "precision_at_k",
        "reference_agreement",
        "interpretation_caveats",
    }
)


class AnalystEvaluationError(ValueError):
    """Raised when a Stage 1.9 evaluation cannot be built safely."""


@dataclass(frozen=True)
class AnalystEvaluationSummary:
    bundle_path: str
    row_count: int
    reviewed_count: int
    resolved_review_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "row_count": self.row_count,
            "reviewed_count": self.reviewed_count,
            "resolved_review_count": self.resolved_review_count,
        }


def _processed_root() -> Path:
    return (Path(__file__).resolve().parents[1] / "data" / "processed").resolve()


def _contains(parent: Path, child: Path) -> bool:
    return child != parent and parent in child.parents


def _has_symlink_component(path: Path) -> bool:
    candidate = path.absolute()
    while candidate != candidate.parent:
        if candidate.exists() and candidate.is_symlink():
            return True
        candidate = candidate.parent
    return candidate.exists() and candidate.is_symlink()


def _resolve_new_output(value: str | Path) -> Path:
    supplied = Path(value)
    if supplied.is_symlink() or _has_symlink_component(supplied):
        raise AnalystEvaluationError("evaluation output path must not traverse a symlink")
    output = supplied.resolve()
    if not _contains(_processed_root(), output) or output.exists() or not output.parent.is_dir() or output.parent.is_symlink():
        raise AnalystEvaluationError("evaluation output must be a new directory beneath data/processed")
    return output


def _file_identity(path: Path, name: str) -> dict[str, object]:
    return {"path": name, "size_bytes": path.stat().st_size, "sha256": file_sha256(path)}


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnalystEvaluationError("required Stage 1.9 JSON metadata cannot be read") from error
    if not isinstance(value, Mapping):
        raise AnalystEvaluationError("required Stage 1.9 JSON metadata must be an object")
    return value


def _read_contextual_labels(path: Path, expected_ids: set[str]) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    if path.is_symlink() or not path.is_file():
        raise AnalystEvaluationError("contextual label CSV is unavailable or unsafe")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != CONTEXTUAL_LABEL_COLUMNS:
                raise AnalystEvaluationError("contextual label CSV columns are incompatible")
            for entry in reader:
                if set(entry) != set(CONTEXTUAL_LABEL_COLUMNS):
                    raise AnalystEvaluationError("contextual review record is invalid")
                review_id = entry["review_id"]
                label = entry["contextual_label"]
                rationale = entry["contextual_rationale"]
                alias = entry["reviewer_alias"]
                if not isinstance(review_id, str) or review_id not in expected_ids or review_id in entries:
                    raise AnalystEvaluationError("contextual review ID is invalid")
                if label not in BLIND_LABELS or not isinstance(rationale, str) or not rationale.strip() or not isinstance(alias, str) or not alias.strip():
                    raise AnalystEvaluationError("contextual review value is invalid")
                entries[review_id] = {
                    "contextual_label": label,
                    "contextual_rationale": rationale,
                    "reviewer_alias": alias,
                    "reviewed_at": _parse_review_timestamp(entry["reviewed_at"]),
                }
    except UnicodeDecodeError as error:
        raise AnalystEvaluationError("contextual label CSV is not valid UTF-8") from error
    except OSError as error:
        raise AnalystEvaluationError("contextual label CSV cannot be read") from error
    if set(entries) != expected_ids:
        raise AnalystEvaluationError("contextual labels must contain exactly every expected review ID")
    return entries


def _reference_agreement(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Describe overlaps without treating source observations as ground truth."""

    reference_names = (
        "rule_observation_present",
        "source_threat_observation_present",
        "anomaly_subtype_observation_present",
        "reference_observation_union",
    )
    payload: dict[str, object] = {}
    population = len(rows)
    top = [row for row in rows if row["analyst_review_selected"]]
    for name in reference_names:
        def observed(row: Mapping[str, object]) -> bool:
            context = row["reference_context"]
            if name == "reference_observation_union":
                return bool(context["rule_observation_present"] or context["source_threat_observation_present"])
            return bool(context[name])

        population_set = {int(row["source_record_number"]) for row in rows if observed(row)}
        top_set = {int(row["source_record_number"]) for row in top if observed(row)}
        selected_set = {int(row["source_record_number"]) for row in top}
        union = selected_set | population_set
        population_share = len(population_set) / population if population else 0.0
        top_share = len(top_set) / len(top) if top else 0.0
        payload[name] = {
            "top_50_and_observation": len(top_set),
            "top_50_without_observation": len(selected_set - population_set),
            "not_top_50_with_observation": len(population_set - selected_set),
            "not_top_50_without_observation": population - len(selected_set | population_set),
            "jaccard": None if not union else len(top_set) / len(union),
            "enrichment": None if population_share == 0 else top_share / population_share,
            "population_denominator": population,
            "top_50_denominator": len(top),
        }
    return payload


def evaluate_analyst_review(
    explanations_dir: str | Path,
    labels_path: str | Path,
    output_dir: str | Path,
    *,
    contextual_labels_path: str | Path | None = None,
    prior_evaluation_dir: str | Path | None = None,
) -> AnalystEvaluationSummary:
    """Freeze human labels and publish one separate no-replace evaluation bundle."""

    if (contextual_labels_path is None) != (prior_evaluation_dir is None):
        raise AnalystEvaluationError("contextual labels and prior evaluation directory must be supplied together")
    temporary: Path | None = None
    published = False
    try:
        pre_bundle = Path(explanations_dir)
        audit_explainability.audit_explanation_bundle(pre_bundle)
        metadata_path = pre_bundle / METADATA_ARTIFACT_NAME
        metadata = _read_json(metadata_path)
        rows = list(iter_explanation_rows(pre_bundle / audit_explainability.EXPLANATION_ARTIFACT_NAME))
        expected_review_ids = {str(row["review_id"]) for row in rows if row["review_id"] is not None}
        label_file = Path(labels_path)
        if label_file.is_symlink() or not label_file.is_file():
            raise AnalystEvaluationError("blind labels are unavailable or unsafe")
        labels = read_blind_labels(label_file, expected_review_ids)
        contextual: dict[str, dict[str, str]] = {}
        contextual_identity: dict[str, object] | None = None
        if contextual_labels_path is not None and prior_evaluation_dir is not None:
            prior = Path(prior_evaluation_dir) / EVALUATION_ARTIFACT_NAME
            previous = _read_json(prior)
            label_identity = _file_identity(label_file, label_file.name)
            if previous.get("frozen_blind_label_identity") != label_identity:
                raise AnalystEvaluationError("contextual evaluation does not retain the frozen blind-label identity")
            contextual_path = Path(contextual_labels_path)
            contextual = _read_contextual_labels(contextual_path, expected_review_ids)
            contextual_identity = _file_identity(contextual_path, contextual_path.name)
        records = []
        for row in rows:
            membership = "TOP_50" if row["analyst_review_selected"] else ("COMPARISON" if row["review_id"] is not None else "NOT_SELECTED")
            records.append(
                {
                    "source_record_number": row["source_record_number"],
                    "anomaly_rank": row["anomaly_rank"],
                    "review_id": row["review_id"],
                    "review_membership": membership,
                    "analyst_review_selected": row["analyst_review_selected"],
                }
            )
        evaluation = evaluate_review_mapping(records, labels)
        for result in evaluation["record_review_results"]:
            review_id = result["review_id"]
            if isinstance(review_id, str) and review_id in contextual:
                result["contextual_label"] = contextual[review_id]["contextual_label"]
        review_mapping = [
            {
                "review_id": record["review_id"],
                "source_record_number": record["source_record_number"],
                "review_membership": record["review_membership"],
            }
            for record in records
            if record["review_id"] is not None
        ]
        output = _resolve_new_output(output_dir)
        temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent))
        summary_payload = {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "upstream_identities": metadata["upstream_identities"],
            "pre_review_metadata_identity": _file_identity(metadata_path, METADATA_ARTIFACT_NAME),
            "queue_identity": metadata["queue_identity"],
            "frozen_blind_label_identity": _file_identity(label_file, label_file.name),
            "contextual_label_identity": contextual_identity,
            "selection_protocol_version": REVIEW_SELECTION_PROTOCOL_VERSION,
            "stratum_counts": metadata["stratum_counts"],
            "review_mapping": review_mapping,
            "record_review_results": evaluation["record_review_results"],
            "review_status_counts": evaluation["review_status_counts"],
            "resolved_matrix": evaluation["resolved_matrix"],
            "uncertain_counts_by_ai_decision": evaluation["uncertain_counts_by_ai_decision"],
            "resolved_review_count": evaluation["resolved_review_count"],
            "metrics": evaluation["metrics"],
            "precision_at_k": evaluation["precision_at_k"],
            "reference_agreement": _reference_agreement(rows),
            "interpretation_caveats": [
                "ANOMALY != ATTACK",
                "ANOMALY SCORE != ATTACK PROBABILITY",
                "RULE MATCH != CONFIRMED ATTACK",
                "SOURCE THREAT OBSERVATION != GROUND-TRUTH ATTACK LABEL",
                "SUSPECTED ATTACK TYPE != CONFIRMED ATTACK",
                "Reviewed-sample metrics are descriptive and do not estimate dataset-wide attack performance.",
            ],
        }
        if set(summary_payload) != EVALUATION_FIELDS:
            raise AnalystEvaluationError("evaluation summary does not contain exactly its contract fields")
        summary_path = temporary / EVALUATION_ARTIFACT_NAME
        summary_path.write_text(canonical_json(summary_payload) + "\n", encoding="utf-8", newline="\n")
        audit_explainability.audit_evaluation_bundle(
            pre_bundle,
            temporary,
            labels_path=label_file,
        )
        if _file_identity(label_file, label_file.name) != summary_payload["frozen_blind_label_identity"]:
            raise AnalystEvaluationError("blind labels changed while evaluation was built")
        if contextual_labels_path is not None:
            contextual_path = Path(contextual_labels_path)
            if contextual_identity is None or _file_identity(contextual_path, contextual_path.name) != contextual_identity:
                raise AnalystEvaluationError("contextual labels changed while evaluation was built")
        if output.exists():
            raise AnalystEvaluationError("evaluation output directory appeared during publication")
        if os.name != "nt":
            raise AnalystEvaluationError("atomic no-replace directory publication is unavailable on this platform")
        os.rename(temporary, output)
        published = True
        return AnalystEvaluationSummary(
            bundle_path=str(output),
            row_count=len(rows),
            reviewed_count=len(expected_review_ids),
            resolved_review_count=int(evaluation["resolved_review_count"]),
        )
    except (ReviewError, EvaluationError, audit_explainability.ExplainabilityAuditError, OSError, ValueError) as error:
        if isinstance(error, AnalystEvaluationError):
            raise
        raise AnalystEvaluationError(str(error)) from error
    finally:
        if temporary is not None and temporary.exists() and not published:
            shutil.rmtree(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate completed Stage 1.9 blind analyst reviews.")
    parser.add_argument("--explanations-dir", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--contextual-labels")
    parser.add_argument("--prior-evaluation-dir")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        summary = evaluate_analyst_review(
            arguments.explanations_dir,
            arguments.labels,
            arguments.output_dir,
            contextual_labels_path=arguments.contextual_labels,
            prior_evaluation_dir=arguments.prior_evaluation_dir,
        )
    except AnalystEvaluationError as error:
        print(f"Stage 1.9 analyst evaluation failed: {error}")
        return 1
    print(canonical_json(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
