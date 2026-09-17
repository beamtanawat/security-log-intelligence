"""Build one deterministic, audited Stage 1.9 pre-review explanation bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

import audit_explainability
from ai_features.artifact import canonical_json, file_sha256
from anomaly.artifact import (
    ANOMALY_ARTIFACT_NAMES,
    MANIFEST_ARTIFACT_NAME,
    MODEL_ARTIFACT_NAME,
    MODEL_METADATA_ARTIFACT_NAME,
    SCORE_ARTIFACT_NAME,
    artifact_identity,
    read_exact_json_object,
    read_manifest,
    read_score_rows,
)
from anomaly.input import EXPECTED_STAGE_1_7_FEATURE_SHA256, AnomalyInputError, load_feature_bundle
from anomaly.models import AnomalyScoreRow
from audit_explainability import (
    EXPLANATION_ARTIFACT_NAME,
    METADATA_ARTIFACT_NAME,
    QUEUE_ARTIFACT_NAME,
)
from detection.input import DetectionInputError, iter_normalized_events
from explainability.interpretation import (
    EXPLANATION_SCHEMA_VERSION,
    REASON_REGISTRY_VERSION,
    InterpretationError,
    assign_investigation_ranks,
    build_explanation,
)
from explainability.drivers import compile_reference_index
from evaluation.review import (
    REVIEW_SELECTION_PROTOCOL_VERSION,
    ReviewError,
    build_review_sample,
    write_review_queue,
)
from storage.input import (
    StorageInputValidationError,
    calculate_artifact_identity,
    validate_detection_artifacts,
)


EXPECTED_STAGE_1_8_SCORE_SHA256 = "f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4"
EXPECTED_STAGE_1_8_MANIFEST_SHA256 = "9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77"


class ExplainBuildError(ValueError):
    """Raised when a Stage 1.9 explanation bundle cannot publish safely."""


@dataclass(frozen=True)
class ExplainBuildSummary:
    bundle_path: str
    row_count: int
    review_queue_count: int
    feature_sha256: str
    score_sha256: str
    manifest_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "row_count": self.row_count,
            "review_queue_count": self.review_queue_count,
            "feature_sha256": self.feature_sha256,
            "score_sha256": self.score_sha256,
            "manifest_sha256": self.manifest_sha256,
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _processed_root() -> Path:
    return (_project_root() / "data" / "processed").resolve()


def _contains(parent: Path, child: Path) -> bool:
    return child != parent and parent in child.parents


def _has_symlink_component(path: Path) -> bool:
    candidate = path.absolute()
    while candidate != candidate.parent:
        if candidate.exists() and candidate.is_symlink():
            return True
        candidate = candidate.parent
    return candidate.exists() and candidate.is_symlink()


def _resolve_output_dir(value: str | Path) -> Path:
    supplied = Path(value)
    if supplied.is_symlink() or _has_symlink_component(supplied):
        raise ExplainBuildError("output directory path must not traverse a symlink")
    resolved = supplied.resolve()
    root = _processed_root()
    if not _contains(root, resolved):
        raise ExplainBuildError("output directory must be beneath data/processed")
    if resolved.exists():
        raise ExplainBuildError("output directory already exists")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise ExplainBuildError("output parent is unavailable or unsafe")
    return resolved


def _identity(path: Path, name: str, *, row_count: int | None = None) -> dict[str, object]:
    identity = artifact_identity(path, name, row_count=row_count)
    return dict(identity)


def _require_score_bundle(
    scores_dir: str | Path,
    *,
    expected_score_sha256: str | None,
    expected_manifest_sha256: str | None,
) -> tuple[Path, tuple[AnomalyScoreRow, ...], Mapping[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    supplied = Path(scores_dir)
    if supplied.is_symlink() or not supplied.is_dir():
        raise ExplainBuildError("Stage 1.8 score bundle is unavailable or unsafe")
    directory = supplied.resolve()
    if directory == _processed_root() or _processed_root() not in directory.parents:
        raise ExplainBuildError("Stage 1.8 score bundle must be beneath data/processed")
    try:
        if {child.name for child in directory.iterdir()} != ANOMALY_ARTIFACT_NAMES:
            raise ExplainBuildError("Stage 1.8 score bundle must contain exactly its four artifacts")
    except OSError as error:
        raise ExplainBuildError("Stage 1.8 score bundle cannot be inspected") from error
    score_path = directory / SCORE_ARTIFACT_NAME
    model_path = directory / MODEL_ARTIFACT_NAME
    metadata_path = directory / MODEL_METADATA_ARTIFACT_NAME
    manifest_path = directory / MANIFEST_ARTIFACT_NAME
    if any(path.is_symlink() or not path.is_file() for path in (score_path, model_path, metadata_path, manifest_path)):
        raise ExplainBuildError("Stage 1.8 score bundle contains unsafe artifact paths")
    score_identity = _identity(score_path, SCORE_ARTIFACT_NAME)
    manifest_identity = _identity(manifest_path, MANIFEST_ARTIFACT_NAME)
    if expected_score_sha256 is not None and score_identity["sha256"] != expected_score_sha256.lower():
        raise ExplainBuildError("Stage 1.8 score SHA-256 does not match the approved identity")
    if expected_manifest_sha256 is not None and manifest_identity["sha256"] != expected_manifest_sha256.lower():
        raise ExplainBuildError("Stage 1.8 manifest SHA-256 does not match the approved identity")
    try:
        manifest = read_manifest(manifest_path)
        if manifest["score_artifact_sha256"] != score_identity["sha256"]:
            raise ExplainBuildError("Stage 1.8 manifest score identity does not reconcile")
        if file_sha256(model_path) != manifest["model_artifact_sha256"]:
            raise ExplainBuildError("Stage 1.8 manifest model identity does not reconcile")
        metadata = read_exact_json_object(
            metadata_path,
            frozenset(
                {
                    "schema_version", "model_kind", "model_config", "feature_metadata_identity",
                    "feature_artifact_identity", "normalized_input_identity", "feature_names",
                    "matrix_dtype", "reference_count", "holdout_count", "score_semantics_version",
                    "reference_raw_score_distribution", "score_artifact_identity", "model_artifact_identity",
                    "dependency_versions", "partition_diagnostics", "determinism_result", "seed_sensitivity",
                    "ranking_semantics_version",
                }
            ),
        )
        metadata_identity = _identity(metadata_path, MODEL_METADATA_ARTIFACT_NAME)
        if manifest["model_metadata_sha256"] != metadata_identity["sha256"]:
            raise ExplainBuildError("Stage 1.8 manifest model metadata identity does not reconcile")
        rows = tuple(read_score_rows(score_path))
        score_identity = _identity(score_path, SCORE_ARTIFACT_NAME, row_count=len(rows))
        if metadata["score_artifact_identity"] != score_identity:
            raise ExplainBuildError("Stage 1.8 score metadata identity does not reconcile")
    except (ValueError, OSError) as error:
        if isinstance(error, ExplainBuildError):
            raise
        raise ExplainBuildError("Stage 1.8 score artifacts are incompatible") from error
    if not rows:
        raise ExplainBuildError("Stage 1.8 score artifact contains no rows")
    return directory, rows, manifest, score_identity, metadata_identity, manifest_identity


def _operational_context(event: object, matched_rule_ids: tuple[str, ...]) -> dict[str, object]:
    network = event.network
    source = network.get("source")
    destination = network.get("destination")
    application = event.application
    session = event.session
    threats = event.threat_observations
    if not all(isinstance(item, Mapping) for item in (source, destination, application, session, threats)):
        raise ExplainBuildError("normalized event operational context is incompatible")
    source_threat_rule = "fortigate.source_threat_observation" in matched_rule_ids
    anomaly_rule = "fortigate.anomaly_subtype_observation" in matched_rule_ids
    return {
        "protocol_number": network.get("protocol_number"),
        "protocol_name": network.get("protocol_name"),
        "source_port": source.get("port"),
        "destination_port": destination.get("port"),
        "service_source": application.get("service_source"),
        "source_identifier": source.get("identifier"),
        "destination_identifier": destination.get("identifier"),
        "sent_bytes": session.get("sent_bytes"),
        "received_bytes": session.get("received_bytes"),
        "sent_packets": session.get("sent_packets"),
        "received_packets": session.get("received_packets"),
        "duration_raw_value": session.get("duration_raw_value"),
        "source_port_missing": source.get("port") is None,
        "destination_port_missing": destination.get("port") is None,
        "service_missing": application.get("service_source") in {None, ""},
        "sent_bytes_missing": session.get("sent_bytes") is None,
        "received_bytes_missing": session.get("received_bytes") is None,
        "sent_packets_missing": session.get("sent_packets") is None,
        "received_packets_missing": session.get("received_packets") is None,
        "duration_missing": session.get("duration_raw_value") is None,
        "source_threat_type": threats.get("type_source"),
        "matched_rule_ids": matched_rule_ids,
        "source_threat_observation_present": source_threat_rule,
        "anomaly_subtype_observation_present": anomaly_rule,
    }


def _write_explanations(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(canonical_json(dict(row)) + "\n")


def _top_50_identity(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    records = [int(row["source_record_number"]) for row in rows if row["analyst_review_selected"]]
    if len(records) != 50:
        raise ExplainBuildError("Stage 1.8 Top-50 membership is incomplete")
    digest = hashlib.sha256(canonical_json(records).encode("utf-8")).hexdigest()
    return {"row_count": len(records), "sha256": digest}


def _write_metadata(
    path: Path,
    *,
    upstream: Mapping[str, object],
    row_count: int,
    explanation_identity: Mapping[str, object],
    queue_identity: Mapping[str, object],
    stratum_counts: Mapping[str, int],
    top_50_identity: Mapping[str, object],
) -> None:
    payload = {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "upstream_identities": dict(upstream),
        "row_count": row_count,
        "explanation_artifact_identity": dict(explanation_identity),
        "queue_identity": dict(queue_identity),
        "selection_protocol_version": REVIEW_SELECTION_PROTOCOL_VERSION,
        "reason_registry_version": REASON_REGISTRY_VERSION,
        "stratum_counts": dict(stratum_counts),
        "top_50_identity": dict(top_50_identity),
    }
    if set(payload) != audit_explainability.METADATA_FIELDS:
        raise ExplainBuildError("Stage 1.9 metadata does not contain exactly its contract fields")
    path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")


def build_explanation_bundle(
    features_dir: str | Path,
    scores_dir: str | Path,
    normalized_path: str | Path,
    findings_path: str | Path,
    summary_path: str | Path,
    output_dir: str | Path,
    *,
    expected_feature_sha256: str | None = EXPECTED_STAGE_1_7_FEATURE_SHA256,
    expected_score_sha256: str | None = EXPECTED_STAGE_1_8_SCORE_SHA256,
    expected_manifest_sha256: str | None = EXPECTED_STAGE_1_8_MANIFEST_SHA256,
) -> ExplainBuildSummary:
    """Build, audit, and no-replace publish a Stage 1.9 pre-review bundle."""

    temporary: Path | None = None
    published = False
    try:
        output = _resolve_output_dir(output_dir)
        features = load_feature_bundle(features_dir, expected_feature_sha256=expected_feature_sha256)
        score_directory, scores, manifest, score_identity, score_metadata_identity, manifest_identity = _require_score_bundle(
            scores_dir,
            expected_score_sha256=expected_score_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        if manifest["stage_1_7_feature_sha256"] != features.feature_artifact_identity["sha256"]:
            raise ExplainBuildError("Stage 1.8 manifest does not bind the supplied feature artifact")
        if len(features.rows) != len(scores):
            raise ExplainBuildError("Stage 1.7 and Stage 1.8 row counts do not reconcile")
        reference_index = compile_reference_index(features.metadata)
        normalized = Path(normalized_path)
        if not normalized.is_file() or normalized.is_symlink():
            raise ExplainBuildError("normalized input is unavailable or unsafe")
        normalized_identity = {
            "path": str(normalized.resolve()),
            "size_bytes": normalized.stat().st_size,
            "sha256": file_sha256(normalized),
            "schema_version": "1.0",
        }
        if normalized_identity != dict(features.metadata["normalized_input"]):
            raise ExplainBuildError("normalized input identity does not match Stage 1.7 metadata")
        detection_identity = calculate_artifact_identity(findings_path, summary_path)
        findings_by_record: dict[int, list[str]] = {}

        def capture_finding(finding: object) -> None:
            findings_by_record.setdefault(finding.source_event.source_record_number, []).append(finding.rule.rule_id)

        validated_detection = validate_detection_artifacts(
            findings_path, summary_path, detection_identity, on_finding=capture_finding
        )
        if validated_detection.summary.normalized_input_record_count != len(features.rows):
            raise ExplainBuildError("Stage 1.4 findings do not reconcile to Stage 1.7 population")
        temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent))
        explanations: list[dict[str, object]] = []
        event_iterator = iter_normalized_events(normalized)
        for feature, score, event in zip(features.rows, scores, event_iterator, strict=True):
            if (
                event.source_record.record_number != feature.source_record_number
                or event.event.get("source_record_id") != feature.source_record_id
                or score.source_record_number != feature.source_record_number
                or score.source_record_id != feature.source_record_id
            ):
                raise ExplainBuildError("Stage 1.3/1.7/1.8 provenance join does not reconcile")
            rule_ids = tuple(sorted(set(findings_by_record.get(feature.source_record_number, []))))
            explanations.append(
                build_explanation(
                    feature,
                    score,
                    features.metadata,
                    _operational_context(event, rule_ids),
                    reference_index=reference_index,
                )
            )
        try:
            next(event_iterator)
        except StopIteration:
            pass
        else:
            raise ExplainBuildError("normalized input contains extra records")
        explanations = assign_investigation_ranks(explanations)
        review_sample, stratum_counts = build_review_sample(explanations, str(normalized_identity["sha256"]))
        review_ids = {int(row["source_record_number"]): str(row["review_id"]) for row in review_sample}
        for row in explanations:
            row["review_id"] = review_ids.get(int(row["source_record_number"]))
        explanation_path = temporary / EXPLANATION_ARTIFACT_NAME
        queue_path = temporary / QUEUE_ARTIFACT_NAME
        _write_explanations(explanation_path, explanations)
        queue_count = write_review_queue(queue_path, review_sample)
        explanation_identity = _identity(explanation_path, EXPLANATION_ARTIFACT_NAME, row_count=len(explanations))
        queue_identity = _identity(queue_path, QUEUE_ARTIFACT_NAME, row_count=queue_count)
        upstream = {
            "feature_artifact": dict(features.feature_artifact_identity),
            "feature_metadata": dict(features.feature_metadata_identity),
            "score_artifact": score_identity,
            "score_metadata": score_metadata_identity,
            "manifest": manifest_identity,
            "normalized": normalized_identity,
            "findings": {"path": Path(findings_path).name, "sha256": detection_identity.findings_sha256},
            "summary": {"path": Path(summary_path).name, "sha256": detection_identity.summary_sha256},
        }
        _write_metadata(
            temporary / METADATA_ARTIFACT_NAME,
            upstream=upstream,
            row_count=len(explanations),
            explanation_identity=explanation_identity,
            queue_identity=queue_identity,
            stratum_counts=stratum_counts,
            top_50_identity=_top_50_identity(explanations),
        )
        audit_explainability.audit_explanation_bundle(temporary)
        if file_sha256(normalized) != normalized_identity["sha256"]:
            raise ExplainBuildError("normalized input changed while explanations were built")
        if (
            file_sha256(features.directory / "stage_1_7_ai_features.jsonl")
            != features.feature_artifact_identity["sha256"]
            or file_sha256(features.directory / "stage_1_7_ai_feature_metadata.json")
            != features.feature_metadata_identity["sha256"]
            or file_sha256(score_directory / SCORE_ARTIFACT_NAME) != score_identity["sha256"]
            or file_sha256(score_directory / MODEL_METADATA_ARTIFACT_NAME) != score_metadata_identity["sha256"]
            or file_sha256(score_directory / MANIFEST_ARTIFACT_NAME) != manifest_identity["sha256"]
            or file_sha256(score_directory / MODEL_ARTIFACT_NAME) != manifest["model_artifact_sha256"]
        ):
            raise ExplainBuildError("immutable Stage 1.7 or Stage 1.8 input changed while explanations were built")
        if calculate_artifact_identity(findings_path, summary_path) != detection_identity:
            raise ExplainBuildError("immutable Stage 1.4 detection artifacts changed while explanations were built")
        if output.exists():
            raise ExplainBuildError("final output directory appeared during publication")
        if os.name != "nt":
            raise ExplainBuildError("atomic no-replace directory publication is unavailable on this platform")
        os.rename(temporary, output)
        published = True
        return ExplainBuildSummary(
            bundle_path=str(output),
            row_count=len(explanations),
            review_queue_count=queue_count,
            feature_sha256=str(features.feature_artifact_identity["sha256"]),
            score_sha256=str(score_identity["sha256"]),
            manifest_sha256=str(manifest_identity["sha256"]),
        )
    except (
        AnomalyInputError,
        DetectionInputError,
        StorageInputValidationError,
        InterpretationError,
        ReviewError,
        audit_explainability.ExplainabilityAuditError,
        OSError,
        ValueError,
    ) as error:
        if isinstance(error, ExplainBuildError):
            raise
        raise ExplainBuildError(str(error)) from error
    finally:
        if temporary is not None and temporary.exists() and not published:
            shutil.rmtree(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build one audited Stage 1.9 explanation bundle.")
    parser.add_argument("--features-dir", required=True)
    parser.add_argument("--scores-dir", required=True)
    parser.add_argument("--normalized", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        summary = build_explanation_bundle(
            arguments.features_dir,
            arguments.scores_dir,
            arguments.normalized,
            arguments.findings,
            arguments.summary,
            arguments.output_dir,
        )
    except ExplainBuildError as error:
        print(f"Stage 1.9 explanation build failed: {error}")
        return 1
    print(canonical_json(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
