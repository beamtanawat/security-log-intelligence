"""Build one deterministic, audited Stage 1.8 anomaly-score bundle."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import joblib

import audit_anomaly_scores
from ai_features.artifact import canonical_json, file_sha256
from ai_features.models import FEATURE_NAMES
from anomaly.artifact import (
    MANIFEST_ARTIFACT_NAME,
    MODEL_ARTIFACT_NAME,
    MODEL_METADATA_ARTIFACT_NAME,
    MODEL_METADATA_FIELDS,
    SCORE_ARTIFACT_NAME,
    AnomalyArtifactError,
    artifact_identity,
    build_manifest_payload,
    write_manifest,
    write_score_row,
)
from anomaly.input import (
    EXPECTED_STAGE_1_7_FEATURE_SHA256,
    AnomalyInputError,
    FeatureBundle,
    load_feature_bundle,
)
from anomaly.models import (
    ANOMALY_SCHEMA_VERSION,
    MATRIX_DTYPE,
    MODEL_KIND,
    PRIMARY_RANDOM_STATE,
    RANKING_SEMANTICS_VERSION,
    SCORE_SEMANTICS_VERSION,
    TRAINING_PARTITION,
    AnomalyContractError,
    collect_runtime_versions,
    model_config_payload,
    validate_runtime_versions,
)
from anomaly.scoring import (
    AnomalyScoringError,
    fit_reference_model,
    score_feature_rows,
    secondary_seed_sensitivity,
)


class AnomalyScoreBuildError(ValueError):
    """Raised when a Stage 1.8 output bundle cannot be safely published."""


@dataclass(frozen=True)
class AnomalyScoreBuildSummary:
    """Bounded summary of a newly published, audited score bundle."""

    bundle_path: str
    row_count: int
    reference_row_count: int
    holdout_row_count: int
    feature_sha256: str
    score_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "row_count": self.row_count,
            "reference_row_count": self.reference_row_count,
            "holdout_row_count": self.holdout_row_count,
            "feature_sha256": self.feature_sha256,
            "score_sha256": self.score_sha256,
        }


def _processed_root() -> Path:
    return (Path(__file__).resolve().parents[1] / "data" / "processed").resolve()


def _contains_path(parent: Path, child: Path) -> bool:
    return child != parent and parent in child.parents


def _has_existing_symlink_component(path: Path) -> bool:
    """Reject a requested path routed through an existing symlink component."""

    candidate = path.absolute()
    while True:
        if candidate.exists() and candidate.is_symlink():
            return True
        if candidate == candidate.parent:
            return False
        candidate = candidate.parent


def _resolve_output_path(output_dir: str | Path) -> Path:
    """Require a new, non-symlink bundle path below the repository processed root."""

    requested = Path(output_dir)
    if requested.is_symlink() or _has_existing_symlink_component(requested):
        raise AnomalyScoreBuildError("output directory path must not be a symlink")
    resolved = requested.resolve()
    processed_root = _processed_root()
    if not _contains_path(processed_root, resolved):
        raise AnomalyScoreBuildError("output directory must be beneath data/processed")
    if resolved.exists():
        raise AnomalyScoreBuildError("output directory already exists")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise AnomalyScoreBuildError("output parent directory is unavailable or unsafe")
    return resolved


def _write_model_metadata(
    path: Path,
    *,
    features: FeatureBundle,
    model_identity: Mapping[str, object],
    score_identity: Mapping[str, object],
    runtime_versions: Mapping[str, str],
    reference_distribution: tuple[tuple[float, int], ...],
    partition_diagnostics: Mapping[str, object],
    seed_sensitivity: Mapping[str, object],
) -> None:
    """Write exact model provenance without a circular metadata self-hash."""

    metadata: dict[str, object] = {
        "schema_version": ANOMALY_SCHEMA_VERSION,
        "model_kind": MODEL_KIND,
        "model_config": model_config_payload(),
        "feature_metadata_identity": dict(features.feature_metadata_identity),
        "feature_artifact_identity": dict(features.feature_artifact_identity),
        "normalized_input_identity": dict(features.metadata["normalized_input"]),
        "feature_names": list(FEATURE_NAMES),
        "matrix_dtype": MATRIX_DTYPE,
        "reference_count": features.reference_count,
        "holdout_count": features.holdout_count,
        "score_semantics_version": SCORE_SEMANTICS_VERSION,
        "reference_raw_score_distribution": [list(item) for item in reference_distribution],
        "score_artifact_identity": dict(score_identity),
        "model_artifact_identity": dict(model_identity),
        "dependency_versions": dict(runtime_versions),
        "partition_diagnostics": dict(partition_diagnostics),
        "determinism_result": {
            "primary_random_state": PRIMARY_RANDOM_STATE,
            "canonical_score_payload_sha256": score_identity["sha256"],
            "same_environment_repeat": "AWAITING_LOCAL_VALIDATION",
        },
        "seed_sensitivity": dict(seed_sensitivity),
        "ranking_semantics_version": RANKING_SEMANTICS_VERSION,
    }
    if set(metadata) != MODEL_METADATA_FIELDS:
        raise AnomalyScoreBuildError("generated model metadata does not contain exactly its contract fields")
    try:
        path.write_text(canonical_json(metadata) + "\n", encoding="utf-8", newline="\n")
    except OSError as error:
        raise AnomalyScoreBuildError("model metadata cannot be written") from error


def _input_identities_unchanged(features: FeatureBundle) -> bool:
    """Check immutable Stage 1.7 artifacts after model construction."""

    feature_path = features.directory / "stage_1_7_ai_features.jsonl"
    metadata_path = features.directory / "stage_1_7_ai_feature_metadata.json"
    return (
        file_sha256(feature_path) == features.feature_artifact_identity["sha256"]
        and file_sha256(metadata_path) == features.feature_metadata_identity["sha256"]
    )


def score_anomaly_bundle(
    features_dir: str | Path,
    output_dir: str | Path,
    *,
    expected_feature_sha256: str | None = EXPECTED_STAGE_1_7_FEATURE_SHA256,
) -> AnomalyScoreBuildSummary:
    """Fit REFERENCE only, score all input rows, audit, then no-replace publish."""

    try:
        output = _resolve_output_path(output_dir)
        features = load_feature_bundle(
            features_dir, expected_feature_sha256=expected_feature_sha256
        )
        if features.directory == output or features.directory in output.parents or output in features.directory.parents:
            raise AnomalyScoreBuildError("input feature bundle and output bundle must not alias or nest")
        runtime_versions = validate_runtime_versions(collect_runtime_versions())
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
        )
    except (AnomalyInputError, AnomalyContractError, OSError, ValueError) as error:
        if isinstance(error, AnomalyScoreBuildError):
            raise
        raise AnomalyScoreBuildError(str(error)) from error

    published = False
    try:
        model = fit_reference_model(features.rows, versions=runtime_versions)
        scored_rows, diagnostics = score_feature_rows(features.rows, model)
        score_path = temporary / SCORE_ARTIFACT_NAME
        with score_path.open("w", encoding="utf-8", newline="\n") as handle:
            for score_row in scored_rows:
                write_score_row(handle, score_row)
        model_path = temporary / MODEL_ARTIFACT_NAME
        joblib.dump(model, model_path)
        score_identity = artifact_identity(score_path, SCORE_ARTIFACT_NAME, row_count=len(scored_rows))
        model_identity = artifact_identity(model_path, MODEL_ARTIFACT_NAME)
        sensitivity = secondary_seed_sensitivity(
            features.rows, scored_rows, versions=runtime_versions
        )
        metadata_path = temporary / MODEL_METADATA_ARTIFACT_NAME
        _write_model_metadata(
            metadata_path,
            features=features,
            model_identity=model_identity,
            score_identity=score_identity,
            runtime_versions=runtime_versions,
            reference_distribution=diagnostics.reference_raw_distribution,
            partition_diagnostics=diagnostics.partition_diagnostics,
            seed_sensitivity=sensitivity,
        )
        # Audit completed model/score/metadata artifacts before finalizing their
        # separate trust manifest, and never publish if that audit fails.
        audit_anomaly_scores.audit_anomaly_score_bundle(
            features.directory,
            temporary,
            expected_feature_sha256=expected_feature_sha256,
            require_manifest=False,
        )
        metadata_identity = artifact_identity(metadata_path, MODEL_METADATA_ARTIFACT_NAME)
        manifest = build_manifest_payload(
            feature_sha256=str(features.feature_artifact_identity["sha256"]),
            feature_count=len(FEATURE_NAMES),
            reference_count=features.reference_count,
            holdout_count=features.holdout_count,
            feature_contract_sha256=features.feature_contract_sha256,
            model_artifact_sha256=str(model_identity["sha256"]),
            model_metadata_sha256=str(metadata_identity["sha256"]),
            score_artifact_sha256=str(score_identity["sha256"]),
            runtime_versions=runtime_versions,
        )
        write_manifest(temporary / MANIFEST_ARTIFACT_NAME, manifest)
        audit_anomaly_scores.audit_anomaly_score_bundle(
            features.directory,
            temporary,
            expected_feature_sha256=expected_feature_sha256,
            require_manifest=True,
        )
        if not _input_identities_unchanged(features):
            raise AnomalyScoreBuildError("Stage 1.7 input artifact changed during scoring")
        if output.exists():
            raise AnomalyScoreBuildError("final output directory appeared during scoring")
        # Windows MoveFile-based directory rename refuses an existing target.
        # The required deployment environment is Windows, so other platforms
        # fail closed rather than relying on replacement-capable semantics.
        if os.name != "nt":
            raise AnomalyScoreBuildError(
                "atomic no-replace directory publication is unavailable on this platform"
            )
        try:
            os.rename(temporary, output)
        except FileExistsError as error:
            raise AnomalyScoreBuildError("final output directory appeared during scoring") from error
        published = True
        return AnomalyScoreBuildSummary(
            bundle_path=str(output),
            row_count=len(scored_rows),
            reference_row_count=features.reference_count,
            holdout_row_count=features.holdout_count,
            feature_sha256=str(features.feature_artifact_identity["sha256"]),
            score_sha256=str(score_identity["sha256"]),
        )
    except (
        AnomalyArtifactError,
        AnomalyContractError,
        AnomalyInputError,
        AnomalyScoringError,
        audit_anomaly_scores.AnomalyScoreAuditError,
        OSError,
        ValueError,
    ) as error:
        if isinstance(error, AnomalyScoreBuildError):
            raise
        raise AnomalyScoreBuildError(str(error)) from error
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build one audited Stage 1.8 Isolation Forest anomaly-score bundle."
    )
    parser.add_argument("--features-dir", required=True, help="Immutable Stage 1.7 feature bundle")
    parser.add_argument(
        "--output-dir", required=True, help="New Stage 1.8 bundle directory below data/processed"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        summary = score_anomaly_bundle(arguments.features_dir, arguments.output_dir)
    except AnomalyScoreBuildError as error:
        print(f"Stage 1.8 score build failed: {error}")
        return 1
    print(canonical_json(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
