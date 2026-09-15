"""Independent read-only reconciliation for a Stage 1.8 score bundle."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import Mapping, Sequence

from ai_features.models import FEATURE_NAMES, HOLDOUT_PARTITION, REFERENCE_PARTITION
from anomaly.artifact import (
    ANOMALY_ARTIFACT_NAMES,
    MANIFEST_ARTIFACT_NAME,
    MODEL_ARTIFACT_NAME,
    MODEL_METADATA_ARTIFACT_NAME,
    MODEL_METADATA_FIELDS,
    SCORE_ARTIFACT_NAME,
    AnomalyArtifactError,
    artifact_identity,
    build_manifest_payload,
    load_trusted_model,
    read_exact_json_object,
    read_manifest,
    read_score_rows,
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
    AnomalyContractError,
    AnomalyScoreRow,
    model_config_payload,
    validate_runtime_versions,
)
from anomaly.scoring import AnomalyScoringError, assign_anomaly_band, score_feature_rows


class AnomalyScoreAuditError(ValueError):
    """Raised when a persisted Stage 1.8 artifact cannot be reconciled."""


@dataclass(frozen=True)
class AnomalyScoreAuditSummary:
    """Bounded result of an independent successful Stage 1.8 audit."""

    row_count: int
    reference_row_count: int
    holdout_row_count: int
    score_sha256: str
    manifest_sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "row_count": self.row_count,
            "reference_row_count": self.reference_row_count,
            "holdout_row_count": self.holdout_row_count,
            "score_sha256": self.score_sha256,
            "manifest_sha256": self.manifest_sha256,
        }


def _require_identity(
    value: object, name: str, *, includes_row_count: bool = False
) -> Mapping[str, object]:
    expected = {"path", "size_bytes", "sha256"}
    if includes_row_count:
        expected.add("row_count")
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AnomalyScoreAuditError(f"{name} artifact identity is incompatible")
    if not isinstance(value["path"], str) or not value["path"]:
        raise AnomalyScoreAuditError(f"{name} artifact identity is incompatible")
    if isinstance(value["size_bytes"], bool) or not isinstance(value["size_bytes"], int):
        raise AnomalyScoreAuditError(f"{name} artifact identity is incompatible")
    if not isinstance(value["sha256"], str) or len(value["sha256"]) != 64:
        raise AnomalyScoreAuditError(f"{name} artifact identity is incompatible")
    if includes_row_count and (
        isinstance(value["row_count"], bool)
        or not isinstance(value["row_count"], int)
        or value["row_count"] < 1
    ):
        raise AnomalyScoreAuditError(f"{name} artifact identity is incompatible")
    return value


def _require_exact_output_bundle(bundle: Path, *, require_manifest: bool) -> dict[str, Path]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise AnomalyScoreAuditError("Stage 1.8 score bundle directory is unavailable or unsafe")
    expected = set(ANOMALY_ARTIFACT_NAMES)
    if not require_manifest:
        expected.remove(MANIFEST_ARTIFACT_NAME)
    try:
        if {item.name for item in bundle.iterdir()} != expected:
            raise AnomalyScoreAuditError("Stage 1.8 score bundle has unexpected artifacts")
    except OSError as error:
        raise AnomalyScoreAuditError("Stage 1.8 score bundle cannot be inspected") from error
    paths = {name: bundle / name for name in expected}
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        raise AnomalyScoreAuditError("Stage 1.8 score bundle contains an unsafe artifact path")
    return paths


def _require_processed_bundle_path(path: str | Path) -> Path:
    supplied = Path(path)
    if supplied.is_symlink() or not supplied.is_dir():
        raise AnomalyScoreAuditError("Stage 1.8 score bundle directory is unavailable or unsafe")
    resolved = supplied.resolve()
    processed_root = (Path(__file__).resolve().parents[1] / "data" / "processed").resolve()
    if resolved == processed_root or processed_root not in resolved.parents:
        raise AnomalyScoreAuditError("Stage 1.8 score bundle must be beneath data/processed")
    return resolved


def _expected_percentiles_and_ranks(
    rows: Sequence[AnomalyScoreRow],
) -> tuple[tuple[float, ...], dict[int, int]]:
    raw_reference = sorted(row.raw_abnormality for row in rows if row.partition == REFERENCE_PARTITION)
    if not raw_reference:
        raise AnomalyScoreAuditError("score bundle contains no REFERENCE rows")
    if raw_reference[0] == raw_reference[-1]:
        raise AnomalyScoreAuditError("DEGENERATE_SCORE_REFERENCE")
    percentiles = tuple(
        float(100.0 * bisect_right(raw_reference, row.raw_abnormality) / len(raw_reference))
        for row in rows
    )
    indexes = sorted(
        range(len(rows)),
        key=lambda index: (-rows[index].raw_abnormality, rows[index].source_record_number),
    )
    return percentiles, {index: rank for rank, index in enumerate(indexes, start=1)}


def _audit_score_rows(features: FeatureBundle, scores: Sequence[AnomalyScoreRow]) -> None:
    if len(scores) != len(features.rows):
        raise AnomalyScoreAuditError("score row count does not reconcile to feature rows")
    for feature, score in zip(features.rows, scores, strict=True):
        if (
            score.source_record_number != feature.source_record_number
            or score.source_record_id != feature.source_record_id
            or score.partition != feature.partition
        ):
            raise AnomalyScoreAuditError("score provenance does not reconcile to Stage 1.7 feature rows")
        if not isfinite(score.model_score) or not isfinite(score.raw_abnormality):
            raise AnomalyScoreAuditError("score row contains a non-finite model value")
        if score.raw_abnormality != -score.model_score:
            raise AnomalyScoreAuditError("score row raw abnormality does not match model-score direction")
    percentiles, ranks = _expected_percentiles_and_ranks(scores)
    review_records: set[int] = set()
    for index, score in enumerate(scores):
        expected_percentile = percentiles[index]
        if score.anomaly_score != float(round(expected_percentile, 6)):
            raise AnomalyScoreAuditError("score percentile does not match the reference empirical CDF")
        if score.anomaly_band != assign_anomaly_band(expected_percentile):
            raise AnomalyScoreAuditError("score band does not match unrounded percentile")
        if score.anomaly_rank != ranks[index]:
            raise AnomalyScoreAuditError("score ranking does not match raw-score order and tie-break")
        if score.analyst_review_selected != (score.anomaly_rank <= 50):
            raise AnomalyScoreAuditError("Top-50 review selection does not match rank")
        if score.analyst_review_selected:
            review_records.add(score.source_record_number)
    expected_review_count = min(50, len(scores))
    if len(review_records) != expected_review_count:
        raise AnomalyScoreAuditError("Top-50 review selection is incomplete or duplicated")


def _distribution(scores: Sequence[AnomalyScoreRow]) -> list[list[float | int]]:
    values = Counter(
        row.raw_abnormality for row in scores if row.partition == REFERENCE_PARTITION
    )
    return [[float(value), int(count)] for value, count in sorted(values.items())]


def _quantiles(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    ordered = sorted(values)

    def quantile(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)

    return {
        "minimum": quantile(0.0),
        "p25": quantile(0.25),
        "p50": quantile(0.5),
        "p75": quantile(0.75),
        "maximum": quantile(1.0),
    }


def _expected_partition_diagnostics(scores: Sequence[AnomalyScoreRow]) -> dict[str, object]:
    diagnostics: dict[str, object] = {}
    for partition in (REFERENCE_PARTITION, HOLDOUT_PARTITION):
        rows = [row for row in scores if row.partition == partition]
        raw_values = [row.raw_abnormality for row in rows]
        bands = Counter(row.anomaly_band for row in rows)
        diagnostics[partition] = {
            "row_count": len(rows),
            "raw_abnormality_quantiles": _quantiles(raw_values),
            "distinct_raw_score_count": len(set(raw_values)),
            "tied_row_count": len(raw_values) - len(set(raw_values)),
            "band_counts": {
                "TOP_0_1_PERCENT": bands["TOP_0_1_PERCENT"],
                "TOP_1_PERCENT": bands["TOP_1_PERCENT"],
                "TOP_5_PERCENT": bands["TOP_5_PERCENT"],
                "BASELINE": bands["BASELINE"],
            },
        }
    return diagnostics


def _audit_metadata(
    metadata: Mapping[str, object],
    *,
    features: FeatureBundle,
    scores: Sequence[AnomalyScoreRow],
    paths: Mapping[str, Path],
) -> None:
    if metadata["schema_version"] != ANOMALY_SCHEMA_VERSION:
        raise AnomalyScoreAuditError("model metadata schema version is incompatible")
    if metadata["model_kind"] != MODEL_KIND or metadata["model_config"] != model_config_payload():
        raise AnomalyScoreAuditError("model metadata Isolation Forest contract is incompatible")
    if metadata["feature_names"] != list(FEATURE_NAMES) or metadata["matrix_dtype"] != MATRIX_DTYPE:
        raise AnomalyScoreAuditError("model metadata feature matrix contract is incompatible")
    _require_identity(metadata["feature_metadata_identity"], "feature metadata")
    _require_identity(metadata["feature_artifact_identity"], "feature", includes_row_count=False)
    _require_identity(metadata["score_artifact_identity"], "score", includes_row_count=True)
    _require_identity(metadata["model_artifact_identity"], "model")
    if metadata["feature_metadata_identity"] != dict(features.feature_metadata_identity):
        raise AnomalyScoreAuditError("model metadata feature metadata identity is incompatible")
    if metadata["feature_artifact_identity"] != dict(features.feature_artifact_identity):
        raise AnomalyScoreAuditError("model metadata feature artifact identity is incompatible")
    if metadata["normalized_input_identity"] != dict(features.metadata["normalized_input"]):
        raise AnomalyScoreAuditError("model metadata normalized input identity is incompatible")
    if (metadata["reference_count"], metadata["holdout_count"]) != (
        features.reference_count,
        features.holdout_count,
    ):
        raise AnomalyScoreAuditError("model metadata partition counts are incompatible")
    if metadata["score_semantics_version"] != SCORE_SEMANTICS_VERSION:
        raise AnomalyScoreAuditError("model metadata score contract is incompatible")
    if metadata["ranking_semantics_version"] != RANKING_SEMANTICS_VERSION:
        raise AnomalyScoreAuditError("model metadata ranking contract is incompatible")
    if metadata["reference_raw_score_distribution"] != _distribution(scores):
        raise AnomalyScoreAuditError("model metadata reference score distribution is incompatible")
    if metadata["score_artifact_identity"] != artifact_identity(
        paths[SCORE_ARTIFACT_NAME], SCORE_ARTIFACT_NAME, row_count=len(scores)
    ):
        raise AnomalyScoreAuditError("model metadata score artifact identity is incompatible")
    if metadata["model_artifact_identity"] != artifact_identity(
        paths[MODEL_ARTIFACT_NAME], MODEL_ARTIFACT_NAME
    ):
        raise AnomalyScoreAuditError("model metadata model artifact identity is incompatible")
    try:
        dependency_versions = validate_runtime_versions(metadata["dependency_versions"])
    except AnomalyContractError as error:
        raise AnomalyScoreAuditError("model metadata runtime provenance is incompatible") from error
    if metadata["partition_diagnostics"] != _expected_partition_diagnostics(scores):
        raise AnomalyScoreAuditError("model metadata partition diagnostics are incompatible")
    score_identity = _require_identity(
        metadata["score_artifact_identity"], "score", includes_row_count=True
    )
    if metadata["determinism_result"] != {
        "primary_random_state": PRIMARY_RANDOM_STATE,
        "canonical_score_payload_sha256": score_identity["sha256"],
        "same_environment_repeat": "AWAITING_LOCAL_VALIDATION",
    }:
        raise AnomalyScoreAuditError("model metadata deterministic primary-score identity is incompatible")
    sensitivity = metadata["seed_sensitivity"]
    if not isinstance(sensitivity, Mapping) or set(sensitivity) != {"primary_random_state", "comparisons"}:
        raise AnomalyScoreAuditError("model metadata seed sensitivity is incompatible")
    if sensitivity["primary_random_state"] != PRIMARY_RANDOM_STATE or not isinstance(
        sensitivity["comparisons"], list
    ):
        raise AnomalyScoreAuditError("model metadata seed sensitivity is incompatible")
    if len(sensitivity["comparisons"]) != 2:
        raise AnomalyScoreAuditError("model metadata seed sensitivity is incomplete")
    for comparison, random_state in zip(sensitivity["comparisons"], (2718, 3141), strict=True):
        if not isinstance(comparison, Mapping) or set(comparison) != {
            "random_state",
            "top_50_jaccard",
            "top_100_jaccard",
        }:
            raise AnomalyScoreAuditError("model metadata seed comparison is incompatible")
        if comparison["random_state"] != random_state:
            raise AnomalyScoreAuditError("model metadata seed comparison is incompatible")
        for field in ("top_50_jaccard", "top_100_jaccard"):
            if isinstance(comparison[field], bool) or not isinstance(comparison[field], float):
                raise AnomalyScoreAuditError("model metadata seed comparison is incompatible")
            if not isfinite(comparison[field]) or not 0.0 <= comparison[field] <= 1.0:
                raise AnomalyScoreAuditError("model metadata seed comparison is incompatible")
    if dependency_versions != metadata["dependency_versions"]:
        raise AnomalyScoreAuditError("model metadata runtime versions are not canonical")


def _audit_manifest(
    paths: Mapping[str, Path], features: FeatureBundle, metadata: Mapping[str, object]
) -> str:
    manifest = read_manifest(paths[MANIFEST_ARTIFACT_NAME])
    expected = build_manifest_payload(
        feature_sha256=str(features.feature_artifact_identity["sha256"]),
        feature_count=len(FEATURE_NAMES),
        reference_count=features.reference_count,
        holdout_count=features.holdout_count,
        feature_contract_sha256=features.feature_contract_sha256,
        model_artifact_sha256=str(metadata["model_artifact_identity"]["sha256"]),
        model_metadata_sha256=artifact_identity(
            paths[MODEL_METADATA_ARTIFACT_NAME], MODEL_METADATA_ARTIFACT_NAME
        )["sha256"],
        score_artifact_sha256=str(metadata["score_artifact_identity"]["sha256"]),
        runtime_versions=metadata["dependency_versions"],
    )
    if manifest != expected:
        raise AnomalyScoreAuditError("Stage 1.8 manifest does not reconcile to completed artifacts")
    return artifact_identity(paths[MANIFEST_ARTIFACT_NAME], MANIFEST_ARTIFACT_NAME)["sha256"]


def audit_anomaly_score_bundle(
    features_dir: str | Path,
    scores_dir: str | Path,
    *,
    expected_feature_sha256: str | None = EXPECTED_STAGE_1_7_FEATURE_SHA256,
    approved_manifest_sha256: str | None = None,
    require_manifest: bool = True,
) -> AnomalyScoreAuditSummary:
    """Reconcile score rows/metadata/manifests, with optional trusted-model replay."""

    try:
        features = load_feature_bundle(
            features_dir, expected_feature_sha256=expected_feature_sha256
        )
        supplied_scores_dir = _require_processed_bundle_path(scores_dir)
        paths = _require_exact_output_bundle(supplied_scores_dir, require_manifest=require_manifest)
        scores = tuple(read_score_rows(paths[SCORE_ARTIFACT_NAME]))
        _audit_score_rows(features, scores)
        metadata = read_exact_json_object(paths[MODEL_METADATA_ARTIFACT_NAME], MODEL_METADATA_FIELDS)
        _audit_metadata(metadata, features=features, scores=scores, paths=paths)
        manifest_sha256 = _audit_manifest(paths, features, metadata) if require_manifest else None
        if approved_manifest_sha256 is not None:
            if not require_manifest:
                raise AnomalyScoreAuditError("trusted model replay requires a completed manifest")
            model = load_trusted_model(
                supplied_scores_dir, approved_manifest_sha256=approved_manifest_sha256
            )
            replayed, _ = score_feature_rows(features.rows, model)
            if tuple(row.to_dict() for row in replayed) != tuple(row.to_dict() for row in scores):
                raise AnomalyScoreAuditError("trusted model replay does not reproduce persisted scores")
        return AnomalyScoreAuditSummary(
            row_count=len(scores),
            reference_row_count=features.reference_count,
            holdout_row_count=features.holdout_count,
            score_sha256=str(metadata["score_artifact_identity"]["sha256"]),
            manifest_sha256=manifest_sha256,
        )
    except (
        AnomalyArtifactError,
        AnomalyContractError,
        AnomalyInputError,
        AnomalyScoringError,
        OSError,
        ValueError,
    ) as error:
        if isinstance(error, AnomalyScoreAuditError):
            raise
        raise AnomalyScoreAuditError(str(error)) from error


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit a Stage 1.8 anomaly-score bundle.")
    parser.add_argument("--features-dir", required=True, help="Immutable Stage 1.7 feature bundle")
    parser.add_argument("--scores-dir", required=True, help="Stage 1.8 score bundle")
    parser.add_argument(
        "--approved-manifest-sha256",
        help="External trusted-manifest SHA-256; enables controlled model replay",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        summary = audit_anomaly_score_bundle(
            arguments.features_dir,
            arguments.scores_dir,
            approved_manifest_sha256=arguments.approved_manifest_sha256,
        )
    except AnomalyScoreAuditError as error:
        print(f"Stage 1.8 score audit failed: {error}")
        return 1
    print(summary.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
