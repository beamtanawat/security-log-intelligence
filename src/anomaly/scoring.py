"""Pure, deterministic Stage 1.8 Isolation Forest scoring helpers.

This module consumes only validated Stage 1.7 numeric feature rows.  It does
not read raw logs, security findings, threat observations, or analyst labels.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from math import isfinite
from typing import Callable, Iterable, Mapping, Protocol, Sequence

import numpy as np

from ai_features.models import FEATURE_NAMES, HOLDOUT_PARTITION, REFERENCE_PARTITION, FeatureRow

from .models import (
    MINIMUM_REFERENCE_ROWS,
    PRIMARY_RANDOM_STATE,
    SENSITIVITY_RANDOM_STATES,
    AnomalyScoreDiagnostics,
    AnomalyScoreRow,
    collect_runtime_versions,
    model_config_payload,
    validate_runtime_versions,
)


class AnomalyScoringError(ValueError):
    """Raised when scoring cannot satisfy the locked Stage 1.8 contract."""


class ScoreSamplesModel(Protocol):
    """The small fitted-model surface used by the pure scoring function."""

    def fit(self, matrix: np.ndarray) -> "ScoreSamplesModel": ...

    def score_samples(self, matrix: np.ndarray) -> np.ndarray: ...


def _ordered_rows(rows: Iterable[FeatureRow]) -> tuple[FeatureRow, ...]:
    """Materialize rows while preserving, and verifying, source-record order."""

    materialized = tuple(rows)
    if not materialized:
        raise AnomalyScoringError("no feature rows are available for scoring")
    previous = 0
    identifiers: set[str] = set()
    for row in materialized:
        if row.source_record_number <= previous:
            raise AnomalyScoringError("feature rows must be ordered by source record number")
        if row.source_record_id in identifiers:
            raise AnomalyScoringError("feature rows contain a duplicate source record ID")
        previous = row.source_record_number
        identifiers.add(row.source_record_id)
    return materialized


def build_feature_matrix(rows: Iterable[FeatureRow]) -> np.ndarray:
    """Return an ordered, contiguous finite ``float32`` matrix from row values only."""

    materialized = _ordered_rows(rows)
    try:
        matrix = np.asarray([row.values for row in materialized], dtype=np.float32)
    except (TypeError, ValueError) as error:
        raise AnomalyScoringError("feature values cannot form a float32 matrix") from error
    expected_shape = (len(materialized), len(FEATURE_NAMES))
    if matrix.shape != expected_shape:
        raise AnomalyScoringError("feature matrix has an incompatible dimension")
    if not bool(np.isfinite(matrix).all()):
        raise AnomalyScoringError("feature matrix contains non-finite values")
    return np.ascontiguousarray(matrix, dtype=np.float32)


def _reference_rows(rows: Sequence[FeatureRow]) -> tuple[FeatureRow, ...]:
    reference = tuple(row for row in rows if row.partition == REFERENCE_PARTITION)
    if len(reference) < MINIMUM_REFERENCE_ROWS:
        raise AnomalyScoringError(
            f"REFERENCE partition must contain at least {MINIMUM_REFERENCE_ROWS} rows"
        )
    return reference


def _default_model_factory(**configuration: object) -> ScoreSamplesModel:
    """Import sklearn only when actual fitting is requested."""

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as error:
        raise AnomalyScoringError("scikit-learn is required to fit IsolationForest") from error
    return IsolationForest(**configuration)


def fit_reference_model(
    rows: Iterable[FeatureRow],
    *,
    model_factory: Callable[..., ScoreSamplesModel] | None = None,
    versions: Mapping[str, object] | None = None,
    random_state: int = PRIMARY_RANDOM_STATE,
) -> ScoreSamplesModel:
    """Fit one locked Isolation Forest using only ordered REFERENCE feature rows."""

    validate_runtime_versions(collect_runtime_versions() if versions is None else versions)
    materialized = _ordered_rows(rows)
    reference = _reference_rows(materialized)
    factory = _default_model_factory if model_factory is None else model_factory
    try:
        model = factory(**model_config_payload(random_state))
        return model.fit(build_feature_matrix(reference))
    except AnomalyScoringError:
        raise
    except (TypeError, ValueError) as error:
        raise AnomalyScoringError("IsolationForest fitting failed") from error


def assign_anomaly_band(unrounded_percentile: float) -> str:
    """Map an unrounded reference percentile to the four locked display bands."""

    if isinstance(unrounded_percentile, bool) or not isinstance(unrounded_percentile, float):
        raise AnomalyScoringError("anomaly percentile must be a finite float")
    if not isfinite(unrounded_percentile) or not 0.0 <= unrounded_percentile <= 100.0:
        raise AnomalyScoringError("anomaly percentile must be within 0 through 100")
    if unrounded_percentile >= 99.9:
        return "TOP_0_1_PERCENT"
    if unrounded_percentile >= 99.0:
        return "TOP_1_PERCENT"
    if unrounded_percentile >= 95.0:
        return "TOP_5_PERCENT"
    return "BASELINE"


def _quantiles(values: Sequence[float]) -> dict[str, float] | None:
    """Return deterministic linear quantiles without depending on NumPy defaults."""

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


def _partition_diagnostics(scored_rows: Sequence[AnomalyScoreRow]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for partition in (REFERENCE_PARTITION, HOLDOUT_PARTITION):
        rows = [row for row in scored_rows if row.partition == partition]
        raw_values = [row.raw_abnormality for row in rows]
        bands = Counter(row.anomaly_band for row in rows)
        payload[partition] = {
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
    return payload


def score_feature_rows(
    rows: Iterable[FeatureRow], model: ScoreSamplesModel
) -> tuple[tuple[AnomalyScoreRow, ...], AnomalyScoreDiagnostics]:
    """Score all rows and derive percentiles/ranks only from REFERENCE scores.

    ``score_samples`` is used directly: lower model scores are more abnormal.
    The stored ``raw_abnormality`` is its negative, so higher values sort first.
    """

    materialized = _ordered_rows(rows)
    matrix = build_feature_matrix(materialized)
    try:
        model_scores = np.asarray(model.score_samples(matrix), dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise AnomalyScoringError("model did not return usable score_samples values") from error
    if model_scores.shape != (len(materialized),):
        raise AnomalyScoringError("model returned an incompatible score_samples shape")
    if not bool(np.isfinite(model_scores).all()):
        raise AnomalyScoringError("model returned a non-finite score")

    raw_values = tuple(float(-value) for value in model_scores)
    reference_raw = sorted(
        raw_values[index]
        for index, row in enumerate(materialized)
        if row.partition == REFERENCE_PARTITION
    )
    if not reference_raw:
        raise AnomalyScoringError("REFERENCE partition contains no score rows")
    if reference_raw[0] == reference_raw[-1]:
        raise AnomalyScoringError("DEGENERATE_SCORE_REFERENCE")

    percentiles = tuple(
        float(100.0 * bisect_right(reference_raw, raw_value) / len(reference_raw))
        for raw_value in raw_values
    )
    ranking_indices = sorted(
        range(len(materialized)),
        key=lambda index: (-raw_values[index], materialized[index].source_record_number),
    )
    ranks = {index: rank for rank, index in enumerate(ranking_indices, start=1)}
    scored_rows = tuple(
        AnomalyScoreRow(
            source_record_number=row.source_record_number,
            source_record_id=row.source_record_id,
            partition=row.partition,
            model_score=float(model_scores[index]),
            raw_abnormality=raw_values[index],
            anomaly_score=float(round(percentiles[index], 6)),
            anomaly_rank=ranks[index],
            anomaly_band=assign_anomaly_band(percentiles[index]),
            analyst_review_selected=ranks[index] <= 50,
        )
        for index, row in enumerate(materialized)
    )
    distribution = tuple((float(value), count) for value, count in sorted(Counter(reference_raw).items()))
    diagnostics = AnomalyScoreDiagnostics(
        reference_count=len(reference_raw),
        holdout_count=sum(row.partition == HOLDOUT_PARTITION for row in materialized),
        reference_raw_distribution=distribution,
        partition_diagnostics=_partition_diagnostics(scored_rows),
    )
    return scored_rows, diagnostics


def _jaccard(left: set[int], right: set[int]) -> float:
    union = left | right
    if not union:
        return 1.0
    return float(len(left & right) / len(union))


def secondary_seed_sensitivity(
    rows: Iterable[FeatureRow],
    primary_scores: Sequence[AnomalyScoreRow],
    *,
    versions: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Report fixed secondary-seed overlap diagnostics; never select a model."""

    materialized = _ordered_rows(rows)
    primary_top_50 = {
        row.source_record_number for row in primary_scores if row.anomaly_rank <= 50
    }
    primary_top_100 = {
        row.source_record_number for row in primary_scores if row.anomaly_rank <= 100
    }
    comparisons: list[dict[str, object]] = []
    for random_state in SENSITIVITY_RANDOM_STATES:
        model = fit_reference_model(materialized, versions=versions, random_state=random_state)
        candidate_scores, _ = score_feature_rows(materialized, model)
        candidate_top_50 = {
            row.source_record_number for row in candidate_scores if row.anomaly_rank <= 50
        }
        candidate_top_100 = {
            row.source_record_number for row in candidate_scores if row.anomaly_rank <= 100
        }
        comparisons.append(
            {
                "random_state": random_state,
                "top_50_jaccard": _jaccard(primary_top_50, candidate_top_50),
                "top_100_jaccard": _jaccard(primary_top_100, candidate_top_100),
            }
        )
    return {
        "primary_random_state": PRIMARY_RANDOM_STATE,
        "comparisons": comparisons,
    }
