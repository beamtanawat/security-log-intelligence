"""TRAIN_INTERNAL-only UNSW feature fitting and frozen transformation."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

import numpy as np

from .contracts import (
    BRANCH_ID,
    CATEGORICAL_FEATURES,
    DATASET_ID,
    FEATURE_ORDER,
    NUMERIC_FEATURES,
)


class FeatureContractError(ValueError):
    """Raised when a row violates the frozen feature contract."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _parse_numeric(value: object, field: str, row_number: object) -> float | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        decimal = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise FeatureContractError(f"{field}: malformed numeric at row {row_number}") from exc
    if not decimal.is_finite() or decimal < 0:
        raise FeatureContractError(f"{field}: invalid nonnegative finite numeric at row {row_number}")
    parsed = float(decimal)
    if not math.isfinite(parsed) or parsed < 0:
        raise FeatureContractError(f"{field}: invalid numeric at row {row_number}")
    return parsed


def _parse_category(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _require_train_internal(row: Mapping[str, object]) -> None:
    if row.get("official_split") == "TEST":
        raise FeatureContractError("official TEST rows cannot be fit or transformed here")
    if row.get("development_partition") != "TRAIN_INTERNAL":
        raise FeatureContractError("feature fitting requires TRAIN_INTERNAL rows")


@dataclass(frozen=True)
class FeatureState:
    dataset_id: str
    branch_id: str
    feature_order: tuple[str, ...]
    numeric_medians: dict[str, float]
    numeric_means: dict[str, float]
    numeric_scales: dict[str, float]
    categorical_vocabularies: dict[str, tuple[str, ...]]
    output_feature_names: tuple[str, ...]
    fit_row_count: int
    state_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "stage_2.2a-feature-state/1.0",
            "dataset_id": self.dataset_id,
            "branch_id": self.branch_id,
            "feature_order": list(self.feature_order),
            "numeric_medians": self.numeric_medians,
            "numeric_means": self.numeric_means,
            "numeric_scales": self.numeric_scales,
            "categorical_vocabularies": {key: list(value) for key, value in self.categorical_vocabularies.items()},
            "output_feature_names": list(self.output_feature_names),
            "fit_row_count": self.fit_row_count,
            "state_sha256": self.state_sha256,
            "fit_boundary": "TRAIN_INTERNAL_ONLY",
        }


def fit_features(rows: Sequence[Mapping[str, object]], dataset_id: str) -> FeatureState:
    if dataset_id != DATASET_ID:
        raise FeatureContractError("UNSW dataset identity required")
    if not rows:
        raise FeatureContractError("TRAIN_INTERNAL cannot be empty")
    for row in rows:
        _require_train_internal(row)
        if row.get("dataset_id", dataset_id) != dataset_id:
            raise FeatureContractError("dataset identity mismatch")
        if row.get("branch_id", BRANCH_ID) != BRANCH_ID:
            raise FeatureContractError("branch identity mismatch")

    parsed_numeric: dict[str, list[float | None]] = {field: [] for field in NUMERIC_FEATURES}
    categories: dict[str, set[str]] = {field: set() for field in CATEGORICAL_FEATURES}
    for row in rows:
        row_number = row.get("row_number", "?")
        for field in NUMERIC_FEATURES:
            value = _parse_numeric(row.get(field), field, row_number)
            parsed_numeric[field].append(None if value is None else math.log1p(value))
        for field in CATEGORICAL_FEATURES:
            value = _parse_category(row.get(field))
            if value is not None:
                categories[field].add(value)

    medians: dict[str, float] = {}
    means: dict[str, float] = {}
    scales: dict[str, float] = {}
    for field, values in parsed_numeric.items():
        observed = sorted(value for value in values if value is not None)
        if not observed:
            median = 0.0
        else:
            midpoint = len(observed) // 2
            median = observed[midpoint] if len(observed) % 2 else (observed[midpoint - 1] + observed[midpoint]) / 2.0
        filled = [median if value is None else value for value in values]
        mean = sum(filled) / len(filled)
        variance = sum((value - mean) ** 2 for value in filled) / len(filled)
        scale = math.sqrt(variance) if variance > 0 else 1.0
        medians[field] = median
        means[field] = mean
        scales[field] = scale

    vocabularies = {field: tuple(sorted(values)) for field, values in categories.items()}
    output_names: list[str] = []
    output_names.extend(f"num::{field}::scaled" for field in NUMERIC_FEATURES)
    output_names.extend(f"num::{field}::missing" for field in NUMERIC_FEATURES)
    for field in CATEGORICAL_FEATURES:
        output_names.extend(f"cat::{field}::value::{value}" for value in vocabularies[field])
        output_names.append(f"cat::{field}::reserved::MISSING")
        output_names.append(f"cat::{field}::reserved::UNKNOWN")
    if len(output_names) > 512:
        raise FeatureContractError("transformed feature count exceeds 512-column gate")
    payload = {
        "dataset_id": dataset_id,
        "branch_id": BRANCH_ID,
        "feature_order": list(FEATURE_ORDER),
        "numeric_medians": medians,
        "numeric_means": means,
        "numeric_scales": scales,
        "categorical_vocabularies": {key: list(value) for key, value in vocabularies.items()},
        "output_feature_names": output_names,
        "fit_row_count": len(rows),
    }
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return FeatureState(
        dataset_id=dataset_id,
        branch_id=BRANCH_ID,
        feature_order=FEATURE_ORDER,
        numeric_medians=medians,
        numeric_means=means,
        numeric_scales=scales,
        categorical_vocabularies=vocabularies,
        output_feature_names=tuple(output_names),
        fit_row_count=len(rows),
        state_sha256=digest,
    )


def transform_features(rows: Sequence[Mapping[str, object]], state: FeatureState) -> np.ndarray:
    output = np.zeros((len(rows), len(state.output_feature_names)), dtype=np.float64)
    name_to_index = {name: index for index, name in enumerate(state.output_feature_names)}
    for row_index, row in enumerate(rows):
        if row.get("dataset_id", state.dataset_id) != state.dataset_id:
            raise FeatureContractError("dataset identity mismatch")
        if row.get("branch_id", state.branch_id) != state.branch_id:
            raise FeatureContractError("branch identity mismatch")
        if row.get("official_split") == "TEST" and ("label" in row or "attack_cat" in row):
            raise FeatureContractError("TEST labels cannot enter transform_features")
        for field in NUMERIC_FEATURES:
            value = _parse_numeric(row.get(field), field, row.get("row_number", "?"))
            missing_index = name_to_index[f"num::{field}::missing"]
            if value is None:
                output[row_index, missing_index] = 1.0
                log_value = state.numeric_medians[field]
            else:
                log_value = math.log1p(value)
            output[row_index, name_to_index[f"num::{field}::scaled"]] = (log_value - state.numeric_means[field]) / state.numeric_scales[field]
        for field in CATEGORICAL_FEATURES:
            value = _parse_category(row.get(field))
            if value is None:
                output[row_index, name_to_index[f"cat::{field}::reserved::MISSING"]] = 1.0
            elif value in state.categorical_vocabularies[field]:
                output[row_index, name_to_index[f"cat::{field}::value::{value}"]] = 1.0
            else:
                output[row_index, name_to_index[f"cat::{field}::reserved::UNKNOWN"]] = 1.0
    return np.ascontiguousarray(output, dtype=np.float64)
