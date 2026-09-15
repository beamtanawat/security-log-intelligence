"""Versioned Stage 1.8 score and runtime-dependency contracts."""

from __future__ import annotations

import importlib.metadata
import math
import platform
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ai_features.models import HOLDOUT_PARTITION, PARTITIONS, REFERENCE_PARTITION


ANOMALY_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"
SCORE_SEMANTICS_VERSION = "1.0"
RANKING_SEMANTICS_VERSION = "1.0"
MODEL_KIND = "IsolationForest"
MATRIX_DTYPE = "float32"
TRAINING_PARTITION = REFERENCE_PARTITION
MINIMUM_REFERENCE_ROWS = 4096
PRIMARY_RANDOM_STATE = 1729
SENSITIVITY_RANDOM_STATES = (2718, 3141)
ANOMALY_BANDS = (
    "TOP_0_1_PERCENT",
    "TOP_1_PERCENT",
    "TOP_5_PERCENT",
    "BASELINE",
)

# These are approved candidate pins.  They become verified only after the
# required local dependency installation, pip check, test suite, and validator.
APPROVED_PACKAGE_PINS = MappingProxyType(
    {
        "scikit-learn": "1.9.1",
        "numpy": "2.5.3",
        "scipy": "1.18.1",
        "joblib": "1.6.0",
        "threadpoolctl": "3.6.0",
        "narwhals": "2.26.0",
    }
)

MODEL_CONFIG = MappingProxyType(
    {
        "n_estimators": 200,
        "max_samples": 4096,
        "contamination": "auto",
        "max_features": 1.0,
        "bootstrap": False,
        "n_jobs": 1,
        "random_state": PRIMARY_RANDOM_STATE,
        "warm_start": False,
    }
)


class AnomalyContractError(ValueError):
    """Raised when a Stage 1.8 value violates its immutable contract."""


def model_config_payload(random_state: int = PRIMARY_RANDOM_STATE) -> dict[str, object]:
    """Return the locked Isolation Forest configuration with one approved seed."""

    if isinstance(random_state, bool) or not isinstance(random_state, int):
        raise AnomalyContractError("random state must be an integer")
    return {**MODEL_CONFIG, "random_state": random_state}


def _require_positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AnomalyContractError(f"{name} must be a positive integer")
    return value


def _require_nonempty_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AnomalyContractError(f"{name} must be a non-empty string")
    return value


def _require_finite_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, float) or not math.isfinite(value):
        raise AnomalyContractError(f"{name} must be a finite float")
    return value


@dataclass(frozen=True)
class AnomalyScoreRow:
    """One model-derived, informational anomaly-prioritization observation."""

    source_record_number: int
    source_record_id: str
    partition: str
    model_score: float
    raw_abnormality: float
    anomaly_score: float
    anomaly_rank: int
    anomaly_band: str
    analyst_review_selected: bool
    schema_version: str = ANOMALY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_positive_int(self.source_record_number, "source_record_number")
        _require_nonempty_text(self.source_record_id, "source_record_id")
        if self.partition not in PARTITIONS:
            raise AnomalyContractError("partition must be REFERENCE or HOLDOUT")
        _require_finite_float(self.model_score, "model_score")
        _require_finite_float(self.raw_abnormality, "raw_abnormality")
        anomaly_score = _require_finite_float(self.anomaly_score, "anomaly_score")
        if not 0.0 <= anomaly_score <= 100.0:
            raise AnomalyContractError("anomaly_score must be within 0 through 100")
        _require_positive_int(self.anomaly_rank, "anomaly_rank")
        if self.anomaly_band not in ANOMALY_BANDS:
            raise AnomalyContractError("anomaly_band is not a locked Stage 1.8 band")
        if not isinstance(self.analyst_review_selected, bool):
            raise AnomalyContractError("analyst_review_selected must be a bool")
        if self.schema_version != ANOMALY_SCHEMA_VERSION:
            raise AnomalyContractError(
                f"schema_version must be {ANOMALY_SCHEMA_VERSION!r}"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the exact deterministic JSON score-row object."""

        return {
            "schema_version": self.schema_version,
            "source_record_number": self.source_record_number,
            "source_record_id": self.source_record_id,
            "partition": self.partition,
            "model_score": self.model_score,
            "raw_abnormality": self.raw_abnormality,
            "anomaly_score": self.anomaly_score,
            "anomaly_rank": self.anomaly_rank,
            "anomaly_band": self.anomaly_band,
            "analyst_review_selected": self.analyst_review_selected,
        }

    @classmethod
    def from_dict(cls, value: object) -> "AnomalyScoreRow":
        """Reconstruct one score row while rejecting unknown contract drift."""

        if not isinstance(value, Mapping):
            raise AnomalyContractError("score row must be a JSON object")
        expected = {
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
        }
        if set(value) != expected:
            raise AnomalyContractError("score row does not contain exactly its contract fields")
        return cls(
            source_record_number=value["source_record_number"],
            source_record_id=value["source_record_id"],
            partition=value["partition"],
            model_score=value["model_score"],
            raw_abnormality=value["raw_abnormality"],
            anomaly_score=value["anomaly_score"],
            anomaly_rank=value["anomaly_rank"],
            anomaly_band=value["anomaly_band"],
            analyst_review_selected=value["analyst_review_selected"],
            schema_version=value["schema_version"],
        )


@dataclass(frozen=True)
class AnomalyScoreDiagnostics:
    """Bounded descriptive state derived from model scores, never labels."""

    reference_count: int
    holdout_count: int
    reference_raw_distribution: tuple[tuple[float, int], ...]
    partition_diagnostics: Mapping[str, object]


def collect_runtime_versions() -> dict[str, str]:
    """Collect the exact package/runtime versions that Stage 1.8 pins require."""

    versions = {"python": platform.python_version()}
    for package_name in APPROVED_PACKAGE_PINS:
        try:
            versions[package_name] = importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError as error:
            raise AnomalyContractError(
                f"required Stage 1.8 package is not installed: {package_name}"
            ) from error
    return versions


def validate_runtime_versions(versions: Mapping[str, object]) -> dict[str, str]:
    """Reject missing or mismatched candidate pins before fitting or model load."""

    expected_keys = {"python", *APPROVED_PACKAGE_PINS}
    if set(versions) != expected_keys:
        raise AnomalyContractError("runtime version mapping has unexpected or missing fields")
    validated: dict[str, str] = {}
    python_version = versions["python"]
    if not isinstance(python_version, str) or not python_version.startswith("3.12."):
        raise AnomalyContractError("Stage 1.8 requires Python 3.12.x")
    validated["python"] = python_version
    for package_name, expected_version in APPROVED_PACKAGE_PINS.items():
        actual_version = versions[package_name]
        if actual_version != expected_version:
            raise AnomalyContractError(
                f"{package_name} must match approved candidate pin {expected_version}"
            )
        validated[package_name] = expected_version
    return validated
