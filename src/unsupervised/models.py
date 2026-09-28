"""Bounded, label-free UNSW U2 anomaly scorer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
from sklearn.cluster import MiniBatchKMeans
from threadpoolctl import threadpool_limits


class U2ModelError(ValueError):
    """Raised when U2 input or scorer invariants fail."""


@dataclass(frozen=True)
class U2Config:
    n_clusters: int = 32
    init: str = "k-means++"
    n_init: int = 3
    batch_size: int = 1024
    init_size: int = 3072
    max_iter: int = 100
    tol: float = 0.0
    max_no_improvement: int = 10
    reassignment_ratio: float = 0.01
    compute_labels: bool = False
    random_state: int = 1729
    score_batch_size: int = 4096

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_clusters": self.n_clusters,
            "init": self.init,
            "n_init": self.n_init,
            "batch_size": self.batch_size,
            "init_size": self.init_size,
            "max_iter": self.max_iter,
            "tol": self.tol,
            "max_no_improvement": self.max_no_improvement,
            "reassignment_ratio": self.reassignment_ratio,
            "compute_labels": self.compute_labels,
            "random_state": self.random_state,
            "score_batch_size": self.score_batch_size,
        }


@dataclass
class U2ModelBundle:
    model: MiniBatchKMeans
    config: U2Config
    feature_count: int
    fit_row_count: int
    membership_hash: str
    score_direction: str = "HIGHER_MORE_ANOMALOUS"


def _as_matrix(values: object, *, name: str) -> np.ndarray:
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2:
        raise U2ModelError(f"{name} must be a two-dimensional matrix")
    if matrix.shape[0] == 0 or matrix.shape[1] == 0:
        raise U2ModelError(f"{name} must be non-empty")
    if not np.isfinite(matrix).all():
        raise U2ModelError(f"{name} must contain only finite values")
    return np.ascontiguousarray(matrix, dtype=np.float64)


def _membership_hash(membership: Sequence[str]) -> str:
    payload = json.dumps(list(membership), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def pilot_order(row_keys: Sequence[str], dataset_id: str) -> list[str]:
    """Return deterministic, label-blind pilot order."""

    def sort_key(row_key: str) -> tuple[str, str]:
        payload = json.dumps(
            ["s2.2-pilot-v1", dataset_id, row_key],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest(), row_key

    return sorted(row_keys, key=sort_key)


def fit_u2(
    X_train: object,
    membership: Sequence[str],
    config: U2Config | None = None,
) -> U2ModelBundle:
    """Fit the frozen MiniBatchKMeans U2 recipe without labels."""

    cfg = config or U2Config()
    matrix = _as_matrix(X_train, name="X_train")
    if matrix.shape[0] < 3072:
        raise U2ModelError("U2 requires at least 3072 TRAIN_INTERNAL rows")
    if len(membership) != matrix.shape[0]:
        raise U2ModelError("membership length must match X_train rows")
    if any(not isinstance(value, str) or not value for value in membership):
        raise U2ModelError("membership must contain row-key strings, not labels")
    distinct = np.unique(matrix, axis=0).shape[0]
    if distinct < cfg.n_clusters:
        raise U2ModelError(f"U2 requires at least {cfg.n_clusters} distinct transformed vectors")
    model = MiniBatchKMeans(
        n_clusters=cfg.n_clusters,
        init=cfg.init,
        n_init=cfg.n_init,
        batch_size=cfg.batch_size,
        init_size=cfg.init_size,
        max_iter=cfg.max_iter,
        tol=cfg.tol,
        max_no_improvement=cfg.max_no_improvement,
        reassignment_ratio=cfg.reassignment_ratio,
        compute_labels=cfg.compute_labels,
        random_state=cfg.random_state,
    )
    with threadpool_limits(limits=1):
        model.fit(matrix)
    centers = np.asarray(model.cluster_centers_, dtype=np.float64)
    if centers.shape != (cfg.n_clusters, matrix.shape[1]) or not np.isfinite(centers).all():
        raise U2ModelError("U2 produced invalid cluster centers")
    return U2ModelBundle(
        model=model,
        config=cfg,
        feature_count=matrix.shape[1],
        fit_row_count=matrix.shape[0],
        membership_hash=_membership_hash(membership),
    )


def score_u2(bundle: U2ModelBundle, X_query: object) -> np.ndarray:
    """Return nearest-centroid squared distance; higher means more anomalous."""

    matrix = _as_matrix(X_query, name="X_query")
    if matrix.shape[1] != bundle.feature_count:
        raise U2ModelError("X_query feature dimension does not match fitted U2 model")
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    for start in range(0, matrix.shape[0], bundle.config.score_batch_size):
        stop = min(start + bundle.config.score_batch_size, matrix.shape[0])
        with threadpool_limits(limits=1):
            distances = bundle.model.transform(matrix[start:stop])
        batch_scores = np.min(np.square(np.asarray(distances, dtype=np.float64)), axis=1)
        if not np.isfinite(batch_scores).all():
            raise U2ModelError("U2 produced non-finite anomaly scores")
        scores[start:stop] = batch_scores
    if not np.isfinite(scores).all():
        raise U2ModelError("U2 produced non-finite anomaly scores")
    return scores
