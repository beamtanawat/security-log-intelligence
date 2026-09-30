from __future__ import annotations

import copy

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from chained.contracts import build_contexts, membership_sha256
from chained.signals import (
    SignalBlocker,
    audit_signal_artifact,
    nearest_centroid_squared_distance,
    score_u1,
)


def _folds() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(12):
        outer = index % 3
        rows.append(
            {
                "dataset_id": "UNSW_NB15_BENCHMARK",
                "branch_id": "BRANCH_B_LABELED_BENCHMARK",
                "row_key": f"r{index}",
                "group_id": f"g{index}",
                "upstream_split": "TRAIN_INTERNAL",
                "outer_fold": outer,
                "inner_fold_by_outer": {
                    str(context): (index // 3) % 2
                    for context in range(3)
                    if context != outer
                },
            }
        )
    return rows


def _records(context: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "schema_version": "stage_2.4/1.0",
            "row_key": row_key,
            "group_id": group_id,
            "context_id": context["context_id"],
            "model_id": "U1",
            "model_version": "stage_2.4b-u1/1.0",
            "fit_row_keys": list(context["fit_row_keys"]),
            "fit_group_ids": list(context["fit_group_ids"]),
            "fit_membership_sha256": context["fit_membership_sha256"],
            "score_membership_sha256": context["score_membership_sha256"],
            "preprocessing_identity": "state",
            "fit_group_fingerprint": membership_sha256(list(context["fit_group_ids"])),
            "signal_role": "OOF_TRAINING",
            "artifact_identity": "artifact",
            "score": 0.1,
            "score_direction": "HIGHER_MORE_ANOMALOUS",
            "label_free_fit": True,
            "labels_used": False,
            "attack_cat_used": False,
            "test_used": False,
        }
        for row_key, group_id in zip(context["score_row_keys"], context["score_group_ids"], strict=False)
    ]


def test_signal_artifact_requires_exact_coverage_and_provenance() -> None:
    context = next(item for item in build_contexts(_folds()) if item["kind"] == "INNER_SIGNAL")
    records = _records(context)
    report = audit_signal_artifact(records, context, "U1")
    assert report["status"] == "PASS"
    assert report["same_row_overlap"] == 0
    assert report["same_group_overlap"] == 0

    missing = records[:-1]
    with pytest.raises(SignalBlocker, match="coverage"):
        audit_signal_artifact(missing, context, "U1")

    duplicate = records + [copy.deepcopy(records[0])]
    with pytest.raises(SignalBlocker, match="duplicate"):
        audit_signal_artifact(duplicate, context, "U1")


def test_signal_artifact_rejects_labels_and_fit_group_overlap() -> None:
    context = next(item for item in build_contexts(_folds()) if item["kind"] == "INNER_SIGNAL")
    records = _records(context)
    labeled = copy.deepcopy(records)
    labeled[0]["label"] = 1
    with pytest.raises(SignalBlocker, match="label"):
        audit_signal_artifact(labeled, context, "U1")

    overlap = copy.deepcopy(records)
    overlap[0]["fit_group_ids"] = list(overlap[0]["fit_group_ids"]) + [overlap[0]["group_id"]]
    with pytest.raises(SignalBlocker, match="group"):
        audit_signal_artifact(overlap, context, "U1")


def test_u1_direction_and_deterministic_replay() -> None:
    X = np.asarray([[0.0], [1.0], [2.0], [3.0]], dtype=np.float64)
    model = IsolationForest(n_estimators=5, max_samples=4, random_state=1729, n_jobs=1)
    model.fit(X)
    first = score_u1(model, X)
    second = score_u1(model, X)
    assert np.allclose(first, second)
    assert np.isfinite(first).all()
    assert first.shape == (4,)


def test_u2_is_nearest_centroid_squared_distance() -> None:
    X = np.asarray([[0.0, 0.0], [2.0, 0.0], [4.0, 0.0]], dtype=np.float64)
    centers = np.asarray([[0.0, 0.0], [3.0, 0.0]], dtype=np.float64)
    scores = nearest_centroid_squared_distance(X, centers)
    assert np.allclose(scores, [0.0, 1.0, 1.0])
    assert np.isfinite(scores).all()
