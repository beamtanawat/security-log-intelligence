from __future__ import annotations

import json

import numpy as np
import pytest

from run_unsw_test_evaluation import (
    build_confusion_artifact,
    build_test_score_row,
    verify_selection_lock_files,
)


def test_confusion_artifact_axes_keep_anomaly_distinct_from_attack() -> None:
    artifact = build_confusion_artifact(
        "UNSW_U1_ISOLATION_FOREST",
        np.asarray([0.2, 0.9, 0.8, 0.1]),
        [0, 1, 0, 1],
        threshold=0.8,
    )
    assert artifact["benchmark_reference_axis"] == ["NORMAL", "ATTACK"]
    assert artifact["unsupervised_decision_axis"] == ["INLIER", "ANOMALY"]
    assert artifact["matrix"] == [[1, 1], [1, 1]]
    assert artifact["prediction_semantics"] == "ANOMALY != ATTACK"


def test_test_score_row_excludes_labels_and_marks_official_test() -> None:
    row = build_test_score_row(
        row_key='["UNSW_NB15_BENCHMARK","TEST",1]',
        score=0.5,
        decision=True,
        model_id="UNSW_U1_ISOLATION_FOREST",
        model_version="stage-2.2e/1.0",
        fit_membership_sha256="a" * 64,
        feature_state_sha256="b" * 64,
        threshold_id="U1_FINAL",
    )
    assert row["split_id"] == "TEST"
    assert row["fit_relationship"] == "OFFICIAL_TEST"
    assert row["decision"] == "ANOMALY"
    assert "label" not in row and "attack_cat" not in row


def test_selection_lock_verification_rejects_hash_mismatch(tmp_path) -> None:
    lock = {
        "models": {"U1": {"model_sha256": "a" * 64}, "U2": {"model_sha256": "b" * 64}},
        "official_test": {"opened": False, "labels_read": False, "predictions_created": False, "status": "LOCKED"},
    }
    lock_path = tmp_path / "selection_lock_manifest.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    (tmp_path / "u1.joblib").write_bytes(b"u1")
    (tmp_path / "u2.joblib").write_bytes(b"u2")
    with pytest.raises(RuntimeError, match="hash"):
        verify_selection_lock_files(lock_path, {"U1": tmp_path / "u1.joblib", "U2": tmp_path / "u2.joblib"})
