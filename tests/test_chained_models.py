from __future__ import annotations

import numpy as np
import pytest

from chained.models import (
    SignalScaler,
    fit_chain_base_state,
    fit_chain_s1,
    fit_chain_s2,
    fit_signal_scaler,
    predict_chain_s1,
    predict_chain_s2,
    transform_chain_features,
)
from chained.contracts import CHAIN_S2_CONFIG


def _row(key: str, label: int = 0) -> dict[str, object]:
    return {
        "dataset_id": "UNSW_NB15_BENCHMARK",
        "branch_id": "BRANCH_B_LABELED_BENCHMARK",
        "official_split": "TRAIN",
        "development_partition": "TRAIN_INTERNAL",
        "row_number": int(key[1:]),
        "row_key": key,
        "group_id": f"g-{key}",
        "label": str(label),
        "dur": "1.0",
        "spkts": "2",
        "dpkts": "3",
        "sbytes": "4",
        "dbytes": "5",
        "rate": "6",
        "sttl": "7",
        "dttl": "8",
        "sload": "9",
        "dload": "10",
        "sloss": "0",
        "dloss": "0",
        "sinpkt": "1",
        "dinpkt": "1",
        "sjit": "0",
        "djit": "0",
        "swin": "1",
        "dwin": "1",
        "tcprtt": "0",
        "synack": "0",
        "ackdat": "0",
        "smean": "1",
        "dmean": "1",
        "trans_depth": "0",
        "response_body_len": "0",
        "proto": "tcp",
        "service": "http",
        "state": "CON",
    }


def test_signal_scaler_is_fit_only_and_appends_exactly_two_columns() -> None:
    rows = [_row("r0", 0), _row("r1", 1), _row("r2", 0), _row("r3", 1)]
    signals = {
        "r0": {"U1": 1.0, "U2": 3.0},
        "r1": {"U1": 2.0, "U2": 8.0},
        "r2": {"U1": 3.0, "U2": 15.0},
        "r3": {"U1": 4.0, "U2": 24.0},
    }
    scaler = fit_signal_scaler(rows[:3], {key: signals[key] for key in ("r0", "r1", "r2")})
    base_state = fit_chain_base_state(rows[:3])
    transformed = transform_chain_features(rows, signals, scaler, base_state)
    assert isinstance(scaler, SignalScaler)
    assert transformed.shape == (4, len(base_state.output_feature_names) + 2)
    assert scaler.fit_row_count == 3
    assert np.isfinite(transformed).all()


def test_chain_s1_uses_c1_and_attack_class_probability() -> None:
    rows = [_row(f"r{i}", i % 2) for i in range(8)]
    signals = {row["row_key"]: {"U1": float(i), "U2": float(i + 1)} for i, row in enumerate(rows)}
    scaler = fit_signal_scaler(rows, signals)
    base_state = fit_chain_base_state(rows)
    X = transform_chain_features(rows, signals, scaler, base_state)
    estimator, report = fit_chain_s1(X, np.asarray([int(row["label"]) for row in rows]))
    probabilities = predict_chain_s1(estimator, X)
    assert report["C"] == 1.0
    assert report["classes"] == [0, 1]
    assert probabilities.shape == (8,)
    assert np.all((probabilities >= 0) & (probabilities <= 1))


def test_missing_or_fallback_signal_is_rejected() -> None:
    rows = [_row("r0", 0), _row("r1", 1)]
    with pytest.raises(ValueError, match="signal"):
        fit_signal_scaler(rows, {"r0": {"U1": 1.0, "U2": 2.0}})
    with pytest.raises(ValueError, match="fallback"):
        fit_signal_scaler(
            rows,
            {
                "r0": {"U1": 1.0, "U2": 2.0, "fallback": True},
                "r1": {"U1": 2.0, "U2": 3.0},
            },
        )


def test_chain_s2_uses_exact_frozen_config_and_attack_class_probability() -> None:
    rows = [_row(f"r{i}", i % 2) for i in range(16)]
    signals = {row["row_key"]: {"U1": float(i), "U2": float(i + 1)} for i, row in enumerate(rows)}
    scaler = fit_signal_scaler(rows, signals)
    base_state = fit_chain_base_state(rows)
    X = transform_chain_features(rows, signals, scaler, base_state)
    estimator, report = fit_chain_s2(X, np.asarray([int(row["label"]) for row in rows]))
    probabilities = predict_chain_s2(estimator, X)
    assert report["config"] == CHAIN_S2_CONFIG
    assert report["classes"] == [0, 1]
    assert probabilities.shape == (16,)
    assert np.all((probabilities >= 0) & (probabilities <= 1))
