from __future__ import annotations

import ast
import inspect

from run_supervised_test_evaluation import _confusion_artifact, run


def test_supervised_confusion_artifact_uses_normal_attack_axes() -> None:
    artifact = _confusion_artifact(
        "S1",
        {
            "confusion_matrix": {"tn": 10, "fp": 2, "fn": 3, "tp": 20},
        },
        test_hash="a" * 64,
    )
    assert artifact["reference_axis"] == ["NORMAL", "ATTACK"]
    assert artifact["prediction_axis"] == ["NORMAL", "ATTACK"]
    assert artifact["matrix"] == [[10, 2], [3, 20]]


def test_locked_evaluator_contains_no_fit_call() -> None:
    tree = ast.parse(inspect.getsource(run))
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fit"
        for node in ast.walk(tree)
    )
