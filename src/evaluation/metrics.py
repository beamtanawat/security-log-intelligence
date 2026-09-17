"""Pure Stage 1.9 reviewed-sample metrics.

Source observations, rule matches, anomaly scores, and ranks are intentionally
absent from label decisions.  Only accepted blind analyst labels are used.
"""

from __future__ import annotations

from typing import Mapping, Sequence


class EvaluationError(ValueError):
    """Raised when review evidence cannot be projected or evaluated safely."""


REVIEW_STATUSES = (
    "NOT_SELECTED",
    "PENDING",
    "REVIEWED_RESOLVED",
    "REVIEWED_UNCERTAIN",
)


def review_status_for(review_id: str | None, blind_label: str | None) -> str:
    """Map a real review identifier and accepted blind decision to one status."""

    if review_id is None:
        if blind_label is not None:
            raise EvaluationError("an unselected record cannot contain a blind label")
        return "NOT_SELECTED"
    if not isinstance(review_id, str) or not review_id:
        raise EvaluationError("review_id must be a non-empty string or null")
    if blind_label is None:
        return "PENDING"
    if blind_label == "UNCERTAIN":
        return "REVIEWED_UNCERTAIN"
    if blind_label in {"SUSPICIOUS", "NOT_SUSPICIOUS"}:
        return "REVIEWED_RESOLVED"
    raise EvaluationError("blind review decision is invalid")


def _metric(numerator: int, denominator: int) -> tuple[float | None, str | None]:
    if denominator == 0:
        return None, "ZERO_DENOMINATOR"
    return float(numerator / denominator), None


def _uncertainty_bounds(matrix: Mapping[str, int], uncertain_top: int, uncertain_comparison: int) -> dict[str, object]:
    values: dict[str, list[float]] = {"precision": [], "recall": [], "f1": []}
    undefined_possible = False
    for a in range(uncertain_top + 1):
        for b in range(uncertain_comparison + 1):
            tp = matrix["tp"] + a
            fp = matrix["fp"] + uncertain_top - a
            fn = matrix["fn"] + b
            precision, _ = _metric(tp, tp + fp)
            recall, _ = _metric(tp, tp + fn)
            f1, _ = _metric(2 * tp, 2 * tp + fp + fn)
            for name, value in (("precision", precision), ("recall", recall), ("f1", f1)):
                if value is None:
                    undefined_possible = True
                else:
                    values[name].append(value)
    return {
        name: None if not entries else [min(entries), max(entries)]
        for name, entries in values.items()
    } | {"undefined_possible": undefined_possible}


def _prefix_metrics(
    source_records: Sequence[Mapping[str, object]], records: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    rank_by_record = {
        int(row["source_record_number"]): int(row.get("anomaly_rank", row["source_record_number"]))
        for row in source_records
    }
    ranked = sorted(
        (row for row in records if row["review_membership"] == "TOP_50"),
        key=lambda row: rank_by_record[int(row["source_record_number"])],
    )
    result: dict[str, object] = {}
    for k in (10, 20, 50):
        prefix = ranked[:k]
        if len(prefix) != k:
            result[str(k)] = {"point_estimate": None, "bounds": None, "coverage": 0.0, "reason": "UNREVIEWED_PREFIX"}
            continue
        suspicious = sum(row["blind_label"] == "SUSPICIOUS" for row in prefix)
        uncertain = sum(row["blind_label"] == "UNCERTAIN" for row in prefix)
        result[str(k)] = {
            "point_estimate": float(suspicious / k) if uncertain == 0 else None,
            "bounds": [float(suspicious / k), float((suspicious + uncertain) / k)] if uncertain else None,
            "coverage": float((k - uncertain) / k),
            "reason": None if uncertain == 0 else "UNCERTAIN_REVIEWS_PRESENT",
        }
    return result


def evaluate_review_mapping(
    records: Sequence[Mapping[str, object]], reviews: Mapping[str, Mapping[str, object]]
) -> dict[str, object]:
    """Create the sole deterministic Stage 2.0 review-status projection.

    This function intentionally accepts no source-threat, rule, or score values
    as labels.  Extra values in ``records`` are ignored for label determination.
    """

    ordered = sorted((dict(record) for record in records), key=lambda row: int(row.get("source_record_number", 0)))
    previous = 0
    matrix = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    uncertain = {"top_50": 0, "comparison": 0}
    statuses = {status: 0 for status in REVIEW_STATUSES}
    results: list[dict[str, object]] = []
    expected_review_ids: set[str] = set()
    for record in ordered:
        number = record.get("source_record_number")
        review_id = record.get("review_id")
        membership = record.get("review_membership")
        selected = record.get("analyst_review_selected")
        if isinstance(number, bool) or not isinstance(number, int) or number <= previous:
            raise EvaluationError("review records must be in unique source-record order")
        if membership not in {"TOP_50", "COMPARISON", "NOT_SELECTED"}:
            raise EvaluationError("review membership is invalid")
        if not isinstance(selected, bool) or selected != (membership == "TOP_50"):
            raise EvaluationError("analyst_review_selected does not match review membership")
        if membership == "NOT_SELECTED" and review_id is not None:
            raise EvaluationError("unselected record cannot have a review ID")
        if membership != "NOT_SELECTED" and (not isinstance(review_id, str) or review_id in expected_review_ids):
            raise EvaluationError("selected review record must have one unique review ID")
        if isinstance(review_id, str):
            expected_review_ids.add(review_id)
        review = reviews.get(review_id) if isinstance(review_id, str) else None
        label = review.get("blind_label") if isinstance(review, Mapping) else None
        status = review_status_for(review_id, label if isinstance(label, str) else None)
        statuses[status] += 1
        result = {
            "source_record_number": number,
            "review_id": review_id,
            "analyst_review_selected": selected,
            "review_membership": membership,
            "blind_label": label if isinstance(label, str) else None,
            "contextual_label": None,
            "review_status": status,
        }
        results.append(result)
        if membership != "NOT_SELECTED" and label == "UNCERTAIN":
            uncertain["top_50" if membership == "TOP_50" else "comparison"] += 1
        if label == "SUSPICIOUS":
            if membership == "TOP_50":
                matrix["tp"] += 1
            elif membership == "COMPARISON":
                matrix["fn"] += 1
        elif label == "NOT_SUSPICIOUS":
            if membership == "TOP_50":
                matrix["fp"] += 1
            elif membership == "COMPARISON":
                matrix["tn"] += 1
        previous = number
    unknown_review_ids = set(reviews) - expected_review_ids
    if unknown_review_ids:
        raise EvaluationError("review labels contain an unknown review ID")
    resolved = sum(matrix.values())
    if resolved == 0:
        metrics: dict[str, object] = {
            "precision": None,
            "recall": None,
            "f1": None,
            "reason": "INSUFFICIENT_RESOLVED_REVIEW_EVIDENCE",
            "uncertainty_bounds": _uncertainty_bounds(matrix, uncertain["top_50"], uncertain["comparison"]),
        }
    else:
        precision, precision_reason = _metric(matrix["tp"], matrix["tp"] + matrix["fp"])
        recall, recall_reason = _metric(matrix["tp"], matrix["tp"] + matrix["fn"])
        f1, f1_reason = _metric(2 * matrix["tp"], 2 * matrix["tp"] + matrix["fp"] + matrix["fn"])
        metrics = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "reason": next((item for item in (precision_reason, recall_reason, f1_reason) if item), None),
            "uncertainty_bounds": _uncertainty_bounds(matrix, uncertain["top_50"], uncertain["comparison"]),
        }
    return {
        "record_review_results": results,
        "review_status_counts": statuses,
        "resolved_matrix": matrix,
        "uncertain_counts_by_ai_decision": uncertain,
        "resolved_review_count": resolved,
        "metrics": metrics,
        "precision_at_k": _prefix_metrics(ordered, results),
    }
