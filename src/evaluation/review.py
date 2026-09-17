"""Deterministic analyst-review sampling, queue export, and label validation."""

from __future__ import annotations

import csv
import hashlib
from bisect import bisect_right
from datetime import datetime
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ai_features.artifact import canonical_json


class ReviewError(ValueError):
    """Raised when a Stage 1.9 review artifact is incomplete or unsafe."""


REVIEW_SELECTION_PROTOCOL_VERSION = "1.0"
BLIND_LABEL_COLUMNS = (
    "review_id",
    "blind_label",
    "blind_rationale",
    "reviewer_alias",
    "reviewed_at",
)
CONTEXTUAL_LABEL_COLUMNS = (
    "review_id",
    "contextual_label",
    "contextual_rationale",
    "reviewer_alias",
    "reviewed_at",
)
QUEUE_COLUMNS = (
    "review_id",
    "protocol_number",
    "protocol_name",
    "source_port",
    "destination_port",
    "service_source",
    "source_identifier",
    "destination_identifier",
    "sent_bytes",
    "received_bytes",
    "sent_packets",
    "received_packets",
    "duration_raw_value",
    "source_port_missing",
    "destination_port_missing",
    "service_missing",
    "sent_bytes_missing",
    "received_bytes_missing",
    "sent_packets_missing",
    "received_packets_missing",
    "duration_missing",
)
DISPLAY_CONTEXT_COLUMNS = QUEUE_COLUMNS[1:]
BLIND_LABELS = frozenset({"SUSPICIOUS", "NOT_SUSPICIOUS", "UNCERTAIN"})
_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@")
_BANDS = (
    ("P99_100", 99.0, 100.0, True),
    ("P95_99", 95.0, 99.0, False),
    ("P50_95", 50.0, 95.0, False),
    ("P5_50", 5.0, 50.0, False),
    ("P0_5", 0.0, 5.0, False),
)


def _sha256_json(parts: list[object]) -> str:
    return hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ReviewError(f"{name} must be a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as error:
        raise ReviewError(f"{name} must be a SHA-256 digest") from error
    return value.lower()


def review_id_for_record(normalized_sha256: str, source_record_number: int) -> str:
    """Return the deterministic pseudonymous review identifier for one record."""

    normalized_hash = _require_sha256(normalized_sha256, "normalized_sha256")
    if isinstance(source_record_number, bool) or not isinstance(source_record_number, int) or source_record_number < 1:
        raise ReviewError("source_record_number must be a positive integer")
    return "R-" + _sha256_json(["stage-1.9-review-v1", normalized_hash, source_record_number])


def _sample_hash(source_record_number: int) -> str:
    return _sha256_json(["stage-1.9-sample-v1", source_record_number])


def _presentation_hash(review_id: str) -> str:
    return _sha256_json(["stage-1.9-order-v1", review_id])


def _unrounded_percentiles(rows: Sequence[Mapping[str, object]]) -> dict[int, float]:
    reference: list[float] = []
    for row in rows:
        if row.get("partition") == "REFERENCE":
            raw = row.get("raw_abnormality")
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ReviewError("score raw_abnormality must be finite")
            reference.append(float(raw))
    if not reference:
        raise ReviewError("review sampling requires REFERENCE score rows")
    reference.sort()
    result: dict[int, float] = {}
    for row in rows:
        number = row.get("source_record_number")
        raw = row.get("raw_abnormality")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise ReviewError("explanation record number is invalid")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ReviewError("score raw_abnormality must be finite")
        result[number] = float(100.0 * bisect_right(reference, float(raw)) / len(reference))
    return result


def _in_band(percentile: float, lower: float, upper: float, upper_inclusive: bool) -> bool:
    return lower <= percentile <= upper if upper_inclusive else lower <= percentile < upper


def build_review_sample(
    explanation_rows: Sequence[Mapping[str, object]], normalized_sha256: str
) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Select exactly Top-50 plus 50 hash-sampled comparison rows.

    The Top-50 is verified from the persisted Stage 1.8 rank and never
    recomputed from a display score or a priority heuristic.
    """

    normalized_hash = _require_sha256(normalized_sha256, "normalized_sha256")
    rows = [dict(row) for row in explanation_rows]
    if len(rows) < 100:
        raise ReviewError("review sampling requires at least 100 explanation rows")
    numbers: set[int] = set()
    top: list[dict[str, object]] = []
    comparison_pool: list[dict[str, object]] = []
    for row in rows:
        number = row.get("source_record_number")
        rank = row.get("anomaly_rank")
        selected = row.get("analyst_review_selected")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1 or number in numbers:
            raise ReviewError("explanation record numbers must be unique positive integers")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
            raise ReviewError("explanation anomaly rank is invalid")
        if not isinstance(selected, bool) or selected != (rank <= 50):
            raise ReviewError("Top-50 membership does not match the Stage 1.8 score contract")
        numbers.add(number)
        (top if selected else comparison_pool).append(row)
    if len(top) != 50:
        raise ReviewError("Stage 1.8 Top-50 review membership is incomplete or duplicated")
    percentiles = _unrounded_percentiles(rows)
    selected_comparison: list[tuple[str, dict[str, object]]] = []
    selected_numbers = {int(row["source_record_number"]) for row in top}
    counts = {"TOP_50": 50, **{name: 0 for name, _, _, _ in _BANDS}, "FALLBACK": 0}
    for name, lower, upper, upper_inclusive in _BANDS:
        candidates = [
            row
            for row in comparison_pool
            if int(row["source_record_number"]) not in selected_numbers
            and _in_band(percentiles[int(row["source_record_number"])], lower, upper, upper_inclusive)
        ]
        candidates.sort(key=lambda row: (_sample_hash(int(row["source_record_number"])), int(row["source_record_number"])))
        for row in candidates[:10]:
            number = int(row["source_record_number"])
            selected_numbers.add(number)
            selected_comparison.append((name, row))
            counts[name] += 1
    shortfall = 50 - len(selected_comparison)
    if shortfall:
        candidates = [row for row in comparison_pool if int(row["source_record_number"]) not in selected_numbers]
        candidates.sort(key=lambda row: (_sample_hash(int(row["source_record_number"])), int(row["source_record_number"])))
        for row in candidates[:shortfall]:
            selected_numbers.add(int(row["source_record_number"]))
            selected_comparison.append(("FALLBACK", row))
            counts["FALLBACK"] += 1
    if len(selected_comparison) != 50:
        raise ReviewError("comparison sample cannot reach the required review population")

    sample: list[dict[str, object]] = []
    for membership, row in [("TOP_50", item) for item in top] + selected_comparison:
        copy = dict(row)
        number = int(copy["source_record_number"])
        review_id = review_id_for_record(normalized_hash, number)
        copy["review_id"] = review_id
        copy["review_membership"] = membership
        sample.append(copy)
    if len({str(row["review_id"]) for row in sample}) != 100:
        raise ReviewError("review sampling produced duplicate review IDs")
    sample.sort(key=lambda row: (_presentation_hash(str(row["review_id"])), str(row["review_id"])))
    return sample, counts


def _spreadsheet_safe(value: object) -> object:
    if isinstance(value, str) and value.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_review_queue(path: str | Path, sample: Iterable[Mapping[str, object]]) -> int:
    """Write the exact blinded first-pass queue with reversible formula escaping."""

    queue_path = Path(path)
    count = 0
    try:
        with queue_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=QUEUE_COLUMNS, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for row in sample:
                display = row.get("display_context")
                review_id = row.get("review_id")
                if not isinstance(display, Mapping) or not isinstance(review_id, str):
                    raise ReviewError("review queue sample is incomplete")
                if set(display) != set(DISPLAY_CONTEXT_COLUMNS):
                    raise ReviewError("review queue display context contains unapproved fields")
                queue_row = {"review_id": review_id, **dict(display)}
                writer.writerow({key: _spreadsheet_safe(queue_row[key]) for key in QUEUE_COLUMNS})
                count += 1
    except OSError as error:
        raise ReviewError("review queue cannot be written") from error
    return count


def _parse_review_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError("reviewed_at must be a non-empty ISO8601 offset timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ReviewError("reviewed_at must be an ISO8601 offset timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReviewError("reviewed_at must contain an ISO8601 offset")
    return value


def validate_blind_reviews(
    entries: Iterable[Mapping[str, object]], expected_review_ids: set[str]
) -> dict[str, dict[str, str]]:
    """Validate exactly one complete, human-supplied blind decision per queue row."""

    expected = set(expected_review_ids)
    if not expected:
        raise ReviewError("expected review IDs must not be empty")
    reviews: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != set(BLIND_LABEL_COLUMNS):
            raise ReviewError("blind review record does not contain exactly its contract fields")
        review_id = entry["review_id"]
        label = entry["blind_label"]
        rationale = entry["blind_rationale"]
        alias = entry["reviewer_alias"]
        if not isinstance(review_id, str) or review_id not in expected or review_id in reviews:
            raise ReviewError("blind review ID is invalid, unexpected, or duplicated")
        if label not in BLIND_LABELS:
            raise ReviewError("blind review decision is invalid")
        if not isinstance(rationale, str) or not rationale.strip() or not isinstance(alias, str) or not alias.strip():
            raise ReviewError("blind rationale and reviewer alias must be non-empty")
        reviews[review_id] = {
            "blind_label": str(label),
            "blind_rationale": rationale,
            "reviewer_alias": alias,
            "reviewed_at": _parse_review_timestamp(entry["reviewed_at"]),
        }
    if set(reviews) != expected:
        raise ReviewError("blind labels must contain exactly every expected review ID")
    return reviews


def read_blind_labels(path: str | Path, expected_review_ids: set[str]) -> dict[str, dict[str, str]]:
    """Read one strict UTF-8-sig human label CSV without modifying it."""

    label_path = Path(path)
    try:
        with label_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != BLIND_LABEL_COLUMNS:
                raise ReviewError("blind label CSV columns are incompatible")
            return validate_blind_reviews(list(reader), expected_review_ids)
    except UnicodeDecodeError as error:
        raise ReviewError("blind label CSV is not valid UTF-8") from error
    except OSError as error:
        raise ReviewError("blind label CSV cannot be read") from error
