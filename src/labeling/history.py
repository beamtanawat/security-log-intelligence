"""Append-only label-history projection."""

from __future__ import annotations

from collections.abc import Iterable

from .models import LabelRecord, LabelValue, Provenance, ResolutionStatus


def append_label_version(
    current: LabelRecord,
    *,
    label: LabelValue,
    provenance: Provenance | None = None,
    version: int | None = None,
) -> LabelRecord:
    """Create a superseding version without mutating the prior record."""

    expected = current.label_version + 1
    if version is not None and version != expected:
        raise ValueError("parent/version gap in label history")
    effective_provenance = provenance or current.label_provenance
    if effective_provenance is None:
        raise ValueError("correction requires explicit provenance")
    return LabelRecord.new(
        dataset_sha256=current.dataset_sha256,
        annotation_unit_id=current.annotation_unit_id,
        label=label,
        resolution_status=ResolutionStatus.RESOLVED,
        provenance=effective_provenance,
        parent_label_record_id=current.label_record_id,
        label_version=expected,
        review_decision_ids=current.review_decision_ids,
        source_record_number=current.source_record_number,
        source_record_id=current.source_record_id,
    )


def resolve_label_history(records: Iterable[LabelRecord]) -> LabelRecord:
    """Return highest non-superseded version for one unit."""

    rows = list(records)
    if not rows:
        raise ValueError("label history cannot be empty")
    unit_ids = {row.annotation_unit_id for row in rows}
    if len(unit_ids) != 1:
        raise ValueError("history contains multiple annotation units")
    rows.sort(key=lambda row: row.label_version)
    for expected, row in enumerate(rows, start=1):
        if row.label_version != expected:
            raise ValueError("label history versions must be contiguous")
        if expected > 1 and row.parent_label_record_id != rows[expected - 2].label_record_id:
            raise ValueError("label history parent mismatch")
    return rows[-1]
