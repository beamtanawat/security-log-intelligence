"""Deterministic Stage 1.9 automated investigation triage.

This module prioritizes already-produced Stage 1.9 explanations.  It does not
retrain or rescore the Stage 1.8 model, and it creates no human labels or
classification-performance claims.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import audit_explainability
from ai_features.artifact import canonical_json, file_sha256
from anomaly.models import ANOMALY_BANDS
from audit_explainability import (
    EXPLANATION_ARTIFACT_NAME,
    METADATA_ARTIFACT_NAME,
    iter_explanation_rows,
)
from explainability.interpretation import CANONICAL_BEHAVIORS


AUTO_TRIAGE_SCHEMA_VERSION = "1.0"
AUTO_TRIAGE_VALUES = frozenset({"HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST"})
AUTO_TRIAGE_ARTIFACT_NAME = "stage_1_9_auto_triage.csv"
TOP_ANOMALIES_ARTIFACT_NAME = "stage_1_9_top_anomalies.csv"
SUMMARY_ARTIFACT_NAME = "stage_1_9_summary.json"
AUTO_TRIAGE_BUNDLE_NAMES = frozenset(
    {AUTO_TRIAGE_ARTIFACT_NAME, TOP_ANOMALIES_ARTIFACT_NAME, SUMMARY_ARTIFACT_NAME}
)
AUTO_TRIAGE_COLUMNS = (
    "source_record_number",
    "source_record_id",
    "partition",
    "anomaly_rank",
    "anomaly_score",
    "anomaly_band",
    "auto_triage",
    "investigation_priority_score",
    "evidence_strength",
    "suspected_attack_type",
    "suspected_behaviors",
    "top_reasons",
    "review_status",
)
SUMMARY_FIELDS = frozenset(
    {
        "schema_version",
        "triage_contract",
        "row_count",
        "reference_count",
        "holdout_count",
        "top_50_count",
        "auto_triage_counts",
        "auto_triage_distribution",
        "anomaly_band_counts",
        "anomaly_band_distribution",
        "evidence_strength_counts",
        "evidence_strength_distribution",
        "suspected_behavior_counts",
        "suspected_behavior_distribution",
        "suspected_attack_interpretation_counts",
        "suspected_attack_interpretation_distribution",
        "review_status_counts",
        "score_quantiles",
        "priority_score_quantiles",
        "explanation_coverage",
        "records_with_specific_suspected_behavior",
        "top_50_fallback_count",
        "null_attack_interpretation_count",
        "pre_review_metadata_identity",
        "explanation_artifact_identity",
        "auto_triage_artifact_identity",
        "top_anomalies_artifact_identity",
    }
)
_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@")
_EVIDENCE_VALUES = ("HIGH", "MEDIUM", "LOW", None)
_REVIEW_STATUSES = ("NOT_SELECTED", "PENDING", "REVIEWED_RESOLVED", "REVIEWED_UNCERTAIN")
_ATTACK_VALUES = ("Possible reconnaissance activity", "Unclassified suspicious behavior", None)
_BEHAVIOR_VALUES = (*CANONICAL_BEHAVIORS, "UNCLASSIFIED_ANOMALOUS_PATTERN")


class AutoTriageError(ValueError):
    """Raised when automated triage cannot preserve its evidence contract."""


@dataclass(frozen=True)
class AutoTriageBuildSummary:
    """Small publication result; aggregate data remains in the artifact."""

    bundle_path: str
    row_count: int
    top_50_count: int
    high_interest_count: int
    medium_interest_count: int
    low_interest_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "row_count": self.row_count,
            "top_50_count": self.top_50_count,
            "high_interest_count": self.high_interest_count,
            "medium_interest_count": self.medium_interest_count,
            "low_interest_count": self.low_interest_count,
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _processed_root() -> Path:
    return (_project_root() / "data" / "processed").resolve()


def _contains(parent: Path, child: Path) -> bool:
    return child != parent and parent in child.parents


def _has_symlink_component(path: Path) -> bool:
    candidate = path.absolute()
    while candidate != candidate.parent:
        if candidate.exists() and candidate.is_symlink():
            return True
        candidate = candidate.parent
    return candidate.exists() and candidate.is_symlink()


def _resolve_new_output(value: str | Path) -> Path:
    supplied = Path(value)
    if supplied.is_symlink() or _has_symlink_component(supplied):
        raise AutoTriageError("auto-triage output path must not traverse a symlink")
    output = supplied.resolve()
    root = _processed_root()
    if not _contains(root, output) or output.exists() or not output.parent.is_dir() or output.parent.is_symlink():
        raise AutoTriageError("auto-triage output must be a new directory beneath data/processed")
    return output


def _file_identity(path: Path, name: str, *, row_count: int | None = None) -> dict[str, object]:
    identity: dict[str, object] = {
        "path": name,
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }
    if row_count is not None:
        identity["row_count"] = row_count
    return identity


def _require_row_value(row: Mapping[str, object], name: str) -> object:
    if name not in row:
        raise AutoTriageError(f"explanation row is missing {name}")
    return row[name]


def classify_auto_triage(row: Mapping[str, object]) -> str:
    """Classify only from fixed Stage 1.8 rank/band evidence.

    HIGH_INTEREST retains exact persisted Top-50 membership.  MEDIUM_INTEREST
    is a non-Top-50 row already in one of the frozen non-baseline Stage 1.8
    anomaly bands.  LOW_INTEREST is the remaining baseline population.
    """

    rank = _require_row_value(row, "anomaly_rank")
    selected = _require_row_value(row, "analyst_review_selected")
    band = _require_row_value(row, "anomaly_band")
    if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
        raise AutoTriageError("anomaly_rank must be a positive integer")
    if not isinstance(selected, bool) or selected != (rank <= 50):
        raise AutoTriageError("Top-50 selection does not reconcile to anomaly_rank")
    if not isinstance(band, str) or band not in ANOMALY_BANDS:
        raise AutoTriageError("anomaly_band is not a locked Stage 1.8 value")
    if selected:
        return "HIGH_INTEREST"
    if band != "BASELINE":
        return "MEDIUM_INTEREST"
    return "LOW_INTEREST"


def _review_status_without_human_label(review_id: object) -> str:
    if review_id is None:
        return "NOT_SELECTED"
    if not isinstance(review_id, str) or not review_id:
        raise AutoTriageError("review_id must be a non-empty queue ID or null")
    return "PENDING"


def project_auto_triage_row(row: Mapping[str, object]) -> dict[str, object]:
    """Project one immutable explanation row to one automated triage row."""

    auto_triage = classify_auto_triage(row)
    attack_type = _require_row_value(row, "suspected_attack_type")
    if row["anomaly_rank"] > 50 and attack_type is not None:
        raise AutoTriageError("non-Top-50 attack interpretation must remain null")
    behaviors = _require_row_value(row, "suspected_behaviors")
    reasons = _require_row_value(row, "top_reasons")
    if not isinstance(behaviors, list) or not isinstance(reasons, list):
        raise AutoTriageError("explanation behavior/reason fields are incompatible")
    return {
        "source_record_number": _require_row_value(row, "source_record_number"),
        "source_record_id": _require_row_value(row, "source_record_id"),
        "partition": _require_row_value(row, "partition"),
        "anomaly_rank": row["anomaly_rank"],
        "anomaly_score": _require_row_value(row, "anomaly_score"),
        "anomaly_band": row["anomaly_band"],
        "auto_triage": auto_triage,
        "investigation_priority_score": _require_row_value(row, "investigation_priority_score"),
        "evidence_strength": _require_row_value(row, "evidence_strength"),
        "suspected_attack_type": attack_type,
        "suspected_behaviors": behaviors,
        "top_reasons": reasons,
        "review_status": _review_status_without_human_label(_require_row_value(row, "review_id")),
    }


def _quantiles(values: Iterable[object]) -> dict[str, float | None]:
    parsed: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise AutoTriageError("summary numeric values must be finite")
        parsed.append(float(value))
    if not parsed:
        return {name: None for name in ("min", "p25", "p50", "p75", "p90", "p95", "p99", "max")}
    parsed.sort()

    def at(fraction: float) -> float:
        position = (len(parsed) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return parsed[lower]
        return parsed[lower] + (parsed[upper] - parsed[lower]) * (position - lower)

    return {
        "min": parsed[0],
        "p25": at(0.25),
        "p50": at(0.50),
        "p75": at(0.75),
        "p90": at(0.90),
        "p95": at(0.95),
        "p99": at(0.99),
        "max": parsed[-1],
    }


def _table(order: Sequence[object], counts: Mapping[object, int], total: int) -> list[dict[str, object]]:
    return [
        {
            "value": value,
            "count": counts.get(value, 0),
            "percentage": 0.0 if total == 0 else counts.get(value, 0) * 100.0 / total,
        }
        for value in order
    ]


@dataclass
class _SummaryAccumulator:
    row_count: int = 0
    reference_count: int = 0
    holdout_count: int = 0
    top_50_count: int = 0
    auto_triage_counts: Counter[str] = field(default_factory=Counter)
    anomaly_band_counts: Counter[str] = field(default_factory=Counter)
    evidence_strength_counts: Counter[object] = field(default_factory=Counter)
    behavior_counts: Counter[str] = field(default_factory=Counter)
    attack_counts: Counter[object] = field(default_factory=Counter)
    review_status_counts: Counter[str] = field(default_factory=Counter)
    scores: list[object] = field(default_factory=list)
    priorities: list[object] = field(default_factory=list)
    reason_available_count: int = 0
    specific_behavior_count: int = 0
    fallback_count: int = 0
    null_attack_count: int = 0

    def add(self, source_row: Mapping[str, object], projected: Mapping[str, object]) -> None:
        partition = projected["partition"]
        if partition == "REFERENCE":
            self.reference_count += 1
        elif partition == "HOLDOUT":
            self.holdout_count += 1
        else:
            raise AutoTriageError("explanation partition is incompatible")
        self.row_count += 1
        self.top_50_count += int(projected["anomaly_rank"] <= 50)
        self.auto_triage_counts[str(projected["auto_triage"])] += 1
        self.anomaly_band_counts[str(projected["anomaly_band"])] += 1
        self.evidence_strength_counts[projected["evidence_strength"]] += 1
        self.attack_counts[projected["suspected_attack_type"]] += 1
        self.review_status_counts[str(projected["review_status"])] += 1
        self.scores.append(projected["anomaly_score"])
        self.priorities.append(projected["investigation_priority_score"])
        behaviors = projected["suspected_behaviors"]
        if not isinstance(behaviors, list):
            raise AutoTriageError("suspected behaviors are incompatible")
        if behaviors:
            self.reason_available_count += 1
        specific = [item for item in behaviors if item in CANONICAL_BEHAVIORS]
        self.specific_behavior_count += int(bool(specific))
        self.fallback_count += int(behaviors == ["UNCLASSIFIED_ANOMALOUS_PATTERN"])
        for behavior in behaviors:
            if behavior not in _BEHAVIOR_VALUES:
                raise AutoTriageError("suspected behavior is incompatible")
            self.behavior_counts[str(behavior)] += 1
        self.null_attack_count += int(projected["suspected_attack_type"] is None)
        if source_row.get("review_id") is None and projected["review_status"] != "NOT_SELECTED":
            raise AutoTriageError("unselected record has an invalid automated review status")
        if source_row.get("review_id") is not None and projected["review_status"] != "PENDING":
            raise AutoTriageError("queue record has an invalid automated review status")

    def summary(self) -> dict[str, object]:
        if self.row_count == 0:
            raise AutoTriageError("auto-triage requires at least one explanation row")
        if self.top_50_count != self.auto_triage_counts["HIGH_INTEREST"]:
            raise AutoTriageError("HIGH_INTEREST must preserve exactly the Stage 1.8 Top-50")
        if self.review_status_counts["REVIEWED_RESOLVED"] or self.review_status_counts["REVIEWED_UNCERTAIN"]:
            raise AutoTriageError("automatic triage must not fabricate human-review states")
        return {
            "schema_version": AUTO_TRIAGE_SCHEMA_VERSION,
            "triage_contract": {
                "HIGH_INTEREST": "Persisted Stage 1.8 Top-50 selection (anomaly_rank <= 50).",
                "MEDIUM_INTEREST": "Non-Top-50 record in a frozen non-baseline Stage 1.8 anomaly band.",
                "LOW_INTEREST": "Remaining baseline record; this does not mean benign or safe.",
                "limitations": [
                    "ANOMALY != ATTACK",
                    "HIGH_INTEREST != CONFIRMED_MALICIOUS",
                    "LOW_INTEREST != CONFIRMED_BENIGN",
                    "No human labels or supervised classification metrics are present.",
                ],
            },
            "row_count": self.row_count,
            "reference_count": self.reference_count,
            "holdout_count": self.holdout_count,
            "top_50_count": self.top_50_count,
            "auto_triage_counts": {name: self.auto_triage_counts[name] for name in ("HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST")},
            "auto_triage_distribution": _table(("HIGH_INTEREST", "MEDIUM_INTEREST", "LOW_INTEREST"), self.auto_triage_counts, self.row_count),
            "anomaly_band_counts": {name: self.anomaly_band_counts[name] for name in ANOMALY_BANDS},
            "anomaly_band_distribution": _table(ANOMALY_BANDS, self.anomaly_band_counts, self.row_count),
            "evidence_strength_counts": {"HIGH": self.evidence_strength_counts["HIGH"], "MEDIUM": self.evidence_strength_counts["MEDIUM"], "LOW": self.evidence_strength_counts["LOW"], "NULL": self.evidence_strength_counts[None]},
            "evidence_strength_distribution": _table(_EVIDENCE_VALUES, self.evidence_strength_counts, self.row_count),
            "suspected_behavior_counts": {name: self.behavior_counts[name] for name in _BEHAVIOR_VALUES},
            "suspected_behavior_distribution": _table(_BEHAVIOR_VALUES, self.behavior_counts, self.row_count),
            "suspected_attack_interpretation_counts": {"POSSIBLE_RECONNAISSANCE_ACTIVITY": self.attack_counts["Possible reconnaissance activity"], "UNCLASSIFIED_SUSPICIOUS_BEHAVIOR": self.attack_counts["Unclassified suspicious behavior"], "NULL": self.attack_counts[None]},
            "suspected_attack_interpretation_distribution": _table(_ATTACK_VALUES, self.attack_counts, self.row_count),
            "review_status_counts": {name: self.review_status_counts[name] for name in _REVIEW_STATUSES},
            "score_quantiles": _quantiles(self.scores),
            "priority_score_quantiles": _quantiles(self.priorities),
            "explanation_coverage": {
                "records_with_suspected_behavior_or_fallback": self.reason_available_count,
                "percentage": self.reason_available_count * 100.0 / self.row_count,
            },
            "records_with_specific_suspected_behavior": self.specific_behavior_count,
            "top_50_fallback_count": self.fallback_count,
            "null_attack_interpretation_count": self.null_attack_count,
        }


def build_auto_triage_summary(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Return deterministic coverage/operational summaries without human truth."""

    accumulator = _SummaryAccumulator()
    for row in rows:
        accumulator.add(row, project_auto_triage_row(row))
    return accumulator.summary()


def _csv_cell(value: object) -> object:
    if isinstance(value, (list, dict)):
        value = canonical_json(value)
    if isinstance(value, str) and value.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return "'" + value
    return value


def _write_csv_header(handle: object) -> csv.DictWriter:
    writer = csv.DictWriter(handle, fieldnames=AUTO_TRIAGE_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    return writer


def _write_csv_row(writer: csv.DictWriter, row: Mapping[str, object]) -> None:
    if set(row) != set(AUTO_TRIAGE_COLUMNS):
        raise AutoTriageError("auto-triage row does not contain exactly its contract columns")
    writer.writerow({name: _csv_cell(row[name]) for name in AUTO_TRIAGE_COLUMNS})


def build_auto_triage_bundle(
    explanations_dir: str | Path,
    output_dir: str | Path,
) -> AutoTriageBuildSummary:
    """Build, audit, and no-replace publish a Stage 1.9 auto-triage bundle."""

    temporary: Path | None = None
    published = False
    try:
        pre_bundle = Path(explanations_dir)
        pre_summary = audit_explainability.audit_explanation_bundle(pre_bundle)
        output = _resolve_new_output(output_dir)
        explanation_path = pre_bundle / EXPLANATION_ARTIFACT_NAME
        metadata_path = pre_bundle / METADATA_ARTIFACT_NAME
        explanation_identity = _file_identity(explanation_path, EXPLANATION_ARTIFACT_NAME, row_count=pre_summary.row_count)
        metadata_identity = _file_identity(metadata_path, METADATA_ARTIFACT_NAME)
        temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent))
        triage_path = temporary / AUTO_TRIAGE_ARTIFACT_NAME
        top_path = temporary / TOP_ANOMALIES_ARTIFACT_NAME
        accumulator = _SummaryAccumulator()
        top_rows: list[dict[str, object]] = []
        with triage_path.open("w", encoding="utf-8", newline="") as handle:
            triage_writer = _write_csv_header(handle)
            for source_row in iter_explanation_rows(explanation_path):
                projected = project_auto_triage_row(source_row)
                _write_csv_row(triage_writer, projected)
                accumulator.add(source_row, projected)
                if projected["anomaly_rank"] <= 50:
                    top_rows.append(projected)
        aggregate = accumulator.summary()
        if len(top_rows) != 50:
            raise AutoTriageError("auto-triage Top-50 projection is incomplete")
        top_rows.sort(key=lambda row: int(row["anomaly_rank"]))
        with top_path.open("w", encoding="utf-8", newline="") as handle:
            top_writer = _write_csv_header(handle)
            for row in top_rows:
                _write_csv_row(top_writer, row)
        triage_identity = _file_identity(triage_path, AUTO_TRIAGE_ARTIFACT_NAME, row_count=accumulator.row_count)
        top_identity = _file_identity(top_path, TOP_ANOMALIES_ARTIFACT_NAME, row_count=len(top_rows))
        payload = {
            **aggregate,
            "pre_review_metadata_identity": metadata_identity,
            "explanation_artifact_identity": explanation_identity,
            "auto_triage_artifact_identity": triage_identity,
            "top_anomalies_artifact_identity": top_identity,
        }
        if set(payload) != SUMMARY_FIELDS:
            raise AutoTriageError("auto-triage summary does not contain exactly its contract fields")
        summary_path = temporary / SUMMARY_ARTIFACT_NAME
        summary_path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")
        audit_explainability.audit_auto_triage_bundle(pre_bundle, temporary)
        if _file_identity(explanation_path, EXPLANATION_ARTIFACT_NAME, row_count=pre_summary.row_count) != explanation_identity:
            raise AutoTriageError("explanation artifact changed while automated triage was built")
        if _file_identity(metadata_path, METADATA_ARTIFACT_NAME) != metadata_identity:
            raise AutoTriageError("explanation metadata changed while automated triage was built")
        if output.exists():
            raise AutoTriageError("auto-triage output appeared during publication")
        if os.name != "nt":
            raise AutoTriageError("atomic no-replace directory publication is unavailable on this platform")
        os.rename(temporary, output)
        published = True
        return AutoTriageBuildSummary(
            bundle_path=str(output),
            row_count=accumulator.row_count,
            top_50_count=accumulator.top_50_count,
            high_interest_count=accumulator.auto_triage_counts["HIGH_INTEREST"],
            medium_interest_count=accumulator.auto_triage_counts["MEDIUM_INTEREST"],
            low_interest_count=accumulator.auto_triage_counts["LOW_INTEREST"],
        )
    except (audit_explainability.ExplainabilityAuditError, OSError, ValueError) as error:
        if isinstance(error, AutoTriageError):
            raise
        raise AutoTriageError(str(error)) from error
    finally:
        if temporary is not None and temporary.exists() and not published:
            shutil.rmtree(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an audited Stage 1.9 automated triage bundle.")
    parser.add_argument("--explanations-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        summary = build_auto_triage_bundle(arguments.explanations_dir, arguments.output_dir)
    except AutoTriageError as error:
        print(f"Stage 1.9 automated triage failed: {error}")
        return 1
    print(canonical_json(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
