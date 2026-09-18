"""Independent reconciliation checks for a Stage 2.0 package."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Mapping, Sequence

from reporting.cases import select_case_studies
from reporting.export import (
    FINAL_CSV_FIELDS,
    FINAL_JSON_FIELDS,
    aggregate_rows,
    canonical_json,
    csv_cell_text,
    file_sha256,
)
from reporting.graphs import build_graph_data, graph_manifest_counts


class PackageAuditError(ValueError):
    """Raised when a final package does not reconcile to its source rows."""


SUMMARY_REQUIRED_FIELDS = {
    "upstream_identities",
    "final_jsonl_identity",
    "final_csv_identity",
    "record_count",
    "rank_validation",
    "feature_count",
    "partition_counts",
    "auto_triage_counts",
    "anomaly_band_counts",
    "evidence_strength_counts",
    "suspected_behavior_counts",
    "suspected_attack_interpretation_counts",
    "review_counts",
    "score_quantiles",
    "priority_score_quantiles",
    "explanation_coverage",
    "model_diagnostics",
    "analyst_review_metrics",
    "reference_agreement",
    "graph_manifest",
    "case_selection",
    "report_contract_version",
    "security_interpretation",
    "package_validation",
}


# These are immutable identities from the accepted Stage 1.7–1.9 inputs.
# The final package must state the same inputs that the builder verifies.
EXPECTED_UPSTREAM_IDENTITIES = {
    "stage_1_7_feature_sha256": "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1",
    "stage_1_7_feature_metadata_sha256": "b74373532d5a15de84113d57249e642311a1b3b6c6e827b8747bba94082e2ae0",
    "stage_1_8_score_sha256": "f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4",
    "stage_1_9_explanation_sha256": "4ddf062473ad84715d73c8599ac03ad3f566c79492599da7a37a6712ac2416e0",
    "stage_1_9_auto_triage_sha256": "f38079cb935619670d4cffcc3d0ce34aad99d1431f7ed3ebf47a4afc79123ade",
    "stage_1_9_summary_sha256": "da18469b426a00f21f79e3f9988b210774b8f811a0d663c53a9cd91607602bac",
    "stage_1_9_top_anomalies_sha256": "9cbef506fa8a6da28947ea472e3eb67a335c17c672b768f0e3a5693601c41ea7",
    "human_evaluation_identity": None,
}


def _matches_final_jsonl_contract(row: Mapping[str, object]) -> bool:
    return set(row) == set(FINAL_JSON_FIELDS)


def rank_validation(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Return the explicit rank-permutation diagnostics for final rows."""

    anomaly_ranks = [row["anomaly_rank"] for row in rows]
    investigation_ranks = [row["investigation_rank"] for row in rows]
    expected = list(range(1, len(rows) + 1))
    return {
        "anomaly_rank": {
            "minimum": min(anomaly_ranks),
            "maximum": max(anomaly_ranks),
            "unique_count": len(set(anomaly_ranks)),
            "expected_count": len(rows),
            "ordered_contiguous": anomaly_ranks == expected,
        },
        "investigation_rank": {
            "minimum": min(investigation_ranks),
            "maximum": max(investigation_ranks),
            "unique_count": len(set(investigation_ranks)),
            "expected_count": len(rows),
            "complete_permutation": sorted(investigation_ranks) == expected,
        },
    }


def read_jsonl(path: str | Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise PackageAuditError(f"invalid JSONL at line {line_number}") from error
            if not isinstance(value, dict):
                raise PackageAuditError(f"JSONL row {line_number} is not an object")
            rows.append(value)
    return rows


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FINAL_CSV_FIELDS:
            raise PackageAuditError("final CSV headers do not match the contract")
        return list(reader)


def _audit_csv(rows: Sequence[Mapping[str, object]], csv_path: Path) -> None:
    csv_rows = _read_csv_rows(csv_path)
    if len(csv_rows) != len(rows):
        raise PackageAuditError("final CSV row count does not match final JSONL")
    for json_row, csv_row in zip(rows, csv_rows):
        context = json_row.get("display_context")
        if not isinstance(context, Mapping):
            raise PackageAuditError("final JSONL display_context does not match the contract")
        for field in FINAL_CSV_FIELDS:
            value = json_row[field] if field in FINAL_JSON_FIELDS else context.get(field)
            if csv_row[field] != csv_cell_text(value):
                raise PackageAuditError(f"final CSV {field} does not reconcile")


def _audit_summary(summary: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> None:
    missing = SUMMARY_REQUIRED_FIELDS - set(summary)
    if missing:
        raise PackageAuditError(f"analysis summary is missing required fields: {', '.join(sorted(missing))}")
    if summary["reference_agreement"] is not None:
        raise PackageAuditError("reference_agreement must be null without accepted human evaluation")
    if not isinstance(summary["model_diagnostics"], Mapping):
        raise PackageAuditError("model_diagnostics must be an object")
    if summary["upstream_identities"] != EXPECTED_UPSTREAM_IDENTITIES:
        raise PackageAuditError("analysis summary does not pin the approved upstream artifact identities")
    if summary["package_validation"] != {"status": "PASS", "scope": "final rows, full CSV/JSONL reconciliation, rank permutations, summary, chart aggregates, cases, and required report references"}:
        raise PackageAuditError("analysis summary has an invalid package_validation contract")
    if summary["rank_validation"] != rank_validation(rows):
        raise PackageAuditError("analysis summary rank diagnostics do not reconcile")
    computed = aggregate_rows(rows, feature_count=int(summary["feature_count"]))
    for key in ("record_count", "partition_counts", "top_50_count", "auto_triage_counts", "anomaly_band_counts", "evidence_strength_counts", "suspected_behavior_counts", "suspected_attack_interpretation_counts", "review_counts"):
        if summary.get(key) != computed.get(key):
            raise PackageAuditError(f"analysis summary does not reconcile for {key}")
    if summary["final_jsonl_identity"] != {"path": "final_anomaly_findings.jsonl", "sha256": file_sha256(Path(summary["_package_dir"]) / "final_anomaly_findings.jsonl"), "row_count": len(rows)}:
        raise PackageAuditError("final JSONL identity does not reconcile")
    if summary["final_csv_identity"] != {"path": "final_anomaly_findings.csv", "sha256": file_sha256(Path(summary["_package_dir"]) / "final_anomaly_findings.csv"), "row_count": len(rows)}:
        raise PackageAuditError("final CSV identity does not reconcile")


def _audit_cases(summary: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> None:
    expected = select_case_studies(rows)
    if summary["case_selection"] != expected:
        raise PackageAuditError("case-study selection does not satisfy the frozen category contract")


def _table_rows(path: Path, headers: tuple[str, ...]) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != headers:
            raise PackageAuditError(f"table headers do not match the contract: {path.name}")
        return list(reader)


def _audit_tables(package: Path, summary: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> None:
    tables = package / "tables"
    if not tables.is_dir():
        raise PackageAuditError("tables directory is missing")
    distributions = (
        ("auto_triage_distribution", summary["auto_triage_distribution"]),
        ("anomaly_band_distribution", summary["anomaly_band_distribution"]),
        ("suspected_behavior_distribution", summary["suspected_behavior_distribution"]),
        ("evidence_strength_distribution", summary["evidence_strength_distribution"]),
        ("suspected_attack_interpretation_distribution", summary["suspected_attack_interpretation_distribution"]),
        ("review_status_distribution", summary["review_status_distribution"]),
    )
    for name, expected in distributions:
        actual = _table_rows(tables / f"{name}.csv", ("value", "count", "percentage"))
        normalized = [{"value": row["value"], "count": int(row["count"]), "percentage": float(row["percentage"])} for row in actual]
        expected_normalized = [{"value": value["value"] if value["value"] is not None else "NULL", "count": int(value["count"]), "percentage": float(value["percentage"])} for value in expected]
        if normalized != expected_normalized:
            raise PackageAuditError(f"distribution table does not reconcile: {name}")
    top = _table_rows(tables / "top_50_anomalies.csv", ("anomaly_rank", "source_record_number", "source_record_id", "partition", "anomaly_score", "auto_triage", "investigation_priority_score", "suspected_behaviors", "suspected_attack_type", "evidence_strength", "top_reasons"))
    expected_top = [row for row in rows if int(row["anomaly_rank"]) <= 50]
    if len(top) != len(expected_top):
        raise PackageAuditError("Top-50 table row count does not reconcile")
    for table_row, row in zip(top, expected_top):
        if (table_row["anomaly_rank"], table_row["source_record_number"], table_row["source_record_id"]) != (str(row["anomaly_rank"]), str(row["source_record_number"]), str(row["source_record_id"])):
            raise PackageAuditError("Top-50 table identity does not reconcile")
    cases_path = tables / "case_studies.json"
    with cases_path.open("r", encoding="utf-8") as handle:
        if json.load(handle) != summary["case_selection"]:
            raise PackageAuditError("case-studies table does not reconcile")
    overall = _table_rows(tables / "overall_summary.csv", ("metric", "value"))
    metrics = {row["metric"]: row["value"] for row in overall}
    for name in ("record_count", "model_diagnostics", "graph_manifest", "package_validation"):
        if name not in metrics:
            raise PackageAuditError("overall summary table lacks required metrics")


def _audit_graphs(summary: Mapping[str, object], rows: Sequence[Mapping[str, object]], feature_rows: Sequence[Mapping[str, object]] | None, feature_names: Sequence[str] | None, score_rows: Sequence[Mapping[str, object]] | None) -> None:
    manifest = summary["graph_manifest"]
    if not isinstance(manifest, list) or len(manifest) != 10:
        raise PackageAuditError("graph manifest must contain exactly ten charts")
    expected_names = {f"{index:02d}_{name}" for index, name in ((1, "score_distribution.png"), (2, "top20_scores.png"), (3, "anomaly_bands.png"), (4, "protocol_representation.png"), (5, "service_representation.png"), (6, "observed_anomaly_driver_frequency.png"), (7, "auto_triage_distribution.png"), (8, "evidence_strength.png"), (9, "suspected_attack_interpretation.png"), (10, "feature_comparison.png"))}
    seen = {item.get("name") for item in manifest if isinstance(item, Mapping)}
    if seen != expected_names:
        raise PackageAuditError("graph manifest does not contain the required chart names")
    package = Path(summary["_package_dir"])
    expected_final_hash = summary["final_jsonl_identity"]["sha256"]
    for item in manifest:
        if not isinstance(item, Mapping) or item.get("status") != "PASS" or not isinstance(item.get("reason"), str) or not isinstance(item.get("source_identities"), Mapping) or not isinstance(item.get("counts"), Mapping):
            raise PackageAuditError("graph manifest entry has an invalid contract")
        relative = item.get("relative_path")
        if not isinstance(relative, str) or not (package / relative).is_file() or (package / relative).stat().st_size == 0:
            raise PackageAuditError("graph manifest references a missing or empty PNG")
        identities = item["source_identities"]
        if identities.get("final_jsonl_sha256") != expected_final_hash:
            raise PackageAuditError("graph manifest does not identify the final JSONL it represents")
        if identities.get("stage_1_8_score_sha256") != EXPECTED_UPSTREAM_IDENTITIES["stage_1_8_score_sha256"]:
            raise PackageAuditError("graph manifest does not identify the approved Stage 1.8 score artifact")
        if item["name"] == "10_feature_comparison.png" and identities.get("stage_1_7_feature_sha256") != EXPECTED_UPSTREAM_IDENTITIES["stage_1_7_feature_sha256"]:
            raise PackageAuditError("Chart 10 does not identify the approved Stage 1.7 feature artifact")
    if feature_rows is not None and feature_names is not None:
        expected = build_graph_data(rows, feature_rows, feature_names, score_rows)
        for item in manifest:
            if item["counts"] != graph_manifest_counts(str(item["name"]), expected[str(item["name"])]):
                raise PackageAuditError(f"graph aggregate does not reconcile: {item['name']}")


def _audit_report(report_path: Path, package_dir: Path) -> None:
    if not report_path.is_file():
        raise PackageAuditError("final report is missing")
    text = report_path.read_text(encoding="utf-8")
    required_sections = (
        "Problem and Dataset", "Data Limitations and Interpretation Boundaries",
        "Architecture", "Workflow", "Rule Baseline", "Feature Engineering",
        "Leakage Controls", "Model", "Anomaly Scoring", "Explanation Method",
        "Suspected Behavior and Attack Boundaries",
        "Automated Triage and Optional Human Evaluation Methodology",
        "Results/Metrics/Graphs", "Results Tables", "Visualizations",
        "Top-50 Investigation Results", "Four Case Studies", "Limitations",
        "Reproducibility", "Local Demo", "Future Work",
    )
    if any(section not in text for section in required_sections):
        raise PackageAuditError("final report is missing a required section")
    targets = {
        (report_path.parent / match.group(1).split("#", 1)[0]).resolve()
        for match in re.finditer(r"\]\(([^)]+)\)", text)
        if not match.group(1).startswith(("http://", "https://", "#"))
    }
    for graph in sorted((package_dir / "graphs").glob("*.png")):
        if graph.resolve() not in targets:
            raise PackageAuditError(f"final report does not reference {graph.name}")
    for relative in ("final_anomaly_findings.jsonl", "final_anomaly_findings.csv", "analysis_summary.json", "tables/top_50_anomalies.csv"):
        if (package_dir / relative).resolve() not in targets:
            raise PackageAuditError(f"final report does not reference {Path(relative).name}")


def audit_package(package_dir: str | Path, *, expected_rows: int | None = 100_000, feature_rows: Sequence[Mapping[str, object]] | None = None, feature_names: Sequence[str] | None = None, score_rows: Sequence[Mapping[str, object]] | None = None, report_path: str | Path | None = None) -> dict[str, object]:
    """Reconcile package rows, exports, summary, cases, and chart data without reading raw logs."""

    package = Path(package_dir)
    jsonl_path = package / "final_anomaly_findings.jsonl"
    csv_path = package / "final_anomaly_findings.csv"
    summary_path = package / "analysis_summary.json"
    if not all(path.is_file() for path in (jsonl_path, csv_path, summary_path)):
        raise PackageAuditError("required final package file is missing")
    rows = read_jsonl(jsonl_path)
    if expected_rows is not None and len(rows) != expected_rows:
        raise PackageAuditError(f"expected {expected_rows} final rows, found {len(rows)}")
    seen: set[tuple[int, str]] = set()
    ranks: list[int] = []
    investigation_ranks: list[int] = []
    for row in rows:
        if not _matches_final_jsonl_contract(row):
            raise PackageAuditError("final JSONL row fields do not match the contract")
        key = (int(row["source_record_number"]), str(row["source_record_id"]))
        if key in seen:
            raise PackageAuditError("duplicate final provenance identity")
        seen.add(key)
        anomaly_rank = row["anomaly_rank"]
        investigation_rank = row["investigation_rank"]
        if isinstance(anomaly_rank, bool) or not isinstance(anomaly_rank, int) or anomaly_rank < 1:
            raise PackageAuditError("final JSONL anomaly_rank must be a positive integer")
        if isinstance(investigation_rank, bool) or not isinstance(investigation_rank, int) or investigation_rank < 1:
            raise PackageAuditError("final JSONL investigation_rank must be a positive integer")
        ranks.append(anomaly_rank)
        investigation_ranks.append(investigation_rank)
    if ranks != list(range(1, len(rows) + 1)):
        raise PackageAuditError("final rows are not ordered by contiguous anomaly rank")
    if sorted(investigation_ranks) != list(range(1, len(rows) + 1)):
        raise PackageAuditError("final investigation ranks are not a complete contiguous permutation")
    expected_top_50 = 50 if expected_rows in (None, 100_000) else min(50, len(rows))
    if sum(rank <= 50 for rank in ranks) != expected_top_50:
        raise PackageAuditError("final package Top-50 count does not match the audited row population")
    _audit_csv(rows, csv_path)
    with summary_path.open("r", encoding="utf-8") as handle:
        summary = json.load(handle)
    if not isinstance(summary, dict):
        raise PackageAuditError("analysis summary must be an object")
    summary["_package_dir"] = str(package)
    try:
        _audit_summary(summary, rows)
        _audit_tables(package, summary, rows)
        _audit_cases(summary, rows)
        _audit_graphs(summary, rows, feature_rows, feature_names, score_rows)
        if report_path is not None:
            _audit_report(Path(report_path), package)
    finally:
        summary.pop("_package_dir", None)
    return {"status": "PASS", "record_count": len(rows), "top_50_count": expected_top_50, "graph_count": 10}
