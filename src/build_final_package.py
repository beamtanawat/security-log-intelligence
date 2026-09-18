"""Build the Stage 2.0 final result package from audited Stage 1.9 V3 data."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import uuid
from pathlib import Path
from typing import Mapping, Sequence

from ai_features.artifact import file_sha256
from reporting.audit import PackageAuditError, audit_package, rank_validation, read_jsonl
from reporting.cases import select_case_studies
from reporting.export import FINAL_CSV_FIELDS, aggregate_rows, build_final_row, canonical_json, write_csv, write_jsonl
from reporting.graphs import write_all_graphs


EXPECTED_V3 = {
    "explanation": "4ddf062473ad84715d73c8599ac03ad3f566c79492599da7a37a6712ac2416e0",
    "auto_triage": "f38079cb935619670d4cffcc3d0ce34aad99d1431f7ed3ebf47a4afc79123ade",
    "summary": "da18469b426a00f21f79e3f9988b210774b8f811a0d663c53a9cd91607602bac",
    "top_anomalies": "9cbef506fa8a6da28947ea472e3eb67a335c17c672b768f0e3a5693601c41ea7",
}

EXPECTED_STAGE_17_FEATURE = "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1"
EXPECTED_STAGE_17_METADATA = "b74373532d5a15de84113d57249e642311a1b3b6c6e827b8747bba94082e2ae0"
EXPECTED_STAGE_18_SCORE = "f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4"


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain an object")
    return value


def _require_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"required {label} is unavailable: {path}")


def _load_auto_rows(path: Path) -> dict[tuple[int, str], dict[str, str]]:
    result: dict[tuple[int, str], dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"source_record_number", "source_record_id", "auto_triage", "review_status"}
        if not required.issubset(reader.fieldnames or ()):
            raise ValueError("V3 auto-triage CSV is missing required columns")
        for row in reader:
            key = (int(row["source_record_number"]), row["source_record_id"])
            if key in result:
                raise ValueError("duplicate V3 auto-triage provenance identity")
            result[key] = row
    return result


def _write_table(path: Path, headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(headers)
        writer.writerows(rows)


def _markdown_distribution(title: str, values: Sequence[Mapping[str, object]]) -> list[str]:
    lines = [f"### {title}", "", "| Category | Count | Share of all records |", "|---|---:|---:|"]
    for value in values:
        label = value["value"] if value["value"] is not None else "No value"
        lines.append(f"| {label} | {int(value['count']):,} | {float(value['percentage']):.3f}% |")
    return [*lines, ""]


def _write_report(path: Path, package_name: str, summary: Mapping[str, object], cases: Sequence[Mapping[str, object]]) -> None:
    """Write the human-facing report only from audited package values."""

    triage = summary["auto_triage_counts"]
    coverage = summary["explanation_coverage"]
    score = summary["score_quantiles"]
    priority = summary["priority_score_quantiles"]
    package_link = f"../data/processed/{package_name}"
    lines = [
        "# Security Log Intelligence — Final Stage 2.0 Results",
        "",
        "Status: **local portfolio package generated from validated Stage 1.9 V3 artifacts**.",
        "",
        "## Problem and Dataset",
        "",
        "This package presents reproducible anomaly, explanation, and investigation-priority outputs for 100,000 sanitized FortiGate records. Sanitized identifiers remain opaque, and raw data remains immutable.",
        "",
        "## Data Limitations and Interpretation Boundaries",
        "",
        "**ANOMALY != ATTACK.** An anomaly score is relative abnormality, not attack probability. HIGH_INTEREST is investigation priority, not confirmed attack; LOW_INTEREST is not confirmed benign. Suspected behaviors and source-product observations are descriptive evidence, not confirmed malicious activity.",
        "",
        "## KPI Summary",
        "",
        f"- Total records: **{summary['record_count']:,}** (REFERENCE {summary['partition_counts']['REFERENCE']:,}; HOLDOUT {summary['partition_counts']['HOLDOUT']:,})",
        f"- Top-50 anomaly records: **{summary['top_50_count']}**",
        f"- HIGH_INTEREST / MEDIUM_INTEREST / LOW_INTEREST: **{triage['HIGH_INTEREST']:,} / {triage['MEDIUM_INTEREST']:,} / {triage['LOW_INTEREST']:,}**",
        f"- Explanation coverage: **{coverage['records_with_suspected_behavior_or_fallback']:,} ({coverage['percentage']:.3f}%)**; specific behavior: **{coverage['records_with_specific_suspected_behavior']:,}**; Top-50 fallback: **{summary['top_50_fallback_count']}**",
        f"- Anomaly-score quantiles (min / p50 / p95 / max): **{score['min']} / {score['p50']} / {score['p95']} / {score['max']}**",
        f"- Investigation-priority quantiles (min / p50 / p95 / max): **{priority['min']} / {priority['p50']} / {priority['p95']} / {priority['max']}**",
        "",
        "## Architecture",
        "",
        "```mermaid",
        "flowchart TD",
        "  raw[Immutable FortiGate CSV] --> parse[Streaming parser] --> norm[Normalized events]",
        "  norm --> rules[Rule observations] --> store[SQLite] --> api[Read-only API]",
        "  norm --> features[Stage 1.7 features] --> scores[Stage 1.8 Isolation Forest scores] --> explanations[Stage 1.9 explanations] --> triage[Automated triage] --> package[Stage 2.0 package]",
        "  rules -. source observations only .-> explanations",
        "```",
        "",
        "## Workflow",
        "",
        "```mermaid",
        "flowchart LR",
        "  v3[Validated V3 artifacts] --> reconcile[Identity, row, rank and aggregate reconciliation]",
        "  reconcile --> exports[JSONL, CSV and tables]",
        "  reconcile --> charts[Ten reproducible charts] --> report[This report]",
        "  queue[Optional blinded review queue] -. optional human review .-> evaluation[Optional audited human evaluation]",
        "  evaluation -. separate validation evidence only .-> reconcile",
        "```",
        "",
        "## Rule Baseline",
        "",
        "Existing Stage 1.4 rule observations are preserved as reference context. They are not labels, training features, or confirmed attacks.",
        "",
        "## Feature Engineering",
        "",
        "Stage 1.7 supplies the frozen, audited feature artifact. Raw identifiers, timestamps, finding values, threat fields, and source-product decisions are excluded from the feature input.",
        "",
        "## Leakage Controls",
        "",
        "Reference and holdout partitions remain frozen. Stage 1.4 rule and source observations are explanation context only and never model features or attack labels.",
        "",
        "## Model",
        "",
        "Stage 1.8 uses the frozen Isolation Forest configuration recorded in the audited model metadata. This package does not retrain, rescore, or rerank the model output.",
        "",
        "## Anomaly Scoring",
        "",
        "Anomaly scores are relative abnormality scores on a 0–100 display scale, not attack probabilities. The frozen Stage 1.8 rank is deterministic and remains the authoritative anomaly order.",
        "",
        "## Explanation Method",
        "",
        "Stage 1.9 supplies evidence-based driver reasons and reference context. Reasons describe observed relationships to the audited reference population; they do not establish maliciousness or incident truth.",
        "",
        "## Suspected Behavior and Attack Boundaries",
        "",
        "Suspected behavior and attack-type fields are cautious investigation aids. They are not confirmed malicious behavior, confirmed attacks, or labels for supervised attack classification.",
        "",
        "## Automated Triage and Optional Human Evaluation Methodology",
        "",
        "Auto-triage prioritizes investigation only. The blinded-review queue is optional; no human labels were provided. PENDING rows are valid queue state, and absent human ground truth makes supervised attack-classification metrics unavailable.",
        "",
        "## Results/Metrics/Graphs",
        "",
        "All reported counts, percentages, tables, and chart aggregates are computed from the validated Stage 1.9 V3 inputs and reconciled final rows.",
        "",
        "## Results Tables",
        "",
        f"Machine-readable exports: [final JSONL]({package_link}/final_anomaly_findings.jsonl), [final CSV]({package_link}/final_anomaly_findings.csv), [summary]({package_link}/analysis_summary.json), and [all tables]({package_link}/tables/).",
        "",
    ]
    lines.extend(_markdown_distribution("Auto-Triage Distribution", summary["auto_triage_distribution"]))
    lines.extend(_markdown_distribution("Anomaly-Band Distribution", summary["anomaly_band_distribution"]))
    lines.extend(_markdown_distribution("Evidence-Strength Distribution", summary["evidence_strength_distribution"]))
    lines.extend(_markdown_distribution("Suspected-Behavior Distribution", summary["suspected_behavior_distribution"]))
    lines.extend(_markdown_distribution("Suspected-Attack Interpretation Distribution", summary["suspected_attack_interpretation_distribution"]))
    lines.extend(_markdown_distribution("Review-Status Distribution", summary["review_status_distribution"]))
    lines.extend([
        "## Visualizations",
        "",
        "The zero-count reconnaissance category is retained intentionally. Chart percentages use the stated record-group denominator; driver tags can overlap and therefore do not sum to 100%.",
        "",
    ])
    chart_captions = {
        "01_score_distribution.png": "Score distribution by partition; scores are relative abnormality, not probabilities.",
        "02_top20_scores.png": "Top-20 rank inspection; raw abnormality is annotated where rounded scores tie.",
        "03_anomaly_bands.png": "Frozen Stage 1.8 anomaly-band distribution.",
        "04_protocol_representation.png": "Source-assigned protocol shares for rank ≤ 1,000 versus remaining records.",
        "05_service_representation.png": "Source-assigned service shares for rank ≤ 1,000 versus remaining records.",
        "06_observed_anomaly_driver_frequency.png": "Complete suspected-behavior record shares for Top-50 and Top-1,000 records.",
        "07_auto_triage_distribution.png": "Automated investigation-priority distribution, not attack classification.",
        "08_evidence_strength.png": "Evidence-strength distribution, not attack probability.",
        "09_suspected_attack_interpretation.png": "Cautious source-supported interpretation distribution; not confirmed attacks.",
        "10_feature_comparison.png": "Stage 1.7 feature empirical CDFs for rank ≤ 100 versus remaining records; missing operands excluded.",
    }
    for item in summary["graph_manifest"]:
        name = item["name"]
        lines.extend([f"### {name}", "", f"![{name}]({package_link}/{item['relative_path']})", "", chart_captions[name], ""])
    lines.extend([
        "## Top-50 Investigation Results",
        "",
        f"The [ranked Top-50 table]({package_link}/tables/top_50_anomalies.csv) contains exactly 50 unique source records, all HIGH_INTEREST. Its rank, source identity, score, evidence, and explanation context are preserved for investigation; this selection does not establish confirmed attacks.",
        "",
        "## Four Case Studies",
        "",
    ])
    for case in cases:
        row = case["row"]
        reasons = row["top_reasons"]
        reason_text = "; ".join(str(reason.get("template_text")) for reason in reasons) if isinstance(reasons, list) else "No reasons available"
        lines.extend([
            f"### Case {case['case_number']} — {case['actual_category']}",
            "",
            f"Requested category: `{case['requested_category']}`. Fallback: `{case['fallback_reason'] or 'none'}`.",
            "",
            f"- Source: `{row['source_record_number']}` / `{row['source_record_id']}`; anomaly rank `{row['anomaly_rank']}`, investigation rank `{row['investigation_rank']}`",
            f"- Scores: anomaly `{row['anomaly_score']}`, investigation priority `{row['investigation_priority_score']}`; band `{row['anomaly_band']}`, triage `{row['auto_triage']}`",
            f"- Behaviors: `{', '.join(row['suspected_behaviors']) or 'none'}`; suspected attack interpretation: `{row['suspected_attack_type'] or 'none'}`; evidence strength: `{row['evidence_strength'] or 'none'}`",
            f"- Rule/source observations: rule IDs `{', '.join(row['rule_ids']) or 'none'}`; source threat type `{row['source_threat_type'] or 'none'}`",
            f"- Review: `{row['review_status']}`; analyst and contextual labels remain `{row['analyst_label']}` / `{row['contextual_label']}`",
            f"- Evidence: {reason_text}",
            "- Interpretation limit: this is an investigation example, not a confirmed incident or attack.",
            "",
        ])
    lines.extend([
        "## Optional Human Evaluation",
        "",
        "Human review is optional. No human labels were supplied, so supervised attack-classification metrics, reference agreement, precision, recall, F1, ROC-AUC, PR-AUC, and confusion matrices are unavailable and are not inferred.",
        "",
        "## Reproducibility",
        "",
        "The package accepts validated Stage 1.9 V3 artifacts only; superseded V2 artifacts are not inputs. Run each command from the repository root only after its predecessor exits with code 0.",
        "",
        "```powershell",
        "& .\\.venv\\Scripts\\python.exe -m pip check",
        "& .\\.venv\\Scripts\\python.exe -m unittest discover -s tests -p \"test_*.py\" -v",
        "& .\\.venv\\Scripts\\python.exe -m pytest tests -q",
        "$AuditedStage19Explanations = '.\\data\\processed\\stage_1_9_corrected_v3'",
        "$AuditedStage19AutoTriage = '.\\data\\processed\\stage_1_9_auto_triage_corrected_v3'",
        "& .\\.venv\\Scripts\\python.exe .\\src\\build_final_package.py --features-dir .\\data\\processed\\stage_1_7 --scores-dir .\\data\\processed\\stage_1_8 --explanations-dir $AuditedStage19Explanations --auto-triage-dir $AuditedStage19AutoTriage --output-dir .\\data\\processed\\stage_2_0",
        ".\\scripts\\validate_stage_2_0.ps1 -PackageDir .\\data\\processed\\stage_2_0 -Report .\\docs\\final_project_report.md",
        ".\\scripts\\validate_stage_1_6.ps1 -Database .\\data\\processed\\stage_1_5f_detection_store.sqlite3 -FindingsInput .\\data\\processed\\stage_1_4f_detection_findings.jsonl -SummaryInput .\\data\\processed\\stage_1_4f_detection_summary.json -ExpectedRunId 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc -Port 8000",
        "```",
        "",
        "## Local Demo",
        "",
        "Open this report and the ranked CSV, then trace a case through its preserved source identity and explanation context. The existing read-only API serves Stage 1.4 rule observations only; it does not serve AI outputs.",
        "",
        "```powershell",
        "& .\\.venv\\Scripts\\python.exe .\\src\\serve_api.py --database .\\data\\processed\\stage_1_5f_detection_store.sqlite3 --findings .\\data\\processed\\stage_1_4f_detection_findings.jsonl --summary .\\data\\processed\\stage_1_4f_detection_summary.json --expected-run-id 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc --port 8000",
        "```",
        "",
        "In a second local terminal:",
        "",
        "```powershell",
        "Invoke-RestMethod http://127.0.0.1:8000/healthz",
        "Invoke-RestMethod \"http://127.0.0.1:8000/api/v1/runs/5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc/findings?limit=5\"",
        "```",
        "",
        "Repository-supported Stage 1.6F evidence records a corrected loopback validation PASS for this exact store and approved Stage 1.4 artifacts: 43 findings across 25 source records, 227 evidence entries, and two rules. Rerun the command above for fresh local confirmation; it remains a read-only rule-observation API, not an AI-results API.",
        "",
        "## Limitations",
        "",
        "Timestamps and duration units are not reinterpreted. Sanitized network identifiers are opaque. No raw label data, confirmed attacks, or supervised evaluation is present.",
        "",
        "## Future Work",
        "",
        "Future work requires a separately approved, audited human-review workflow rather than automatically treating anomalies as attacks.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def build_final_package(features_dir: str | Path, scores_dir: str | Path, explanations_dir: str | Path, auto_triage_dir: str | Path, output_dir: str | Path, *, report_path: str | Path = "docs/final_project_report.md") -> dict[str, object]:
    features = Path(features_dir).resolve()
    scores = Path(scores_dir).resolve()
    explanations = Path(explanations_dir).resolve()
    auto = Path(auto_triage_dir).resolve()
    output = Path(output_dir).resolve()
    report = Path(report_path).resolve()
    if output.exists():
        raise ValueError("Stage 2.0 output destination already exists")
    explanation_path = explanations / "stage_1_9_explained_anomalies.jsonl"
    auto_path = auto / "stage_1_9_auto_triage.csv"
    auto_summary_path = auto / "stage_1_9_summary.json"
    top_path = auto / "stage_1_9_top_anomalies.csv"
    for path, label in ((explanation_path, "V3 explanation artifact"), (auto_path, "V3 auto-triage artifact"), (auto_summary_path, "V3 summary artifact"), (top_path, "V3 Top-50 artifact")):
        _require_file(path, label)
    upstream_summary = _load_json_object(auto_summary_path, "V3 summary artifact")
    if upstream_summary.get("explanation_artifact_identity", {}).get("sha256") != EXPECTED_V3["explanation"] or file_sha256(explanation_path) != EXPECTED_V3["explanation"]:
        raise ValueError("V3 explanation identity does not match approved hash")
    if upstream_summary.get("auto_triage_artifact_identity", {}).get("sha256") != EXPECTED_V3["auto_triage"] or file_sha256(auto_path) != EXPECTED_V3["auto_triage"]:
        raise ValueError("V3 auto-triage identity does not match approved hash")
    if file_sha256(auto_summary_path) != EXPECTED_V3["summary"] or file_sha256(top_path) != EXPECTED_V3["top_anomalies"]:
        raise ValueError("V3 summary or Top-anomalies identity does not match approved hash")
    feature_metadata = features / "stage_1_7_ai_feature_metadata.json"
    feature_path = features / "stage_1_7_ai_features.jsonl"
    score_path = scores / "stage_1_8_anomaly_scores.jsonl"
    score_manifest_path = scores / "stage_1_8_manifest.json"
    model_metadata_path = scores / "stage_1_8_model_metadata.json"
    for path, label in ((feature_metadata, "Stage 1.7 feature metadata"), (feature_path, "Stage 1.7 feature artifact"), (score_path, "Stage 1.8 score artifact"), (score_manifest_path, "Stage 1.8 manifest"), (model_metadata_path, "Stage 1.8 model metadata")):
        _require_file(path, label)
    if file_sha256(feature_metadata) != EXPECTED_STAGE_17_METADATA or file_sha256(feature_path) != EXPECTED_STAGE_17_FEATURE:
        raise ValueError("Stage 1.7 feature identities do not match approved hashes")
    if file_sha256(score_path) != EXPECTED_STAGE_18_SCORE:
        raise ValueError("Stage 1.8 score identity does not match approved hash")
    feature_metadata_value = _load_json_object(feature_metadata, "Stage 1.7 feature metadata")
    score_manifest = _load_json_object(score_manifest_path, "Stage 1.8 manifest")
    model_metadata = _load_json_object(model_metadata_path, "Stage 1.8 model metadata")
    feature_names = feature_metadata_value.get("feature_names")
    if not isinstance(feature_names, list) or not all(isinstance(name, str) for name in feature_names):
        raise ValueError("Stage 1.7 feature metadata has no valid ordered feature names")
    if score_manifest.get("stage_1_7_feature_sha256") != EXPECTED_STAGE_17_FEATURE or score_manifest.get("score_artifact_sha256") != EXPECTED_STAGE_18_SCORE:
        raise ValueError("Stage 1.8 manifest does not reconcile to approved Stage 1.7/1.8 identities")
    explanations_rows = read_jsonl(explanation_path)
    auto_rows = _load_auto_rows(auto_path)
    final_rows = [build_final_row(row, auto_rows[(int(row["source_record_number"]), str(row["source_record_id"]))]) for row in explanations_rows]
    final_rows.sort(key=lambda row: int(row["anomaly_rank"]))
    feature_rows = read_jsonl(feature_path)
    score_rows = read_jsonl(score_path)
    feature_count = len(feature_names)
    temporary = output.parent / f".stage_2_0_{uuid.uuid4().hex}"
    try:
        (temporary / "tables").mkdir(parents=True)
        (temporary / "graphs").mkdir()
        write_jsonl(temporary / "final_anomaly_findings.jsonl", final_rows)
        write_csv(temporary / "final_anomaly_findings.csv", final_rows)
        summary = aggregate_rows(final_rows, feature_count=feature_count)
        cases = select_case_studies(final_rows)
        _write_table(temporary / "tables" / "overall_summary.csv", ("metric", "value"), tuple((key, canonical_json(value) if isinstance(value, (dict, list)) else value) for key, value in summary.items() if key not in {"security_interpretation", "analyst_review_metrics"}))
        for name, values in (("auto_triage_distribution", summary["auto_triage_distribution"]), ("anomaly_band_distribution", summary["anomaly_band_distribution"]), ("suspected_behavior_distribution", summary["suspected_behavior_distribution"]), ("evidence_strength_distribution", summary["evidence_strength_distribution"]), ("suspected_attack_interpretation_distribution", summary["suspected_attack_interpretation_distribution"]), ("review_status_distribution", summary["review_status_distribution"])):
            _write_table(temporary / "tables" / f"{name}.csv", ("value", "count", "percentage"), tuple((item["value"] if item["value"] is not None else "NULL", item["count"], item["percentage"]) for item in values))
        top50 = [row for row in final_rows if int(row["anomaly_rank"]) <= 50]
        _write_table(temporary / "tables" / "top_50_anomalies.csv", ("anomaly_rank", "source_record_number", "source_record_id", "partition", "anomaly_score", "auto_triage", "investigation_priority_score", "suspected_behaviors", "suspected_attack_type", "evidence_strength", "top_reasons"), tuple((row["anomaly_rank"], row["source_record_number"], row["source_record_id"], row["partition"], row["anomaly_score"], row["auto_triage"], row["investigation_priority_score"], canonical_json(row["suspected_behaviors"]), row["suspected_attack_type"] or "", row["evidence_strength"] or "", canonical_json(row["top_reasons"])) for row in top50))
        (temporary / "tables" / "case_studies.json").write_text(canonical_json(cases) + "\n", encoding="utf-8", newline="\n")
        summary["upstream_identities"] = {"stage_1_9_explanation_sha256": EXPECTED_V3["explanation"], "stage_1_9_auto_triage_sha256": EXPECTED_V3["auto_triage"], "stage_1_9_summary_sha256": EXPECTED_V3["summary"], "stage_1_9_top_anomalies_sha256": EXPECTED_V3["top_anomalies"], "stage_1_7_feature_sha256": EXPECTED_STAGE_17_FEATURE, "stage_1_7_feature_metadata_sha256": EXPECTED_STAGE_17_METADATA, "stage_1_8_score_sha256": EXPECTED_STAGE_18_SCORE, "human_evaluation_identity": None}
        summary["final_jsonl_identity"] = {"path": "final_anomaly_findings.jsonl", "sha256": file_sha256(temporary / "final_anomaly_findings.jsonl"), "row_count": len(final_rows)}
        summary["final_csv_identity"] = {"path": "final_anomaly_findings.csv", "sha256": file_sha256(temporary / "final_anomaly_findings.csv"), "row_count": len(final_rows)}
        summary["rank_validation"] = rank_validation(final_rows)
        summary["model_diagnostics"] = {"model_kind": score_manifest.get("model_kind"), "model_config": score_manifest.get("model_config"), "primary_random_state": score_manifest.get("random_state"), "primary_reproducibility": model_metadata.get("determinism_result"), "partition_diagnostics": model_metadata.get("partition_diagnostics"), "seed_sensitivity": model_metadata.get("seed_sensitivity")}
        summary["reference_agreement"] = None
        summary["graph_manifest"] = write_all_graphs(final_rows, feature_rows, feature_names, temporary / "graphs", score_rows=score_rows, source_identities={"final_jsonl_sha256": summary["final_jsonl_identity"]["sha256"], "stage_1_8_score_sha256": EXPECTED_STAGE_18_SCORE, "stage_1_7_feature_sha256": EXPECTED_STAGE_17_FEATURE})
        summary["case_selection"] = cases
        summary["report_contract_version"] = "1.0"
        summary["package_validation"] = {"status": "PASS", "scope": "final rows, full CSV/JSONL reconciliation, rank permutations, summary, chart aggregates, cases, and required report references"}
        _write_table(temporary / "tables" / "overall_summary.csv", ("metric", "value"), tuple((key, canonical_json(value) if isinstance(value, (dict, list)) else value) for key, value in summary.items() if key not in {"security_interpretation", "analyst_review_metrics"}))
        (temporary / "analysis_summary.json").write_text(canonical_json(summary) + "\n", encoding="utf-8", newline="\n")
        audit = audit_package(temporary, feature_rows=feature_rows, feature_names=feature_names, score_rows=score_rows)
        temporary.rename(output)
        _write_report(report, output.name, summary, cases)
        return {"status": "PASS", "output_dir": str(output), "report": str(report), "audit": audit}
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Stage 2.0 final project package.")
    parser.add_argument("--features-dir", required=True)
    parser.add_argument("--scores-dir", required=True)
    parser.add_argument("--explanations-dir", required=True)
    parser.add_argument("--auto-triage-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        print(canonical_json(build_final_package(args.features_dir, args.scores_dir, args.explanations_dir, args.auto_triage_dir, args.output_dir)))
    except (KeyError, OSError, ValueError, PackageAuditError) as error:
        print(f"Stage 2.0 package build failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
