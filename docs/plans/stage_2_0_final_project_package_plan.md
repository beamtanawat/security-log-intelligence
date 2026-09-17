# Stage 2.0 — Final Results + Visualizations + Report + Demo Package

Status: PLAN ONLY. Final package NOT YET EXECUTED.
This is the final FortiGate project stage. No Stage 2.1+ is introduced.

## 1. Objective

Finish the FortiGate project with traceable results, honest evaluation,
8–10 useful charts, four evidence-based case studies, a technical report and
a reproducible local demo. Consume the frozen Stage 1.7–1.9 artifacts without
training, changing or selecting a model.

## 2. Current State / Dependencies

Planning baseline verified on 2026-09-11: main at e1f92d4, with local
origin/main comparison 0 0 (no fresh fetch implied). Stage 1.6 is complete;
docs/stage_1_6_api_findings.md records 176 unittest passes, 176 pytest passes,
109 subtests and two known non-blocking warnings. These are historical local
execution results, not tests rerun during this planning mission.

Evidence sources: root AGENTS.md; plans/stage_1_6_read_only_api_plan.md (structural
reference); data_dictionary.md; stage_1_2_data_quality_findings.md;
normalized_event_schema.md; fortigate_normalization_mapping.md;
stage_1_3_normalization_findings.md; detection_contract.md;
initial_detection_rules.md; stage_1_4_detection_findings.md;
detection_storage_contract.md; stage_1_5_storage_findings.md;
read_only_api_contract.md; stage_1_6_api_findings.md; existing normalization,
detection reader, storage and API implementations. Document paths above are
under docs/ except root AGENTS.md. The user's final planning mission and
approved decisions authorize the remaining ML stages despite historical
Stage-1-only language in AGENTS.md.

Dataset baseline: sanitized structured FortiGate CSV, not original syslog;
100,000 rows, 58 columns, approximately 39.3 MiB; no exact duplicate rows;
100,000 distinct loguid values; 50,399 session IDs and 49,601 repeated
occurrences beyond first occurrences. Repeated ID does not establish a session
lifecycle. TCP=66,357, ICMP=27,447, UDP=6,196. Missing source/destination ports
align with 27,447 ICMP records. Five session metrics share a missing mask on
778 records. Stage 1.4 has 43 informational findings, 25 matched records,
two rules and 227 evidence entries; 18 anomaly-subtype records are within the
25 source-threat-observation records. These counts are reconciliation
expectations, never manufactured future AI outcomes.

No reliable attack ground truth exists. Sanitized endpoints are opaque
identifiers; do not infer literal IP/MAC, topology or geography. Preserve raw
timestamp values and existing tentative derived-time interpretation. Do not
assume file order is chronological or duration is measured in seconds.

### Environment context

The user's LOCAL VS Code PowerShell project .venv is validated, using Python
3.12.10; Stage 1.3 processed the real dataset and passed 68 tests, and Stage 1.6
subsequently passed the documented regression and real-store/API checks.
Some Codex execution contexts cannot access that local Windows runtime.
This is an EXECUTION-CONTEXT LIMITATION, not evidence of project dependency
failure. No stage is globally BLOCKED BY ENVIRONMENT.

1. Do NOT reinstall Python merely because Codex cannot access it.
2. Do NOT rebuild .venv merely because Codex cannot access it.
3. Do NOT modify PATH to work around Codex sandbox isolation.
4. If accessible, use the validated project environment and run the checkpoint.
5. If inaccessible, perform only pre-runtime work permitted by the checkpoint;
   do not fabricate results; STOP at AWAITING LOCAL VALIDATION with the exact
   commands in this plan. Do not advance to a dependent checkpoint.
6. Local results from the validated VS Code PowerShell environment are
   authoritative execution evidence. Associate results with code revision,
   input hashes and commands; reconcile failures instead of overriding them.
7. Use BLOCKED BY ENVIRONMENT only when a checkpoint truly cannot safely
   proceed, recording its specific cause and remaining permitted work.

## 3. Inputs

Require completed, corrected, and audited Stage 1.9 explanation and
auto-triage bundles, plus Stage 1.7/1.8 metadata/feature/score identities.
The Stage 1.9 auto-triage summary is the authoritative automated aggregate
handoff; its bound row-level CSV supplies auto_triage and the no-human-review
status for every record. Reconcile its Top-50 table, row counts, source-record
joins and hashes before packaging. Human review is optional. If a completed
human evaluation summary is separately supplied, audit its lineage and copy
its accepted labels/review statuses without changing auto_triage. Otherwise
keep human labels null, queue members PENDING and other rows NOT_SELECTED.
The builder never opens or reinterprets a raw frozen label CSV.
Existing SQLite and API remain the validated rule-finding demonstration.

## 4. Scope

Lossless analysis-result JSONL, spreadsheet CSV, summary JSON, graph images,
four case studies, portfolio-ready Markdown report and existing API/CLI demo.

## 5. Non-Goals

No new model, model tuning, altered taxonomy/priority, new API endpoints,
database schema, static frontend, PDF, cloud or production deployment.
No required work after Stage 2.0. A future-work paragraph may discuss general
limitations, but creates no new stage or completion dependency.

## 6. Methodology / Technical Decisions

### Primary result table and exports

Write 100,000 rows ordered by anomaly_rank, preserving both anomaly_rank and
investigation_rank so the priority queue can be sorted without ambiguity.
Do not call all 100k records suspicious findings merely because the export
filename contains "findings". Include the exact Stage 1.8 score disclaimer.
An explanation row provides descriptive context only; it does not by itself
make a record suspicious, an alert, a suspected attack or a Top-50 selection.

JSONL is lossless for the final analysis contract, not a copy of all original
58 source columns; source provenance links back to immutable normalized data.
CSV serves spreadsheet browsing, and summary JSON serves machine-readable
counts/evaluation. This functional difference justifies both row formats.

Exact JSONL columns/types:
schema_version:str="1.0"; anomaly_rank:int; investigation_rank:int;
source_record_number:int; source_record_id:str;
partition:REFERENCE|HOLDOUT; anomaly_score:float[0,100];
investigation_priority_score:float[0,100]; anomaly_band:str;
auto_triage:HIGH_INTEREST|MEDIUM_INTEREST|LOW_INTEREST;
analyst_review_selected:bool; suspected_behaviors:list[str];
suspected_attack_type:str|null; evidence_strength:LOW|MEDIUM|HIGH|null;
explanation_status:COMPLETE|LIMITED; top_reasons:list[reason];
rule_observation_present:bool; rule_ids:list[str];
source_threat_observation_present:bool;
anomaly_subtype_observation_present:bool; source_threat_type:str|null;
display_context:object; review_id:str|null;
analyst_label:SUSPICIOUS|NOT_SUSPICIOUS|UNCERTAIN|null;
contextual_label:same nullable enum;
review_status:NOT_SELECTED|PENDING|REVIEWED_RESOLVED|REVIEWED_UNCERTAIN.

Fields are copied from audited upstream artifacts, never recomputed
differently. The auto-triage CSV supplies the per-record triage value and
no-human-review status; its summary supplies automated aggregate tables.
suspected_behaviors is the complete ordered Stage 1.9 projection and is never
reconstructed from bounded top_reasons. suspected_attack_type remains null for
non-Top-50 rows and is not rendered as "No Attack"; a presentation may show
the neutral text "Not assigned" while machine-readable artifacts preserve
null. Without an optional audited human evaluation, analyst_label and
contextual_label are null, queue rows remain PENDING, and non-queue rows remain
NOT_SELECTED. If real human evaluation is supplied, analyst_label means its
accepted blind_label; contextual_label is copied separately; review_status is
copied from that evaluation's per-record projection. Stage 2.0 never infers a
label or status from scores, rules, source threat fields or auto_triage.
PENDING does not block closure. Explainable anomaly and auto_triage are not
attack verdicts; LOW_INTEREST does not mean benign or safe.

CSV uses the same scalar columns in listed order, expands display_context
into the exact Stage 1.9 operational columns, encodes lists/reasons as compact
JSON cells, booleans as true/false and null as empty cell. UTF-8 with BOM for
Windows spreadsheet usability; RFC4180 quoting; LF. Prefix an apostrophe in
text cells beginning =,+,-,@, tab, CR or LF; prefix existing leading apostrophe
too, document removal of exactly one escape prefix for round-trip. Numeric
typed fields are serialized as numbers, not evaluated formulas. JSONL remains
unescaped and canonical; audit CSV values after decoding display escaping.
No labels/rationale are silently inferred for unreviewed records.

### Graph specification

Use Matplotlib only after reviewed Python-3.12-compatible dependency pinning;
headless Agg backend, fixed figure size 10x6 inches, 150 DPI, fixed palette,
sorted categories and seed. No graph collection during the planning mission.
All charts use validated final JSONL/summary, except chart 10 also reads the
hashed Stage 1.7 feature artifact. Denominators/caveats appear in captions.
Render zero/empty groups as zero or "no observations", not fabricated values.

| # / PNG name | Purpose / input | X-axis | Y-axis / encoding | Gate and valid interpretation |
|---|---|---|---|---|
| 01_score_distribution | Summary of scores; final JSONL | Score bins 0..100, width 5 | Row count, separate reference/holdout series | Required; relative abnormality, not probabilities |
| 02_top20_scores | Ranked inspection; final JSONL | Anomaly rank 1..20 with record numbers | Anomaly score | Required; ties visible, not attack severity |
| 03_anomaly_bands | Distribution; final JSONL | Four locked bands | Count and share labels | Required; percentile cutoffs do not guarantee exact band sizes |
| 04_protocol_representation | Context; final JSONL | ICMP/TCP/UDP/OTHER | Share in rank<=1000 versus rank>1000 | Required; exact Top-1%-by-rank selection, not the percentile band |
| 05_service_representation | Context; final JSONL | Ten most frequent services in rank<=1000 plus Other/Missing | Selected versus remaining share | Required; ties lexical, source-assigned services |
| 06_observed_anomaly_driver_frequency | Honest driver-frequency summary; complete suspected_behaviors from final JSONL, never top_reasons | Five canonical driver families plus UNCLASSIFIED_ANOMALOUS_PATTERN when present | Count and share of each tag in Top50 and Top1000 | Required; one record may contribute to multiple qualifying-family counts; fallback counts only Top-50 rows with no qualifying family; descriptive frequency, not Model Feature Importance |
| 07_auto_triage_distribution | Automated priority; audited Stage 1.9 auto-triage summary | HIGH/MEDIUM/LOW_INTEREST | Record count and share | Required; priority is not maliciousness or benignness |
| 08_evidence_strength | Explanation evidence richness; audited auto-triage summary | HIGH/MEDIUM/LOW/null | Record count and share | Required; strength is not attack probability |
| 09_suspected_attack_interpretation | Cautious interpretation; audited auto-triage summary | Two approved phrases and null | Record count and share | Required; interpretations are not confirmed attacks |
| 10_feature_comparison | Explain volume distributions; features and final JSONL | log_total_bytes, log_duration (two panels) | Empirical cumulative proportion for rank<=100 and remainder | Required; exclude missing operands, display counts/zero mass; no time-unit claim |

Exactly ten required charts use audited automated results and need no human
labels. An optional human-reviewed comparison may be described separately
when real review evidence exists, but no required chart or project closure
depends on it. Never invent values or fill an invalid plot. No ROC/PR curves.
Chart data definitions are frozen; independent aggregation audit checks each
count/denominator. Use band names only for actual Stage 1.8 band groups;
rank-based Top1% selection is explicitly labelled as such.

### Metrics panel

DATASET / SYSTEM COUNTS: records, feature count=36, actual partition counts,
Top50 selection size, auto-triage counts, and NOT_SELECTED/PENDING review counts.
MODEL DIAGNOSTICS: seed/config, primary reproducibility result, distinct scores,
ties, partition quantiles and secondary-seed overlap.
AUTOMATED ASSESSMENT: audited Stage 1.9 triage/band/evidence/behavior/attack
interpretation distributions, score/priority quantiles and explanation
coverage. No attack-detection accuracy or confidence.
OPTIONAL ANALYST REVIEW: only if a real audited human evaluation is supplied,
show its reviewed-sample metrics with denominators, uncertainty/null reasons,
P@10/20/50 and descriptive correlated reference agreement. With no human
ground truth, supervised metrics remain null with reason
NO_HUMAN_GROUND_TRUTH and are never inferred from model outputs.

### Four case studies

Select unique records in sequence, sorting each candidate set by anomaly_rank:

1. Top50 with reference union present.
2. Top50 without reference union.
3. Reference present outside Top50 (AI/reference disagreement).
4. MEDIUM_INTEREST outside Top50 with a specific suspected behavior.

If a category is empty, select the next unused Top50 record with a different
dominant driver family; then next unused anomaly rank. Clearly label fallback
and state that the desired category was absent. Never fabricate a disagreement
or human label. Four cases are the default, within the requested 3–5 range.

Each case: source record number/ID, both ranks, scores, band, reasons/raw
operands, suspected behaviors, exact nullable attack fallback/category, nullable
evidence strength, auto_triage, rule/source observations, optional genuine
blind/contextual review, interpretation, limitations and source identity. No
hardcoded record IDs before actual results.

### Architecture and demo

Final report shows two branches after normalization:
normalized events -> existing rules -> SQLite -> read-only API;
normalized events -> features -> Isolation Forest -> scores -> explanations
-> auto-triage -> final outputs/report. Optional human review/evaluation is a
separate validation branch after the blinded queue.
Rule/source observations feed explanation context/evaluation, never X.
The API is NOT a pipeline step that supplies all 100k rows to feature building.
Embed a Mermaid representation in the report during implementation; no new
diagram file in this planning mission.

Report sections: Problem; Dataset; Data Limitations; Architecture; Rule
Baseline; Feature Engineering; Leakage Controls; Model; Anomaly Scoring;
Explanation Method; Suspected Behavior/Attack Boundaries; Automated Triage
and Optional Human Evaluation Methodology; Results/Metrics/Graphs; Four Case
Studies; Limitations;
Reproducibility; Local Demo; conceptual Future Work.
Use docs/final_project_report.md; existing README gains a short link/demo
entry only during Stage 2.0 implementation. Link local ignored package graphs;
README/report must explain how to regenerate missing local artifacts.
No upload/publication is authorized. Portfolio-ready means reproducible local
presentation, not publicly hosting the dataset.

Demo sequence: open report and ranked CSV; trace one actual case to normalized
source; explain its features/score/reference caveats; show audited auto-triage;
launch the existing loopback API for rule observations. Do not claim API serves
AI results. Use existing documented launcher arguments and input identities.

## 7. Data Contracts

Final row schema is specified above. Its Stage 1.9 join copies auto_triage
and no-human-review status from the audited auto-triage CSV, and top_reasons,
complete ordered suspected_behaviors, nullable suspected_attack_type, nullable
evidence_strength, rule observation context and source threat observation
context from the explanation artifact. Without optional human evaluation,
analyst_label and contextual_label remain null. With a separately supplied,
audited human evaluation summary, copy blind_label as analyst_label,
contextual_label and review_status from its authoritative per-record projection
while preserving auto_triage. Stage 1.8 remains authoritative for anomaly
score/rank, partition and band identity; Stage 1.9 supplies its bound identity
rather than duplicating the Stage 1.8 artifact. No label, status, behavior or
attack-type field is inferred during final packaging.

analysis_summary.json schema 1.0 holds:
upstream_identities (including audited Stage 1.9 auto-triage identities and
optional human evaluation identity); final_jsonl_identity;
final_csv_identity; record_count; feature_count; partition_counts;
auto_triage_counts/distribution; anomaly_band_counts/distribution;
evidence_strength_counts/distribution; suspected_behavior_counts/distribution;
suspected_attack_interpretation_counts/distribution; score_quantiles;
priority_score_quantiles; explanation_coverage; review_counts;
model_diagnostics; analyst_review_metrics (null with
reason=NO_HUMAN_GROUND_TRUTH when no human evaluation exists, otherwise copied
with reviewed-sample scope/null/bounds); reference_agreement (null when no
human evaluation exists, otherwise copied as descriptive overlap);
graph_manifest (name,status,reason,source identities,counts,relative path);
case_selection (record keys,requested category,actual category,fallback reason);
report_contract_version="1.0"; security_interpretation; package_validation.
No self-hash. Model/feature metadata and explanation/auto-triage files remain
upstream references; do not duplicate model binaries, raw label files or
metadata in the package. When optional human evaluation is supplied, its
lineage records the frozen label identity; the Stage 2.0 builder verifies that
identity without opening or reinterpreting the raw label CSV.

## 8. Planned Modules / Files

Create src/reporting/{__init__,export,graphs,cases,audit}.py;
src/build_final_package.py; tests/test_final_package.py;
scripts/validate_stage_2_0.ps1; docs/final_project_report.md.
Modify README.md only for final report/demo navigation and requirements.txt
only for reviewed Matplotlib dependency. These are future implementation files;
this targeted correction changes this Stage 2.0 plan as part of the approved
Stage 1.9 handoff correction, but creates no Stage 2.0 implementation file.

## 9. Detailed Implementation Tasks

### Checkpoint 2.0A — Final contract and package review

Reconcile all upstream contracts/hashes and the audited auto-triage bundle. Freeze
column order/escaping, graph aggregations, four-case selection and report
template; review minimal plotting dependency. An optional human evaluation is
audited only if supplied. Gate: no fabricated labels or metrics and no new
ML/architecture task; PENDING queue rows are valid. STOP for checkpoint review.

### Checkpoint 2.0B — Tested exporter, charts and cases

Test joins, schema/CSV round-trip, independent aggregation and fallback case
selection before implementation. Build the three exports and chart bundle.
Use synthetic fixtures for the required graphs and optional review evidence,
then inspect rendered labels, legends, count captions and missing-value behavior. Gate: all tests
pass; no invented metric or evidence.

### Checkpoint 2.0C — Final real-data validation

Build actual package, independently reconcile 100k rows and both rank
permutations, verify unchanged source artifacts and the audited auto-triage
lineage. Verify human-label lineage only if a real evaluation is supplied.
Audit every graph aggregation and all four cases. Run full regression and
the existing Stage 1.6 real loopback validator, cleaning only its owned process.
Gate: real artifacts/reproducibility/input integrity/demo validation PASS.
No arbitrary anomaly-rate/metric threshold is a pass requirement.

### Checkpoint 2.0D — Report, demo and project closure

Write report from audited outputs only, embed workflow/graphs/cases and exact
local reproduction commands; verify all relative links and render the report
for legibility. Add minimal README navigation. Perform the demo and record
evidence/limits, including unavailable optional human metrics. Close the FortiGate
project at Stage 2.0; no follow-on stage or extra feature is required.

## 10. Output Artifacts

New data/processed/stage_2_0/ bundle:
final_anomaly_findings.jsonl; final_anomaly_findings.csv;
analysis_summary.json; graphs/ containing 8–10 specified PNG files.
Report is docs/final_project_report.md, with README navigation.
No extra duplicate report PDF/HTML, model copy or data export format.
Canonical row hashes must repeat in a pinned environment; graph raster bytes
are not a cross-platform determinism gate.

## 11. Tests

Synthetic: exact schema/types/nulls; rank versus source ordering; omitted or
duplicate join records; CSV formulas/quoting/newlines/Unicode and round-trip;
exact copying of auto_triage and NOT_SELECTED/PENDING from the audited
auto-triage bundle; no required human evaluation; no fabricated labels or
supervised metrics. When optional human evaluation is supplied, test
blind/contextual label separation, exact copying of its four review_status
values and rejection of independent status/label reinterpretation. Preserve
non-Top-50 nullable attack types.
Integration: input tampering, graph counts/denominators independent of renderer,
zero/empty groups, optional human metrics unavailable, case category absence/uniqueness,
report relative links and refusal to overwrite existing package. Chart 06
fixtures must exercise all five canonical behavior families, multi-family rows,
canonical ordering, duplicate rejection and no under-count from top_reasons;
UNCLASSIFIED_ANOMALOUS_PATTERN is counted only for a Top-50 row with no
qualifying family and never for a baseline/non-Top-50 row.
Rendering: all titles/axes/legends/caveats readable, no misleading percent
labels; inspect all produced charts. Ordinary suite uses no real data, network
or persistent service. Real API validation is a separate explicit command.

## 12. Real-Data Validation

Planned commands after checkpoint B; local repository PowerShell:

```powershell
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest tests -q
$AuditedStage19Explanations = '.\data\processed\stage_1_9_corrected_v3'
$AuditedStage19AutoTriage = '.\data\processed\stage_1_9_auto_triage_corrected_v3'
& .\.venv\Scripts\python.exe .\src\build_final_package.py --features-dir .\data\processed\stage_1_7 --scores-dir .\data\processed\stage_1_8 --explanations-dir $AuditedStage19Explanations --auto-triage-dir $AuditedStage19AutoTriage --output-dir .\data\processed\stage_2_0
.\scripts\validate_stage_2_0.ps1 -PackageDir .\data\processed\stage_2_0 -Report .\docs\final_project_report.md
.\scripts\validate_stage_1_6.ps1 -Database .\data\processed\stage_1_5f_detection_store.sqlite3 -FindingsInput .\data\processed\stage_1_4f_detection_findings.jsonl -SummaryInput .\data\processed\stage_1_4f_detection_summary.json -ExpectedRunId 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc -Port 8000
```

Builder generates package data/graphs only; report is authored from its audited
content in checkpoint D. Run final validator after the report exists; it
resolves upstream identities from package metadata, reruns required audits,
checks full regression, JSONL/CSV reconciliation, charts/cases/report links,
and verifies immutable inputs. Checkpoint C may invoke it without -Report
for package-only validation; that mode cannot close Stage 2.0.
The Stage 1.9 directory values above are intended fresh corrected outputs;
use them only after their independent audits and official Stage 1.9 validator
pass. Never substitute the superseded pre-correction `stage_1_9` or
`stage_1_9_auto_triage` bundles. An optional separately audited human
evaluation may be supplied through --evaluation-dir; it is not part of the
standard command or closure gate.

Local demo launcher, after validators pass:

```powershell
& .\.venv\Scripts\python.exe .\src\serve_api.py --database .\data\processed\stage_1_5f_detection_store.sqlite3 --findings .\data\processed\stage_1_4f_detection_findings.jsonl --summary .\data\processed\stage_1_4f_detection_summary.json --expected-run-id 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc --port 8000
```

In a second local terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/healthz
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/runs/5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc/findings?limit=5"
```

Stop only the owned launcher after demonstration. Occupied port fails closed;
do not terminate unrelated processes or silently choose another port.
Each dependent validation command requires prior exit code 0.

## 13. Determinism / Reproducibility

Freeze schema version 1.0, ordered feature manifest, algorithm/configuration,
input SHA-256 and package versions. Canonical JSON uses UTF-8, sorted object
keys, compact separators, allow_nan=False and LF; arrays retain contract order.
Reject duplicate JSON keys, duplicate provenance keys, nonfinite values and
unsupported versions. Operational timestamps/runtime measurements belong in
validation summaries, not deterministic payload identity. Metadata identifies
upstream and output artifacts, but does not hash itself; downstream records
its file hash. No circular hashes.

Reruns use different new output directories. Compare deterministic payload
hashes in the same pinned environment. Do not require byte-identical pickle
files, PNGs or environment-specific paths across operating systems. Report
cross-environment differences honestly. Preserve all rows; never deduplicate
or silently filter unusual records.

## 14. Security / Data Integrity Constraints

- RULE MATCH != CONFIRMED ATTACK
- ANOMALY != ATTACK
- SOURCE THREAT OBSERVATION != GROUND-TRUTH ATTACK LABEL
- ANOMALY SCORE != ATTACK PROBABILITY

Reuse strict normalized input validation through src/detection/input.py where
needed; keep the existing normalized, rule, SQLite and HTTP contracts unchanged.
The API remains a rule-finding API, not a source of all normalized records or
AI scores. No raw-syslog parser, new rule, new source, LLM, RAG, deep learning,
autoencoder, GNN, transformer, OCSF, cloud deployment, Docker, Kubernetes,
queue, full SIEM, authentication system or large frontend.

Raw/source artifacts are immutable. Resolve paths and reject input/output
aliases and escaping symlinks/reparse points. Outputs must be below the
existing data/processed directory for generated data/graphs, excluded from Git;
the explicitly planned report and README documentation are the only output
location exceptions. Reject existing generated-output
destinations. Assemble each stage bundle in an owned sibling temporary
directory, audit it, then publish by same-volume no-replace directory rename.
If no-replace publication is unavailable, fail closed. Never replace an
existing run directory; clean up only owned temporary paths. Human-review
input files are never silently regenerated or overwritten. Do not log full
events. Do not stage, commit or push without a separate explicit user request.

## 15. Failure / Stop Conditions

STOP for upstream validation absence, changed input hash, incompatible
contract, prohibited feature, unsupported required semantics, invalid numeric
data, non-deterministic canonical payloads, insufficient input population,
unexpected existing destination, or regression failure. Report the failing
gate, evidence and exact remediation scope. Unsupported attack interpretations
inside Top 50 use the documented fallback; outside Top 50
suspected_attack_type remains null and no suspicious fallback is assigned. Do
not force a specific attack category.
PENDING queue reviews do not block closure. Without accepted human ground
truth, supervised metrics remain null with NO_HUMAN_GROUND_TRUTH; no review
labels or attack metrics may be synthesized. If optional human review is
supplied, properly documented undefined reviewed-sample metrics caused by
UNCERTAIN labels do not alone block a complete, honest package.
No dependency installation occurs during planning. At implementation time,
review the minimal dependency set, Python 3.12 compatibility and exact resolved
versions before installation. If this requires a scope change, stop for that
decision. Never silently substitute a different model or environment.

## 16. Acceptance Criteria

All four stage checkpoints pass with actual evidence: versioned contracts and
scope reviewed; synthetic/integration tests pass; separate real-data validation
reconciles every input/output record; upstream hashes are unchanged; required
artifacts are independently audited; limitations and measured results are
documented. No made-up target test count, attack rate, overlap, score,
performance or runtime. Predicted deliverables are expectations until measured.

## 17. Completion Gate

Report changed files, commands/exit codes, exact test counts, input/output
identities, measured counts, limitations and remaining approvals.
Run git diff --check and inspect the complete diff/status. Keep real data,
models and generated artifacts out of Git. Mark Stage 2.0 COMPLETE only
after its actual validation gate passes. STOP for final project review;
there is no later FortiGate stage.

### Final project Definition of Done

- Established 100k pipeline preserved and all final records traceable.
- One reproducible Isolation Forest, ranked anomaly scores and clearly
  distinguished investigation priority.
- Evidence-based reasons and defensible interpretation/fallback.
- Audited automatic triage for all records, with optional genuine human
  review and valid scoped metrics only where accepted reviews support them.
- Ranked table, 8–10 graphs including honest driver visualization, four cases,
  machine-readable exports, workflow, final report and working local demo.
- Full regression and real-data validation PASS; upstream artifacts immutable.
- No invented performance, unsupported attack claims or hidden pending work.
- FortiGate project COMPLETE at Stage 2.0. STOP; no Stage 2.1+.
