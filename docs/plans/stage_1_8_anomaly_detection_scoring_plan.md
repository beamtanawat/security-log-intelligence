# Stage 1.8 — Isolation Forest + Anomaly Detection + Scoring

Status: PLAN ONLY. Model training and results are NOT YET EXECUTED.

## 1. Objective

Train one reproducible Isolation Forest and score/rank every validated feature
row. Separate model abnormality, percentile display, review bands and human
review budget. Explanations, priority heuristics and analyst evaluation belong
to Stage 1.9; graphs and portfolio packaging belong to Stage 2.0.

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

Require completed Stage 1.7 and read its bundle:
data/processed/stage_1_7/stage_1_7_ai_features.jsonl and
stage_1_7_ai_feature_metadata.json. Verify metadata, exact 36-feature order,
schema 1.0, recorded normalized identity and feature SHA-256. No direct raw
CSV, source threat/rule label or analyst-label input to fitting.

## 4. Scope

One numeric observation per source record; fit REFERENCE only and score both
partitions. Emit versioned model, score artifact and metadata, with a separate
real-data reproducibility gate.

## 5. Non-Goals

No model zoo, supervised model, tuning on holdout/labels, SHAP, priority score,
attack verdict, production alert threshold or HTTP/database changes.

## 6. Methodology / Technical Decisions

### Dependencies and model

Propose scikit-learn and direct-use NumPy/joblib, with their minimal transitive
dependencies. Review compatibility/resolution on Python 3.12 before installing;
pin actual tested versions in requirements.txt and record numpy/scipy/sklearn/
joblib/threadpoolctl versions. Do not invent version pins in this plan.
No pandas or plotting dependencies here.

Use IsolationForest(n_estimators=200, max_samples=4096,
contamination="auto", max_features=1.0, bootstrap=False, n_jobs=1,
random_state=1729, warm_start=False). Fit only reference rows, ordered by
source_record_number, as a finite contiguous float32 matrix. All transforms
are already frozen by Stage 1.7. Fail if the real reference population has
fewer than 4,096 rows; do not silently change max_samples. Unit tests may
exercise pure scoring helpers with small synthetic score arrays; an actual
primary-model integration fixture needs at least 4,096 reference rows.

200 trees and 4,096 samples/tree are fixed engineering choices for a bounded
100k-row workload, not an empirically optimal configuration. No quality claim
follows from these values. contamination="auto" supplies only sklearn's
internal offset; do not use predict/decision_function threshold as an alert.
n_jobs=1 and fixed ordering improve reproducibility in the pinned environment.

### Score contract

For each row:
model_score = model.score_samples(X); lower means more abnormal.
raw_abnormality = -model_score; higher means more abnormal.

Let R be the sorted reference raw_abnormality values from this same trained
model. anomaly_score_unrounded = 100 * bisect_right(R, raw_abnormality)/len(R).
Persist anomaly_score rounded to six decimal places using Python round.
Use unrounded percentile for band assignment. Persist model_score and
raw_abnormality as finite unrounded JSON floats.

Mandatory display sentence:
"Anomaly Score is relative abnormality within the validated Stage 1.7
reference population; a higher value is more unusual. It is not an attack
probability, confidence, severity, or proof of malicious activity."

This inclusive empirical CDF intentionally gives tied values equal scores.
A reference maximum, even a tied maximum, maps to 100. Percentile bands do
NOT guarantee an exact percentage of records. If all reference raw scores are
equal, fail with DEGENERATE_SCORE_REFERENCE rather than present all 100s as
a useful anomaly model. Report tie counts and distinct scores.

Ranks are unique 1..N, ordered by descending unrounded raw_abnormality then
ascending source_record_number. Rounded scores never determine ties/order.
Band thresholds on the unrounded reference percentile:
TOP_0_1_PERCENT >=99.9; else TOP_1_PERCENT >=99;
else TOP_5_PERCENT >=95; else BASELINE.
Names denote reference-percentile cutoffs, not observed bucket sizes.
analyst_review_selected = anomaly_rank <= 50. This is a fixed review budget
(0.05% for the current dataset), not an operational alert/attack decision.
Do not derive it from contamination, source observations or human labels.

Fit/reference diagnostics describe in-sample behavior. HOLDOUT diagnostics
describe unseen session-ID groups within the same dataset only. Report both
separately (counts, score quantiles, ties, bands); pooled results are descriptive.
No claim of chronological/general deployment performance.

### Persistence and reproducibility

Persist trusted local model only via joblib. Before loading, validate path,
approved manifest hash and package-version equality; hashes provide integrity
relative to a trusted manifest, not authenticity of arbitrary downloads.
Do not deserialize a model supplied by an untrusted source.

Primary seed=1729. Repeat it in the same pinned environment and require
identical canonical score payload hash. Also run seeds 2718 and 3141 solely
for sensitivity diagnostics: report top-50/top-100 Jaccard overlap with
the primary run. Never select the best seed using references/labels; only
the primary model is a delivered model. Secondary artifacts are temporary.
Low overlap is a documented limitation, not an instruction to tune until
results look good. Unexpected primary nondeterminism blocks completion.

Technical references:
[IsolationForest API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html),
[model persistence](https://scikit-learn.org/stable/model_persistence.html),
[data leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).
Confirm installed-version behavior against these contracts during dependency
review; no network access is required by the tests.

## 7. Data Contracts

Each score row, schema_version="1.0":
source_record_number:int; source_record_id:str; partition:REFERENCE|HOLDOUT;
model_score:float; raw_abnormality:float; anomaly_score:float [0,100];
anomaly_rank:int; anomaly_band:one of four locked strings;
analyst_review_selected:bool. Write rows in source-record order for streaming
joins; anomaly_rank is the ranking view. Exactly one row per input feature.

Model metadata: schema_version; model_kind="IsolationForest";
model_config; feature_metadata_identity; feature_artifact_identity;
normalized_input_identity; feature_names; matrix_dtype="float32";
reference_count; holdout_count; score_semantics_version="1.0";
reference_raw_score_distribution (sorted value/count arrays);
score_artifact_identity; model_artifact_identity; dependency_versions;
partition_diagnostics; determinism_result; seed_sensitivity (Jaccard values).
Identities contain relative path, size_bytes and SHA-256.
Model metadata has no self-hash; Stage 1.9 hashes it on consumption.

## 8. Planned Modules / Files

Create src/anomaly/{__init__,models,input,scoring,artifact}.py;
src/score_anomalies.py; src/audit_anomaly_scores.py;
tests/test_anomaly.py; scripts/validate_stage_1_8.ps1;
docs/stage_1_8_anomaly_findings.md.
Only implementation checkpoint A may propose reviewed dependency changes.
Public normalized/detection/storage/API interfaces remain unchanged.

## 9. Detailed Implementation Tasks

### Checkpoint 1.8A — Contract and dependency review

Audit Stage 1.7 artifacts, freeze score examples including ties/rounded
boundaries, review/pin compatible dependencies, capture feature identity and
matrix dimensions. Gate: Stage 1.7 passed, config/versions reviewed and no
source-only data in X. STOP for checkpoint review.

### Checkpoint 1.8B — Tested scorer, persistence and audit

Test pure percentile/ranking/band functions first. Implement matrix assembly,
reference-only fit, score serialization and trusted-local persistence.
Independent auditor recomputes percentile/rank/bands from persisted raw
scores and reference partition and validates full provenance. Integration
tests verify trusted-model reload gives identical primary scores.
Gate: meaningful synthetic/integration tests pass; no final report generated.

### Checkpoint 1.8C — Real scoring and reproducibility

Score 100k records, rerun primary seed in an owned temporary directory, compare
canonical scores, run secondary-seed diagnostics, verify upstream hashes and
all counts/ranks. Audit reference and holdout separately and record actual
time/memory observations without promising a benchmark target.
Gate: primary deterministic, finite nondegenerate scores, all rows reconciled,
full regression passes and feature/input artifacts unchanged.

### Checkpoint 1.8D — Documentation and handoff

Record measured distributions and limitations. Handoff score JSONL and model
metadata, plus Stage 1.7 feature bundle identity, to Stage 1.9. Retain model
for reproducibility; Stage 1.9 does not need to deserialize it. STOP for review.

## 10. Output Artifacts

New bundle data/processed/stage_1_8/:
stage_1_8_isolation_forest.joblib;
stage_1_8_anomaly_scores.jsonl;
stage_1_8_model_metadata.json.
Keep transient reruns/secondary models out of the delivered bundle.

## 11. Tests

Synthetic: score direction; tied extrema; degenerate reference; percentile
thresholds immediately below/at cutoffs; rounded threshold mismatch; unique
ranks; all negative model scores; NaN/Infinity rejection; exact feature order.
Integration: no holdout fitting; tampered hash/manifest; version mismatch;
record omission/duplication; model load trust boundary; wrong matrix dimension;
successful reload/repeat; existing destination and failed publication.
Ordinary tests use synthetic fixtures only, no internet or real data.

## 12. Real-Data Validation

Planned interfaces, executable only after checkpoint B; local PowerShell from
repository root:

```powershell
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest tests -q
& .\.venv\Scripts\python.exe .\src\score_anomalies.py --features-dir .\data\processed\stage_1_7 --output-dir .\data\processed\stage_1_8
& .\.venv\Scripts\python.exe .\src\audit_anomaly_scores.py --features-dir .\data\processed\stage_1_7 --scores-dir .\data\processed\stage_1_8
.\scripts\validate_stage_1_8.ps1 -FeaturesDir .\data\processed\stage_1_7 -ScoresDir .\data\processed\stage_1_8
```

Validator performs full suites, immutable input hashes, score audit, primary
temporary rerun and seed sensitivity checks; it never replaces the bundle.
The scorer produces reproducibility metadata before final bundle publication.
All dependent commands require prior exit code 0.

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
existing data/processed directory, excluded from Git; reject existing output
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
use the documented fallback; do not force a specific attack category.
No source-overlap or metric target is a quality gate; actual nondeterminism, degenerate reference scoring or nonfinite output is.
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
models and generated artifacts out of Git. Mark Stage 1.8 COMPLETE only
after its actual validation gate passes. STOP for review before advancing;
this plan document is NOT implementation authorization for a later stage.
