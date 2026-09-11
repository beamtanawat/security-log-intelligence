# Stage 1.9 — Explainability + Suspected Behavior/Attack Analysis + Evaluation

Status: PLAN ONLY. Explanations, human review and metrics NOT YET EXECUTED.

## 1. Objective

Explain observed feature deviations, produce evidence-bounded investigation
context, and evaluate the fixed Top-50 review selection against 100 actual
human reviews. Distinguish blind human judgments from later informed
interpretation and from source observations.

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

Require Stage 1.8 completion. Read data/processed/stage_1_7/ feature bundle and
data/processed/stage_1_8/ score/metadata bundle, validating upstream hashes.
Stream data/processed/stage_1_3f_normalized_events.jsonl for provenance and
operational context. Read stage_1_4f_detection_findings.jsonl and
stage_1_4f_detection_summary.json through the existing detection/storage
validation contract. Bind every join to the exact normalized input identity,
source_record_number and source_record_id. Do not load the ML binary.
Human labels become an additional explicit input only after queue publication.

## 4. Scope

Lightweight feature-based explanations, cautious taxonomy, separate priority
heuristic, deterministic 100-row review sample, actual blind review,
reviewed-sample metrics and full-population reference agreement.

## 5. Non-Goals

No model retraining/tuning, SHAP, causal attribution, new security rule,
session/time-window attack detector, production alerting or final graph/report
package. Model score, ranks and feature contract are immutable.

## 6. Methodology / Technical Decisions

### Explanation algorithm and its limits

Use only Stage 1.7 eligible reference distributions and numeric model inputs for
drivers; source threat/rule fields enter a separate reference_context object.
These are descriptive feature deviations, not proof of why the forest made
a prediction. No ordinary supervised feature importance is available.

For a continuous feature value x, compute midrank
Fmid=(count(ref<x)+0.5*count(ref=x))/N.
Two-sided extremeness E=2*abs(Fmid-0.5).
For rarity features use E=max(0,2*Fmid-1), so common values never become
"rare" because of a lower-tail deviation.
For categorical/flag observations use E=1-count(reference_value)/N.
Constant reference features observed at their constant value have E=0;
a differing value has E=1 for two-sided numeric/categorical features.
For one-sided rarity, only a value above the constant has E=1; below has E=0.
An empty eligible reference distribution provides no numeric driver.
This prevents constant/tied modes being
misrepresented as maximally abnormal.

Group manifest features into VOLUME (17..20,22..23), DIRECTION (24..25),
SESSION_CHARACTERISTICS (21,26..36), PORT_SERVICE (5..16) and
PROTOCOL (1..4). For one-hot groups evaluate only the active category using
its reference category frequency, never absent categories as separate drivers.
Collapse redundant one-hot flags into one observed-category
reason. Do not count four protocol flags or correlated totals as independent
evidence. Eligibility uses source missingness: imputed metric/ratio values
cannot generate numeric-value deviations when inputs are missing. Missing
flags can yield a clearly named source-completeness reason.

Choose the highest-E eligible feature per family, tie-breaking by manifest
position, then the three highest families, with family order above for ties.
Emit up to three reasons. If fewer informative families (E>0) exist, report
the actual number and explanation_status=LIMITED; never pad with invented
reasons. Each reason stores family, feature_name, observed_value, source_paths,
raw_observed_values, reference_n, less/equal counts, extremeness and template
text. Templates: numeric "{feature}: observed {raw}; {higher/lower} relative
to {reference_n} eligible reference records; descriptive extremeness {E}";
rarity "{category}: observed in {count}/{denominator} reference records of
this protocol"; missingness "{field}: absent in this record; reference
absence frequency {count}/{N}". For observed presence or another binary flag,
use "{field}: observed {value}; reference frequency {count}/{N}", rather than
the absence template. Active categorical reasons use that same template with
the decoded category. Do not describe a missing value as source zero.
For derived ratios include all source operands/flags. Display at six
decimals but use full precision for selection.

A behavior tag requires E>=0.95 from an eligible non-missing driver in the
corresponding family; this is an explanation threshold, not a security
threshold. Missingness alone is not suspicious session behavior and cannot
establish attack evidence. The fixed canonical family/tag order is:
UNUSUAL_TRAFFIC_VOLUME, UNUSUAL_TRAFFIC_DIRECTION,
UNUSUAL_SESSION_CHARACTERISTICS, RARE_PORT_OR_SERVICE_CONTEXT,
UNUSUAL_PROTOCOL_CONTEXT. suspected_behaviors is the complete structured
projection: include every qualifying tag exactly once in this order. It is
separate from top_reasons, which is an intentionally bounded human-readable
summary of at most three reasons and need not contain every qualifying family.

When no family qualifies, a non-Top-50 record has suspected_behaviors=[]. A
Top-50 record may instead contain the sole fallback tag
UNCLASSIFIED_ANOMALOUS_PATTERN. This fallback is never assigned outside the
explicit Top-50 investigation/review population. Report low rather than high
tails accurately; absence/zero is not exfiltration. An explanation row may
exist for any of the 100,000 records; explanation availability does not make a
record suspicious, an alert, a suspected attack or a Top-50 selection.

### Reference context, taxonomy and priority

Preserve separate flags for:
fortigate.anomaly_subtype_observation;
fortigate.source_threat_observation;
source threat observations using the existing Stage 1.4 predicate.
Validate rule summary/counts instead of redefining "threat observation"
as any nonempty threat string. Keep matched rule IDs sorted and distinct.

suspected_attack_type is nullable and is assigned only inside the explicit
Top-50 investigation/review population. For a Top-50 record it is exactly
"Possible reconnaissance activity" only when source-record threat_type is the
documented Reconnaissance observation and an eligible non-missing
protocol/port/service family has E>=0.95. Wording explicitly attributes the
source observation and says no scan sequence is established. Co-occurrence is
not independent confirmation: source-assigned port/service can share source
processing. Every other Top-50 record uses exactly "Unclassified suspicious
behavior". Every non-Top-50 record uses suspected_attack_type=null, including
records with qualifying descriptive behavior tags; it receives no attack or
suspicion label.
Do not infer brute force, malware, C2, exfiltration, DDoS, port scanning,
compromise or incident status from rarity/bytes alone.

reference_observation_present = any matched Stage 1.4 rule OR existing
source-threat predicate. investigation_priority_score =
round(min(100,0.90*anomaly_score+10*int(reference_observation_present)),6).
Use the persisted six-decimal anomaly_score in this formula. This approved
90/10 weighting is a fixed uncalibrated investigation-order heuristic,
not measured risk, attack probability, severity or confidence.
Do not double-count source threat plus its corresponding rule.
investigation_rank sorts by priority score descending, anomaly_rank ascending.
Top-50 model selection and evaluation remain based on anomaly_rank, never
investigation_rank; priority performance is not evaluated by Precision@K here.

Evidence strength applies to Top-50 records only; every non-Top-50 record uses
null. Evaluate exactly once in this precedence order: HIGH when at least two
distinct eligible non-missing E>=0.95 families and a reference observation are
present; otherwise MEDIUM when at least one such family exists and either at
least two such families or a reference observation is present; otherwise LOW
when at least one such family exists; otherwise null. A record receives only
the first matching value in HIGH -> MEDIUM -> LOW -> null order.
explanation_status remains based solely on the number of informative reasons,
not the 0.95 threshold.
Missingness alone never qualifies. Strength denotes evidence richness only;
it is neither model confidence nor attack probability. HIGH does not imply
independence, security confidence or an attack.
Analyst labels never change drivers, ranks, score, priority or strength.

### Review set and blinding

Exactly 100 unique rows: all Top 50 plus 50 comparison records. For each
comparison band [99,100], [95,99), [50,95), [5,50), [0,5), excluding Top 50,
select 10 by SHA-256 of canonical
["stage-1.9-sample-v1",source_record_number]. Compare unrounded percentiles
recomputed from Stage 1.8 reference distribution, not displayed scores.
If a band lacks ten rows, take all available, then fill shortfall from all
remaining non-Top-50 rows in the same hash order. Record actual stratum counts;
ties cannot prevent obtaining 100 rows when N>=100.

Assign review_id="R-"+full SHA-256 of
["stage-1.9-review-v1",normalized_sha256,source_record_number].
Shuffle presentation using hash ["stage-1.9-order-v1",review_id].
This is deterministic pseudonymization for blinding, not anonymization.

First-pass queue column order is: review_id, protocol_number, protocol_name,
source_port, destination_port, service_source, source_identifier,
destination_identifier, sent_bytes, received_bytes, sent_packets,
received_packets, duration_raw_value, source_port_missing,
destination_port_missing, service_missing, sent_bytes_missing,
received_bytes_missing, sent_packets_missing, received_packets_missing,
duration_missing. Ports/identifiers map from network.source and
network.destination, service from application.service_source, metrics from
session. Display_context uses these names/types, excluding review_id.
No score, rank, selection/band,
driver, source record number, source log ID, event subtype/type/severity/action,
rule or threat fields. The reviewer must not consult unblinded artifacts
during this pass; blinding is a workflow control, not an access-control claim.

Blind label input fields: review_id; blind_label; blind_rationale;
reviewer_alias; reviewed_at (ISO8601 offset timestamp).
SUSPICIOUS = operational context warrants further security investigation,
without claiming an attack.
NOT_SUSPICIOUS = reviewer finds no reason to escalate from shown context,
without proving benignness.
UNCERTAIN = evidence insufficient/conflicting.
Require all 100 reviews, nonempty rationale/alias, unique expected IDs.

Freeze and hash the completed blind-label file BEFORE revealing source
observations. Later optional contextual adjudication has separate fields
contextual_label and contextual_rationale in a different supplied review
version supplied through optional --contextual-labels. That CSV has review_id,
contextual_label, contextual_rationale, reviewer_alias, reviewed_at; require
the same expected ID set and a completed prior blind evaluation identity
supplied through --prior-evaluation-dir. These two optional arguments must
occur together; absent both, contextual labels stay null. An informed rerun
requires a new output directory and retains the prior blind-label hash.
Never overwrite the blind snapshot or use informed labels as primary
evaluation truth. Record both versions/identities if supplied. A sole reviewer
is acceptable; report reviewer count and lack of inter-rater evidence.
Codex must never manufacture human labels. Missing reviews STOP at
AWAITING ANALYST REVIEW.

The Stage 1.9 evaluation summary is the sole Stage 2.0 authority for primary
review status. For every source record, derive review_status deterministically
from review expectation and the accepted blind label only:

- no review_id -> NOT_SELECTED;
- an expected/selected review_id without an accepted blind label -> PENDING;
- accepted blind label UNCERTAIN -> REVIEWED_UNCERTAIN;
- accepted blind label SUSPICIOUS or NOT_SUSPICIOUS -> REVIEWED_RESOLVED.

These are the only review_status values. A contextual/unblinded label is
preserved separately when supplied but never determines primary review_status.
Stage 2.0 copies this normalized status and associated review data; it does not
reopen or independently reinterpret the frozen raw label CSV.

### Evaluation, denominators and uncertainty

Positive AI decision = anomaly_rank<=50; negative = selected comparison.
Human positive = blind SUSPICIOUS, human negative = blind NOT_SUSPICIOUS.
UNCERTAIN is excluded from resolved matrix and its denominators; show its
counts by AI decision, resolved count and coverage explicitly.

TP=selected+suspicious; FP=selected+not_suspicious;
FN=comparison+suspicious; TN=comparison+not_suspicious.
Title: "AI Review Selection vs Analyst-Reviewed Suspicion (Reviewed Sample Only)".
Precision=TP/(TP+FP); Recall=TP/(TP+FN);
F1=2TP/(2TP+FP+FN). Zero denominator -> null with reason, never zero by default.
These are unweighted descriptive metrics of an intentionally enriched reviewed
sample containing both reference and holdout records. Recall/F1 do not
estimate dataset-wide attack recall or unseen-group generalization.

Report uncertainty bounds by enumerating a=0..Upositive and b=0..Unegative:
TP'=TP+a; FP'=FP+Upositive-a; FN'=FN+b; TN'=TN+Unegative-b.
Compute metric min/max across defined assignments; if any assignment is
undefined, retain an undefined_possible flag. Do not call these statistical
confidence intervals.

For each K in 10,20,50: P@K denominator is K, with S suspicious and U uncertain
in the complete reviewed prefix. If U=0 report S/K; else point estimate=null,
bounds=[S/K,(S+U)/K], coverage=(K-U)/K. No unreviewed rows in these prefixes.
No ROC/PR curves, attack accuracy or source-label-based model evaluation.

Agreement over all 100k rows: separate 2x2 overlap tables for Top-50 selection
versus each rule flag, source threat predicate and their union. Include actual
numerators/denominators and Jaccard (null for empty union). Enrichment =
observation share in Top 50 / observation share in population, null if the
population share is zero. These correlated references are not ground truth.

## 7. Data Contracts

Explanation row extends Stage 1.8 score row with:
investigation_priority_score:float[0,100]; investigation_rank:int;
suspected_behaviors:list[str] in the fixed complete canonical order;
suspected_attack_type:str|null;
evidence_strength:LOW|MEDIUM|HIGH|null;
explanation_status:COMPLETE|LIMITED; top_reasons:list[reason] length<=3;
reference_context={rule_ids:list[str],rule_observation_present:bool,
source_threat_observation_present:bool,anomaly_subtype_observation_present:bool,
source_threat_type:str|null}; review_id:str|null;
display_context (the exact operational queue fields above).
COMPLETE means three informative families; otherwise LIMITED.
Write explanation rows in source-record order; ranks provide sorted views.
No blind labels enter this immutable pre-review artifact.

Review queue CSV uses the exact first-pass columns above. Quote per CSV;
escape spreadsheet formula-leading text on export and document reversible
presentation escaping; canonical source tokens remain exact in JSONL.
Use the exact Stage 2.0 CSV escaping/encoding contract for this queue too.
Pre-review metadata schema 1.0 contains upstream_identities (feature metadata,
features, model metadata, scores, normalized, findings and summary), row_count,
explanation_artifact_identity, queue_identity, selection_protocol_version,
reason_registry_version and actual stratum counts. This small manifest makes
the review bundle verifiable before human labels exist; no self-hash.
Evaluation JSON schema 1.0 records all upstream hashes, queue identity,
frozen blind-label identity, optional contextual-label identity, selection
protocol/stratum counts, review_mapping (review_id to provenance), resolved
matrix, metrics/denominators/null reasons/bounds/coverage, reference agreement
and interpretation caveats. Its record_review_results contains exactly one row
per source_record_number in source-record order with review_id:str|null,
analyst_review_selected:bool, review_membership:TOP_50|COMPARISON|NOT_SELECTED,
blind_label:SUSPICIOUS|NOT_SUSPICIOUS|UNCERTAIN|null, contextual_label using the
same nullable enum, and
review_status:NOT_SELECTED|PENDING|REVIEWED_RESOLVED|REVIEWED_UNCERTAIN.
The blind and contextual labels remain distinct. This per-record projection is
the sole reviewed-status source for Stage 2.0 and lets that stage copy review
state without opening the raw frozen label file. The evaluation lineage retains
the frozen label identity so Stage 2.0 can verify it without reinterpreting it.

## 8. Planned Modules / Files

Create src/explainability/{__init__,drivers,interpretation}.py and
src/evaluation/{__init__,review,metrics}.py; src/explain_anomalies.py;
src/evaluate_analyst_review.py; tests/test_explainability.py;
tests/test_analyst_evaluation.py; scripts/validate_stage_1_9.ps1;
docs/stage_1_9_evaluation_findings.md during implementation only.
Reuse existing artifact readers; do not alter the Stage 1.8 model.

## 9. Detailed Implementation Tasks

### Checkpoint 1.9A — Contracts and protocol

Freeze reason registry/templates, family map, taxonomy gates, priority
formula, blind queue columns, label definitions and metric formulas.
Gate: worked tie/constant, missingness and confusion-matrix examples agree.
STOP for checkpoint review.

### Checkpoint 1.9B — Tested explanations and review queue

Test formulas and safety boundaries first; implement streaming provenance
joins, family drivers, taxonomy and priority, deterministic review sampling,
and blinded CSV publication. Gate: synthetic/integration tests pass and no
source-only field reaches the driver computation or blind queue.

### Checkpoint 1.9C — Real explanations, human review and metrics

Produce all 100k explanations and the 100-row queue; audit references against
43 findings/25 records/18 subtype observations. Request actual human review,
STOP at AWAITING ANALYST REVIEW, freeze its input hash, then compute metrics.
Optional reveal/adjudication follows the freeze; primary labels stay blind.
Verify uncertainty/null handling and independent metric recomputation.
Gate: 100 actual reviews (UNCERTAIN allowed), legitimate primary matrix/
metrics or explicit undefined reasons, full regression and input integrity.

### Checkpoint 1.9D — Findings and handoff

Document reviewer protocol adherence, limitations, actual metric denominators,
tie/sample fallback and all taxonomy/score caveats. Handoff explanations,
the authoritative per-record evaluation summary and its exact queue/label
lineage to Stage 2.0.
Do not create final graphs/report. STOP for stage review.

## 10. Output Artifacts

Pre-review bundle data/processed/stage_1_9/:
stage_1_9_explained_anomalies.jsonl, stage_1_9_analyst_review_queue.csv and
stage_1_9_explanation_metadata.json.

Human creates data/processed/stage_1_9_analyst_review_labels.csv matching queue.
Evaluator publishes separate new bundle data/processed/stage_1_9_evaluation/
containing stage_1_9_evaluation_summary.json. Two publication steps are
intentional: labels arrive after the immutable queue. Never republish/replace
the pre-review bundle to add labels.

## 11. Tests

Synthetic: constant/tied distributions, tail direction, rare flags, missing
operands, family duplicates, fewer than three reasons, taxonomy fallback,
missing-only evidence, correlated source references and union priority.
Lock these interpretation boundaries explicitly: non-Top-50/no qualifying
family -> suspected_behaviors=[] and suspected_attack_type=null;
non-Top-50/qualifying descriptive families -> all ordered tags but attack type
still null; Top-50 reconnaissance gate -> "Possible reconnaissance activity";
other Top-50 with a qualifying family -> "Unclassified suspicious behavior";
Top-50/no qualifying family -> UNCLASSIFIED_ANOMALOUS_PATTERN fallback and
"Unclassified suspicious behavior". A multi-family row must emit every
qualifying family exactly once in canonical order. Evidence-strength fixtures
must prove HIGH wins when HIGH/MEDIUM/LOW overlap, MEDIUM wins when MEDIUM/LOW
overlap without HIGH, LOW is used when only LOW qualifies, and null is used
when no strength rule qualifies.
Metrics: hand-worked TP/FP/FN/TN, zero denominators, all uncertain, bounds,
uncertain prefix P@K, exact 100 IDs, duplicate/invented reviewer entries.
Integration: unblinded fields absent from queue, deterministic shuffle,
stratum shortfall, labels do not alter AI fields, frozen-hash mismatch,
mismatched normalized identity, exact per-record review-status mapping,
contextual labels never changing primary status, and late output failure.
Ordinary tests are synthetic/offline and independent of real human labels.

## 12. Real-Data Validation

Planned commands, after checkpoint B, from local repository PowerShell:

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest tests -q
& .\.venv\Scripts\python.exe .\src\explain_anomalies.py --features-dir .\data\processed\stage_1_7 --scores-dir .\data\processed\stage_1_8 --normalized .\data\processed\stage_1_3f_normalized_events.jsonl --findings .\data\processed\stage_1_4f_detection_findings.jsonl --summary .\data\processed\stage_1_4f_detection_summary.json --output-dir .\data\processed\stage_1_9
```

STOP for actual blind review. After the user supplies the completed labels:

```powershell
& .\.venv\Scripts\python.exe .\src\evaluate_analyst_review.py --explanations-dir .\data\processed\stage_1_9 --labels .\data\processed\stage_1_9_analyst_review_labels.csv --output-dir .\data\processed\stage_1_9_evaluation
.\scripts\validate_stage_1_9.ps1 -FeaturesDir .\data\processed\stage_1_7 -ScoresDir .\data\processed\stage_1_8 -ExplanationsDir .\data\processed\stage_1_9 -Labels .\data\processed\stage_1_9_analyst_review_labels.csv -EvaluationDir .\data\processed\stage_1_9_evaluation
```

Validator resolves immutable normalized/reference paths from upstream identity,
verifies queue/label identity, independently recomputes joins, sampling,
drivers and metrics, runs full suites, and checks inputs unchanged. Reruns use
owned temporary outputs. Each dependent command requires exit code 0.

## 13. Determinism / Reproducibility

Freeze schema version 1.0, ordered feature manifest, algorithm/configuration,
input SHA-256 and package versions. Canonical JSON uses UTF-8, sorted object
keys, compact separators, allow_nan=False and LF; arrays retain contract order.
Reject duplicate JSON keys, duplicate provenance keys, nonfinite values and
unsupported versions. suspected_behaviors arrays retain the fixed canonical
family order and contain no duplicate tag. Operational timestamps/runtime measurements belong in
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
inside Top 50 use the documented fallback; outside Top 50
suspected_attack_type remains null and no suspicious fallback is assigned. Do
not force a specific attack category.
Absent human labels: AWAITING ANALYST REVIEW. All-uncertain labels are legitimate completed review, but matrix/point metrics remain unavailable; never force labels to manufacture charts.
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
models and generated artifacts out of Git. Mark Stage 1.9 COMPLETE only
after its actual validation gate passes. STOP for review before advancing;
this plan document is NOT implementation authorization for a later stage.
