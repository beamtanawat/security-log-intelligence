# Stage 1.7 — AI Feature Engineering + Evaluation Foundation

Status: PLAN ONLY. Implementation and future results are NOT YET EXECUTED.

## 1. Objective

Produce deterministic record-level numeric features with controlled
port/service rarity and an explicit evaluation foundation. The user approved
a reduced feature set: exclude opaque endpoint and endpoint-pair frequencies.
Do not train the final Isolation Forest in this stage.

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

Read data/processed/stage_1_3f_normalized_events.jsonl through the existing
strict reader. Use its actual schema, not guessed CSV fields. No raw CSV read
is needed. Record the normalized artifact size/SHA-256 and schema. Metadata
must identify this exact input for all later source-record joins.

## 4. Scope

One normalized record is one observation. Build a numeric feature matrix and
reference statistics, preserving every record and its provenance. Separate
REFERENCE/HOLDOUT before fitting frequency maps. Session aggregation is
deferred out of this finish-line scope because lifecycle/time semantics are
unverified.

## 5. Non-Goals

No training, scoring, threshold tuning, attack labels, session aggregation,
endpoint rarity, explainability reports, database or API changes. No new
runtime dependency; standard library is sufficient here.

## 6. Methodology / Technical Decisions

### Split and evaluation population

Use canonical JSON bytes of ["stage-1.7-split-v1","session",identifier] when
session.identifier is nonempty, otherwise
["stage-1.7-split-v1","record",source_record_number]. Do not trim/case-fold opaque
tokens or conflate fallback records with session strings. Compute SHA-256,
interpret its first eight bytes as unsigned big-endian, and take modulo 10.
Buckets 0..7 are REFERENCE; 8..9 HOLDOUT. Preserve record-number order.

This targets an approximately 80/20 split, not an exact row count. Assert both
partitions are nonempty and no nonempty session ID crosses them. Require at
least 4,096 REFERENCE records for the locked Stage 1.8 real-data model.
This prevents leakage by repeated session ID only: it does not prove temporal,
host or semantic independence. HOLDOUT is for descriptive unseen-group
diagnostics, not an unbiased future attack-detection benchmark. Do not tune
features/model using holdout or analyst labels.

### Leakage matrix

| Source family | Classification | Locked use / exclusion rationale |
|---|---|---|
| net_proto | SAFE MODEL FEATURE | Numeric protocol one-hot; unknown valid protocol goes OTHER |
| src_port, dst_port | SAFE MODEL FEATURE | Presence, classes and reference rarity; never continuous port magnitude |
| net_sentbytes, net_recvbytes, net_sentpkts, net_rcvdpkts | SAFE MODEL FEATURE | Nonnegative log1p and guarded ratios |
| net_sessionduration | CONDITIONAL | Unit-neutral log1p only; no seconds, throughput or timeout claims |
| app_service | CONDITIONAL | Exact protocol/service rarity only; source-assigned service is not independently verified application identity |
| app_cat, app_name, app_id | CONDITIONAL | Excluded in v1 because sparse/enriched context; display only |
| src_ip, dst_ip and other opaque endpoints | CONDITIONAL | Provenance/context only; raw tokens and all endpoint frequencies excluded |
| net_sessionid | CONDITIONAL | Split-group key only; not a feature or verified session entity |
| itime, data_timestamp | CONDITIONAL | Excluded from X and ordering; preserve original context |
| event_action | CONDITIONAL | Display/review only; exclude lifecycle/source-decision proxy |
| event_subtype, event_type, event_severity | REFERENCE ONLY | Excluded from X, feature selection, fitting and tuning |
| threat_action, threat_severity, threat_type, threat_name, all other threat fields | REFERENCE ONLY | Excluded from X and tuning; not attack truth |
| Stage 1.4 findings/rule matches/source observations | REFERENCE ONLY | Later agreement/priority context only |
| data_sourcetype | SAFE MODEL FEATURE | Eligible metadata but excluded as constant in this dataset |
| loguid, source_record_number, raw identifiers | PROHIBITED / LEAKAGE | Join/provenance only, never numeric or encoded predictors |
| Analyst labels, AI scores/ranks, later explanations | PROHIBITED / LEAKAGE | Never fed into features/fitting/model selection |
| Any field not explicitly allowed above | PROHIBITED / LEAKAGE | Default deny as model input |

REFERENCE ONLY fields are explicitly prohibited in the model feature vector.
Physical presence in the normalized event does not grant model eligibility.
Port/service/missingness may still proxy source collection behavior: quantify
their association with source observations after scoring without calling this
independent confirmation.

### Fixed 36-feature order

Emit exactly these names in order (schema 1.0):

1. protocol_icmp
2. protocol_tcp
3. protocol_udp
4. protocol_other
5. src_port_present
6. dst_port_present
7. src_port_well_known
8. src_port_registered
9. src_port_dynamic
10. dst_port_well_known
11. dst_port_registered
12. dst_port_dynamic
13. src_port_rarity
14. dst_port_rarity
15. service_rarity
16. service_missing
17. log_sent_bytes
18. log_received_bytes
19. log_sent_packets
20. log_received_packets
21. log_duration
22. log_total_bytes
23. log_total_packets
24. sent_byte_share
25. sent_packet_share
26. log_sent_bytes_per_packet
27. log_received_bytes_per_packet
28. sent_bytes_missing
29. received_bytes_missing
30. sent_packets_missing
31. received_packets_missing
32. duration_missing
33. zero_total_bytes
34. zero_total_packets
35. zero_sent_packets
36. zero_received_packets

The authoritative dimension is **36**; any
dimension mismatch fails. Feature names/order are immutable within schema 1.0.

Use network.protocol_number, network.source.port, network.destination.port,
application.service_source, session.sent_bytes, session.received_bytes,
session.sent_packets, session.received_packets, session.duration_raw_value,
source.record_number and event.source_record_id according to the existing
normalized contract. These ports are nested under source/destination, as
verified in src/normalization/fortigate_mapping.py; the illustrative flat
example in normalized_event_schema.md is not the FortiGate adapter mapping.

Ports: well-known=0..1023, registered=1024..49151, dynamic=49152..65535.
Missing ports produce presence/class/rarity=0. ICMP absence is contextual,
not corruption. Reject invalid values; do not impute port zero for absence.

For each rarity dictionary, use exact typed [protocol_number,value] keys:
separate src-port, dst-port and service maps. For a present value,
rarity=1-c/N, where c is reference count for that pair and N the reference
count of present values of that family within that protocol. Unseen
pair/protocol gives rarity=1; missing gives 0 plus presence/missing indicator.
No smoothing, one-hot service expansion, endpoint encoding or hash buckets.

Metric nulls: substitute zero only in derived numeric computation, with its
individual missing flag=1. Validate nonnegative finite metrics, rejecting
malformed strings and booleans. The normalized duration is already a
nonnegative integer or null; consume that value without parsing raw strings
or inferring a time unit. Require integer-or-null ports and session counters.
Protocol must be a present integer in 0..255; 1/6/17 map to ICMP/TCP/UDP
and other valid numbers to OTHER. Invalid/null protocol stops this dataset run.
Service null/empty means missing; preserve other tokens exactly.

log features use natural log1p. Totals require both operands present; else
derived total=0 and retain operand missing flags. Shares require both operands
present and positive total; otherwise 0.5. Zero-total flags are 1 only when
both operands are present and sum is truly zero. Bytes-per-packet requires
both values present and packets>0, else 0. Zero-packet flags are 1 only for
observed zero, not missing. Observed bytes>0 with zero packets is retained
and distinguishable, not repaired. No scaling, clipping, winsorization,
automatic feature dropping or StandardScaler.

## 7. Data Contracts

feature row: schema_version="1.0"; source_record_number: positive int;
source_record_id: nonempty opaque string; partition: REFERENCE|HOLDOUT;
values: exactly 36 finite floats in manifest order. Join keys are unique;
source_record_number strictly increases. No source label fields in rows.

Metadata: schema_version; normalized_input={path,size_bytes,sha256,schema_version};
feature_artifact={path,size_bytes,sha256,row_count}; feature_names;
feature_definitions (source paths, transform, family, flags and exclusions);
split={namespace,hash_algorithm,bucket_rule,counts,distinct_group_counts};
rarity_maps (sorted typed key/count arrays and protocol denominators);
reference_distributions (sorted unique float value/count arrays per feature,
including all 36 dimensions); reference constant-feature list;
eligible_reference_distributions (same arrays excluding numeric values whose
required source operands are missing, plus eligible N per feature);
runtime={python_version}; evaluation_protocol_version="1.0".
Both distribution sets are required: full model-input distributions for audit,
eligible distributions for Stage 1.9 numeric explanations. Flags use all rows;
port/service rarity excludes missing values; numeric totals/shares/per-packet
exclude missing operands and invalid zero denominators; logs exclude their
missing operand. Zero flags describe observed zeros separately.
Only REFERENCE observations populate distributions/maps. Publish no hash of
the metadata inside itself. Later stages hash the completed metadata file.

## 8. Planned Modules / Files

Create src/ai_features/{__init__,models,transform,input,artifact}.py;
src/build_ai_features.py; src/audit_ai_features.py;
tests/test_ai_features.py; scripts/validate_stage_1_7.ps1;
docs/stage_1_7_feature_findings.md at implementation time only.
Keep reusable feature contract/transform logic separate from CLI orchestration.
No existing public API/schema changes.

## 9. Detailed Implementation Tasks

### Checkpoint 1.7A — Contract and source reconciliation

Reconcile normalized field paths/types and baseline counts; freeze the
36-name manifest, null semantics, split vectors, reference-map examples and
metadata schema. Record which facts are historical versus revalidated.
Gate: no unreviewed predictor or unsupported numeric/time assumption. STOP
for checkpoint review; no model or dependency work.

### Checkpoint 1.7B — Tested feature builder and auditor

Write meaningful failing synthetic tests first; implement pure transforms and
split logic, then strict streaming I/O and an independent contract auditor.
Pass one streams source to count reference rarity; pass two builds reference
feature distributions and all feature rows. Hold only counters/compact
numeric reference distributions, never the ~907 MB normalized payload.
The auditor independently recomputes split/selected transforms and checks
all rows, dimensions and counts. Unit fixtures cover all exact formulas.
Gate: synthetic and integration suites pass, safe publication demonstrated.

### Checkpoint 1.7C — Real-data validation

Run the separate validator below. Rebuild into an owned temporary sibling
directory and compare feature hashes, maps and reference distributions.
Audit all 100,000 rows, protocol/missing masks, source identities and group
separation. Report actual split counts, unseen rarity counts and constant
features. Never assert an exact 80,000/20,000 count. Gate: unchanged input
hash, no leakage, deterministic payloads and full regression PASS.

### Checkpoint 1.7D — Findings and handoff

Document measured counts, feature semantics and limits. Handoff exactly
stage_1_7_ai_features.jsonl and stage_1_7_ai_feature_metadata.json plus their
hashes to Stage 1.8. No model artifact exists yet. STOP for stage review.

## 10. Output Artifacts

Bundle data/processed/stage_1_7/ contains exactly:
stage_1_7_ai_features.jsonl and stage_1_7_ai_feature_metadata.json.
Optional validator diagnostics go to stdout; do not create extra permanent
data formats. Subsequent reruns require a new operator-selected directory.

## 11. Tests

Synthetic: exact hash split vectors; ambiguous group serialization; empty
session fallback; negative/nonfinite numbers; null versus observed zero;
all protocols and port boundaries; unseen values; partial session missingness;
ratio zero denominators; constant distributions; field exclusion allowlist.
Integration: malformed JSONL, late failure publishes nothing, duplicate IDs,
reordered rows, output collision/path alias, two identical builds, changed
HOLDOUT values cannot alter reference maps/distributions. Real data is not
part of ordinary tests; no internet/service/machine-specific path required.

## 12. Real-Data Validation

These are planned interfaces, available only after checkpoint B. Run from
the repository root using local PowerShell:

```powershell
& .\.venv\Scripts\python.exe --version
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest tests -q
& .\.venv\Scripts\python.exe .\src\build_ai_features.py --input .\data\processed\stage_1_3f_normalized_events.jsonl --output-dir .\data\processed\stage_1_7
& .\.venv\Scripts\python.exe .\src\audit_ai_features.py --bundle .\data\processed\stage_1_7 --normalized .\data\processed\stage_1_3f_normalized_events.jsonl
.\scripts\validate_stage_1_7.ps1 -NormalizedInput .\data\processed\stage_1_3f_normalized_events.jsonl -Bundle .\data\processed\stage_1_7
```

Validator audits the existing bundle, runs suites, creates/cleans its own
temporary rerun, compares deterministic content, verifies all input hashes,
and checks Git data safety. It does not overwrite the named bundle.
Every command must have exit code 0 before the next dependent command.

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
Missing source semantics or required runtime evidence prevents handoff.
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
models and generated artifacts out of Git. Mark Stage 1.7 COMPLETE only
after its actual validation gate passes. STOP for review before advancing;
this plan document is NOT implementation authorization for a later stage.
