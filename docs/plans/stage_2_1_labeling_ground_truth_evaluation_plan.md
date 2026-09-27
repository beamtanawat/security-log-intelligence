# Stage 2.1 — Labeling, Ground Truth Proxy & Evaluation Design

## 1. Plan Metadata

**PLAN STATUS:** APPROVED — TWO-BRANCH BENCHMARK ARCHITECTURE RE-APPROVED

**Prior human approval:** Plan version 1.0 was explicitly approved by the human
on 2026-09-25

**Split-allocation amendment approval:** Explicitly re-approved by the human on
2026-09-26

**Focused amendment review:** Threshold preservation, label-blindness,
whole-group isolation, determinism/bounded search, and infeasibility handling
all passed; no new methodology issue was found

**Human Input Contract Amendment approval:** Explicitly re-approved by the
human on 2026-09-26 after focused review; no new blocking issue was found

**AI Proxy Labeling Amendment approval:** Explicitly re-approved by the human
on 2026-09-26

**Focused AI Proxy amendment review:** AI provenance, evidence blinding, TEST
seal safety, supervised eligibility, claim language, and active-path
consistency all passed; no new blocking issue was found

**Precision-First Proxy Labeling Amendment approval:** Explicitly re-approved
by the human on 2026-09-27 after focused review; attack precision, benign
precision, UNCERTAIN policy, feature leakage controls, sufficiency/claim
language, and active-path consistency all passed; no new blocking issue was
found; all prior approvals remain preserved

**Two-Branch Benchmark Architecture Amendment approval:** Explicitly
re-approved by the human on 2026-09-27 after focused architecture review;
dataset separation, benchmark TEST independence, stage/model ownership,
evaluation/claim language, required model evaluation, and active architecture
consistency all passed with no surviving contradiction; all prior approval and
amendment history remains preserved

**Plan type:** Detailed Stage 2.1 implementation plan; plan authoring only

**Repository:** `security-log-intelligence`

**Repository root:** `/Users/tanawat/Projects/security-log-intelligence`

**Planning baseline:** `b81816f0cd02bff8c1c2f08f839ffc7cafc35cf5`

**Baseline message:** `Complete Stage 2.0 final project package`

**Document date:** 2026-09-27

**Plan version:** `2.0-two-branch-benchmark-architecture-amendment`

**Split amendment ID:** `S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2`

**Human input amendment ID:**
`S2.1-AMEND-2026-09-26-HUMAN-INPUT-CONTRACTS-V1`

**AI proxy amendment ID:** `S2.1-AMEND-2026-09-26-AI-PROXY-LABELING-V1`

**Precision-first amendment ID:**
`S2.1-AMEND-2026-09-27-PRECISION-FIRST-PROXY-V1`

**Current amendment ID:**
`S2.1-AMEND-2026-09-27-TWO-BRANCH-BENCHMARK-V1`

**Authoritative master:** `docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md`

**Master plan SHA-256:**
`5d388f62e1d1c2a22de2e4388aee80da427c975b42ed87f2bea7c6112f0719ba`

**Frozen normalized input SHA-256:**
`c195c6322665530d56f1bd5390b6b1c20728881a21ee36352c7c46e0a7138976`

Version 1.0 and every re-approved split, human-input, AI-proxy, and
precision-first amendment remain preserved as approval history. The completed
precision-first work is now a closed FortiGate label-feasibility study, not an
active supervised-label publication path. The current re-approved amendment
adopts the two-branch architecture: FortiGate remains the real-log
unsupervised case study, while UNSW-NB15 becomes the separate labeled benchmark
for supervised and chained ML. It changes no implementation file and performs
no dataset acquisition.

## 2. Relationship to Amended Master Pipeline

The two-branch master amendment is authoritative. This detailed amendment owns
only Stage 2.1 closure and contract work: preserve the measured FortiGate
label-feasibility result, retire every FortiGate proxy-labeling method from
active execution, and define the acquisition, schema, feature, split, TEST,
duplicate/leakage, and handoff requirements for the separate UNSW-NB15
benchmark branch. It does not train models or transfer FortiGate label rules to
UNSW-NB15.

The shared invariants remain raw-data immutability, dataset-specific
provenance, strict branch separation, TRAIN/fold-local learned state, locked
TEST evaluation, deterministic manifests, no-overwrite publication, and
evidence-bounded claims. Where retained Sections 3–55 conflict with Section
2A, they are historical FortiGate label-feasibility records and Section 2A
controls.

## 2A. Active Stage 2.1 Two-Branch Contract

### FortiGate label-feasibility closure

The completed precision-first dry-run result is frozen exactly as:

| FortiGate cohort | ATTACK | BENIGN | UNCERTAIN |
|---|---:|---:|---:|
| TRAIN | 18 | 0 | 67,984 |
| VALIDATION | 0 | 12 | 15,988 |

```text
CANONICAL FORTIGATE SUPERVISED LABELS: NOT PUBLISHED
FORTIGATE SUPERVISED STATUS: CLOSED / INSUFFICIENT
```

The Stage 2.1 conclusion is: **FortiGate labels were insufficient for
defensible supervised classification, so the project does not fabricate
additional ground truth.** The counts are feasibility evidence only. They are
not prevalence, supervised training data, TEST metrics, or released labels.

The following are preserved but classified only as
`HISTORICAL / LABEL-FEASIBILITY STUDY`:

- human-review and external-evidence labeling designs;
- AI-assisted proxy labeling;
- detector/deterministic proxy labeling;
- precision-first proxy labeling and its exact rules;
- FortiGate label sampling/sufficiency/TEST-seal contracts; and
- FortiGate proxy-supervised and FortiGate chained progression branches.

No historical path may resume, publish canonical FortiGate labels, trigger
more label sampling, lower evidence thresholds, train S1/S2, or authorize
FortiGate chained ML under this amendment. Their immutable history and approval
records remain in this document.

### Active Stage 2.1 objective

Stage 2.1 now closes Branch A label feasibility and defines Branch B benchmark
contracts before any UNSW-NB15 acquisition or modeling. It must publish an
approved contract specification—not data or model artifacts—for:

1. dataset identity `UNSW_NB15_BENCHMARK` and branch identity
   `BRANCH_B_LABELED_BENCHMARK`;
2. an approved acquisition source, usage/license record, expected official
   file inventory, checksum procedure, immutable raw location, acquisition
   manifest schema, and fail-closed source-identity policy;
3. a UNSW-specific adapter and source/normalized schema that preserves raw
   fields and rejects silent coercion;
4. primary binary target `NORMAL` versus `ATTACK`, with original attack
   category preserved separately for secondary analysis and forbidden from
   model inputs;
5. a benchmark-specific feature contract and target-leakage allowlist; and
6. official split preservation, deterministic TRAIN/VALIDATION derivation,
   fold/group policy, duplicate/leakage audits, locked TEST handling,
   manifests, and downstream consumer allowlists.

This amendment does not download UNSW-NB15. Acquisition may begin only after
this amendment and a Stage 2.1 execution plan/contract payload are explicitly
human-approved.

### Strict dataset separation

FortiGate and UNSW-NB15 are never concatenated. Separate dataset/branch IDs are
mandatory in every manifest and artifact. Each branch retains separate:

- raw and processed data roots;
- adapters and schemas;
- feature definitions and feature-state artifacts;
- preprocessing, imputation, encoding, scaling, selection, and calibration
  state;
- split/fold manifests and seeds;
- model, threshold, score, prediction, and metric artifacts; and
- publication bundles, validators, and report namespaces.

Cross-branch parents, rows, fitted state, features, or model artifacts fail
closed. FortiGate keeps the existing ordered 36-feature contract for its
unsupervised case study. UNSW-NB15 must receive a benchmark-specific contract
after source-schema verification and must not be padded, renamed, or forced
into the FortiGate 36-feature schema.

### UNSW-NB15 official split and TEST lock

The official UNSW-NB15 TEST split is immutable final benchmark membership.
Official TEST cannot supply fit state, feature selection, hyperparameters,
thresholds, calibration, stopping, model choice, or headline selection.

Only the official training split may create development data. Stage 2.1 must
freeze deterministic TRAIN/VALIDATION membership and any group-aware folds
from official training before Stage 2.2. The contract requires:

- exact official train/test source hashes, row counts, schema, target mapping,
  and membership manifests verified from acquired files;
- exact-duplicate, target-conflicting-duplicate, near-duplicate, stable
  entity/flow-key, and cross-official-split overlap audits;
- no moving or deleting official TEST rows; if train/test duplicate overlap
  exists, retain the official-TEST result and require a separately named
  duplicate-excluded sensitivity result;
- target leakage audit covering binary label, attack category,
  target-derived/post-outcome fields, row/split identifiers, and trivially
  reconstructive fields;
- preprocessing fit only on TRAIN or the applicable fold-local training
  partition;
- deterministic validation purpose, allocation, seed/namespace, and manifest;
- official TEST labels quarantined from Stage 2.2–2.4 selection code, with
  test features exposed only by allowlist and test identity locked by hash;
  and
- independent split/leakage/manifest validation before handoff.

### Stage 2.1 handoff and ownership boundary

Stage 2.1 owns the two-branch contract and no model behavior. Its active
handoff must include:

- the FortiGate feasibility closure record and historical-method registry;
- UNSW acquisition/source/schema/target contracts;
- branch-separation and consumer-allowlist contracts;
- official split identity plus deterministic TRAIN/VALIDATION/fold rules;
- benchmark feature-definition and target-leakage contracts;
- duplicate/leakage and locked-TEST validation requirements; and
- exact blockers/readiness reasons for Stage 2.2 and Stage 2.3.

Stage 2.2 owns U1/U2 fitting separately on FortiGate and UNSW-NB15. Stage 2.3
owns S1/S2 only on UNSW-NB15. Stage 2.4 owns UNSW-only chained ML under the
existing nested cross-fitting invariant. Stage 2.5 owns branch-separated final
reporting, including FortiGate real-log findings, UNSW metrics, four primary
U1/U2/S1/S2 benchmark matrices, paired baseline/chained comparisons, and the
mandatory domain-transfer limitation.

```text
Benchmark performance does not prove identical performance on the real FortiGate environment.
```

No label-generation, acquisition, split, feature, or leakage methodology in
this active Stage 2.1 scope is left for an Execution Agent to invent.

## 3. Historical FortiGate Label-Feasibility Purpose — Closed

**Historical status:** Sections 3–55 retain the complete audit trail of the
FortiGate label-feasibility program. Any retained use of “active,” “current,”
“ready,” or “may resume” describes the status of an earlier approved version,
not current execution authority. Only Section 2A is the active Stage 2.1
architecture under this amendment.

Stage 2.1 will build a defensible, versioned ground-truth-proxy and evaluation
foundation for Stages 2.2–2.5. It must make every label, exclusion, split,
sample, fitted-state boundary, and TEST access decision auditable.

Stage 2.1 will not assume that the available data can support supervised
learning or final attack-detection claims. Its valid result may be a blocked S1
or S2 path, a label-free unsupervised path, or a conditional final evaluation.

Mandatory interpretation boundaries are:

```text
ANOMALY != ATTACK
RULE MATCH != CONFIRMED ATTACK
ANOMALY SCORE != ATTACK PROBABILITY
HIGH_INTEREST != CONFIRMED ATTACK
LOW_INTEREST != CONFIRMED BENIGN
SOURCE THREAT OBSERVATION != GROUND TRUTH
ABSENCE OF ALERT != BENIGN
```

## 4. Historical FortiGate Label-Feasibility Scope — Closed

Stage 2.1 execution will:

1. reconcile all 100,000 normalized records to one frozen sampling frame;
2. freeze record-level annotation and evidence semantics;
3. create deterministic precision-first evidence packages and immutable
   decision/label histories without an AI API or required human reviewers;
4. define and validate `PRECISION_FIRST_PROXY_LABEL` provenance,
   `HIGH_CONFIDENCE_PROXY` eligibility, and the separate optional
   stronger-provenance upgrade path;
5. build label-blind duplicate, group, entity, and split diagnostics;
6. freeze one group-aware 70/15/15 TRAIN/VALIDATION/TEST split;
7. select separate enriched TRAIN, frozen VALIDATION, and representative TEST
   review samples under predeclared designs;
8. freeze the evaluation charter and validation-use budget;
9. freeze the shared 36-feature transformation protocol;
10. compute public development and private TEST sufficiency results;
11. publish one no-overwrite public bundle and one separately sealed private
    TEST bundle; and
12. issue explicit readiness statuses for Stage 2.2, S1, S2, and chaining.

## 5. Explicit Out-of-Scope

Stage 2.1 must not:

- train or replace Isolation Forest;
- select U2;
- train Logistic Regression or any stronger classifier;
- build a chained model;
- calculate final model performance, curves, or confusion matrices;
- open TEST labels for model development;
- infer labels from anomaly, triage, or model output, or from any single
  rule/source-threat status outside the complete Section 16C conjunctions;
- modify frozen Stage 1.7–2.0 artifacts or reports;
- alter raw or normalized evidence;
- add a dependency unless a separately approved plan revision requires it;
- add a UI, API, database, cloud service, AI/LLM labeling dependency, or
  deployment system;
  or
- create detailed plans for Stages 2.2–2.5.

## 6. Repository Evidence Reviewed

| Evidence | Stage 2.1 fact used |
|---|---|
| `AGENTS.md` and `/Users/tanawat/.codex/RTK.md` | Raw evidence is immutable; sanitized identifiers are opaque; missingness is contextual; results must be measured and reproducible. |
| `README.md` | Stage 2.0 V5 is the completed baseline; existing anomaly output is not attack truth. |
| `docs/final_project_report.md` | Dataset has 100,000 rows; no human labels or supervised metrics exist. |
| Approved master pipeline | Owns all cross-stage methodology and assigns exact Stage 2.1 decision authority. |
| Stage 1.7 plan, findings, `src/ai_features/`, and tests | One normalized record is one observation; feature order is fixed at 36; session grouping exists; rarity maps and distributions are population-fitted. |
| Stage 1.8 plan, findings, `src/anomaly/`, and tests | Historical scores/ranks/bands and Top-50 are model outputs usable only as sampling context. |
| Stage 1.9 plan, findings, `src/evaluation/`, and tests | Existing 100-row queue proves a blinded representation pattern, but `SUSPICIOUS`/`NOT_SUSPICIOUS` are not ATTACK/BENIGN labels and no reviews were completed. |
| Stage 2.0 plan, builder, and tests | Versioned no-overwrite publication, hash binding, and fail-closed validation are established conventions. |
| `src/labeling/evidence.py`, `models.py`, `contracts.py`, `human_inputs.py`, `ai_proxy.py`, and Stage 2.1 tests | Current implementation contains evidence registries, append-only history primitives, human-input validation, TEST guards, and the prior AI path. The precision-first amendment specifies future replacements/additions without modifying implementation now; `ai_proxy.py` and its tests remain historical and are not active execution inputs. |
| `data/raw/network_log_SAFE.csv` read-only profile and Stage 1.2 findings | Actual fields support conservative deterministic predicates: 18 `utm/anomaly/clear_session/alert` ICMP records with internally consistent blocked reconnaissance signature fields; seven traffic denies with `Policy Violation` remain ambiguous; 12 exact NTP app-control-pass / traffic-start / traffic-accept session triplets exist; and 13,788 exact two-record sessions have a lower-`itime` `start` followed by a higher-`itime` `accept` with stable endpoint/protocol/service identity. These are measured design inputs, not labels or promised class yield. |
| Normalization models and mapping | Stable joins use `source_record_number` and `event.source_record_id`; session/entity tokens are opaque; duration and timestamp meaning remain unverified. |
| Stage 1.2 timestamp findings | `itime` interpretation is unverified, one value is missing, file order is not chronological, and `data_timestamp` meaning is unknown. |
| `.gitignore` and local bundle layout | Generated artifacts live under versioned `data/processed/` roots and remain outside Git. |

Verified upstream identities used by this plan are:

- Stage 1.7 feature JSONL:
  `1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1`;
- Stage 1.7 metadata:
  `b74373532d5a15de84113d57249e642311a1b3b6c6e827b8747bba94082e2ae0`;
- Stage 1.8 score JSONL:
  `f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4`;
  and
- Stage 1.8 manifest:
  `9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77`.

These historical identities are evidence and optional sampling context. They
are not Stage 2.x feature state or primary annotation evidence.

## 7. Inputs / Preconditions

Execution requires all of the following:

- explicit human approval of this detailed plan;
- unchanged baseline and upstream SHA-256 identities;
- strict successful validation of all 100,000 normalized rows;
- the Section 16C precision-first evidence policy, context window, rule
  registry, decision schema, quality-tier policy, immutable history rules,
  dry-run contract, and proxy-eligibility rules frozen and human-approved;
- human TEST Custodian `Tanawat`, recorded as
  `CUSTODIAN_TANAWAT_V1`, independent from model-selection execution;
- an approved Section 16A Custodian acknowledgement proving status-only private
  storage configuration and a sealed committed 32-byte private seed;
- exactly one approved Section 16A external-evidence registry or exact
  no-independent-evidence declaration; and
- the already approved, feasible HARD_GROUP_ONLY V2 split and audit; and
- fresh output paths. Existing bundles must never be replaced.

The Section 16A reviewer registry is optional for the active proxy path. Its
absence does not block proxy labeling and must never be replaced with fake
reviewer identities. It is required only if later real human review attempts
to supersede proxy history with a human/external provenance tier. Custodian
unavailability, an invalid precision-first labeling contract, or a missing
evidence-registry / no-evidence declaration remains blocking.

## 8. Annotation Unit

### Frozen unit

`annotation_unit_type = SOURCE_RECORD`.

One normalized source record is one annotation unit and one future prediction
point. This matches Stage 1.7's one-record observation contract and preserves
the only fully reconciled identity available across all 100,000 rows.

### Identity

- `source_record_number`: positive integer from `source.record_number`.
- `source_record_id`: exact opaque string from `event.source_record_id`.
- `source_record_identity_sha256`: SHA-256 of canonical JSON array
  `["stage-2.1-source-record-v1", dataset_sha256, source_record_number,
  source_record_id]`, where unquoted names denote their typed values.
- `annotation_unit_id`: `AU-` plus the same full 64-character digest.
- `unit_mapping_sha256`: SHA-256 of canonical JSON containing the unit ID and
  its one-element ordered source-record identity list.

Both source keys must match. A mismatch, duplicate key, missing key, or changed
dataset identity blocks the unit.

### Relationship to sessions, events, and incidents

`session.identifier`, source event IDs, endpoint identifiers, and host
identifiers are context/grouping keys only. They do not replace the annotation
unit. Stage 2.1 creates no incident unit because no validated incident or
correlation contract exists.

### Propagation

Labels never propagate to another record, including records sharing a session,
entity, event type, near-duplicate signature, or apparent behavior. Each record
requires its own review history and evidence linkage. Group membership affects
split isolation and uncertainty resampling only.

## 9. Evidence Window / Evidence Policy

### Prediction point and window

The prediction point is the target source record as observed in the frozen
normalized artifact. Repository evidence does not establish timestamp units or
temporal generalization, but it supports one bounded predecessor relation for
the precision-first BENIGN rule: within an exact nonempty `net_sessionid`, a
context record whose integer `itime` is strictly smaller than the target's
integer `itime` may be treated as source-order predecessor evidence. The active
version therefore uses:

```text
window_basis = TARGET_PLUS_PAST_SAME_SESSION_RAW_ITIME_V1
prediction_cutoff = TARGET_RAW_ITIME
context_group_key = exact nonempty net_sessionid
context_direction = context.itime < target.itime
maximum_context_records = 2
```

Context is admitted only when target and context `itime` values are valid
integers, the exact session group is wholly contained in one split, and the
complete session shape matches an approved Section 16C rule. Select at most
the two context records with the greatest lower raw `itime`, ties by
`source_record_number` then exact `source_record_id`. Equal/higher `itime`, file
adjacency, another session/entity, unrestricted dataset lookup, an inferred
clock unit, and post-target evidence are forbidden. Invalid ordering disables
the contextual rule and yields `UNCERTAIN` unless a record-only ATTACK rule
independently resolves the target. Labels never propagate to context records.

### Permitted evidence

The active deterministic precision-first engine, and any later optional human
reviewer, may inspect only a generated Stage 2.1 evidence package:

1. exact target-record operational source fields and their normalized
   projections;
2. source provenance and normalization issues for that record;
3. independently registered evidence that identifies the same record or
   source event and documents that it existed at the prediction cutoff; and
4. a separately marked source-detector panel, when opened deliberately.

The operational panel field allowlist is exact:

```text
itime, data_timestamp,
data_parsername, data_sourceid, data_sourcename, data_sourcetype,
src_geo, src_intf, src_ip, src_mac, src_port, src_natip, src_natport, src_domain,
dst_geo, dst_intf, dst_ip, dst_mac, dst_port,
net_proto, net_rcvdpkts, net_recvbytes, net_sentbytes, net_sentpkts,
net_sessionduration, net_sessionid,
app_cat, app_service, app_id, app_name,
host_ip, host_location, host_mac, host_type, host_hwvendor, host_hwver,
host_osfamily, host_osname, host_osver, host_name,
epid, euid, adom_oid
```

The normalized operational projection allowlist is also exact:

```text
time.itime_raw, time.itime_utc_derived,
source.parser_name, source.source_identifier, source.source_name,
source.source_type,
network.source.geo_source, network.source.interface_source,
network.source.identifier, network.source.link_layer_identifier,
network.source.port, network.source.nat_identifier_source,
network.source.nat_port_source, network.source.domain_source,
network.destination.geo_source, network.destination.interface_source,
network.destination.identifier, network.destination.link_layer_identifier,
network.destination.port,
network.protocol_raw, network.protocol_number, network.protocol_name,
session.received_packets, session.received_bytes, session.sent_bytes,
session.sent_packets, session.duration_raw_value, session.identifier,
application.category_source, application.service_source, application.id_raw,
application.name_source,
host.identifier, host.location_source, host.link_layer_identifier,
host.type_source, host.hardware_vendor_source, host.hardware_version_source,
host.os_family_source, host.os_name_source, host.os_version_source,
host.name_source
```

`data_timestamp`, `epid`, `euid`, and `adom_oid` have no approved normalized
projection and therefore appear only under their original source-field keys.

The evidence builder may use `loguid` only to create the private label-task
mapping; it must not display `loguid`, `source_record_number`, split/sample
identity, or cohort purpose to the labeling decision logic or optional
reviewers. Raw timestamps remain unit-neutral; only the frozen strict-less-than
relation above is allowed.

The separately gated detector-panel allowlist is exact:

```text
event_action, event_id, event_severity, event_subtype, event_type,
event_profile, event_message,
threat_action, threat_name, threat_severity, threat_type, threat_pattern,
threat_id, threat_ref,
stage_1_4_rule_ids, stage_1_4_source_threat_observation
```

The normalized source-observation projection allowlist is exact:

```text
event.action_source, event.source_event_id, event.severity_source,
event.subtype_source, event.type_source, event.message_source,
threat_observations.action_source, threat_observations.name_source,
threat_observations.severity_source, threat_observations.type_source,
threat_observations.pattern_source, threat_observations.id_raw,
threat_observations.reference_source
```

`event_profile`, `stage_1_4_rule_ids`, and
`stage_1_4_source_threat_observation` have no normalized projection and remain
source-observation keys only.

Every opened field path is recorded and every field in this panel is marked
`SOURCE_OBSERVATION`. The prompt and rubric contain these exact literals:

```text
SOURCE THREAT OBSERVATION != CONFIRMED ATTACK
RULE MATCH != CONFIRMED ATTACK
```

No source-observation value automatically determines ATTACK or BENIGN. Only the
complete Section 16C conjunctive functions may resolve a binary label, and the
active path always retains `PRECISION_FIRST_PROXY_LABEL` provenance. A
separate future direct-detector path, if ever used, retains
`DETECTOR_DERIVED_PROXY`; neither tier becomes confirmatory provenance without
a later valid human/external superseding version.

### Prohibited evidence

Precision-first evidence packages and optional human-review packages must not
contain:

- Stage 1.7 feature values, rarity, distributions, or partition;
- Stage 1.8 scores, raw abnormality, ranks, bands, or Top-50 membership;
- Stage 1.9 reasons, suspected behaviors, attack interpretation, evidence
  strength, auto-triage, review labels, priority, or ranks;
- any Stage 2.x score, prediction, threshold, model output, or split purpose;
- sampling stratum, selection probability, cohort, or label yield; or
- summaries generated from prohibited fields.

The existing Stage 1.9 queue must not be reused. Stage 2.1 creates a separate
queue with a new schema and field-level allowlist.

### External corroboration

Each external item must have an immutable evidence ID, evidence type, issuer,
report creation time, asserted observation/effective time with documented
semantics, target linkage, full artifact SHA-256, and availability
classification. Content may remain in a restricted evidence store; label
artifacts retain only bounded references and hashes. A report may be authored
later, but the facts used for the label must describe the same target event or
contemporaneous activity and must not depend on subsequent behavior. Because
event chronology is unverified, exact source-record/source-event linkage or a
documented synthetic-generator mapping is mandatory. If timing or linkage
cannot be verified, the deterministic engine or optional reviewer must select
`UNCERTAIN` or an ineligible provenance for the requested evaluation scope.

Section 16A owns the exact registry and no-independent-evidence schemas. An
empty registry, informal prose declaration, unknown evidence enum, physical
storage path, or Execution-Agent-created evidence record is invalid.

### Missing evidence and future information

Missing evidence is never interpreted as benign. The deterministic engine must
return `UNCERTAIN` whenever every required predicate of an approved binary rule
cannot be proven. A task that cannot be evaluated because evidence is
inaccessible uses the separate `EVIDENCE_UNAVAILABLE` resolution status. Any
future/prohibited information or context-window violation invalidates the
decision and requires a new version.

## 10. Label Semantics

`label` has exactly three non-null values:

| Value | Machine semantics | Required evidence |
|---|---|---|
| `ATTACK` | Both frozen high-precision ATTACK evidence functions agree for the target and no BENIGN function fires. It means **proxy ATTACK**, not confirmed real-world attack. | Every conjunctive predicate in `PF_ATTACK_CONTROL_CORROBORATION_V1` and `PF_ATTACK_SIGNATURE_INTEGRITY_V1` passes from permitted evidence. Deny, timeout, reset, rare port/destination, high traffic, ICMP/PING, source threat flag, rule match, anomaly score, or anomaly rank alone is insufficient. |
| `BENIGN` | Both frozen affirmative expected-interaction functions agree for the target and no ATTACK function fires. It means **proxy BENIGN**, not proven absence of attack. | Every conjunctive predicate in `PF_BENIGN_SESSION_COMPLETION_V1` and `PF_BENIGN_APPCTRL_CORROBORATION_V1` passes. Not-ATTACK, accepted traffic alone, no alert/threat/anomaly/deny, common service, or low volume alone is insufficient. |
| `UNCERTAIN` | Required evidence is missing, partial, conflicting, ambiguous, temporally unsupported, outside the frozen context window, or no complete binary rule matches. | Exact failed predicates, conflict/evidence references, and reason codes are retained. `UNCERTAIN` is expected, resolved proxy output and is preferred over unsupported certainty. |

These active-path definitions do not change the meaning of a later stronger
human/external superseding label. A proxy ATTACK or proxy BENIGN is never
serialized or reported as confirmed truth.

The separate `resolution_status` enum is:

- `RESOLVED`: final label is ATTACK, BENIGN, or UNCERTAIN;
- `EVIDENCE_UNAVAILABLE`: required evidence could not be accessed;
- `REVIEWER_NONRESPONSE`: optional human-upgrade reviews were not completed;
- `DISAGREEMENT_UNRESOLVED`: optional human adjudication could not resolve a
  disagreement; and
- `REVIEW_INCOMPLETE`: the deterministic rule evaluation or optional review
  was interrupted or structurally incomplete.

For any non-`RESOLVED` status, `label` must be null. These states must not be
collapsed into `UNCERTAIN` because their missingness mechanisms differ.

## 11. Label Provenance

The exact `label_provenance` taxonomy is:

| Provenance | Generator and evidence | Human verification | Strength | TRAIN | VALIDATION | TEST | Secondary use |
|---|---|---:|---|---:|---:|---:|---:|
| `EXTERNAL_CONFIRMED` | Independent case, verified IOC, documented simulation, or equivalent evidence is directly linked to the unit and cutoff. | Two reviewers verify linkage; adjudicator resolves conflict. | Strictest | Yes | Yes | Yes | Yes |
| `HUMAN_ANALYST_ADJUDICATED` | Two independent analysts apply the frozen rubric to permitted evidence; agreement or human adjudication produces the label. | Required | Primary proxy | Yes | Yes | Yes | Yes |
| `AI_ASSISTED_HUMAN_VERIFIED` | AI performs only allowed clerical assistance; two humans independently decide from permitted evidence and accept the final record. | Required | Conditional primary proxy | Yes only when assistance audit passes | Same | Same | Yes |
| `DETECTOR_DERIVED_PROXY` | FortiGate threat fields, rule/source observations, alerts, or detector decisions are decisive without independent corroboration. | May be present but cannot promote tier | Weak proxy | No | No | No | Yes, separately |
| `AI_ASSISTED_PROXY_LABEL` | The previously approved frozen two-pass AI workflow generated a substantive proxy label. | Not required | Historical inactive proxy | No for active branch | No for active branch | No for active branch | Historical only unless reactivated by a future approved plan |
| `PRECISION_FIRST_PROXY_LABEL` | The frozen deterministic Section 16C rules generate a proxy label from permitted target/context evidence. | Not required | Active high-confidence proxy reference only when quality tier passes | Yes, active proxy branch only | Yes, matching proxy-validation purpose only | Yes, private proxy-reference evaluation only | Yes, explicitly named |

`AI_ASSISTED_HUMAN_VERIFIED` is primary eligible only when assistance class is
`CLERICAL_ONLY`, the AI input manifest contains no prohibited field, tool/model
identity and outputs are hashed, both reviewers make independent decisions,
and the human adjudicator owns the final decision. Otherwise the record keeps
the applicable non-primary provenance; the active deterministic path never
claims a human tier.

Provenance tiers must never be pooled silently. The master-plan confirmatory
primary projection still contains only the first three tiers after every other
eligibility check passes. `AI_ASSISTED_PROXY_LABEL` and
`PRECISION_FIRST_PROXY_LABEL` are excluded from every master-confirmatory
`primary_*_eligible` flag. Only `PRECISION_FIRST_PROXY_LABEL` with
`label_quality_tier=HIGH_CONFIDENCE_PROXY` may set the active branch flags
`precision_proxy_training_eligible`, `precision_proxy_validation_eligible`,
and private `precision_proxy_test_reference_eligible` under Sections 12, 16C,
and 33. This is primary evaluation within the explicitly named proxy branch,
not primary-confirmatory learning. The strictest-
tier sensitivity cohort contains only `EXTERNAL_CONFIRMED` records and is
reportable only with at least 30 ATTACK rows, 30 BENIGN rows, and 25
independent groups per class in the applicable evaluation cohort.

## 12. Label Schema

All label-history rows use canonical JSON Lines schema `stage_2_1_label/1.2`.
Unknown fields, duplicate keys, invalid UTF-8, nonfinite numbers, and short
hashes are rejected.

Visibility codes below are `D` for public development rows only, `T` for
private TEST rows only, and `S` for schema/contract definitions in both. No
TEST label row or label-derived TEST value may appear in a public file.

| Field | Type / nullability | Contract | Visibility |
|---|---|---|---|
| `schema_version` | string, non-null | Exactly `1.2`. | S/D/T |
| `label_record_id` | string, non-null | `LR-` plus full SHA-256 of canonical unit/version/parent/decision references. | D/T |
| `dataset_sha256` | 64-lowercase-hex string | Exact frozen normalized identity. | D/T |
| `annotation_contract_sha256` | 64-hex string | Frozen annotation-contract identity. | D/T |
| `source_record_number` | integer >=1 | Exact normalized record number. | D/T |
| `source_record_id` | nonempty string | Exact opaque normalized source record ID. | D/T |
| `source_record_identity_sha256` | 64-hex string | Identity formula in Section 8. | D/T |
| `annotation_unit_type` | enum | Exactly `SOURCE_RECORD`. | D/T |
| `annotation_unit_id` | string | `AU-` plus full digest. | D/T |
| `unit_mapping_sha256` | 64-hex string | Binds unit to its one source record. | D/T |
| `label` | enum or null | `ATTACK`, `BENIGN`, `UNCERTAIN`; null unless resolution is `RESOLVED`. | D/T |
| `resolution_status` | enum | Values in Section 10. | D/T |
| `decision_status` | enum | `RESOLVED` or `CLOSED_UNRESOLVED` at label-record publication. Current status is derived from state history. | D/T |
| `label_provenance` | provenance enum or null | Required for resolved labels; null for unresolved outcomes. | D/T |
| `human_verified` | boolean | True only when required humans verified the decision. | D/T |
| `review_decision_ids` | array of unique strings | Sorted immutable human references; empty for deterministic/AI proxy versions; at least two independent human decisions for confirmatory primary eligibility. | D/T |
| `proxy_decision_ids` | array of exactly two unique strings or empty | Historical `APD-` references for AI proxy versions; empty for the active precision-first path. | D/T |
| `precision_rule_decision_id` | `PFD-` string or null | Required for `PRECISION_FIRST_PROXY_LABEL`; null for every other provenance. | D/T |
| `label_quality_tier` | enum or null | Exactly `HIGH_CONFIDENCE_PROXY` for active binary labels; null for UNCERTAIN, unresolved, and non-precision provenance. No lower binary tier exists. | D/T |
| `matched_rule_ids` | sorted unique string array | Exact Section 16C rule IDs whose complete predicates matched. | D/T |
| `failed_rule_ids` | sorted unique string array | Exact evaluated rule IDs that did not fully match; required for active UNCERTAIN. | D/T |
| `context_record_identity_sha256s` | sorted unique 64-hex array | Zero to two permitted predecessor records from Section 9; empty for record-only decisions. | D/T |
| `label_source_exclusion_manifest_sha256` | 64-hex string | Binds the label-source-to-feature leakage audit used for eligibility. | D/T |
| `finalized_by_actor_type` | enum | `PRECISION_RULE_ENGINE`, `AI_PROXY_WORKFLOW` (historical), `WORKFLOW_ENGINE`, or `HUMAN_ADJUDICATOR`. | D/T |
| `finalized_by_id` | nonempty pseudonymous string | Registry-backed actor ID. | D/T |
| `adjudication_status` | enum | `NOT_APPLICABLE_DETERMINISTIC_PROXY`, `NOT_APPLICABLE_AI_PROXY`, `NOT_REQUIRED`, `REQUIRED`, `IN_PROGRESS`, `RESOLVED`, `UNRESOLVED`. | D/T |
| `adjudication_decision_id` | string or null | Required only for resolved adjudication. | D/T |
| `evidence_package_id` | nonempty string | Immutable evidence package identity. | D/T |
| `evidence_source_ids` | sorted unique string array | References evidence registry; no raw content. | D/T |
| `evidence_viewed` | sorted unique string array | Exact evidence item IDs and field paths opened by final decision makers. | D/T |
| `evidence_window` | object | Exact basis/start/end/cutoff fields from Section 9. | D/T |
| `decision_reason` | string, 1..2000 characters, or null | Required for resolved labels; bounded, NFC-normalized, no secret/raw evidence dump. | D/T |
| `review_completed_at` | RFC 3339 offset timestamp or null | Immutable submission time; null only for unresolved incomplete state. | D/T |
| `label_version` | integer >=1 | Starts at 1 and increments by exactly 1 per unit. | D/T |
| `parent_label_record_id` | string or null | Null only for version 1; otherwise immediate prior version. | D/T |
| `supersedes_label_record_id` | string or null | Same as parent for corrections; null for first version. | D/T |
| `sampling_manifest_row_id` | nonempty string | Exact selected-sample row reference. | D/T |
| `sampling_stratum` | enum string | Frozen mutually exclusive stratum. Hidden from reviewer interface. | D/T |
| `sampling_phase` | enum string | Frozen phase identifier. | D/T |
| `intended_cohort` | enum | `TRAIN_ENRICHED`, `VALIDATION_U`, `VALIDATION_S`, `VALIDATION_CHAIN`, or `TEST_PRIMARY`. | D/T |
| `split_assignment` | enum | `TRAIN`, `VALIDATION`, or `TEST`; must match split manifest. | D/T |
| `primary_training_eligible` | boolean | Derived by frozen eligibility rules. | D/T |
| `primary_validation_eligible` | boolean | True only for matching validation purpose and eligible provenance. | D/T |
| `primary_test_eligible` | boolean, conditionally required | Required only when `split_assignment=TEST`; forbidden in development rows; computed only in private TEST bundle. | T |
| `precision_proxy_training_eligible` | boolean | True only for resolved TRAIN ATTACK/BENIGN with `PRECISION_FIRST_PROXY_LABEL`, `HIGH_CONFIDENCE_PROXY`, valid rule/context/history, and a passing label-source exclusion audit. | D/T |
| `precision_proxy_validation_eligible` | boolean | Same requirements for the row's frozen VALIDATION purpose. | D/T |
| `precision_proxy_test_reference_eligible` | boolean, conditionally required | Required and private only for TEST; true only for an eligible high-confidence binary proxy label. | T |
| `reference_label_scope` | enum | `HIGH_CONFIDENCE_PROXY_REFERENCE`, `PRIMARY_CONFIRMATORY_REFERENCE`, or `NONE`; active precision-first rows use the first value. | D/T |
| `secondary_sensitivity_eligible` | boolean | Permits separately named proxy sensitivity analysis. | D/T |
| `eligibility_reason_codes` | sorted unique enum array | Positive machine reasons for each true flag. | D/T |
| `exclusion_reason_codes` | sorted unique enum array | Required when any primary flag is false. | D/T |
| `ai_assistance` | object | Existing clerical-assistance audit for human tiers; active precision-first rows require `used=false`. | D/T |
| `source_artifact_fingerprints` | object of 64-hex values | At least normalized input, split manifest, sampling manifest, evidence package, and review-history snapshot identities. | D/T |
| `created_at` | RFC 3339 offset timestamp | Immutable label-record creation time. | D/T |

The active label projection retains no numeric probability or confidence.
`HIGH_CONFIDENCE_PROXY` is a rule/evidence eligibility tier, not a calibrated
probability. Historical Section 16B AI records retain their original
categorical certainty field. A separate
`parent_label_version` field is also omitted because the mandatory parent ID
resolves to exactly one validated prior version; duplicating the number could
create contradictory lineage.

Required exclusion codes include `PROXY_PROVENANCE_FROM_CONFIRMATORY`,
`PROHIBITED_EVIDENCE`, `PARTIAL_ATTACK_RULE`, `PARTIAL_BENIGN_RULE`,
`RULE_CONFLICT`, `CONTEXT_WINDOW_INVALID`, `LABEL_SOURCE_LEAKAGE_AUDIT_FAIL`,
`QUALITY_TIER_INELIGIBLE`, `INVALID_PROXY_PASS_HISTORY`,
`INSUFFICIENT_REVIEW_INDEPENDENCE`, `EVIDENCE_UNAVAILABLE`,
`REVIEWER_NONRESPONSE`, `DISAGREEMENT_UNRESOLVED`, `WRONG_COHORT`,
`INVALID_HISTORY`, and `SUPERSEDED_VERSION`.

## 13. Immutable Label History

Label history is append-only. Published rows are never edited or deleted.

`label_record_id` is `LR-` plus SHA-256 of canonical JSON array
`["stage-2.1-label-record-v1", dataset_sha256, annotation_unit_id,
label_version, parent_label_record_id, sorted_review_decision_ids,
sorted_proxy_decision_ids,
precision_rule_decision_id, adjudication_decision_id]`, retaining nulls. A
review decision ID is `RD-` plus
SHA-256 of its complete canonical decision payload excluding the ID field. A
review event ID is `RE-` plus SHA-256 of its complete canonical event payload
excluding the ID field. An AI proxy decision ID is `APD-` plus SHA-256 of its
complete canonical Section 16B decision payload excluding
`proxy_decision_id`. These IDs identify immutable events; a changed payload
necessarily creates a new ID.

An active precision-first decision ID is `PFD-` plus SHA-256 of its complete
canonical Section 16C payload excluding `precision_rule_decision_id`.

- Version 1 has no parent.
- A correction appends version `n+1`, references version `n`, and appends a
  `SUPERSEDED` state event for the prior version.
- A version gap, fork, duplicate active version, changed timestamp, changed
  evidence hash, or parent mismatch fails validation.
- Adjudication produces new events and, when necessary, a new label version;
  it never rewrites reviewer submissions.
- Conflict history retains every independent decision and rationale.
- The resolved projection chooses the highest valid non-superseded version per
  unit. It is fully reproducible from history and the declared snapshot hash.
- Downstream stages bind one explicit label-history snapshot SHA-256 and one
  resolved-projection SHA-256.
- A correction after any model fit creates a new Stage 2.x pipeline version.
  Earlier models and metrics remain bound to their old snapshot.

Human review timestamps and historical AI inference outputs are not assumed
deterministic. Active precision-first decisions are deterministic from the
frozen package/rule/policy/exclusion identities and must reproduce exactly.

## 14. Optional Human Reviewer Upgrade Workflow

This workflow is inactive unless real human reviewers become available and a
human-approved reviewer registry passes Section 16A. It is not a Checkpoint
2.1C precondition for the active precision-first proxy path. No automated
actor may occupy a human slot or adjudicator role.

Review state is derived from append-only state events. Exact states are:

`PENDING`, `IN_REVIEW`, `REVIEWED`, `NEEDS_ADJUDICATION`, `ADJUDICATING`,
`RESOLVED`, `CLOSED_UNRESOLVED`, and `SUPERSEDED`.

| From | To | Authorized actor | Condition |
|---|---|---|---|
| none | `PENDING` | workflow engine | Valid sampled unit and blinded package exist. |
| `PENDING` | `IN_REVIEW` | assigned human reviewer | Reviewer accepts task; no conflict; package hash matches. |
| `IN_REVIEW` | `REVIEWED` | same human reviewer | One immutable decision, rationale, viewed-evidence list, and timestamp validate. |
| `REVIEWED` | `RESOLVED` | workflow engine | Two independent decisions agree and provenance/eligibility checks pass; agreement may be `UNCERTAIN`. |
| `REVIEWED` | `NEEDS_ADJUDICATION` | workflow engine | Decisions conflict, provenance differs materially, or either reviewer requests adjudication. |
| `NEEDS_ADJUDICATION` | `ADJUDICATING` | assigned human adjudicator | Adjudicator is distinct from both reviewers and accepts task. |
| `ADJUDICATING` | `RESOLVED` | same adjudicator | Final label and reconciliation rationale satisfy rubric. |
| `PENDING`, `IN_REVIEW`, `NEEDS_ADJUDICATION`, or `ADJUDICATING` | `CLOSED_UNRESOLVED` | review administrator | Replacement attempts are exhausted; exact unresolved status is recorded. |
| `RESOLVED` or `CLOSED_UNRESOLVED` | `SUPERSEDED` | correction officer plus human approval | A linked next version exists. |

All other transitions fail. No actor may review and adjudicate the same unit,
submit twice for one slot, backdate a transition, or edit a prior event.
Reviewer order and the target split/purpose remain hidden from reviewers.

## 15. Optional Human Adjudication Upgrade

When the optional upgrade path is activated, a selected unit receives two
independent first-pass human reviews. Each reviewer is blind to the other
decision and to sampling/split purpose. These requirements do not apply to or
block the active precision-first proxy workflow.

- Matching ATTACK/BENIGN decisions resolve only if evidence and provenance
  requirements pass.
- Matching UNCERTAIN decisions resolve as UNCERTAIN.
- ATTACK versus BENIGN, binary versus UNCERTAIN, or material provenance
  disagreement requires a third human adjudicator.
- The adjudicator may choose ATTACK or BENIGN only by citing permissible
  evidence that reconciles the conflict. Otherwise the result is UNCERTAIN.
- If evidence cannot be obtained, use `EVIDENCE_UNAVAILABLE`, not UNCERTAIN.
- If a reviewer never responds and no valid replacement completes the slot,
  use `REVIEWER_NONRESPONSE`.
- If adjudication cannot close the conflict, use
  `DISAGREEMENT_UNRESOLVED` with null label.
- An AI suggestion has no vote and never breaks a tie.
- A source detector has no vote. If decisive without independent evidence,
  final provenance is `DETECTOR_DERIVED_PROXY` even when humans agree.

## 16. Optional AI-Assisted Human Review Policy

This section applies only when AI provides clerical assistance to the optional
human-review upgrade path. No AI system is an active substantive labeler;
Section 16B is historical and Section 16C is deterministic.

Allowed AI assistance is limited to:

- formatting already permitted evidence;
- producing a source-field inventory without interpretation;
- identifying missing required fields;
- checking schema completeness;
- drafting a summary whose every statement cites a permitted evidence item;
  and
- flagging rubric sections for human consideration.

AI must not:

- map anomaly, rank, band, triage, rule, or threat status to ATTACK/BENIGN;
- access prohibited model/pipeline fields for primary review;
- invent missing context or external corroboration;
- override, merge, or silently rewrite human decisions;
- act as either independent human reviewer or adjudicator; or
- produce a label represented as confirmed human ground truth.

Every optional clerical-assistance call must bind an allowlisted input-manifest SHA-256, tool/model
identity when available, output SHA-256, assistance class, and human acceptance
record. A substantive AI label or unauditable assistance is
`AI_ASSISTED_PROXY_LABEL` and primary-confirmatory ineligible; it is not valid
for the active precision-first proxy-supervised branch.

## 16A. Human Input Contracts

Amendment `S2.1-AMEND-2026-09-26-HUMAN-INPUT-CONTRACTS-V1` froze the
machine-readable human inputs originally required before Checkpoint 2.1C. It changed no
label, evidence semantics, split, sample, evaluation, sufficiency, or
transformation rule. All four schemas use canonical Section 40 JSON,
`additionalProperties=false`, exact case-sensitive enums, full lowercase
64-hex SHA-256 values, and RFC 3339 timestamps with offsets. Placeholder text
is valid only in this plan's templates; submitted artifacts containing
`<HUMAN_FILL>` fail.

The reviewer-registry portion is now an optional future human-upgrade contract;
the evidence/declaration and TEST Custodian portions remain active
preconditions. The human supplies and approves every artifact that is used.
The Execution Agent may validate and consume them but may not create reviewer
identities, attest human training/conflicts, invent external evidence, declare
evidence absence on a human's behalf, generate the TEST seed, or simulate
Custodian acknowledgement.

### Reviewer registry contract

**Path status:** OPTIONAL / NOT REQUIRED FOR ACTIVE PRECISION-FIRST PROXY LABELING. It
becomes mandatory only before a human-reviewed or adjudicated superseding
label may be created.

- Logical artifact ID: `STAGE_2_1_REVIEWER_REGISTRY`.
- Public Stage 2.1 path: `contracts/reviewer_registry.json`; it is not a
  Stage 2.2-2.4 consumer input.
- Format/schema: canonical JSON, `stage_2_1_reviewer_registry/1.0`.
- Role enum: `PRIMARY_REVIEWER`, `ADJUDICATOR`.
- Conflict enum: `NO_CONFLICT`, `NON_BLOCKING_DISCLOSED`, `BLOCKING`.

Required top-level fields are:

| Field | Type / rule |
|---|---|
| `schema_version` | string, exactly `1.0` |
| `registry_version` | string, exactly `1.0` |
| `registry_id` | `RR-` plus SHA-256 of the canonical payload excluding `registry_id` |
| `approved_by_human` | boolean, must be true |
| `approval_timestamp` | RFC 3339 string |
| `reviewers` | array of at least three records; unique `reviewer_id` and unique `person_binding_id` |

Every reviewer record requires exactly:

| Field | Type / rule |
|---|---|
| `reviewer_id` | nonempty pseudonymous string; no real name required |
| `person_binding_id` | nonempty human-assigned opaque identity binding used only to prevent one person occupying multiple roles |
| `registry_version` | string matching top-level `registry_version` |
| `role` | reviewer role enum |
| `training_acknowledged` | boolean; must be true for eligibility |
| `training_acknowledged_at` | RFC 3339 string when acknowledged; otherwise null |
| `conflict_status` | conflict enum |
| `conflict_declaration` | null only for `NO_CONFLICT`; otherwise nonempty human statement |
| `independence_acknowledged` | boolean; must be true for eligibility |
| `active` | boolean |
| `approved_by_human` | boolean; must be true for eligibility |
| `approval_timestamp` | RFC 3339 string when approved; otherwise null |

An eligible reviewer is active, human-approved, training-acknowledged,
independence-acknowledged, and not `BLOCKING`. Before review, the registry must
contain exactly two eligible `PRIMARY_REVIEWER` records and at least one
eligible `ADJUDICATOR`. The two primaries must have distinct reviewer/person
bindings. Every adjudicator binding must differ from both primaries. Duplicate
IDs/bindings, a blocking conflict, missing acknowledgement/timestamp, false
human approval, unknown field/enum, or invalid registry hash fails closed.

```json
{
  "approval_timestamp": "<HUMAN_FILL_RFC3339>",
  "approved_by_human": true,
  "registry_id": "RR-<HUMAN_FILL_64HEX>",
  "registry_version": "1.0",
  "reviewers": [
    {
      "active": true,
      "approval_timestamp": "<HUMAN_FILL_RFC3339>",
      "approved_by_human": true,
      "conflict_declaration": null,
      "conflict_status": "NO_CONFLICT",
      "independence_acknowledged": true,
      "person_binding_id": "<HUMAN_FILL_PRIMARY_1_BINDING>",
      "registry_version": "1.0",
      "reviewer_id": "<HUMAN_FILL_PRIMARY_1_PSEUDONYM>",
      "role": "PRIMARY_REVIEWER",
      "training_acknowledged": true,
      "training_acknowledged_at": "<HUMAN_FILL_RFC3339>"
    },
    {
      "active": true,
      "approval_timestamp": "<HUMAN_FILL_RFC3339>",
      "approved_by_human": true,
      "conflict_declaration": null,
      "conflict_status": "NO_CONFLICT",
      "independence_acknowledged": true,
      "person_binding_id": "<HUMAN_FILL_PRIMARY_2_BINDING>",
      "registry_version": "1.0",
      "reviewer_id": "<HUMAN_FILL_PRIMARY_2_PSEUDONYM>",
      "role": "PRIMARY_REVIEWER",
      "training_acknowledged": true,
      "training_acknowledged_at": "<HUMAN_FILL_RFC3339>"
    },
    {
      "active": true,
      "approval_timestamp": "<HUMAN_FILL_RFC3339>",
      "approved_by_human": true,
      "conflict_declaration": null,
      "conflict_status": "NO_CONFLICT",
      "independence_acknowledged": true,
      "person_binding_id": "<HUMAN_FILL_ADJUDICATOR_BINDING>",
      "registry_version": "1.0",
      "reviewer_id": "<HUMAN_FILL_ADJUDICATOR_PSEUDONYM>",
      "role": "ADJUDICATOR",
      "training_acknowledged": true,
      "training_acknowledged_at": "<HUMAN_FILL_RFC3339>"
    }
  ],
  "schema_version": "1.0"
}
```

### Reviewer independence contract

Each unit has two fixed primary slots assigned to the two eligible primary
bindings. A primary reviewer receives only the allowlisted blinded package and
may not read the other primary's task state, decision, label, rationale,
provenance proposal, or evidence-viewed list before submitting an immutable
decision. Both primaries remain blind to prohibited model evidence and to
split, cohort, stratum, selection probability, and sampling purpose. Each
submission independently records rationale, exact evidence IDs/fields viewed,
package hash, provenance proposal, and submission timestamp.

Adjudication starts only after both immutable primary submissions exist and the
workflow engine emits `NEEDS_ADJUDICATION`. The assigned distinct human
adjudicator may then read the two frozen decisions, rationales,
evidence-viewed references, provenance proposals, resolution issue, and the
same permitted evidence package. The adjudicator may not read prohibited model
evidence or split/cohort/sampling-purpose data. AI may assist only under
Section 16; it cannot occupy a registry record, satisfy reviewer cardinality,
act as adjudicator, vote, or resolve a conflict.

### External evidence registry contract

- Logical artifact ID: `STAGE_2_1_EXTERNAL_EVIDENCE_REGISTRY`.
- Conditional public Stage 2.1 path:
  `contracts/external_evidence_registry.json`; it is not a Stage 2.2-2.4
  consumer input.
- Format/schema: canonical JSON,
  `stage_2_1_external_evidence_registry/1.0`.
- `evidence_type` is closed:
  `INCIDENT_CASE_RECORD`, `VERIFIED_IOC_RECORD`, `DOCUMENTED_SIMULATION`,
  `SYNTHETIC_GENERATOR_GROUND_TRUTH`.
- `observation_time_semantics` is closed: `EVENT_OBSERVED_AT`,
  `INDICATOR_EFFECTIVE_AT`, `SIMULATION_EXECUTED_AT`,
  `SYNTHETIC_GENERATOR_EVENT_TIME`, `UNKNOWN`.
- `target_type` is closed: `SOURCE_RECORD_IDENTITY`, `SOURCE_EVENT_ID`,
  `SYNTHETIC_GENERATOR_RECORD`.
- `linkage_method` is closed: `EXACT_SOURCE_RECORD_KEYS`,
  `EXACT_SOURCE_EVENT_ID`, `SYNTHETIC_GENERATOR_MAPPING`.
- `availability_classification` is closed: `AVAILABLE_TO_REVIEWERS`,
  `RESTRICTED_CUSTODIAN_MEDIATED`, `UNAVAILABLE`.

Required top-level fields are `schema_version`, `registry_version`,
`registry_id`, `approved_by_human`, `approval_timestamp`, and nonempty
`evidence_items`. `registry_id` is `ER-` plus SHA-256 of the canonical payload
excluding `registry_id`. Every evidence item requires exactly:

| Field | Type / rule |
|---|---|
| `evidence_id` | unique nonempty string |
| `evidence_type` | closed enum |
| `issuer` | nonempty string |
| `report_created_at` | RFC 3339 string |
| `observation_time` | RFC 3339 string or null |
| `observation_time_semantics` | closed enum; `UNKNOWN` requires null time |
| `target_type` | closed enum |
| `target_id` | nonempty opaque string |
| `source_record_linkage` | exact object below |
| `artifact_sha256` | full lowercase 64-hex string |
| `availability_classification` | closed enum |
| `restricted_storage_reference` | null, or an opaque `evidence://` logical reference only when classification is `RESTRICTED_CUSTODIAN_MEDIATED` |
| `approved_by_human` | boolean; must be true for use |
| `approval_timestamp` | RFC 3339 string |
| `registry_version` | string matching top-level `registry_version` |

`source_record_linkage` requires exactly `dataset_sha256`,
`source_record_number`, `source_record_id`, `source_record_identity_sha256`,
`linkage_method`, and boolean `linkage_verified`. Hashes are full lowercase
64-hex; record number is positive; source IDs are opaque nonempty strings.
Primary external provenance additionally requires verified linkage,
non-`UNKNOWN` observation semantics, non-null observation time, and evidence
that is not `UNAVAILABLE`. Otherwise existing UNCERTAIN/proxy/ineligibility
rules apply. Physical paths and credentials are forbidden.

```json
{
  "approval_timestamp": "<HUMAN_FILL_RFC3339>",
  "approved_by_human": true,
  "evidence_items": [
    {
      "approval_timestamp": "<HUMAN_FILL_RFC3339>",
      "approved_by_human": true,
      "artifact_sha256": "<HUMAN_FILL_64HEX>",
      "availability_classification": "AVAILABLE_TO_REVIEWERS",
      "evidence_id": "<HUMAN_FILL>",
      "evidence_type": "INCIDENT_CASE_RECORD",
      "issuer": "<HUMAN_FILL>",
      "observation_time": "<HUMAN_FILL_RFC3339>",
      "observation_time_semantics": "EVENT_OBSERVED_AT",
      "registry_version": "1.0",
      "report_created_at": "<HUMAN_FILL_RFC3339>",
      "restricted_storage_reference": null,
      "source_record_linkage": {
        "dataset_sha256": "<HUMAN_FILL_64HEX>",
        "linkage_method": "EXACT_SOURCE_RECORD_KEYS",
        "linkage_verified": true,
        "source_record_id": "<HUMAN_FILL_OPAQUE>",
        "source_record_identity_sha256": "<HUMAN_FILL_64HEX>",
        "source_record_number": 1
      },
      "target_id": "<HUMAN_FILL_OPAQUE>",
      "target_type": "SOURCE_RECORD_IDENTITY"
    }
  ],
  "registry_id": "ER-<HUMAN_FILL_64HEX>",
  "registry_version": "1.0",
  "schema_version": "1.0"
}
```

### No-independent-evidence declaration contract

When no independent external evidence exists, use this artifact instead of an
empty or fabricated registry:

- Logical artifact ID:
  `STAGE_2_1_NO_INDEPENDENT_EVIDENCE_DECLARATION`.
- Conditional public Stage 2.1 path:
  `contracts/no_independent_evidence_declaration.json`.
- Format/schema: canonical JSON,
  `stage_2_1_no_independent_evidence_declaration/1.0`.
- Exactly one of the external evidence registry or this declaration must exist.

Required fields are `schema_version`, `declaration_version`,
`declaration_type`, `independent_external_evidence_available`, `declared_by`,
`declared_at`, `scope`, `statement`, `acknowledgement`, `approved_by_human`,
`approval_timestamp`, `dataset_sha256`, `evidence_policy_sha256`,
`plan_amendment_id`, and `declaration_payload_sha256`.
`declaration_payload_sha256` hashes the canonical object excluding that field;
the bundle manifest separately records the complete artifact SHA-256.

```json
{
  "acknowledgement": "HUMAN_ACKNOWLEDGED",
  "approval_timestamp": "<HUMAN_FILL_RFC3339>",
  "approved_by_human": true,
  "dataset_sha256": "<HUMAN_FILL_64HEX>",
  "declaration_payload_sha256": "<HUMAN_FILL_64HEX>",
  "declaration_type": "NO_INDEPENDENT_EXTERNAL_EVIDENCE",
  "declaration_version": "1.0",
  "declared_at": "<HUMAN_FILL_RFC3339>",
  "declared_by": "<HUMAN_FILL_HUMAN_ID>",
  "evidence_policy_sha256": "<HUMAN_FILL_64HEX>",
  "independent_external_evidence_available": false,
  "plan_amendment_id": "S2.1-AMEND-2026-09-26-HUMAN-INPUT-CONTRACTS-V1",
  "schema_version": "1.0",
  "scope": "STAGE_2_1_PRIMARY_ADJUDICATION",
  "statement": "No independent external evidence is available for Stage 2.1 primary adjudication beyond the evidence sources explicitly permitted elsewhere."
}
```

`declaration_type`, `scope`, `acknowledgement`, the false availability value,
and `statement` are exact literals. The declaration never turns absence of
evidence into BENIGN, never permits fabricated corroboration, and disables
evidence-dependent provenance tiers where their evidence requirement is not
met. The declaration does not block active precision-first proxy labeling from
the permitted source evidence; it limits provenance strength and claim scope.
Records become UNCERTAIN or otherwise ineligible under the existing
evidence/provenance rules when permitted evidence is insufficient.

### TEST Custodian setup and acknowledgement contract

- Logical artifact ID: `STAGE_2_1_TEST_CUSTODIAN_ACKNOWLEDGEMENT`.
- Public Stage 2.1 path:
  `contracts/test_custodian_acknowledgement.json`.
- Format/schema: canonical JSON,
  `stage_2_1_test_custodian_acknowledgement/1.0`.
- Public logical private-bundle identity:
  `custodian://security-log-intelligence/stage_2_1/test/v1`.

The private physical root is supplied only in the Custodian-controlled process
environment variable `SLI_STAGE_2_1_TEST_PRIVATE_ROOT`. The value is never a
command-line argument and is unavailable to public/development processes. A
Custodian-only setup verifier reads it, resolves it locally, and emits only an
exit status plus the acknowledgement below. It must verify that the root is
outside the repository and public processed roots, is not a symlink/alias into
them, is writable only under Custodian control, and has owner-only semantics
(POSIX directories `0700` and files `0600`, or Windows ACL access limited to
the Custodian and required operating-system principals). Empty, unavailable,
unsafe, or unverifiable configuration fails closed.

The environment value and private root must never be committed, copied into a
public manifest/artifact, echoed to logs/errors/chat/status, or retained in
shell history. Public artifacts use only the logical bundle identity and
`private_location_disclosed=false`.

The TEST seed is exactly 32 cryptographically random raw bytes generated
locally by the human Custodian using an OS cryptographic random source. The AI
Execution Agent may not generate, request, print, log, commit, copy to chat, or
store the seed outside Custodian-controlled private storage. The public
commitment is exactly lowercase hexadecimal SHA-256 of the raw 32 bytes, not
of hex, Base64, text, filename, or JSON encoding.

The acknowledgement requires exactly:

| Field | Type / rule |
|---|---|
| `schema_version` | string, exactly `1.0` |
| `custodian_id` | string, exactly `CUSTODIAN_TANAWAT_V1` |
| `private_bundle_id` | exact public logical bundle identity |
| `setup_completed` | boolean, must be true |
| `private_storage_verified` | boolean, must be true |
| `owner_only_permissions_verified` | boolean, must be true |
| `backup_policy_acknowledged` | boolean, must be true |
| `seed_generated` | boolean, must be true |
| `seed_commitment_sha256` | full lowercase 64-hex string |
| `seed_not_disclosed` | boolean, must be true |
| `independence_acknowledged` | boolean, must be true |
| `opening_policy_acknowledged` | boolean, must be true |
| `opening_policy_sha256` | full lowercase 64-hex string |
| `opening_state` | enum, exactly `SEALED` |
| `private_location_disclosed` | boolean, must be false |
| `hash_algorithm` | exactly `SHA-256` |
| `canonicalization` | exactly `UTF-8_SORTED_KEYS_COMPACT_LF` |
| `acknowledged_at` | RFC 3339 string |
| `approved_by_human` | boolean, must be true |
| `approval_timestamp` | RFC 3339 string |

The schema rejects a seed field, private path/root/location value, credential,
private label, private sampling detail, or unknown field.

```json
{
  "acknowledged_at": "<HUMAN_FILL_RFC3339>",
  "approval_timestamp": "<HUMAN_FILL_RFC3339>",
  "approved_by_human": true,
  "backup_policy_acknowledged": true,
  "canonicalization": "UTF-8_SORTED_KEYS_COMPACT_LF",
  "custodian_id": "CUSTODIAN_TANAWAT_V1",
  "hash_algorithm": "SHA-256",
  "independence_acknowledged": true,
  "opening_policy_acknowledged": true,
  "opening_policy_sha256": "<HUMAN_FILL_64HEX>",
  "opening_state": "SEALED",
  "owner_only_permissions_verified": true,
  "private_bundle_id": "custodian://security-log-intelligence/stage_2_1/test/v1",
  "private_location_disclosed": false,
  "private_storage_verified": true,
  "schema_version": "1.0",
  "seed_commitment_sha256": "<HUMAN_FILL_64HEX>",
  "seed_generated": true,
  "seed_not_disclosed": true,
  "setup_completed": true
}
```

### Checkpoint 2.1C active-input precondition

For the active precision-first proxy path, the reviewer registry is not
required. Before any
Checkpoint 2.1C sample draw or private artifact creation, one fail-closed
validator must prove all of:

1. every Section 16C evidence-window, deterministic-rule, quality-tier,
   label-source-exclusion, dry-run, schema, and claim-language contract is
   frozen, approved, hash-bound, internally consistent, and contains no
   unresolved placeholder;
2. exactly one approved external-evidence registry or approved no-independent-
   evidence declaration passes schema/hash/lineage validation;
3. Custodian acknowledgement passes; the Custodian-only verifier returns
   `CONFIGURED` without disclosing the root; owner-only storage is available;
   exactly 32 seed bytes exist privately; recomputed raw-byte commitment equals
   the public lowercase hash; and opening state is `SEALED`;
4. the approved HARD_GROUP_ONLY V2 split/audit is `FEASIBLE`, hash-valid, and
   unchanged; and
5. no submitted/public artifact, normal log, error, chat/status response, or
   environment snapshot contains the seed, private physical root, credential,
   private TEST label, or private TEST sampling detail.

If the optional human-upgrade path is invoked, its reviewer registry must also
pass the original reviewer eligibility and independence checks. Its absence
cannot block precision-first proxy labeling and cannot be filled with
fabricated identities.
Any missing, malformed, duplicate, conflicting, unapproved, inaccessible, or
secret-disclosing required active-path input stops Checkpoint 2.1C before
sampling. The Execution Agent cannot downgrade failure to a warning or
synthesize a replacement.

### Status-output security

Normal execution/status output may contain only these secret-adjacent forms:

```text
PRIVATE TEST ROOT: CONFIGURED | NOT CONFIGURED
TEST SEED: SEALED | NOT CREATED
TEST SEED COMMITMENT: <lowercase 64-hex public commitment> | NOT AVAILABLE
```

It must never print the private TEST root, seed bytes or encoding, private
labels, private sampling details, credentials, restricted physical evidence
location, or environment value.

## 16B. Historical AI-Assisted Proxy Labeling Contract — Inactive

Amendment `S2.1-AMEND-2026-09-26-AI-PROXY-LABELING-V1` previously made
`AI_ASSISTED_PROXY_LABEL` active and remains preserved as approved history.
Amendment `S2.1-AMEND-2026-09-27-PRECISION-FIRST-PROXY-V1` supersedes it for
new execution. Nothing in this section is an active Checkpoint 2.1C
precondition, artifact requirement, label generator, eligibility source, or
consumer input unless a future human-approved plan explicitly reactivates it.
Historical AI records, if any, remain immutable and cannot be promoted to
`HUMAN_ANALYST_ADJUDICATED`, `AI_ASSISTED_HUMAN_VERIFIED`, or
`EXTERNAL_CONFIRMED` merely because the active path changed.

### Historical artifacts and versions

The following public contract artifacts were frozen by the superseded AI path
and are retained for audit history only:

| Logical artifact | Path | Exact schema/version |
|---|---|---|
| `STAGE_2_1_AI_PROXY_LABELING_POLICY` | `contracts/ai_proxy_labeling_policy.json` | `stage_2_1_ai_proxy_labeling_policy/1.0` |
| `STAGE_2_1_AI_PROXY_PROMPT` | `contracts/ai_proxy_prompt.json` | `stage_2_1_ai_proxy_prompt/1.0` |
| `STAGE_2_1_AI_PROXY_RUNTIME_REGISTRATION` | `contracts/ai_proxy_runtime_registration.json` | `stage_2_1_ai_proxy_runtime_registration/1.0` |
| `STAGE_2_1_AI_PROXY_EVIDENCE_PACKAGE_SCHEMA` | `schemas/ai_proxy_evidence_package.schema.json` | `stage_2_1_ai_proxy_evidence_package/1.0` |
| `STAGE_2_1_AI_PROXY_DECISION_SCHEMA` | `schemas/ai_proxy_decision.schema.json` | `stage_2_1_ai_proxy_decision/1.0` |
| `STAGE_2_1_AI_PROXY_AUDIT_SCHEMA` | `schemas/ai_proxy_audit.schema.json` | `stage_2_1_ai_proxy_audit/1.0` |

All use canonical Section 40 JSON, full lowercase SHA-256, RFC 3339 offset
timestamps, strict enums, required/null rules, and
`additionalProperties=false`. The human approves the completed contract and
runtime registration. The Execution Agent may not substitute another prompt,
rubric, model/config registration, schema, or provenance value.

### Exact evidence package and context window

The evidence package contains only:

1. `annotation_unit_id` and `source_record_identity_sha256` for binding;
2. all exact Section 9 operational-panel keys, with source values and the
   documented normalized projections from
   `src/normalization/fortigate_mapping.py`;
3. the exact Section 9 source-observation-panel keys, each tagged
   `SOURCE_OBSERVATION`;
4. normalization provenance and issues for the same record; and
5. same-target external-evidence references from the approved registry, or an
   empty list when the approved no-evidence declaration is active.

The package fields are exactly `schema_version`, `evidence_package_id`,
`dataset_sha256`, `annotation_unit_id`, `source_record_identity_sha256`,
`window_basis`, `prediction_cutoff`, `operational_fields`,
`normalized_projections`, `source_observation_fields`,
`normalization_provenance`, `normalization_issues`,
`external_evidence_reference_ids`, `source_artifact_hashes`,
`prohibited_field_audit_sha256`, and `evidence_package_sha256`.
`window_basis` is exactly `RECORD_ONLY`; `prediction_cutoff` is exactly
`SOURCE_RECORD_OBSERVATION`. No adjacent row, same-session row, dataset search,
future event, split/cohort/stratum value, TEST-derived aggregate, downstream
prediction, or 36-feature vector is allowed.

Every scalar evidence value is represented exactly when its canonical UTF-8
length is at most 4,096 bytes. A larger value is represented by the first
4,096 bytes at a valid UTF-8 boundary plus `truncated=true`,
`original_byte_length`, and `original_sha256`; a truncated value cannot by
itself support a binary proxy label. The complete canonical package is capped
at 262,144 UTF-8 bytes. A package that still exceeds the cap is not sent to a
model and terminates as `EVIDENCE_UNAVAILABLE` with null label. Labels never
propagate to another record, including a record in the same session, entity,
duplicate group, or apparent incident.

The prohibited registry includes exact or semantic equivalents of
`anomaly_score`, `raw_abnormality`, `anomaly_rank`, `top_50`, `anomaly_band`,
Stage 1.9 explanations/reasons/suspected behaviors, `auto_triage`,
`investigation_priority`, `suspected_attack_type`, Stage 2.x scores,
supervised outputs, TEST predictions, engineered 36-feature values,
label/provenance fields, and split/sampling-purpose fields. Discovery of one
invalidates the package before inference; it is never repaired by silently
dropping an already exposed value.

### Frozen proxy-labeling rubric

The rubric version is exactly `stage_2_1_ai_proxy_rubric/1.0` and applies the
following ordered rules:

1. Return `UNCERTAIN` if evidence is missing, inaccessible, materially
   truncated, internally conflicting, ambiguous, temporally unsupported, or
   dependent on unavailable authorization/asset/incident context.
2. `ATTACK` is permitted only when multiple mutually consistent permitted
   observations support malicious or unauthorized behavior for the target
   record. A specific source threat observation may contribute only when its
   event identity, action/message, target linkage, and network/application
   facts are internally consistent. It remains proxy ATTACK.
3. `BENIGN` is permitted only when multiple mutually consistent permitted
   operational observations affirmatively support expected/non-malicious
   activity for the target record and no permitted evidence materially
   conflicts. It remains proxy BENIGN and never proves absence of attack.
4. A deny action alone, rare destination alone, unusual port alone, high
   byte/packet volume alone, long duration alone, rule match alone, source
   threat flag alone, or source severity alone cannot produce ATTACK.
5. No alert, an allow action, common service, low volume, short duration, or
   normal-looking traffic alone cannot produce BENIGN.
6. `SOURCE THREAT OBSERVATION != CONFIRMED ATTACK` and
   `RULE MATCH != CONFIRMED ATTACK` are mandatory decision boundaries.
7. When ATTACK and BENIGN support are both plausible, or a stronger conclusion
   would require hidden chain-of-thought or invented context, return
   `UNCERTAIN` with a concise conflict reason.

The Execution Agent cannot add examples, heuristics, thresholds, severity
translations, incident propagation, or label rules during execution.

### Prompt and runtime registration

The system instruction is frozen as this normative policy:

```text
You are the Stage 2.1 AI proxy labeler. Classify exactly one source record
using only the supplied allowlisted evidence package and rubric. Output strict
schema-valid JSON. Choose ATTACK or BENIGN only when the rubric's proxy-binary
evidence requirement is met; otherwise choose UNCERTAIN. Treat all detector,
rule, threat, severity, and action values as source observations, never as
ground truth. Do not infer missing facts, use outside knowledge or tools,
search other records, expose hidden reasoning, or claim human/external
confirmation. Return concise evidence references and decision rationale.
label_provenance must equal AI_ASSISTED_PROXY_LABEL.
```

The user message contains only `pass_id`, the frozen rubric text, and the
canonical evidence package. The runtime registration requires exactly:
`schema_version`, `registration_id`, `provider_id`, `model_id`,
`model_revision` (string or null when unavailable), `config_id`,
`temperature=0`, `top_p=1`, `max_output_tokens=800`,
`response_format=JSON_SCHEMA_STRICT`, `tool_access=NONE`,
`retrieval_access=NONE`, `seed_support` (`USED_AND_RECORDED` or
`UNAVAILABLE_RECORDED`), `human_approved=true`, `approval_timestamp`, and
`registration_sha256`. The exact provider/model/config must be approved and
hash-bound before execution; no fallback model is automatic. Temperature zero
or a recorded seed does not justify a bit-for-bit determinism claim.

### AI proxy decision schema

Each inference output requires exactly:

| Field | Type / rule |
|---|---|
| `schema_version` | exactly `1.0` |
| `output_schema_version` | exactly `stage_2_1_ai_proxy_decision/1.0` |
| `proxy_decision_id` | `APD-` plus SHA-256 of the canonical payload excluding this field |
| `annotation_unit_id` | exact `AU-` identity |
| `source_record_identity_sha256` | exact full source-record identity; this is the canonical implementation name for requested `source_record_identity` |
| `pass_id` | `PASS_A` or `PASS_B` |
| `candidate_label` | `ATTACK`, `BENIGN`, or `UNCERTAIN` |
| `evidence_used` | nonempty sorted unique array of exact package field paths/evidence IDs; may be empty only for `UNCERTAIN` with unavailable evidence |
| `evidence_summary` | NFC string, 1..2,000 characters; concise factual summary only |
| `decision_reason` | NFC string, 1..2,000 characters; concise rubric rationale, no hidden chain-of-thought |
| `decision_certainty` | `HIGH`, `MEDIUM`, or `LOW`; categorical and explicitly uncalibrated |
| `evidence_sufficiency` | `SUFFICIENT_FOR_PROXY_BINARY`, `INSUFFICIENT`, or `CONFLICTING` |
| `label_provenance` | exactly `AI_ASSISTED_PROXY_LABEL` |
| `labeler_model_id` | exact registered nonempty model ID |
| `labeler_model_revision` | registered string or null |
| `labeler_config_id` | exact registered config ID |
| `labeler_prompt_version` | exactly `stage_2_1_ai_proxy_prompt/1.0` |
| `labeler_rubric_version` | exactly `stage_2_1_ai_proxy_rubric/1.0` |
| `labeler_policy_version` | exactly `stage_2_1_ai_proxy_labeling_policy/1.0` |
| `input_evidence_package_sha256` | full lowercase package SHA-256 |
| `source_artifact_hashes` | nonempty object of full lowercase hashes including normalized input, split manifest, sampling manifest, evidence policy, prompt, rubric, and runtime registration |
| `prohibited_field_audit_sha256` | full lowercase audit hash |
| `review_timestamp` | RFC 3339 offset timestamp |
| `label_version` | integer >=1 matching the pending label-history version |

Binary labels require nonempty evidence, `SUFFICIENT_FOR_PROXY_BINARY`, and
`decision_certainty` of `HIGH` or `MEDIUM`. `LOW` requires `UNCERTAIN`.
`UNCERTAIN` cannot claim sufficient proxy-binary evidence. Schema, enum,
identity, hash, provenance, evidence-reference, and cross-field failures make
that pass invalid.

### Bounded two-pass consistency workflow

Each valid package receives exactly two independent requests, `PASS_A` then
`PASS_B`, using the same frozen package, prompt, rubric, and registered
model/config. Each pass cannot see the other output. The hard cost limits are
two model calls, at most 262,144 UTF-8 input bytes and 800 output tokens per
call, and at most 1,600 output tokens per unit. There is no retry,
self-critique, majority vote, third pass, or retry-until-agreement behavior.

The workflow finalizes mechanically:

- matching ATTACK or BENIGN is accepted only when both passes independently
  satisfy every binary-output rule; otherwise final label is `UNCERTAIN`;
- matching UNCERTAIN finalizes as `UNCERTAIN`;
- any ATTACK/BENIGN disagreement, binary-versus-UNCERTAIN disagreement,
  evidence-sufficiency conflict, or materially different cited target evidence
  finalizes as `UNCERTAIN` with `AI_PASS_DISAGREEMENT`;
- one malformed/failed pass produces `REVIEW_INCOMPLETE` with null label; and
- neither pass is represented as a human reviewer or adjudicator.

The accepted label record references both immutable `proxy_decision_id`
values, uses `label_provenance=AI_ASSISTED_PROXY_LABEL`,
`human_verified=false`, `finalized_by_actor_type=AI_PROXY_WORKFLOW`, and
`adjudication_status=NOT_APPLICABLE_AI_PROXY`.

### Reproducibility, ordering, and TEST isolation

AI output is not assumed bit-for-bit deterministic. Reproducibility is the
ability to replay the exact frozen package/prompt/rubric/model/config and audit
the immutable original bytes and hashes. A rerun never overwrites a decision
or label; it creates a new decision pair and label version linked to the prior
version. Both versions remain available to lineage validation.

Execution order is fixed:

1. freeze and approve evidence allowlist, rubric, prompt, schemas, runtime
   registration, proxy eligibility, and claim language;
2. freeze the approved HARD_GROUP_ONLY split and all sampling designs;
3. label TRAIN under the frozen two-pass procedure;
4. label only the frozen VALIDATION purpose cohorts under the same procedure;
5. have the Custodian run the same procedure for TEST inside the private root;
6. seal TEST decisions, proxy labels, class counts, audit, and sufficiency; and
7. expose them only at the authorized Stage 2.5 opening.

No TRAIN/VALIDATION/TEST outcome may revise the rubric, prompt, allowlist,
model/config, pass rule, split, or sampling design. TEST proxy labels and every
class-derived TEST value remain unavailable to Stages 2.2-2.4.

### Proxy-supervised eligibility and claim contract

Resolved proxy ATTACK/BENIGN rows with valid package, two-pass history,
immutable lineage, split/sample membership, and no prohibited evidence may
enter supervised TRAIN and their assigned VALIDATION purpose. This is
explicitly `proxy-supervised training`. `UNCERTAIN`, unresolved rows,
single-pass rows, detector-direct proxy rows, invalid histories, and rows from
the wrong cohort are excluded from binary fitting and denominators; they are
never silently converted.

Private eligible proxy ATTACK/BENIGN TEST rows may be used at Stage 2.5 only
for **evaluation against AI-assisted proxy reference labels**. Reports must use
that exact phrase or the shorter defined terms `AI-assisted proxy label`,
`proxy ATTACK`, and `proxy BENIGN`. Without stronger superseding evidence they
must not use `confirmed attack`, `verified benign`, `true attack`,
`ground-truth attack`, `analyst-confirmed performance`, `attack probability`,
or `confirmed attack-detection accuracy`.

The AI labeler sees raw/normalized facts that may be related to later
engineered features. Therefore proxy-reference evaluation measures model
agreement/prediction relative to this frozen labeling methodology. It does not
establish independent real-world attack truth, even when metrics are high.
This incorporation/circularity limitation is mandatory in every Stage 2.5
table, chart caption, executive summary, and conclusion that uses proxy labels.

### Audit and future stronger-provenance upgrade

`reports/ai_proxy_labeling_audit.json` requires exactly `schema_version`,
`audit_id`, `scope`, `total_selected`, `total_attempted`, `valid_pass_pairs`,
`incomplete_pass_pairs`, `proxy_attack_count`, `proxy_benign_count`,
`uncertain_count`, `evidence_available_count`,
`evidence_unavailable_count`, `pass_disagreement_count`,
`evidence_sufficiency_counts`, `rubric_version`, `prompt_version`,
`policy_version`, `model_id`, `model_revision`, `config_id`,
`runtime_registration_sha256`, `provenance_counts`,
`source_artifact_hashes`, and `created_at`. Counts are nonnegative integers;
count maps have closed enum keys; hashes are full lowercase; `scope` is
`DEVELOPMENT` publicly or `TEST_PRIVATE` privately. The public artifact may
contain development totals only. TEST audit values and class-derived counts
use the same schema but remain private until opening.

If real analysts or independent evidence later become available, they may
append a stronger version through Sections 14-16A. They must not overwrite AI
history. Valid lineage is:

```text
AI_ASSISTED_PROXY_LABEL
  -> AI_ASSISTED_HUMAN_VERIFIED or HUMAN_ANALYST_ADJUDICATED
  -> EXTERNAL_CONFIRMED when its independent-evidence contract is met
```

No upgrade is inferred merely because a human reads an AI output.

## 16C. Historical Precision-First Proxy Labeling Contract — Feasibility Study

Amendment `S2.1-AMEND-2026-09-27-PRECISION-FIRST-PROXY-V1` makes
`PRECISION_FIRST_PROXY_LABELING` the active method and
`PRECISION_FIRST_PROXY_LABEL` the only active automated-label provenance. The
method uses deterministic source-evidence rules; it requires no AI API and no
human reviewer registry. Human/external upgrades remain optional under
Sections 14-16A. The TEST Custodian remains mandatory.

### Frozen priority and non-optimization rule

Every design and execution decision uses this immutable priority:

1. label correctness and evidence quality;
2. leakage safety;
3. TEST independence;
4. reproducibility;
5. label quantity; and
6. model complexity.

There is no class-balance target. No observed or desired ATTACK/BENIGN count,
S1/S2 requirement, model need, minority ratio, or TEST result may change a
predicate, add a rule, lower an evidence requirement, recode UNCERTAIN, or
trigger a replacement sample. A scientifically honest `BLOCKED` result is a
valid terminal outcome.

### Historical precision-first artifacts and versions

The following public contracts freeze before any dry-run label is generated:

| Logical artifact | Path | Exact schema/version |
|---|---|---|
| `STAGE_2_1_PRECISION_FIRST_POLICY` | `contracts/precision_first_proxy_policy.json` | `stage_2_1_precision_first_proxy_policy/1.0` |
| `STAGE_2_1_PRECISION_FIRST_RULE_REGISTRY` | `contracts/precision_first_rule_registry.json` | `stage_2_1_precision_first_rule_registry/1.0` |
| `STAGE_2_1_PRECISION_FIRST_EVIDENCE_SCHEMA` | `schemas/precision_first_evidence_package.schema.json` | `stage_2_1_precision_first_evidence_package/1.0` |
| `STAGE_2_1_PRECISION_FIRST_DECISION_SCHEMA` | `schemas/precision_first_decision.schema.json` | `stage_2_1_precision_first_decision/1.0` |
| `STAGE_2_1_PRECISION_FIRST_DRY_RUN_SCHEMA` | `schemas/precision_first_dry_run.schema.json` | `stage_2_1_precision_first_dry_run/1.0` |
| `STAGE_2_1_LABEL_SOURCE_EXCLUSION_SCHEMA` | `schemas/label_source_exclusion_manifest.schema.json` | `stage_2_1_label_source_exclusion_manifest/1.0` |

All use canonical Section 40 JSON, strict enums, full lowercase SHA-256,
`additionalProperties=false`, and no unresolved placeholders. The Execution
Agent cannot add examples, thresholds, mappings, fallback rules, model calls,
or external lookups.

### Exact deterministic ATTACK functions

The two ATTACK functions are conjunctive evidence blocks. Neither can finalize
a label alone.

`PF_ATTACK_CONTROL_CORROBORATION_V1` is true only when the target record has
all exact source values:

```text
event_type = utm
event_subtype = anomaly
event_action = clear_session
event_severity = alert
threat_action = blocked
threat_severity = medium
threat_type = Reconnaissance
```

`PF_ATTACK_SIGNATURE_INTEGRITY_V1` is true only when
`net_proto=1`, `app_service=PING`, and exactly one complete signature branch
passes:

- `ICMP_SWEEP`: `threat_name=icmp_sweep`,
  `threat_pattern=icmp_sweep`, `threat_id=16777320`,
  `threat_ref=http://www.fortinet.com/ids/VID16777320`, and
  `event_message` matches
  `^anomaly: icmp_sweep, ([0-9]+) > threshold 100, repeats ([1-9][0-9]*) times since last log, pps ([1-9][0-9]*) of prior second$`
  with the first captured integer strictly greater than 100; or
- `ICMP_SOURCE_SESSION`: `threat_name=icmp_src_session`,
  `threat_pattern=icmp_src_session`, `threat_id=16777321`,
  `threat_ref=http://www.fortinet.com/ids/VID16777321`, and
  `event_message` matches
  `^anomaly: icmp_src_session, ([0-9]+) > threshold 300, repeats ([1-9][0-9]*) times since last log$`
  with the first captured integer strictly greater than 300.

Final ATTACK requires both functions true and both BENIGN functions false.
These correlated source-product observations justify only a high-confidence
proxy, never confirmed real-world attack truth. A deny, timeout, reset, rare
port, rare destination, high traffic value, ICMP/PING value, source threat
flag, rule match, anomaly score/rank/band, or Top-N status alone—or in any
unlisted combination—cannot produce ATTACK. The seven observed traffic-deny
`Policy Violation` records do not satisfy these functions and remain
UNCERTAIN absent stronger independently linked evidence.

### Exact deterministic BENIGN functions

`PF_BENIGN_SESSION_COMPLETION_V1` is true only when:

1. the target is `event_type=traffic`, `event_subtype=forward`, and
   `event_action=accept`, with `event_severity=notice`;
2. the Section 9 context contains exactly one permitted predecessor with
   `event_type=traffic`, `event_subtype=forward`, `event_action=start`, and
   `event_severity=notice`; the only other permitted predecessor, if present,
   is the exact app-control record required by the corroboration function;
3. target and predecessor have exact equal nonempty `src_ip`, `dst_ip`,
   `net_sessionid`, `net_proto`, and `app_service`; their `src_port` and
   `dst_port` are equal including the valid ICMP-empty-port case;
4. the predecessor's integer `itime` is strictly smaller than the target's;
5. neither record has a populated threat field, an action in
   `{deny, timeout, server-rst, client-rst, clear_session}`, or an event
   subtype other than the values above; and
6. both records pass normalization/source-identity validation without a
   conflicting issue on any predicate field.

`PF_BENIGN_APPCTRL_CORROBORATION_V1` is true only when:

1. the target is `traffic/forward/accept` with `net_proto=17`,
   `src_port=123`, `dst_port=123`, `app_service=junos-ntp`, `app_id=16270`,
   `app_name=NTP`, and `app_cat=Network.Service`;
2. the Section 9 context contains exactly two permitted predecessors, both
   with smaller integer `itime`: exactly one
   `utm/app-ctrl/pass/information` record and the exact
   `traffic/forward/start/notice` record required by the session-completion
   function;
3. the app-control record has `net_proto=17`, `src_port=123`, `dst_port=123`,
   `app_service=junos-ntp`, `app_id=16270`, `app_name=NTP`,
   `app_cat=Network.Service`, and
   `event_message=Network.Service: NTP`;
4. all three records share exact nonempty `src_ip`, `dst_ip`,
   `net_sessionid`, `net_proto`, and `app_service`, with equal ports under the
   same contextual-missingness rule; and
5. no record has a populated threat field, conflicting action/subtype, or
   normalization/source-identity issue on a predicate field.

Final BENIGN requires both BENIGN functions true and both ATTACK functions
false. Thus a generic `start`/`accept` pair—including the 13,788 measured pairs
in the repository—cannot become BENIGN without the separate exact
app-control NTP corroboration. The functions supply affirmative session-
completion and internally consistent application-control evidence. They do not
treat not-ATTACK, accepted traffic alone, no alert, no threat field, no
anomaly, no deny, ordinary volume, or a common service as sufficient by
itself.

### Mechanical finalization and UNCERTAIN

The engine evaluates every predicate in rule-ID order and finalizes exactly:

```text
if A_CONTROL and A_SIGNATURE and not B_SESSION and not B_APPCTRL:
    ATTACK / HIGH_CONFIDENCE_PROXY
elif B_SESSION and B_APPCTRL and not A_CONTROL and not A_SIGNATURE:
    BENIGN / HIGH_CONFIDENCE_PROXY
else:
    UNCERTAIN / null quality tier
```

Any partial ATTACK block, partial BENIGN block, attack/benign conflict,
multiple incompatible context shapes, prohibited evidence, missing predicate
field, invalid context order, normalization conflict, or unmatched record is
UNCERTAIN with exact reason codes. UNCERTAIN is not minimized and never enters
binary fitting or binary metric denominators.

Each decision records exactly `schema_version`, `decision_schema_version`,
`precision_rule_decision_id`, `annotation_unit_id`,
`source_record_identity_sha256`, `candidate_label`, `label_quality_tier`,
`matched_rule_ids`, `failed_rule_ids`, `predicate_results`, `evidence_used`,
`context_record_identity_sha256s`, `evidence_package_sha256`,
`rule_registry_sha256`, `label_source_exclusion_manifest_sha256`,
`source_artifact_hashes`, `decision_reason_code`, `label_version`, and
`created_at`. `precision_rule_decision_id` is `PFD-` plus SHA-256 of the
canonical payload excluding that ID. No probability/confidence score exists.

### Historical quality tier and proxy eligibility

`label_quality_tier` has one active binary value:
`HIGH_CONFIDENCE_PROXY`. No medium/low binary tier or relaxed fallback exists.
Only ATTACK/BENIGN decisions produced by the exact finalizer above may receive
it. Eligible active-branch rows also require valid split/sample purpose,
immutable history, no prohibited evidence, and a passing Section 37
label-source exclusion manifest. UNCERTAIN, partial/conflicting rules,
insufficient evidence, invalid context, failed lineage, historical AI labels,
and lower/unknown quality are excluded.

The active eligibility flags are
`precision_proxy_training_eligible`,
`precision_proxy_validation_eligible`, and private
`precision_proxy_test_reference_eligible`. Master-confirmatory
`primary_*_eligible` remains false unless a later stronger provenance version
independently satisfies the master contract.

### Deterministic distribution dry run before publication

All TRAIN phases, VALIDATION membership/purposes, and the private TEST sample
freeze before any rule output. The engine then runs once in `DRY_RUN` mode over
every selected unit before any canonical label is published. The public dry-run
report contains separate TRAIN and VALIDATION ATTACK, BENIGN, and UNCERTAIN
counts; binary-resolved percentage `(ATTACK+BENIGN)/selected`; UNCERTAIN
percentage; ATTACK agreement
`count(A_CONTROL and A_SIGNATURE)/count(A_CONTROL or A_SIGNATURE)`; BENIGN
agreement
`count(B_SESSION and B_APPCTRL)/count(B_SESSION or B_APPCTRL)`; rule-conflict
count; and evidence-sufficiency-failure count. Zero denominators serialize as
null with a reason.

The Custodian runs the same dry run privately for TEST. Public artifacts expose
only `test_seal_state` and structural integrity. The private dry-run report may
contain counts and emits only private `S1_TEST: PASS|BLOCK` and
`S2_TEST: PASS|BLOCK` sufficiency statuses under Section 33. No TEST label,
class count, percentage, rule count, or sufficiency status appears publicly.

Dry-run outputs are noncanonical and cannot enter training/evaluation. If every
methodology, leakage, lineage, and seal validator passes, canonical generation
must replay the exact inputs/rules and reproduce every dry-run decision hash
before changing mode to `CANONICAL`. A mismatch blocks publication. A rule or
threshold change requires a new human-approved amendment, new rule version,
new dry run, and complete affected relabeling. Class yield or gate failure is
never a permissible change reason by itself.

### Label-source exclusion manifest and 36-feature re-audit

Before active binary eligibility, publish
`manifests/label_source_exclusion_manifest.json`. For every source field,
context relation, rule predicate, and ordered Stage 1.7 feature it records
source paths, transform lineage, relationship
`DIRECT_RULE_SOURCE|DERIVED_FROM_RULE_SOURCE|CONTEXT_ONLY|CORRELATED_RISK|NO_KNOWN_LINK`,
allow/exclude status, reason, audit version, and hashes.

Because active rules inspect protocol, ports, and service, features 1-16
(`protocol_*`, port presence/classes/rarity, `service_rarity`, and
`service_missing`) are default-excluded from the active supervised matrix.
The rule does not use byte/packet/duration values; features 17-36 remain only
candidate features and must pass a TRAIN-only exact-reconstruction audit. If
any remaining feature or predeclared missing/zero predicate perfectly
reconstructs an active binary label in TRAIN across at least two independent
groups per class, exclude it. With fewer than two independent groups in either
class, the reconstruction audit is inconclusive and the candidate remains
excluded rather than passing on low support. The audit never reads VALIDATION
or TEST labels, never changes a label rule, and may honestly leave no
sufficient supervised feature set; that outcome blocks S1/S2.

The ordered 36-feature definition remains unchanged for unsupervised work and
provenance. Only the supervised allowlist is reduced. Population-derived state
remains TRAIN-only/fold-local.

### Reproducibility, TEST isolation, and claims

Rule evaluation is deterministic from frozen canonical evidence. A rerun may
not overwrite history; any input/rule/version change appends a new decision and
label version. TRAIN and VALIDATION decisions are public only through their
purpose allowlists. TEST evidence, decisions, labels, dry-run details, counts,
audit, and sufficiency remain under the private Custodian path until authorized
Stage 2.5 opening. The TEST seed stays private; only its commitment is public;
the Execution Agent cannot self-authorize opening.

All active metrics, including confusion matrix, accuracy, precision, recall,
F1, ROC-AUC, and weighted average precision/PR summary, must use the exact
phrase **evaluation against high-confidence proxy reference labels**. Reports
may use `precision-first proxy label`, `proxy ATTACK`, and `proxy BENIGN`.
Without stronger evidence they must not claim confirmed/verified ground truth,
confirmed attack-detection accuracy, analyst-confirmed performance, true
attacks, verified benign activity, or real-world attack probability.

`reports/precision_first_labeling_audit.json` requires development-only counts,
rule agreement, partial/conflict/evidence-failure counts, quality/provenance
counts, rule/policy/context/exclusion-manifest identities, source hashes, and
creation time. Its TEST counterpart remains private. Real analysts or external
evidence may append stronger versions under Sections 14-16A but never overwrite
precision-first history.

## 17. Sampling Architecture

### Sampling frame

The frame is all 100,000 reconciled normalized records. Missing historical
context never removes a row. Sampling occurs only after the authoritative
split is frozen.

Historical context creates these mutually exclusive strata in precedence
order:

1. `SOURCE_OR_RULE_CONTEXT`: Stage 1.4 source/rule observation or approved
   source-threat predicate is present;
2. `HISTORICAL_TOP_0_1`: no prior stratum and Stage 1.8 unrounded historical
   reference percentile is at least 99.9;
3. `HISTORICAL_TOP_1`: no prior stratum and percentile is at least 99.0;
4. `HISTORICAL_TOP_5`: no prior stratum and percentile is at least 95.0;
5. `HISTORICAL_MID_50_95`: no prior stratum and percentile is at least 50.0;
6. `HISTORICAL_BASE_0_50`: every remaining record.

These are sampling variables only. They cannot affect the deterministic
labeling decision, are hidden from optional reviewers, and never
become labels, features, evidence strength, or severity.

### A. Enriched TRAIN sample

- Draw only from `TRAIN`.
- Run at most four predeclared phases: `TRAIN_P0_PILOT`, `TRAIN_P1_FIXED`,
  `TRAIN_P2A_FIXED_COVERAGE`, and `TRAIN_P2B_FIXED_COVERAGE`.
- Phase P0 selects at most 400 records; P1 adds at most 1,200; P2A adds at
  most 800; P2B adds at most 800.
- Maximum cumulative TRAIN review budget is 3,200 unique records.
- No record may appear in more than one TRAIN phase.
- TRAIN inclusion probabilities and selection reasons are preserved, but no
  population prevalence claim uses this sample.
- Every TRAIN phase is `development_only=true` and
  `representative_evaluation_eligible=false`.
- Every phase uses the label-blind Section 18A allocation and freezes before
  the dry run. No class/support target or outcome-driven selection is allowed.

P0 target quotas are 40, 60, 70, 80, 75, and 75 records respectively in
the stratum order above. A stratum smaller than its quota is a census; unused
quota is redistributed in this fixed order:
`HISTORICAL_TOP_0_1`, `HISTORICAL_TOP_1`, `HISTORICAL_TOP_5`,
`HISTORICAL_MID_50_95`, `HISTORICAL_BASE_0_50`, then
`SOURCE_OR_RULE_CONTEXT`, always capped by remaining frame size.

P0 orders records within each stratum by SHA-256 of canonical JSON array
`["stage-2.1-train-p0-v1", 21012100, source_record_identity_sha256]` and
selects the first quota. Before any label exists, P1 selects exactly
`min(1,200, N_remaining)` unselected TRAIN records using the hybrid allocation
formula below. Within each P1 stratum, order by SHA-256 of canonical
JSON array
`["stage-2.1-train-p1-v1", 21012100, source_record_identity_sha256]`, ties by
`source_record_number` then exact `source_record_id`, and select the first
allocated records. P2A/P2B then freeze under Section 18A. P0 label yield does
not change any size, allocation, or order.

### B. Frozen VALIDATION sample

- Draw exactly 1,500 records from `VALIDATION` once, before any review outcome.
- Use the six strata and the hybrid allocation formula below.
- Assign each selected group, and therefore every selected member of that
  group, by SHA-256 of canonical JSON array
  `["stage-2.1-validation-purpose-v1", 21012102, group_id]`, where `group_id`
  denotes its string value. Use first-eight-byte
  unsigned big-endian modulo 10,000: `0..2999` is `VALIDATION_U`, `3000..6499`
  is `VALIDATION_S`, and `6500..9999` is `VALIDATION_CHAIN`. Expected shares
  are 30% (target 450), 35% (target 525), and 35% (target 525).
- Each purpose cohort has its own combined inclusion probability and weight.
- No outcome-based replacement, expansion, borrowing, or purpose reassignment
  is permitted. Insufficient support blocks the affected path.

### C. Locked TEST sample

- Draw exactly 1,500 records from `TEST` once, before Stage 2.2 output exists.
- Use the same six-stratum hybrid probability design.
- Every TEST-frame record has positive within-stratum inclusion probability.
- Sampling seed, selected identities, strata, weights, review status, and all
  label-derived data remain private.
- No outcome-based replacement or expansion is permitted. Insufficient support
  blocks the affected final claim; TEST is never resampled to obtain a desired
  class count.

### Hybrid allocation formula

For each nonempty stratum `h`, frame size `N_h`, total frame size `N`, review
budget `n`, and `H` nonempty strata, compute:

```text
raw_h = 0.5 * n * (N_h / N) + 0.5 * n * (1 / H)
```

Take floors, distribute remaining slots by descending fractional remainder,
then ascending frozen stratum order. Cap `n_h` at `N_h`; redistribute any
excess by the same rule until `sum(n_h) = n`. Select the first `n_h` rows in
the deterministic hash order. For one-stage selection:

```text
inclusion_probability_h = n_h / N_h
raw_design_weight_h = 1 / inclusion_probability_h
```

For VALIDATION purpose assignment, `q_p` is exactly 0.30, 0.35, or 0.35 from
the group-hash design. The combined probability is `(n_h / N_h) * q_p`, and
the purpose weight is its reciprocal. Actual purpose counts may differ from
their targets because whole groups cannot be split; numeric sufficiency gates,
not row movement, decide usability.

## 18. Historical Outcome-Adaptive TRAIN Sampling — Inactive

This section preserves the previously approved AI-path sampling controller for
audit history only. The precision-first amendment supersedes its label-yield
triggers, target-class deficits, adaptive utilities, and outcome-driven P2
selection with Section 18A. No active execution may use this section to target
class balance or increase a class count.

### Frozen phase table

| Phase | Purpose | Eligible frame | Eligible strata | Maximum additional reviews | Rule / seed | Overlap | Completion condition |
|---|---|---|---|---:|---|---|---|
| `TRAIN_P0_PILOT` | Validate AI rubric, prompt, evidence blinding, schema, and bounded two-pass workflow. | All TRAIN rows before any label outcome. | All six strata. | 400 | `TRAIN_P0_FIXED_QUOTA_V1` / `21012100` | None. | Every selected task has a terminal proxy-label state; pilot methodology gate and manifest audit are computed. |
| `TRAIN_P1_FIXED` | Create fixed initial development support without outcome targeting. | TRAIN rows not selected in P0. | All six strata. | 1,200 | `TRAIN_P1_HYBRID_V1` / `21012100` | None. | Every selected task is terminal; TRAIN S1/S2 support snapshots and manifest audit are computed. |
| `TRAIN_P2A_SUPPORT` | First and only intermediate outcome-driven development expansion. | One canonical candidate from each previously unrepresented TRAIN group; no earlier selected record/group. | All six strata with remaining candidates. | 800 | `TRAIN_P2A_LABEL_YIELD_V1` / `21012103` | None. | Every selected task is terminal; TRAIN support gates and manifest audit are recomputed. |
| `TRAIN_P2B_FINAL` | Final permitted outcome-driven development expansion. | One canonical candidate from each TRAIN group still unrepresented after P2A. | All six strata with remaining candidates. | 800 | `TRAIN_P2B_LABEL_YIELD_V1` / `21012104` | None. | Every selected task is terminal; final TRAIN and full S1/S2 sufficiency gates are computed. Sampling then stops permanently. |
| `VALIDATION_FIXED_1` | Frozen purpose-specific model selection. | VALIDATION only. | All six strata. | 1,500 | Section 17 fixed design / `21012101`, purpose seed `21012102` | None with TRAIN/TEST. | Frozen sample and three purpose assignments validate; no later expansion. |
| `TEST_LOCKED_1` | Locked final evaluation. | TEST only. | All six strata. | 1,500 | Section 17 fixed private-seed design | None with TRAIN/VALIDATION. | Private sample validates and seals; no later expansion. |

Every phase emits the complete Section 19 manifest field set for every
selected record. P2A/P2B additionally require `active_support_gate`,
`target_class`, `allocation_utility`, and `trigger_snapshot_sha256`; those
fields are null for fixed phases. A phase is incomplete if its manifest does
not independently reproduce its frame, allocation, selection order, and
non-overlap result.

P0 always attempts all 400 label tasks; class yield cannot stop it early.
It measures rubric/prompt/schema validity, evidence availability, valid
two-pass completion, pass disagreement, provenance distribution, class yield,
inference resource use, and group support. It is never declared sufficient in
advance.

Pilot methodology passes only when:

- all 400 queue rows pass blinding and schema validation;
- at least 90% obtain two valid immutable AI proxy decisions;
- PASS_A/PASS_B disagreement among valid pairs is at most 25%;
- every valid disagreement resolves mechanically to `UNCERTAIN`; and
- no critical prohibited-evidence exposure occurs.

A failed methodology gate stops production labeling. Any rubric, prompt,
allowlist, schema, model/config, or consistency-policy change requires a new
contract version and complete relabeling of every affected pilot row before
those rows can become proxy-supervised eligible.

### Trigger algorithm

The phase controller is deterministic and frozen before P0 labels open:

1. Run P0. If its methodology gate fails, emit
   `TRAIN_STOP_METHOD_BLOCKED`; do not run P1/P2A/P2B.
2. If P0 passes, run P1 exactly as specified. After all P1 tasks are terminal,
   evaluate the frozen common quality gates and TRAIN-only S1/S2 support gates.
3. If any label-independence, two-pass integrity, provenance, split,
   history, blinding, sampling-manifest, or common-quality gate fails, emit
   `TRAIN_STOP_METHOD_BLOCKED`; additional sampling cannot repair it.
4. If the S2 TRAIN support gate passes, emit
   `TRAIN_STOP_SUPPORT_S1_S2_MET`; do not run another TRAIN phase. S2 is
   stricter, so this status also requires S1 TRAIN support.
5. Otherwise run P2A by the exact allocation rule below. If P2A has no
   candidate or its capped allocation is zero, emit
   `TRAIN_STOP_FRAME_EXHAUSTED` and compute final S1/S2 statuses.
6. After P2A tasks are terminal, repeat steps 3 and 4. If S2 TRAIN support still
   fails, compute and run P2B by the same frozen rule with its own seed. No
   human or agent may skip P2B because S1 already passes. If P2B has no
   candidate or its capped allocation is zero, emit
   `TRAIN_STOP_FRAME_EXHAUSTED` and compute final S1/S2 statuses.
7. After all P2B tasks are terminal, repeat step 3. If no methodology or
   common-quality invariant fails, sampling stops permanently. If S2 TRAIN
   support passes, emit `TRAIN_STOP_SUPPORT_S1_S2_MET`. If only S1 TRAIN
   support passes, emit `TRAIN_STOP_S1_MET_S2_NOT_MET_BUDGET`. Otherwise emit
   `TRAIN_STOP_S1_S2_NOT_MET_BUDGET`.

Only TRAIN support components of Section 33 trigger P2A/P2B. VALIDATION or
private TEST insufficiency never triggers TRAIN sampling because TRAIN
expansion cannot repair those cohorts. Final public S1/S2 `READY`/`BLOCKED`
states combine the final TRAIN support result with the separately frozen
VALIDATION and common-quality gates.

### Active-gate and target-class rule

For P2A/P2B, the active gate is S1 when S1 TRAIN support fails; otherwise it is
S2. Let the active gate requirements be `R_A`, `R_B`, `R_GA`, and `R_GB` for
ATTACK rows, BENIGN rows, ATTACK groups, and BENIGN groups. Let observed
eligible counts through the prior phase be `A`, `B`, `GA`, and `GB`. Compute:

```text
D_A = max(0, (R_A - A) / R_A, (R_GA - GA) / R_GA)
D_B = max(0, (R_B - B) / R_B, (R_GB - GB) / R_GB)
```

If the active gate's majority/minority ratio fails, set the current minority
class deficit to at least `1.0`. If its group-dominance limit fails, set the
deficit for the class with the larger maximum group share to at least `1.0`;
ties select ATTACK. If `D_A = D_B = 0` but the active total-row requirement
fails, target the class with fewer eligible rows; an exact tie selects ATTACK.
Otherwise target ATTACK when `D_A > D_B`, BENIGN when `D_B > D_A`, and the
current minority class when equal; an exact class-count tie selects ATTACK.

The trigger snapshot records every input count, requirement, deficit, ratio,
dominance value, active gate, target class, and its full SHA-256. No other
outcome quantity may affect allocation.

### Adaptive candidate frame and allocation

For each P2 phase, exclude every previously selected record and every group
already represented by any prior TRAIN phase. For each remaining group, choose
one candidate: the member with the smallest SHA-256 of canonical JSON array
`[phase_selection_rule_id, phase_seed, source_record_identity_sha256]`, ties by
`source_record_number` then exact `source_record_id`. Therefore every adaptive
selection adds at most one record and one new independent group.

For each stratum `h`, let `R_h` be its remaining candidate count,
`Y_h` the number of prior terminal TRAIN tasks in that stratum with an eligible
label equal to the target class, and `T_h` the total prior terminal TRAIN tasks
in that stratum. Define the frozen Laplace-smoothed utility:

```text
U_h = (Y_h + 1) / (T_h + 2)
base_h = min(50, R_h)
cap_h = min(400, R_h)
```

The phase target is `n = min(800, sum(cap_h))`. Initialize `a_h = base_h` and
repeat this exact bounded allocation until `sum(a_h) = n`:

1. Set `K = n - sum(a_h)` and eligible set `E = {h: a_h < cap_h}`.
2. For each `h` in `E`, compute `q_h = K * U_h / sum(U_j for j in E)` and add
   `min(cap_h - a_h, floor(q_h))` to `a_h`.
3. Recompute `K`. If `K > 0`, rank the still-eligible strata by the fractional
   remainder from the most recent `q_h`, descending, then by the frozen
   Section 17 stratum order. Add one slot in that order while headroom and `K`
   remain.
4. If slots remain after one pass through that ranking, return to step 1 with
   the reduced eligible set and recomputed values.

Because `cap_h <= R_h`, allocation cannot exceed the remaining candidate
frame. A stratum with fewer than 50 candidates is a census at initialization;
its unavailable slots are automatically assigned by the same loop. Select the
first `a_h` candidates in each stratum by the phase hash order above.

The 50-record floor preserves broad pre-label stratum coverage. The 400-record
cap prevents one outcome-enriched stratum from supplying more than half of a
planned adaptive phase. If caps or remaining groups yield fewer than 800
records, select the exact computable phase target; do not relax caps or reuse a
group. A zero target stops with `TRAIN_STOP_FRAME_EXHAUSTED`.

P2A/P2B are explicitly development-only outcome-driven enrichment. Conditional
on the canonical one-per-group candidate frame, their within-phase probability
is `allocated_h / R_h`; it is not a representative original-row probability.
Their unconditional cumulative probability relative to the original TRAIN
frame is not identifiable after outcome-driven triggering and must be null. No
design weight is created, and their labels cannot support prevalence,
representative performance, VALIDATION, or TEST claims.

### Finite stopping statuses

Only these terminal TRAIN sampling statuses are valid:

- `TRAIN_STOP_METHOD_BLOCKED`: a methodology/common-quality invariant failed;
- `TRAIN_STOP_FRAME_EXHAUSTED`: no permitted new-group candidate remains;
- `TRAIN_STOP_SUPPORT_S1_S2_MET`: both TRAIN support gates pass;
- `TRAIN_STOP_S1_MET_S2_NOT_MET_BUDGET`: P2B ended, S1 TRAIN support passes,
  and S2 TRAIN support fails; and
- `TRAIN_STOP_S1_S2_NOT_MET_BUDGET`: P2B ended and S1 TRAIN support fails.

No fifth TRAIN phase, ad hoc replacement, cap relaxation, changed target class,
manual stratum priority, or increased review budget is allowed. A different
protocol requires a new human-approved plan version before any affected review.

### Numeric rationale

| Numeric choice | Category | Rationale |
|---|---|---|
| P0 maximum 400 | `OPERATIONAL` | Within the approved 300–500 pilot range; validates workflow only, not statistical sufficiency. |
| P1 maximum 1,200; cumulative 1,600 | `RESOURCE_CONSTRAINED` | Fixed development-review capacity chosen before labels; not a scientific optimum. |
| P2A/P2B maximum 800 each | `RESOURCE_CONSTRAINED` | Two bounded chances to close predeclared TRAIN support gaps without indefinite review. |
| Four TRAIN phases; cumulative maximum 3,200 | `RESOURCE_CONSTRAINED` | AI-labeling budget requiring approval with this plan; never represented as statistical truth or optimality. |
| P0 quotas `40/60/70/80/75/75` | `OPERATIONAL` | Fixed 400-task pilot coverage across all strata; not an estimate of population need. |
| P1 hybrid coefficients `0.5/0.5` | `METHODOLOGICAL` | Balance frame-proportional coverage with equal-stratum coverage before outcomes. |
| One P2 candidate per previously unrepresented group | `METHODOLOGICAL` | Each adaptive selection adds independent-group support and cannot deepen an already represented group. |
| Adaptive floor 50 per available stratum | `METHODOLOGICAL` | Retains broad stratum coverage during outcome-driven enrichment. |
| Adaptive cap 400 per stratum/phase | `METHODOLOGICAL` | Prevents one stratum from monopolizing an adaptive phase. |
| Utility constants `+1` and `+2` | `METHODOLOGICAL` | Fixed Laplace smoothing keeps every remaining stratum eligible when prior target-class yield is zero. |
| Deficit escalation floor `1.0` | `METHODOLOGICAL` | Gives a failed ratio or dominance criterion fixed priority without an agent-chosen severity score. |
| Seeds `21012100`, `21012103`, `21012104` | `OPERATIONAL` | Stable deterministic constants; they do not imply statistical optimality. |

Approving this plan freezes every value above. The Execution Agent cannot
alter one after labels are observed.

### VALIDATION and TEST non-adaptation

TRAIN alone may use P2A/P2B. VALIDATION remains exactly
`VALIDATION_FIXED_1`; TEST remains exactly `TEST_LOCKED_1` and sealed. TRAIN
phase outcomes cannot change VALIDATION membership, TEST membership, the
primary TEST estimand, TEST selection probability, TEST seed, or sealed TEST
class composition. No ATTACK/BENIGN yield may trigger a VALIDATION/TEST draw,
replacement, expansion, or reassignment.

## 18A. Historical Label-Blind Fixed Sampling — Feasibility Study

All sample membership freezes before the Section 16C dry run. Label outcomes,
quality tiers, support counts, and S1/S2 states never trigger selection.

### Frozen active phase table

| Phase | Purpose | Eligible frame | Maximum unique TRAIN rows | Rule / seed | Outcome dependency |
|---|---|---|---:|---|---|
| `TRAIN_P0_PILOT` | Fixed methodology/dry-run coverage | All TRAIN records | 400 | Existing Section 17 P0 quotas / `21012100` | None |
| `TRAIN_P1_FIXED` | Fixed development coverage | Remaining unselected TRAIN records | 1,200 | Existing Section 17 hybrid allocation / `21012100` | None |
| `TRAIN_P2A_FIXED_COVERAGE` | Additional fixed group/stratum coverage | Remaining unrepresented TRAIN groups | 800 | `TRAIN_FIXED_COVERAGE_V1` / `21012103` | None |
| `TRAIN_P2B_FIXED_COVERAGE` | Final fixed group/stratum coverage | Remaining unrepresented TRAIN groups | 800 | `TRAIN_FIXED_COVERAGE_V1` / `21012104` | None |
| `VALIDATION_FIXED_1` | Frozen purpose-specific model selection | VALIDATION only | 1,500 | Section 17 design / `21012101`, purpose seed `21012102` | None |
| `TEST_LOCKED_1` | Locked representative evaluation | TEST only | 1,500 | Section 17 private-seed design | None |

P0 uses frozen quotas `40/60/70/80/75/75`. P1 uses the existing Section 17
50/50 proportional/equal-stratum hybrid formula. For each P2 fixed phase, form
one canonical candidate per still-unrepresented TRAIN group using the smallest
SHA-256 of `[phase_rule_id, phase_seed,
source_record_identity_sha256]`, ties by source record number then ID. Let
`R_h` be remaining candidates in stratum `h`, `R=sum(R_h)`, and
`n=min(800,R)`. Compute:

```text
raw_h = n * (0.5 * R_h / R + 0.5 / 6)
floor_h = min(R_h, floor(raw_h))
```

Allocate residual slots one at a time to strata with remaining capacity by
descending fractional remainder, ties by frozen stratum order; after one pass,
recompute using only strata with capacity until exactly `n` slots are assigned.
Select the first allocated candidates in each stratum's hash order. A stratum
shortage redistributes mechanically; it never changes another rule or creates
a label target.

All four TRAIN selections freeze before any dry-run decision. After freeze,
the deterministic engine evaluates every selected TRAIN/VALIDATION unit and
the Custodian evaluates TEST privately. P0 is the designated methodology
cohort, but its class yield cannot alter P1/P2 because those memberships already
exist. If P0 methodology validation fails, canonical publication stops and all
later dry-run outputs remain noncanonical audit evidence.

Only these active sampling terminal statuses exist:

- `TRAIN_STOP_METHOD_BLOCKED`;
- `TRAIN_STOP_FRAME_EXHAUSTED` when the applicable P0/P1 row frames and P2
  one-candidate-per-unrepresented-group frames are exhausted before 3,200
  unique records can be selected; and
- `TRAIN_STOP_FIXED_PLAN_COMPLETE` when all four frozen phases complete.

Maximum phases are four and maximum unique TRAIN records are 3,200. Both are
`RESOURCE_CONSTRAINED`, not statistically optimal. Neither human nor Execution
Agent may add a phase, change 3,200, target a class, reuse a selected record,
reuse a previously represented group in P2, or replace a record after labels
are observed without a new human-approved amendment.

S1/S2 sufficiency is computed only after canonical high-confidence labels
exist. `S1 BLOCKED` or `S2 BLOCKED` never triggers resampling, rule relaxation,
or relabeling. VALIDATION and TEST membership, probabilities, purposes,
estimand, seed, class composition, and TEST seal remain unchanged by all TRAIN
outcomes.

For active P2 rows, `selection_method=HASH_ORDER_FIXED_COVERAGE`,
`conditional_on_prior_outcomes=false`, and `active_support_gate`,
`target_class`, `allocation_utility`, and `trigger_snapshot_sha256` are null.
Every selected row retains phase/frame/stratum sizes, formula/rule ID, seed,
selection order, non-overlap proof, probability where meaningful,
development-only flag, representative-evaluation eligibility, and manifest
version. No representative population claim uses TRAIN.

## 19. Sampling Manifest

Each selected or frame-eligible row uses JSON Lines schema
`stage_2_1_sampling/1.1` with these exact fields:

| Field | Type | Contract |
|---|---|---|
| `schema_version` | string | `1.1`. |
| `manifest_version` | string | Exactly `1.1`. |
| `sampling_manifest_row_id` | string | `SM-` plus full SHA-256 of design/cohort/source identity. |
| `dataset_sha256` | 64-hex string | Frozen normalized identity. |
| `source_record_number` | positive integer | Exact source key. |
| `source_record_id` | nonempty string | Exact opaque source key. |
| `source_record_identity_sha256` | 64-hex string | Section 8 identity. |
| `split_assignment` | enum | `TRAIN`, `VALIDATION`, `TEST`. |
| `intended_cohort` | enum | Five cohort values from Section 12. |
| `sampling_phase` | enum | Frozen phase identifier. |
| `selection_rule_id` | enum | Exact active phase rule ID from Section 18A or the fixed VALIDATION/TEST rule ID; historical Section 18 IDs are forbidden. |
| `sampling_stratum` | six-value enum | Section 17 precedence result. |
| `phase_frame_size` | integer >=1 | Total eligible frame size at phase freeze. |
| `stratum_frame_size` | integer >=1 | `N_h` at selection freeze. |
| `phase_target_size` | integer >=1 | Frozen phase budget. |
| `stratum_target_size` | integer >=0 | `n_h`. |
| `selected` | boolean | Selection result. Private for TEST. |
| `selection_method` | enum | `HASH_ORDER_SRSWOR`, `HASH_ORDER_FIXED_COVERAGE`, or `CENSUS`. |
| `selection_namespace` | nonempty string | Versioned canonical namespace. |
| `random_seed` | string | Exact public seed for TRAIN/VALIDATION; exact seed only in private TEST manifest. |
| `selection_order_digest` | 64-hex string | Digest used to order the row. Private for TEST. |
| `selection_order` | positive integer or null | Within-stratum deterministic order for selected rows; null for unselected frame rows. |
| `phase_selection_probability` | finite float `(0,1]` or null | Fixed-phase probability `allocated_h/R_h`; null only when not mathematically defined for an unselected frame row. |
| `cumulative_selection_probability` | finite float `(0,1]` or null | Combined probability under the frozen label-blind sequential design; null only when mathematically inapplicable to an unselected frame row. |
| `raw_design_weight` | finite float `>=1` or null | Reciprocal of combined probability only for representative VALIDATION/TEST use; always null for TRAIN. |
| `development_only` | boolean | True for every TRAIN phase; false for VALIDATION/TEST. |
| `representative_evaluation_eligible` | boolean | False for every TRAIN row; true only for valid frozen VALIDATION/TEST designs. |
| `conditional_on_prior_outcomes` | boolean | Always false for the active precision-first design. |
| `active_support_gate` | enum or null | Always null for the active precision-first design; retained only for historical schema migration. |
| `target_class` | enum or null | Always null for the active precision-first design. |
| `allocation_utility` | finite float or null | Always null for the active precision-first design. |
| `trigger_snapshot_sha256` | 64-hex string or null | Always null for the active precision-first design. |
| `group_id` | nonempty string | Exact split-group identity. |
| `selection_timestamp` | RFC 3339 timestamp | Immutable selection freeze time. |
| `design_sha256` | 64-hex string | Sampling-design contract identity. |
| `split_manifest_sha256` | 64-hex string | Frozen split identity. |
| `source_artifact_sha256s` | object | Full hashes for normalized and historical context inputs. |

Rows sort by `source_record_number`, then cohort and phase. TRAIN/VALIDATION
rows are public. TEST selection rows are private; the public bundle contains
only the predeclared design contract and non-label TEST seal fields.

P0/P1 use seed `21012100`, VALIDATION uses `21012101`, VALIDATION purpose
assignment uses `21012102`, P2A fixed coverage uses `21012103`, and P2B fixed
coverage uses `21012104`.
For fixed P0/P1 stratum selection, the through-P1 combined probability is
`p0_h + (1 - p0_h) * p1_h`, where `p0_h` is the P0 stratum probability and
`p1_h` is the P1 conditional probability among remaining stratum records.
Active P2 cumulative probabilities are computed from the complete frozen
label-blind sequential design; TRAIN design weight remains null because TRAIN
is development-only. The TEST Custodian generates a 32-byte
cryptographic random seed once, records it only in the private manifest, and
publishes only its SHA-256 commitment. Selection remains reproducible from the
sealed private inputs.

## 20. Evaluation Estimand

### Populations

- **Source dataset:** all frozen 100,000 records. No primary performance claim
  applies to this population.
- **Target population:** all annotation units in the deterministic locked TEST
  split.
- **Evaluation sample:** the 1,500 probability-selected TEST units.
- **Resolved active proxy domain:** sampled units with ATTACK/BENIGN
  `PRECISION_FIRST_PROXY_LABEL`, `HIGH_CONFIDENCE_PROXY`, valid deterministic
  rule/context history, a passing leakage audit, and private
  `precision_proxy_test_reference_eligible=true`.
- **Confirmatory primary domain:** sampled units with ATTACK/BENIGN labels from
  a master-approved primary-eligible provenance tier and valid immutable
  history; AI-only labels never enter this domain.
- **Excluded domain:** UNCERTAIN, unavailable/insufficient evidence,
  partial/conflicting rules, invalid context/history/leakage audit, and
  provenance ineligible for the evaluated domain.

### Historical proxy and confirmatory estimands

For each frozen candidate, the active proxy-reference estimand is
design-weighted average precision for proxy ATTACK ranking in the resolved
active proxy domain of the locked TEST frame, using raw TEST label-selection
weights. It is named
`WEIGHTED_AVERAGE_PRECISION_HIGH_CONFIDENCE_PROXY_REFERENCE_TEST`.

The master-plan confirmatory estimand remains
`WEIGHTED_AVERAGE_PRECISION_RESOLVED_ELIGIBLE_TEST` and is `UNAVAILABLE` when
the TEST labels have only precision-first proxy provenance. Proxy labels never
silently satisfy that estimand.

The active estimand is a conditional high-confidence proxy-reference estimand. It
measures agreement with the frozen proxy-labeling methodology and does not
establish independent real-world truth. It does not estimate
performance for unresolved units, the full TEST frame without assumptions, or
the 100,000-record dataset. Sampling weights address unequal label selection;
they do not correct non-random resolvability or deterministic split assignment.

The active proxy paired estimand is the difference in that metric between frozen
S1 baseline and its corresponding frozen S1 chained pipeline on identical
eligible TEST rows and weights. Under Branch A the chain uses U1; under Branch
B it uses U1 plus valid U2; under Branch C the comparison is `UNAVAILABLE`.

## 21. TRAIN / VALIDATION / TEST Architecture

### Chronology decision

Time-aware splitting is rejected for version 1. Timestamp meaning and ordering
remain unverified. Raw time values are preserved and are not used for split
allocation or generalization claims. Their sole ordering use is the frozen,
unit-neutral, strict-lower same-session context relation in Section 9; no
wall-clock or chronology claim follows from it.

Checkpoint 2.1B observed `itime_raw` on 99,999 rows, one missing value, and
2,789 file-order reversals. Those observations do not establish chronology and
do not change `NON_TEMPORAL_UNVERIFIED_TIMESTAMPS`.

### Split proportions

Target record shares are:

```text
TRAIN      70%
VALIDATION 15%
TEST       15%
```

The target, global tolerance, and eligible-stratum tolerance remain exactly
70/15/15, +/-2.0 percentage points, and +/-5.0 percentage points. The observed
miss described below does not relax or reinterpret any threshold.

### Execution-discovered blocker and amendment scope

The approved fallback execution produced this evidence before labeling:

| Tier / draft | Groups | Largest group | Result |
|---|---:|---:|---|
| `ENTITY_ALL_ENDPOINTS` | 2 | 99.896% | `INFEASIBLE` |
| `ENTITY_SOURCE_HOST` | 17 | 99.896% | `INFEASIBLE` |
| `HARD_GROUP_ONLY` frame | 41,123 over 100,000 rows | 113 rows / 0.113% | Structurally eligible |

The predecessor `HASH_BUCKET_GROUP_ASSIGNMENT_V1` draft assigned 28,835 groups
and 69,611 rows to TRAIN, 6,169 groups and 15,203 rows to VALIDATION, and 6,119
groups and 15,186 rows to TEST. Group exclusivity, group-count, largest-group,
global-share, minimum-row, duplicate, near-duplicate, session, hard-group, and
non-temporal checks passed. Only eligible-stratum balance failed:
`HISTORICAL_TOP_5` contained 4,259 rows, with 2,708 / 63.583% in TRAIN and 895 /
21.014% in TEST. Against the achieved global TRAIN and TEST shares, those are
-6.028 and +5.828 percentage points, outside the approved +/-5.0 limit.

For approval-history reproducibility, V1 assigned each whole group from the
first eight bytes of SHA-256 over canonical JSON
`["stage-2.1-split-v1", 21012026, group_id]`, interpreted unsigned big-endian
modulo 10,000: `0..6999` TRAIN, `7000..8499` VALIDATION, and `8500..9999` TEST.
That rule is historical evidence only and cannot select the amended split.

The predecessor draft is not authoritative and must not be published or used
downstream. Amendment V2 changes only `HARD_GROUP_ONLY` allocation. The two
entity-tier failures and their human fallback approvals remain immutable
provenance.

### Label-blind HARD_GROUP_ONLY allocation contract

`HARD_GROUP_STRATIFIED_GREEDY_REPAIR_V2` uses namespace
`stage-2.1-hard-group-stratified-v2` and seed `21012026`. The seed is used only
for deterministic SHA-256 tie-breaking. There is one run, no seed search, and
no retry with alternate parameters.

The allocator may read only frozen pre-label fields: hard-group membership,
group size, Section 17 sampling-stratum membership, source/group identities,
and the approved split targets and thresholds. It must not read any human
label, reviewer/adjudication result, review yield, supervised prediction, TEST
label, or label-derived summary. Historical anomaly/rule context remains a
balancing stratum only: sampling stratum is not ground truth.

#### Group-level input and eligible balancing strata

Create one row per `HARD_GROUP_ONLY` `group_id`, sorted only as specified below,
with:

- `group_id` and sorted-member identity SHA-256;
- `group_size = n_g`;
- one integer count `c_g,h` for each of the six Section 17 strata, in frozen
  stratum order; the six counts must sum to `n_g`; and
- `group_order_digest`: SHA-256 of canonical JSON array
  `[allocation_namespace, allocation_seed, group_id]`.

Let `N` be total rows and `N_h` the total rows in stratum `h`. The eligible
balancing set is exactly `B = {h: N_h >= 100}`. All six counts remain recorded,
but only strata in `B` enter the balance objective and +/-5.0-point gate.
Groups may contain multiple strata and always move as indivisible vectors.

#### Target matrix and exact arithmetic

For splits `s` in frozen order TRAIN, VALIDATION, TEST, let
`p_s = 0.70, 0.15, 0.15`. Define real-valued targets:

```text
T_s   = p_s * N
T_h,s = p_s * N_h  for every h in B
```

All comparisons use integer counts and exact rational arithmetic; binary
floating-point rounding may not decide assignments or ties. For a complete
assignment, `A_s` is its split row count, `A_h,s` its stratum/split row count,
and `K_s` its group count. The approved gates are:

```text
abs(A_s / N - p_s) <= 0.02
abs(A_h,s / N_h - A_s / N) <= 0.05  for every h in B and split s
K_s >= 75
A_VALIDATION >= 1500
A_TEST >= 1500
```

The stratum gate remains relative to the achieved global split share, matching
the criterion used to identify the execution blocker. The fixed target matrix
drives construction and residual minimization; it does not replace that gate.

#### Constraint priority and objective

Whole-group, exact-duplicate, near-duplicate, session, and hard-component
isolation are absolute admissibility constraints and can never be traded for a
better objective. Before allocation, fewer than 500 groups or a largest group
above 10% of `N` immediately returns `HARD_GROUP_ONLY: INFEASIBLE`.

For a complete assignment define the following lexicographic objective, using
exact rationals:

1. `M_count`: the number of failed conditions among the three `K_s >= 75`
   checks and two 1,500-row VALIDATION/TEST checks; and
   `M_amount = sum_s max(0, 75-K_s)/75 +
   max(0, 1500-A_VALIDATION)/1500 + max(0, 1500-A_TEST)/1500`;
2. `G_count`, `G_max`, `G_sum`: count, maximum, and sum of global excesses
   `max(0, abs(A_s/N - p_s) - 0.02)`;
3. `H_count`, `H_max`, `H_sum`: count, maximum, and sum of eligible-stratum
   excesses `max(0, abs(A_h,s/N_h - A_s/N) - 0.05)`, with all three defined
   as zero if `B` is empty; and
4. `R`: residual target deviation
   `sum_s abs(A_s/N - p_s) + (1/|B|) * sum_h,s abs(A_h,s/N_h - p_s)`, with the
   second term defined as zero if `B` is empty.

`J = (M_count, M_amount, G_count, G_max, G_sum, H_count, H_max, H_sum, R)`
is minimized lexicographically. This freezes priority as: isolation, minimum
split feasibility, global tolerance, eligible-stratum tolerance, then residual
imbalance.

#### Deterministic initial assignment

1. Order groups by descending
   `max(n_g/N, max(c_g,h/N_h for h in B))`, with the inner maximum defined as
   zero if `B` is empty, then descending `n_g`, ascending `group_order_digest`,
   then exact `group_id` UTF-8 bytes.
2. For each group in that order, evaluate assignment to each split. Reject a
   candidate if, after that assignment, the remaining group count is less than
   `sum_s max(0, 75 - K_s)` or remaining rows are less than
   `max(0, 1500 - A_VALIDATION) + max(0, 1500 - A_TEST)`.
3. Among remaining candidates minimize, in order: maximum and sum of
   `abs(A_s/N - p_s)` over splits, maximum and sum of
   `abs(A_h,s/N_h - p_s)` over `h in B` and splits, then SHA-256 of canonical
   JSON array `[allocation_namespace, allocation_seed, group_id, split]`.
   Final ties use frozen split order.
4. Assign the whole group. If no candidate survives, terminate
   `HARD_GROUP_ONLY: INFEASIBLE`.

#### Bounded deterministic repair

If the initial assignment fails any approved gate, run at most 512 repair
iterations. Each iteration evaluates:

- every whole-group move to either other split; and
- for each unordered split pair, every swap in the Cartesian product of up to
  32 frontier groups per side. A side's frontier is the 32 groups with the
  smallest exact `J` after a hypothetical move to the paired split, ties by
  `group_order_digest` then `group_id`.

Moves/swaps may change only `split_assignment`; they may not alter group
membership, strata, targets, thresholds, labels, time policy, or any contract.
Rank candidate actions by resulting `J`, then by SHA-256 of canonical JSON
array `[allocation_namespace, allocation_seed, repair_iteration, action_type,
sorted_group_ids, source_splits, destination_splits]`, then by exact action
tuple. `action_type` is exactly `MOVE` or `SWAP`; group IDs are sorted and the
source/destination arrays use that same order. Apply exactly one action only
when its `J` is strictly smaller than the current `J`.

Repair terminates immediately with `HARD_GROUP_ONLY: FEASIBLE` when every
approved gate passes. It returns `HARD_GROUP_ONLY: INFEASIBLE` when no strict
improvement exists, the 512-iteration budget is exhausted, or any structural,
provenance, or reproducibility check fails. Infeasibility does not authorize a
new grouping tier, changed target, relaxed tolerance, split group, alternate
seed, or label-informed assignment; another human methodology decision is
required.

No row moves after the amended split freezes. Label insufficiency permits only
the frozen review-phase actions and never permits resplitting. Balancing the
TEST frame with pre-label strata does not authorize access to TEST labels,
predictions, class counts, or label-derived summaries.

### Relationship to historical split

Historical Stage 1.7 REFERENCE/HOLDOUT remains historical metadata only. It
does not constrain, replace, or validate the Stage 2.1 split. Later stages must
regenerate fitted feature state under this new split.

## 22. Group / Entity Isolation

### Hard grouping

Union records into one hard component when any condition holds:

1. exact decoded 58-field `source_record` canonical JSON SHA-256 is equal;
2. a nonempty exact `session.identifier` is equal; or
3. the near-duplicate signature below is equal.

Opaque strings are compared byte-for-byte after JSON decoding. Do not trim,
case-fold, parse as IP/MAC, or infer topology.

The near-duplicate signature is SHA-256 of canonical JSON containing this exact
ordered projection, with nulls retained:

```text
stage-2.1-near-duplicate-v1
event.type_source
event.subtype_source
event.action_source
event.severity_source
network.protocol_number
network.source.identifier
network.source.port
network.destination.identifier
network.destination.port
application.service_source
session.sent_bytes
session.received_bytes
session.sent_packets
session.received_packets
session.duration_raw_value
host.identifier
threat_observations.action_source
threat_observations.name_source
threat_observations.severity_source
threat_observations.type_source
threat_observations.pattern_source
threat_observations.id_raw
threat_observations.reference_source
```

It intentionally excludes record/log IDs, source event ID, time values, and
session ID. Equality is exact; version 1 uses no fuzzy distance threshold.

### Candidate entity tiers

Starting from hard components, test these tiers in order:

1. `ENTITY_ALL_ENDPOINTS`: union components sharing any nonempty exact source,
   destination, or host network identifier across roles;
2. `ENTITY_SOURCE_HOST`: union components sharing any nonempty exact source or
   host identifier; and
3. `HARD_GROUP_ONLY`: no additional entity union.

All source/destination/host overlaps remain audited even when a weaker tier is
selected.

### Measurable feasibility

A tier is feasible only when its predeclared allocation satisfies all of:

- every group appears in exactly one split;
- no group exceeds 10% of all frame rows;
- at least 500 allocation groups exist overall and at least 75 groups land in
  each split;
- each actual split share is within 2.0 percentage points of its target;
- for each nonempty sampling stratum with at least 100 rows and each split,
  `A_h,s/N_h` is within 5.0 percentage points of that split's achieved global
  share `A_s/N`;
- VALIDATION and TEST each contain at least 1,500 records; and
- no exact, near-duplicate, or session component crosses splits.

Class feasibility is intentionally not used to choose a split because labels
are unavailable and must not move rows. After review, class/group support is a
sufficiency gate only.

Use the strongest feasible tier. If `ENTITY_ALL_ENDPOINTS` fails, stop and
obtain explicit human approval before accepting `ENTITY_SOURCE_HOST`. If that
tier fails, stop again before accepting `HARD_GROUP_ONLY`. If the hard tier
fails, Stage 2.1 is blocked and this plan must be revised. A weaker approved
tier prohibits new-entity generalization claims for entity types that overlap.
For this amendment, the approved `HARD_GROUP_ONLY` tier uses only the Section
21 V2 allocator. Source, destination, and host entity overlap remains permitted
and must be separately measured by role; neither the split nor later reporting
may claim entity-disjoint evaluation.

`group_id` is `G-` plus SHA-256 of canonical JSON containing the selected tier,
group-contract version, and sorted member source-record identities.

## 23. Split Manifest

The amended authoritative JSON Lines schema is `stage_2_1_split/1.1`. Version
1.0 remains approval history for the rejected predecessor draft and cannot be
published as the Stage 2.1 split:

| Field | Type | Contract |
|---|---|---|
| `schema_version` | string | `1.1`. |
| `plan_amendment_id` | string | Exactly `S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2`. |
| `dataset_sha256` | 64-hex string | Frozen input. |
| `source_record_number` | positive integer | Unique, strictly ascending. |
| `source_record_id` | nonempty string | Unique exact opaque ID. |
| `source_record_identity_sha256` | 64-hex string | Section 8 identity. |
| `annotation_unit_id` | nonempty string | One-to-one unit identity. |
| `split_assignment` | enum | `TRAIN`, `VALIDATION`, `TEST`. |
| `selected_group_tier` | enum | Three candidate tier values. |
| `group_id` | nonempty string | Selected allocation component. |
| `hard_component_id` | nonempty string | Union of exact/near/session edges. |
| `exact_duplicate_id` | 64-hex string | Exact decoded record digest. |
| `near_duplicate_id` | 64-hex string | Frozen projection digest. |
| `session_group_id` | string or null | Dataset-scoped hash; raw session token omitted. |
| `entity_source_id` | string or null | Dataset-scoped hash. |
| `entity_destination_id` | string or null | Dataset-scoped hash. |
| `entity_host_id` | string or null | Dataset-scoped hash. |
| `time_policy` | enum | Exactly `NON_TEMPORAL_UNVERIFIED_TIMESTAMPS`. |
| `time_value_present` | boolean | Structural audit only. |
| `split_reason` | enum | Exactly `HARD_GROUP_STRATIFIED_GREEDY_REPAIR`. |
| `allocation_algorithm` | enum | Exactly `HARD_GROUP_STRATIFIED_GREEDY_REPAIR_V2`. |
| `allocation_version` | string | Exactly `2.0`. |
| `allocation_namespace` | string | Exactly `stage-2.1-hard-group-stratified-v2`. |
| `allocation_seed` | integer | `21012026`. |
| `allocation_parameters_sha256` | 64-hex string | Full hash of targets, tolerances, ordering, frontier sizes, and iteration budget. |
| `allocation_objective_sha256` | 64-hex string | Full hash of the exact-rational objective contract. |
| `balancing_strata_sha256` | 64-hex string | Full hash of ordered eligible strata and totals. |
| `group_balance_vector_sha256` | 64-hex string | Full hash of `group_id`, size, and six-stratum count vector. |
| `group_order_digest` | 64-hex string | Section 21 deterministic group-order digest. |
| `initial_split_assignment` | enum | TRAIN, VALIDATION, or TEST before repair. |
| `final_assignment_action` | enum | `INITIAL_GREEDY`, `REPAIR_MOVE`, or `REPAIR_SWAP`. |
| `repair_iteration` | integer `>=0` | Zero if unchanged after greedy assignment; otherwise final action iteration. |
| `assignment_action_sha256` | 64-hex string | Hash of the deterministic action that produced the final assignment. |
| `sampling_frame_eligible` | boolean | True for every reconciled row. |
| `leakage_check_status` | enum | `PASS` only in published manifest. |
| `source_artifact_sha256s` | object | Full source hashes. |

Entity IDs use SHA-256 of canonical dataset-scoped exact tokens and never
expose raw opaque values. Manifest identity is its complete file SHA-256. It is
immutable after publication and consumed unchanged by all later stages.

`reports/group_leakage_audit.json` additionally records the selected grouping
strategy, allocator algorithm/version/namespace/seed, all allocation
parameters, exact objective, eligible balancing strata, target matrix, initial
and final split row/group counts and proportions, per-stratum target and
achieved proportions, every repair action plus iteration summary, termination
reason, every feasibility criterion/result, human fallback approvals,
predecessor grouping failures, rejected V1 draft measurements, entity overlaps
by role, temporal-policy evidence, all source/contract/artifact SHA-256 values,
and overall `FEASIBLE` or `INFEASIBLE` status. These fields and the manifest
must reproduce the final assignment from frozen inputs without TEST-label
access.

## 24. Private TEST Isolation

Two separate versioned handoffs are required:

- Public development bundle:
  `data/processed/stage_2_1_public_v1/`.
- Private logical identity exposed outside the private manifest:
  `custodian://security-log-intelligence/stage_2_1/test/v1`.

The private physical root is supplied and verified only through the Section
16A Custodian-controlled environment mechanism. It is outside the repository,
`data/processed/`, and every Stage 2.2–2.4 readable or mounted root. It uses
owner-only permissions and a separate backup under the same custody policy.
The physical path must not appear in this public contract's generated
artifacts, manifests, TEST seal, validation/status logs, errors, chat, or
downstream configuration.

Private contents include TEST precision-first evidence packages, rule
decisions and label history/projection, optional human-upgrade histories when
used, TEST sampling manifest and seed,
label-derived sufficiency, validation detail, and private manifest. Public
contents include TEST record identities in the split manifest and a
non-revealing seal only. They include no TEST label, selected-label identity,
class count, resolution count, provenance count, weight, or gate status.

Stages 2.2–2.4 run with the private root unmounted and OS read/list permission
denied. Knowing the proposed path does not grant access. A denied-access test
must prove both direct reads and recursive discovery fail.

## 25. TEST Seal

`contracts/test_seal.json` is public, immutable, and uses schema
`stage_2_1_test_seal/1.0` with exactly:

- `schema_version = '1.0'`;
- `seal_id`: `TS-` plus full seal-payload SHA-256;
- `dataset_sha256`;
- `split_manifest_sha256`;
- `test_frame_record_count`;
- `planned_test_review_count = 1500`;
- `private_bundle_id`: opaque logical ID, not a path;
- `private_manifest_sha256`;
- `private_bundle_payload_sha256`;
- `private_artifact_count`;
- `test_seed_commitment_sha256`;
- `hash_algorithm = 'SHA-256'`;
- `canonicalization = 'UTF-8_SORTED_KEYS_COMPACT_LF'`;
- `created_at`: RFC 3339 offset timestamp;
- `custodian_id = 'CUSTODIAN_TANAWAT_V1'`;
- `opening_state = 'SEALED'`;
- `opening_policy_sha256`; and
- `private_location_disclosed = false`.

Safe public counts are only TEST frame size, planned review budget, and private
artifact count. Actual selected/completed/resolved counts, class/provenance
totals, effective sample size, prevalence, and label-derived status remain
private.

`private_bundle_payload_sha256` hashes the canonical sorted list of private
logical artifact ID, file SHA-256, and byte size. The list excludes the
manifest to avoid circular hashing. The completed private manifest is then
hashed and bound by the seal. The immutable seal always says `SEALED`; Stage
2.5 creates a separate opening audit rather than editing it.

## 26. TEST Custodian

The named human Custodian is `Tanawat`, role ID
`CUSTODIAN_TANAWAT_V1`. While serving this role, Tanawat must not perform or
direct candidate selection, threshold selection, or content-level TEST
prediction inspection. The role is separate from every AI Execution Agent and
owns:

- Section 16A acknowledgement, private-root environment configuration,
  permissions, backup, and non-public path registry;
- local generation and custody of the exact 32-byte TEST seed, publication of
  only its raw-byte SHA-256 commitment, and TEST selection execution or
  supervision;
- private TEST AI-labeling execution/access and evidence delivery;
- private artifact and public seal verification;
- opening authorization and one-time release to Stage 2.5; and
- append-only access/opening audit.

Opening requires all model, transformation, calibration, threshold, and TEST
prediction hashes to be frozen; all prior validators to pass; Stage 2.5 plan
approval; unchanged seal identities; and one explicit dated human
authorization referencing those hashes.

Any unapproved list/read/copy, leaked class-like summary, manual prediction
inspection, label access by a model-selection actor, or seal mismatch is an
invalid opening. It blocks clean locked proxy-reference or confirmatory
evaluation and requires a human
incident decision. The AI Execution Agent cannot grant, infer, or simulate
authorization.

## 27. Public Input Allowlist

Consumers must open exact paths from a signed/hash-bound allowlist. Recursive
discovery, directory globs, symlinks, and undeclared files are prohibited.

Common files allowed to all Stage 2.2–2.4 consumers are:

```text
contracts/evaluation_charter.json
contracts/transformation_protocol.json
contracts/annotation_contract.json
contracts/precision_first_proxy_policy.json
contracts/precision_first_rule_registry.json
contracts/test_seal.json
manifests/split_manifest.jsonl
reports/group_leakage_audit.json
reports/sufficiency_public.json
manifests/stage_2_1_public_manifest.json
```

Purpose-specific additions are:

| Consumer | Additional allowed files |
|---|---|
| Stage 2.2 | `labels/validation_u_resolved_labels.jsonl`; `sampling/validation_u_sampling_manifest.jsonl` |
| Stage 2.3 | `labels/train_resolved_labels.jsonl`; `labels/validation_s_resolved_labels.jsonl`; `sampling/train_sampling_manifest.jsonl`; `sampling/validation_s_sampling_manifest.jsonl` |
| Stage 2.4 | `labels/train_resolved_labels.jsonl`; `labels/validation_chain_resolved_labels.jsonl`; `sampling/train_sampling_manifest.jsonl`; `sampling/validation_chain_sampling_manifest.jsonl` |

Full development histories and audit artifacts exist in the public Stage 2.1
bundle for Stage 2.1 validation but are not consumer inputs.

Each consumer validator must reject:

- any absolute/private path or `custodian://` URI;
- any private manifest, TEST sampling manifest, TEST review artifact, or TEST
  label field;
- any public label row whose `split_assignment` is `TEST`;
- fields named or semantically equivalent to TEST class, provenance,
  resolution, sufficiency, or label-derived gate summaries;
- symlinks, hard-link aliases outside the public root, path traversal, unknown
  files, duplicate JSON keys, and hash mismatch; and
- an allowlist whose own SHA-256 is not bound by the public manifest.

Discovery of a prohibited artifact fails closed before model code runs.

## 28. Pre-Opening TEST Policy

Before Custodian authorization, automated validators may inspect TEST
prediction artifacts only for:

- exact schema and version;
- expected row count and unique public TEST identities;
- complete join coverage against the split manifest;
- required null/missingness constraints;
- finite numeric values and declared numeric ranges;
- canonical ordering/serialization;
- file size and full SHA-256; and
- frozen model/configuration/threshold lineage.

Validator output is limited to PASS/FAIL, counts already public from the split,
error codes without prediction values, and hashes. It must not output or permit
manual inspection of score distributions, quantiles, ranks, top/bottom rows,
alert/predicted-positive volume, class-like clusters, examples, feature
attributions, or aggregate prediction values. Access logs must prove no other
operation occurred.

## 29. Defect Recovery Policy

### Mechanical defect

A mechanical defect is transport, truncation, encoding, ordering, or
serialization corruption whose repair provably leaves source rows, feature
values, learned state, scores, thresholds, and per-row decisions unchanged.
Examples are a truncated copy, noncanonical key order, or damaged container
with an intact independently verified canonical payload.

- Before opening: repair into a new version, rerun all structural validators,
  freeze new hashes, and update the pre-opening freeze record. No TEST attempt
  is consumed.
- After opening: repair only when canonical per-row score/decision hashes are
  identical. Custodian approval and a versioned audit are required. Otherwise
  classify as model-changing.

### Model-changing defect

A defect is model-changing when correction alters data interpretation,
membership, labels, features, fitted state, model/configuration, calibration,
threshold, score, or any per-row decision. Examples include wrong feature
state, leaked rarity maps, wrong join, label correction, threshold bug, or
missing rows that change model output.

- Before opening: invalidate predictions, correct under a new version, rerun
  selection only within unused charter budget, and refreeze. Human approval is
  required if budget or contract changes.
- After opening: the TEST attempt is consumed and cannot support a clean
  confirmatory claim for the corrected system. Stop, preserve all artifacts,
  and obtain explicit human approval for a new evaluation design or an
  exploratory-only report.

Unauthorized TEST access is never a mechanical defect. It consumes the clean
opening and triggers the same stop rule as a post-opening model-changing defect.

## 30. Evaluation Charter

`contracts/evaluation_charter.json` uses schema
`stage_2_1_evaluation_charter/1.2`. It freezes these exact decisions before
Stage 2.2:

| Charter field | Frozen value or rule |
|---|---|
| `confirmatory_primary_estimand_id` | `WEIGHTED_AVERAGE_PRECISION_RESOLVED_ELIGIBLE_TEST`; unavailable when stronger primary-eligible TEST provenance is absent. |
| `active_proxy_estimand_id` | `WEIGHTED_AVERAGE_PRECISION_HIGH_CONFIDENCE_PROXY_REFERENCE_TEST`. |
| `target_population` | Deterministic locked TEST split. |
| `evaluation_population` | Probability-selected, resolved, `HIGH_CONFIDENCE_PROXY`, precision-proxy-test-reference-eligible ATTACK/BENIGN TEST units. |
| `primary_metric` | Design-weighted average precision with ATTACK as positive class and higher score meaning more ATTACK-like. |
| `primary_comparison` | Paired S1 baseline minus/versus corresponding S1 chain on identical rows; Branch A uses U1, Branch B uses U1+U2, Branch C is unavailable. Report chain-minus-baseline delta. |
| `secondary_metrics` | Precision, recall, F1, accuracy, ROC-AUC, separately named descriptive trapezoidal PR-AUC, TP/FP/TN/FN, confusion matrix, predicted-positive rate, coverage; unweighted versions are descriptive only. |
| `active_proxy_eligible_provenance` | Exactly `PRECISION_FIRST_PROXY_LABEL` with `HIGH_CONFIDENCE_PROXY`, valid Section 16C rule/context history, and a passing label-source exclusion audit. |
| `confirmatory_eligible_provenance` | `EXTERNAL_CONFIRMED`, `HUMAN_ANALYST_ADJUDICATED`, and qualifying `AI_ASSISTED_HUMAN_VERIFIED`; never AI-only proxy. |
| `required_claim_language` | Exactly `evaluation against high-confidence proxy reference labels` for active-path metrics. |
| `weighting` | Raw reciprocal combined label-selection probability; no active-proxy or confirmatory weight trimming/post-stratification. |
| `uncertainty_unit` | Selected split group within sampling stratum. |
| `uncertainty_method` | Paired stratified group bootstrap, 2,000 replicates, seed `21012500`, percentile 95% intervals, preserving raw design weights. Sample selected groups with replacement inside each sampling stratum and carry all sampled rows from each group. If a contributing stratum has fewer than two groups or either class has fewer than 30 groups overall, report the interval unavailable; do not pool strata post hoc. |
| `multiplicity` | One unadjusted primary 95% interval. For secondary primary-metric comparisons only, compute two-sided paired-bootstrap tail p-values with `(1 + extreme_replicates) / 2001` in each tail, double the smaller tail capped at 1, then apply Holm step-down at familywise 0.05 across U1-vs-U2, S1-vs-S2, and non-primary eligible chain comparisons. Other metrics are descriptive. |
| `validation_design` | Three disjoint purpose cohorts with one batch access each. |
| `threshold_policy` | Maximize weighted F1 on the assigned validation cohort; ties: higher recall, then higher precision, then lower predicted-positive rate, then higher threshold, then configuration hash. |
| `calibration_policy` | Only `NONE` or sigmoid/Platt; choose and fit inside TRAIN group-preserving folds. No VALIDATION/TEST calibration fitting. Probability wording requires successful calibration validation. |
| `unresolved_policy` | Exclude unresolved/UNCERTAIN from binary metrics; report coverage and predeclared sensitivity scenarios. No nonresponse weighting. |
| `test_policy` | One Custodian-authorized opening after all model/prediction hashes freeze; structural checks only before opening. |
| `defect_policy` | Section 29. |

### Tuning budgets

- U1: frozen configuration; zero hyperparameter search.
- U2: at most three candidate families and 12 total configurations, selected
  with group-preserving TRAIN-only CV before one `VALIDATION_U` batch.
- S1: at most two interpretable families and 24 total configurations.
- S2: at most two stronger families and 24 total configurations, only after S2
  sufficiency passes.
- Calibration: `NONE` and at most one sigmoid/Platt configuration per selected
  supervised candidate, fitted/selected inside TRAIN CV.
- Chained architecture: frozen baseline family plus at most eight registered
  anomaly-signal/regularization configurations per eligible branch.
- Development CV uses at most five group-preserving folds. Exact fold count and
  model-family details belong to approved later plans but may not exceed these
  budgets.

For every selection, compare the charter metric first. Exact ties use, in
order: lower configuration complexity, lower measured runtime, fewer new
dependencies, then lexicographically smaller full configuration SHA-256.

### Unresolved sensitivity

If non-binary/unresolved coverage exceeds 20% overall or 30% in any nonempty
sampling stratum, final reporting must retain the conditional estimand and add:

- threshold-metric best/worst assignments of unresolved rows by frozen
  predicted class;
- PR ranking scenarios with all unresolved rows assigned ATTACK and all
  assigned BENIGN, explicitly described as scenarios rather than mathematical
  bounds; and
- resolved-versus-unresolved score-distribution diagnostics only after TEST
  opening.

No sensitivity result promotes the active proxy result to confirmatory truth or
replaces a separately available confirmatory eligible-provenance result.

## 31. Metric Policy

The active proxy headline metric and the unchanged confirmatory primary metric
are weighted average precision, computed as the weighted
stepwise area summary of the precision-recall curve. Implementation must use a
single audited function equivalent to
`sklearn.metrics.average_precision_score(y_true, score, sample_weight=weight)`.
It is reported as `weighted_average_precision`, not mislabeled as a generic
trapezoidal `PR-AUC` value. A descriptive trapezoidal PR-AUC may also be
computed later as `pr_auc_trapezoidal_descriptive`; it never replaces the
registered headline metric.

This remains the registered headline metric for continuous security rankings;
it does not assume or target any class balance. Active-path results remain
high-confidence proxy-reference results. Accuracy remains secondary. No target
performance value is set.

Metrics are undefined and serialized as null with a reason when:

- eligible evaluation has no ATTACK or no BENIGN row;
- either class has zero total design weight;
- a threshold metric denominator is zero; or
- inputs contain nonfinite values, inconsistent score direction, or invalid
  weights.

Low effective sample size does not silently turn a value into zero. The metric
may be reported as descriptive with `support_gate = FAIL`, but no supported
primary claim is allowed.

The required supporting set is weighted and unweighted precision, recall, F1,
accuracy, ROC-AUC, descriptive trapezoidal PR-AUC, TP, FP, TN, FN, confusion matrix, predicted-positive rate,
labeling coverage, resolution coverage, effective sample size, and class/group
support. Weighted confusion cells are labeled non-integer population-domain
estimates; raw counts remain separate.

The uncertainty precision objective is a 95% primary-metric interval half-width
no greater than 0.10 and a paired-delta interval half-width no greater than
0.10. These are claim-precision gates, not desired model performance. They can
only be measured after frozen predictions and TEST opening. Failure limits the
claim to descriptive evidence and never triggers TEST resampling.

## 32. Validation-Use Budget

Validation labels are partitioned before review and never shared across
purposes:

- `VALIDATION_U`: Stage 2.2 U1/U2 selection and anomaly thresholding;
- `VALIDATION_S`: Stage 2.3 S1/S2 final pre-TEST selection and thresholding;
- `VALIDATION_CHAIN`: Stage 2.4 paired baseline/chain architecture and
  threshold confirmation.

Each purpose allows one batch evaluation request after all TRAIN/CV candidates
for that purpose are frozen. A batch may score only candidates within the
charter tuning budget. It returns registered metrics, selected threshold, and
hash-bound selection output. Record-level validation labels must not be used
for manual error analysis or another stage's selection.

An append-only `validation_access_ledger.jsonl` records requester, purpose,
prediction hashes, candidate hashes, opening time, output hash, and consumed
status. A second request, changed candidate after opening, cross-purpose label
read, or manual label inspection invalidates that purpose cohort for
registered proxy or confirmatory selection. Recovery requires a new human-approved pipeline
version; cohorts cannot be reassigned.

All hyperparameter exploration, preprocessing, calibration choice, and feature
selection before the one batch occurs in group-preserving TRAIN-only nested or
cross-validation. VALIDATION never enters fitting or population-derived state.

## 33. Label Sufficiency Gate

All thresholds below are predeclared support gates, not measured results.
For the active path, counts include only resolved proxy ATTACK/BENIGN rows with
`PRECISION_FIRST_PROXY_LABEL`, `HIGH_CONFIDENCE_PROXY`, valid deterministic
rule/context history, a passing label-source exclusion audit, the applicable
precision-proxy eligibility flag, and valid split/sample history. Independent groups use
the selected Stage 2.1 `group_id`. UNCERTAIN contributes to resolution
coverage but never to binary support or fitting.

The numeric thresholds remain unchanged. They authorize only the explicitly
named proxy-supervised branch and proxy-reference evaluation. A separate
confirmatory gate remains `BLOCKED` unless enough labels are later superseded
by master-approved primary provenance.

### Sampling trigger versus model sufficiency

`S1_TRAIN_SUPPORT` and `S2_TRAIN_SUPPORT` contain only their TRAIN row, class,
group, ratio, and dominance criteria below. They are assessed after fixed
labeling and never drive sampling or rule changes. They do not by themselves
authorize a model.

`STAGE_2_3_S1` and `STAGE_2_3_S2` are final model-sufficiency gates. Each
combines its final TRAIN support result with common-quality and assigned frozen
VALIDATION requirements. A failed final gate never authorizes a new phase,
different allocation, replacement record, larger budget, lower quality tier,
or relaxed rule. After Section 18A fixed sampling and canonical labeling,
compute the frozen full gates and emit independent S1/S2 `READY` or `BLOCKED`
statuses. Sampling cannot continue.

S1 and S2 are independent: S1 may be `READY` while S2 is `BLOCKED`. Neither
status is forced to READY merely because proxy labels exist.

VALIDATION and private TEST results are not sampling triggers. Their failure
blocks or limits the corresponding model/evaluation path without changing any
sample.

### Common quality gates

For every applicable TRAIN or VALIDATION cohort:

- deterministic rule-evaluation completion is 100% of structurally valid
  evidence packages; any execution failure is explicit and ineligible;
- resolved-label rate, including resolved UNCERTAIN, is at least 70% overall
  and 50% in each nonempty sampling stratum with at least 20 selected rows;
- every partial/conflicting rule result finalizes as UNCERTAIN and every
  failed/malformed evaluation is explicitly `REVIEW_INCOMPLETE`; neither may
  become binary;
- every probability/weight required by the fixed Section 18A design is valid;
  TRAIN weights remain null only with `development_only=true`;
  `representative_evaluation_eligible=false`; and
- no prohibited-evidence or history violation survives.

### Unsupervised label-guided evaluation gate U

`VALIDATION_U` needs at least 300 eligible binary rows, 60 ATTACK, 120 BENIGN,
50 ATTACK groups, 100 BENIGN groups, weighted ESS at least 250 overall, and
class-specific ESS at least 50. Failure blocks label-guided U selection or
threshold claims but does not block technical label-free U1 work.

### S1 gate

TRAIN requires:

- at least 1,000 eligible binary rows;
- at least 200 ATTACK and 500 BENIGN rows;
- at least 150 ATTACK and 300 BENIGN independent groups;
- minority-class support at least `5 * 36 = 180` rows, already implied by the
  200-row ATTACK floor; and
- no group supplies more than 5% of either binary class; and
- majority-class count divided by minority-class count no greater than 10.

`VALIDATION_S` and `VALIDATION_CHAIN` each require at least 300 eligible binary
rows, 60 ATTACK, 120 BENIGN, 50 ATTACK groups, 100 BENIGN groups, weighted ESS
at least 250 overall, and class-specific ESS at least 50.

### S2 gate

TRAIN requires:

- at least 2,000 eligible binary rows;
- at least 500 ATTACK and 1,000 BENIGN rows;
- at least 350 ATTACK and 700 BENIGN independent groups;
- minority-class support at least `12 * 36 = 432` rows;
- no group supplies more than 2.5% of either class; and
- majority-class count divided by minority-class count no greater than 6.

`VALIDATION_S` requires at least 450 eligible binary rows, 120 ATTACK,
240 BENIGN, 100 ATTACK groups, 200 BENIGN groups, weighted ESS at least 350
overall, and class-specific ESS at least 100.

### Private TEST support gates

The private S1/final-proxy-reference gate requires at least 500 eligible binary rows,
100 ATTACK, 250 BENIGN, 80 ATTACK groups, 160 BENIGN groups, weighted ESS at
least 400 overall, class-specific ESS at least 75, and no group above 5% of
either class.

The private S2 test gate requires at least 650 eligible binary rows,
150 ATTACK, 300 BENIGN, 120 ATTACK groups, 200 BENIGN groups, weighted ESS at
least 500 overall, class-specific ESS at least 100, and no group above 2.5% of
either class.

These private results never enter the public bundle before Stage 2.5. Failure
does not alter sampling; it limits or blocks the corresponding final claim.

## 34. Public / Private Sufficiency Reporting

`reports/sufficiency_public.json` may contain:

- schema/criterion version and full contract hashes;
- TRAIN and purpose-specific VALIDATION `PASS`, `FAIL`, or `INSUFFICIENT` for
  U, S1, S2, and chaining;
- safe aggregate TRAIN/VALIDATION counts, resolution, disagreement, provenance,
  groups, and ESS;
- exact failed criterion IDs and next-stage reasons;
- `test_seal_state = SEALED`; and
- `test_integrity = PASS|FAIL` based only on hash/structure.

It must not contain a TEST eligibility/sufficiency gate status, selected TEST
IDs, TEST class/provenance/resolution totals, TEST ESS, TEST prevalence, or
private path.

Private `reports/sufficiency_test_private.json` contains the same criterion
definitions plus all TEST support counts, ESS, resolution/provenance detail,
and private U/S1/S2/final gate results. It is seal-bound and unavailable until
authorized Stage 2.5 opening.

## 35. UNCERTAIN / Resolution Reporting

Reports must keep these categories separate:

- resolved ATTACK;
- resolved BENIGN;
- resolved UNCERTAIN;
- `EVIDENCE_UNAVAILABLE`;
- `PARTIAL_ATTACK_RULE` or `PARTIAL_BENIGN_RULE`;
- `RULE_CONFLICT` or malformed/failed deterministic evaluation;
- `REVIEWER_NONRESPONSE`;
- `DISAGREEMENT_UNRESOLVED`;
- `REVIEW_INCOMPLETE`;
- proxy-confirmatory exclusions;
- other eligibility exclusions; and
- superseded versions.

Development reporting gives counts and weighted rates overall, by cohort,
sampling stratum, provenance, and split purpose. TEST reporting is private
until opening. Any category below five rows in a human-facing report is
suppressed or combined only for privacy display; machine artifacts retain
exact private counts.

The sensitivity policy in Section 30 is mandatory when unresolved/non-binary
coverage crosses its thresholds. Even below them, the final claim remains
explicitly conditional on the resolved eligible domain.

## 36. Provenance-Stratified Evaluation Contract

Stage 2.5 must be able to reproduce:

1. active metrics using only valid `PRECISION_FIRST_PROXY_LABEL` rows with
   `HIGH_CONFIDENCE_PROXY`, explicitly named `evaluation against
   high-confidence proxy reference labels`;
2. confirmatory primary metrics only when a separate primary-eligible stronger
   provenance population exists; proxy rows never enter it;
3. separate metrics for each stronger eligible provenance tier when both classes and
   minimum 30 rows/25 groups per class exist;
4. strictest-tier `EXTERNAL_CONFIRMED` sensitivity under the gate in Section
   11; and
5. separate detector-direct and historical AI proxy sensitivity, if later
   approved and supported, never merged with the active precision-first proxy
   or confirmatory results.

Every resolved active label therefore preserves provenance, rule-decision and
rule-registry identities, evidence/context references, quality tier,
label-source exclusion identity, human verification state, sampling
probability, group, and eligibility reason. Unsupported strata return null
metrics and explicit support reasons.

## 37. Shared Transformation Protocol

`contracts/transformation_protocol.json` uses schema
`stage_2_1_transformation_protocol/1.0` and separates immutable feature
definition from fitted feature state.

### Feature definition

The ordered schema remains exactly:

```text
protocol_icmp, protocol_tcp, protocol_udp, protocol_other,
src_port_present, dst_port_present,
src_port_well_known, src_port_registered, src_port_dynamic,
dst_port_well_known, dst_port_registered, dst_port_dynamic,
src_port_rarity, dst_port_rarity, service_rarity, service_missing,
log_sent_bytes, log_received_bytes, log_sent_packets, log_received_packets,
log_duration, log_total_bytes, log_total_packets,
sent_byte_share, sent_packet_share,
log_sent_bytes_per_packet, log_received_bytes_per_packet,
sent_bytes_missing, received_bytes_missing,
sent_packets_missing, received_packets_missing, duration_missing,
zero_total_bytes, zero_total_packets,
zero_sent_packets, zero_received_packets
```

Source paths, port classes, natural-log transforms, guarded ratios, finite
fallback values, missingness flags, protocol mapping, unseen-value behavior,
and feature order remain identical to Stage 1.7 schema 1.0. A changed
definition requires a new version and approved paired comparison.

### Population-derived fitted state

The following are fitted state, not definition:

- source-port, destination-port, and service count maps and denominators used
  by `src_port_rarity`, `dst_port_rarity`, and `service_rarity`;
- full and eligibility-filtered feature distributions;
- constant-feature discovery;
- any later scaler, imputer, encoder, selector, resampler, or calibrator;
- anomaly-score reference distributions/CDFs; and
- any model-specific preprocessing statistics.

Historical Stage 1.7 values were fitted on historical REFERENCE rows and are
not authoritative Stage 2.x matrices.

### Fit boundaries

Every fitted state records one `fit_scope`:

- `TRAIN_FULL`: only authoritative TRAIN groups;
- `OUTER_TRAIN`: only the applicable outer-TRAIN groups;
- `INNER_TRAIN`: only the applicable inner-TRAIN groups; or
- `FINAL_TRAIN_CROSSFIT`: only the permitted complement groups for each
  cross-fitted row.

VALIDATION, TEST, outer-held-out, inner-held-out, and the scored row's own
group are excluded as applicable. `FULL_DATASET`, `TRAIN_PLUS_VALIDATION`, and
any TEST-derived state are forbidden.

Each state manifest contains protocol SHA-256, feature-definition SHA-256,
split/fold manifest SHA-256, sorted fit-row/group membership SHA-256, fitted
payload SHA-256, fit scope, parent state, runtime/dependency versions, and all
source artifact hashes. `fitted_state_id` is `FS-` plus SHA-256 of these
canonical identities.

Stage 2.2–2.4 may own fitted state but cannot redefine transformations. Any
scaling, calibration, imputation, selection, or resampling must live inside the
permitted model/fold pipeline. The 36 features remain the immutable candidate
base definition. For the active precision-first supervised branch, the Section
16C label-source exclusion manifest initially denies features 1-16 because
they derive from protocol, port, or service fields used by active rules.
Features 17-36 remain candidates only after the TRAIN-only exact-reconstruction
audit. Stage 2.3 must consume that reduced allowlist unchanged or narrow it
further inside permitted TRAIN/fold boundaries; it cannot restore an excluded
feature. If no adequate non-circular feature set remains, S1 and S2 are
`BLOCKED` without changing labels.

## 38. Leakage Threat Model

| Risk | Owner | Prevention | Validator | Blocking condition |
|---|---|---|---|---|
| Temporal leakage | 2.1 | Non-temporal split; only target plus strictly lower-`itime` same-session context under Section 9; no clock-unit claim. | Timestamp/evidence-policy auditor | Equal/higher-`itime`, other-session, unbounded, or post-cutoff evidence enters a decision. |
| Exact duplicate leakage | 2.1 | Exact decoded-record components stay in one split. | Split component auditor | Exact digest crosses splits. |
| Near-duplicate leakage | 2.1 | Frozen exact near-signature components stay together. | Signature recomputation auditor | Signature crosses splits or contract drifts. |
| Entity leakage | 2.1 | Measured tier hierarchy and overlap reporting. | Entity component/overlap auditor | Selected tier fails thresholds or fallback lacks human approval. |
| Session leakage | 2.1 | Exact nonempty session token union before split. | Session hash auditor | Session group crosses splits. |
| Label leakage | 2.1/2.3 | Default-deny all label/review/provenance fields from matrices. | Feature-column allowlist auditor | Any prohibited field reaches model input. |
| Target leakage | 2.1/2.3 | Versioned label-source exclusion manifest; deny direct/derived rule-source features; TRAIN-only reconstruction audit. | Evidence-to-feature lineage auditor | Direct/derived rule feature or perfect remaining single-feature reconstruction enters active supervised input. |
| Feature leakage | 2.1/2.2–2.4 | Frozen definition; per-scope fitted-state lineage. | Transformation-state auditor | State contains held-out row/group. |
| Future-information leakage | 2.1 | Strict lower-raw-`itime` same-session cutoff, bounded context count, and external timing proof. | Evidence/context auditor | Context violates cutoff/group/count or external evidence cannot be tied to the target cutoff. |
| Rarity/distribution leakage | 2.1/2.2–2.4 | Refit maps/distributions on TRAIN or fold-local populations. | Independent state recomputation | Historical/global/held-out values influence state. |
| Preprocessing leakage | 2.2–2.4 | Put scaling/imputation/selection/calibration inside fit boundary. | Pipeline lineage auditor | Preprocessor sees validation/held-out/test. |
| TEST-label leakage | Custodian/2.1 | Separate unmounted root, seal, allowlists, access audit. | Denied-access and public-bundle auditor | Any TEST label or derivative becomes visible before opening. |
| Annotation incorporation bias | 2.1 | Exact deterministic predicates, source-observation marking, label-source exclusions, and explicit proxy limitation. | Package/rule/provenance auditor | Prohibited model output enters a rule or report omits proxy incorporation limits. |
| Sampling leakage | 2.1 | Freeze all TRAIN/VALIDATION/TEST membership, phases, sizes, and probabilities before the dry run. | Sampling probability auditor | Any membership adapts to label outcome, quality tier, or support count. |
| VALIDATION overuse | 2.1/2.2–2.4 | Disjoint purpose cohorts and one batch access ledger. | Validation ledger auditor | Repeated/cross-purpose access. |
| Split-purpose disclosure | 2.1 | Rule decisions are identical across splits; optional reviewers never see stratum/cohort/order. | Evidence-package field auditor | Split purpose changes rule input or decision semantics. |
| Proxy provenance pooling | 2.1/2.3/2.5 | Separate proxy and confirmatory eligibility flags, inputs, estimands, and claim language. | Label projection/metric auditor | Proxy row enters a confirmatory projection/metric or proxy output is described as ground truth. |
| Chained stacking leakage | 2.3/2.4 | Later outer/inner/full-TRAIN cross-fitting under shared groups. | Stage 2.4 lineage auditor | Scored row/group influences its anomaly signal fit. |

Any blocking condition stops publication or the affected downstream path.

## 39. Artifact Inventory

### Public bundle

Proposed fixed leaf paths under `data/processed/stage_2_1_public_v1/` are:

```text
contracts/annotation_contract.json
contracts/evidence_policy.json
contracts/precision_first_proxy_policy.json
contracts/precision_first_rule_registry.json
contracts/test_custodian_acknowledgement.json
contracts/evaluation_charter.json
contracts/transformation_protocol.json
contracts/consumer_allowlists.json
contracts/test_seal.json
schemas/annotation_unit.schema.json
schemas/review_task.schema.json
schemas/review_event.schema.json
schemas/review_decision.schema.json
schemas/precision_first_evidence_package.schema.json
schemas/precision_first_decision.schema.json
schemas/precision_first_dry_run.schema.json
schemas/label_source_exclusion_manifest.schema.json
schemas/label_record.schema.json
schemas/sampling_manifest.schema.json
schemas/split_manifest.schema.json
schemas/reviewer_registry.schema.json
schemas/external_evidence_registry.schema.json
schemas/no_independent_evidence_declaration.schema.json
schemas/test_custodian_acknowledgement.schema.json
labeling/development_precision_first_evidence_packages.jsonl
labeling/development_precision_first_decisions.jsonl
labels/development_label_history.jsonl
labels/development_resolved_labels.jsonl
labels/train_resolved_labels.jsonl
labels/validation_u_resolved_labels.jsonl
labels/validation_s_resolved_labels.jsonl
labels/validation_chain_resolved_labels.jsonl
sampling/train_sampling_manifest.jsonl
sampling/validation_sampling_manifest.jsonl
sampling/validation_u_sampling_manifest.jsonl
sampling/validation_s_sampling_manifest.jsonl
sampling/validation_chain_sampling_manifest.jsonl
manifests/split_manifest.jsonl
manifests/validation_access_ledger.jsonl
manifests/label_source_exclusion_manifest.json
manifests/stage_2_1_public_manifest.json
reports/group_leakage_audit.json
reports/precision_first_dry_run.json
reports/precision_first_labeling_audit.json
reports/sufficiency_public.json
reports/stage_2_1_validation_summary.json
```

Exactly one additional conditional contract leaf is required:
`contracts/external_evidence_registry.json` or
`contracts/no_independent_evidence_declaration.json`, never both. Both schema
files remain mandatory. `contracts/reviewer_registry.json` and the five
`review/development_*` human-review artifacts are optional and may appear only
when a real Section 16A human-upgrade workflow is activated; empty/fabricated
substitutes are forbidden. The public bundle must not contain the private root,
seed, credentials, restricted physical evidence locations, private labels, or
private sampling details.

### Private bundle

Fixed leaf paths under the Custodian root are:

```text
contracts/private_test_sampling_design.json
labeling/test_precision_first_evidence_packages.jsonl
labeling/test_precision_first_decisions.jsonl
labels/test_label_history.jsonl
labels/test_resolved_labels.jsonl
sampling/test_sampling_manifest.jsonl
manifests/custodian_access_log.jsonl
manifests/stage_2_1_test_private_manifest.json
reports/sufficiency_test_private.json
reports/precision_first_dry_run_private.json
reports/precision_first_labeling_audit_private.json
reports/stage_2_1_test_private_validation.json
```

No file overwrites Stage 2.0. Corrections create matching `v2`, `v3`, and later
public/private bundles and new seals.

## 40. Machine-Readable Schemas

### Common serialization contract

All JSON/JSONL uses UTF-8, LF, sorted object keys, compact separators,
`allow_nan=false`, exact integer preservation, and duplicate-key rejection.
JSONL has no blank lines. Enumerations are case-sensitive. Schema version is
the exact version assigned to each artifact, including label schema `1.2` and
precision-first schemas `1.0`. Unknown fields fail unless a future approved
major/minor contract explicitly permits them.

### Optional human-review schemas

The schemas in this subsection are emitted/used only for the optional future
human-upgrade path. `stage_2_1_review_task/1.0` requires:

- `review_task_id`, `annotation_unit_id`, `review_round`, `review_slot`;
- `blinded_review_id = BR-<full_sha256>`;
- `evidence_package_id` and `evidence_package_sha256`;
- `allowed_operational_fields`: exact typed target-record projection;
- `detector_panel_available`: boolean, with content separately gated;
- `external_evidence_reference_ids`: sorted IDs;
- `forbidden_field_audit_sha256`;
- `assigned_reviewer_id`: pseudonym;
- `state = PENDING`; and
- `created_at`.

It must not contain source record keys visible to the reviewer, split, cohort,
stratum, score, rank, band, model feature, explanation, triage, label, or other
reviewer's decision. A private mapping artifact binds `blinded_review_id` to
source identity; TEST mappings remain private.

#### Review event schema

`stage_2_1_review_event/1.0` requires event ID, task/unit/version, prior state,
new state, actor type, pseudonymous actor ID, event timestamp, reason code,
related decision ID, and previous-event SHA-256. Events sort by unit, label
version, sequence number. The first previous hash is null; all others form a
hash chain.

#### Review decision schema

`stage_2_1_review_decision/1.0` requires decision ID, task/unit/version,
reviewer role (`PRIMARY_REVIEWER` or `ADJUDICATOR`), reviewer pseudonym, decision
label or null, proposed provenance, resolution issue, evidence viewed, detector
panel opened/decisive booleans, rationale, AI-assistance object, package hash,
submitted timestamp, and decision payload SHA-256.

### Historical precision-first schemas

The Section 16C policy, rule-registry, evidence-package,
deterministic-decision, dry-run, label-source exclusion, audit, and
label-projection schemas are authoritative. The evidence schema enforces exact
target/context allowlists, source-observation tags, strict lower-`itime`
same-session cutoff, bounded context, full hashes, and prohibited-field audit.
The decision schema enforces rule/predicate identities, finalization logic,
evidence references, quality tier, provenance, and immutable `PFD-` IDs.
Dry-run and audit schemas separate public development totals from private TEST
details. All reject unknown fields and unapproved versions. Section 16B
schemas are historical and not active bundle requirements.

### Human input schemas

The four Section 16A schemas are authoritative and must be emitted as the four
named JSON Schema files in Section 39. They encode every exact key, type, enum,
constant, pattern, conditional null rule, uniqueness/cardinality rule, and
`additionalProperties=false`. Validation must also recompute registry/payload
IDs and enforce cross-record reviewer/person independence, evidence/declaration
XOR, source-record linkage, full lowercase hashes, all human approvals, and the
Custodian secret-field denylist. Submitted placeholders are invalid.

### Label, sampling, and split schemas

Exact label fields are in Section 12, sampling fields in Section 19, and split
fields in Section 23. JSON Schema files must express those same fields, enums,
required/null rules, patterns, array uniqueness, and `additionalProperties:
false`.

### Contract JSON schemas

Annotation/evidence contracts contain version, master/plan/dataset hashes,
unit/evidence rules, allowed/prohibited field registries, label/provenance
enums, workflow transitions, eligibility rules, and their canonical contract
ID. Evaluation and transformation contracts contain every field specified in
Sections 30 and 37.

### Manifest schema

Each public/private manifest uses `stage_2_1_manifest/1.0` and requires bundle
ID/version, logical root, creation time, source identities, contract hashes,
ordered artifact entries (`logical_id`, relative path, byte size, SHA-256,
schema version, row count or null, confidentiality), runtime identity, and
validation-summary hash. It has no self-hash. The public manifest rejects any
private logical ID/path or TEST label-derived field.

### Remaining critical artifact schemas

| Artifact | Format and ordering | Required top-level fields |
|---|---|---|
| `annotation_contract.json` | Canonical JSON | `schema_version`, `contract_id`, `master_plan_sha256`, `dataset_sha256`, `annotation_unit`, `identity_rules`, `label_semantics`, `provenance_rules`, `eligibility_rules`, `workflow_states`, `workflow_transitions`, `hash_algorithm`. |
| `evidence_policy.json` | Canonical JSON | `schema_version`, `policy_id`, `prediction_point`, `window_basis`, `operational_field_allowlist`, `detector_field_allowlist`, `prohibited_field_registry`, `external_evidence_schema`, `future_information_rule`, `missing_evidence_rules`, `blinding_rules`. |
| `reviewer_registry.json` | Optional canonical JSON; reviewer records sorted by `reviewer_id` | Exact Section 16A registry identity, approval, version, and reviewer records; absent for the active proxy-only path. |
| `external_evidence_registry.json` | Conditional canonical JSON; items sorted by `evidence_id` | Exact Section 16A registry identity, approval, version, and nonempty evidence items. |
| `no_independent_evidence_declaration.json` | Conditional canonical JSON | Exact Section 16A declaration literals, human approval, lineage, and payload hash. |
| `test_custodian_acknowledgement.json` | Canonical JSON | Exact Section 16A public setup/seed commitment/opening-state acknowledgement; secret/path fields forbidden. |
| `precision_first_proxy_policy.json` | Canonical JSON | Section 16C priority, evidence/context, finalization, quality-tier, eligibility, dry-run, leakage, claim-language, amendment, and master identities. |
| `precision_first_rule_registry.json` | Canonical JSON | Exact four rule IDs, ordered predicates, constants/regexes, conflict/UNCERTAIN logic, source paths, and full registry hash. |
| Precision-first evidence-package JSONL | Sort by `annotation_unit_id` | Exact Section 16C target/context fields, cutoff proof, source hashes, prohibited-field audit, and package hash; TEST rows private. |
| Precision-first decision JSONL | Sort by `annotation_unit_id` | Exact Section 16C decision fields and immutable `PFD-` identity; TEST rows private. |
| `precision_first_dry_run.json` | Canonical JSON | Development counts/rates/agreement/conflict/evidence failures and frozen source identities; TEST counterpart remains private. |
| `label_source_exclusion_manifest.json` | Canonical JSON | Every label source/context predicate mapped to all 36 features with lineage class, allow/exclude decision, reason, and hashes. |
| `precision_first_labeling_audit.json` | Canonical JSON | Development-safe rule, quality, provenance, lineage, and replay totals; TEST counterpart remains private. |
| Optional human evidence/review JSONL | Sort by blinded review ID | Existing Section 40 human task/mapping/event/decision schemas; absent unless the upgrade path is active. |
| `consumer_allowlists.json` | Canonical JSON | `schema_version`, public manifest identity, one object per consumer with exact logical IDs/relative paths/schema versions/SHA-256 values, global forbidden logical IDs/field names/path patterns, symlink/path policy. |
| `group_leakage_audit.json` | Canonical JSON | amendment ID; source/group-contract identities; per-tier component/group diagnostics; selected tier and fallback approvals; predecessor failures and rejected V1 measurements; allocator algorithm/version/namespace/seed/parameters/objective; balancing strata and target matrix; initial/final split counts and proportions; per-stratum targets/achieved proportions; ordered repair actions and termination reason; hard-crossing counts; entity overlaps by role; temporal evidence; criterion results; full provenance hashes; overall `FEASIBLE` or `INFEASIBLE`. |
| Validation-access ledger JSONL | Append order; hash chained | request ID, purpose, requester, candidate/prediction hashes, input cohort/label/sampling hashes, opened timestamp, output hash, prior event hash, consumed status. |
| Public sufficiency JSON | Canonical JSON | criterion version/hash, public TRAIN/VALIDATION measurements, U/S1/S2/chain states and reason codes, TEST seal/integrity state only, source hashes. TEST label-derived keys are forbidden. |
| Private sufficiency JSON | Canonical JSON | public criterion identity plus TEST counts by class/group/provenance/resolution/stratum, raw weights, overall/class ESS, private gate results/reasons, private manifest identity. |
| Validation summary JSON | Canonical JSON | command identity, code revision, runtime/dependency versions, input/output hashes, validator status map, measured row/artifact counts, denied-access result, warnings, overall status, completed timestamp. Public summary contains no private TEST semantics/path. |
| TEST private validation JSON | Canonical JSON | same operational proof plus private artifact reconciliation, permission audit, sampling/label/sufficiency validation, seal payload result; remains private. |

Every JSON object uses `additionalProperties: false` at its schema boundary.
Every JSONL row has a dedicated schema and deterministic sort key. Counts and
timestamps are measured execution data; this plan supplies no future values.

## 41. Provenance / Hashing

- Machine-readable artifacts use full lowercase 64-character SHA-256 only.
- Short hashes may appear only in human prose.
- Canonical IDs include a versioned namespace, dataset identity, and exact
  source or parent identities.
- Every artifact entry records relative path, byte size, SHA-256, schema, and
  row count where applicable.
- Raw evidence content is not copied into labels; immutable references and
  hashes preserve provenance.
- The public manifest binds every public contract, schema, report, and
  consumer allowlist.
- The TEST seal binds the private payload and private manifest without listing
  private paths or semantic counts.
- No file hashes itself. Downstream manifests hash completed upstream files.
- Hash mismatch, missing hash, uppercase/short digest, circular identity, or
  path alias fails closed.

## 42. Determinism / Reproducibility

- HARD_GROUP_ONLY split allocator:
  `HARD_GROUP_STRATIFIED_GREEDY_REPAIR_V2`, namespace
  `stage-2.1-hard-group-stratified-v2`, seed `21012026`, one deterministic run,
  32 groups per swap frontier, and at most 512 repair iterations. The rejected
  10,000-bucket V1 result remains provenance only; no seed retry is permitted.
- TRAIN sample seed: `21012100`.
- Fixed P2A/P2B coverage seeds: `21012103` and `21012104`.
- VALIDATION sample seed: `21012101`.
- VALIDATION purpose seed: `21012102`.
- Bootstrap seed: `21012500`.
- TEST seed: exactly 32 raw bytes generated by the human Custodian under
  Section 16A; public commitment is lowercase SHA-256 of those raw bytes only.
- Hash-order ties break by `source_record_number`, then exact
  `source_record_id` UTF-8 bytes.
- Stratum allocation ties use the frozen stratum order.
- Rows use the ordering defined by their schema; object keys are sorted.
- Builders publish from owned same-volume temporary directories only after
  independent audit, using no-replace directory rename.
- Existing destinations, path aliases, escaping links, and partial publication
  fail closed.
- A rerun uses a fresh root and must reproduce all deterministic pre-review
  payload hashes from the same inputs/configuration.
- Precision-first decisions are deterministic. Identical evidence-package,
  rule-registry, policy, exclusion-manifest, and source hashes must reproduce
  identical predicate results, `PFD-` IDs, labels, and quality tiers. Any
  changed input/rule creates a new version and preserves prior history.
- Frozen human histories reproduce by byte/hash verification, not by rerunning
  human decisions.
- TEST selection reproduces only inside Custodian custody from the sealed seed.
- Operational timestamps may change only in new versioned summaries; they are
  never substituted into deterministic source/split/sample IDs.

## 43. Validators

Implementation must provide independent, read-only validators with these
responsibilities:

| Validator | Required proof |
|---|---|
| Contract/schema validator | Exact fields, types, enums, null rules, versions, unknown-field rejection, duplicate-key rejection. |
| Identity validator | 100,000 unique paired source keys; dataset and unit identities recompute exactly. |
| Active-path precondition validator | Precision-first policy/rules/schemas, exclusion manifest, evidence-registry/declaration XOR, HARD_GROUP_ONLY split, Custodian acknowledgement, private status-only verification, raw-byte seed commitment, human approvals, and secret-output denylist all pass before Checkpoint 2.1C; reviewer registry is optional. |
| Evidence/context validator | Exact target allowlist and bounded lower-`itime` same-session context; source observations marked; all prohibited model/pipeline/sampling/36-feature values absent; external registry/declaration valid. |
| Precision-first workflow validator | Four exact rule IDs/predicates, mechanical finalizer, UNCERTAIN closure, one quality tier, immutable `PFD-` outputs, dry-run/canonical replay, no AI call, and no human/external provenance claim. |
| Optional human workflow validator | When invoked, registry-bound humans are eligible/independent and every transition is authorized, ordered, hash-chained, and role-separated. |
| Label-history validator | Versions are monotonic and linear; parents/supersession resolve; final projection reproduces. |
| Provenance/eligibility validator | Only high-confidence precision-first rows enter active proxy flags and never confirmatory projections; UNCERTAIN cannot enter binary fitting. |
| Sampling validator | All phase membership froze pre-label; fixed P0/P1/P2 strata, allocations, seeds, probabilities, non-overlap, isolation, terminal status, and 3,200-record cap recompute without label input. |
| Split/group validator | V2 group vectors, eligible strata, target matrix, exact objective, greedy order, every repair action, final assignment, all thresholds, selected tier, predecessor failures/approvals, entity overlaps, and no-crossing guarantees independently recompute without labels. |
| Evaluation-charter validator | Every required frozen field exists and later budgets cannot exceed charter. |
| Sufficiency validator | Counts, groups, rates, dominance, ESS, and gate states independently recompute. |
| Transformation-protocol validator | Exact 36 names/order/transforms; fitted-state boundaries and forbidden scopes explicit. |
| Label-source exclusion validator | Every active predicate maps to all 36 features; features 1-16 are denied; remaining TRAIN-only reconstruction audit passes; no excluded feature reaches supervised input. |
| Dry-run replay validator | Development report fields recompute, TEST details stay private, and canonical decisions byte-match frozen dry-run decision hashes. |
| Public-bundle validator | Exact active precision/evidence/Custodian contract inventory plus optional human-upgrade artifacts only when valid; no TEST label/derivative, seed, credential, private/restricted physical path, symlink, or unknown file. |
| Private-bundle validator | Status-only configured root, owner-controlled permissions, private identities, TEST histories, sampling, sufficiency, and manifest reconcile under Custodian access without printing location or secrets. |
| TEST-seal validator | Private payload hash, manifest hash, raw-32-byte seed commitment, safe public fields, and immutable SEALED state reconcile. |
| Denied-access validator | Stage 2.2–2.4 execution principals cannot list, stat, read, mount, or discover the private root. |
| Artifact fingerprint validator | Every full SHA-256, byte size, row count, parent identity, and no-overwrite publication condition matches. |
| Claim-language validator | Proxy metrics use `evaluation against high-confidence proxy reference labels`; prohibited truth/confirmation/probability language is absent unless a separately supported stronger tier is reported. |

The implementation must keep builder and auditor expectation sources separate.
An auditor must not import builder-private output state as its expected answer.
Only a complete successful sequence may emit `STAGE 2.1 LOCAL VALIDATION PASS`.

## 44. Test Plan

### Unit tests

- canonical IDs, full hashes, JSON encoding, enums, null rules, and ordering;
- annotation-unit one-to-one mapping and no label propagation;
- precision-first target/context allowlists, strict lower-`itime` same-session
  cutoff, bounded context, source-observation tags, and prohibited-field audit;
- all exact ATTACK/BENIGN predicates and regex captures, partial/conflict to
  UNCERTAIN, `HIGH_CONFIDENCE_PROXY`, `PFD-` identity, and eligibility flags;
- valid/invalid state transitions and actor-role separation;
- append-only version chains and resolved projection;
- optional reviewer eligibility/cardinality/person-binding independence,
  evidence XOR,
  no-evidence consequences, Custodian acknowledgement, and raw-byte seed
  commitment calculations;
- stratum precedence, hybrid allocation, weights, ESS, and gate calculations;
- P0/P1/P2A/P2B fixed allocation, sparse-stratum redistribution, pre-label
  freeze, frame exhaustion, and terminal status;
- required sampling-manifest fields, fixed P2 cumulative probability,
  null TRAIN weight, phase non-overlap, and cumulative TRAIN cap;
- exact/near/session/entity grouping, six-stratum group vectors, V2 greedy
  assignment, lexicographic objective, frontier swaps, and repair termination;
- transformation feature order and fitted-state scope validation; and
- seal payload and manifest hashing without circular identities.

### Contract tests

- each JSON Schema accepts exact valid examples and rejects unknown fields;
- public/private manifests accept only their inventories;
- Stage 2.2/2.3/2.4 allowlists expose only their purpose labels;
- evaluation charter contains every required budget/policy;
- precision-first policy/rules/evidence/decision/dry-run/exclusion/audit schemas
  freeze every key, enum, hash, version, predicate, and cross-field rule;
- all four human-input templates validate only after placeholders are replaced;
- reviewer/evidence/declaration/Custodian schemas enforce exact enums,
  constants, conditional nullability, approvals, uniqueness, and unknown-field
  rejection;
- split/sampling/label rows bind the same source and dataset identities;
- split schema 1.1 and group audit require the amendment, allocator,
  target/achieved balance, repair, predecessor-failure, approval, and full-hash
  provenance fields; and
- full SHA-256 values are mandatory in machine artifacts.

### Negative tests

- infer ATTACK from anomaly rank or Top-50, or from a rule/threat status alone
  or outside the complete Section 16C conjunctions;
- expose anomaly score, anomaly rank, Stage 1.9 explanation/reason, auto-triage,
  suspected behavior, downstream prediction, or 36-feature vector to the
  precision-first decision engine;
- infer BENIGN from a generic start/accept pair, accepted traffic, low
  interest, or no alert without both Section 16C BENIGN functions;
- allow a deterministic decision to claim `HUMAN_ANALYST_ADJUDICATED`,
  `AI_ASSISTED_HUMAN_VERIFIED`, or `EXTERNAL_CONFIRMED`;
- convert a partial ATTACK/BENIGN function, conflict, missing predicate,
  invalid context, or policy-violation deny into ATTACK or BENIGN;
- permit UNCERTAIN, non-high-confidence output, or incomplete evaluation to
  enter binary fitting;
- describe proxy labels/metrics as confirmed ground truth, true attacks,
  analyst-confirmed performance, or attack probability;
- put a TEST label, TEST class total, private path, or private manifest in the
  public bundle;
- expose a TEST proxy decision, TEST proxy label, TEST proxy class count, or
  TEST proxy audit total before authorized opening;
- overwrite a precision-first decision/label on rerun rather than append a
  superseding version;
- submit reviewer and adjudicator roles from the same actor;
- accept duplicate reviewer/person-binding IDs, other than exactly two eligible
  primaries, no distinct adjudicator, missing training/independence
  acknowledgement, blocking conflict, or false/missing human approval;
- accept an unknown evidence enum, empty evidence registry, missing/false
  source-record linkage, malformed evidence SHA-256, both evidence alternatives,
  neither alternative, or an agent-authored evidence/declaration artifact;
- accept malformed seed commitment, non-32-byte private seed, commitment over
  encoded text, Custodian opening state other than `SEALED`, or unapproved
  Custodian acknowledgement;
- expose a seed/encoding, credential, private TEST root, restricted physical
  evidence location, private label, or private sampling detail in any public
  artifact, log, error, chat/status response, or environment snapshot;
- block the active path solely because reviewer registry is absent, or create
  fake reviewer/adjudicator identities;
- continue Checkpoint 2.1C when any required precision-first contract/rule/
  exclusion manifest, evidence alternative, split proof, or Custodian input is
  missing, malformed, conflicting, inaccessible, or unapproved;
- use invalid transition, version gap, fork, duplicate decision, or backdated
  event;
- accept short/invalid hash, duplicate JSON key, NaN/Infinity, or path alias;
- use adaptive VALIDATION/TEST selection or a zero/unknown probability;
- use a label/review/prediction field in split allocation, split a hard group,
  retry another seed, exceed 512 repair iterations, relax +/-2 or +/-5 points,
  change 70/15/15, or publish an infeasible assignment;
- invent a fifth TRAIN phase, select P2 after labels, target a class, change a
  fixed allocation, reuse a previously represented group in P2, or exceed
  3,200 TRAIN rows;
- let sampling stratum, anomaly score, quality yield, support gate, or split
  purpose change a deterministic decision;
- publish canonical labels before the dry-run replay matches, change a rule
  after observing class counts, or expose TEST dry-run counts/status publicly;
- restore any feature denied by the label-source exclusion manifest;
- load Stage 2.2 with any private or purpose-incompatible artifact; and
- publish to an existing destination.

### Leakage tests

- exact, near-duplicate, session, and selected entity groups crossing splits;
- historical Stage 1.7 rarity map used as Stage 2.x state;
- rarity/distribution/scaler/calibrator fitted on held-out, VALIDATION, or TEST;
- prohibited label/review/source-detector field in the supervised matrix;
- equal/higher-`itime`, adjacent-file-row, other-session, over-limit context,
  unrestricted-search, or TEST-derived aggregate evidence in labeling;
- label-source feature 1-16 or any later exact-reconstruction failure in the
  active supervised matrix;
- downstream engineered features containing label/provenance, anomaly rank,
  auto-triage, suspected attack type, or predictions;
- validation purpose reused or opened twice;
- TEST prediction content summarized before opening;
- private root readable/listable by each Stage 2.2–2.4 execution principal; and
- private-root value printed by setup/validation/status code or persisted in a
  public artifact.

### Determinism tests

- repeated frame/group/split/sample construction yields identical canonical
  hashes from the same inputs and seed;
- repeated V2 allocation yields identical group order, greedy assignment,
  objective sequence, repair actions, terminal status, and manifest bytes;
- exact-rational comparison is unchanged across platforms and cannot be
  altered by binary floating-point rounding;
- synthetic feasible, no-improvement, and iteration-budget-exhausted fixtures
  terminate respectively as `FEASIBLE`, `INFEASIBLE`, and `INFEASIBLE`;
- allocation ties and sparse-stratum redistribution are stable;
- fixed P2 coverage produces identical allocations, ordered selections, and
  terminal transitions without reading labels or sufficiency;
- every permitted TRAIN outcome sequence leaves frozen VALIDATION/TEST
  membership, seeds, probabilities, purpose assignments, and seal unchanged;
- independent resolved-view and sufficiency recomputation matches byte-for-byte;
- deterministic rule reruns reproduce identical dry-run/canonical decisions;
  changed rule/input versions append and preserve prior outputs;
- same private seed under Custodian access reproduces TEST selection; and
- fresh no-overwrite bundle builds reproduce every deterministic pre-review
  artifact identity.

### Integration tests

- synthetic full workflow from precision-first package through rule
  evaluation, dry-run replay, finalization, supersession, proxy projection,
  exclusion audit, sufficiency, manifests, and seal;
- real pre-label HARD_GROUP_ONLY inputs reproduce the amended allocation or
  return `HARD_GROUP_ONLY: INFEASIBLE` without opening labels or changing a
  threshold;
- public build plus private Custodian build with matching split and distinct
  roots;
- Checkpoint 2.1C accepts complete precision-first contracts plus exactly one
  evidence alternative, approved split, and Custodian fixture without a
  reviewer registry, and fails closed for every missing/invalid required
  combination before sample creation;
- permitted Stage 2.2–2.4 consumer loads succeed and every forbidden variant
  fails before model execution;
- private TEST bundle tampering breaks the public seal;
- mechanical recovery preserves canonical row decisions; and
- model-changing recovery invalidates the TEST attempt after opening.

Ordinary tests use synthetic fixtures only. Real Stage 2.1 validation reads
approved local artifacts but never modifies upstream evidence or prints private
TEST semantics.

## 45. Pilot Methodology

The 400-record `TRAIN_P0_PILOT` is the designated methodology cohort, not a
class-discovery or sufficiency mechanism. All TRAIN/VALIDATION/TEST sample
membership is already frozen before its outcomes exist. P0 uses the exact
Section 16C deterministic rules and has no AI/human inference step.

The pilot report measures:

- complete deterministic evaluation and structural failures;
- evidence availability and source categories;
- ATTACK/BENIGN/UNCERTAIN yield without treating yield as prevalence;
- provenance/quality-tier and active proxy-eligibility yield;
- ATTACK/BENIGN rule agreement, partial predicates, conflicts, and UNCERTAIN
  closure;
- label-source exclusion results and candidate-feature count;
- reason-code and evidence-field usage;
- class and independent-group support by sampling stratum; and
- observed violations of evidence, context, future-information, or
  detector-proxy rules.

Section 16C also requires the full selected development/private TEST
distribution dry run before canonical publication. A structural/methodology
failure stops publication. Any rule, policy, context, schema, semantic, or
evidence change requires a new human-approved version and complete dry run.
Class yield or S1/S2 failure cannot change the frozen rules, samples, split,
estimand, metric, phase sizes, allocation, or stopping rules.

## 46. Historical FortiGate Implementation Sequence — Closed After Feasibility

The separate Execution Agent must follow these ordered checkpoints. No later
checkpoint starts until its completion condition passes.

### Checkpoint 2.1A — Contracts and schemas

**Inputs:** approved master, approved detailed plan, normalized and historical
contract identities.

**Planned files:**

```text
src/labeling/__init__.py
src/labeling/contracts.py
src/labeling/models.py
src/labeling/identity.py
src/labeling/evidence.py
src/labeling/precision_first.py
src/labeling/eligibility.py
tests/test_stage_2_1_contracts.py
tests/test_stage_2_1_precision_first.py
```

**Work:** encode all enums, schemas, identity formulas, exact evidence/context
and prohibited-field registries, deterministic rule registry/finalizer,
quality tier, immutable `PFD-` decisions, label-source exclusion,
proxy/confirmatory eligibility separation, dry-run replay, and claim-language
rules. Preserve
`src/labeling/workflow.py` only for the optional human-upgrade path. Generate
contract/schema artifacts from one reviewed public definition without letting
auditors import builder-private expected output.

**Validation:** unit/contract/negative tests for Sections 8–16C and schema
round-trips.

**Completion:** precision-first contract/rule payloads are frozen and
human-approved; no label or sample exists and no AI runtime is required.

### Checkpoint 2.1B — Frame, grouping, and split

**Inputs:** strict normalized JSONL, source identity contract, frozen group
rules, approved entity-tier fallback records, amendment
`S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2`, and no label/review/prediction
input.

**Execution-owned files requiring update only after human re-approval (not
modified by this amendment):**

```text
src/labeling/grouping.py
src/labeling/splitting.py
tests/test_stage_2_1_split.py
```

**Work:** preserve the recorded `ENTITY_ALL_ENDPOINTS` and
`ENTITY_SOURCE_HOST` failures and fallback approvals; rebuild and hash the
HARD_GROUP_ONLY group-level six-stratum vectors; reject the V1 bucket draft;
run the exact Section 21 V2 greedy allocator and, only if needed, its bounded
repair; create the immutable split and group audit only on `FEASIBLE`. Do not
read labels, TEST-label derivatives, predictions, or chronology.

**Artifacts:** draft `split_manifest.jsonl` and
`group_leakage_audit.json` in owned staging paths.

**Validation:** independent recomputation of group vectors, eligible strata,
target matrix, exact objective, ordering, assignments, every repair action,
termination, 100,000-row coverage, unchanged 70/15/15 with +/-2 points,
unchanged eligible-stratum balance with +/-5 points, minimum rows/groups,
largest-group limit, no exact/near/session/hard-group crossing, entity overlap,
schema 1.1 provenance, sealed-TEST non-access, and deterministic rerun.

**Completion:** either every approved HARD_GROUP_ONLY criterion passes and the
V2 split/audit hashes freeze, or emit `HARD_GROUP_ONLY: INFEASIBLE`, preserve
all evidence, and stop for another human methodology decision. Execution may
not resume past Checkpoint 2.1C until the current precision-first amendment is
human-approved. Precision-first contracts, one external-evidence/declaration
alternative, and Custodian setup remain Checkpoint 2.1C preconditions under
Sections 16A and 16C; passing 2.1B does not satisfy them.

### Checkpoint 2.1C — Evaluation, transformation, and sampling contracts

**Inputs:** approved feasible HARD_GROUP_ONLY split/audit, historical context
artifacts, Stage 1.7 definition, frozen/human-approved Section 16C policy,
rule registry, evidence/context/decision/dry-run/exclusion schemas, exactly one approved
external-evidence registry or no-independent-evidence declaration, approved
Custodian acknowledgement, and Custodian-only status verification of private
storage plus the 32-byte sealed seed. Reviewer registry is optional.

**Planned files:**

```text
src/labeling/sampling.py
src/labeling/transformation_contract.py
src/labeling/human_inputs.py
tests/test_stage_2_1_sampling.py
tests/test_stage_2_1_transformation.py
tests/test_stage_2_1_human_inputs.py
```

**Work:** run the Sections 16A and 16C active-path precondition before any
sample draw or private artifact creation. Fail closed unless precision-first
contracts/rules,
evidence-registry/declaration XOR, HARD_GROUP_ONLY split, human approvals,
status-only private storage, raw-32-byte seed commitment, and `SEALED` opening
state all validate. Do not require or fabricate reviewer records. Then freeze
the unchanged metric/comparison, validation budget, transformation protocol,
strata, sampling designs, and public/private separation, plus the explicit
proxy-reference estimand/claim scope. Draw TRAIN/VALIDATION and private TEST
samples only after all contracts are frozen. Never print the private root or
seed.

**Artifacts:** precision-first policy/rule registry and schemas; exactly one
evidence registry/declaration; Custodian acknowledgement; sampling manifests,
charter, transformation protocol, annotation/evidence contracts, and consumer
allowlists. Reviewer registry appears only when the optional upgrade path is
actually activated.

**Validation:** Sections 16A/16C active precondition and secret-output denylist;
allocation/probability/weight recomputation, cohort isolation, positive TEST
coverage, exact feature order, and fitted-state boundary tests.

**Completion:** active-path contracts/inputs are immutable, approved,
hash-bound, and complete;
private status is `CONFIGURED`, seed status is `SEALED`, opening state is
`SEALED`, sample identities are immutable, no secret/private location was
disclosed, and no label outcome has been observed. Any failed required input
condition stops before sampling and cannot be replaced by agent judgment.

### Checkpoint 2.1D — Precision-first evidence/context construction

**Inputs:** selected samples, approved evidence alternative, exact Section 9
fields/context window, and Section 16C policy/rule/schema identities.

**Planned files:**

```text
src/labeling/artifact.py
src/prepare_stage_2_1.py
src/prepare_stage_2_1_test.py
tests/test_stage_2_1_precision_first.py
```

**Work:** create separate development and private TEST precision-first evidence
packages, bounded lower-`itime` same-session context, package hashes, and
prohibited-field audits. The TEST command runs only under Custodian credentials
and never logs the physical root.

**Validation:** exact allowlists, context group/direction/count, no future or
unrestricted lookup, source-observation tags, forbidden-field scan, mapping
completeness, package hashes, and public/private denied-access test.

**Completion:** every selected unit has one immutable schema-valid package;
packages contain no prohibited field; TEST packages are private.

### Checkpoint 2.1E — Deterministic distribution dry run

**Inputs:** all frozen TRAIN/VALIDATION evidence packages and the Custodian's
private TEST packages; frozen rules, policy, exclusion manifest, and sampling.

**Work:** run all four Section 16C functions in `DRY_RUN` mode, finalize
ATTACK/BENIGN/UNCERTAIN mechanically, compute required development statistics,
and compute TEST details/status only inside custody. Do not publish canonical
labels and do not alter rules or samples from observed counts.

**Artifacts:** noncanonical decision hashes, public development dry-run report,
private TEST dry-run report, and label-source exclusion audit.

**Validation:** exact predicate/regex/finalizer checks, quality/provenance,
agreement/conflict/evidence-failure formulas, public TEST redaction, fixed
sampling, and leakage audit.

**Completion:** methodology passes, or Stage 2.1 stops for contract revision
and a new human-approved dry run. Class insufficiency alone does not fail the
methodology.

### Checkpoint 2.1F — Canonical precision-first proxy labeling

**Inputs:** passing dry-run evidence and decision hashes; frozen rule registry,
all fixed sample phases, all VALIDATION purposes, and private TEST sample.

**Work:** replay identical deterministic inputs in `CANONICAL` mode and require
every decision hash to match the dry run before appending immutable decisions
and label versions. Custodian controls all TEST evidence, decisions, labels,
audits, and outputs. No AI call, reviewer decision, target-class controller, or
post-yield sampling occurs.

**Artifacts:** complete development and private TEST precision-first
decision/label histories plus separate safe/private audits.

**Validation:** dry-run replay, evidence/context, rule/finalizer, quality,
provenance, exclusion-manifest, state, and history audits; no TEST semantic
output leaves custody.

**Completion:** every task selected by each executed phase is resolved or has
one explicit unresolved terminal status, and one valid terminal TRAIN sampling
status is recorded.

### Checkpoint 2.1G — Resolution and sufficiency

**Inputs:** immutable histories, sampling/split manifests, charter criteria.

**Planned files:**

```text
src/labeling/history.py
src/labeling/sufficiency.py
src/finalize_stage_2_1.py
src/finalize_stage_2_1_test.py
tests/test_stage_2_1_sufficiency.py
```

**Work:** derive resolved proxy projections, separate proxy and confirmatory
eligibility flags, independent S1/S2 proxy readiness states, confirmatory
block status where stronger provenance is absent, and private TEST proxy
support states. Never infer a missing label or convert UNCERTAIN.

**Validation:** independent projection; counts/groups/ESS/rates; public report
redaction; private report reconciliation.

**Completion:** every gate has `PASS`, `FAIL`, or `INSUFFICIENT` plus exact
reason, with TEST semantics still private.

### Checkpoint 2.1H — Seal, audit, and publication

**Inputs:** completed staged public/private bundles and all upstream identities.

**Planned files:**

```text
src/labeling/sealing.py
src/labeling/audit.py
src/audit_stage_2_1.py
src/audit_stage_2_1_test.py
tests/test_stage_2_1_isolation.py
scripts/validate_stage_2_1.ps1
```

**Work:** Custodian finalizes private manifest and seal; copy only public seal
to public staging; run independent audits; publish both bundles by no-replace
rename; rerun denied-access and consumer-allowlist tests.

**Validation command interfaces:**

```powershell
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest tests -q
& .\.venv\Scripts\python.exe .\src\audit_stage_2_1.py --normalized-input .\data\processed\stage_1_3f_normalized_events.jsonl --public-bundle .\data\processed\stage_2_1_public_v1
.\scripts\validate_stage_2_1.ps1 -NormalizedInput .\data\processed\stage_1_3f_normalized_events.jsonl -PublicBundle .\data\processed\stage_2_1_public_v1
```

The Custodian runs the private auditor separately with a protected private
configuration. Public commands must not accept or print the private path.

**Completion:** public and private independent audits pass; seal matches;
private denied access passes; public manifest and progression statuses publish;
no upstream file changed.

## 47. Historical FortiGate Acceptance Criteria — Superseded

Stage 2.1 is complete only when actual evidence proves all of the following:

- approved contract/schema versions validate;
- all 100,000 source identities reconcile without omission or duplication;
- annotation unit, evidence policy, label semantics, provenance, workflow, and
  eligibility are frozen;
- Sections 16A/16C precision-first labeling, evidence-or-no-evidence, split,
  and Custodian contracts are human-approved, immutable, hash-bound, and pass the active
  Checkpoint 2.1C fail-closed precondition without requiring a reviewer
  registry;
- every active label has one immutable valid deterministic decision or one
  explicit incomplete terminal outcome; no decision claims a human/external
  provenance tier;
- every fixed selected label task has a resolved or explicit unresolved terminal
  outcome;
- fixed sample membership freezes before the distribution dry run; the 400-row
  methodology cohort passes and canonical decisions reproduce dry-run hashes;
- sampling, probabilities, weights, phase rules, and cohort separation pass;
- the human-approved HARD_GROUP_ONLY V2 allocation passes every unchanged
  threshold, reproduces from its audit, and no hard component crosses splits;
- evaluation charter and validation-use budget are frozen before modeling;
- shared transformation protocol preserves 36-feature semantics and all
  learned-state boundaries;
- public/private manifests are physically separate and complete;
- no TEST label, class total, label-derived status, selected identity, weight,
  private path, or reconstructive metadata appears publicly;
- TEST seal and private manifest identities reconcile;
- Stage 2.2–2.4 denied-access and exact-allowlist tests pass;
- public and private sufficiency gates are computed without fabricated data;
- S1 and S2 precision-proxy-supervised readiness are independently
  READY/BLOCKED, no sufficiency result changes a rule/sample, and UNCERTAIN
  never enters binary fitting;
- the label-source exclusion manifest re-audits all 36 features, features 1-16
  stay excluded, and no trivially reconstructive candidate survives;
- every proxy metric/report uses the frozen high-confidence proxy-reference language and the
  mandatory incorporation/circularity limitation;
- deterministic rule reruns, immutable decision versioning, and no-overwrite
  publication pass;
- raw, normalized, and Stage 1.7–2.0 artifacts remain unchanged;
- relevant unit, contract, negative, leakage, determinism, integration, and
  full regression tests pass with measured counts; and
- human accepts the Stage 2.1 completion/handoff.

Label-file existence alone is not completion. A supervised path may remain
blocked while Stage 2.1 itself completes honestly.

## 48. Historical FortiGate Progression Gates — Superseded

The public progression artifact must emit these exact keys and statuses:

```text
STAGE_2_2: READY | BLOCKED
STAGE_2_2_LABEL_GUIDED_EVALUATION: READY | BLOCKED
STAGE_2_3_S1: READY | BLOCKED
STAGE_2_3_S2: READY | BLOCKED
STAGE_2_4_CHAIN: READY | BLOCKED
LABEL_REFERENCE_SCOPE: HIGH_CONFIDENCE_PROXY_REFERENCE
STAGE_2_5_CONFIRMATORY_REFERENCE: READY | BLOCKED
```

Each value includes criterion IDs and reasons.

- `STAGE_2_2` is READY when split, public bundle, U1-required TRAIN population
  of at least 4,096 rows, transformation protocol, charter, allowlist, and seal
  pass. U-label insufficiency blocks only
  `STAGE_2_2_LABEL_GUIDED_EVALUATION`; Stage 2.2 may proceed label-free within
  its later approved plan.
- `STAGE_2_3_S1` requires all public S1 precision-proxy-supervised TRAIN and
  `VALIDATION_S` gates.
- `STAGE_2_3_S2` requires S1 plus all stricter public S2 precision-proxy-supervised
  gates. It may be BLOCKED while S1 is READY.
- `STAGE_2_4_CHAIN` requires Stage 2.2 technical readiness, S1 readiness, and
  `VALIDATION_CHAIN` support. U2 remains conditional and is not a Stage 2.1
  requirement.
- `STAGE_2_5_CONFIRMATORY_REFERENCE` remains BLOCKED when TEST has only
  precision-first proxy reference labels; it becomes READY only through a later
  approved stronger-provenance superseding history.

No public key reveals private TEST sufficiency. The Custodian preserves
private Stage 2.5/S1/S2 TEST gates until authorized opening.

## 49. Historical FortiGate Blocker / Stop Conditions — Preserved

Stop Stage 2.1 or affected progression when:

- upstream identity or row reconciliation changes;
- no approved annotation/evidence/charter/transformation contract exists;
- any precision-first policy, rule registry, decision/dry-run/exclusion schema,
  predicate/finalizer, quality-tier, eligibility, or claim-language contract is
  missing, changed, or unapproved;
- a precision-first package receives prohibited model/pipeline information or
  context outside the strict Section 9 cutoff;
- evidence/provenance cannot distinguish confirmatory, precision-first proxy,
  historical AI proxy, and detector-direct proxy scopes;
- pilot methodology fails and no approved revision/re-review exists;
- entity fallback is needed without explicit human approval;
- the current precision-first proxy labeling amendment lacks explicit human
  approval;
- the Section 16A evidence-registry/declaration XOR or Custodian
  acknowledgement/private status precondition is missing, malformed,
  conflicting, inaccessible, agent-fabricated, or not human-approved;
- the active path is blocked solely for a missing reviewer registry, or any
  reviewer/adjudicator identity is fabricated;
- V2 returns `HARD_GROUP_ONLY: INFEASIBLE`, exceeds its repair budget, has no
  improving action, or cannot reproduce its exact objective/action trace;
- hard groups cannot produce feasible 70/15/15 splits within the unchanged
  global and eligible-stratum tolerances;
- any exact/near/session hard component crosses a split;
- validation or TEST sample selection adapts to outcomes;
- any TRAIN membership is selected after labels, a class/support target affects
  allocation, or the fixed phase/seed/non-overlap/cap contract deviates;
- an evaluation row has zero/unknown inclusion probability or invalid weight;
- label history is mutable, forked, incomplete, or unreproducible;
- a rerun overwrites prior deterministic output, partial/conflicting evidence
  becomes binary, non-high-confidence/UNCERTAIN enters fitting, or automation
  claims human/external provenance;
- canonical labels publish before dry-run replay, class counts alter a rule or
  sample, or label-source leakage audit fails;
- any public artifact/status/log/error/chat exposes a TEST seed/encoding,
  credential, private TEST semantic/sampling detail, private physical root, or
  restricted physical evidence location;
- denied private access cannot be demonstrated;
- TEST seal, private manifest, seed commitment, or payload identity fails;
- validation-use ledger shows repeat/cross-purpose access;
- fitted-state contract permits global/held-out rarity or preprocessing;
- U, S1, S2, chain, or private final support fails its numeric gate;
- active proxy metric/estimand becomes undefined or is described as
  confirmatory truth; the confirmatory estimand may honestly remain
  `UNAVAILABLE` without blocking proxy reporting;
- unauthorized TEST access occurs; or
- any builder/auditor/test/regression/publication gate fails.

Never replace a blocker with a guessed label, fabricated result, changed split,
ad hoc sample, lower unpublished threshold, or post-hoc estimand.

## 50. Historical FortiGate Contract to Stage 2.2 — Superseded by Section 2A

After Stage 2.1 completion and separate Stage 2.2 plan approval, Stage 2.2 may
consume only its Section 27 allowlist. The exported contract provides:

- immutable split/group identities and public TEST identities;
- frozen evaluation charter, U tuning/validation budget, score orientation,
  threshold policy, and tie-breaks;
- exact 36-feature definition and fitted-state rules;
- `VALIDATION_U` proxy-reference-eligible labels and design weights only,
  explicitly scoped `HIGH_CONFIDENCE_PROXY_REFERENCE`;
- U readiness and label-guided-evaluation status;
- non-revealing TEST seal; and
- no private TEST labels, test-sample identities, test weights, class totals,
  or private paths.

Stage 2.2 may fit unsupervised models on label-blind TRAIN only. It may not
reinterpret labels, resplit rows, reuse historical rarity maps, or inspect TEST
prediction content.

## 51. Historical FortiGate Contract to Stage 2.3 — Superseded

After Stage 2.1 completion and separate Stage 2.3 plan approval, Stage 2.3 may
consume only its Section 27 allowlist. The exported contract provides:

- precision-proxy-supervised-eligible TRAIN labels and immutable rule-decision/
  quality/provenance/exclusion-manifest identities;
- `VALIDATION_S` proxy-reference labels, probabilities, and weights only;
- S1/S2 readiness states and exact support reasons;
- split/group identities for later outer folds;
- charter limits for candidates, configurations, calibration, thresholds,
  metrics, and one batch validation use;
- the shared transformation protocol and default-denied feature registry; and
- the non-revealing TEST seal and public TEST identities.

Stage 2.3 must name the branch `precision-first-proxy-supervised`, must not mix
precision-first/historical AI proxy rows with stronger provenance as though one
truth tier, and cannot borrow another
validation purpose, redefine S1/S2 sufficiency, resplit, expose private TEST
data, or change feature semantics. Its supervised feature allowlist must
exclude anomaly rank/score unless a later chained contract explicitly permits
fold-safe signals, all triage/suspected-behavior/label/provenance fields, and
downstream predictions.

## 52. Historical FortiGate Deferred Decisions — Superseded

No Stage 2.1 methodology decision is left to the Execution Agent. Measured
execution outcomes feed only frozen reports/gates. Section 18A freezes every
TRAIN selection before labels and computes stratum allocation, selected
records, and terminal status without a target class. Entity fallback still
requires the separately defined human approval.

The following remain owned by later detailed plans within this charter:

- Stage 2.2 U2 shortlist, exact family choice, and subordinate model-specific
  feasibility settings;
- Stage 2.3 final S1 family if not Logistic Regression, S2 candidate choice,
  supervised allowlist after audit, and exact nested-fold allocation;
- Stage 2.4 inner-fold allocation and exact chained signal fields; and
- Stage 2.5 report/graph inventory and bounded presentation details.

Those decisions cannot change Stage 2.1 labels, split, sampling, estimand,
primary metric/comparison, validation purposes, weights, transformation
semantics, provenance eligibility, TEST seal, or opening policy.

## 53. Risks / Limitations

- The sanitized dataset may lack context needed for many proxy binary labels.
  High UNCERTAIN, partial/conflicting-rule, or unavailable-evidence rates may block
  S1 and/or S2 independently.
- Record-level labeling cannot establish incident-level truth. Lower raw
  `itime` supplies only the bounded source-order context in Section 9 and does
  not establish timestamp units or temporal generalization.
- Deterministic TEST split membership does not support a 100,000-row population
  claim.
- Unequal sampling weights and clustered groups may reduce effective sample
  size despite 1,500 reviewed TEST units.
- Deterministic proxy resolvability can be non-random; design weights do not
  remove that bias.
- Destination/entity components may form a giant network and force a weaker
  human-approved grouping tier. Resulting claims must not imply unseen-entity
  performance.
- Deterministic rules reduce inference cost but remain limited by sparse source
  context and source-product semantics; reproducibility does not make proxy
  truth independently confirmed.
- Public validation labels are methodologically sensitive even when not TEST
  secrets. Purpose allowlists and access ledger reduce, but cannot erase,
  deliberate human misuse.
- Weighted average precision and bootstrap intervals can remain unstable with
  sparse ATTACK groups. The precision gate limits claims but does not guarantee
  a winner.
- Precision-first labels are based on raw facts related to later engineered
  features. The exclusion manifest reduces direct target leakage, but metrics
  still measure agreement with the proxy methodology, not independent
  real-world attack truth.

### Devil's advocate closure

- Anomaly/explanation/triage/downstream evidence cannot enter deterministic
  packages; source detector data remains observation and cannot create
  confirmed truth.
- Public seal exposes hashes and safe planned counts only; TEST semantics,
  sample identities, weights, and physical path are forbidden from generated
  public artifacts.
- Execution agents receive no private mount/permission and cannot self-authorize
  opening.
- TRAIN/VALIDATION/TEST membership and probabilities all freeze before the dry
  run; no outcome-adaptive expansion remains active.
- BENIGN requires affirmative evidence; missing alerts and normal-looking
  traffic are insufficient.
- UNCERTAIN and every unresolved mechanism remain visible in coverage and
  sensitivity reporting.
- Precision-first, historical AI, detector, and stronger provenance tiers
  remain explicit in labels, gates, projections, estimands, and metrics.
- Hard components cannot cross splits; entity fallback is measured and
  human-approved.
- Historical Stage 1.7 rarity values are forbidden; every population-derived
  state is TRAIN/fold-local.
- Three disjoint validation purposes plus one batch each prevent repeated
  optimization against one cohort.
- Weighted average precision and S1 baseline-versus-chain comparison freeze
  before modeling; active reporting is explicitly proxy-reference reporting.
- Later stages consume contracts and may not reinterpret Stage 2.1 decisions.
- Schemas, formulas, thresholds, paths, states, and stop rules are explicit;
  the Execution Agent does not invent methodology.

## 54. Historical FortiGate Approval Requirements — Preserved as History

Human approval is required for:

1. this precision-first proxy labeling amendment before Checkpoint 2.1C resumes;
   all prior approvals remain preserved but do not approve this methodology
   change;
2. final precision-first policy/rule/schema/exclusion and other contract
   payloads before sampling;
3. any fallback from `ENTITY_ALL_ENDPOINTS` and separately from
   `ENTITY_SOURCE_HOST`;
4. any dry-run-driven rule/context/evidence contract revision and complete
   relabeling under a new version; class yield alone never justifies revision;
5. reviewer/adjudicator registry and conflicts only if the optional human
   upgrade path is activated;
6. Custodian private-root binding, seal creation, and Stage 2.1 private audit;
7. any change to fixed sample, charter, sufficiency, or transformation rules;
8. Stage 2.1 completion and public handoff;
9. each later detailed stage plan; and
10. one Stage 2.5 TEST opening after every prerequisite hash freezes.

Approval never authorizes label invention, premature TEST access, automatic
commit/push, or methodology changes outside the approved version.

## 55. Plan Status

**PLAN STATUS:** APPROVED — TWO-BRANCH BENCHMARK ARCHITECTURE RE-APPROVED

Plan version 1.0 was explicitly approved by the human on 2026-09-25. Execution
then reached Checkpoint 2.1B and discovered the recorded
`HISTORICAL_TOP_5` balance blocker. Amendment
`S2.1-AMEND-2026-09-26-HARD-GROUP-ALLOCATOR-V2` preserves that approval history
and passed focused review for threshold preservation, label-blindness,
whole-group isolation, deterministic bounded search, and true infeasibility,
with no new methodology issue. The human explicitly re-approved the amendment
on 2026-09-26.

Execution then reached Checkpoint 2.1C and found that required reviewer,
external-evidence/no-evidence, and TEST Custodian inputs lacked exact
machine-readable contracts. Amendment
`S2.1-AMEND-2026-09-26-HUMAN-INPUT-CONTRACTS-V1` defines only those schemas,
templates, validations, private-root/seed handling, and fail-closed
preconditions. The human explicitly re-approved this Human Input Contract
Amendment on 2026-09-26 after focused review: reviewer registry contract
PASS; evidence / no-evidence contract PASS; Custodian secret handling PASS;
Checkpoint 2.1C fail-closed contract PASS; no new blocking issue. This
approval changes metadata only and changes no implementation/test file or
labeling, split, sampling, evaluation, sufficiency, transformation, or
TEST-isolation methodology. At that historical point the human-input blocker
was cleared; the then-pending methodology amendment below re-paused Checkpoint
2.1C.

The human subsequently selected AI-assisted proxy labeling because three
independent human reviewers are unavailable. Amendment
`S2.1-AMEND-2026-09-26-AI-PROXY-LABELING-V1` makes the bounded two-pass
`AI_ASSISTED_PROXY_LABEL` workflow active, makes the reviewer registry an
optional future upgrade, permits explicit proxy-supervised TRAIN/VALIDATION,
and limits TEST claims to **evaluation against AI-assisted proxy reference
labels**. It preserves the approved HARD_GROUP_ONLY split, sampling designs
and numeric thresholds, 36-feature transformation contract, external-evidence
/ no-evidence alternative, TEST Custodian, private seed/seal, and master plan.
It changes no implementation file. The human explicitly re-approved this AI
Proxy Labeling Amendment on 2026-09-26 after focused review: AI provenance
PASS; evidence blinding PASS; TEST seal safety PASS; supervised eligibility
PASS; claim language PASS; active-path consistency PASS; no new blocking
issue. This re-approval changes approval metadata only. Checkpoint 2.1C may
resume subject to every unchanged active-path precondition.

On 2026-09-27 the human requested a correctness-first replacement that does
not depend on an AI API or required human reviewers. Amendment
`S2.1-AMEND-2026-09-27-PRECISION-FIRST-PROXY-V1` preserves every prior
approval and blocker record but makes `PRECISION_FIRST_PROXY_LABELING` the
active path. It freezes exact high-precision ATTACK/BENIGN functions,
`PRECISION_FIRST_PROXY_LABEL` provenance, the sole binary quality tier
`HIGH_CONFIDENCE_PROXY`, label-blind fixed sampling, a pre-publication dry run,
post-label S1/S2 gates, and a 36-feature label-source leakage re-audit. Class
balance has no target; UNCERTAIN is preferred whenever evidence is
insufficient; S1/S2 may remain BLOCKED. The master pipeline, approved split,
numeric sufficiency thresholds, base feature definition, TEST Custodian, seed,
seal, and opening policy remain unchanged. No implementation file was changed.
The human explicitly re-approved this Precision-First Proxy Labeling Amendment
on 2026-09-27 after focused review: attack precision PASS; benign precision
PASS; UNCERTAIN policy PASS; feature leakage controls PASS; sufficiency / claim
language PASS; active-path consistency PASS; no new blocking issue. This
re-approval changes approval metadata only and preserves all prior approval,
blocker, and amendment history. Checkpoint 2.1C may resume under every
unchanged active-path precondition and proceed toward the frozen label-
distribution dry run.

Execution subsequently completed the approved precision-first FortiGate label-
distribution feasibility run. It measured TRAIN `ATTACK=18`, `BENIGN=0`,
`UNCERTAIN=67,984` and VALIDATION `ATTACK=0`, `BENIGN=12`,
`UNCERTAIN=15,988`. Canonical FortiGate supervised labels were not published.
The evidence therefore closed FortiGate supervised feasibility as
`INSUFFICIENT`; it did not authorize relaxed labels or fabricated ground truth.

On 2026-09-27 the human directed amendment
`S2.1-AMEND-2026-09-27-TWO-BRANCH-BENCHMARK-V1`. Section 2A is now the sole
current active architecture: FortiGate remains the real-log unsupervised
branch, and separately acquired UNSW-NB15 will become the labeled benchmark
branch for U1/U2 quantitative evaluation, S1/S2, and chained ML. Every earlier
FortiGate labeling approach remains preserved as
`HISTORICAL / LABEL-FEASIBILITY STUDY`. The human explicitly re-approved this
amendment on 2026-09-27 after focused review: dataset separation PASS;
benchmark TEST independence PASS; stage/model ownership PASS;
evaluation/claim language PASS; required model evaluation PASS; active
architecture consistency PASS; no surviving contradiction. This update
changes approval metadata only; no UNSW-NB15 data was downloaded, no canonical
FortiGate label was published, and no implementation file was changed.
