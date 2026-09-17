# Stage 1.9 Explainability and Analyst Review Findings

Status: **VALIDATED**. The corrected Stage 1.9 explanation and auto-triage
bundles were rebuilt from the real 100,000-row inputs, independently audited,
and accepted by the deterministic official validator. Corrected local
validation returned exit code 0 with `STAGE 1.9 LOCAL VALIDATION PASS`.
Human review is optional and has not been performed.

The correction fixes a compiled reference-distribution lookup that previously
assigned `equal_count = less_count` when an observed value was absent from the
REFERENCE distribution. The corrected behavior is `equal_count = 0`. A
synthetic regression independently compares compiled counts and extremeness
with scalar formulas and explicit expected values below, between, above, and
at REFERENCE values, including 90 zeros plus 10 ones with observed `0.9`.
This affects Stage 1.9 behavior assignments only; it does not change Stage 1.8
features, scores, ranks, bands, Top-50 membership, or manifest identity.

## Purpose

Stage 1.9 adds deterministic, descriptive context to immutable Stage 1.7
features and Stage 1.8 anomaly scores. It does not retrain the model, alter
scores/ranks/Top-50 membership, create an attack label, or assert malicious
activity. The governing boundaries are:

- ANOMALY != ATTACK
- ANOMALY SCORE != ATTACK PROBABILITY
- RULE MATCH != CONFIRMED ATTACK
- SOURCE THREAT OBSERVATION != GROUND-TRUTH ATTACK LABEL
- SUSPECTED ATTACK TYPE != CONFIRMED ATTACK

## Explanation Method

Feature deviations are calculated only against the eligible Stage 1.7
REFERENCE distribution. Numeric features use two-sided midrank extremeness;
rarity features use upper-tail-only extremeness. Source missingness prevents
an imputed numeric value from becoming a numeric deviation. A source absence
may be described as a source-completeness observation, but never establishes
suspicious session behavior by itself.

At most three top reasons are rendered. Behavior tags retain this fixed order:

1. `UNUSUAL_TRAFFIC_VOLUME`
2. `UNUSUAL_TRAFFIC_DIRECTION`
3. `UNUSUAL_SESSION_CHARACTERISTICS`
4. `RARE_PORT_OR_SERVICE_CONTEXT`
5. `UNUSUAL_PROTOCOL_CONTEXT`

`UNCLASSIFIED_ANOMALOUS_PATTERN` is only a Top-50 fallback with no qualifying
specific behavior. Opaque sanitized identifiers remain operational context;
they are not semantically interpreted.

## Interpretation Boundaries

Every non-Top-50 row has `suspected_attack_type: null`. A qualifying Top-50
reconnaissance source observation yields exactly `Possible reconnaissance
activity`; all other Top-50 rows yield `Unclassified suspicious behavior`.
Neither phrase confirms an attack or a scan sequence.

Evidence strength is `HIGH`, `MEDIUM`, `LOW`, or `null` only. It expresses
the bounded richness of explanatory evidence, not attack confidence,
probability, severity, or independent confirmation.

## Automated Triage

The normal Stage 1.9 completion path adds deterministic automated
investigation prioritization for every explanation row. It uses only immutable
Stage 1.8 rank/band evidence:

- `HIGH_INTEREST`: exact persisted Top-50 selection.
- `MEDIUM_INTEREST`: a non-Top-50 row in frozen `TOP_0_1_PERCENT`,
  `TOP_1_PERCENT`, or `TOP_5_PERCENT` bands.
- `LOW_INTEREST`: remaining `BASELINE` rows.

This is an operational ordering aid. `HIGH_INTEREST` does not mean confirmed
malicious activity, and `LOW_INTEREST` does not mean benign or safe. No human
labels are generated. Without actual human ground truth, precision, recall,
F1, accuracy, and a confusion matrix are unavailable and are not reported.

The corrected, independently audited automated bundle contains:

- `data/processed/stage_1_9_auto_triage_corrected_driver_v2/stage_1_9_auto_triage.csv`
- `data/processed/stage_1_9_auto_triage_corrected_driver_v2/stage_1_9_top_anomalies.csv`
- `data/processed/stage_1_9_auto_triage_corrected_driver_v2/stage_1_9_summary.json`

Its summary contains deterministic coverage, triage, band, evidence,
behavior, interpretation, review-status, score-quantile, and priority-quantile
tables for later visualization. These are not supervised performance metrics.

## Optional Analyst Review

The immutable pre-review bundle contains every explanation and a blinded
100-row queue: the unchanged Stage 1.8 Top-50 plus 50 deterministic comparison
rows. The initial queue excludes scores, ranks, driver details, source event
labels, rule IDs, and threat fields. It provides operational context only.

Human-provided blind labels may later be `SUSPICIOUS`, `NOT_SUSPICIOUS`, or
`UNCERTAIN`. They are optional review judgments, not attack/benign truth
labels. No label or review identifier is manufactured by this project.

Without human labels, the automated bundle uses the honest state mapping:

- no review ID -> `NOT_SELECTED`
- queue row -> `PENDING`
- `REVIEWED_RESOLVED` -> `0`
- `REVIEWED_UNCERTAIN` -> `0`

## Evaluation

Only an optional, completed future blind-review artifact may form the bounded
reviewed-sample matrix. `UNCERTAIN` rows are excluded from its resolved binary
denominators and are reported separately. Any future precision, recall, and F1
remain reviewed-sample-only and do not estimate dataset-wide attack performance
or unseen-group generalization.

Source threat observations, Stage 1.4 rules, scores, and Top-50 membership are
never consumed as analyst ground truth. The automated triage summary is the
Stage 2.0 source for no-human-label coverage and triage tables; a future
evaluation summary remains the authority for any actual human review state.

## Artifacts and Validation

Corrected pre-review output was published after temporary build, audit, and
no-replace publication in fresh directories:

- `data/processed/stage_1_9_corrected_driver_v2/stage_1_9_explained_anomalies.jsonl`
- `data/processed/stage_1_9_corrected_driver_v2/stage_1_9_analyst_review_queue.csv`
- `data/processed/stage_1_9_corrected_driver_v2/stage_1_9_explanation_metadata.json`

After optional completed human labels, evaluation may be separately published as
`data/processed/stage_1_9_evaluation/stage_1_9_evaluation_summary.json`.
The raw CSV, normalized JSONL, Stage 1.7/1.8 artifacts, and the blind-label
file remain immutable inputs.

### Corrected validation evidence

| Check | Measured result |
|---|---|
| Corrected explanation build | PASS; 93.8282885 seconds |
| Corrected auto-triage build | PASS |
| Independent audit | PASS |
| Deterministic validator rebuild | PASS |
| Official validator | `STAGE 1.9 LOCAL VALIDATION PASS` (exit code 0) |
| Full unittest suite | 268 passed |
| Full pytest suite | 268 passed; 123 subtests passed; 2 known deprecation warnings |

The unchanged upstream identities are:

| Artifact | SHA-256 |
|---|---|
| Stage 1.7 feature artifact | `1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1` |
| Stage 1.8 score artifact | `f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4` |
| Stage 1.8 manifest | `9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77` |

The corrected artifact identities are:

| Artifact | SHA-256 |
|---|---|
| Explanation JSONL | `de6b253b03fc5cb99420fb0a5ee017efd7da5027322ac70edf6235f5b95b666a` |
| Auto-triage CSV | `64487bd90ad0cb59132f8bf024040b9e06c16daf05d053bf1ec594e3d7948f02` |
| Auto-triage summary JSON | `76a0cb76e1e171440d1de3678edbdc851699e262bf3e2ecaa882a3d39a708efe` |
| Top-anomalies CSV | `fcb3510c3e8a0b71c4c1e6361f5e6eeefa12e6b4376dcd46f4b66d8461e338ac` |

### Corrected real-data findings

The corrected artifacts contain 100,000 rows: 79,947 `REFERENCE` and 20,053
`HOLDOUT`. The frozen Stage 1.8 Top-50 count remains 50. Anomaly-band counts
are 94,767 `BASELINE`, 94 `TOP_0_1_PERCENT`, 880 `TOP_1_PERCENT`, and 4,259
`TOP_5_PERCENT`.

| Auto-triage value | Count |
|---|---:|
| `HIGH_INTEREST` | 50 |
| `MEDIUM_INTEREST` | 5,183 |
| `LOW_INTEREST` | 94,767 |

| Explainability measure | Corrected value |
|---|---:|
| Records with a specific suspected behavior | 15,123 |
| Records with suspected behavior or fallback | 15,141 |
| Explanation coverage | 15.141% |
| `UNUSUAL_TRAFFIC_VOLUME` | 2,480 |
| `UNUSUAL_TRAFFIC_DIRECTION` | 1,484 |
| `UNUSUAL_SESSION_CHARACTERISTICS` | 3,610 |
| `RARE_PORT_OR_SERVICE_CONTEXT` | 11,533 |
| `UNUSUAL_PROTOCOL_CONTEXT` | 0 |
| `UNCLASSIFIED_ANOMALOUS_PATTERN` | 18 |
| Evidence `HIGH` / `MEDIUM` / `LOW` / `null` | 0 / 0 / 32 / 99,968 |
| Top-50 fallback count | 18 |
| `Possible reconnaissance activity` | 0 |
| `Unclassified suspicious behavior` | 50 |
| Null suspected attack interpretation | 99,950 |

Review statuses are 99,900 `NOT_SELECTED`, 100 `PENDING`, zero
`REVIEWED_RESOLVED`, and zero `REVIEWED_UNCERTAIN`. No human labels were
generated. Supervised classification metrics remain unavailable without
accepted human ground truth.

### Superseded pre-correction local evidence

The user's local Stage 1.9 validator returned exit code 0 and
`STAGE 1.9 LOCAL VALIDATION PASS` **before** the compiled-reference-count
correction. It reported 268 passing unittest tests, 268 passing pytest tests,
123 passing subtests, and two known upstream deprecation warnings. The run
processed 100,000 records: 79,947 REFERENCE and 20,053 HOLDOUT. It reported
50 HIGH_INTEREST, 5,183 MEDIUM_INTEREST, 94,767 LOW_INTEREST, and the
unchanged Top-50 membership count of 50. Review statuses were 99,900
NOT_SELECTED, 100 PENDING, zero REVIEWED_RESOLVED, and zero
REVIEWED_UNCERTAIN. No human labels or supervised attack metrics were created.

The pre-correction hashes were:

| Artifact | Superseded SHA-256 |
|---|---|
| Auto-triage CSV | `43d3caaad447684d11dfb422a18791628d6b41b9bc2c6b7af9d8f47efc6f917f` |
| Auto-triage summary JSON | `f8ab151d36dd7c3ef2a221071067da86621410f375f8ce77831bb6684de1bf79` |
| Top-anomalies CSV | `9cd17242285227436b83c89d18aaaed3ce5b54ac6665633912715c08668d2e2e` |

The pre-correction figures above are superseded and must not be presented as
corrected results. The corrected real-data results are the measured values in
the preceding corrected findings section.

### Measured pre-fix versus corrected explainability changes

| Measure | Pre-fix | Corrected | Change |
|---|---:|---:|---:|
| Records with a specific suspected behavior | 15,150 | 15,123 | -27 |
| Records with suspected behavior or fallback | 15,168 | 15,141 | -27 |
| Explanation coverage | 15.168% | 15.141% | -0.027 percentage points |
| `UNUSUAL_TRAFFIC_VOLUME` | 2,597 | 2,480 | -117 |
| `UNUSUAL_TRAFFIC_DIRECTION` | 1,457 | 1,484 | +27 |
| `UNUSUAL_SESSION_CHARACTERISTICS` | 3,714 | 3,610 | -104 |
| `RARE_PORT_OR_SERVICE_CONTEXT` | 11,533 | 11,533 | 0 |
| `UNUSUAL_PROTOCOL_CONTEXT` | 0 | 0 | 0 |
| `UNCLASSIFIED_ANOMALOUS_PATTERN` | 18 | 18 | 0 |

Evidence-strength counts and suspected-attack-interpretation counts remained
unchanged. Auto-triage remained 50 `HIGH_INTEREST`, 5,183 `MEDIUM_INTEREST`,
and 94,767 `LOW_INTEREST`; the Top-50 count remained 50. This is expected:
auto-triage uses frozen Stage 1.8 rank and anomaly-band outputs rather than
Stage 1.9 explainability-driver extremeness.

## Handoff Status

Stage 1.9 corrected implementation is **VALIDATED**. Corrected artifacts are
built and audited, and the local validator passed. Human review remains
optional and is not completed. Supervised classification metrics are
unavailable without accepted human ground truth. The Stage 2.0 automated
handoff is ready subject to final review and human approval. This status does
not state that Stage 1.9 has been committed or pushed.
