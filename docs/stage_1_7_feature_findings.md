# Stage 1.7 — AI Feature Engineering + Evaluation Foundation

## Status

**LOCAL VALIDATION PASS**

Stage 1.7 implementation has not yet been committed or pushed.

## Objective

Stage 1.7 creates a deterministic, leakage-safe, source-traceable feature
foundation for the planned Stage 1.8 evaluation work. It is feature
engineering and evaluation preparation, not anomaly detection.

## Modeling Boundary

One normalized record is one observation. The split uses canonical UTF-8 JSON
for `["stage-1.7-split-v1","session",identifier]` when `session.identifier`
is nonempty; otherwise it uses
`["stage-1.7-split-v1","record",source_record_number]`. SHA-256
first-eight-byte modulo-ten buckets `0..7` are REFERENCE and `8..9` are
HOLDOUT. Opaque identifiers are neither trimmed nor case-folded.

This grouping prevents the same nonempty session identifier from crossing the
two partitions. It does not establish temporal, host, or semantic
independence. HOLDOUT is a descriptive unseen-group diagnostic partition, not
a labeled test set and not a ground-truth attack benchmark.

## Feature Contract

- `feature_count`: **36**
- Feature order is fixed and deterministic under schema version `1.0`.
- Each feature row contains exactly 36 finite model-ready float values.
- `source_record_number` and the opaque `source_record_id` are retained for
  joins and provenance; they are not predictive feature values.
- The metadata uses one neutral, ordered 36-feature contract shared by the
  builder and read-only auditor. The auditor does not derive expected feature
  definitions from builder-private state.
- No final machine-learning model was trained in Stage 1.7.

The bundle contains exactly:

- `stage_1_7_ai_features.jsonl`
- `stage_1_7_ai_feature_metadata.json`

## Real-Data Validation

| Measurement | Verified value |
|---|---:|
| Row count | 100,000 |
| Reference row count | 79,947 |
| Holdout row count | 20,053 |
| Feature count | 36 |
| Feature JSONL SHA-256 | `1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1` |

Reconciliation: **79,947 + 20,053 = 100,000**.

The official local Stage 1.7 validator/audit result was:

```text
STAGE 1.7 LOCAL VALIDATION PASS
```

## Regression Evidence

- `unittest`: **200 PASS**
- `pytest`: **200 PASS**
- Subtests: **123 PASS**
- Warnings: **2 known non-blocking upstream deprecation warnings**

## Leakage Controls

The model-ready matrix uses only the approved feature families: numeric
protocol one-hot encoding; port presence, class and reference-only rarity;
reference-only protocol/service rarity; nonnegative metric `log1p` values;
guarded ratios; and explicit missingness or observed-zero indicators. Duration
is used only as a unit-neutral raw numeric value; no seconds, throughput, or
timeout interpretation is asserted.

The bytes-per-packet features are log-transformed when eligible:

- `log_sent_bytes_per_packet = log1p(sent_bytes / sent_packets)`
- `log_received_bytes_per_packet = log1p(received_bytes / received_packets)`

If their required operands are missing or the packet denominator is zero, the
feature uses the approved finite `0.0` fallback. Separate missingness and
observed-zero indicators retain that context; these are not raw ratios.

The approved leakage matrix excludes or reference-gates source threat
observations, explicit event anomaly/security labels, Stage 1.4 rule
observations, raw opaque identifiers as literal predictive identities,
timestamps, and model outputs. `net_sessionid` is a split-group key only.
Fields not explicitly allowed by the matrix are default-denied as predictors.

## Reference / Holdout Isolation

REFERENCE-only state includes rarity maps, REFERENCE distributions, eligible
REFERENCE distributions, and constant-feature metadata. HOLDOUT-only changes
cannot influence that fitted state. HOLDOUT remains an unlabeled unseen-group
diagnostic partition, not an attack test set.

## Identifier Semantics

Sanitized identifiers are opaque identifiers. Tokens such as `SRCIP_xxx`,
`DSTIP_xxx`, `HOSTIP_xxx`, and `SRCMAC_xxx` are not interpreted as literal
network addresses or link-layer addresses.

## Determinism and Validation Architecture

The feature builder emits canonical compact UTF-8 JSON with ordered feature
names and deterministic split logic. Metadata retains stable structures and
artifact identity. The builder completes an owned temporary bundle, the
read-only auditor recomputes and reconciles its feature contract, and only a
passing audit permits no-replace publication. An audit failure prevents final
publication. The official Stage 1.7 validator performs the regression, audit,
determinism, and data-safety checks.

```text
temporary bundle → independent audit → no-replace publish → Stage 1.7 validation
```

The auditor is validation and audit logic, not a model.

## Security Interpretation

- **RULE MATCH != CONFIRMED ATTACK**
- **ANOMALY != ATTACK**
- **SOURCE THREAT OBSERVATION != GROUND-TRUTH ATTACK LABEL**

Stage 1.7 contains no AI attack detections.

## Stage Boundary

Stage 1.7 did not perform:

- Isolation Forest training
- anomaly scoring
- Top-50 selection
- suspected-behavior labeling
- suspected-attack classification
- precision, recall, F1, or a confusion matrix
- a final Stage 2.0 graphs/report package

Those activities belong to later stages.

## Inputs to Stage 1.8

The planned Stage 1.8 input boundary is the Stage 1.7 feature bundle contract:
the 36-value deterministic JSONL rows and the accompanying metadata with the
feature manifest, split counts, reference-only rarity maps, reference
distributions, eligible reference distributions, and artifact identities. No
Stage 1.8 implementation is introduced here.

## Limitations

- No ground-truth attack labels were created.
- Feature preparation alone does not establish anomaly or attack truth.
- REFERENCE and HOLDOUT are methodological partitions, not malicious/benign
  classes.
- Stage 1.8 still needs to train and evaluate Isolation Forest according to
  its approved plan.
