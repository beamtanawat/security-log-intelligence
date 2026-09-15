# Stage 1.8 Anomaly Scoring Findings

## Evidence Status

**STAGE 1.8 LOCAL VALIDATION PASS**

Authoritative local validation completed with Python 3.12.10. The final
post-trust-regression evidence is:

- targeted Stage 1.8 unittest: 24 PASS
- targeted Stage 1.8 pytest: 24 PASS
- full unittest: PASS (the final supplied terminal evidence did not include
  a numeric count)
- full pytest: 224 PASS
- pytest subtests: 123 PASS
- warnings: 2 known non-blocking upstream deprecation warnings

Dependency validation (`pip check`), the full Stage 1.7 audit, the published
Stage 1.8 trusted audit, the controlled Stage 1.8 rebuild, controlled manifest
identity verification, controlled trusted audit/replay, and the official Stage
1.8 validator all passed.

## Upstream Boundary

The only normal builder input is the immutable Stage 1.7 feature bundle. The
validated handoff contract is 100,000 rows, 36 ordered numeric features,
79,947 `REFERENCE` rows, 20,053 `HOLDOUT` rows, and feature JSONL SHA-256:

`1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1`

The scoring builder accepts `--features-dir`; it does not read raw CSV or
normalized JSONL. The official Stage 1.8 validator additionally requires
`-NormalizedInput` and ran the complete Stage 1.7 audit before Stage 1.8
model construction. This prevents a model run from relying only on a copied
upstream identity.

## Model and Training Contract

The one configured model is `IsolationForest` with:

- `n_estimators=200`
- `max_samples=4096`
- `contamination="auto"`
- `max_features=1.0`
- `bootstrap=False`
- `n_jobs=1`
- `random_state=1729`
- `warm_start=False`

The fit matrix is finite, contiguous `float32`, constructed from the exact
ordered 36 Stage 1.7 values only. Fitting uses `REFERENCE` rows in ascending
`source_record_number` order. `HOLDOUT` rows are scored but never participate
in fitting, calibration, feature construction, distribution fitting, model
selection, or tuning. A run fails if fewer than 4,096 reference rows exist.

Validated runtime dependency versions are:

```text
scikit-learn==1.9.1
numpy==2.5.3
scipy==1.18.1
joblib==1.6.0
threadpoolctl==3.6.0
narwhals==2.26.0
```

The validated runtime is Python 3.12.10. Exact runtime package versions are
captured in model metadata and must equal the manifest before trusted model
loading is allowed. `pip check` found no broken requirements.

## Score, Rank, and Top-50 Contract

For every feature row:

```text
model_score = IsolationForest.score_samples(X)
raw_abnormality = -model_score
```

Lower `model_score` is more abnormal; higher `raw_abnormality` is more
unusual. The displayed `anomaly_score` is the inclusive empirical percentile
of the raw abnormality against only the reference score distribution:

```text
100 * bisect_right(sorted_reference_raw_abnormality, raw_abnormality)
    / reference_row_count
```

It is persisted rounded to six decimal places, while bands use the unrounded
percentile. Bands are `TOP_0_1_PERCENT` (at least 99.9), `TOP_1_PERCENT` (at
least 99), `TOP_5_PERCENT` (at least 95), and `BASELINE`. All-equal reference
raw scores fail closed as `DEGENERATE_SCORE_REFERENCE`.

Ranks are unique across both partitions: descending **unrounded** raw
abnormality, then ascending `source_record_number`. Output JSONL retains
source-record order for joins. The fixed Top-50 contract is represented only
as `analyst_review_selected = anomaly_rank <= 50`; it identifies the
highest-ranked anomaly review candidates. It does not mean 50 attacks, 50
malicious records, or 50 true positives, and is not a separate analyst
workflow, alert, or verdict.

**Anomaly Score is relative abnormality within the validated Stage 1.7
reference population; a higher value is more unusual. It is not an attack
probability, confidence, severity, or proof of malicious activity.**

## Artifact and Trusted-Model Contract

The validated output directory is `data/processed/stage_1_8/`, containing:

- `stage_1_8_isolation_forest.joblib`
- `stage_1_8_anomaly_scores.jsonl`
- `stage_1_8_model_metadata.json`
- `stage_1_8_manifest.json`

All JSON uses canonical deterministic UTF-8, sorted keys, compact separators,
finite values, and LF line endings. The manifest deliberately has no
self-hash. It records the Stage 1.7 identity and feature order, model
configuration and training partition, exact dependency versions, and SHA-256
values for the completed model, metadata, and score artifacts.

`joblib.load` is available only through a controlled entry point that requires
an externally supplied `approved_manifest_sha256`. It verifies the manifest
SHA-256, manifest schema, model/metadata/score SHA-256 values, and exact
runtime versions before deserializing. A wrong approved hash, tampered
manifest, tampered model, or incompatible runtime fails closed. `joblib.load`
must not execute before those checks pass.

Publication is:

```text
owned temporary bundle -> independent audit -> manifest finalization ->
artifact validation -> same-volume no-replace publication
```

An audit failure leaves the final destination absent and removes only the
builder-owned temporary directory.

## Final External Trust-Anchor Validation

The official Stage 1.8 validator requires the mandatory operator-supplied
parameter `-ApprovedManifestSha256`. For the validated published bundle, the
external approved manifest SHA-256 is:

`9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77`

This value is **externally supplied** and is **not self-derived** from the
bundle under audit. Published-bundle trusted replay receives this external
value; the auditor independently computes the bundle manifest SHA-256 and
compares it with the supplied identity. The trust flow is:

```text
external approved manifest SHA -> manifest SHA and schema verification ->
model/artifact SHA verification -> runtime compatibility verification ->
controlled joblib.load
```

The controlled rebuild must produce a manifest whose SHA-256 equals the same
external approved value before trusted audit/replay can continue. A mismatch
fails closed and cannot self-approve a rebuilt bundle. `joblib.load` remains
unreachable until all of these trust checks succeed.

Regression coverage independently verifies that the published-bundle audit
uses `$scores` with `--approved-manifest-sha256 $ApprovedManifestSha256`, and
that the controlled-rebuild audit separately uses its rebuilt directory with
the same external hash. The test does not accept merely one matching audit
invocation.

The corrected official validator completed locally with:

```text
STAGE 1.8 LOCAL VALIDATION PASS
```

## Determinism and Sensitivity

The primary seed is 1729. The official validator rebuilt in a fresh owned
directory and reproduced the same canonical score JSONL SHA-256:

`f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4`

It also reproduced the same manifest SHA-256:

`9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77`

These are the measured deterministic identities for the approved runtime and
environment contract; they do not claim determinism outside that contract.
Secondary seeds 2718 and 3141 provide only Top-50 and Top-100 Jaccard overlap
diagnostics; they are not selection or tuning criteria and their models are
not published. No unsupported overlap, score-distribution, runtime, memory,
or processing-time metric is claimed here.

## Leakage and Interpretation Boundaries

The matrix never includes raw or opaque identifiers, timestamps, threat
fields, source-product anomaly/security flags, rule findings, labels, analyst
outcomes, later-stage interpretation, or API/storage outputs. Sanitized values
remain opaque provenance strings; they are not interpreted as literal network
addresses.

- `ANOMALY != ATTACK`
- `ANOMALY SCORE != ATTACK PROBABILITY`
- `HIGH ANOMALY SCORE != CONFIRMED MALICIOUS ACTIVITY`
- `RULE MATCH != CONFIRMED ATTACK`
- `SOURCE THREAT OBSERVATION != GROUND-TRUTH ATTACK LABEL`

Stage 1.8 provides no suspected attack type, suspected behavior,
evidence-strength label, analyst review-outcome workflow, review-status
semantics, precision/recall/F1 from analyst review, confusion matrix, or
operational incident conclusion. It does not implement the Stage 2.0 final
visualization/report package.

## Measured Artifact Evidence

The real Stage 1.8 build and independent audit both passed with:

- `row_count=100000`
- `reference_row_count=79947`
- `holdout_row_count=20053`
- Stage 1.7 `feature_sha256=1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1`
- `score_sha256=f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4`
- `manifest_sha256=9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77`

Trusted model replay passed. The externally supplied approved manifest
SHA-256 was verified before controlled deserialization, followed by manifest,
model, metadata, score-artifact identity, and runtime-compatibility checks.
`joblib.load` occurs only after those checks succeed; arbitrary joblib files
are not considered safe to load.

## Local Validation Command

The authoritative successful run used the existing local Python 3.12 virtual
environment from repository root:

```powershell
.\scripts\validate_stage_1_8.ps1 `
  -NormalizedInput .\data\processed\stage_1_3f_normalized_events.jsonl `
  -FeaturesDir .\data\processed\stage_1_7 `
  -ScoresDir .\data\processed\stage_1_8 `
  -ApprovedManifestSha256 9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77
```

Only a complete successful sequence emits `STAGE 1.8 LOCAL VALIDATION PASS`.
