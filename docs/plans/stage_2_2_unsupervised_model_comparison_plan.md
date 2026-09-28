# Stage 2.2 — Unsupervised Model Comparison Implementation Plan

**PLAN STATUS:** APPROVED — STAGE 2.2 WITH CONFLICT-GROUP RECONCILIATION FIX

**Date:** 2026-09-28

**Version:** 1.0

**Plan ID:** S2.2-TWO-BRANCH-UNSUPERVISED-V1

**Prior approval:** Explicit HUMAN APPROVAL provided on 2026-09-28 for Stage 2.2 Unsupervised Model Comparison. That approval and its preconditions remain preserved as history.

**Prior amendment:** S2.2-DUPLICATE-TARGET-CONFLICT-V1, dated 2026-09-28. Initially pending review and approval; explicitly HUMAN RE-APPROVED on 2026-09-28 as the DUPLICATE / CONFLICTING-TARGET AMENDMENT. The initial execution report attributed 229 conflicting official TRAIN groups to the approved 28 predictive features. Subsequent reconciliation supplied by the human establishes that 229 came from historical 42-field grouping; the current approved 28-feature grouping yields 273 conflict groups. This correction preserves the blocker and approval history without retaining the mistaken grouping attribution. These are supplied execution observations, not fresh measurements by the plan author. No implementation or training is performed here.

**Current reconciliation fix:** S2.2-CONFLICT-GROUP-RECONCILIATION-V1, dated 2026-09-28; initially pending human review and approval, then explicitly HUMAN RE-APPROVED on 2026-09-28 as the CONFLICT-GROUP RECONCILIATION FIX. This fix changes only the stale reconciliation expectation and its provenance/reproducibility check. This update records approval metadata only and preserves all prior approval, review, blocker, and amendment history.

**Focused reconciliation review:** Active 28-feature definition PASS; 229 historical only PASS; 273 reproducibility fingerprint PASS; no forced historical count PASS; future versioning PASS; other methodology unchanged PASS.

**Reconciliation re-approval scope:** The human explicitly re-approves the existing Section 4 contract: 28 approved predictive features before learned preprocessing; historical 42-field grouping yields 229 conflict groups and is not an active acceptance criterion; the current fingerprint is 273 groups / 6896 rows / 2156 NORMAL / 4740 ATTACK. With the same raw TRAIN artifact, feature contract/version, and grouping/canonicalization algorithm, a count other than 273 remains a reproducibility STOP. A future human-approved feature-contract change requires a recomputed, versioned fingerprint rather than forcing 273. All existing preservation, split, preprocessing, TEST, threshold, U1/U2, primary-metric, and sensitivity policies remain unchanged. Checkpoint 2.2A is ready to resume subject to existing preconditions; this metadata-only task does not resume 2.2A, start 2.2B, implement, train, commit, or push.

**Focused amendment review:** Row/label preservation PASS; duplicate-group definition PASS; split containment PASS; label-blind allocation PASS; split-size policy PASS; sensitivity policy PASS; TEST/model safety PASS; active plan consistency PASS; blocking issue NONE.

**Re-approval scope:** The human explicitly approves the existing Section 4 policy: preserve every official TRAIN row and binary label; no relabeling, majority vote, or dropping solely due to conflict; atomic predictive-feature groups with no internal cross-split membership; deterministic label-blind allocation; primary official-row-label metrics; sensitivity diagnostics clearly separated from primary metrics; locked official TEST; and label-free U1/U2 fitting. The existing restriction on additional conflict-excluded metrics remains unchanged. This records approval metadata only and preserves all prior review/fix history. Checkpoint 2.2A is ready to resume subject to existing preconditions, but this approval-recording task does not resume 2.2A, start 2.2B, or implement anything.

**Review/fix history:** The initial focused review passed U2 choice, UNSW preprocessing/leakage, TEST lock, dataset separation, and resource safety, but identified an ambiguous threshold tie between ALL_ANOMALY and the minimum numeric calibration threshold. The Section 7 fix froze explicit total ordering and added the acceptance example. The subsequent threshold review passed total ordering, deterministic tie-breaking, minimum numeric precedence over ALL_ANOMALY, TEST independence, U1/U2 consistency, and the acceptance example. The human's approval confirms all listed focused-review areas, including the corrected threshold policy. The fix and its methodology remain unchanged.

> For agentic workers: after approval, use superpowers:executing-plans or superpowers:subagent-driven-development checkpoint by checkpoint. The user's plan-only instruction governs this authoring task. Do not commit or push automatically.

**Goal:** Compare the frozen FortiGate Isolation Forest with one practical U2 anomaly scorer, and evaluate independently fitted UNSW-NB15 U1/U2 pipelines without exposing official TEST to model selection.

**Architecture:** FortiGate is a real-log anomaly case study. UNSW-NB15 is a separate labeled benchmark. Shared algorithm code is allowed; rows, schemas, fitted state, models, thresholds, predictions, and evaluations remain dataset-specific.

**Tech stack:** Python 3.12; existing pinned NumPy, SciPy, scikit-learn, joblib, threadpoolctl, matplotlib; pytest for implementation verification. No new dependency is required by this plan.

**Spec:** Approved master `docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md`, especially Section 2A; closed Stage 2.1 plan `docs/plans/stage_2_1_labeling_ground_truth_evaluation_plan.md`; validated acquisition and validation manifests below. This document refines Stage 2.2 only.

## 1. Authoritative inputs and limits

Stage 2.1 is CLOSED at commit `5d1de4a35e0535a68ed891a8ae4708e18a7095dd`, which is the inspected HEAD. Bind the following complete SHA-256 identities before execution:

| Input | SHA-256 |
|---|---|
| Master plan | `5d388f62e1d1c2a22de2e4388aee80da427c975b42ed87f2bea7c6112f0719ba` |
| Stage 2.1 plan | `0dcc029f1313066dc6fd65fedf0187676c09d86af5df115892155eea7f8bbb70` |
| `data/unsw_nb15/processed/unsw_nb15_acquisition_manifest.json` | `867ed2f8c83bba5caf4afa148ee421e5142a2d1de8da77e18d25e98cb6afd5ab` |
| `data/unsw_nb15/processed/unsw_nb15_validation_summary.json` | `d8e75198271001cb5952e15a0249f9a9c5ae2803a572669ab796d502d49727b7` |
| Official TRAIN CSV | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| Official TEST CSV | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |
| FortiGate Stage 1.8 manifest | `9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77` |

UNSW files live in `data/unsw_nb15/raw/`, with exact filenames `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`. The validated counts are 175,341 TRAIN and 82,332 TEST rows, with 45 source columns. No acquisition is needed here. The older Stage 2.1 template/code uses different root paths and a blanket overlap blocker; it is not a populated acquisition manifest. Consume the closed actual manifests and the master Section 2A overlap policy, preserving older files unchanged. Do not silently pass the actual manifest through an incompatible template validator.

The closure reports `PASS_WITH_SENSITIVITY_REQUIRED`: canonical feature duplicates excluding ID/targets/category include 74,301 TRAIN duplicate rows, 28,386 TEST duplicate rows, 1,302 cross-split feature overlaps, and 279 cross-split target conflicts. These are recorded audit outputs, not class distributions or counts of independent cases. Do not reinterpret an overlap count as the number of TEST rows to exclude. Compute the exact row mask under Section 4.

FortiGate remains 100,000 sanitized records. Its label-feasibility study is CLOSED: TRAIN 18 ATTACK / 0 BENIGN / 67,984 UNCERTAIN; VALIDATION 0 ATTACK / 12 BENIGN / 15,988 UNCERTAIN. Canonical supervised labels remain NOT PUBLISHED. AI, deterministic, and precision-first labeling remain HISTORICAL / LABEL-FEASIBILITY STUDY. No label-generation path resumes.

### Global constraints

- PLAN ONLY now: create this file only; no fitting, data processing, downloads, code/tests changes, Stage 2.3 plan, commit, or push.
- Execution requires human approval of this plan. Changed upstream identities block execution until reconciled through review; do not self-approve replacement hashes.
- Raw and published upstream artifacts are immutable; output publication is versioned and no-overwrite.
- `ANOMALY != ATTACK`; an anomaly score is not attack probability, severity, confidence, or proof of maliciousness.
- Unsupervised fitting accepts features only: no binary targets, attack categories, class-conditioned row filtering, target weights, or normal-only training.
- Model selection, threshold choice, preprocessing fitting, calibration, and architecture selection never use official TEST.
- No shared FortiGate/UNSW preprocessing state, merged training tables, transferred labels, common forced schema, or cross-dataset row-level metrics.

## 2. Stage ownership and TEST timing

| Owner | This plan's boundary |
|---|---|
| Stage 2.1 | Closed acquisition/feasibility and benchmark requirements. Stage 2.2A materializes the previously required development membership and feature contract before any fitting; it does not reopen labels or official splits. |
| Stage 2.2 | U1/U2, preprocessing, feature contract, validation, score semantics, frozen thresholds and label-free official-TEST predictions. |
| Stage 2.3 | S1/S2 supervised learning and downstream outer folds over the frozen TRAIN_INTERNAL population. No supervised fitting occurs here. |
| Stage 2.4 | UNSW-only chaining, consuming Stage 2.3 outer folds and refitting Stage 2.2 recipes with nested cross-fitting. |
| Stage 2.5 | Authorized TEST-label opening, final matrices/curves/metrics, all four U1/U2/S1/S2 primary matrices, and baseline-versus-chain reporting. |

The user's requested Stage 2.2 evaluation artifacts are produced on internal validation. Stage 2.2E also freezes final TEST predictions and executable evaluation specifications. Actual TEST confusion matrices and ROC/PR metrics remain `DEFERRED_TO_STAGE_2_5`; neither dummy matrices nor early TEST metrics satisfy the contract. This preserves the approved master assignment of final reporting to Stage 2.5. Stage 2.2 COMPLETE means its validation and prediction handoff is complete, not that final benchmark evaluation has occurred.

Before model work, the human-controlled Custodian configures an isolated TEST reader. Model-selection processes may read official TRAIN and public structural manifests only; they must not have access to the combined TEST CSV containing `label` and `attack_cat`. TEST reader storage/access configuration is private, never a public physical path or secret in the bundle. A boolean in a manifest alone is insufficient proof of access isolation: run denied-access tests from the selection process. If isolation cannot be enforced, block before fitting.

Only after 2.2D freezes model, feature-state, threshold, and comparison hashes may the isolated scoring job transform TEST features and write sealed predictions. It must remove ID/target/category before inference; it may not emit class totals, confusion counts, score histograms, examples, or feature-distribution diagnostics to model selection. Public output is status, row-count reconciliation, and artifact hashes. The Execution Agent cannot self-authorize TEST-label opening. Stage 2.5 authorization remains separately required after all model families and comparisons freeze.

## 3. U2 decision and bounded feasibility

Exactly one primary U2 family is proposed: **MiniBatchKMeans nearest-centroid squared-distance anomaly scoring**, with 32 clusters. This is a distance-based unsupervised detector, not a density estimate or attack classifier. It models multiple centers, scores unseen records, stores only centers plus preprocessing state, and has bounded cluster-distance scoring cost. This is a resource-driven candidate, not a measured winner. Its assumptions can miss dense anomalous clusters and over-rank legitimate sparse behavior; correlated numeric fields and mixed one-hot/numeric distance also affect rankings.

| Candidate considered | Decision before labels/results |
|---|---|
| MiniBatchKMeans distance scorer | Sole runnable primary candidate; selected if feasibility gates pass. |
| LOF with `novelty=True` | Valid unseen scoring, but neighbor search across this population is costly; novelty scoring must not be applied to its fitting rows as if they were unseen. Not run in this plan. |
| Kernel One-Class SVM | Excluded from full-data trials because kernel training scales poorly at this population size. |
| Robust covariance/Mahalanobis distance | Not selected: a single elliptical cloud is an unsuitable default for heterogeneous network traffic and mixed encoded features. |
| SGD one-class SVM with kernel approximation | Scalable alternative considered, but adds approximation and optimization choices. Not an automatic fallback. |

Technical basis: [MiniBatchKMeans API](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.MiniBatchKMeans.html) documents mini-batches and distances to centers; [LOF novelty guidance](https://scikit-learn.org/stable/auto_examples/neighbors/plot_lof_novelty_detection.html) distinguishes unseen scoring from training-row scoring; [scikit-learn's one-class comparison](https://scikit-learn.org/stable/auto_examples/linear_model/plot_sgdocsvm_vs_ocsvm.html) describes kernel versus stochastic-gradient scaling. These support feasibility reasoning; no runtime or accuracy is inferred from them.

Freeze U2 parameters: `n_clusters=32`, `init='k-means++'`, `n_init=3`, `batch_size=1024`, `init_size=3072`, `max_iter=100`, `tol=0.0`, `max_no_improvement=10`, `reassignment_ratio=0.01`, `compute_labels=False`, `random_state=1729`. Use one CPU thread and float64 contiguous matrices. Require at least 3,072 fitting rows and 32 distinct transformed vectors; otherwise mark that branch BLOCKED. Do not reduce cluster count, retry random seeds, or substitute another family.

U2 score: `raw_abnormality = min_j sum_k (x_k - center_jk)^2`, computed in batches of at most 4,096 rows. Higher is more anomalous. Use the smallest center index on exact ties for explanation only; center ID is not a feature or predicted attack type. There is one configuration, no hyperparameter search, and no selection based on TEST or label yield.

At 2.2B run one label-blind pilot per branch on exactly the first 10,000 eligible fitting rows in hash order, or all eligible rows if fewer. Hash ordering is ascending SHA-256 of compact JSON `["s2.2-pilot-v1", dataset_id, row_key]`, then row key. Reserve the last 2,000 of those rows as pilot unseen queries, fit on the rest, and fit pilot preprocessing on that fitting subset only. Two separate identical pilot fits per branch verify reproducibility; pilot state is discarded, never exported as the full model.

Each pilot fit plus query must finish within 120 seconds, stay below the process memory budget in Section 10, emit finite nonconstant query scores, survive serialize/reload, and reproduce scores within `rtol=1e-10, atol=1e-12` under the same pinned runtime. Use no labels in this gate. A branch failing does not trigger more candidates. If UNSW fails, U2 is BLOCKED and Stage 2.2 cannot claim COMPLETE. A FortiGate-only failure may yield the explicitly allowed documented FortiGate blocker while UNSW proceeds. Freeze the family and gate report before validation labels are read.

## 4. UNSW development split and duplicate protection

Row key is `(dataset_id, official_split, one_based_data_row_number)`; source `id` remains audit-only. Preserve every raw value and source row. TRAIN_INTERNAL, VALIDATION_CALIBRATION, and VALIDATION_COMPARISON are derived solely from official TRAIN. The latter two together are VALIDATION_INTERNAL. No TEST-dependent group assignment or removal from development is permitted.

Canonical hashing uses SHA-256 over UTF-8 JSON arrays with fixed field order, `ensure_ascii=False`, compact separators, and no NaN. Numeric canonicalization parses finite nonnegative decimal values, normalizes equivalent decimal representations, and maps negative zero to zero; missing is JSON null. Categorical strings are case-sensitive, whitespace-trimmed; `-` is a real category, empty is null. The full 42-feature source digest excludes exactly `id`, `label`, `attack_cat` and follows acquisition-manifest column order.

Within official TRAIN construct union-find groups, joining rows on any of:

1. Equal canonical full 42-feature digest.
2. Equal canonical projection onto the Section 5 allowed raw fields, preventing collisions caused by denied-feature removal from crossing splits.
3. Equal projected signature with numeric values rounded to six decimal places using decimal half-even rounding and identical categoricals/missingness. This is the frozen near-duplicate operational definition; it is not proof that all semantic duplicates were identified.

### Exact predictive duplicates and benchmark label ambiguity

An exact predictive duplicate group is equality of the canonical 28-field array BEFORE learned preprocessing: the 25 numeric fields in Section 5 order, followed by `proto`, `service`, `state`, using the existing canonicalization above. No imputation, scaling, vocabulary fit, target, attack category, ID, or model output enters this equality. Its key is the full SHA-256 of compact JSON `["s2.2-predictive-duplicate-v1", canonical_28_field_array]`. Verify canonical-array equality when grouping digest matches; a hash collision blocks instead of merging unequal arrays. This exact group remains distinct from the larger near-duplicate union-find allocation component.

Classify an exact predictive group containing both NORMAL and ATTACK as `TARGET_CONFLICT_GROUP`, representing **BENCHMARK LABEL AMBIGUITY**. Preserve every source row and official binary label, including conflicts on all 42 source features. This explicitly supersedes the previous internal TRAIN target-conflict STOP rule. Label conflict alone is not corruption or grounds for removal. Never majority-vote, relabel, collapse rows into one labeled row, drop a group solely for conflict, or use `attack_cat` to resolve targets. Do not call a label incorrect without independent evidence. Rows remain valid benchmark evaluation observations: no model using only this predictive representation can perfectly distinguish identical feature rows carrying opposite targets.

Conflict-group identity derives ONLY from the approved 28 predictive features before learned preprocessing, using the exact canonicalization and group-key algorithm above. Conflict-group count is a **DERIVED DATASET PROPERTY**, not a methodology target. Recompute it deterministically; no requirement remains to reproduce 229 under the active contract.

Historical clarification: **229 = historical observation from 42-field grouping; 273 = current observation from approved 28-predictive-feature grouping.** These observations are not contradictory because their group definitions differ. The active exact predictive/conflict-group definition remains the 28-feature definition. Do not restore historical 42-field grouping to reproduce 229. The existing full-feature and near-duplicate union rules for allocation components remain unchanged; they do not redefine the exact predictive conflict group being counted.

The human-supplied current validated Stage 2.2A observation is recorded as this provenance fingerprint:

| Property | Current observation |
|---|---:|
| Total official TRAIN rows | 175341 |
| Exact predictive groups | 88976 |
| Conflict groups | 273 |
| Conflict rows | 6896 |
| Conflict NORMAL | 2156 |
| Conflict ATTACK | 4740 |
| Group cross-split | 0 |

Bind the fingerprint to the official TRAIN raw SHA-256 `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`, the current Section 5 28-feature contract/version and its recorded representation hash, and the current canonicalization/group-key algorithm, including namespace `s2.2-predictive-duplicate-v1`. Record those identities alongside recomputed conflict metadata. If the same raw TRAIN SHA-256, same 28-feature contract/version, and same canonicalization/group-key algorithm later produce a conflict-group count other than 273, STOP as a reproducibility blocker; investigate without editing rows, labels, or grouping to force either historical or current counts.

An intentional feature-contract/version change requires a future approved amendment and a newly recomputed, versioned fingerprint, not forced preservation of 273. No row or label may be modified to force any count. Unknown/invalid binary values still fail schema validation; this policy covers valid but conflicting NORMAL/ATTACK labels only.

### Deterministic label-blind whole-group allocation

Retain the three union rules above. All rows in each resulting connected component are indivisible, regardless of label agreement. Thus exact predictive groups cannot cross TRAIN_INTERNAL, VALIDATION_CALIBRATION, or VALIDATION_COMPARISON. Both validation subsets remain VALIDATION_INTERNAL; the target proportions remain 80/10/10 (80/20 TRAIN_INTERNAL/VALIDATION_INTERNAL).

Freeze this allocation procedure, replacing the former modulo-100 bucket assignment:

1. Component ID is SHA-256 of compact JSON `["s2.2-unsw-group-v1", smallest_row_key]`, where `smallest_row_key` is the lexicographically smallest canonical full row-key JSON in the component. Order components ascending by full SHA-256 of `["s2.2-unsw-split-v1", component_id]`, then component ID. Hash inputs use the canonical JSON encoding above. No PRNG seed, random retry, label stratification, target, `attack_cat`, conflict flag, or class count participates.
2. Let `G` be component count, `N` total official TRAIN rows, and `P[k]` cumulative row count of the first `k` ordered components, with `P[0]=0`. Consider contiguous whole-component allocations with boundaries `1 <= i < j < G`: first `i` components to TRAIN_INTERNAL, next through `j` to VALIDATION_CALIBRATION, remainder to VALIDATION_COMPARISON.
3. Feasible counts must satisfy TRAIN at least 3,072 rows, each partition nonempty, and absolute deviation at most **2 percentage points** from each 80/10/10 row target. Use exact integer inequalities: `abs(100*n_train-80*N) <= 2*N`, and corresponding 10*N expressions for each validation subset. The aggregate TRAIN/VALIDATION tolerance is consequently also ±2pp. The existing component-above-20%-of-N blocker remains. These are operational allocation limits, not scientific sufficiency claims.
4. Among feasible boundary pairs, minimize lexicographically `(abs(100*n_train-80*N), abs(100*n_cal-10*N), abs(100*n_compare-10*N), i, j)`. This is the exact deterministic nearest-feasible allocation **within this frozen ordered-contiguous family**, with TRAIN ratio deviation taking priority. Do not claim a global optimum over arbitrary group permutations.
5. Bound computation to `O(G log G)` after sorting: enumerate each eligible `i` once. Binary-search the monotonically increasing prefix sums for the interval of `j` satisfying both validation tolerances and `i<j<G`; within that interval only the predecessor/successor around `P[i]+N/10` and the clipped interval endpoints need evaluation. Compare integer objective tuples, including boundary-index tie-breaks. No quadratic enumeration, optimization solver, repair rounds, seed trials, or alternative ordering is permitted.
6. If no feasible boundary pair exists, return `SPLIT_ALLOCATION_BLOCKED`, preserve the audit, and stop; never split groups, loosen tolerance, drop rows, or use labels to choose another allocation. If feasible, record boundaries, achieved counts/proportions/deviations, group counts, ordered component-list hash and membership hash. A nearest allocation within tolerance is accepted even when exact quotas are impossible. Later stages consume this immutable membership; no silent re-split.

Run label-conflict metadata as a separate audit after membership freezes. Changing valid labels or attack categories while holding feature/row inputs fixed must leave component identities, ordering and membership byte-identical. Unsupervised U1/U2 fit remains feature-only on TRAIN_INTERNAL; validation labels retain only their already-approved evaluation/threshold-selection uses. A single-class validation subset still blocks its two-class comparison/threshold evaluation without reallocating records or changing the allocation policy.

### Required conflict sensitivity diagnostic

Primary benchmark metrics preserve every eligible original row and its official row-level binary label. Include conflict rows in model fitting when assigned TRAIN_INTERNAL and in primary calibration/comparison when assigned the corresponding validation subset; do not label-condition sample weights or thresholds. Conflict metadata is audit-only, never a model feature or a model-selection objective.

Publish a reproducible official-TRAIN conflict registry containing each exact predictive group key, its allocation component ID, assigned partition, source row keys, row count, NORMAL count, ATTACK count and `TARGET_CONFLICT_GROUP` flag. Include schema version, representation/input/membership hashes, and registry SHA-256. Counts aggregate by partition and overall; rows reconcile to the unchanged 175,341-row source and unchanged official-label snapshot. A multi-class larger near-duplicate component alone does not count as an exact predictive conflict group.

Require a separately labeled **SENSITIVITY ANALYSIS ONLY — TARGET CONFLICT GROUPS** diagnostic: group count, row count and NORMAL/ATTACK totals for those exact groups, plus per-model validation TP/FP/TN/FN restricted to conflict rows and their FP/FN contribution to the primary validation error totals. Evaluate using the same frozen U1/U2 scores and thresholds; do not refit, recalibrate or select a model from this diagnostic. Show calibration and comparison partitions separately, with denominator and role labels. Zero conflict groups gives zero counts; undefined error fractions are null with a reason. These are descriptive counts/contributions, not replacement performance metrics.

No extra conflict-excluded metric is authorized by this amendment. The existing feature-overlap-excluded official TEST sensitivity policy below is unchanged and remains distinct. Do not read TEST to discover, design or tune this conflict rule. Any TEST-label-based reporting remains exclusively subject to the existing Stage 2.5 lock and cannot influence selection.

Check post-transform vector hashes for exact TRAIN/validation collisions before fitting models. Any additional collision blocks; do not revise membership after fitting. Prepared files lack stable entity/session/time fields needed to prove complete entity or chronological independence. Record this limitation explicitly, never call this a time-aware split or invent identifiers from `id`.

### Official TEST sensitivity mask

The isolated Custodian job keeps all 82,332 TEST rows for the primary official-split evaluation. Separately, exclude from the sensitivity population every TEST row whose full-feature digest, allowed-field projection, or rounded near-duplicate signature matches **any official TRAIN row**, including both internal validation subsets. Also exclude exact transformed-vector collisions with official TRAIN. The mask depends only on feature equality, never the TEST label, target-conflict status, score, or correctness. Apply the same mask to every model and freeze its hash before opening TEST labels. Do not move/delete raw rows, alter the primary population, or drop only conflicting-label cases. Report exact retained/excluded row counts and denominators at Stage 2.5. Empty or one-class sensitivity sets produce explicit unavailable metrics, not a changed mask.

## 5. UNSW feature and transformation contract

The acquisition schema is authoritative for parsing. Model features use this exact ordered numeric allowlist:

```text
dur, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload,
sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, dwin, tcprtt, synack,
ackdat, smean, dmean, trans_depth, response_body_len
```

Categorical fields follow in order: `proto, service, state`.

Deny `id`, `label`, `attack_cat`, all row/split/source identities, target aliases, predicted targets, anomaly/triage outputs, external labels, post-outcome annotations, and unknown columns. Additionally exclude `stcpb`, `dtcpb` as sequence-identity-like values; `is_ftp_login`, `is_sm_ips_ports`, and every `ct_*` source field from this version. The latter exclusions conservatively avoid undocumented contextual aggregation or identity shortcuts. Preserve them in raw evidence and the exclusion manifest. Do not recompute them using TEST or expand the allowlist after validation results. This reduced benchmark contract is intentionally not a claim to reproduce published all-feature UNSW experiments.

An ID audit proves source `id` and row/split aliases cannot enter the transformer; audit the ordered output names against all target/ID fields, and fail on extra inputs, duplicated columns, or changed schema. Correlation with a label alone is not proof of leakage and is not an automatic feature-removal criterion. No outcome-driven feature search is permitted.

Numeric handling is fixed: blank after trimming is missing; malformed text, NaN/infinity, or negative numbers block parsing with row/field identifiers (no silent coercion). Preserve valid zero. Apply `log1p` to every observed allowed numeric field, impute each missing value using the fitting partition's median in log space (all-missing fitting column uses zero), then StandardScaler population mean/variance with zero-variance scale one. Append one unscaled missing indicator per numeric field, in the same order, including for columns with no fitting missingness. No clipping, winsorization, outcome imputation, or feature selection.

Categoricals use ordered one-hot encoding: per field, sorted lexicographic fitting vocabulary plus distinct reserved `MISSING` and `UNKNOWN` channels; namespace tokens so literal strings cannot collide with reserved values. Missing maps to MISSING; unseen observed values map to UNKNOWN. Fit vocabulary only on TRAIN_INTERNAL or the current nested fitting subset. No target/frequency encoding. Each observed category contributes a single 1, no dummy dropping or categorical scaling.

Final order: scaled numeric fields, numeric missing indicators, then categorical blocks in the listed order. Persist names/order/dtype, medians, means, scales, vocabularies, and hashes. Reject more than 512 output columns as a resource/schema blocker, not a reason to truncate vocabulary. U1 and U2 receive the identical matrix and row order on UNSW. All transformation state fits only TRAIN_INTERNAL; calibration/comparison/TEST receive transform-only calls. No final refit on validation is allowed in this version, avoiding changed score scales and invalid frozen thresholds.

## 6. FortiGate path and frozen U1

Consume the frozen Stage 1.7 feature artifact and metadata and Stage 1.8 manifest/scores through their existing integrity checks. Preserve the exact ordered 36-feature definition from `src/ai_features/models.py`. Stage 1.7's recorded REFERENCE/HOLDOUT membership is 79,947 / 20,053, with session-aware hash grouping; validate actual identities and counts before use. Rarity maps and historical feature state must verify as REFERENCE-only. Never substitute the later historical label-feasibility 70/15/15 split for these artifact partitions.

U1 remains the existing frozen Stage 1.8 Isolation Forest and its published scores. Do not refit, rescale, redefine, or overwrite it. Validate hashes before any model deserialization; published score reuse is sufficient for comparison, so no U1 full-data rebuild is scheduled. An incompatible trusted-model runtime does not authorize refitting. Preserve raw abnormality and historical percentile semantics separately.

For U2, StandardScaler with population variance fits on REFERENCE only and transforms all 36 existing features; constant columns use scale one. No new base features, imputation, clipping, or label-derived transforms are added. Log transforms and missing flags already in the frozen 36 features are not reapplied. Fit the fixed U2 on all REFERENCE rows; score REFERENCE and HOLDOUT separately, then all-row reporting joins by source record key. REFERENCE scores are explicitly in-sample diagnostics.

Primary behavioral comparison is on the identical HOLDOUT row IDs: Spearman rank correlation using average ranks for ties, and Top-50 / Top-100 / Top-1%-of-HOLDOUT Jaccard overlap. Top-1% uses ceiling; deterministic top lists sort descending unrounded abnormality, then ascending source record number. Report alert fraction for each model using its own REFERENCE 99th-percentile threshold (nearest-rank `ceil(0.99*n)`, decision `score > threshold`). This 1% reference-tail policy is operational prioritization, not estimated attack prevalence; ties may yield fewer alerts.

Report all-row and REFERENCE overlap as secondary descriptive analysis. Do not treat agreement with U1, source threat observations, or old proxy labels as ground truth. Existing historical split limitations, including any cross-partition duplicate activity, must be disclosed through a feature-only audit; do not re-split/rebuild the frozen baseline to improve agreement. No accuracy/precision/recall/F1 or attack confusion matrix for FortiGate.

For the top 50 U2 rows, explain the three largest squared coordinate residuals from their nearest center (descending contribution, feature-order ties). Name them as distance contributions in scaled feature space; do not describe causal attacks. Include source evidence links and reuse existing U1 explanations only with their original identity and interpretation. Runtime comparison lists historical U1 timing as unavailable unless a comparable recorded measurement exists; do not invent a U1 speed advantage.

## 7. UNSW U1/U2 fitting, threshold and comparison

UNSW U1 is a new benchmark-specific Isolation Forest, not a modification of FortiGate U1. Freeze `n_estimators=200`, `max_samples=4096`, `max_features=1.0`, `contamination='auto'`, `bootstrap=False`, `n_jobs=1`, `random_state=1729`, `warm_start=False`. Fit features from all TRAIN_INTERNAL rows, with no labels or class filtering. Require at least 4,096 TRAIN rows for this model; otherwise block U1. U1 score is `-score_samples(X)`, higher meaning more anomalous. U2 uses Section 3. No library default contamination decision or cluster ID defines the benchmark decision.

Threshold selection uses only VALIDATION_CALIBRATION labels after both recipes and fits freeze. For each model, consider the sorted unique observed calibration scores plus two explicitly serialized boundary policies `ALL_INLIER` and `ALL_ANOMALY`. A numeric threshold predicts ANOMALY iff `score >= threshold`, and INLIER otherwise; never split tied scores by label or row identity. Maximize binary F1 against ATTACK=1 and NORMAL=0. Compare rational F1 exactly using confusion integers. This is label-assisted development threshold calibration of an unsupervised fit and must be described as such. It is not fully label-free deployment performance. Require both reference classes in calibration.

Apply the same threshold semantics and deterministic total ordering to U1 and U2:

```text
ALL_ANOMALY < any finite numeric threshold < ALL_INLIER
```

`ALL_ANOMALY` is a logical sentinel below every possible finite score and always predicts ANOMALY. `ALL_INLIER` is a logical sentinel above every possible finite score and always predicts INLIER. Serialize these boundary policies as enums, never actual floating-point infinity or JSON infinity.

First maximize the approved calibration F1 objective. Among candidates with exactly identical objective values, choose the larger threshold under this total ordering. Between numeric candidates, retain the existing larger-numeric-threshold rule; equal numeric values are already deduplicated in the sorted unique candidate set and represent the same decision policy. No TEST information may participate in any tie-break. Freeze the selected policy before TEST scoring.

Acceptance example for both U1 and U2: calibration scores `[1.0, 2.0]` with reference labels `[ATTACK, NORMAL]` give both `ALL_ANOMALY` and numeric threshold `1.0` the decisions `[ANOMALY, ANOMALY]`, with TP=1, FP=1, FN=0 and F1=2/3. Threshold `2.0` and `ALL_INLIER` each have F1=0. Numeric threshold `1.0` MUST win over `ALL_ANOMALY` under the frozen ordering. For a hypothetical unseen score `0.5`, the selected numeric policy predicts INLIER while `ALL_ANOMALY` would predict ANOMALY; this intended distinction is why the tie must resolve explicitly. This is a synthetic acceptance example, not TEST data or a measured result.

Evaluate each frozen threshold once on VALIDATION_COMPARISON. Primary comparison metric is **average precision (AP)** on continuous anomaly scores with ATTACK positive; label the reported PR-AUC convention `PR_AUC_AP`, computed by sklearn `average_precision_score`, not trapezoidal PR integration. See the [AP definition](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html). Secondary continuous metric: ROC-AUC plus complete ROC and precision-recall point arrays. Thresholded outputs: TP/FP/TN/FN, precision, recall, F1, accuracy, and predicted anomaly fraction. Axes are reference rows NORMAL/ATTACK and decision columns INLIER/ANOMALY: `[[TN,FP],[FN,TP]]`.

Precision with no predicted positives is null with `NO_PREDICTED_ANOMALIES`; recall without reference positives is null; F1 is `2TP/(2TP+FP+FN)` unless its denominator is zero (null). ROC-AUC/AP are null with `SINGLE_REFERENCE_CLASS` for a one-class population; never silently replace undefined metrics by perfect performance. Output population sizes and denominators alongside every metric. Score ties are valid; all-equal fitting scores block the model as degenerate before TEST prediction.

U1/U2 comparison uses the same preprocessing, fitting rows, comparison rows, threshold-selection rule, and one configuration each. AP higher by more than `1e-6` determines the descriptive validation preference; at absolute difference <= `1e-6`, prefer lower recorded fit-plus-comparison-score wall time; if rounded millisecond times tie, prefer U1. Runtime preference is operational, hardware-dependent, and not statistical significance. Keep both valid models regardless of preference. Validation is a development comparison, not a final unbiased performance claim. No assumption U2 must beat U1 or chained ML must outperform either baseline. Do not rerun a losing model or tune from comparison-set metrics.

## 8. Artifacts, schemas and chained compatibility

Use fresh no-overwrite roots `data/processed/stage_2_2/fortigate/v1/` and `data/unsw_nb15/processed/stage_2_2/v1/`. A failed partial run remains an explicitly incomplete builder-owned workspace; checkpoint resume uses validated hashes, never overwrites an accepted bundle.

| Branch | Required logical artifacts |
|---|---|
| FortiGate | input identity manifest; U2 scaler/model; U2 scores; U1 immutable score reference; HOLDOUT and descriptive comparison JSON; top-row distance explanations; resource/reproducibility record; manifest or branch blocker. |
| UNSW | frozen feature/exclusion contract; split/group membership; training duplicate audit; preprocessing state; U1/U2 models; fitting/validation scores; calibration thresholds; validation metrics; U1/U2 validation confusion matrices and ROC/PR points; comparison; frozen selection lock; sealed TEST predictions; TEST evaluation recipe and deferred status; sensitivity-mask hash; resource/reproducibility record. |
| Handoff | per-branch statuses, artifact manifests, recipe registry, score semantics, consumer allowlists, and pending Stage 2.5 evaluation status. No mixed dataset rows. |

Every score JSONL row has exactly: `schema_version` string `1.0`; `dataset_id`, `branch_id`, `row_key`, `split_id`, `model_id`, `model_version`, `fit_membership_sha256`, `feature_state_sha256` strings; finite float `raw_abnormality`; `score_direction` exactly `HIGHER_MORE_ANOMALOUS`; `fit_relationship` enum `IN_SAMPLE|HELD_OUT|OFFICIAL_TEST`; nullable `threshold_id`; nullable `decision` enum `ANOMALY|INLIER`; `chain_training_eligible` boolean (false for all current Stage 2.2 rows). No target/category field appears in scores. U1 and U2 use separate files. Persist source-order rows; separate ranks use score descending/key ascending.

Each artifact manifest includes schema version, dataset/branch IDs, plan/commit/runtime identities, parameters, ordered feature contract hash, fit split and membership hash, parent hashes, seed, score formula/version, threshold source/hash, row count, and each file's complete SHA-256. No self-referential hash. JSON is UTF-8, sorted keys, compact separators, finite values and LF endings. Resource/timestamps are separate observational metadata; reproducible numerical content hashes exclude timing. Load serialized models only after externally anchored manifest and model hashes and runtime compatibility pass.

The Stage 2.4 handoff exports a **refittable recipe**, not permission to append the globally fitted score file to supervised TRAIN. Export `fit_recipe(X_train)` and `score_unseen(model, X_query)` semantics with dataset/version/feature lineage. All Stage 2.2 scores remain ineligible as chained training features. Stage 2.3 owns outer folds; Stage 2.4 must fit preprocessing and U1/U2 anew inside each outer training partition, generate its supervised training anomaly signals by nested inner cross-fitting, and score the outer held-out group with no exposure to its rows. Learned rarity, scaling, medians, vocabularies, centroids/trees and score transformations are fold-local. Stage 2.2 exports raw score only; any later percentile normalization must also be fit within the appropriate fold. No chained model runs here.

## 9. Frozen final evaluation specification

Stage 2.5 consumes the sealed predictions and unchanged thresholds. It joins labels by validated official TEST keys inside Custodian-controlled evaluation, computes Section 7 metrics and U1/U2 matrices both on all official TEST rows and the frozen duplicate-excluded sensitivity population, and reports both with distinct population names. It cannot choose a new headline population, flip score signs, select thresholds, fit calibration, or pick a new model after results. Primary headline remains official TEST AP; sensitivity AP is mandatory alongside it. The known overlap/conflict limitation must accompany the official result.

These are two of the master’s four primary benchmark matrices; S1/S2 matrices belong to later stages, and chained matrices are additional. No placeholder S1/S2 results are generated here. No current measured performance is claimed in this plan.

Allowed language: “U1/U2 anomaly decisions evaluated against UNSW-NB15 NORMAL/ATTACK benchmark labels.” Quantitative metrics are UNSW-scoped; FortiGate reports anomaly scoring, explainability, prioritization, and real-log case-study findings only.

Mandatory statement: **Benchmark performance does not prove identical performance on the real FortiGate environment.**

## 10. Resource and replay budget

All budgets are RESOURCE-CONSTRAINED operational limits for an Apple Silicon MacBook Air, not claims of optimal statistical design. Record hardware/RAM, OS, Python/library versions and thread environment before running. Cap BLAS/OpenMP and estimator execution to one thread; prohibit parallel model fits. No full pairwise distance matrix, kernel matrix, exhaustive search, GPU, or extra dependency.

Memory ceiling is `min(4 GiB, 0.5 * physical RAM)` for the model worker, including its children. The parent watchdog polls RSS at least every second and terminates on breach; preflight estimates matrices and work arrays and blocks if their estimated peak exceeds that limit. Record macOS RSS in bytes, not assumed Linux units. If usage cannot be measured, block the expensive run. Dense encoded arrays are limited to 512 columns and 4,096-row scoring batches.

Budget: four pilot fits total (two per branch); then at most one full FortiGate U2 fit, one full UNSW U1 fit and one full UNSW U2 fit. Each full fit is capped at 900 seconds; each full scoring pass at 300 seconds; each contract/feature-building checkpoint at 600 seconds. Shared feature parsing happens once per branch per accepted recipe. Serialize once, reload and replay a fixed first-1,000 hash-ordered query subset once per full model; no additional full refit for replay. Verify same-runtime pilot refit reproducibility and full-model serialization replay separately. Cross-platform byte-identical pickle files are not promised.

One recorded initial execution per expensive step; interruption/resource failure produces BLOCKED, without automatic retries, bigger limits, alternate seeds, more clusters, or repeated full datasets. A separately authorized resume may replay an interrupted step with identical inputs after reporting why; acceptance cannot silently increase the scientific search budget. Checkpoints report elapsed time, peak memory, counts, hashes and next permitted action, then return control before the next expensive checkpoint. No performance claim until measured.

## 11. Implementation map and checkable checkpoints

All paths in this section are **future execution targets**, not changes made while authoring this plan. Reuse existing pure contracts from `src/ai_features/`, `src/anomaly/`, and `src/benchmarks/unsw_contract.py` where compatible; preserve their historical semantics and tests. New orchestration lives in `src/compare_unsupervised.py`; a focused `src/unsupervised/` package contains `contracts.py`, `features.py`, `splits.py`, `models.py`, `evaluation.py`, `artifacts.py`, and `__init__.py`. Tests mirror these boundaries in `tests/test_stage_2_2_contracts.py`, `test_stage_2_2_models.py`, `test_stage_2_2_evaluation.py`, and `test_stage_2_2_artifacts.py`. Execution findings eventually go to `docs/stage_2_2_unsupervised_findings.md`. No Stage 2.3 files are in scope.

Shared typed interfaces: `RowKey = str` (canonical JSON row key); `SplitManifest` holds row/group/partition mapping and hash; `FeatureState` holds ordered fields, learned transforms and hash; `ScoreBatch` holds aligned row keys and finite raw scores; `ModelBundle` binds model, state, fit membership and provenance; `ThresholdPolicy` holds enum/numeric threshold and calibration hash. Exact serialized records are governed by Sections 4–8; Python dataclasses may carry the same fields without introducing alternate semantics.

### 2.2A — UNSW feature/split contract

**Files:** create contracts/features/splits and contract tests; add the CLI contract subcommand.

**Interfaces:** `build_split_manifest(train_rows) -> SplitManifest`; `fit_features(train_rows, dataset_id) -> FeatureState`; `transform_features(rows, state) -> ndarray`; `validate_input_identities() -> report`. No function accepts TEST labels or a combined train/test fitting frame.

- [ ] Write synthetic tests for canonical equivalence, duplicate/near-duplicate grouping, group-size blocker, deterministic partitioning, ID/target exclusion, unseen categories, all-missing/constant numerics, invalid numbers, cross-branch rejection, and transform-only holdouts.
- [ ] Add targeted duplicate-conflict tests: mixed-label exact 28-feature groups (including full-42-feature conflicts) preserve all rows and labels and occupy one partition; zero exact predictive groups cross any internal partition; label/category permutations leave allocation unchanged; equal canonical features yield identical keys; registry counts/hashes replay exactly; no majority vote, relabeling, label-based dropping or collapse occurs. Verify approved fitting receives features only and TEST readers are never invoked by grouping/allocation/conflict audit.
- [ ] Test allocation on small synthetic component sizes against an exhaustive boundary-pair oracle for the frozen contiguous family, including exact quotas, nearest feasible quotas, ±2pp endpoints, index tie-breaks, indivisible large components and infeasible results. Test per-model conflict FP/FN contributions against hand-counted validation examples while primary metrics retain every row. Exhaustive enumeration is a tiny-fixture test oracle only, never the production allocator.
- [ ] Run `python -m pytest tests/test_stage_2_2_contracts.py -q`; confirm new tests fail before their implementation, then pass after implementation.
- [ ] Implement the exact deterministic split, parser, allowlist and transformation state; bind upstream hashes and isolated TEST access verification.
- [ ] Run read-only official TRAIN contract materialization once; verify coverage equals 175,341, row keys are unique, protected groups never cross partitions, feature dimensions/order match and artifacts reconcile. Record missing entity/time guarantees. No model fitting yet.
- [ ] Before 2.2A may proceed under this amendment, independently assert zero predictive-duplicate groups cross TRAIN_INTERNAL/VALIDATION_INTERNAL or the two validation subsets; prove source-row and official-label preservation; verify label-blind deterministic allocation, achieved ratios/tolerance, reproducible conflict metadata, and no TEST access. Conflict presence alone is not a blocker; remaining schema, resource, partition and TEST-isolation gates still apply. Materialize the diagnostic metadata now; validation error contributions are completed from frozen scores in 2.2D.
- [ ] Publish a contract checkpoint/hash; block on any invalid input or missing TEST isolation.

### 2.2B — U2 candidate feasibility

**Files:** models and model tests; resource watchdog in CLI orchestration.

**Interfaces:** `fit_u2(X_train, membership) -> ModelBundle`; `score_u2(bundle, X_query) -> ScoreBatch`; `run_feasibility(dataset_id, contract) -> report`.

- [ ] Test nearest-center squared distance, tie behavior, finite checks, too-small training sets, target-free fit calls, resource-stop behavior and serialization replay using small synthetic inputs.
- [ ] Run `python -m pytest tests/test_stage_2_2_models.py -q` before/after implementation.
- [ ] Implement the single U2 recipe and bounded gate; run exactly the four allowed pilot fits. Record parameters, timings, memory and numerical replay checks for both branches.
- [ ] Freeze SELECTED or BLOCKED by branch. Never add a fallback or optimize against labels. Return control before full fits.

### 2.2C — FortiGate U2 run

**Files:** FortiGate adapter in features, model runner, evaluation and model tests.

**Interfaces:** `load_fortigate_reference() -> rows_and_state`; `compare_fortigate(u1_scores, u2_scores) -> report`.

- [ ] Test that the 36-feature order and original partitions survive, U1 is never fit, U2 scaling fits only REFERENCE, and joins reject missing/duplicate row keys.
- [ ] Run focused model tests plus `python -m pytest tests/test_ai_features.py tests/test_anomaly.py -q` after adapter work.
- [ ] Validate frozen input hashes; fit U2 once and score 100,000 rows under the budget, or publish the exact FortiGate blocker if its gate fails.
- [ ] Produce HOLDOUT overlap/correlation, separate in-sample diagnostics, top-50 distance explanations and resource metadata. No attack metrics. Return control.

### 2.2D — UNSW U1/U2 validation

**Files:** evaluation, UNSW model runner, evaluation tests.

**Interfaces:** `fit_u1(X_train, membership) -> ModelBundle`; `select_threshold(calibration_scores, calibration_labels) -> ThresholdPolicy`; `evaluate_scores(scores, labels, threshold) -> metrics`; `compare_models(reports) -> preference`.

- [ ] Test fit spies never receive labels, identical U1/U2 feature matrices, threshold ties/boundary policies, exact confusion-axis ordering, missing metric reasons, AP versus ROC separation and deterministic preference ties.
- [ ] Run `python -m pytest tests/test_stage_2_2_evaluation.py tests/test_stage_2_2_models.py -q`; then fit each UNSW model once on TRAIN_INTERNAL.
- [ ] Freeze models; calibrate on VALIDATION_CALIBRATION once, compare on VALIDATION_COMPARISON once. Neither validation subset enters fit state. Reuse saved scores for all metrics and plots.
- [ ] Persist both models regardless of which is preferred, numerical replay evidence, thresholds, all validation artifacts and a selection-lock manifest. No TEST access. Return control.

### 2.2E — Locked prediction and evaluation handoff

**Files:** artifacts, artifact tests, final CLI checkpoint and findings document.

**Interfaces:** `publish_bundle(bundle, destination) -> manifest`; `score_locked_test(selection_lock, custodian_reader) -> sealed_manifest`; `audit_bundle(manifest) -> report`. TEST scoring interface accepts no labels and returns no public diagnostics derived from TEST scores.

- [ ] Test rejected pre-lock TEST access, failed hashes before deserialization, mismatched feature order, no-overwrite publication, partial failure, no target/class totals in public output, full/sensitivity population separation and rejected chain-training use of Stage 2.2 scores.
- [ ] Run targeted artifact tests; then `python -m pytest tests/test_stage_2_2_contracts.py tests/test_stage_2_2_models.py tests/test_stage_2_2_evaluation.py tests/test_stage_2_2_artifacts.py tests/test_stage_2_1_unsw_contract.py tests/test_ai_features.py tests/test_anomaly.py -q`.
- [ ] Verify selection lock before the isolated job scores all 82,332 official TEST rows once per model and freezes the feature-only sensitivity mask. No TEST metrics are released.
- [ ] Independently validate row reconciliation, schemas, full hashes, state boundaries, manifests and replay. Publish bundles plus deferred final-evaluation specification; record honest branch status and findings. Run the existing full test suite once after the targeted tests pass and before completion.

Checkpoint CLI design: `python src/compare_unsupervised.py --checkpoint 2.2A` through `2.2E`, with explicit versioned output root and approved input/plan hashes. No default command trains every model. Sensitive Custodian storage is configured out of band. Exact CLI parsing is routine implementation; it must expose no option that changes frozen seeds, metrics, populations, model family or TEST timing.

## 12. Review focus and acceptance

Review focuses on five failure modes: leakage through labels/IDs (2.2A/D tests), duplicate groups crossing development splits (2.2A), hidden preprocessing fit on validation/TEST (2.2A/D), early TEST diagnostics affecting later models (2.2E), and global anomaly scores reused in chained training (2.2E). Synthetic tests must exercise each, not merely successful runs.

Stage 2.2 is COMPLETE only when:

- U2 selection is documented and UNSW U1/U2 pass their gates; FortiGate U2 completes or has a concrete documented branch blocker.
- Frozen FortiGate U1 and its features remain unchanged; no FortiGate canonical labels or supervised metrics were created.
- Feature/split/duplicate and fit-state audits pass, no model-selection step accesses TEST, and only official TRAIN supplies development data.
- Exact predictive duplicates are partition-contained, all original rows/official labels are retained, allocation is label-blind and within its frozen tolerance, and the reproducible conflict registry plus required validation sensitivity diagnostic exist. No conflict diagnostic replaces primary official-label metrics.
- Numerical replay, manifest verification, targeted tests and final regression tests pass; resource measurements are real, not forecasts reported as results.
- UNSW validation matrices, continuous metrics/curves, thresholds and comparison exist for both models; all official TEST predictions are locked and complete.
- Duplicate-excluded sensitivity policy/mask is frozen; final TEST metrics are explicitly deferred to Stage 2.5 and have no fabricated values.
- Stage 2.3 receives immutable membership/feature contracts, Stage 2.4 receives refittable recipes and the no-global-score guard, and Stage 2.5 receives sealed predictions/evaluation instructions.
- Required interpretation and domain-transfer statements appear in reports; U1 may remain preferable and chaining has no promised benefit.

Possible checkpoint states are NOT_STARTED, RUNNING, PASS, BLOCKED; overall status is COMPLETE only under the above rule, otherwise BLOCKED with exact prerequisite/branch and evidence. A failed UNSW U2 may still yield an honest U1 partial artifact and `U2_UNAVAILABLE`, as permitted by the master, but does not satisfy this requested Stage 2.2 completion gate. No automatic later-stage progression, new model search or approval of this plan occurs.

**PLAN STATUS:** APPROVED — STAGE 2.2 WITH CONFLICT-GROUP RECONCILIATION FIX
