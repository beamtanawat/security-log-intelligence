# Stage 2.4 — Chained ML Pipeline Implementation Plan

> For agentic workers: after explicit human approval, use superpowers:executing-plans or superpowers:subagent-driven-development checkpoint by checkpoint. This document is PLAN ONLY; do not implement, train, generate signals, evaluate TEST, start Stage 2.5, commit, or push during plan authoring.

**PLAN STATUS:** APPROVED — STAGE 2.4 CHAINED ML PIPELINE

**Plan ID / version:** S2.4-UNSW-CHAIN-V1 / 1.0

**Approval:** Explicit HUMAN APPROVAL provided for Stage 2.4 Chained ML Pipeline. Previously READY FOR HUMAN REVIEW with approval pending. The focused review passed chain feature contract, same-row/group leakage, nested cross-fitting, baseline-vs-chain comparison, baseline immutability, TEST governance, resource/provenance safety, and active plan consistency; blocking issue NONE. The human approves the existing UNSW-only architecture, frozen baseline model configurations, continuous U1/U2 signals, nested OOF/group-exclusion rules, Average Precision comparison, baseline immutability and TEST restrictions unchanged. This update records approval metadata only; it does not implement, generate OOF signals, train chained models, open TEST, start Stage 2.5, commit or push. Each checkpoint must STOP before the next, and final TEST evaluation still requires its separate selection lock and explicit human authorization.

**Goal:** Determine whether leakage-safe continuous U1/U2 anomaly signals add useful predictive information beyond the 28 UNSW base features, without modifying the frozen supervised baselines.

**Architecture:** CHAIN-S1 is Logistic Regression; CHAIN-S2 is Random Forest. Both append exactly two continuous anomaly signals to the existing base representation. Nested group-safe cross-fitting constructs training signals; full authorized-training fits serve held-out inference only. Model configurations and thresholds are inherited, not tuned again.

**Tech stack:** Python 3.12 and existing pinned NumPy/scikit-learn/SciPy/joblib/threadpoolctl/matplotlib; pytest. No new dependency, model family, GPU, or exhaustive search.

**Spec:** Human Stage 2.4 request and resume instruction in this conversation; approved master `docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md`, active Section 2A; closed Stage 2.2 and Stage 2.3 plans and immutable artifacts listed below. This plan refines Stage 2.4 only.

## 1. Authority and global constraints

Stage 2.2 is CLOSED at `aeb36ebb8c16fa6eed0b42960dd619b68a889f72`. Stage 2.3 is CLOSED at `674f9035737f5e675797c911c6e92e1f4cdcabca`, the inspected HEAD. Let `B3` mean `data/unsw_nb15/processed/stage_2_3/v1/` and `B2` mean `data/unsw_nb15/processed/stage_2_2/v1/`.

| Authoritative input | SHA-256 of file bytes |
|---|---|
| Master plan | `5d388f62e1d1c2a22de2e4388aee80da427c975b42ed87f2bea7c6112f0719ba` |
| Stage 2.2 plan | `3dd3fccb40f800600c79225e5c2815b88f26a76313fadc96f94cd37b34d64849` |
| Stage 2.3 plan | `8f4d58146353b76fdca3279983c9258535b33ae8f6e87b39862eedae72a658c6` |
| `B3/manifests/selection_lock.json` | `515df6a7b017853d3917dae276aa656b858587ba294ffdb28a001762ba6ceb5a` |
| `B3/manifests/stage_2_4_handoff.json` | `54db2ea4a8b5fa5e12a3a66226fc21ddd8fb5b953aaca9dcbdb5a7bf608acf0e` |
| `B3/manifests/folds.jsonl` | `2c86ff51fa4cf2af761f2d26841747c2559a76999a92321351f4b09ef0d784dd` |
| `B3/reports/selection.json` | `8f7fffecccad0999c7959654616eaef0b5d8bea60ebe32c5bf6915f7d78d059f` |
| `B3/contracts/supervised_contract.json` | `057cc9b9eb1eb8183f4513ec30cc7471c4da5d3cd766d91d59309c603975f539` |
| `B2/contracts/unsw_feature_contract.json` | `bc66e157f74992c66b798f37a933f2894fe65b6df7d4b010e973465a7e6e14f6` |
| `B2/manifests/unsw_split_manifest.jsonl` | `f58d7527168a44588d095d0be9e718dccd86641f0d10570ef9986ea8efd9d06b` |

Official TRAIN identity is `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`; inherited official TEST identity is `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`. Raw filenames are `data/unsw_nb15/raw/UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`. Development verifies TRAIN only; TEST content verification belongs to the authorized final evaluator.

- Dataset `UNSW_NB15_BENCHMARK`, branch `BRANCH_B_LABELED_BENCHMARK` only. Reject mixed branches/datasets. FortiGate remains a separate real-log unsupervised anomaly case study; no supervised chaining, merged tables, fitted-state sharing, or transferred labels.
- Preserve every official row and binary label: NORMAL=0, ATTACK=1. No majority vote, relabeling, conflict-row dropping, target-conditioned unsupervised fitting, class weighting or resampling. Neither `label` nor `attack_cat` enters U1/U2 fitting or predictive features.
- Stage 2.3 baselines, thresholds and preferred model S2 remain immutable. No retraining/overwriting baselines, rewriting their TEST results or changing their prior preference. Additional chained results never replace the four primary baseline matrices.
- Existing Stage 2.2/2.3 TEST results are HISTORICAL EVALUATION OUTPUTS ONLY. They must not influence features, folds, models, thresholds, improvement criteria, retention of U1/U2 or development decisions. They were not read as planning inputs.
- Changed upstream identities, unavailable required lineage or incompatible runtime blocks execution; do not silently regenerate upstream artifacts or update hashes.
- Each checkpoint requires explicit authorization and STOP before the next. No automatic implementation, dependency change, commit or push. Outputs are versioned and no-overwrite.

### Review focus

- A globally OOF signal can still leak an outer held-out group into outer-training signals: 2.4B tests context-specific exclusion, not merely same-row exclusion.
- Reusing full-TRAIN categorical/scaling state leaks held-out information: 2.4B tests fold-local vocabulary and statistics.
- Cached artifacts can have the right row count but wrong fit groups: 2.4A/B verify exact membership and hashes, not counts alone.
- Frozen outer baseline configurations must come from fold-local Stage 2.3 selection: 2.4A checks provenance before paired OOF comparison.
- Earlier benchmark TEST results remain locally available: 2.4D/E test logical read/write boundaries and disclosure, not a false claim that TEST has never been seen.

## 2. Data, features, and immutable comparison populations

Reuse Stage 2.2 membership and Stage 2.3 outer/inner fold manifests unchanged. Official TRAIN has 175341 rows: TRAIN_INTERNAL `T` has 140273; VALIDATION_CALIBRATION has 17539; VALIDATION_COMPARISON has 17529. Neither validation subset is fitted, cross-fitted into training, or added to final training. TEST retains its original 82332 rows.

Duplicate identity remains the approved **28 predictive features before learned preprocessing**. Reconcile 88976 exact predictive groups, 273 conflicting-label groups, 6896 conflict rows, 2156 NORMAL, 4740 ATTACK; historical 229 is a different 42-field definition, not an active target. Same input/contract/group algorithm must reproduce this fingerprint. Preserve upstream `group_id` components, including stronger near-duplicate containment; never derive groups from targets or transformed chain features.

Base numeric feature order (25): `dur, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, dwin, tcprtt, synack, ackdat, smean, dmean, trans_depth, response_body_len`. Categorical order: `proto, service, state`.

Retain Stage 2.3 target/ID/leakage denylist. Only two additional predictive fields are authorized: `u1_anomaly_score`, `u2_anomaly_score`. Exclude binary anomaly decisions, cluster IDs, ranks, threshold bands, explanations, rule/triage outputs, supervised predictions, target encodings, and all other Stage 2.2 outputs. No U1-only/U2-only variants, post-hoc combinations or signal removal in V1. Missing/invalid required U1 or U2 signals BLOCK both chains rather than falling back to another feature set.

Reuse the base preprocessing algorithm, not globally fitted state: nonnegative finite numeric parsing, log1p, fit-only log-space median (all-missing fallback 0), population mean/std (zero std becomes 1), 25 missing indicators, and fit-only sorted categorical one-hot vocabulary with existing missing/unknown handling. Deterministic ordering is scaled numeric, numeric missing indicators, categorical blocks, then the two signal columns. Dense float64; maximum base width 512, chained width 514. Full T base width must reconcile to 209, giving 211 chained columns. Fold widths may differ; no held-out vocabulary borrowing.

U1/U2 preprocessing is fit on each anomaly model's authorized fit subset. Supervised base preprocessing is separately fit on each downstream supervised training population. Even if the pure transformation code is shared, state can be shared only for exactly identical authorized fit memberships and algorithm/configuration hashes.

### Signal transformations

Raw U1 signal is `-IsolationForest.score_samples(X)`; raw U2 signal is squared distance to the nearest centroid, `min_j ||X - center_j||^2`. Both mean **HIGHER = MORE ANOMALOUS**, not attack/malicious probability or confirmed attack score.

For both chains, append `z_u1` and `z_log1p_u2`: use raw U1 and log1p(raw U2), then standardize each with population mean/std learned exclusively from the OOF signal values in the current supervised training population. Zero std uses 1. Store the raw scores and scaler separately. All scores must be finite; U2 must be nonnegative; no clipping, winsorizing, score ranking or TEST normalization. Held-out rows receive these frozen training-OOF-derived scalers. These fixed monotonic transformations preserve score direction and do not create extra predictive signals.

OOF-fit versus full-fit anomaly scores can differ in distribution because training sizes differ. Report this limitation; validation/TEST shifts do not authorize recalibration or rescoring training rows with full-fit models.

## 3. Exact nested cross-fitting contract

Let `H_k` be upstream outer fold k, k=0,1,2; `A_k = T minus H_k`. Inside `A_k`, reuse the two upstream inner subsets `J_k0`, `J_k1`. Allocate no new folds and never change upstream membership. All membership operations use row keys and indivisible upstream groups.

For each outer context k:

1. For j=0,1, fit new U1/U2 preprocessing and models on `A_k minus J_kj` only; transform/score `J_kj` only. U fitting has no labels, label weights or class filtering. Concatenate these held-out scores in original row-key order to cover every row of `A_k` once.
2. Fit downstream base preprocessing on `A_k`; fit signal scalers on the OOF scores from step 1 only. Fit CHAIN-S1 and CHAIN-S2 on this representation and official `A_k` labels.
3. Fit separate U1/U2 preprocessing and models on all `A_k`, then transform/score `H_k`. These models cannot generate step 1 training signals. Transform `H_k` base fields with the downstream `A_k` state and its step 1 signal scalers; predict both chains.
4. Store one supervised outer-OOF prediction per `H_k` row. Entire `H_k` groups are absent from every U fit, preprocessing fit, signal scaler fit, supervised fit and inherited supervised configuration-selection population used by that outer pipeline.

```text
Outer training A_k
  J_k0 <- U fitted/preprocessed on J_k1
  J_k1 <- U fitted/preprocessed on J_k0
  concatenate OOF signals -> train-only signal scaling + base preprocessing
                          -> fit CHAIN-S1 / CHAIN-S2 on A_k
Outer held-out H_k <- U fitted/preprocessed on A_k
                  -> frozen A_k downstream transforms -> outer predictions
```

For final development fits, concatenate the step 3 raw held-out U1/U2 scores across H_0/H_1/H_2 to obtain full-T OOF signals. This reuse is valid for final training because every scored group was absent from its U/preprocessing fit. It is NOT valid as outer-training signals in step 1: the global OOF scorer may have seen another outer held-out group. Fit downstream base preprocessing on T and signal scalers on full-T OOF scores. Fit final CHAIN-S1/CHAIN-S2 on these features and official T labels.

Fit one additional U1/U2 pair on all T for inference on both validation subsets and, only after the final lock, TEST. No validation/TEST row contributes to any fit. Full-T U models must never score T to construct training features.

There is **no chain-specific inner hyperparameter tuning**. The two inner folds above exist to construct training signals, not to select a chain. Any future tuning proposal must introduce another within-inner-training cross-fit layer and receive human approval; do not reuse an inner validation row to fit its anomaly scorer or the inner-training feature generators.

Validate every actual fit/score pair: exact disjoint row keys and group sets; fit groups are contained in the authorized context; no outer H_k group in any A_k-side generator; complete, nonduplicated expected score coverage. A boolean claim of exclusion is insufficient without fit membership manifests and independently recomputed intersections. Fail before supervised fitting on any violation.

Each anomaly fit needs at least 4096 rows and at least 32 distinct transformed vectors; every supervised training/evaluation population needs both classes and at least 4096 rows. Gates are operational feasibility constraints, not statistical sufficiency claims. Fail without reseeding, splitting groups, dropping conflicts, reducing cluster count or changing folds.

## 4. Frozen model recipes and controlled ablation

**Policy A for both chains: freeze the corresponding Stage 2.3 configurations; no chain-specific search.** This is a controlled feature ablation, not a comparison of separately optimized algorithms. Baseline selection already happened on official TRAIN; the chain gets no additional hyperparameter budget.

U1: Isolation Forest with `n_estimators=200`, `max_samples=4096`, `max_features=1.0`, `contamination="auto"`, `bootstrap=False`, `n_jobs=1`, `random_state=1729`, `warm_start=False`. Use negative score_samples, not default contamination decisions. New fold-local fits only; no globally fitted Stage 2.2 model or score arrays in training.

U2: MiniBatchKMeans with `n_clusters=32`, `init="k-means++"`, `batch_size=1024`, `n_init=3`, `init_size=3072`, `max_iter=100`, `tol=0.0`, `max_no_improvement=10`, `reassignment_ratio=0.01`, `compute_labels=False`, `random_state=1729`, score batches 4096. Reuse pure `fit_u2`/`score_u2` recipe semantics without loading global model state. No new feasibility-family search or cluster selection.

CHAIN-S1: Logistic Regression `C=1.0`, `solver="lbfgs"`, `l1_ratio=0.0`, `dual=False`, `tol=1e-4`, `max_iter=1000`, `fit_intercept=True`, `class_weight=None`, `random_state=1729`, `warm_start=False`, `verbose=0`. Match the pinned Stage 2.3 API; do not pass deprecated penalty options or change solver/iterations on convergence failure. Convergence warnings BLOCK that required fit.

The inspected Stage 2.3 `reports/selection.json` records C=1.0 independently for outer contexts 0,1,2 and for the final fit. Bind this provenance: outer chain configurations inherit the corresponding fold-local baseline selection, not a newly selected global C. If those identities/configurations no longer reconcile, BLOCK instead of assuming outer-fold independence. Existing Stage 2.3 OOF results can then support context-matched diagnostic pairing without retraining baselines.

CHAIN-S2: exact `S2_CONFIG`: `n_estimators=150`, `criterion="gini"`, `max_depth=16`, `min_samples_split=2`, `min_samples_leaf=2`, `min_weight_fraction_leaf=0.0`, `max_features="sqrt"`, `max_leaf_nodes=1024`, `min_impurity_decrease=0.0`, `bootstrap=True`, `oob_score=False`, `class_weight=None`, `n_jobs=1`, `random_state=1729`, `warm_start=False`, `ccp_alpha=0.0`, `max_samples=None`, `monotonic_cst=None`, `verbose=0`. Identical recipe does not mean identical trees when features change; adding two columns changes the available split choices. No boosting or new family.

Both chains: no weights/resampling/calibration. Require classes `[0,1]`; `p_attack = predict_proba(X)[:, index_of_class_1]`, higher means model-estimated probability of official benchmark ATTACK, not a guaranteed or calibrated real-world attack probability. Threshold is **0.5** for both: ATTACK iff `p_attack >= 0.5`. No threshold search. Nonfinite/out-of-range probabilities or sums differing from 1 by more than 1e-12 BLOCK.

## 5. Comparisons and immutable baseline policy

Primary metric is **Average Precision (AP)** using `sklearn.metrics.average_precision_score(y_true, p_attack, pos_label=1)`, without sample weights. It is not trapezoidal PR-AUC. Required pairs are BASE S1 versus CHAIN-S1 and BASE S2 versus CHAIN-S2 on identical row populations and official labels.

Primary development comparison uses only VALIDATION_COMPARISON (17529 rows). CALIBRATION (17539) is diagnostic-only; do not tune thresholds or combine subsets into a new headline metric. Outer OOF paired metrics are diagnostics on the existing folds, not an additional feature-selection opportunity. Report pooled OOF AP and per-fold AP separately; never silently substitute mean fold AP for pooled AP.

For each pair, freeze `delta_AP = chain_AP - base_AP`: improvement iff delta > 1e-6; degradation iff delta < -1e-6; otherwise NO IMPROVEMENT / TIE. This is an operational numerical tie rule, not statistical or practical significance. Ties prefer the simpler BASE model; degradation also retains BASE. Report both chains regardless of the outcome. No requirement to win and no feature/model redesign following a loss.

For secondary CHAIN-S1 versus CHAIN-S2 preference, choose higher VALIDATION_COMPARISON AP; candidates within 1e-6 of the maximum tie and prefer CHAIN-S1. Freeze this chain-only preference before TEST. It does not overwrite Stage 2.3 preferred S2. TEST deltas are reporting-only and cannot revise development preferences.

Report for both chains AP, ROC-AUC, TP, FP, TN, FN, accuracy, precision, recall and F1. Thresholded matrix is `[[TN, FP], [FN, TP]]`, true and predicted order `[NORMAL, ATTACK]`. Precision/recall/F1 zero-denominator values are 0 with warning; one-class AP/ROC-AUC are null with reason under the inherited policy. Use unrounded values for decisions. V1 paired deltas are AP only; other metrics are side-by-side descriptive context. No significance test, confidence interval or significance claim is authorized.

Load frozen baseline validation/OOF predictions and metadata only, with exact row-key alignment and parent hash checks. Baseline final model hashes: S1 `fc8f6bf60210b4dd499b09fc300487dcbe345b26d2d6ea983ee1862ac75e58d8`, S2 `e3e56eaf42331d708d458ab7b824d7df14e61e3c5329a04414e87e9bfcfa5b8d`. Snapshot baseline artifact byte hashes before execution and verify unchanged after every checkpoint. Never silently rerun a baseline to fill a missing result; missing required provenance blocks pairing.

Preserve the predeclared duplicate-excluded sensitivity population from Stage 2.3 for TEST. It is SENSITIVITY ANALYSIS ONLY and cannot replace primary all-row metrics or select a chain. Development conflict-excluded diagnostics likewise use the frozen group ambiguity definition, never remove rows from fitting or primary metrics. Do not invent an outcome-dependent mask. No new conflict-based TEST exclusion beyond the upstream approved mask.

## 6. Resources, cache, and artifact contracts

This is a RESOURCE-CONSTRAINED budget for an Apple Silicon MacBook Air, not an optimum. One fit at a time, threadpoolctl=1 and model n_jobs=1. No parallel CV or new dependency.

| Required fits | U1 | U2 | CHAIN-S1 | CHAIN-S2 |
|---|---:|---:|---:|---:|
| Two inner signal fits for each of three outer contexts | 6 | 6 | 0 | 0 |
| Outer training fits serving H_k | 3 | 3 | 3 | 3 |
| Final T inference / downstream fits | 1 | 1 | 1 | 1 |
| V1 maximum model-fit attempts | 10 | 10 | 4 | 4 |

Maximum 28 real-data model-fit attempts. No additional candidate pilots or failed-fit retries hidden outside the cap. Start with synthetic correctness tests, then the first required inner U1/U2 fits as the real resource gate; retain their valid outputs. Failed required fit means BLOCKED, not automatic retry. Final TEST is inference-only, with zero fitting.

Each fit <=600 seconds; each predict batch <=300 seconds; cumulative fitting/scoring <=14400 seconds across checkpoints/resumptions. Aggregate process-tree RSS <=min(4 GiB, half physical RAM). Predict/transform in at most 4096-row batches; check projected matrix size before allocation. Monitor and abort on limits; no automatic downsampling, fewer trees, smaller groups or extra budget. Log actual attempts, timing and RSS without inventing benchmarks. No manual seed retries.

The same U signal artifacts serve both chains. Cache identity includes dataset, contract/algorithm/dependency version, seed/config, exact fit-row/group hashes, scoring-row/group hashes and outer/inner context. Reuse only after verifying every identity and authorized exclusion. In particular, full-T OOF cache is not eligible for outer-training contexts. Base preprocessing may be reused for identical memberships only. At most ten unique base-preprocessing fit populations are needed here; supervised A_k/T base states can reuse corresponding anomaly-preprocessor state if membership and contract are identical. Supervised signal scalers have four distinct training contexts.

Output root: `data/unsw_nb15/processed/stage_2_4/v1/`. Every artifact includes schema/version `stage_2.4/1.0`, dataset/branch, plan/code/dependency hashes, parent identities and byte SHA-256; semantic hashes are separately named. Canonical JSON uses UTF-8, sorted keys, compact separators, allow_nan=False. No overwrites or upstream writes.

| Output | Frozen contents |
|---|---|
| `contracts/chain_contract.json` | Base allowlist, exactly two score definitions/transforms, model recipes, thresholds, AP/ties, no-tuning policy, budgets |
| `manifests/crossfit_contract.json` | Upstream outer/inner identities; every authorized fit/score context and exact membership hashes |
| `signals/{context}/{U1_or_U2}.jsonl` | Row key, group ID, outer/inner context, source model, config/version, fit partition hash, fit-group manifest hash, preprocessing identity, raw score, HIGHER_MORE_ANOMALOUS direction, parent/model hashes |
| `signals/{context}/exclusion_audit.json` | Explicit expected/scored coverage; zero intersections for row/group sets; outer exclusion proof and input hashes |
| `models/{context}/` | U models/state, chain models, downstream base state and OOF signal scalers, config, classes, fit lineage |
| `predictions/` and `reports/` | Chain outer OOF and validation outputs, baseline-paired development metrics/AP deltas, resource and preservation audits |
| `manifests/selection_lock.json` | All feature/crossfit/config/state/model/threshold identities, comparison rules, chain preference, TEST identity, baseline references, sensitivity policy |
| `test_evaluation/` | Authorized inference-only chain TEST scores/predictions, matrices, metrics, paired baseline AP deltas, sensitivity and final manifest |
| `manifests/stage_2_5_handoff.json` | Locked chain/baseline identities, separate development/TEST comparisons, leakage audits, limitations and release status |

Signal exclusion proof must be independently checkable from immutable membership manifests, not a self-reported `excluded=true`. Downstream scalers bind the precise OOF input hashes. Same-row/same-group U fit/score overlap, extra/missing row, wrong context, changed state, or invalid score is a hard failure before chain fitting.

## 7. TEST governance and final evaluation

Official TEST has already served locked Stage 2.2 and Stage 2.3 evaluations. Disclose in final reporting: **the same official benchmark TEST was used in earlier fixed-stage evaluations and is not newly unseen at project level**. Public availability does not permit using earlier metrics, predictions or class totals for Stage 2.4 design/selection. Any known prior result exposure is recorded as a limitation, not erased by a new lock.

Development read allowlist consists of approved plans/code, official TRAIN, immutable training/split/feature contracts, baseline development artifacts and fold/handoff identities. Historical TEST outputs are not development inputs. Selective integrity hashing may bind their identities without exposing metrics; final evaluator alone reads their results for paired reporting after lock. No model outcome from TEST is used to choose U1/U2 inclusion, chain configuration, fold count, thresholds or comparison rules.

2.4D must lock both chain models; final T U1/U2 inference models; all preprocessing/signal-scaler identities; exact feature/crossfit contract; thresholds; classes; AP/tie/improvement rules; development preferences; and original TEST/paired-baseline identities. Lock all required immutable file references, including the approved sensitivity membership. A missing artifact blocks rather than permitting new methodology.

Require a separate explicit human authorization for 2.4E. Use `manifests/final_test_evaluator_authorization.json`, schema `stage_2.4-final-evaluator-authorization/1.0`: dataset_id `UNSW-NB15` mapping only to the benchmark branch, stage `2.4E`, authorization_type `PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION`, human_authorized=true, selection_lock_sha256, both chain model hashes, U1/U2 inference model and preprocessing hashes, downstream state hashes, both thresholds 0.5, test_role `FINAL_EVALUATION_ONLY`, post_test_tuning_allowed=false, evaluator_boundary_version `S2.4-PUBLIC-FINAL-EVALUATOR-V1`, actual RFC3339 authorization timestamp and reference/hash of real human approval. Hash fields are full lowercase SHA-256. No nulls, unresolved placeholders, invented consent, secrets or physical Custodian requirement. Do not create authorization during planning.

The logical evaluator may read only the validated authorization/lock, frozen pipeline and provenance, official TEST, and locked baseline TEST/sensitivity artifacts needed for final comparisons. Only if upstream sensitivity provenance requires it, allow its bound official-TRAIN reference for unchanged overlap reconstruction, never fitting. It may write only new Stage 2.4 final-evaluation artifacts plus its integrity receipt. No development/model-selection/validation/fold/model-state writes or feedback. Check resolved read/write paths and protected-state hashes before opening TEST and after evaluation; attempted mutation or invalid boundary blocks. Development/Stage 2.5 selection cannot consume final TEST outcomes for retuning.

In one joint locked evaluation, verify official TEST identity, infer U1/U2 signals using T-only state, apply frozen downstream base and OOF-derived signal scalers, predict both chains, and compute all required metrics/matrices and paired baseline deltas. Primary population remains all 82332 original rows; match baseline row identities and official labels exactly. No TEST fit, calibration or threshold change. Required sensitivity results remain separate. If locked baseline metrics cannot be reconciled, STOP reporting the paired result rather than overwrite/retrain baselines.

Ledger: NOT_OPENED -> AUTHORIZED -> OPENED -> COMPLETE, or FAILED_LOCKED. Resume interrupted evaluation only with identical lock/code/config and checkpointed outputs; no repeated alternative evaluations or hidden tuning. Performance degradation still produces COMPLETE when integrity gates pass. A changed method after TEST requires a new reviewed experiment and cannot be represented as this predeclared test.

Stage 2.5 receives additional chain matrices and AP deltas while retaining U1/U2/S1/S2 primary matrices. Claims are UNSW-only. No significance claim, no guaranteed gain, and never “UNSW chained performance = FortiGate performance.” Do not start Stage 2.5 in this task.

## 8. Implementation map and checkpoints

Proposed future files only: `src/chained/__init__.py`, `src/chained/contracts.py` (bindings/allowlists/locks), `src/chained/signals.py` (context-safe U fits/scores and audits), `src/chained/models.py` (OOF signal transforms/downstream fits), `src/chained/evaluation.py` (paired metrics), `src/run_chained.py` (TRAIN-only checkpoints), `src/run_chained_test_evaluation.py` (separate locked evaluator). Reuse pure upstream transformer/scorer/metric functions; do not import orchestration that reads historical TEST or modify baseline fitting code. Tests: `tests/test_chained_contracts.py`, `tests/test_chained_signals.py`, `tests/test_chained_models.py`, `tests/test_chained_evaluation.py`, `tests/test_chained_test_lock.py`.

Interfaces: `validate_inputs(root: Path) -> dict`; `build_contexts(folds: Sequence[Mapping[str, object]]) -> list[dict]`; `fit_score_signals(rows, fit_keys: frozenset[str], score_keys: frozenset[str], context: Mapping[str, object]) -> dict`; `audit_signals(signal_records, fit_membership, expected_score_membership, excluded_outer_groups) -> dict`; `fit_chain(rows, oof_signals, model_id: str, context: Mapping[str, object]) -> dict`; `predict_chain(bundle, rows, inference_signals) -> numpy.ndarray`; `compare_pair(y_true, base_p, chain_p) -> dict`; `freeze_selection(artifacts, output_root: Path) -> dict`; `evaluate_locked_test(lock_path: Path, authorization_path: Path) -> dict`. Rows/manifests are typed mappings; bundles hold estimator, base state, signal scaler, classes/config and lineage; persisted artifacts contain hashes/references. Signal generation receives features/membership only, with labels stripped before any U call.

### 2.4A — contract and nested-context proof

- [ ] Write failing tests for branch/target/output exclusions, immutable upstream identities, exact inherited folds/configurations, invalid cache lineage and all-row/group preservation. A synthetic case where globally OOF training signals include an outer held-out group must be rejected.
- [ ] Run `python -m pytest tests/test_chained_contracts.py -q`; confirm new tests fail before implementation.
- [ ] Implement contracts/context manifests and validators only; no real U fits. Verify required subset sizes, class support and upstream row/group reconciliation without TEST access.
- [ ] Rerun to PASS; execute `python -m src.run_chained --checkpoint 2.4A`, publishing exact planned fit/score memberships, provenance and expected 28-fit cap. STOP for review/authorization.

### 2.4B — nested OOF U signals

- [ ] Write failing synthetic tests for group intersection, missing/duplicate rows, full-T cache rejection in outer contexts, held-out category/statistic isolation, score direction, exact nearest-centroid squared-distance semantics and no labels reaching U fits.
- [ ] Run `python -m pytest tests/test_chained_signals.py -q`, confirm failures, implement generators/auditors/resource watchdog and rerun to PASS.
- [ ] Execute `python -m src.run_chained --checkpoint 2.4B`: first required inner fits act as resource gate, then at most ten U1/ten U2 fits. Reuse valid context artifacts across chains. Publish exclusion/coverage proofs for every row/context and inference-state identities. STOP; no chain fitting if any signal proof fails.

### 2.4C — CHAIN-S1 development

- [ ] Write failing tests for train-OOF-only signal scalers, transform-only held-out rows, fixed C=1 and threshold, convergence blocking, no in-sample signal substitution and inherited outer configuration lineage.
- [ ] Run `python -m pytest tests/test_chained_models.py -q`, confirm failures, implement chain adapter and rerun to PASS.
- [ ] Execute `python -m src.run_chained --checkpoint 2.4C`: three outer and one final CHAIN-S1 fit, paired baseline diagnostics and validation predictions. Independently recompute serialized-model predictions in batches and require max absolute difference <=1e-12 and identical threshold decisions, without refitting. STOP.

### 2.4D — CHAIN-S2, comparisons and lock

- [ ] Add failing tests for exact S2_CONFIG, AP versus trapezoidal PR distinction, 1e-6 ties/degradation, unchanged baseline preference, row alignment, sensitivity separation, baseline no-overwrite and denial of historical TEST reads.
- [ ] Run `python -m pytest tests/test_chained_models.py tests/test_chained_evaluation.py -q`, confirm new failures, implement comparisons and lock builder, rerun to PASS.
- [ ] Execute `python -m src.run_chained --checkpoint 2.4D`: three outer and one final CHAIN-S2 fit; serialized prediction replay as in C; required paired validation AP deltas and chain-only preference. Freeze all E inputs. Verify baseline hashes unchanged. STOP for explicit final-evaluation authorization even if chains improve.

### 2.4E — locked final chained TEST evaluation

- [ ] Write synthetic-only lock tests: absent/false/placeholder consent, altered artifact/threshold/feature/scaler identity, forbidden read/write, fitting attempted inside evaluator, changed-lock retry, and baseline overwrite all fail closed before TEST evaluation.
- [ ] Run `python -m pytest tests/test_chained_test_lock.py -q`, confirm failures, implement final evaluator and rerun to PASS. Then run targeted tests plus `python -m pytest -q` without opening real TEST or performing real-data training in tests.
- [ ] After separate human authorization and successful D lock/boundary validation, run `python -m src.run_chained_test_evaluation` with the approved lock and authorization paths. Neither this plan nor a development preference authorizes this command.
- [ ] Verify 82332 unique primary rows per chain, matrix sums, required metrics, matched baseline AP deltas, sensitivity provenance, no protected-state mutation and no fitting. Publish final manifest and Stage 2.5 handoff with prior-TEST-exposure disclosure. STOP; do not start Stage 2.5.

## 9. Completion and limitations

COMPLETE requires validated nested OOF signals for every training row, zero protected-group leakage, reproducible completion of both chains, unchanged baseline artifacts, frozen comparisons before TEST, no historical/new TEST influence on development, actual final chain metrics/matrices and baseline AP deltas, required sensitivity results, no post-TEST tuning and a verified Stage 2.5 handoff. A loss is a valid completed result. Missing U2/S2, failed fit, missing lineage or resource exhaustion means BLOCKED, not silent fallback or partial COMPLETE. STOPPED_AT_CHECKPOINT means awaiting human authorization.

No model was trained or chain signal generated during plan authoring. Chain metrics, resource timings and improvements are NOT YET MEASURED. Results will be conditional on the inherited benchmark split, duplicate ambiguity, frozen baseline recipe and two-signal design; they do not establish transfer to FortiGate or statistical significance.
