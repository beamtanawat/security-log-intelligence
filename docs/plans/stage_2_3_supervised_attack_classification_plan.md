# Stage 2.3 — Supervised Attack Classification Implementation Plan

> For agentic workers: after human approval, use superpowers:executing-plans or superpowers:subagent-driven-development checkpoint by checkpoint. This task authors a plan only. Do not implement, train, commit, push, or start Stage 2.4 automatically.

**PLAN STATUS:** APPROVED — STAGE 2.3 WITH PUBLIC BENCHMARK EVALUATOR AUTHORIZATION

**Date:** 2026-09-28

**Plan ID / version:** S2.3-UNSW-SUPERVISED-V1 / 1.0

**Approval:** Explicit HUMAN APPROVAL provided on 2026-09-30 for Stage 2.3 Supervised Attack Classification. Previously READY FOR HUMAN REVIEW with approval pending; the focused review passed target/feature leakage, group leakage, preprocessing/CV, S1 baseline, S2 gate, TEST lock, Stage 2.4 OOF compatibility, and active plan consistency, with no blocking issue. This approval records the existing UNSW-only Logistic Regression / bounded Random Forest V1 architecture and Average Precision selection policy unchanged. This update changes approval metadata only; it does not implement, train, start Stage 2.4, commit, or push. Existing checkpoint and isolated-evaluator authorization requirements remain in force.

**Current amendment:** PUBLIC BENCHMARK EVALUATOR AUTHORIZATION FIX, initially pending human review; explicitly HUMAN RE-APPROVED as the PUBLIC BENCHMARK FINAL EVALUATOR AUTHORIZATION AMENDMENT. Execution reported that 2.3E stopped before TEST opening on unresolved `<HUMAN_FILL>` fields in the inherited Custodian/evaluator prerequisite. Preserve the preceding approval and blocker history. The active replacement is Section 7.1 below; historical Custodian acknowledgements are HISTORICAL / NOT ACTIVE FOR UNSW STAGE 2.3E and must not be deleted. This amendment does not authorize final TEST execution or creation of the authorization artifact. A separate subsequent explicit human authorization is still required for artifact creation and final TEST execution, subject to the frozen lock and evaluator checks.

**Focused amendment review and re-approval:** Public benchmark governance PASS; human authorization contract PASS; evaluator isolation boundary PASS; fail-closed safety PASS; methodology unchanged PASS; active plan consistency PASS; blocking issue NONE. The human explicitly re-approves the existing Section 7.1 governance: UNSW-NB15 public benchmark, no physical secret Custodian, logical/procedural TEST isolation, and authorization type `PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION`. Valid Stage 2.3D lock, frozen model/feature/preprocessing identities, both thresholds 0.5, frozen preferred-model decision S2, explicit human authorization and evaluator isolation checks remain prerequisites; unresolved `<HUMAN_FILL>` values remain forbidden in active prerequisites. As stated in the human's re-approval, preserve the frozen execution selections unchanged: S1 Logistic Regression C=1.0; S2 Random Forest S2_CONFIG; preferred model S2. This records approval metadata, not a new selection or measured result. Official TEST remains FINAL EVALUATION ONLY, post-TEST tuning is forbidden, and the Stage 2.4 boundary is unchanged. No authorization artifact is created, TEST opened, 2.3E resumed, commit made, or push performed by this approval-recording task.

**Goal:** Produce reproducible, group-safe UNSW-NB15 S1/S2 supervised baselines, their final benchmark metrics, and refittable interfaces for later nested chained comparisons.

**Architecture:** S1 is Logistic Regression. S2 is Random Forest, conditional on the bounded capability/resource gate below. Both consume only the approved 28 base features through separately fitted supervised preprocessing. Official TEST is excluded from selection; an isolated evaluator computes final results only after the joint supervised lock.

**Tech stack:** Python 3.12; existing pinned scikit-learn, NumPy, SciPy, joblib, threadpoolctl, matplotlib; pytest. No new dependency or GPU required.

**Spec:** Human Stage 2.3 request supplied on 2026-09-28; approved `docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md`, active Section 2A; completed `docs/plans/stage_2_2_unsupervised_model_comparison_plan.md` and its actual published contracts. Historical FortiGate supervised methodology is not active.

## 1. Authority, scope, and immutable inputs

Stage 2.1 is closed at `5d1de4a35e0535a68ed891a8ae4708e18a7095dd`. Stage 2.2 is CLOSED at `aeb36ebb8c16fa6eed0b42960dd619b68a889f72`, the inspected repository HEAD. Existing Stage 2.2 TEST artifacts already exist; do not claim that the benchmark TEST has never been evaluated. This plan's authoring does not inspect TEST scores, labels, distributions, or performance. Existing TEST-derived reports are prohibited selection inputs.

Let `UPSTREAM` denote `data/unsw_nb15/processed/stage_2_2/v1/`. Bind these identities before executing 2.3A:

| Artifact | Complete SHA-256 |
|---|---|
| Master plan | `5d388f62e1d1c2a22de2e4388aee80da427c975b42ed87f2bea7c6112f0719ba` |
| Stage 2.2 plan | `3dd3fccb40f800600c79225e5c2815b88f26a76313fadc96f94cd37b34d64849` |
| `data/unsw_nb15/raw/UNSW_NB15_training-set.csv` | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| Official TEST identity, inherited without selection access | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |
| `UPSTREAM/contracts/unsw_feature_contract.json` | `bc66e157f74992c66b798f37a933f2894fe65b6df7d4b010e973465a7e6e14f6` |
| `UPSTREAM/manifests/unsw_split_manifest.jsonl` — file bytes | `f58d7527168a44588d095d0be9e718dccd86641f0d10570ef9986ea8efd9d06b` |
| Same split — upstream semantic manifest hash, NOT file hash | `4e01861133cb05a589ae26ece173043df45326002cf42b35aa483c4d8c96e71a` |
| `UPSTREAM/manifest.json` | `ff76fb00da29cdaab4abddadc9fed0547cde394edc864148f7d50089cf5e514e` |
| `UPSTREAM/validation/selection_lock_manifest.json` — identity only | `6a2e5f22e352ebcf156afa3bc3bf655055a02e542aa38a15b86ff5caf9b43889` |
| `UPSTREAM/test_evaluation/final_stage_2_2_manifest.json` — identity only | `97158a8ca0ed4952ec1087400f067d36d1daa41ea0b5fb733ae217a1dc832888` |
| `UPSTREAM/test_evaluation/unsw_test_sensitivity_mask.json` — evaluator-only content | `302e247862e7f80d636aa459158ea2ce240e6cccef376bfe76c382b22b36c8dc` |

Hash mismatches block execution; never silently replace expected identities. TEST-file verification/content access belongs only to the isolated evaluator; development binds its inherited identity. Record implementation commit, approved plan SHA-256, actual dependency versions, OS/architecture, and every input/output hash in each checkpoint manifest.

### Global constraints

- Create this plan only now. No raw-data processing, model training, code/test edits, download, other plan edit, commit, or push.
- Execution needs explicit human approval and stops after each checkpoint for authorization of the next checkpoint.
- Dataset is `UNSW_NB15_BENCHMARK`; branch is `BRANCH_B_LABELED_BENCHMARK`. Mixed IDs or FortiGate inputs fail closed.
- FortiGate remains REAL-LOG UNSUPERVISED / ANOMALY ANALYSIS ONLY. No FortiGate supervised labels, fitted state, rows, metrics, or 36-feature schema enter this stage.
- Preserve official rows and binary labels. No majority voting, relabeling, conflict-row deletion, target-conditioned filtering, or synthetic oversampling.
- TEST cannot inform feature choices, preprocessing, folds, candidate feasibility, hyperparameters, class weights, calibration, thresholds, architecture, resource expansion, or preferred-model selection.
- Base S1/S2 exclude U1/U2 scores, anomaly decisions, ranks, and every Stage 2.2 model output. Chained features belong only to Stage 2.4.
- Published outputs are immutable/no-overwrite, with a new run/version for an authorized retry. No automatic advancement or automatic commit.

### Review focus

- A huge duplicate component cannot be split to balance folds; test atomic assignment and fail closed on unusable class support in 2.3A.
- A category seen only in held-out rows must map to unknown without altering fitted vocabulary; test in 2.3A.
- A converged low-performing model is not a feasibility failure; test capability gates independently from AP in 2.3C.
- An interrupted final evaluation must not become a tuning/reselection opportunity; test lock-bound recovery in 2.3E.
- Public TEST metrics can contaminate later chain selection even without raw labels; test restricted output publication and Stage 2.4 handoff rejection in 2.3E.

## 2. Target, row preservation, and split ownership

Use official integer `label`: `0 = NORMAL`, `1 = ATTACK`; positive class is always 1. Reject other/missing target values in permitted development data. Keep `attack_cat` only in the original audit source; no category-based training, selection, stratification, weighting, conflict resolution, or secondary metric is authorized here. Optional category analysis requires a later approved reporting specification.

Reuse the exact Stage 2.2 membership, row keys, component `group_id`, and canonicalization implementation. Do not recreate groups from encoded/scaled arrays or add a new digest namespace. Exact duplicate/conflict identity uses the approved 28 predictive features BEFORE learned preprocessing; targets, IDs, categories, TEST, and fitted state never define identity. Existing stronger near-duplicate/component containment is also retained, not weakened to exact-only groups.

| Official TRAIN population | Rows | Authorized role |
|---|---:|---|
| All official TRAIN | 175341 | Identity/group reconciliation; not a single fitting population |
| TRAIN_INTERNAL | 140273 | Model/preprocessor fitting; nested CV |
| VALIDATION_INTERNAL | 35068 | Held-out development evaluation, never fitting |
| Existing VALIDATION_CALIBRATION subset | 17539 | Frozen-threshold diagnostic metrics only |
| Existing VALIDATION_COMPARISON subset | 17529 | Final development S1-versus-S2 preference |

The two validation subsets retain upstream membership and remain disjoint. The CALIBRATION name does not require calibration: this plan performs none. Neither validation subset enters fitted preprocessing, hyperparameter CV, pilots, or final refitting. Do not refit on combined TRAIN+VALIDATION after selection.

Reconcile official TRAIN fingerprint: **88976 exact predictive groups; 273 conflict groups; 6896 conflict rows; 2156 NORMAL; 4740 ATTACK; zero cross-internal-split exact groups**. Historical **229** belongs to 42-field grouping and is not an acceptance target. Same raw TRAIN, contract/version, and canonicalization algorithm must reproduce the current fingerprint or STOP. An approved future contract change requires a versioned fingerprint, never forced counts. Conflict-group metadata include group and row counts plus NORMAL/ATTACK counts per permitted development partition. Primary metrics retain all official rows and labels.

### 2.1 Frozen nested folds

Stage 2.3 owns a three-fold outer manifest over TRAIN_INTERNAL only. Stage 2.4 must consume it unchanged. Allocation is label-blind, even though subsequent model fitting uses labels.

1. Use upstream indivisible component IDs and sizes. Sort components by descending row count, then ascending SHA-256 of UTF-8 compact JSON `["S2.3-OUTER-V1", group_id]` (`ensure_ascii=False`, separators comma/colon); remaining ties use ascending UTF-8 group ID bytes.
2. Starting with zero row counts in folds 0, 1, 2, assign each whole component to the fold with fewest assigned rows; ties go to smaller fold index. No random restart, target stratification, repair, group split, or alternate seed.
3. For outer fold `k`, training is all other folds and evaluation is fold `k`. Within that outer training set, derive exactly two inner folds by the same algorithm, namespace `S2.3-INNER-V1:k`, with indices 0 and 1. Inner validation never includes outer evaluation groups.
4. Freeze and hash all memberships before fitting. Report realized sizes, not an invented exact 1/3 or 1/2 ratio. Whole-group constraints take priority; row-count balancing is only the specified greedy rule, not an optimality claim.
5. Every outer/inner fit and evaluation subset must contain both classes; every fit must contain at least 4096 rows. These are operational feasibility gates, not scientific sufficiency claims. If any gate fails, BLOCK; no agent-invented resplit or fold count. Check labels only after assignment, never feed support counts back into allocation.

Each row receives exactly one outer OOF prediction per available model. An outer model's preprocessing, tuning, and fit must exclude that row's entire component. In-sample predictions must never be renamed OOF. Stage 2.4 may construct further inner folds within these outer training boundaries under its own approved nested plan, never alter the outer manifest.

## 3. Supervised preprocessing contract

Reuse the pure Stage 2.2 feature contract and functions in `src/unsupervised/contracts.py` and `src/unsupervised/features.py`; do not reuse a fitted U1/U2 object or full-TRAIN state inside CV. A supervised adapter validates exact fit membership before calling `fit_features`; the parent `TRAIN_INTERNAL` flag alone is insufficient to prove fold isolation.

Ordered numeric features (25):

`dur, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, dwin, tcprtt, synack, ackdat, smean, dmean, trans_depth, response_body_len`.

Ordered categorical features (3): `proto, service, state`.

Only those 28 fields enter the transformer. Explicitly exclude `id`, `label`, `attack_cat`, row/split/group IDs, `stcpb`, `dtcpb`, `is_ftp_login`, `is_sm_ips_ports`, all `ct_*`, target aliases, and upstream model/triage outputs. Retain row identity separately for joins; enforce one-to-one row alignment between X, y, and manifests.

- Numeric blank/missing is allowed. Malformed, negative, or nonfinite numeric values block rather than being silently coerced. Apply `log1p`; fit medians on fit rows in log space, with all-missing median 0. Impute, then fit population mean/std on fit rows; zero std uses scale 1. Append one unscaled missingness indicator per numeric field.
- Categories are trimmed, case-preserved; literal `-` remains a category. Fit sorted vocabulary only on fit rows. Use the existing collision-safe missing/unknown buckets, one-hot encoding, no dropped reference category and no one-hot scaling.
- Deterministic output order: 25 scaled numeric columns, 25 missing indicators, then ordered categorical blocks. Full TRAIN_INTERNAL Stage 2.2 representation has 209 columns; supervised full-fit state must reconcile. Fold-local vocabularies may yield fewer columns; do not borrow held-out categories to force 209.
- Use contiguous dense float64 as the public transformer output for both S1/S2. A model's documented internal conversion does not redefine predictive-group identity. Maximum output width is 512; exceedance blocks, not feature truncation.
- Fresh state for each distinct fit membership. State may be cached only when dataset, contract, algorithm version, and exact fit-row membership hashes match. Inner-fit, outer-fit, and full TRAIN_INTERNAL state are distinct identities.
- Held-out folds, both validation subsets, and final TEST receive transform-only fitted state. TEST labels never enter transformation. No population-wide rarity, feature selection, target encoding, PCA, or additional learned transformation.

## 4. Models, selection, and class handling

### 4.1 S1: interpretable Logistic Regression

Freeze two configurations: `C in [0.1, 1.0]`, `solver="lbfgs"`, `l1_ratio=0.0` (L2 in the pinned scikit-learn 1.9.1 API), `dual=False`, `tol=1e-4`, `max_iter=1000`, `fit_intercept=True`, `class_weight=None`, `random_state=1729`, `warm_start=False`, `verbose=0`. Do not pass deprecated `penalty` or tune solver, iterations, seed, or regularization family. Verify runtime API against the pinned environment; incompatibility blocks instead of silently substituting a recipe.

For each outer fold, evaluate both C values using its two inner folds; select largest arithmetic mean inner-fold average precision (AP). A candidate must succeed on every applicable fold; any convergence warning, failed fit, invalid probability, or resource breach makes it ineligible in that selection context. If none remain, S1 is BLOCKED. Refit the selected C on that outer training population, then predict its held-out outer fold once.

Choose final full-fit C independently using three-fold CV on TRAIN_INTERNAL with the frozen outer memberships: two candidates times three folds. Those six candidate-fold evaluations select the final C; do not use their selected pooled predictions as unbiased OOF. The separate nested predictions above are the OOF baseline. Fit the chosen C once on all TRAIN_INTERNAL, then evaluate the two validation subsets without fitting. A failed final fit blocks S1; no post-validation candidate switch.

For every hyperparameter selection, candidates within `1e-6` absolute AP of the maximum are tied; prefer smaller C. Use unrounded metrics. Record all candidate metrics and failures, not just the winner.

Coefficients are interpretable only relative to the final encoded/scaled representation and jointly included predictors. Report signed coefficients, transformed feature names, scaling state and intercept. Full one-hot encoding, correlation, and regularization limit individual attribution. Coefficients are associations, not causal security explanations or raw-unit effects.

### 4.2 S2: bounded capability gate

Exactly one executable primary candidate: `RandomForestClassifier`. Its nonlinear split interactions provide stronger modeling capacity than a linear boundary; this does not promise better measured performance.

| Family considered | Frozen disposition |
|---|---|
| Random Forest | Only fit-eligible S2; gate below |
| HistGradientBoosting / Gradient Boosting | Not run in V1; an alternate representation/early-stopping or boosting search adds no necessary capability for this baseline |
| XGBoost / other external boosters | Not run; no new external dependency justified |

Fixed RF recipe: `n_estimators=150`, `criterion="gini"`, `max_depth=16`, `min_samples_split=2`, `min_samples_leaf=2`, `min_weight_fraction_leaf=0.0`, `max_features="sqrt"`, `max_leaf_nodes=1024`, `min_impurity_decrease=0.0`, `bootstrap=True`, `max_samples=None`, `oob_score=False`, `class_weight=None`, `n_jobs=1`, `random_state=1729`, `warm_start=False`, `ccp_alpha=0.0`, `monotonic_cst=None`, `verbose=0`. No hyperparameter grid, feature-importance selection, warm-start expansion, seed sweep, or validation-controlled early stopping.

Gate order: compatible API/feature schema → bounded pilot → unseen-row finite probabilities and reproducibility → resource compliance → three outer-fold fits and one full TRAIN_INTERNAL fit. Pilot construction is fixed: take the largest whole-group prefix of the Section 2.1 component order that fits within 20000 TRAIN_INTERNAL rows; the first non-fitting group ends the prefix. Require at least 4096 rows and both classes, otherwise BLOCK rather than choose a label-favorable subset. Fit two identical pilots; score all remaining TRAIN_INTERNAL rows without fitting them. Require aligned classes `[0,1]`, finite probabilities in [0,1], rowwise sum within `1e-12` of 1, maximum repeated-prediction difference at most `1e-12`, and identical threshold decisions. Pilot labels may enter classifier fitting, never allocation or TEST selection.

After the gate passes, outer S2 fits use only each outer training set; there is no inner S2 search. Their predictions are true outer OOF. Final S2 fits once on TRAIN_INTERNAL. Capability acceptance has no AP/F1 floor and never requires beating S1. If RF fails any gate or required fit, publish `S2=BLOCKED` and reason; do not try another family or silently reduce the recipe. A fallback requires an explicit human-approved plan amendment. Stage 2.3 cannot be COMPLETE without the required S2 results.

### 4.3 Frozen objective, class handling, probabilities, threshold

**Primary selection metric: average precision (AP), reported as PR-AUC (average precision), ATTACK-positive.** Use `average_precision_score`; not trapezoidal integration of the PR curve. S1 C selection uses mean fold AP. S1-versus-S2 final development preference uses AP on the fixed VALIDATION_COMPARISON subset only; within `1e-6` of maximum prefer S1 for simplicity. Nested OOF metrics are diagnostics and a later paired baseline, not a second opportunity to change the preference rule. A low-scoring model remains reportable.

Both models use no class weights, no sample weights, no resampling, and all fit rows including conflicting-label duplicates. Record permitted development/fold class distributions. Do not use TEST prevalence or adapt the recipe to class counts. AP supports ranking comparison under imbalance but depends on prevalence; no cross-dataset AP comparison or prevalence-free claim.

Both output `p_attack = predict_proba(X)[:, index_of_class_1]`; require model classes `[0,1]`. Higher means greater model-estimated probability of the official benchmark ATTACK label, not confirmed attack probability, real-world FortiGate risk, or a calibrated guarantee. No Platt/isotonic/other calibration is performed.

**Fixed threshold = 0.5** for S1 and S2: predict ATTACK iff `p_attack >= 0.5`, otherwise NORMAL. No threshold optimization, no threshold-selection metric, no threshold sentinel search; the U1/U2 anomaly threshold rule is unchanged and is not repurposed as a supervised threshold search. Exactly 0.5 predicts ATTACK. Neither validation metrics nor TEST metrics can alter this policy.

Secondary reporting, always model- and partition-scoped: TP, FP, TN, FN, accuracy, precision, recall, F1 from thresholded predictions; ROC-AUC and AP from continuous `p_attack`. Matrix ordering is true rows `[NORMAL, ATTACK]`, predicted columns `[NORMAL, ATTACK]`, i.e. `[[TN, FP], [FN, TP]]`. Set precision/recall/F1 undefined-denominator results to 0 with an explicit warning/count; one-class ROC-AUC/AP is `null` with reason, never fabricated. Development class gates prevent such folds from qualifying. Do not rank models by a favorable secondary metric after inspection.

## 5. Resources and deterministic execution

All limits here are RESOURCE-CONSTRAINED operational budgets, not statistical optimality claims. No expensive candidate fallback is automatic.

- One fit at a time; threadpoolctl limit 1 and RF `n_jobs=1`. No GPU, all-core parallelism, exhaustive grid, or parallel CV.
- Aggregate process-tree RSS ceiling: smaller of 4 GiB and half physical RAM. Check prospectively before matrix allocation and monitor during fitting. Abort on breach; no silent downsampling or swapping as a strategy.
- Each pilot fit: at most 120 seconds; each non-pilot fit: at most 600 seconds; each prediction batch: at most 300 seconds. Sequential transform/predict batches of at most 4096 rows; train matrices remain bounded by the fixed population and width.
- Aggregate model fit/prediction budget: 7200 seconds across checkpoints and resumed attempts. Record monotonic elapsed time, peak RSS, fit attempts, context, and reasons. Resource exhaustion is BLOCKED, not evidence that another model wins.
- S1 pilot: same group-safe population as S2, two identical C=1 fits and unseen-row reproducibility check before nested fitting. Same convergence/probability gates. At most 24 S1 fits: 2 pilots + 12 inner candidate fits + 3 outer refits + 6 final-C CV fits + 1 final fit.
- S2 at most 6 fits: 2 pilots + 3 outer fits + 1 final fit. Total at most 30 attempted model fits; failed attempts count. Reuse an exact matching candidate fit only by membership/configuration/state hashes; this may reduce, never increase, the cap.
- Exactly one full TRAIN_INTERNAL final fit per model, not repeated fitting of all candidates on all official TRAIN. Pilot and CV fits use only their declared subsets. Cache fold state only under Section 3 identities; release arrays/models when not needed and retain artifacts for audit.
- Synthetic/targeted tests precede real-data pilots; resource capability precedes full fits. Every checkpoint can STOP without starting the next expensive step.

## 6. Artifacts, interfaces, and Stage 2.4 handoff

Development output root: `data/unsw_nb15/processed/stage_2_3/v1/`. Final evaluator outputs use its `test_evaluation/` subdirectory, logically separated from development artifacts. UNSW-NB15 is public: no private root, secret, password, hidden-label store, or private human Custodian is required. TEST predictions, labels, class counts, metrics, and matrices must not feed development logs, selection code, or Stage 2.4 selection; the existing reporting-release boundary remains unchanged. Separation is procedural/logical and must pass Section 7.1 checks, not merely rely on a directory name.

Every manifest has `schema_version="stage_2.3/1.0"`, plan/code/dependency identities, dataset/branch IDs, parent hashes, deterministic configuration, checkpoint/status, and full SHA-256 for each referenced artifact. Serialize finite JSON (`allow_nan=False`); undefined metrics are null plus reason. Hash canonical configuration JSON with sorted keys, UTF-8, compact separators. Byte hashes of published files remain separately named.

| Artifact under development root | Required contents |
|---|---|
| `contracts/supervised_contract.json` | Target/positive class, 28-field order and denylist, preprocessing recipe/version, model configurations, AP/tie rule, threshold 0.5, resources, TEST access policy |
| `manifests/folds.jsonl` | `row_key`, upstream `group_id`, upstream split, outer fold; inner assignments for each outer context where the row is in outer training; no TEST rows |
| `manifests/fold_audit.json` | Membership hashes, row/group counts, class support, zero overlaps, allocation namespaces and algorithm version |
| `models/S1/`, `models/S2/` | Trusted-local serialized model and separate feature state; recipe, classes, transformed feature order, fit-row hash, fitted split, preprocessing hash, artifact hash |
| `predictions/oof_S1.jsonl`, `predictions/oof_S2.jsonl` | One row per TRAIN_INTERNAL row: row/group keys, outer fold, model/config/state/fit-membership hashes, `p_attack`, threshold, predicted label, `prediction_role="OUTER_OOF"` |
| `predictions/validation_*.jsonl` | Both validation subsets, identified separately, final model identity, same probability/decision semantics; no use as training features |
| `reports/selection.json`, `reports/validation.json` | All permitted candidate outcomes, unrounded AP/ties, preferred model, secondary metrics, ambiguity diagnostics, timing/RSS and failures |
| `manifests/selection_lock.json` | Both frozen pipelines, threshold, TEST identity, sensitivity policy, primary/secondary metric recipes, all dependencies and planned evaluator access; no mutable file reference |
| `manifests/stage_2_4_handoff.json` | Refittable recipes, baseline OOF/fold identities, base feature version, classes `[0,1]`, probability direction, fixed threshold, train-only state boundary; no TEST results |
| `manifests/checkpoint_2_3A.json` through `checkpoint_2_3E.json` | Status/evidence hashes and permitted next action; E public receipt contains integrity/status only |

OOF records describe each fold's own configuration/state; they must not pretend to come from the final full-fit model. Store fold models/state for replay, not only a final estimator. Do not serialize arbitrary untrusted objects or load outside bound artifact roots.

Stage 2.4 consumes recipes and authoritative outer folds, not global S1/S2 or U1/U2 in-sample training scores. Where a supervised signal is needed, it must be produced by a model and preprocessing fitted without the scored protected group, with tuning nested inside the relevant training boundary. Stage 2.3 OOF predictions are a baseline comparison artifact, not automatically authorized meta-training features in every outer context. Stage 2.4 must refit where its boundary differs. Baseline/chain comparisons retain the same base allowlist, rows, official targets, outer folds and comparable selection budgets. No chain is implemented here and no improvement is assumed.

## 7. Locked final TEST evaluation and reporting boundary

The current human request explicitly requires final S1/S2 TEST metrics and matrices in 2.3E. This plan therefore specifies an **isolated final evaluation**, not development access to TEST. The active master allows Stage 2.3 frozen TEST predictions and reserves final cross-stage reporting for Stage 2.5. Any older wording requiring all metric computation to occur only in Stage 2.5 is not silently treated as permission: approval of this detailed plan must explicitly cover this evaluation-timing refinement. If that approval is absent or upstream authority is disputed, STOP before 2.3E; do not declare Stage 2.3 COMPLETE on validation results alone. No master file is changed by this plan.

Before 2.3E, freeze both final models, feature states, hyperparameters, threshold 0.5, preferred model, every metric and sensitivity recipe, code/dependency hashes, and all Stage 2.4-visible development artifacts. Stage 2.3D selection lock must exist and validate. Explicit human authorization recorded under Section 7.1 binds that lock and a single joint S1/S2 evaluation run. Development commands accept only official TRAIN and cannot load TEST or historical TEST metrics. The evaluator uses a logical final-evaluation boundary, not separate operating-system identities or a physical secret-label Custodian. If the logical isolation checks fail, BLOCK before TEST access. Local availability of public TEST labels does not permit their use in model selection.

1. Verify immutable lock and frozen pipeline hashes before opening `UNSW_NB15_testing-set.csv`; then verify its inherited SHA-256 and 82332 rows. Join original binary labels by original row keys only inside the evaluator.
2. Transform with each frozen TRAIN_INTERNAL-derived state, score each model once, use fixed threshold, and compute all primary metrics on all 82332 official TEST rows. No TEST class distribution configures any fit or choice. No fitting, calibration, candidate selection, or code change occurs in this evaluator.
3. Produce separately sealed S1/S2 predictions, metrics and matrices 3 and 4. Preserve the existing U1/U2 outputs as matrices 1 and 2; do not rerun/reselect U models. U1/U2 retain `ANOMALY != ATTACK`.
4. Also produce the upstream-required duplicate-excluded TEST sensitivity result, labeled **SENSITIVITY ANALYSIS ONLY**. Reuse the Stage 2.2 frozen mask definition and exact TEST row membership. If the upstream artifact is only a summary, reproduce its mask using the frozen Stage 2.2 raw full/allowed/near-feature overlap and transformed-feature overlap algorithms against official TRAIN, then reconcile its recorded membership identity/counts within the final-evaluator boundary. No new label-based exclusion or S1/S2-specific favorable mask. If exact reconstruction cannot be proven, BLOCK publication rather than invent a mask. Primary results always keep official rows/labels.
5. Development conflict-group exclusion is diagnostic only: report AP and threshold metrics on validation nonconflict rows separately, never use these values for C selection/preference and never replace all-row primary metrics. If a diagnostic population has one class, report undefined metrics as specified. Do not add target-conflict-based TEST exclusions beyond the frozen upstream mask.
6. Freeze evaluator artifacts and send only pass/fail completion/integrity hashes to development. TEST performance and class totals stay logically sealed from Stage 2.4 model selection. Stage 2.5 may release the full results only after all chained candidates, thresholds and comparisons are frozen. Public receipt reveals no TEST metrics; no private physical root is required. Here and below, sealed evaluator outputs mean immutable outputs excluded from selection inputs, not physically secret public benchmark labels.

Maintain a one-way evaluator ledger `NOT_OPENED -> AUTHORIZED -> OPENED -> SEALED_COMPLETE`, or `FAILED_LOCKED`. An interruption may resume the identical locked evaluation with checkpointed outputs; no new fit/selection, changed code or alternative threshold. A changed lock requires human review and cannot masquerade as the original confirmatory test. Existing Stage 2.2 exposure must be recorded honestly: isolation prevents further selection access but cannot erase prior knowledge. If a decision-maker has already seen benchmark TEST performance, disclose that limitation rather than claim fully naive held-out selection.

Stage 2.5 reports: “F1 = X on UNSW-NB15 official TEST using official binary benchmark labels.” Never “FortiGate attack classification F1 = X” from UNSW results. Benchmark performance does not prove identical performance in the real FortiGate environment. FortiGate reporting remains anomaly scoring, explainability, prioritization and real-log case studies. Poor TEST performance, S2 losing to S1, or later chains losing to baselines are valid results; no post-TEST tuning or headline switching.

### 7.1 Public benchmark final-evaluator authorization — active replacement

The sole active authorization type is `PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION`. Historical private-label Custodian acknowledgements and their placeholders are HISTORICAL / NOT ACTIVE FOR UNSW STAGE 2.3E. Retain them for audit, but do not load or validate them as active prerequisites. No unresolved placeholder, including `<HUMAN_FILL>`, is permitted in an active authorization or prerequisite. This is a fail-closed validation rule, not a field for the executor to fill by guessing human consent.

After the next explicit human approval authorizes artifact creation and final evaluation, create `data/unsw_nb15/processed/stage_2_3/v1/manifests/final_test_evaluator_authorization.json`. Do not create it during this plan fix. Use the following exact JSON field contract; all fields are required, no nulls, no extra fields, no template values:

| Field | Type / required value |
|---|---|
| `schema_version` | string, `stage_2.3-final-evaluator-authorization/1.0` |
| `dataset_id` | string, `UNSW-NB15` |
| `stage` | string, `2.3E` |
| `authorization_type` | string, `PUBLIC_BENCHMARK_FINAL_EVALUATOR_AUTHORIZATION` |
| `human_authorized` | JSON boolean, exactly `true` |
| `selection_lock_sha256` | string, full 64-character lowercase hexadecimal SHA-256 of the validated 2.3D lock file |
| `s1_model_sha256`, `s2_model_sha256` | strings, full SHA-256 of each frozen serialized model, matching the lock |
| `s1_threshold`, `s2_threshold` | JSON numbers, each exactly `0.5`, matching the lock |
| `feature_contract_sha256` | string, full SHA-256 of the frozen supervised feature contract, matching the lock |
| `s1_preprocessing_sha256`, `s2_preprocessing_sha256` | strings, full SHA-256 of the respective frozen feature-state artifacts, matching the lock |
| `test_role` | string, `FINAL_EVALUATION_ONLY` |
| `post_test_tuning_allowed` | JSON boolean, exactly `false` |
| `evaluator_boundary_version` | string, `PUBLIC_BENCHMARK_FINAL_EVALUATOR_V1` |
| `authorized_at` | string, actual RFC 3339 authorization timestamp with timezone |
| `human_approval_reference` | nonempty string identifying the actual explicit human approval in the audit record |
| `human_approval_sha256` | string, full SHA-256 of the preserved explicit human approval record |

The authorization's required public dataset name `UNSW-NB15` maps only to the existing artifact dataset ID `UNSW_NB15_BENCHMARK` and branch `BRANCH_B_LABELED_BENCHMARK`. This explicit mapping does not rename existing contracts or allow another dataset. Validate the actual human approval record, not merely the boolean; prior model-plan approval alone does not authorize this final-evaluation run. Model configurations, positive-class ordering, preferred-model decision, preprocessing and feature contract remain bound through the validated lock and its immutable references. Do not mint new consent, secrets, or provenance on the human's behalf.

**Read allowlist:** the authorization and its approval evidence; validated 2.3D lock; official UNSW TEST raw artifact; frozen feature contract and S1/S2 preprocessing; frozen S1/S2 models/configurations and thresholds; immutable source/provenance identities and frozen evaluator code/dependencies. The already-required sensitivity calculation may read only the lock-bound upstream mask and its immutable official-TRAIN reference inputs under the unchanged Section 7 mask algorithm; no fitting or new selection is permitted. Resolve concrete artifact references/hashes before TEST access; reject unrelated directory scans, unbound references and path escapes. A missing reference blocks rather than expanding the allowlist.

**Write allowlist:** new immutable S1/S2 TEST predictions/scores, metrics, confusion matrices, existing required sensitivity results, final evaluation provenance/ledger and manifest, all under `test_evaluation/`; and the integrity-only `manifests/checkpoint_2_3E.json` receipt. Authorization creation is a separate human-authorized pre-evaluation action, never a self-authorization write by the evaluator. No overwrite of existing published results.

**Isolation checks:** before opening TEST, validate authorization and all lock-bound identities, and snapshot hashes of development/model-selection state, model artifacts, thresholds, feature/preprocessing state, preferred-model decision, folds and validation artifacts. Enforce resolved read/write path allowlists in the evaluator; reject writes outside the output allowlist before they occur. The final evaluator has no fitting/tuning entry point and cannot dispatch development commands. Development and Stage 2.4 loaders reject TEST evaluation artifacts as selection inputs. Verify protected-state hashes again before publication; any change blocks publication and records a failure. Synthetic tests must exercise forbidden reads/writes and feedback attempts. Filesystem-account separation and physical secrecy are not prerequisites.

STOP before TEST access if authorization is absent, human consent is not explicitly evidenced, `human_authorized` is not exactly true, any field is missing/invalid/placeholder-bearing, the selection-lock hash differs, any frozen model/configuration/feature/preprocessing identity or threshold differs, or boundary checks fail. STOP any attempted development-state write or feedback and do not publish success. No post-TEST tuning, model switching, threshold change, feature/preprocessing change, fold change or validation-artifact rewrite is allowed. Existing identical-lock interruption recovery remains unchanged.

## 8. Implementation map and bounded checkpoints

The files below are proposed future execution scope, NOT files created during planning. Reuse pure existing feature/contract functions without modifying Stage 2.2 or importing its TEST orchestration into development.

| Future file | Responsibility |
|---|---|
| `src/supervised/__init__.py` | Package only |
| `src/supervised/contracts.py` | Bound inputs, recipe/schema validation, no-overwrite manifests |
| `src/supervised/folds.py` | Deterministic component-safe outer/inner membership and audit |
| `src/supervised/models.py` | Fit-boundary adapter, S1/S2 recipes, resource gates and nested fitting |
| `src/supervised/evaluation.py` | Pure probability metrics, validation preference, freeze checks |
| `src/run_supervised.py` | TRAIN-only checkpoint CLI; cannot dispatch TEST |
| `src/run_supervised_test_evaluation.py` | Separately authorized locked evaluator and sealed publication |
| `tests/test_supervised_contracts.py`, `tests/test_supervised_folds.py` | Contract/group/feature-state tests |
| `tests/test_supervised_models.py`, `tests/test_supervised_evaluation.py` | Recipe, nested fitting, metrics and selection tests |
| `tests/test_supervised_test_lock.py` | TEST access/lock/recovery and publication-boundary tests |

Use typed `Mapping[str, object]` manifest records and `Sequence[Mapping[str, object]]` rows; NumPy arrays for features/probabilities. Interfaces are frozen as follows: `validate_inputs(root: Path) -> dict`; `build_folds(split_rows: Sequence[Mapping[str, object]]) -> list[dict]`; `audit_folds(rows, folds) -> dict`; `fit_pipeline(rows, fit_row_keys: frozenset[str], model_id: str, parameters: Mapping[str, object]) -> dict`; `predict_pipeline(bundle: Mapping[str, object], rows) -> numpy.ndarray`; `run_nested_models(rows, folds, model_id: str, output_root: Path) -> dict`; `evaluate_probabilities(y_true, p_attack, threshold: float = 0.5) -> dict`; `freeze_selection(artifacts: Mapping[str, object], output_root: Path) -> dict`. Bundles contain estimator, feature state, classes, config and exact fit-membership identity; persisted manifests store serialized artifact references/hashes, not Python objects. TEST entry point is separate `evaluate_locked_test(lock_path: Path, authorization_path: Path) -> dict` returning a public integrity receipt only; output storage and logical read/write allowlists follow Section 7.1; no private root or Custodian configuration is required.

### 2.3A — supervised contracts, folds, preprocessing

- [ ] Write failing contract/fold tests: mixed/FortiGate IDs rejected; forbidden target/model columns excluded from X; preserved official labels and conflict fingerprint; deterministic assignment independent of swapped labels; zero group overlap; a large group remains whole; single-class fit/eval blocks without resplitting.
- [ ] Write failing feature-state tests: held-out-only category maps to unknown; extreme held-out numeric values cannot alter medians/scales; missing/invalid numeric handling; one-to-one X/y joins; fold fit keys reject held-out groups even when parent partition is TRAIN_INTERNAL.
- [ ] Run `python -m pytest tests/test_supervised_contracts.py tests/test_supervised_folds.py -q`; expect the new tests to fail before implementation, without opening TEST.
- [ ] Implement contracts/folds and the thin `fit_pipeline` membership adapter around existing pure feature functions. Freeze supervised contract and outer/inner manifests before fitting real models.
- [ ] Rerun those tests; require PASS. Run TRAIN-only audit via `python -m src.run_supervised --checkpoint 2.3A`; reconcile Section 2 counts, identities and gates. Publish A receipt; STOP for authorization.

### 2.3B — S1 bounded fit and validation

- [ ] Write failing S1 tests: exact two-C recipe and AP tie rule; convergence failure invalidates candidate; inner fitting excludes outer groups; all OOF rows covered once; final-C CV is not mislabeled OOF; no validation fitting; coefficient/output-name alignment.
- [ ] Run `python -m pytest tests/test_supervised_models.py -q`; confirm relevant new failures.
- [ ] Implement S1 pilot/resource watchdog, nested procedure, final-C selection and one final fit. Test on synthetic rows before real pilots.
- [ ] Require targeted PASS, then run `python -m src.run_supervised --checkpoint 2.3B`; publish nested OOF, final model/state, permitted validation metrics and resource ledger. Failure gives `S1=BLOCKED`; successful output still needs checkpoint review. STOP.

### 2.3C — S2 bounded capability gate

- [ ] Add failing S2 tests: one eligible RF recipe; no dependency installation/fallback; deterministic whole-group pilot; finite unseen predictions; identical repeated predictions; low AP does not fail capability; resource timeout/RSS breach blocks without reducing trees or changing families.
- [ ] Run model tests and confirm new failures; implement the RF gate, three outer fits and one final fit only.
- [ ] Require targeted PASS before `python -m src.run_supervised --checkpoint 2.3C`. Publish S2 gate record, OOF, final model/state and validation metrics. `S2=BLOCKED` preserves S1 artifacts but prevents COMPLETE; STOP.

### 2.3D — validation comparison and joint freeze

- [ ] Write failing evaluation tests: fixed 0.5 including equality; matrix axes/count reconciliation; AP distinct from trapezoidal PR area; undefined metrics; AP preference with S1 ties; CALIBRATION diagnostic cannot change preference; sensitivity cannot replace primary; TEST path/reports rejected by development loader.
- [ ] Run `python -m pytest tests/test_supervised_evaluation.py tests/test_supervised_test_lock.py -q`; confirm relevant failures, then implement pure metrics, preference and lock/handoff publication.
- [ ] Require PASS and unchanged upstream identities before `python -m src.run_supervised --checkpoint 2.3D`. Freeze both models and all choices; audit zero target/model-output features, fold-local state, OOF lineage and matching baseline/chain interface. STOP for human evaluator authorization; no TEST access yet.

### 2.3E — isolated final TEST evaluation

- [ ] Add synthetic-only lock tests: absent authorization, false/nonboolean consent, missing approval evidence, unresolved placeholders, changed model/state/hash/threshold, unapproved timing refinement and invalid boundary all block before TEST open; forbidden reads/writes and selection feedback are rejected; no `.fit` callable in evaluator flow; interrupted identical-lock recovery; changed-lock retry denied; public receipt contains no metrics, class totals or row predictions.
- [ ] Run `python -m pytest tests/test_supervised_test_lock.py -q`; confirm new failures, implement evaluator, and rerun to PASS. Test logical allowlists and rejection of synthetic TEST results by development/Stage 2.4 loaders before real TEST; no private account, secret or Custodian required.
- [ ] Run the targeted suite plus repository regression suite `python -m pytest -q` without real TEST access. Require PASS; record resource and schema compatibility. No training is hidden inside tests.
- [ ] Only after explicit human approval authorizes artifact creation and execution, record the fully populated Section 7.1 authorization. With validated 2.3D lock and logical isolation checks passing, invoke `python -m src.run_supervised_test_evaluation` with `--lock` pointing to the validated lock and `--authorization` pointing to `data/unsw_nb15/processed/stage_2_3/v1/manifests/final_test_evaluator_authorization.json`. No unresolved placeholders or secret storage configuration are execution prerequisites.
- [ ] Privately verify 82332 unique primary rows per model, confusion counts summing to 82332, all required defined metrics, reconciled sensitivity population, both matrix artifacts, immutable hashes and no fitting. Publish integrity receipt; STOP. Do not start Stage 2.4 or release TEST results to its selection context.

## 9. Acceptance and terminal states

`COMPLETE` requires all checkpoint receipts PASS; reproducible S1 and capability-selected S2; preserved rows/labels/groups; no target or chained-signal leakage; frozen fold-local/TRAIN-only state; both frozen supervised TEST metric sets and matrices present in the sealed evaluator bundle; exact probability/class/threshold semantics; no TEST-informed selection or post-TEST changes; required sensitivity result; refittable Stage 2.4 handoff; and dataset-scoped claims. A final-evaluation artifact's existence and integrity must be verified by the evaluator, not merely promised in a public manifest.

`BLOCKED` records exact failed gate (inputs, support, convergence, capability, resources, lock, evaluator authorization/isolation, metric integrity); no invented fallback or budget growth. `STOPPED_AT_CHECKPOINT` means awaiting authorization, not model failure. Neither status may be relabeled COMPLETE because one model succeeded or validation metrics exist. Changes to consequential methodology require review and human approval before execution resumes.

All Stage 2.3 model metrics, feasibility timings, and performance outcomes are **not yet measured** when this plan is authored. Upstream counts above are provenance observations, not new experiments.

## 10. Technical references and review checklist

API/metric references: [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html), [RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html), [average_precision_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html). Runtime must match the repository-pinned versions; documentation links do not authorize dependency upgrades.

- [ ] Human review confirms bounded S1 search, capability-only RF gate, fixed no-weighting/0.5 policy and AP selection.
- [ ] Human review confirms authoritative group-safe outer/inner folds and no U1/U2 signals in baseline features.
- [ ] Human approval explicitly covers isolated 2.3E final metric computation, sealed from Stage 2.4 selection, with Stage 2.5 final reporting retained.
- [ ] Executor verifies each checkpoint's evidence before requesting the next action; no implementation is authorized by this READY FOR HUMAN REVIEW document.
