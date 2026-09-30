# Stage 2.5 — Final Evaluation, Reporting, and Project Closure Implementation Plan

> For agentic workers: after explicit approval, use superpowers:executing-plans or superpowers:subagent-driven-development checkpoint by checkpoint. PLAN ONLY now: create this plan only. No implementation, report/README edits, training, prediction generation, TEST rerun, tuning, commit or push.

**PLAN STATUS:** APPROVED — STAGE 2.5 FINAL EVALUATION, REPORTING, AND PROJECT CLOSURE

**Plan ID / version:** S2.5-FINAL-PACKAGE-V1 / 1.0

**Approval:** Explicit HUMAN APPROVAL provided for Stage 2.5 Final Evaluation, Reporting, and Project Closure. Previously READY FOR HUMAN REVIEW with approval pending. The focused review passed source of truth, metric terminology, claims/limitations, final artifact contract, visual integrity, reproducibility/validation, checkpoint boundaries, and active plan consistency; blocking issue NONE. The human approves the existing frozen-artifact packaging methodology, seven tables, four figures, report/README/runbook scope, claims and TEST limitations unchanged. Scientific conclusions of Stages 2.1–2.4 remain frozen: no retraining, tuning, new cross-fitting, post-TEST model changes, new TEST-based selection, FortiGate supervised performance claim or unapproved significance analysis. Each checkpoint must STOP before the next; existing separate commit/push authorization requirements remain in force. This update records approval metadata only and does not implement 2.5A, modify the report/README, generate tables/figures, retrain models, rerun TEST, commit or push.

**Goal:** Assemble a coherent, auditable final project package from frozen results without changing scientific outcomes.

**Architecture:** A read-only artifact adapter produces one provenance-bearing JSON result registry. Seven tables and four figures derive from that registry or verified existing artifacts; an updated technical report, concise README and runbook explain both separate branches. Closure validates evidence and package integrity, not new model performance.

**Tech stack:** Python 3.12, standard-library JSON/CSV/hashlib/pathlib, existing matplotlib for deterministic plotting, pytest. No new dependencies or model deserialization required.

**Spec:** Human Stage 2.5 request; approved master `docs/plans/stage_2_1_to_2_5_ml_pipeline_plan.md`; Stage 2.1–2.4 plans; primary `data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json`.

## 1. Authority and non-negotiable scope

Inspected branch is `main`, HEAD `d011808855acdfe63fe18865b9e937ba3db3c801`. Closed checkpoints:

| Stage | Commit |
|---|---|
| 2.1 | `5d1de4a35e0535a68ed891a8ae4708e18a7095dd` |
| 2.2 | `aeb36ebb8c16fa6eed0b42960dd619b68a889f72` |
| 2.3 | `674f9035737f5e675797c911c6e92e1f4cdcabca` |
| 2.4 | `d011808855acdfe63fe18865b9e937ba3db3c801` |

Primary handoff schema is `stage_2.4e-stage-2.5-handoff/2.0`; SHA-256 is `059e930611897776bec00f892bd0c72dec40d0236a18b0de5ab1c6814601fc64`. Verify this exact identity before aggregation. Bind dependent file hashes through its selection lock, authorization, final manifests and immutable source inventory. Do not infer numbers from README/prose, silently choose between conflicting artifacts, or regenerate a missing result. Inconsistency is BLOCKED pending reconciliation.

Global prohibitions:

- NO MODEL RETRAINING; NO HYPERPARAMETER TUNING; NO POST-TEST MODEL CHANGES.
- NO NEW MODEL-SELECTION DECISION FROM TEST; NO PREDICTION REGENERATION; NO NEW TEST EVALUATION.
- NO FORTIGATE SUPERVISED PERFORMANCE CLAIM; NO DATASET MERGING.
- NO STATISTICAL SIGNIFICANCE CLAIM WITHOUT A SEPARATELY APPROVED ANALYSIS. No such analysis is included here.
- Preserve baseline/chain models, states, predictions, labels, thresholds, selections and historical approvals unchanged.
- Do not delete raw evidence or authoritative local generated artifacts, even if ignored or untracked.
- Stop at each checkpoint. Plan approval does not authorize automatic commit/push or any later modeling stage.

### Review focus

- Different PR-related metric names must retain source semantics and implementations, not silently become one column.
- Handoff U1/U2 identities describe chain inference models, not necessarily the Stage 2.2 benchmark fits; distinguish both.
- Conflicting duplicate rows remain in primary results; sensitivity populations never replace the headline population.
- A known Windows validation result is software history, not a fresh Mac pass or model accuracy.
- Public tables/figures must work without publishing raw logs, row-level predictions, secrets or ignored artifact trees.

## 2. Source-of-truth inventory

Let `B2`, `B3`, `B4` denote `data/unsw_nb15/processed/stage_2_2/v1/`, `stage_2_3/v1/`, `stage_2_4/v1/` respectively. These aliases are documentation conveniences, not permission to scan arbitrary inputs.

| Subject | Exact authoritative sources / resolution |
|---|---|
| Architecture and label-feasibility decision | Approved master and `docs/plans/stage_2_1_labeling_ground_truth_evaluation_plan.md`, active two-branch amendment; qualitative history only unless a bound machine-readable feasibility result is available |
| FortiGate legacy package | `data/processed/stage_2_0_v5/analysis_summary.json`, `tables/case_studies.json`, `graphs/01_score_distribution.png`; resolve their Stage 1.8/1.9 source identities through package audit inputs, not report prose |
| FortiGate Stage 2.2 comparison | `data/processed/stage_2_2/fortigate/v1/manifest.json`, `fortigate_u1_u2_comparison.json`, `fortigate_u2_top50_explanations.json`; validate manifest hashes before extracting aggregates |
| UNSW source and split | `data/unsw_nb15/processed/unsw_nb15_acquisition_manifest.json`, `unsw_nb15_validation_summary.json`; `B2/contracts/unsw_feature_contract.json`, `B2/manifests/unsw_split_manifest.jsonl`; inherited raw identities only, no raw TEST read |
| U1/U2 benchmark development | `B2/validation/selection_lock_manifest.json` and its exact referenced model, threshold and metric artifacts |
| U1/U2 benchmark TEST | `B2/test_evaluation/final_stage_2_2_manifest.json`, `unsw_u1_test_metrics.json`, `unsw_u2_test_metrics.json`, corresponding `unsw_u1_test_confusion_matrix.json` / `unsw_u2_test_confusion_matrix.json`, `unsw_test_sensitivity_mask.json` |
| BASE S1/S2 development | `B3/manifests/selection_lock.json`, `stage_2_4_handoff.json`, `B3/reports/validation_comparison_S1_S2.json`; lock references resolve exact model/state/config identities |
| BASE S1/S2 TEST | `B3/test_evaluation/final_stage_2_3_manifest.json`, `unsw_s1_test_metrics.json`, `unsw_s2_test_metrics.json`, corresponding `unsw_s1_test_confusion_matrix.json` / `unsw_s2_test_confusion_matrix.json` |
| Chain results and governance | Primary `B4/manifests/stage_2_5_handoff.json`; `B4/manifests/selection_lock.json`, `final_test_evaluator_authorization.json`, `fit_accounting_2_4B.json`; exact audit/model references carried by these manifests |
| Chain TEST reconciliation | `B4/test_evaluation/final_stage_2_4_manifest.json`, `chained_s1_test_metrics.json`, `chained_s2_test_metrics.json`, corresponding `chained_s1_test_confusion_matrix.json` / `chained_s2_test_confusion_matrix.json`, `chained_test_sensitivity_analysis.json`, `chained_test_evaluation_provenance.json` |
| Metric implementation evidence | `src/unsupervised/evaluation.py`, `src/run_unsw_test_evaluation.py`, `src/supervised/evaluation.py`, and frozen chain evaluation source referenced by B4 provenance |

2.5A produces an explicit resolved source inventory: repository-relative path, full file-byte SHA-256, schema, parent manifest/hash, checkpoint, purpose and allowed JSON pointers. Resolve references without glob-based newest-file selection. Reject path escapes, changed hashes and ambiguous versions. Do not treat a semantic state hash as a file-byte hash. A manifest without its authoritative child evidence is insufficient for a numerical claim.

Stage 2.1 narrative: precision-first FortiGate labeling did not yield enough defensible ATTACK/BENIGN coverage for primary supervised evaluation. Keeping FortiGate unsupervised and adopting UNSW as a separate benchmark avoided weak/fabricated ground truth. Describe this as a methodology/governance finding, not a failed project. No new labeling, retrospective ground truth or revived historical proxy path. Omit exact feasibility counts if no authoritative machine-readable source can be reconciled; this does not permit inventing them from prose.

## 3. Final registry and metric contract

Create public aggregate package `docs/results/stage_2_5/` with:

- `final_result_registry.json`: single authoritative derived summary; schema `stage_2.5-results/1.0`.
- `source_inventory.json`: exact source paths/hashes/pointers and code/plan/checkpoint identities, including the primary handoff hash.
- `claims_matrix.json`: supported/forbidden claims, required qualifications and evidence references.
- `package_manifest.json`: output hashes, registry hash, schema/version, validation status; do not include a circular self-hash.
- `validation_report.json`: commands, environment, pass/fail/unavailable outcomes and scoped exceptions.
- `closure_audit.json`: final scope/preservation/hygiene/handoff status and separate commit/push status.
- Seven CSV tables and four figure assets defined below. Markdown report tables are rendered from those CSVs, not maintained independently.

Registry required top-level fields: `schema_version`, `checkpoints`, `datasets`, `branches`, `models`, `metrics`, `comparisons`, `leakage`, `governance`, `claim_limits`, `source_inventory_sha256`. Each numerical record includes source path/hash/JSON pointer, dataset, branch, model identity, population/split, row count, metric source key/display name/implementation, value and undefined reason. Retain source precision; JSON uses finite values only, null plus reason for undefined values. No rounding in decision/reconciliation logic.

Model identities distinguish FortiGate U1/U2, UNSW Stage 2.2 U1/U2, BASE S1/S2 and CHAIN-S1/S2, plus chain inference U1/U2 references. Never attribute a Stage 2.2 metric to the handoff's newly cross-fitted U artifact merely because its family matches. Record config, feature-contract version, model/state hashes, fit partition, score semantics and threshold where applicable. Preserve logical threshold sentinels if present; do not serialize infinity.

**Metric terminology:** Stage 2.2 TEST artifacts use `metrics.pr_auc_ap` and convention `PR_AUC_AP`. Inspection shows `src/run_unsw_test_evaluation.py` calls `evaluate_scores`, whose implementation uses `sklearn.metrics.average_precision_score`. Preserve the display label **Stage 2.2 PR_AUC_AP**, with that implementation explicitly documented; do not silently rename it. If another upstream record says PR_AUC, retain its exact name and verify implementation independently. Do not substitute trapezoidal PR area. Supervised Stage 2.3/2.4 metric is **Average Precision (AP)** via `sklearn.metrics.average_precision_score`, ATTACK=1, continuous `p_attack`. Unsupervised continuous anomaly scores are not supervised probabilities, even when the metric function matches.

Preserve AP, ROC-AUC, TP/FP/TN/FN, accuracy, precision, recall, F1 and threshold from each original metric artifact; preserve each stage's undefined-value conventions. Confusion rows are true classes, columns predicted classes. For U models use true NORMAL/ATTACK versus predicted INLIER/ANOMALY and state ANOMALY != ATTACK; for supervised models use NORMAL/ATTACK on both axes. All six primary-population matrix totals must reconcile to 82332 without filtering conflict rows. Sensitivity records are separately population-tagged and labeled SENSITIVITY ANALYSIS ONLY.

The handoff values below are reconciliation anchors, not manually typed chart inputs:

| Pair | Development BASE AP | Development CHAIN AP | Development delta | TEST BASE AP | TEST CHAIN AP | Descriptive TEST delta |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 0.9939231496371828 | 0.9941359114288555 | +0.00021276179167273312 | 0.9650555012702602 | 0.9659663520592334 | +0.0009108507889732387 |
| S2 | 0.9968637967521546 | 0.9968208117560664 | -0.00004298499608823558 | 0.9848644789351858 | 0.9845491751973731 | -0.00031530373781274434 |

Development S1 IMPROVEMENT and S2 DEGRADATION follow the existing 1e-6 comparison rule. Preserve them; do not invent a new threshold. TEST deltas are descriptive reporting only. Stage 2.3 preferred S2 and Stage 2.4 development decisions remain unchanged. No universal winner or deployment-selection decision from TEST. Reconcile delta arithmetic within absolute 1e-12; preserve original stored values. Mismatches block publication rather than changing frozen results. Display AP/deltas to nine decimal places, counts as integers, with full precision retained in JSON/CSV and an explicit fractional-unit legend.

No metric replay is required in the default workflow. Validate source hashes, duplicate representations, count sums and derived arithmetic only. If a metric disagrees, STOP; prediction-based replay or corrective upstream amendments need separate approval. No model loading, `.fit`, `.predict`, `.score_samples`, or raw TEST access in the Stage 2.5 package builder.

## 4. Tables and figures

Seven CSVs under `docs/results/stage_2_5/tables/`, fixed row ordering by branch/stage/model, not sorted to suggest a new TEST winner:

1. `01_dataset_roles.csv`: separate datasets, identities, populations, purposes, allowed claims.
2. `02_models.csv`: eight branch-specific model entries plus chain U provenance references; family/config/state/threshold/score semantics.
3. `03_unsupervised_results.csv`: FortiGate review/scoring aggregates and UNSW U1/U2 development/TEST metrics in explicitly separate sections; no FortiGate classification metrics or cross-dataset ranking.
4. `04_base_supervised_results.csv`: S1/S2 fixed development and TEST metrics, thresholds and existing preference.
5. `05_chain_development.csv`: paired BASE/CHAIN AP, delta, frozen result and identical VALIDATION_COMPARISON population.
6. `06_chain_locked_test.csv`: paired AP/delta, full supervised metric sets, clearly descriptive TEST label and separately marked sensitivity population rows.
7. `07_leakage_governance.csv`: exact row/group exclusion audits, fold-local state evidence, selection locks, human authorization, baseline preservation, prior TEST exposure and limitations.

Exactly four final figures under `docs/results/stage_2_5/figures/`:

1. `01_two_branch_architecture.mmd`: Mermaid diagram from registry branch/model relationships. Distinct FortiGate and UNSW lanes, no data-merge arrows. Report embeds the same diagram; README uses a compact link/summary, not a contradictory architecture.
2. `02_fortigate_score_distribution.png`: byte-for-byte copy of `data/processed/stage_2_0_v5/graphs/01_score_distribution.png` after audit reconciliation. This image was inspected: REFERENCE/HOLDOUT histogram and explicit 0–100 relative-abnormality/non-probability axis. Caption identifies Stage 1.8/2.0 historical scoring population; not UNSW or Stage 2.2 U2 scores. Bind image hash, analysis-summary hash and source feature/score identities. No cosmetic replot with invented bins.
3. `03_paired_ap_deltas.png`: two panels (development and locked TEST), S1/S2 signed AP deltas from registry, common symmetric y-range determined as 1.1 times maximum absolute displayed delta (fallback 1e-6 if all zero), visible zero line, exact annotations, no error bars/significance marks. Do not disguise the small magnitude or use inconsistent scales.
4. `04_confusion_matrices.png`: six panels from registry count arrays: U1, U2, BASE S1, BASE S2 as the four primary matrices; CHAIN-S1/S2 clearly additional. Counts, row/column labels and population in every panel; identical color scale 0 through the maximum count across panels. No matrix regeneration from model predictions.

Existing Stage 2.0 has ten figures. Reuse only the one specified; other historical figures remain untouched and accessible through historical documentation. Existing authoritative Stage 2.2–2.4 confusion matrices are JSON, so this plan renders their values rather than fabricating new evaluation. No new ROC/PR curves, significance plots or redundant model-ranking figure.

Each figure has provenance in the registry/package manifest: source hashes and pointers, generation code/dependency identity, plotting settings and output hash. New PNGs use matplotlib Agg, fixed 150 dpi and recorded font; exclude current-time metadata. Inspect every figure visually for clipping, misleading axes and labels during 2.5B. Exact binary reproducibility is required within the pinned rendering environment; cross-platform font differences must be disclosed rather than mistaken for model-result changes.

## 5. Report, README and runbook

Update the existing `docs/final_project_report.md`; do not create a competing final report. Preserve its Stage 2.0 findings as explicitly historical, with immutable original accessible at the closed checkpoint. Keep substantiated case-study context, but do not convert suspected behavior or priority into labels. No new case selection driven by desired performance claims.

Freeze report sections: Executive Summary; Problem/Motivation; Data and Two-Branch Architecture; Stage 2.1 Label-Feasibility Finding; Branch A FortiGate; Branch B UNSW; Leakage Prevention; Model Methodology; Development and Final-Evaluation Protocol; Results (seven tables/four figures); Chained ML Analysis; Limitations; Reproducibility; Conclusion. Narrative numbers must resolve to registry evidence. Clearly distinguish 36 FortiGate features, 28 UNSW base features and the two continuous chain signals; never imply a shared fitted schema.

README scope: project purpose, current CLOSED-stage package status only after acceptance, two-branch summary, actual repository structure, model/stage overview, concise S1 increase/S2 decrease with dataset/population/metric labels, setup/inspect commands, data/artifact policy, limitations and links to report/runbook. Preserve historical validation facts with dates/context; remove stale *current-stage* descriptions without rewriting history. Do not duplicate all tables or claim production readiness, real-world attack detection accuracy or an AI-results API where only a rule-observation API exists.

Create `docs/reproducibility_runbook.md`. Required contents:

- Python 3.12 virtual environment; `python -m pip install -r requirements-dev.txt`, `python -m pip check`; pinned requirements and OS/runtime recording. Show PowerShell activation/interpreter paths and separate macOS equivalents; do not assume Windows commands run on Mac.
- Raw placement: FortiGate `data/raw/network_log_SAFE.csv`, UNSW training/testing files in `data/unsw_nb15/raw/`; checksums from acquisition manifests. No secrets required. FortiGate data redistribution requires explicit authorization even if sanitized. Public UNSW provenance/acquisition instructions must respect original source terms; do not bundle raw files automatically.
- Two modes: lightweight frozen-artifact inspection/package reproduction, and historical pipeline reproduction instructions for an independently authorized fresh workspace. Stage 2.5 executes only the first mode. Full historical reproduction may train models and must never overwrite checkpoint artifacts; no misleading one-command promise that retraining is part of closure.
- Entry-point map: Stage 1 parser/normalization/detection/storage/features/scoring/explanation and existing `scripts/validate_stage_1_*.ps1`; `src/build_final_package.py` and `scripts/validate_stage_2_0.ps1`; Stage 2.1 `src/prepare_stage_2_1.py`; Stage 2.2 `src/run_fortigate_u2.py`, `src/run_unsw_validation.py`, `src/run_unsw_test_evaluation.py`; Stage 2.3 `src/run_supervised.py`, `src/run_supervised_test_evaluation.py`; Stage 2.4 `src/run_chained.py`, `src/run_chained_test_evaluation.py`. Verify flags from source/parser or safe --help before documenting exact examples. Do not run evaluators or training commands to validate documentation.
- How to obtain approved frozen artifact bundles, verify `source_inventory.json`, inspect registry/tables, reproduce the package in a fresh output directory, run package validators and locate prior-stage locks. Missing local generated artifacts are an explicit limitation, not permission to regenerate predictions.
- Generated trees/large model bundles are not required in public Git. Aggregate publication package is intentionally versioned; private/local row-level data are not. Document exact current ignore behavior and changes made in 2.5D.

## 6. Claims and limitations policy

Every supported claim in `claims_matrix.json` must carry a source path/hash/pointer or approved qualitative methodology reference, scope and required qualification. Forbidden entries have reason and replacement wording. Validators ensure required phrases and evidence fields exist; a human reviews semantic overclaims that keyword matching cannot prove absent.

Supported: real FortiGate logs can be scored/prioritized for anomaly review; UNSW supervised models were quantitatively evaluated; the frozen controlled chain comparison gave a small S1 AP increase and did not improve S2 AP; observed zero row/group overlap is supported by bound audits. These are benchmark/software findings, not production security guarantees.

Required limits: ANOMALY != ATTACK; ANOMALY SCORE != ATTACK PROBABILITY; RULE MATCH != CONFIRMED ATTACK; HIGH_INTEREST != CONFIRMED ATTACK; LOW_INTEREST != CONFIRMED BENIGN; SOURCE THREAT OBSERVATION != GROUND TRUTH; ABSENCE OF ALERT != BENIGN. No fabricated ground truth, universal attack detection, FortiGate classification score imported from UNSW, or statistical proof of chaining superiority.

Quote this disclosure prominently in report protocol/limitations and summarize in README: “The same official UNSW-NB15 TEST split was used in earlier fixed-stage evaluations. Stage 2.4E was a locked fixed-design final chained evaluation, not a newly unseen dataset at the overall project level.” Keep small AP deltas descriptive; no new resampling, hypothesis tests or confidence intervals. Mention duplicate ambiguity, benchmark/enterprise domain gap, conditional fixed recipes and lack of production validation.

## 7. Implementation map and validation contract

Future execution creates `src/reporting/final_results.py` (source adapters, registry, table/figure assembly, validation), `src/build_stage_2_5_package.py` (CLI), `tests/test_stage_2_5_package.py`, `tests/test_stage_2_5_claims.py`; modifies only README/report, adds runbook and aggregate package, and narrowly updates `.gitignore` under 2.5D. Reuse existing reporting helpers only where they do not import model fitting, rescore rows or overwrite Stage 2.0 outputs. Do not refactor frozen model code.

Interfaces: `collect_frozen_results(handoff: Path) -> dict`; `validate_registry(registry: dict, inventory: dict) -> list[dict]`; `render_tables(registry: dict, output: Path) -> None`; `render_figures(registry: dict, inventory: dict, output: Path) -> None`; `validate_package(root: Path) -> dict`. Exceptions carry source path, pointer, expected/actual identity and no sensitive payload. CLI supports `--handoff`, `--output-dir`, `--validate-only`; build requires a fresh output directory, validate-only is read-only. No training/prediction hooks.

Frozen commands for execution (not run while planning):

1. Package tests: `python -m pytest tests/test_stage_2_5_package.py tests/test_stage_2_5_claims.py -q`.
2. Targeted Stage 2 regression scope: `python -m pytest tests -q -k "stage_2_1 or stage_2_2 or supervised or chained"`. Record collection counts and node IDs; zero collected is a failure. Tests use fixtures/synthetic data, not real pipeline reruns.
3. Environment: `python -m pip check`.
4. Aggregate build: `python -m src.build_stage_2_5_package --handoff data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json --output-dir docs/results/stage_2_5` (fresh output only).
5. Package validation: `python -m src.build_stage_2_5_package --output-dir docs/results/stage_2_5 --validate-only`.
6. Full repository validation once: `python -m pytest tests -q`; do not silently skip failures or change frozen expectations.
7. Scope/whitespace: `git diff --check`, `git status --short`, and reviewed exact changed-file diff.

Validators cover hash/source reconciliation, model/population identities, matrix totals and axes, source metric terminology, unchanged full-precision values, AP delta arithmetic, required limitations, forbidden cross-dataset claims, deterministic table order, report/table/figure links, absent private paths/secrets and upstream immutability. Inject synthetic mismatches, swapped populations, missing inputs, changed locks, sensitivity-as-primary, and metric-name substitution; each must fail. Prove builder never calls model fit/predict functions using tests that raise if invoked. Render twice to two fresh temporary directories and compare registry/table/figure hashes under the same pinned environment; exclude environment/timestamp-bearing validation receipts from deterministic-content equality.

Historical Windows validation **286 passed / 130 subtests / 2 upstream deprecation warnings** remains labeled historical software validation, never current test count or accuracy. Fresh Mac failures must be recorded by exact test node, command, traceback summary, OS/Python/dependency versions and evidence for platform specificity. Do not assume a failure is known merely because it occurs on Mac. No baseline/methodology change to force green status. Package/source/result-integrity failures block closure. An independently evidenced environment-only baseline exception requires explicit human acceptance; report `COMPLETE_WITH_DOCUMENTED_ENVIRONMENT_LIMITATION`, not ALL TESTS PASS. New/unexplained failures remain BLOCKED. No rerun loop seeking a favorable result.

## 8. Repository hygiene and resource boundaries

Observed `.gitignore` covers `.venv/`, caches, `.env`, `data/processed/`, and the FortiGate raw CSV, but not `data/unsw_nb15/raw/`, `data/unsw_nb15/processed/` or `.DS_Store`. These are currently untracked local trees, not automatically safe publication candidates. Plan a narrow ignore update for those UNSW trees, `.DS_Store`, `.pytest_cache/`, `.env.*` with an explicit sanitized `.env.example` exception only if one exists and passes review. Ignoring is not deletion and does not untrack an already tracked secret.

Inventory with `git ls-files`, `git status --short --untracked-files=all`, `git ls-files --others --exclude-standard`; verify new rules with `git check-ignore` on representative exact paths. Inspect the changed/staged file set for credentials, tokens, private keys, `.env`, raw rows, prediction exports, caches, temporary/debug outputs and accidental model binaries. Secret-pattern checks report paths/line numbers only, never echo matched values. Scan aggregate publication for sensitive identifiers and unsupported claims. Record files over 10 MiB as review blockers for staging unless separately approved; do not delete them. No blanket `git add .`, `git clean`, recursive cleanup or raw-data mutation. Existing local `.DS_Store` may remain ignored; no cleanup is required to close methodology.

Lightweight execution: one process, no model loading or fit; <=2 GiB process RSS, <=10 minutes per package build/validation, <=60 seconds per new plot, <=1 GiB new aggregate outputs. Stream file hashing and JSONL only if needed for identity checks; default numerical aggregation uses small summaries, not prediction arrays. Tests have a 30-minute operational cap per targeted/full run; on timeout report incomplete and STOP, do not weaken coverage. Unexpected resource growth blocks for review, not a larger hidden recomputation. These are operational budgets, not measured performance promises.

## 9. Checkpoints and closure

### 2.5A — result/claims contract and registry

- [ ] Write failing package tests for missing source, wrong handoff hash, model identity collision, metric-name drift, mismatched matrix totals and rounded/source-conflicting deltas. Run package tests to confirm failures.
- [ ] Implement source adapters/registry and claims contract; reconcile handoff with child manifests. Preserve exact metric keys and recorded selection decisions. Rerun targeted package tests to PASS.
- [ ] Generate registry/inventory/claims in a fresh output root, snapshot protected upstream identities; publish checkpoint evidence. STOP before plotting/report edits.

### 2.5B — tables and figures

- [ ] Add tests for seven table schemas, identical population pairing, figure provenance, no typed metric constants, deterministic output and sensitive-field exclusion. Confirm failures, then implement renderers and rerun to PASS.
- [ ] Produce exactly seven CSVs and four figures; copy the verified legacy histogram unchanged. Visually inspect all figures and reconcile labels/counts against registry. STOP; do not alter results to improve presentation.

### 2.5C — report, README and runbook

- [ ] Update the existing report using the frozen structure, register-backed tables and four figure links; distinguish historical Stage 2.0 material.
- [ ] Update README within the defined scope and add runbook with inspect-only versus historical reproduction clearly separated. Document earlier TEST exposure prominently.
- [ ] Validate every numerical claim/link and perform human claims-matrix review. Verify documented flags without running training/evaluation. STOP.

### 2.5D — reproducibility, package and hygiene validation

- [ ] Run package tests, targeted Stage 2 tests, pip check, package validator and one full suite as specified; record actual outcomes and environment separately from Windows history.
- [ ] Run deterministic fresh-output replay and upstream hash preservation checks. Apply only the narrow ignore-policy additions; inspect aggregate outputs and proposed Git file set for secrets/large files/raw data.
- [ ] Publish validation report and scoped exceptions. Result/provenance failures or unexplained test failures BLOCK. STOP for closure review, including any environment exception approval.

### 2.5E — closure audit; optional separately authorized commit/push

- [ ] Verify all required outputs, provenance, claims, figures, documentation, unchanged frozen scientific artifacts, and absence of new selection/training. Publish `closure_audit.json` with COMPLETE, COMPLETE_WITH_DOCUMENTED_ENVIRONMENT_LIMITATION, or BLOCKED and exact reasons.
- [ ] Preserve all checkpoint history. State results: small S1 gain, S2 degradation, no significance/production claim, no hidden TEST novelty claim. Mark the final report/repository status closed only when acceptance holds.
- [ ] Prepare an exact file list and suggested commit summary. Commit only after separate explicit human authorization following reviewed validation/diff; push only with separate explicit authorization and confirmed remote/branch. No force push. If no authorization, report closure package complete with commit/push NOT PERFORMED; do not keep working or claim a pushed checkpoint.

Acceptance: all seven tables/four figures and registry/report/runbook/README are consistent with immutable sources; required claims/limitations and software-validation distinctions are present; upstream models/results remain unchanged; package validation passes; hygiene/publication scope is reviewed; unresolved scientific/integrity failures are absent. Missing frozen artifacts block the affected required output rather than triggering reconstruction. Planning creates only this file and confers no execution or publication approval.
