# Security Log Intelligence

Status: **Stage 2.5C documentation generated from the frozen Stage 2.5 registry.**

Registry SHA-256: `c7a29a52b6ef9d3a95dc8c53f2f44c19ee7e91583a4d7231b7f7135b75dedb10`

## Executive Summary

Security Log Intelligence separates operational anomaly review from quantitative
benchmark evaluation. Branch A retains sanitized FortiGate logs for
unsupervised anomaly scoring, prioritization, explainability, and case-study
review. Branch B uses UNSW-NB15 as a labeled benchmark for U1/U2, BASE S1/S2,
and CHAIN-S1/S2 evaluation. **DATASETS MERGED: NO.**

Stage 2.1 established that precision-first FortiGate labeling did not provide
sufficient defensible ATTACK/BENIGN coverage for primary supervised evaluation.
Weak labels were not forced into that role. The benchmark branch therefore
enables measured supervised comparisons without converting real-log anomalies
into ground truth.

The frozen chained development comparison improved S1 by
`0.00021276179167273312` AP and degraded S2 by `-4.298499608823558e-05` AP.
These are descriptive, dataset-scoped results; **NO STATISTICAL SIGNIFICANCE
CLAIM** is made. Locked TEST deltas are also descriptive and do not create a
new model-selection decision.

## 1. Problem and Motivation

Security teams must review large volumes of network events while preserving
evidence, uncertainty, and reproducibility. This project prioritizes unusual
events for analyst review and evaluates supervised methods only where a labeled
benchmark exists. It does not claim production attack detection or invent
attack labels from anomaly scores, deny actions, rule matches, or source
observations.

## 2. Project Architecture

The two branches are intentionally separate:

- **Branch A — FortiGate real sanitized logs:** REAL-LOG UNSUPERVISED /
  ANOMALY ANALYSIS.
- **Branch B — UNSW-NB15:** LABELED BENCHMARK QUANTITATIVE EVALUATION.

**DATASETS MERGED: NO.** The architecture diagram is
[`01_two_branch_architecture.mmd`](results/stage_2_5/figures/01_two_branch_architecture.mmd).

## 3. Data

FortiGate is a sanitized real-log source kept local under
`data/raw/network_log_SAFE.csv`; it supports anomaly review and contextual
case studies. UNSW-NB15 is a public benchmark kept separate under
`data/unsw_nb15/raw/`; it supports labeled quantitative evaluation. Neither
dataset is treated as a sample of the other environment. Raw data is immutable,
local, and not committed. UNSW metrics do NOT establish FortiGate production performance.

## 4. Stage 2.1 — Label Feasibility

Precision-first labeling was investigated for FortiGate. Defensible
ATTACK/BENIGN coverage was insufficient for primary supervised evaluation, so
weak labels were not forced into training or performance claims. FortiGate
remained the real-log anomaly branch and UNSW-NB15 became the labeled benchmark
branch. This is a methodology and governance finding, not a failed project.

## 5. Branch A — FortiGate Real-Log Analysis

The frozen Branch A workflow uses Isolation Forest for relative anomaly scoring
and a MiniBatchKMeans distance scorer where applicable. It supports
prioritization, explainability, and case-study review. The historical score
distribution is preserved at
[`02_fortigate_score_distribution.png`](results/stage_2_5/figures/02_fortigate_score_distribution.png).

**ANOMALY != ATTACK** and **ANOMALY SCORE != ATTACK PROBABILITY**. No FortiGate
supervised accuracy, precision, recall, F1, or production-performance claim is
made.

## 6. Branch B — UNSW-NB15 Benchmark

U1 is Isolation Forest. U2 is the MiniBatchKMeans distance scorer. BASE-S1 is
Logistic Regression with C=1.0; BASE-S2 is the frozen Stage 2.3 Random Forest
S2_CONFIG. CHAIN-S1 and CHAIN-S2 use 28 BASE features plus continuous U1 and U2
signals, for 30 source features. CHAIN-S1 uses Logistic Regression C=1.0;
CHAIN-S2 uses the frozen Random Forest S2_CONFIG. Chained training signals were
OOF / CROSS-FITTED with same-row overlap `0`
and same-group overlap `0`.

## 7. Metric Terminology

Stage 2.2 is reported using the registry label **Stage 2.2 PR_AUC_AP**,
with implementation `sklearn.metrics.average_precision_score`;
the source terminology is not silently renamed. Stage 2.3/2.4 supervised
primary evaluation uses Average Precision from
`sklearn.metrics.average_precision_score`, with
ATTACK = 1 and continuous score `p_attack`.

## 8. Final Results

The machine-readable outputs are the seven approved tables:

1. [`01_dataset_roles.csv`](results/stage_2_5/tables/01_dataset_roles.csv)
2. [`02_models.csv`](results/stage_2_5/tables/02_models.csv)
3. [`03_unsupervised_results.csv`](results/stage_2_5/tables/03_unsupervised_results.csv)
4. [`04_base_supervised_results.csv`](results/stage_2_5/tables/04_base_supervised_results.csv)
5. [`05_chain_development.csv`](results/stage_2_5/tables/05_chain_development.csv)
6. [`06_chain_locked_test.csv`](results/stage_2_5/tables/06_chain_locked_test.csv)
7. [`07_leakage_governance.csv`](results/stage_2_5/tables/07_leakage_governance.csv)

They preserve separate FortiGate descriptive anomaly aggregates, UNSW
unsupervised metrics, supervised baselines, chain comparisons, locked TEST
secondary metrics, sensitivity-only rows, and governance evidence.

## 9. Chained ML Analysis

| Pair | BASE AP | CHAIN AP | Delta | Frozen result |
|---|---:|---:|---:|---|
| S1 development | 0.9939231496371828 | 0.9941359114288555 | 0.00021276179167273312 | IMPROVEMENT |
| S2 development | 0.9968637967521546 | 0.9968208117560664 | -4.298499608823558e-05 | DEGRADATION |

Adding anomaly scores produced a small positive AP change for S1 and did not
improve S2. Additional features are therefore not automatically beneficial to
every supervised model. See
[`03_paired_ap_deltas.png`](results/stage_2_5/figures/03_paired_ap_deltas.png).

## 10. Locked TEST Reporting

Stage 2.4E is a **LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION** over
`82332` rows. The frozen
descriptive AP results are:

| Pair | BASE AP | CHAIN AP | Delta |
|---|---:|---:|---:|
| S1 | 0.9650555012702602 | 0.9659663520592334 | 0.0009108507889732387 |
| S2 | 0.9848644789351858 | 0.9845491751973731 | -0.00031530373781274434 |

These TEST deltas are descriptive reporting only. They do not establish a new
winner or alter the frozen selection. The six reconciled matrices are shown in
[`04_confusion_matrices.png`](results/stage_2_5/figures/04_confusion_matrices.png).

## 11. Test Limitation

The official UNSW-NB15 TEST split was used in earlier fixed-stage evaluations.
Therefore Stage 2.4E was a **LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION**, but
the TEST split was **NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL**.

## 12. Governance and Leakage Controls

- Training anomaly signals: **OOF / CROSS-FITTED**.
- Same-row fit/signal overlap: **0**.
- Same-group fit/signal overlap: **0**.
- Planned fit IDs: **28**; fresh executed: **20**;
  validated reused: **0**; not required by deduplication:
  **8**; unresolved: **0**.
- Accounted: **28/28**; signal coverage: **140273/140273**;
  fallback/imputed signals: **0**.
- Selection lock: **VERIFIED**; human TEST authorization: **VERIFIED**.
- TEST contribution to fitted state: **NONE**; post-TEST tuning: **NONE**.

## 13. Limitations

- FortiGate has no defensible primary supervised ground truth in this project.
- UNSW is a benchmark and does not establish FortiGate production performance.
- Small chain AP changes carry **NO STATISTICAL SIGNIFICANCE CLAIM**.
- The official TEST split is not newly unseen at the overall project level.
- FortiGate anomaly findings require analyst and contextual interpretation.
- Benchmark performance does not imply detection of every attack.
- The project is not claimed production-ready.

## 14. Claim Boundaries

The approved claims contract is [`claims_matrix.json`](results/stage_2_5/claims_matrix.json).
The following boundaries remain explicit:

`ANOMALY != ATTACK` · `ANOMALY SCORE != ATTACK PROBABILITY` ·
`RULE MATCH != CONFIRMED ATTACK` · `HIGH_INTEREST != CONFIRMED ATTACK` ·
`LOW_INTEREST != CONFIRMED BENIGN` · `SOURCE THREAT OBSERVATION != GROUND TRUTH` ·
`ABSENCE OF ALERT != BENIGN` · `NO STATISTICAL SIGNIFICANCE CLAIM`.

## 15. Reproducibility

The frozen registry, source inventory, tables, figures, and validation commands
are documented in [`docs/reproducibility_runbook.md`](reproducibility_runbook.md).
Stage 2.5 reporting adapts frozen artifacts; it does not retrain, regenerate
predictions, or rerun official TEST.

## 16. Conclusion

The project preserves a real-log anomaly workflow without fabricated ground
truth, while the separate UNSW benchmark branch enables quantitative supervised
evaluation. Leakage-safe chained signals were implemented successfully. S1
received a small frozen development AP increase; S2 did not improve. These
conclusions remain dataset-scoped, descriptive, and unsuitable for claims of
universal or production superiority.

## Historical Stage 2.0 Context

The earlier FortiGate Stage 2.0 package remains historical context and is
preserved under `data/processed/stage_2_0_v5/`. Its anomaly, explanation, and
prioritization outputs are not relabeled as attacks by this report.
