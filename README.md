# Security Log Intelligence

Security Log Intelligence is a reproducible cybersecurity log-analysis project
with two deliberately separate evaluation branches.

## Architecture

- **Branch A — FortiGate:** real sanitized logs for unsupervised anomaly
  scoring, prioritization, explainability, and case studies.
- **Branch B — UNSW-NB15:** labeled benchmark for U1/U2, BASE S1/S2, and
  CHAIN-S1/S2 quantitative evaluation.

**DATASETS MERGED: NO.** UNSW metrics do NOT establish FortiGate production
performance. See the [final architecture](docs/results/stage_2_5/figures/01_two_branch_architecture.mmd).

## Key Capabilities

- real-log anomaly scoring and prioritization
- labeled benchmark supervised evaluation
- leakage-safe OOF / cross-fitted chained ML
- frozen-artifact provenance and governance
- reproducible tables, figures, and validation

## Project Stages

- **Stage 1:** FortiGate ingestion, normalization, detection, storage, and
  anomaly/explainability foundations.
- **Historical Stage 1.3 — Evidence-Preserving FortiGate Normalization —
  Complete:** the read-only normalization contract and audit remain documented
  in the [schema](docs/normalized_event_schema.md),
  [mapping](docs/fortigate_normalization_mapping.md), and
  [findings](docs/stage_1_3_normalization_findings.md).
- **Stage 2.1:** FortiGate labeling-feasibility finding; UNSW adopted as the
  separate labeled benchmark.
- **Stage 2.2:** UNSW unsupervised U1/U2 comparison and FortiGate anomaly review.
- **Stage 2.3:** UNSW BASE S1/S2 supervised classification.
- **Stage 2.4:** leakage-safe CHAIN-S1/S2 development and locked fixed-design
  evaluation.
- **Stage 2.5A–C:** registry, seven tables, four figures, and this documentation.

## Headline Results

Frozen UNSW development comparisons use Average Precision:

- CHAIN-S1: `0.00021276179167273312` AP delta (`IMPROVEMENT`).
- CHAIN-S2: `-4.298499608823558e-05` AP delta (`DEGRADATION`).

Locked TEST deltas are descriptive only: S1 `0.0009108507889732387` and
S2 `-0.00031530373781274434` (CHAIN-S2 AP `0.9845491751973731`).
**NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL.** **NO STATISTICAL SIGNIFICANCE CLAIM.**
UNSW metrics do NOT establish FortiGate production performance.

## Repository Structure

`src/` contains pipeline and reporting code; `tests/` contains focused tests;
`docs/plans/` contains approved plans; `docs/results/stage_2_5/` contains the
registry, provenance, tables, and figures; `data/` contains local raw and
processed evidence according to the data policy.

## Quick Start / Validation

See the [reproducibility runbook](docs/reproducibility_runbook.md). The frozen
package validators are:

```sh
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_package --output-dir docs/results/stage_2_5 --validate-only
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_tables_figures --output-dir docs/results/stage_2_5 --validate-only
PYTHONPATH=src .venv/bin/python -m pytest tests/test_stage_2_5_package.py tests/test_stage_2_5_claims.py tests/test_stage_2_5_tables_figures.py tests/test_stage_2_5_docs.py -q
```

## Data Policy

Raw FortiGate and UNSW files are immutable local evidence and are not committed.
Generated row-level predictions, model bundles, caches, and local metadata may
remain ignored. Public aggregate registry/table/figure artifacts carry hashes
and provenance; no secrets or credentials are required.

## Limitations

`ANOMALY != ATTACK`; `ANOMALY SCORE != ATTACK PROBABILITY`;
`RULE MATCH != CONFIRMED ATTACK`; `HIGH_INTEREST != CONFIRMED ATTACK`;
`LOW_INTEREST != CONFIRMED BENIGN`; `SOURCE THREAT OBSERVATION != GROUND TRUTH`;
`ABSENCE OF ALERT != BENIGN`. FortiGate has no defensible primary supervised
ground truth here. Benchmark results do not imply every attack is detected or
production readiness. The official TEST split was used in earlier fixed-stage
evaluations and is not newly unseen at the overall project level.
**NO STATISTICAL SIGNIFICANCE CLAIM.**

## Documentation

- [Final technical report](docs/final_project_report.md)
- [Reproducibility runbook](docs/reproducibility_runbook.md)
- [Stage 2.5 results package](docs/results/stage_2_5/)
- [Claims contract](docs/results/stage_2_5/claims_matrix.json)

Registry SHA-256: `c7a29a52b6ef9d3a95dc8c53f2f44c19ee7e91583a4d7231b7f7135b75dedb10`
