"""Render the Stage 2.5C report, README, and reproducibility runbook."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "docs/results/stage_2_5/final_result_registry.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_registry() -> tuple[dict[str, Any], str]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8")), _sha256(REGISTRY_PATH)


def _render_report(registry: dict[str, Any], registry_sha: str) -> str:
    dev = registry["comparisons"]["development"]
    test = registry["comparisons"]["locked_test"]
    fit = registry["leakage"]["fit_accounting"]
    return f'''# Security Log Intelligence

Status: **Stage 2.5C documentation generated from the frozen Stage 2.5 registry.**

Registry SHA-256: `{registry_sha}`

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
`{dev['CHAIN-S1']['delta_ap']}` AP and degraded S2 by `{dev['CHAIN-S2']['delta_ap']}` AP.
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
OOF / CROSS-FITTED with same-row overlap `{registry['leakage']['same_row_fit_signal_overlap']}`
and same-group overlap `{registry['leakage']['same_group_fit_signal_overlap']}`.

## 7. Metric Terminology

Stage 2.2 is reported using the registry label **{registry['metrics']['stage_2_2_unsupervised']['display_name']}**,
with implementation `{registry['metrics']['stage_2_2_unsupervised']['implementation']}`;
the source terminology is not silently renamed. Stage 2.3/2.4 supervised
primary evaluation uses Average Precision from
`{registry['metrics']['supervised_average_precision']['implementation']}`, with
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
| S1 development | {dev['CHAIN-S1']['base_ap']} | {dev['CHAIN-S1']['chain_ap']} | {dev['CHAIN-S1']['delta_ap']} | {dev['CHAIN-S1']['result']} |
| S2 development | {dev['CHAIN-S2']['base_ap']} | {dev['CHAIN-S2']['chain_ap']} | {dev['CHAIN-S2']['delta_ap']} | {dev['CHAIN-S2']['result']} |

Adding anomaly scores produced a small positive AP change for S1 and did not
improve S2. Additional features are therefore not automatically beneficial to
every supervised model. See
[`03_paired_ap_deltas.png`](results/stage_2_5/figures/03_paired_ap_deltas.png).

## 10. Locked TEST Reporting

Stage 2.4E is a **LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION** over
`{registry['datasets']['UNSW_NB15_BENCHMARK']['official_test_rows']}` rows. The frozen
descriptive AP results are:

| Pair | BASE AP | CHAIN AP | Delta |
|---|---:|---:|---:|
| S1 | {test['CHAIN-S1']['base_ap']} | {test['CHAIN-S1']['chain_ap']} | {test['CHAIN-S1']['ap_delta']} |
| S2 | {test['CHAIN-S2']['base_ap']} | {test['CHAIN-S2']['chain_ap']} | {test['CHAIN-S2']['ap_delta']} |

These TEST deltas are descriptive reporting only. They do not establish a new
winner or alter the frozen selection. The six reconciled matrices are shown in
[`04_confusion_matrices.png`](results/stage_2_5/figures/04_confusion_matrices.png).

## 11. Test Limitation

The official UNSW-NB15 TEST split was used in earlier fixed-stage evaluations.
Therefore Stage 2.4E was a **LOCKED FIXED-DESIGN FINAL CHAINED EVALUATION**, but
the TEST split was **NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL**.

## 12. Governance and Leakage Controls

- Training anomaly signals: **OOF / CROSS-FITTED**.
- Same-row fit/signal overlap: **{registry['leakage']['same_row_fit_signal_overlap']}**.
- Same-group fit/signal overlap: **{registry['leakage']['same_group_fit_signal_overlap']}**.
- Planned fit IDs: **{fit['planned_fit_ids']}**; fresh executed: **{fit['fresh_executed']}**;
  validated reused: **{fit['validated_reused']}**; not required by deduplication:
  **{fit['not_required_by_deduplication']}**; unresolved: **{fit['unresolved']}**.
- Accounted: **{fit['total_accounted']}**; signal coverage: **{fit['signal_coverage']}**;
  fallback/imputed signals: **{fit['fallback_or_imputed_signals']}**.
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
'''


def _render_readme(registry: dict[str, Any], registry_sha: str) -> str:
    dev = registry["comparisons"]["development"]
    test = registry["comparisons"]["locked_test"]
    return f'''# Security Log Intelligence

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
- **Stage 2.1:** FortiGate labeling-feasibility finding; UNSW adopted as the
  separate labeled benchmark.
- **Stage 2.2:** UNSW unsupervised U1/U2 comparison and FortiGate anomaly review.
- **Stage 2.3:** UNSW BASE S1/S2 supervised classification.
- **Stage 2.4:** leakage-safe CHAIN-S1/S2 development and locked fixed-design
  evaluation.
- **Stage 2.5A–C:** registry, seven tables, four figures, and this documentation.

## Headline Results

Frozen UNSW development comparisons use Average Precision:

- CHAIN-S1: `{dev['CHAIN-S1']['delta_ap']}` AP delta (`{dev['CHAIN-S1']['result']}`).
- CHAIN-S2: `{dev['CHAIN-S2']['delta_ap']}` AP delta (`{dev['CHAIN-S2']['result']}`).

Locked TEST deltas are descriptive only: S1 `{test['CHAIN-S1']['ap_delta']}` and
S2 `{test['CHAIN-S2']['ap_delta']}` (CHAIN-S2 AP `{test['CHAIN-S2']['chain_ap']}`).
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

Registry SHA-256: `{registry_sha}`
'''


def _render_runbook(registry: dict[str, Any], registry_sha: str) -> str:
    return f'''# Reproducibility Runbook

This runbook describes frozen-artifact inspection and authorized historical
reproduction. Stage 2.5C does not retrain models, regenerate predictions, or
rerun official TEST. Do not rerun official TEST during documentation work.
TEST STATUS: **NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL.**
DATASETS MERGED: NO.
NO STATISTICAL SIGNIFICANCE CLAIM.
ANOMALY != ATTACK; ANOMALY SCORE != ATTACK PROBABILITY.
Registry SHA-256: `{registry_sha}`.

## Environment

The repository uses Python 3.12 and pinned dependencies in
[`requirements.txt`](../requirements.txt) and
[`requirements-dev.txt`](../requirements-dev.txt). The validated environment
reported Python 3.12.14 and `python -m pip check` with no broken requirements.

macOS/Linux shell:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip check
```

PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pip check
```

Record OS, Python, dependency versions, and platform-specific warnings when
reproducing. Do not treat software-test counts as model accuracy.

## Repository Setup

Open the repository root, activate the environment, and keep raw and generated
data local. Do not use a broad cleanup command and do not overwrite checkpoint
artifacts.

## Data Placement

- FortiGate raw input: `data/raw/network_log_SAFE.csv`
- UNSW training: `data/unsw_nb15/raw/UNSW_NB15_training-set.csv`
- UNSW testing: `data/unsw_nb15/raw/UNSW_NB15_testing-set.csv`

Raw files are not committed. Verify them with the Stage 2.1 acquisition and
validation manifests before any authorized historical pipeline run. FortiGate
redistribution requires explicit authorization; public UNSW use must respect
the dataset's source terms.
UNSW metrics do NOT establish FortiGate production performance.

## Pipeline Entry Points

The following are current repository entry points. Historical training or TEST
commands require separate authorization and must write to a fresh output root:

- Stage 1 validation scripts: `scripts/validate_stage_1_2.ps1` through
  `scripts/validate_stage_1_9.ps1`, and `scripts/validate_stage_2_0.ps1`.
- Stage 2.1 preparation: `src/prepare_stage_2_1.py` (`--normalized-input`,
  `--output-dir`, and tier options).
- Stage 2.2 FortiGate U2: `src/run_fortigate_u2.py`; UNSW validation:
  `src/run_unsw_validation.py`; fixed TEST evaluator:
  `src/run_unsw_test_evaluation.py`.
- Stage 2.3 supervised development: `src/run_supervised.py --checkpoint
  2.3A|2.3B|2.3C|2.3D`; fixed TEST evaluator:
  `src/run_supervised_test_evaluation.py`.
- Stage 2.4 chained development: `src/run_chained.py --checkpoint 2.4A|2.4B|2.4C|2.4D`;
  fixed TEST evaluator: `src/run_chained_test_evaluation.py`.
- Stage 2.5A registry: `src/build_stage_2_5_package.py`.
- Stage 2.5B tables/figures: `src/build_stage_2_5_tables_figures.py`.

Inspect `--help` and source parsers before any authorized execution. The
default Stage 2.2–2.4 runners may perform fitting or evaluation; they are not
part of frozen Stage 2.5 validation.

## Generated Artifacts

Processed artifacts, model bundles, signals, predictions, caches, and local
metadata may be Git-ignored while remaining necessary provenance. Do not delete
them merely because they are ignored. The public aggregate package is under
`docs/results/stage_2_5/`.

## Final Reporting

The Stage 2.5A builder reads the approved Stage 2.4 handoff and reconciles
frozen Stage 2.1–2.4 manifests, locks, reports, metrics, plans, and evaluator
source hashes. The Stage 2.5B builder reads the registry and explicitly
referenced immutable FortiGate/sensitivity artifacts to produce seven tables,
four figures, and `stage_2_5B_provenance.json`.

```sh
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_package --handoff data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json --output-dir docs/results/stage_2_5
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_package --output-dir docs/results/stage_2_5 --validate-only
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_tables_figures --registry docs/results/stage_2_5/final_result_registry.json --output-dir docs/results/stage_2_5
PYTHONPATH=src .venv/bin/python -m src.build_stage_2_5_tables_figures --output-dir docs/results/stage_2_5 --validate-only
```

These commands use frozen artifacts only. They do not load models, fit, score
rows, regenerate predictions, or open official TEST.

## Validation

Targeted Stage 2.5 validation:

```sh
PYTHONPATH=src .venv/bin/python -m pytest tests/test_stage_2_5_package.py tests/test_stage_2_5_claims.py tests/test_stage_2_5_tables_figures.py tests/test_stage_2_5_docs.py -q
```

The full repository suite is a separate validation scope:
`PYTHONPATH=src .venv/bin/python -m pytest tests -q`. Stage 2.5C does not run
that suite or change frozen expectations to make platform-sensitive failures
green.

## Platform Notes

Known macOS/sandbox-specific baseline regression failures from prior audits are
environment limitations unless independently shown to be caused by Stage 2.5.
No methodology changes are authorized to hide them. Historical Windows
validation of **286 passed / 130 subtests / 2 upstream deprecation warnings**
is software validation only: **THIS IS NOT MODEL ACCURACY.**

## Security / Data Hygiene

Raw logs, row-level predictions, model bundles, secrets, credentials, API keys,
and private TEST material stay outside public Git. `.env` and caches are
excluded by repository policy. Provenance uses full SHA-256 hashes and explicit
repository-relative paths; no raw rows are embedded in the aggregate package.
Rule matches, HIGH_INTEREST, LOW_INTEREST, source threat observations, and
absence of alerts are not ground truth or confirmed attack/benign labels.

## Final Artifacts

- [Final technical report](final_project_report.md)
- [Registry](results/stage_2_5/final_result_registry.json)
- [Tables](results/stage_2_5/tables/)
- [Figures](results/stage_2_5/figures/)
- [Claims contract](results/stage_2_5/claims_matrix.json)
'''


def build() -> None:
    registry, registry_sha = _load_registry()
    (ROOT / "docs/final_project_report.md").write_text(_render_report(registry, registry_sha), encoding="utf-8")
    (ROOT / "README.md").write_text(_render_readme(registry, registry_sha), encoding="utf-8")
    (ROOT / "docs/reproducibility_runbook.md").write_text(_render_runbook(registry, registry_sha), encoding="utf-8")


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
