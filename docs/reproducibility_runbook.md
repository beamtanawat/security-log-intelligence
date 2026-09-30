# Reproducibility Runbook

This runbook describes frozen-artifact inspection and authorized historical
reproduction. Stage 2.5C does not retrain models, regenerate predictions, or
rerun official TEST. Do not rerun official TEST during documentation work.
TEST STATUS: **NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL.**
DATASETS MERGED: NO.
NO STATISTICAL SIGNIFICANCE CLAIM.
ANOMALY != ATTACK; ANOMALY SCORE != ATTACK PROBABILITY.
Registry SHA-256: `c7a29a52b6ef9d3a95dc8c53f2f44c19ee7e91583a4d7231b7f7135b75dedb10`.

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
.venv\Scripts\Activate.ps1
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
