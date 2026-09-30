from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = json.loads((ROOT / "docs/results/stage_2_5/final_result_registry.json").read_text())


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_stage_2_5_documents_have_required_sections_and_boundaries() -> None:
    report = _read("docs/final_project_report.md")
    readme = _read("README.md")
    runbook = _read("docs/reproducibility_runbook.md")
    for heading in ("## Executive Summary", "## 2. Project Architecture", "## 4. Stage 2.1 — Label Feasibility", "## 8. Final Results", "## 11. Test Limitation", "## 14. Claim Boundaries", "## 16. Conclusion"):
        assert heading in report
    for heading in ("## Architecture", "## Key Capabilities", "## Project Stages", "## Headline Results", "## Repository Structure", "## Quick Start / Validation", "## Data Policy", "## Limitations", "## Documentation"):
        assert heading in readme
    for heading in ("## Environment", "## Repository Setup", "## Data Placement", "## Pipeline Entry Points", "## Generated Artifacts", "## Final Reporting", "## Validation", "## Platform Notes", "## Security / Data Hygiene"):
        assert heading in runbook
    for document in (report, readme, runbook):
        assert "DATASETS MERGED: NO" in document
        assert "NOT NEWLY UNSEEN AT THE OVERALL PROJECT LEVEL" in document
        assert "NO STATISTICAL SIGNIFICANCE CLAIM" in document
        assert "ANOMALY != ATTACK" in document
        assert "UNSW metrics do NOT establish FortiGate production performance" in document


def test_documented_numbers_match_registry() -> None:
    report = _read("docs/final_project_report.md")
    readme = _read("README.md")
    development = REGISTRY["comparisons"]["development"]
    locked = REGISTRY["comparisons"]["locked_test"]
    values = [
        development["CHAIN-S1"]["base_ap"], development["CHAIN-S1"]["chain_ap"], development["CHAIN-S1"]["delta_ap"],
        development["CHAIN-S2"]["base_ap"], development["CHAIN-S2"]["chain_ap"], development["CHAIN-S2"]["delta_ap"],
        locked["CHAIN-S1"]["base_ap"], locked["CHAIN-S1"]["chain_ap"], locked["CHAIN-S1"]["ap_delta"],
        locked["CHAIN-S2"]["base_ap"], locked["CHAIN-S2"]["chain_ap"], locked["CHAIN-S2"]["ap_delta"],
    ]
    for value in values:
        assert str(value) in report
    assert str(locked["CHAIN-S2"]["chain_ap"]) in readme
    assert str(REGISTRY["datasets"]["UNSW_NB15_BENCHMARK"]["official_test_rows"]) in report


def test_all_relative_document_links_resolve() -> None:
    for relative in ("README.md", "docs/final_project_report.md", "docs/reproducibility_runbook.md"):
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
            target = target.split("#", 1)[0].strip().strip("<>")
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            assert (path.parent / target).exists(), f"dead link in {relative}: {target}"


def test_runbook_documents_current_entry_points_and_frozen_workflow() -> None:
    runbook = _read("docs/reproducibility_runbook.md")
    for entry_point in ("src/prepare_stage_2_1.py", "src/run_fortigate_u2.py", "src/run_unsw_validation.py", "src/run_unsw_test_evaluation.py", "src/run_supervised.py", "src/run_supervised_test_evaluation.py", "src/run_chained.py", "src/run_chained_test_evaluation.py", "src/build_stage_2_5_package.py", "src/build_stage_2_5_tables_figures.py"):
        assert entry_point in runbook
        assert (ROOT / entry_point).exists()
    assert "Do not rerun official TEST" in runbook
    assert "THIS IS NOT MODEL ACCURACY" in runbook
