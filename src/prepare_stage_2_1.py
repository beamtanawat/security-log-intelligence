"""Build deterministic Stage 2.1 pre-review contracts and split staging.

This command never creates labels, opens TEST, or creates the Custodian's
private bundle. Human review and private custody remain explicit gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterable

from detection.input import iter_normalized_events
from labeling.artifact import write_json_no_replace, write_jsonl_no_replace, validate_public_bundle
from labeling.contracts import build_contracts, build_json_schemas
from labeling.grouping import build_group_rows, evaluate_tier_feasibility, select_entity_tier
from labeling.identity import sha256_hex
from labeling.sampling import STRATA
from labeling.splitting import allocate_hard_group_splits, build_hard_group_vectors, build_split_rows


DATASET_SHA256 = "c195c6322665530d56f1bd5390b6b1c20728881a21ee36352c7c46e0a7138976"


class Stage21Blocker(RuntimeError):
    """Raised when an approved Stage 2.1 gate cannot safely proceed."""


def check_execution_preconditions(
    *,
    private_root: str | Path,
    reviewer_registry: str | Path | None,
    external_evidence_registry: str | Path | None,
    custodian_id: str = "CUSTODIAN_TANAWAT_V1",
) -> None:
    """Check required human-controlled inputs without opening private data."""

    if reviewer_registry is None or not Path(reviewer_registry).is_file():
        raise Stage21Blocker("two independent human reviewers and approved reviewer registry are required")
    if external_evidence_registry is None or not Path(external_evidence_registry).is_file():
        raise Stage21Blocker("approved external-evidence registry or explicit no-evidence record is required")
    if custodian_id != "CUSTODIAN_TANAWAT_V1":
        raise Stage21Blocker("named TEST Custodian must be CUSTODIAN_TANAWAT_V1")
    root = Path(private_root)
    if not root.is_dir():
        raise Stage21Blocker("Custodian private TEST root must exist before TEST review")


def _write_contracts(root: Path, dataset_sha256: str) -> None:
    contracts = build_contracts(dataset_sha256)
    for name, payload in contracts.items():
        write_json_no_replace(root / "contracts" / f"{name}.json", payload)
    for name, schema in build_json_schemas().items():
        write_json_no_replace(root / "schemas" / name, schema)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _historical_context_paths(normalized_input: Path) -> tuple[Path, Path]:
    processed = normalized_input.parent
    return (
        processed / "stage_1_8" / "stage_1_8_anomaly_scores.jsonl",
        processed / "stage_1_4f_detection_findings.jsonl",
    )


def _load_sampling_strata(normalized_input: Path, rows: list[object]) -> tuple[dict[str, str], dict[str, str]]:
    score_path, finding_path = _historical_context_paths(normalized_input)
    if not score_path.is_file():
        raise Stage21Blocker(f"historical score artifact required for frozen sampling strata: {score_path}")
    if not finding_path.is_file():
        raise Stage21Blocker(f"historical finding artifact required for frozen sampling strata: {finding_path}")
    scores: dict[int, tuple[str, float]] = {}
    with score_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            payload = json.loads(line)
            scores[int(payload["source_record_number"])] = (str(payload["anomaly_band"]), float(payload["anomaly_score"]))
    source_context: set[int] = set()
    with finding_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            payload = json.loads(line)
            source_context.add(int(payload["source_event"]["source_record_number"]))

    def classify(record_number: int) -> str:
        if record_number in source_context:
            return "SOURCE_OR_RULE_CONTEXT"
        band, score = scores[record_number]
        if band == "TOP_0_1_PERCENT":
            return "HISTORICAL_TOP_0_1"
        if band == "TOP_1_PERCENT":
            return "HISTORICAL_TOP_1"
        if band == "TOP_5_PERCENT":
            return "HISTORICAL_TOP_5"
        if score >= 50.0:
            return "HISTORICAL_MID_50_95"
        return "HISTORICAL_BASE_0_50"

    strata: dict[str, str] = {}
    for row in rows:
        number = row.source_record_number
        if number not in scores:
            raise Stage21Blocker(f"historical score artifact missing source record {number}")
        strata[row.source_record_identity_sha256] = classify(number)
    hashes = {
        "normalized_input": _sha256_file(normalized_input),
        "stage_1_8_scores": _sha256_file(score_path),
        "stage_1_4_findings": _sha256_file(finding_path),
    }
    return strata, hashes


def _evaluate_selection(
    rows: list[object],
    selection: object,
    *,
    normalized_input: Path,
) -> tuple[dict[str, object], object | None, dict[str, str] | None]:
    if selection.selected_tier != "HARD_GROUP_ONLY":
        return evaluate_tier_feasibility(rows, selection), None, None
    strata, hashes = _load_sampling_strata(normalized_input, rows)
    vectors, totals = build_hard_group_vectors(rows, selection, strata)
    allocation = allocate_hard_group_splits(vectors, total_rows=len(rows), stratum_totals=totals)
    report = evaluate_tier_feasibility(
        rows,
        selection,
        assignment_by_group=allocation.assignments,
        sampling_strata=strata,
    )
    report["allocator"] = dict(allocation.report)
    report["source_artifact_sha256s"] = hashes
    report["allocator_status"] = allocation.status
    report["allocator_termination_reason"] = allocation.termination_reason
    report["allocator_failed_criteria"] = list(allocation.failed_criteria)
    return report, allocation, hashes


def build_pre_review_staging(
    normalized_input: str | Path,
    output_dir: str | Path,
    *,
    dataset_sha256: str = DATASET_SHA256,
    selected_tier: str = "ENTITY_ALL_ENDPOINTS",
    approved_fallback_tier: str | None = None,
) -> dict[str, object]:
    """Build no-label, no-TEST staging artifacts for Checkpoints 2.1A/B.

    The output is published only after independent structural validation and
    never replaces an existing versioned directory.
    """

    destination = Path(output_dir)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"output already exists: {destination}")
    normalized_path = Path(normalized_input)
    events = iter_normalized_events(normalized_path)
    rows = build_group_rows(events, dataset_sha256=dataset_sha256)
    selection = select_entity_tier(rows, selected_tier)
    feasibility, allocation, source_hashes = _evaluate_selection(rows, selection, normalized_input=normalized_path)
    predecessor_results: dict[str, object] = {selected_tier: feasibility}
    if feasibility["status"] != "PASS":
        if approved_fallback_tier is None:
            raise Stage21Blocker(
                f"entity tier {selected_tier} failed; explicit human fallback approval required: "
                + ",".join(feasibility["failed_criteria"])
            )
        if approved_fallback_tier == "HARD_GROUP_ONLY":
            for predecessor in ("ENTITY_ALL_ENDPOINTS", "ENTITY_SOURCE_HOST"):
                predecessor_selection = select_entity_tier(rows, predecessor)
                predecessor_results[predecessor] = evaluate_tier_feasibility(rows, predecessor_selection)
        selection = select_entity_tier(rows, approved_fallback_tier)
        feasibility, allocation, source_hashes = _evaluate_selection(rows, selection, normalized_input=normalized_path)
        feasibility["predecessor_results"] = predecessor_results
        feasibility["fallback_approvals"] = {
            "ENTITY_SOURCE_HOST": "HUMAN_APPROVED_FALLBACK",
            "HARD_GROUP_ONLY": "HUMAN_REAPPROVED_EXECUTION_AMENDMENT",
        }
        feasibility["rejected_predecessor_allocator"] = "HASH_BUCKET_GROUP_ASSIGNMENT_V1"
        if feasibility["status"] != "PASS":
            raise Stage21Blocker(
                f"approved fallback tier {approved_fallback_tier} failed: "
                + ",".join(feasibility["failed_criteria"])
            )
    split_rows = build_split_rows(rows, selection, allocation=allocation, source_artifact_sha256s=source_hashes)
    staging_parent = destination.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=staging_parent))
    try:
        _write_contracts(temporary, dataset_sha256)
        write_jsonl_no_replace(temporary / "manifests" / "split_manifest.jsonl", split_rows)
        write_json_no_replace(temporary / "reports" / "group_leakage_audit.json", feasibility)
        write_json_no_replace(
            temporary / "reports" / "pre_review_status.json",
            {
                "status": "PRE_REVIEW_STAGING_ONLY",
                "labels_created": False,
                "test_opened": False,
                "private_bundle_created": False,
                "selected_tier": selection.selected_tier,
                "split_manifest_sha256": sha256_hex(split_rows),
            },
        )
        validate_public_bundle(temporary)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"output appeared during build: {destination}")
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {"status": "PRE_REVIEW_STAGING_ONLY", "output_dir": str(destination), **feasibility}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Stage 2.1 pre-review staging artifacts.")
    parser.add_argument("--normalized-input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--selected-tier", default="ENTITY_ALL_ENDPOINTS")
    parser.add_argument("--approved-fallback-tier")
    args = parser.parse_args()
    result = build_pre_review_staging(
        args.normalized_input,
        args.output_dir,
        selected_tier=args.selected_tier,
        approved_fallback_tier=args.approved_fallback_tier,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
