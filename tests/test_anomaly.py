"""Synthetic contract tests for the Stage 1.8 anomaly-scoring foundation.

These tests deliberately use small, synthetic Stage 1.7 feature bundles.  They
never read the sanitized raw CSV or a real processed artifact.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import numpy as np  # noqa: E402

from ai_features.artifact import canonical_json, file_sha256, write_feature_row  # noqa: E402
from ai_features.contract import (  # noqa: E402
    EVALUATION_PROTOCOL_VERSION,
    METADATA_FIELDS,
    feature_definitions_payload,
)
from ai_features.models import (  # noqa: E402
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    HOLDOUT_PARTITION,
    REFERENCE_PARTITION,
    FeatureRow,
)
from anomaly.artifact import (  # noqa: E402
    MANIFEST_ARTIFACT_NAME,
    MODEL_ARTIFACT_NAME,
    MODEL_METADATA_ARTIFACT_NAME,
    SCORE_ARTIFACT_NAME,
    AnomalyArtifactError,
    build_manifest_payload,
    load_trusted_model,
    write_manifest,
)
from anomaly.input import (  # noqa: E402
    EXPECTED_STAGE_1_7_FEATURE_SHA256,
    AnomalyInputError,
    load_feature_bundle,
)
from anomaly.models import (  # noqa: E402
    ANOMALY_BANDS,
    APPROVED_PACKAGE_PINS,
    MODEL_CONFIG,
    AnomalyContractError,
    AnomalyScoreRow,
    validate_runtime_versions,
)
from anomaly.scoring import (  # noqa: E402
    AnomalyScoringError,
    assign_anomaly_band,
    build_feature_matrix,
    fit_reference_model,
    score_feature_rows,
)
from audit_anomaly_scores import (  # noqa: E402
    AnomalyScoreAuditError,
    audit_anomaly_score_bundle,
)
from score_anomalies import (  # noqa: E402
    AnomalyScoreBuildError,
    score_anomaly_bundle,
)


def feature_values(model_score: float) -> tuple[float, ...]:
    """Create one finite 36-value vector whose first value drives a fake model."""

    return (float(model_score),) + tuple(float(index) for index in range(1, 36))


def feature_row(
    record_number: int,
    partition: str,
    *,
    model_score: float = -0.5,
) -> FeatureRow:
    return FeatureRow(
        source_record_number=record_number,
        source_record_id=f"LOGUID_OPAQUE_{record_number}",
        partition=partition,
        values=feature_values(model_score),
    )


def runtime_versions() -> dict[str, str]:
    """Return the approved pin contract without querying the local environment."""

    return {
        "python": "3.12.10",
        **APPROVED_PACKAGE_PINS,
    }


class CapturingModel:
    """Small deterministic test double with an IsolationForest-like surface."""

    def __init__(self) -> None:
        self.fit_matrix: np.ndarray | None = None

    def fit(self, matrix: np.ndarray) -> "CapturingModel":
        self.fit_matrix = np.array(matrix, copy=True)
        return self

    def score_samples(self, matrix: np.ndarray) -> np.ndarray:
        return np.asarray(matrix[:, 0], dtype=np.float64)


def write_feature_bundle(directory: Path, rows: tuple[FeatureRow, ...]) -> str:
    """Write a strict minimal Stage 1.7 bundle for synthetic integration tests."""

    directory.mkdir()
    feature_path = directory / "stage_1_7_ai_features.jsonl"
    with feature_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            write_feature_row(handle, row)
    feature_sha256 = file_sha256(feature_path)
    counts = {
        REFERENCE_PARTITION: sum(row.partition == REFERENCE_PARTITION for row in rows),
        HOLDOUT_PARTITION: sum(row.partition == HOLDOUT_PARTITION for row in rows),
    }
    metadata = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "normalized_input": {
            "path": str((directory / "synthetic-normalized.jsonl").resolve()),
            "size_bytes": 1,
            "sha256": "a" * 64,
            "schema_version": "1.0",
        },
        "feature_artifact": {
            "path": "stage_1_7_ai_features.jsonl",
            "size_bytes": feature_path.stat().st_size,
            "sha256": feature_sha256,
            "row_count": len(rows),
        },
        "feature_names": list(FEATURE_NAMES),
        "feature_definitions": feature_definitions_payload(),
        "split": {
            "namespace": "stage-1.7-split-v1",
            "hash_algorithm": "sha256-first-8-bytes-unsigned-big-endian-modulo-10",
            "bucket_rule": "0..7=REFERENCE;8..9=HOLDOUT",
            "counts": counts,
            "distinct_group_counts": counts,
        },
        "rarity_maps": {
            "source_port": {"counts": [], "protocol_denominators": []},
            "destination_port": {"counts": [], "protocol_denominators": []},
            "service": {"counts": [], "protocol_denominators": []},
        },
        "reference_distributions": [
            {"name": name, "values": []} for name in FEATURE_NAMES
        ],
        "reference_constant_features": [],
        "eligible_reference_distributions": [
            {"name": name, "values": [], "eligible_count": 0}
            for name in FEATURE_NAMES
        ],
        "runtime": {"python_version": "3.12.10"},
        "evaluation_protocol_version": EVALUATION_PROTOCOL_VERSION,
    }
    assert set(metadata) == METADATA_FIELDS
    (directory / "stage_1_7_ai_feature_metadata.json").write_text(
        canonical_json(metadata) + "\n", encoding="utf-8", newline="\n"
    )
    return feature_sha256


class AnomalyScoreContractTests(unittest.TestCase):
    def test_score_rows_use_negative_model_score_percentiles_and_stable_ties(self) -> None:
        rows = (
            feature_row(10, REFERENCE_PARTITION, model_score=-0.2),
            feature_row(20, HOLDOUT_PARTITION, model_score=-0.9),
            feature_row(30, REFERENCE_PARTITION, model_score=-0.4),
            feature_row(40, HOLDOUT_PARTITION, model_score=-0.9),
        )
        model = CapturingModel().fit(build_feature_matrix(rows))

        scored, diagnostics = score_feature_rows(rows, model)

        self.assertEqual([row.source_record_number for row in scored], [10, 20, 30, 40])
        for row, expected_model_score in zip(
            scored, (-0.2, -0.9, -0.4, -0.9), strict=True
        ):
            self.assertAlmostEqual(row.model_score, expected_model_score, places=7)
            self.assertAlmostEqual(row.raw_abnormality, -row.model_score, places=12)
        self.assertEqual([row.anomaly_score for row in scored], [50.0, 100.0, 100.0, 100.0])
        self.assertEqual([row.anomaly_rank for row in scored], [4, 1, 3, 2])
        self.assertEqual(
            [row.source_record_number for row in sorted(scored, key=lambda row: row.anomaly_rank)],
            [20, 40, 30, 10],
        )
        self.assertEqual(
            [row.anomaly_band for row in scored],
            ["BASELINE", "TOP_0_1_PERCENT", "TOP_0_1_PERCENT", "TOP_0_1_PERCENT"],
        )
        self.assertTrue(all(row.analyst_review_selected for row in scored))
        self.assertEqual(diagnostics.reference_count, 2)

    def test_band_boundaries_use_unrounded_reference_percentiles(self) -> None:
        self.assertEqual(assign_anomaly_band(99.9), "TOP_0_1_PERCENT")
        self.assertEqual(assign_anomaly_band(99.0), "TOP_1_PERCENT")
        self.assertEqual(assign_anomaly_band(95.0), "TOP_5_PERCENT")
        self.assertEqual(assign_anomaly_band(94.999999), "BASELINE")
        self.assertEqual(set(ANOMALY_BANDS), {
            "TOP_0_1_PERCENT", "TOP_1_PERCENT", "TOP_5_PERCENT", "BASELINE"
        })

    def test_degenerate_reference_scores_fail_closed(self) -> None:
        rows = (
            feature_row(1, REFERENCE_PARTITION, model_score=-0.5),
            feature_row(2, REFERENCE_PARTITION, model_score=-0.5),
            feature_row(3, HOLDOUT_PARTITION, model_score=-0.7),
        )
        model = CapturingModel().fit(build_feature_matrix(rows))
        with self.assertRaisesRegex(AnomalyScoringError, "DEGENERATE_SCORE_REFERENCE"):
            score_feature_rows(rows, model)

    def test_fit_reference_model_never_passes_holdout_rows_to_fit(self) -> None:
        reference_rows = tuple(
            feature_row(index, REFERENCE_PARTITION, model_score=-0.1)
            for index in range(1, 4097)
        )
        holdout = feature_row(4097, HOLDOUT_PARTITION, model_score=-999.0)
        rows = reference_rows + (holdout,)
        captured: list[CapturingModel] = []

        def factory(**_kwargs: object) -> CapturingModel:
            model = CapturingModel()
            captured.append(model)
            return model

        fit_reference_model(rows, model_factory=factory, versions=runtime_versions())

        self.assertEqual(len(captured), 1)
        self.assertIsNotNone(captured[0].fit_matrix)
        self.assertEqual(captured[0].fit_matrix.shape, (4096, 36))
        self.assertNotIn(-999.0, captured[0].fit_matrix[:, 0])

    def test_holdout_only_changes_cannot_change_the_fitted_reference_matrix(self) -> None:
        reference_rows = tuple(
            feature_row(index, REFERENCE_PARTITION, model_score=-0.1)
            for index in range(1, 4097)
        )
        first_rows = reference_rows + (feature_row(4097, HOLDOUT_PARTITION, model_score=-0.2),)
        second_rows = reference_rows + (feature_row(4097, HOLDOUT_PARTITION, model_score=-999.0),)
        captured: list[CapturingModel] = []

        def factory(**_kwargs: object) -> CapturingModel:
            model = CapturingModel()
            captured.append(model)
            return model

        fit_reference_model(first_rows, model_factory=factory, versions=runtime_versions())
        fit_reference_model(second_rows, model_factory=factory, versions=runtime_versions())

        self.assertTrue(np.array_equal(captured[0].fit_matrix, captured[1].fit_matrix))

    def test_top_50_selection_is_a_rank_budget_not_an_attack_label(self) -> None:
        rows = tuple(
            feature_row(index, REFERENCE_PARTITION, model_score=-float(index))
            for index in range(1, 52)
        )
        model = CapturingModel().fit(build_feature_matrix(rows))

        scored, _ = score_feature_rows(rows, model)

        self.assertEqual(sum(row.analyst_review_selected for row in scored), 50)
        least_abnormal = next(row for row in scored if row.source_record_number == 1)
        self.assertEqual(least_abnormal.anomaly_rank, 51)
        self.assertFalse(least_abnormal.analyst_review_selected)
        self.assertFalse(any("attack" in field for field in scored[0].to_dict()))

    def test_reference_only_scores_report_explicit_empty_holdout_diagnostics(self) -> None:
        rows = (
            feature_row(1, REFERENCE_PARTITION, model_score=-0.2),
            feature_row(2, REFERENCE_PARTITION, model_score=-0.4),
        )
        model = CapturingModel().fit(build_feature_matrix(rows))

        _, diagnostics = score_feature_rows(rows, model)

        self.assertEqual(
            diagnostics.partition_diagnostics[HOLDOUT_PARTITION],
            {
                "row_count": 0,
                "raw_abnormality_quantiles": None,
                "distinct_raw_score_count": 0,
                "tied_row_count": 0,
                "band_counts": {
                    "TOP_0_1_PERCENT": 0,
                    "TOP_1_PERCENT": 0,
                    "TOP_5_PERCENT": 0,
                    "BASELINE": 0,
                },
            },
        )

    def test_repeated_scoring_produces_identical_logical_rows_and_finite_numbers(self) -> None:
        rows = (
            feature_row(1, REFERENCE_PARTITION, model_score=-0.2),
            feature_row(2, REFERENCE_PARTITION, model_score=-0.4),
            feature_row(3, HOLDOUT_PARTITION, model_score=-0.7),
        )
        model = CapturingModel().fit(build_feature_matrix(rows))

        first, _ = score_feature_rows(rows, model)
        second, _ = score_feature_rows(rows, model)

        self.assertEqual([row.to_dict() for row in first], [row.to_dict() for row in second])
        for row in first:
            self.assertTrue(math.isfinite(row.model_score))
            self.assertTrue(math.isfinite(row.raw_abnormality))
            self.assertTrue(math.isfinite(row.anomaly_score))

    def test_matrix_uses_only_the_36_numeric_values_not_source_provenance(self) -> None:
        first = feature_row(10, REFERENCE_PARTITION, model_score=-0.25)
        second = FeatureRow(
            source_record_number=20,
            source_record_id="DIFFERENT_OPAQUE_PROVENANCE",
            partition=HOLDOUT_PARTITION,
            values=first.values,
        )

        matrix = build_feature_matrix((first, second))

        self.assertEqual(matrix.shape, (2, 36))
        self.assertTrue(np.array_equal(matrix[0], matrix[1]))

    def test_runtime_versions_require_the_approved_exact_package_pins(self) -> None:
        validate_runtime_versions(runtime_versions())
        incompatible = runtime_versions()
        incompatible["scikit-learn"] = "0.0.0"
        with self.assertRaises(AnomalyContractError):
            validate_runtime_versions(incompatible)

    def test_score_row_rejects_nonfinite_values_and_invalid_attack_like_contract_data(self) -> None:
        with self.assertRaises(AnomalyContractError):
            AnomalyScoreRow(
                source_record_number=1,
                source_record_id="LOGUID_OPAQUE",
                partition=REFERENCE_PARTITION,
                model_score=float("nan"),
                raw_abnormality=0.5,
                anomaly_score=50.0,
                anomaly_rank=1,
                anomaly_band="BASELINE",
                analyst_review_selected=True,
            )


class FeatureBundleInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_root = Path(tempfile.mkdtemp(prefix=".stage_1_8_input."))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary_root, ignore_errors=True)

    def test_feature_bundle_rejects_expected_identity_mismatch_before_modeling(self) -> None:
        features = self.temporary_root / "features"
        actual_hash = write_feature_bundle(
            features,
            (
                feature_row(1, REFERENCE_PARTITION),
                feature_row(2, HOLDOUT_PARTITION),
            ),
        )
        self.assertNotEqual(actual_hash, EXPECTED_STAGE_1_7_FEATURE_SHA256)
        with self.assertRaises(AnomalyInputError):
            load_feature_bundle(features, expected_feature_sha256="b" * 64)

    def test_feature_bundle_requires_exact_36_feature_order(self) -> None:
        features = self.temporary_root / "features"
        actual_hash = write_feature_bundle(
            features,
            (
                feature_row(1, REFERENCE_PARTITION),
                feature_row(2, HOLDOUT_PARTITION),
            ),
        )
        metadata_path = features / "stage_1_7_ai_feature_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["feature_names"] = list(reversed(metadata["feature_names"]))
        metadata_path.write_text(canonical_json(metadata) + "\n", encoding="utf-8")
        with self.assertRaises(AnomalyInputError):
            load_feature_bundle(features, expected_feature_sha256=actual_hash)

    def test_feature_bundle_reconciles_rows_to_metadata_feature_artifact_row_count(self) -> None:
        features = self.temporary_root / "features"
        actual_hash = write_feature_bundle(
            features,
            (
                feature_row(1, REFERENCE_PARTITION),
                feature_row(2, HOLDOUT_PARTITION),
            ),
        )

        bundle = load_feature_bundle(features, expected_feature_sha256=actual_hash)

        self.assertEqual(len(bundle.rows), 2)


class TrustedManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_root = Path(
            tempfile.mkdtemp(prefix=".stage_1_8_manifest.", dir=PROJECT_ROOT / "data" / "processed")
        )
        self.bundle = self.temporary_root / "bundle"
        self.bundle.mkdir()
        (self.bundle / MODEL_ARTIFACT_NAME).write_bytes(b"synthetic-model")
        (self.bundle / MODEL_METADATA_ARTIFACT_NAME).write_text("{}\n", encoding="utf-8")
        (self.bundle / SCORE_ARTIFACT_NAME).write_text("{}\n", encoding="utf-8")
        payload = build_manifest_payload(
            feature_sha256="1" * 64,
            feature_count=36,
            reference_count=4,
            holdout_count=1,
            feature_contract_sha256="2" * 64,
            model_artifact_sha256=file_sha256(self.bundle / MODEL_ARTIFACT_NAME),
            model_metadata_sha256=file_sha256(self.bundle / MODEL_METADATA_ARTIFACT_NAME),
            score_artifact_sha256=file_sha256(self.bundle / SCORE_ARTIFACT_NAME),
            runtime_versions=runtime_versions(),
        )
        write_manifest(self.bundle / MANIFEST_ARTIFACT_NAME, payload)
        self.approved_hash = file_sha256(self.bundle / MANIFEST_ARTIFACT_NAME)

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary_root, ignore_errors=True)

    def test_wrong_or_tampered_manifest_never_calls_joblib_load(self) -> None:
        with patch("anomaly.artifact.joblib.load") as load:
            with self.assertRaises(AnomalyArtifactError):
                load_trusted_model(self.bundle, approved_manifest_sha256="0" * 64)
            load.assert_not_called()

            manifest_path = self.bundle / MANIFEST_ARTIFACT_NAME
            manifest_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(AnomalyArtifactError):
                load_trusted_model(self.bundle, approved_manifest_sha256=self.approved_hash)
            load.assert_not_called()

    def test_tampered_model_or_runtime_mismatch_never_calls_joblib_load(self) -> None:
        with patch("anomaly.artifact.joblib.load") as load:
            (self.bundle / MODEL_ARTIFACT_NAME).write_bytes(b"tampered-model")
            with self.assertRaises(AnomalyArtifactError):
                load_trusted_model(self.bundle, approved_manifest_sha256=self.approved_hash)
            load.assert_not_called()

    def test_incompatible_runtime_never_calls_joblib_load(self) -> None:
        incompatible_versions = runtime_versions()
        incompatible_versions["numpy"] = "0.0.0"
        with patch("anomaly.artifact.collect_runtime_versions", return_value=incompatible_versions), patch(
            "anomaly.artifact.joblib.load"
        ) as load:
            with self.assertRaises(AnomalyArtifactError):
                load_trusted_model(self.bundle, approved_manifest_sha256=self.approved_hash)
            load.assert_not_called()

    def test_manifest_payload_is_canonical_and_repeatable(self) -> None:
        first = build_manifest_payload(
            feature_sha256="1" * 64,
            feature_count=36,
            reference_count=4,
            holdout_count=1,
            feature_contract_sha256="2" * 64,
            model_artifact_sha256=file_sha256(self.bundle / MODEL_ARTIFACT_NAME),
            model_metadata_sha256=file_sha256(self.bundle / MODEL_METADATA_ARTIFACT_NAME),
            score_artifact_sha256=file_sha256(self.bundle / SCORE_ARTIFACT_NAME),
            runtime_versions=runtime_versions(),
        )
        second = build_manifest_payload(
            feature_sha256="1" * 64,
            feature_count=36,
            reference_count=4,
            holdout_count=1,
            feature_contract_sha256="2" * 64,
            model_artifact_sha256=file_sha256(self.bundle / MODEL_ARTIFACT_NAME),
            model_metadata_sha256=file_sha256(self.bundle / MODEL_METADATA_ARTIFACT_NAME),
            score_artifact_sha256=file_sha256(self.bundle / SCORE_ARTIFACT_NAME),
            runtime_versions=runtime_versions(),
        )
        self.assertEqual(canonical_json(first), canonical_json(second))

    def test_matching_manifest_and_model_permit_controlled_load(self) -> None:
        sentinel = object()
        with patch("anomaly.artifact.collect_runtime_versions", return_value=runtime_versions()), patch(
            "anomaly.artifact.joblib.load", return_value=sentinel
        ) as load:
            self.assertIs(
                load_trusted_model(self.bundle, approved_manifest_sha256=self.approved_hash),
                sentinel,
            )
            load.assert_called_once_with(self.bundle / MODEL_ARTIFACT_NAME)


class PublicationAndValidatorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_root = Path(
            tempfile.mkdtemp(prefix=".stage_1_8_test.", dir=PROJECT_ROOT / "data" / "processed")
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary_root, ignore_errors=True)

    def test_audit_failure_after_completed_temporary_artifacts_prevents_publication(self) -> None:
        features = self.temporary_root / "features"
        expected_hash = write_feature_bundle(
            features,
            tuple(
                feature_row(index, REFERENCE_PARTITION, model_score=-float(index) / 10000.0)
                for index in range(1, 4097)
            )
            + (feature_row(4097, HOLDOUT_PARTITION, model_score=-0.8),),
        )
        destination = self.temporary_root / "scores"

        with patch(
            "score_anomalies.audit_anomaly_scores.audit_anomaly_score_bundle",
            side_effect=AnomalyScoreAuditError("synthetic audit rejection"),
        ), patch("score_anomalies.collect_runtime_versions", return_value=runtime_versions()), patch(
            "score_anomalies.fit_reference_model", return_value=CapturingModel()
        ), patch(
            "score_anomalies.secondary_seed_sensitivity",
            return_value={"primary_random_state": 1729, "comparisons": []},
        ):
            with self.assertRaises(AnomalyScoreBuildError):
                score_anomaly_bundle(
                    features,
                    destination,
                    expected_feature_sha256=expected_hash,
                )

        self.assertFalse(destination.exists())
        self.assertEqual(list(self.temporary_root.glob(".scores.*.tmp")), [])

    def test_completed_synthetic_bundle_reconciles_and_replays_through_trusted_manifest(self) -> None:
        features = self.temporary_root / "features"
        expected_hash = write_feature_bundle(
            features,
            tuple(
                feature_row(index, REFERENCE_PARTITION, model_score=-float(index) / 10000.0)
                for index in range(1, 4097)
            )
            + (feature_row(4097, HOLDOUT_PARTITION, model_score=-0.8),),
        )
        destination = self.temporary_root / "scores"
        sensitivity = {
            "primary_random_state": 1729,
            "comparisons": [
                {"random_state": 2718, "top_50_jaccard": 1.0, "top_100_jaccard": 1.0},
                {"random_state": 3141, "top_50_jaccard": 1.0, "top_100_jaccard": 1.0},
            ],
        }
        with patch("score_anomalies.collect_runtime_versions", return_value=runtime_versions()), patch(
            "score_anomalies.fit_reference_model", return_value=CapturingModel()
        ), patch("score_anomalies.secondary_seed_sensitivity", return_value=sensitivity), patch(
            "score_anomalies.os.name", "nt"
        ):
            summary = score_anomaly_bundle(
                features,
                destination,
                expected_feature_sha256=expected_hash,
            )

        manifest_hash = file_sha256(destination / MANIFEST_ARTIFACT_NAME)
        audit = audit_anomaly_score_bundle(
            features,
            destination,
            expected_feature_sha256=expected_hash,
            approved_manifest_sha256=manifest_hash,
        )
        self.assertEqual(summary.row_count, 4097)
        self.assertEqual(audit.row_count, 4097)
        self.assertEqual(audit.reference_row_count, 4096)
        self.assertEqual(audit.holdout_row_count, 1)
        metadata = json.loads(
            (destination / MODEL_METADATA_ARTIFACT_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["dependency_versions"], runtime_versions())

    def test_validator_requires_normalized_input_and_audits_stage_1_7_before_build(self) -> None:
        validator = (PROJECT_ROOT / "scripts" / "validate_stage_1_8.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[string]$NormalizedInput", validator)
        self.assertIn("src\\audit_ai_features.py", validator)
        self.assertIn("src\\score_anomalies.py", validator)
        self.assertLess(
            validator.index("src\\audit_ai_features.py"),
            validator.index("src\\score_anomalies.py"),
        )

    def _run_validator_with_test_arguments(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("requires PowerShell to exercise the validator contract")
        validator = PROJECT_ROOT / "scripts" / "validate_stage_1_8.ps1"
        return subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(validator),
                "-NormalizedInput",
                "unused-normalized-input",
                "-FeaturesDir",
                "unused-features-dir",
                "-ScoresDir",
                "unused-scores-dir",
                *arguments,
            ],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_validator_requires_and_rejects_invalid_external_manifest_hash_before_paths(self) -> None:
        missing = self._run_validator_with_test_arguments()
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("ApprovedManifestSha256", missing.stdout + missing.stderr)

        malformed = self._run_validator_with_test_arguments(
            "-ApprovedManifestSha256", "not-a-sha256"
        )
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn(
            "ApprovedManifestSha256 must contain exactly 64 hexadecimal characters",
            malformed.stdout + malformed.stderr,
        )

    def test_validator_uses_one_external_manifest_hash_for_published_and_rebuilt_bundles(self) -> None:
        validator = (PROJECT_ROOT / "scripts" / "validate_stage_1_8.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[string]$ApprovedManifestSha256", validator)
        self.assertIn("^[0-9A-Fa-f]{64}$", validator)
        published_audit = (
            'Invoke-Stage18Native $python ".\\src\\audit_anomaly_scores.py" '
            '"--features-dir" $features "--scores-dir" $scores '
            '"--approved-manifest-sha256" $ApprovedManifestSha256'
        )
        controlled_rebuild = (
            'Invoke-Stage18Native $python ".\\src\\score_anomalies.py" '
            '"--features-dir" $features "--output-dir" $rerun'
        )
        rebuilt_audit = (
            'Invoke-Stage18Native $python ".\\src\\audit_anomaly_scores.py" '
            '"--features-dir" $features "--scores-dir" $rerun '
            '"--approved-manifest-sha256" $ApprovedManifestSha256'
        )
        self.assertIn(published_audit, validator)
        self.assertIn(rebuilt_audit, validator)
        self.assertLess(validator.index(published_audit), validator.index(controlled_rebuild))
        self.assertNotIn("$approvedManifestHash", validator)
        self.assertNotRegex(validator, r"\$manifest\s*=")
        rerun_comparison = "$rerunManifestHash -cne $ApprovedManifestSha256"
        self.assertIn(rerun_comparison, validator)
        mismatch_failure = (
            'throw "Controlled rebuild manifest SHA-256 does not match '
            'the external approved identity"'
        )
        self.assertIn(mismatch_failure, validator)
        self.assertLess(
            validator.index(rerun_comparison),
            validator.index(mismatch_failure),
        )
        self.assertLess(
            validator.index(mismatch_failure),
            validator.index(rebuilt_audit),
        )


if __name__ == "__main__":
    unittest.main()
