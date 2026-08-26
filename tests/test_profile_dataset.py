"""Tests for the read-only CSV dataset profiler."""

from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from profile_dataset import DatasetProfileError, profile_csv  # noqa: E402


class ProfileDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp_path = Path(self.temporary_directory.name)

    def write_csv(self, name: str, rows: list[list[str]]) -> Path:
        path = self.temp_path / name
        with path.open("w", encoding="utf-8", newline="") as csv_file:
            csv.writer(csv_file).writerows(rows)
        return path

    def test_profiles_valid_csv(self) -> None:
        path = self.write_csv(
            "valid.csv",
            [
                ["event_type", "event_action", "dst_port", "loguid"],
                ["traffic", "accept", "443", "LOG_1"],
                ["traffic", "deny", "22", "LOG_2"],
            ],
        )
        original_bytes = path.read_bytes()

        profile = profile_csv(
            path,
            categorical_fields=("event_type", "event_action"),
            numeric_fields=("dst_port",),
            identifier_fields=("loguid",),
        )

        self.assertEqual(profile["row_count"], 2)
        self.assertEqual(profile["column_count"], 4)
        self.assertEqual(
            profile["column_names"],
            ["event_type", "event_action", "dst_port", "loguid"],
        )
        self.assertEqual(profile["numeric_fields"]["dst_port"]["min"], 22)
        self.assertEqual(profile["numeric_fields"]["dst_port"]["max"], 443)
        self.assertEqual(
            profile["categorical_frequencies"]["event_type"]["unique_count"],
            1,
        )
        self.assertEqual(path.read_bytes(), original_bytes)

    def test_rejects_empty_csv(self) -> None:
        path = self.temp_path / "empty.csv"
        path.write_bytes(b"")

        with self.assertRaisesRegex(DatasetProfileError, "empty"):
            profile_csv(path)

    def test_rejects_unusable_header(self) -> None:
        path = self.write_csv(
            "bad_header.csv",
            [["", "net_sessionid"], ["traffic", "SESSION_1"]],
        )

        with self.assertRaisesRegex(DatasetProfileError, "blank column"):
            profile_csv(path)

    def test_counts_optional_missing_values_without_failing(self) -> None:
        path = self.write_csv(
            "optional_missing.csv",
            [
                ["event_type", "threat_name", "loguid"],
                ["traffic", "", "LOG_1"],
                ["utm", "icmp_sweep", "LOG_2"],
            ],
        )

        profile = profile_csv(
            path,
            categorical_fields=("event_type", "threat_name"),
            numeric_fields=(),
            identifier_fields=("loguid",),
        )

        self.assertEqual(profile["missing_values"]["threat_name"]["count"], 1)
        self.assertEqual(
            profile["missing_values"]["threat_name"]["percentage"], 50.0
        )

    def test_accepts_sanitized_identifiers_as_opaque_values(self) -> None:
        path = self.write_csv(
            "identifiers.csv",
            [
                ["src_ip", "dst_ip", "host_ip", "loguid"],
                ["SRCIP_abcd", "DSTIP_efgh", "HOSTIP_ijkl", "LOG_mnop"],
            ],
        )

        profile = profile_csv(
            path,
            categorical_fields=(),
            numeric_fields=(),
            identifier_fields=("src_ip", "dst_ip", "host_ip", "loguid"),
        )

        for field in ("src_ip", "dst_ip", "host_ip", "loguid"):
            self.assertEqual(
                profile["identifier_cardinality"][field]["unique_count"], 1
            )

    def test_reports_invalid_numeric_values(self) -> None:
        path = self.write_csv(
            "mixed_numeric.csv",
            [
                ["dst_port", "loguid"],
                ["443", "LOG_1"],
                ["not-a-port", "LOG_2"],
                ["", "LOG_3"],
            ],
        )

        profile = profile_csv(
            path,
            categorical_fields=(),
            numeric_fields=("dst_port",),
            identifier_fields=("loguid",),
        )

        numeric = profile["numeric_fields"]["dst_port"]
        self.assertEqual(numeric["non_missing_count"], 2)
        self.assertEqual(numeric["valid_numeric_count"], 1)
        self.assertEqual(numeric["conversion_failure_count"], 1)
        self.assertEqual(numeric["min"], 443)
        self.assertEqual(numeric["max"], 443)

    def test_counts_exact_duplicate_rows(self) -> None:
        path = self.write_csv(
            "duplicates.csv",
            [
                ["event_action", "net_sessionid", "loguid"],
                ["start", "100", "LOG_1"],
                ["start", "100", "LOG_1"],
            ],
        )

        profile = profile_csv(
            path,
            categorical_fields=("event_action",),
            numeric_fields=(),
            identifier_fields=("net_sessionid", "loguid"),
        )

        self.assertEqual(profile["exact_duplicate_row_count"], 1)

    def test_repeated_session_ids_are_not_exact_duplicates(self) -> None:
        path = self.write_csv(
            "repeated_session.csv",
            [
                ["event_action", "net_sessionid", "loguid"],
                ["start", "100", "LOG_1"],
                ["close", "100", "LOG_2"],
            ],
        )

        profile = profile_csv(
            path,
            categorical_fields=("event_action",),
            numeric_fields=(),
            identifier_fields=("net_sessionid", "loguid"),
        )

        self.assertEqual(profile["exact_duplicate_row_count"], 0)
        session_cardinality = profile["identifier_cardinality"]["net_sessionid"]
        self.assertEqual(session_cardinality["non_missing_count"], 2)
        self.assertEqual(session_cardinality["unique_count"], 1)
        self.assertEqual(session_cardinality["repeated_occurrence_count"], 1)


if __name__ == "__main__":
    unittest.main()
