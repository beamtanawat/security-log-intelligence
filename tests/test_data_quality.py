"""Synthetic tests for the Stage 1.2A field-inventory foundation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from data_quality import (  # noqa: E402
    KNOWN_FORTIGATE_COLUMNS,
    build_field_inventory,
    validate_inventory_complete,
)


class FieldInventoryTests(unittest.TestCase):
    def test_known_header_has_one_entry_per_field(self) -> None:
        inventory = build_field_inventory(KNOWN_FORTIGATE_COLUMNS)

        self.assertEqual(len(inventory), 58)
        self.assertEqual([entry["field"] for entry in inventory], list(KNOWN_FORTIGATE_COLUMNS))
        validate_inventory_complete(KNOWN_FORTIGATE_COLUMNS, inventory)

    def test_known_optional_fields_keep_their_documented_nullable_notes(self) -> None:
        inventory = build_field_inventory(("app_name", "threat_name", "src_natip"))
        by_field = {entry["field"]: entry for entry in inventory}

        self.assertIn("129 non-missing", by_field["app_name"]["nullable_behavior"])
        self.assertIn("25 non-missing", by_field["threat_name"]["nullable_behavior"])
        self.assertIn("98,350 missing", by_field["src_natip"]["nullable_behavior"])

    def test_unknown_column_is_preserved_for_verification(self) -> None:
        inventory = build_field_inventory(("event_type", "future_source_field"))

        unknown = inventory[1]
        self.assertEqual(unknown["field"], "future_source_field")
        self.assertEqual(unknown["group"], "Unknown")
        self.assertEqual(unknown["confidence"], "NEEDS VERIFICATION")
        self.assertIn("do not discard", unknown["nullable_behavior"])

    def test_sanitized_identifier_fields_are_documented_as_opaque(self) -> None:
        inventory = build_field_inventory(("src_ip", "dst_ip", "host_ip", "src_mac"))

        for entry in inventory:
            self.assertIn("Opaque sanitized identifier", entry["observed_representation"])
            self.assertIn("not validated", entry["observed_representation"])

    def test_completeness_validation_rejects_a_missing_entry(self) -> None:
        columns = ("event_type", "event_action")
        inventory = build_field_inventory(columns)

        with self.assertRaisesRegex(ValueError, "do not match"):
            validate_inventory_complete(columns, inventory[:1])


if __name__ == "__main__":
    unittest.main()
