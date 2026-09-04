"""Create one new SQLite detection-finding store from validated artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from storage.importer import StorageImportError, import_detection_run
from storage.input import StorageInputValidationError


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create one new SQLite store from validated detection findings."
    )
    parser.add_argument("--findings", required=True, help="Stage 1.4 finding JSONL path")
    parser.add_argument("--summary", required=True, help="Stage 1.4 summary JSON path")
    parser.add_argument("--database", required=True, help="New SQLite path beneath data/processed")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Import one detection run and print only its bounded deterministic summary."""

    arguments = _argument_parser().parse_args(argv)
    try:
        result = import_detection_run(
            arguments.findings,
            arguments.summary,
            arguments.database,
        )
    except (StorageImportError, StorageInputValidationError, OSError) as error:
        print(f"storage import failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
