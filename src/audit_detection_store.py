"""Read-only bounded audit of one Stage 1.5 detection store."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from storage.audit import StorageAuditError, audit_detection_store


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit one Stage 1.5 detection store.")
    parser.add_argument("--database", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = audit_detection_store(arguments.database)
    except StorageAuditError as error:
        print(f"storage audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
