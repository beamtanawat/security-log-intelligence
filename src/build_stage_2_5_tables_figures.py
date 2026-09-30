"""Build and validate the Stage 2.5B tables and figures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reporting.tables_figures import build_package, validate_package


DEFAULT_REGISTRY = Path("docs/results/stage_2_5/final_result_registry.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    result = validate_package(args.output_dir) if args.validate_only else build_package(args.registry, args.output_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
