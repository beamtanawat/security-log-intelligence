"""Build and validate the Stage 2.5A frozen-result package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from reporting.final_results import _collect_bundle, validate_package


DEFAULT_HANDOFF = Path(
    "data/unsw_nb15/processed/stage_2_4/v1/manifests/stage_2_5_handoff.json"
)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def build_package(handoff: Path, output_dir: Path) -> dict[str, Any]:
    """Create the three deterministic Stage 2.5A package artifacts."""
    handoff = Path(handoff)
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    registry, inventory, claims = _collect_bundle(handoff)
    _write_json(output_dir / "source_inventory.json", inventory)
    _write_json(output_dir / "claims_matrix.json", claims)
    _write_json(output_dir / "final_result_registry.json", registry)
    return validate_package(output_dir)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, default=DEFAULT_HANDOFF)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = (
        validate_package(args.output_dir)
        if args.validate_only
        else build_package(args.handoff, args.output_dir)
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
