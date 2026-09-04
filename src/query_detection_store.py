"""Bounded read-only command line access to one Stage 1.5 detection store."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence

from storage.models import EvidenceQuery, FindingQuery, StorageContractError
from storage.query import (
    StorageQueryError,
    get_detection_run,
    get_finding,
    get_finding_evidence,
    list_findings,
)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect one detection store using bounded read-only operations."
    )
    parser.add_argument("--database", required=True, help="Stage 1.5 SQLite database path")
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser("run", help="Get one detection run")
    run_parser.add_argument("--run-id", required=True)

    finding_parser = commands.add_parser("finding", help="Get one finding by ID")
    finding_parser.add_argument("--finding-id", required=True)

    findings_parser = commands.add_parser("findings", help="List bounded findings")
    for option in (
        "run_id",
        "finding_id",
        "rule_id",
        "rule_version",
        "severity",
        "reason_code",
        "source_type",
        "source_record_number",
        "evidence_path",
    ):
        findings_parser.add_argument(f"--{option.replace('_', '-')}")
    findings_parser.add_argument("--limit", type=int, default=50)

    evidence_parser = commands.add_parser("evidence", help="Get bounded finding evidence")
    evidence_parser.add_argument("--run-id", required=True)
    evidence_parser.add_argument("--finding-id", required=True)
    evidence_parser.add_argument("--limit", type=int, default=50)
    return parser


def _write_jsonl(values: Iterable[Mapping[str, object]]) -> None:
    for value in values:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    """Run one narrow read-only command and write compact bounded JSON Lines."""

    arguments = _argument_parser().parse_args(argv)
    try:
        if arguments.command == "run":
            result = get_detection_run(arguments.database, arguments.run_id)
            if result is None:
                raise StorageQueryError("RUN_NOT_FOUND", "Requested detection run was not found.")
            _write_jsonl((result.to_dict(),))
        elif arguments.command == "finding":
            result = get_finding(arguments.database, arguments.finding_id)
            if result is None:
                raise StorageQueryError("FINDING_NOT_FOUND", "Requested finding was not found.")
            _write_jsonl((result.to_dict(),))
        elif arguments.command == "findings":
            query = FindingQuery(
                run_id=arguments.run_id,
                finding_id=arguments.finding_id,
                rule_id=arguments.rule_id,
                rule_version=arguments.rule_version,
                severity=arguments.severity,
                reason_code=arguments.reason_code,
                source_type=arguments.source_type,
                source_record_number=(
                    int(arguments.source_record_number)
                    if arguments.source_record_number is not None
                    else None
                ),
                evidence_path=arguments.evidence_path,
                limit=arguments.limit,
            )
            _write_jsonl(result.to_dict() for result in list_findings(arguments.database, query))
        else:
            query = EvidenceQuery(
                run_id=arguments.run_id,
                finding_id=arguments.finding_id,
                limit=arguments.limit,
            )
            _write_jsonl(
                result.to_dict() for result in get_finding_evidence(arguments.database, query)
            )
    except (StorageContractError, StorageQueryError, OSError, ValueError) as error:
        print(f"storage query failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
