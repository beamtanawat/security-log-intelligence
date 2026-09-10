"""Fixed-loopback entry point for the local read-only findings API."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

import uvicorn

from api import ApiSettings, ApiSettingsError, create_app


LOOPBACK_HOST = "127.0.0.1"


def _argument_parser() -> argparse.ArgumentParser:
    """Build the intentionally small, explicit local-launch interface."""

    parser = argparse.ArgumentParser(
        description="Start the local read-only Security Log Intelligence API."
    )
    parser.add_argument("--database", required=True, type=Path, metavar="PATH")
    parser.add_argument("--findings", required=True, type=Path, metavar="PATH")
    parser.add_argument("--summary", required=True, type=Path, metavar="PATH")
    parser.add_argument("--expected-run-id", required=True, metavar="SHA256")
    parser.add_argument("--port", type=int, metavar="PORT")
    return parser


def parse_settings(argv: Sequence[str] | None = None) -> ApiSettings:
    """Validate explicit launcher arguments before application or socket startup."""

    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    settings_values: dict[str, object] = {
        "database_path": arguments.database,
        "findings_path": arguments.findings,
        "summary_path": arguments.summary,
        "expected_run_id": arguments.expected_run_id,
    }
    if arguments.port is not None:
        settings_values["port"] = arguments.port
    try:
        return ApiSettings(**settings_values)  # type: ignore[arg-type]
    except ApiSettingsError as error:
        parser.error(str(error))
        raise AssertionError("argparse.error must exit") from error


def run_server(settings: ApiSettings) -> None:
    """Run one fixed-local Uvicorn worker for already-validated settings."""

    application = create_app(settings)
    uvicorn.run(
        application,
        host=LOOPBACK_HOST,
        port=settings.port,
        reload=False,
        workers=1,
        proxy_headers=False,
        access_log=False,
        log_level="critical",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the application only after its explicit settings are valid."""

    settings = parse_settings(argv)
    try:
        run_server(settings)
    except SystemExit as error:
        exit_code = error.code if isinstance(error.code, int) else 1
        if exit_code != 0:
            print("API_STARTUP_FAILED", file=sys.stderr)
        return exit_code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
