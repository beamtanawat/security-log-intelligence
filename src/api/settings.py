"""Typed, side-effect-free settings for the local read-only API."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


_RUN_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


class ApiSettingsError(ValueError):
    """Raised when explicit API settings fail their local contract."""


@dataclass(frozen=True)
class ApiSettings:
    """Operator-supplied paths for one approved, existing detection store.

    Paths are deliberately checked for existence and safe location during the
    application lifespan, not when this value is constructed.  This keeps
    settings validation free of filesystem and network side effects.
    """

    database_path: Path
    findings_path: Path
    summary_path: Path
    expected_run_id: str
    port: int = 8000

    def __post_init__(self) -> None:
        for field_name in ("database_path", "findings_path", "summary_path"):
            if not isinstance(getattr(self, field_name), Path):
                raise ApiSettingsError(f"{field_name} must be a pathlib.Path")
        if (
            not isinstance(self.expected_run_id, str)
            or _RUN_ID_PATTERN.fullmatch(self.expected_run_id) is None
        ):
            raise ApiSettingsError(
                "expected_run_id must be a lowercase SHA-256 hexadecimal digest"
            )
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ApiSettingsError("port must be a non-boolean integer")
        if not 1 <= self.port <= 65_535:
            raise ApiSettingsError("port must be between 1 and 65535")
