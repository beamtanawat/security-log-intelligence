"""Stage 1.6 read-only API application boundary.

Importing this package creates no files, opens no database, and starts no
network listener.  A caller must construct explicit settings and pass them to
the application factory.
"""

from .app import create_app
from .settings import ApiSettings, ApiSettingsError

__all__ = ["ApiSettings", "ApiSettingsError", "create_app"]
