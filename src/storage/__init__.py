"""Stage 1.5 storage-contract primitives.

This package currently defines only immutable storage models and SQLite schema
creation helpers. It does not read findings, import data, query a database, or
perform storage audits.
"""

from .models import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    STORAGE_SCHEMA_VERSION,
    STORAGE_USER_VERSION,
    FindingQuery,
    StorageAuditResult,
    StorageContractError,
    StorageImportSummary,
)
from .schema import (
    REQUIRED_INDEX_NAMES,
    STORAGE_METADATA_VALUES,
    STORAGE_TABLE_NAMES,
    StorageSchemaError,
    configure_connection,
    create_storage_schema,
)

__all__ = [
    "DEFAULT_QUERY_LIMIT",
    "MAX_QUERY_LIMIT",
    "REQUIRED_INDEX_NAMES",
    "STORAGE_METADATA_VALUES",
    "STORAGE_SCHEMA_VERSION",
    "STORAGE_TABLE_NAMES",
    "STORAGE_USER_VERSION",
    "FindingQuery",
    "StorageAuditResult",
    "StorageContractError",
    "StorageImportSummary",
    "StorageSchemaError",
    "configure_connection",
    "create_storage_schema",
]
