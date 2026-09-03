"""Stage 1.5 storage-contract primitives.

This package defines immutable storage models, SQLite schema creation helpers,
and strict finding/summary input validation. It does not import data, create a
final database, query a database, or perform storage audits.
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
from .input import (
    ApprovedArtifactIdentity,
    StorageInputValidationError,
    ValidatedDetectionArtifacts,
    validate_detection_artifacts,
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
    "ApprovedArtifactIdentity",
    "REQUIRED_INDEX_NAMES",
    "STORAGE_METADATA_VALUES",
    "STORAGE_SCHEMA_VERSION",
    "STORAGE_TABLE_NAMES",
    "STORAGE_USER_VERSION",
    "FindingQuery",
    "StorageAuditResult",
    "StorageContractError",
    "StorageImportSummary",
    "StorageInputValidationError",
    "StorageSchemaError",
    "ValidatedDetectionArtifacts",
    "configure_connection",
    "create_storage_schema",
    "validate_detection_artifacts",
]
