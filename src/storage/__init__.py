"""Stage 1.5 storage-contract primitives.

This package defines immutable storage models, SQLite schema creation helpers,
strict finding/summary input validation, and transactional single-run import.
It does not query a database or perform storage audits.
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
    calculate_artifact_identity,
    validate_detection_artifacts,
)
from .importer import StorageImportError, import_detection_run
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
    "StorageImportError",
    "StorageSchemaError",
    "ValidatedDetectionArtifacts",
    "calculate_artifact_identity",
    "configure_connection",
    "create_storage_schema",
    "import_detection_run",
    "validate_detection_artifacts",
]
