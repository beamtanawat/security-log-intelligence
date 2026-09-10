# Read-Only Detection Findings API Contract

**Status:** Stage 1.6 contract updated for Checkpoint 1.6E; local runtime
validation remains a checkpoint gate.

This document records the verified Stage 1.5 storage boundary and the
implemented Stage 1.6 contract. It specifies a local read-only API and its
fixed-loopback launcher; it does not change a stored database.

## Scope and non-security-decision boundary

The API may expose only one independently audited Stage 1.5 detection store.
It is a local, read-only lookup surface for stored deterministic findings.

`RULE MATCH != CONFIRMED ATTACK` remains mandatory in all API responses and
documentation. A finding is a record that a configured deterministic rule
matched. It is not a confirmed attack, compromise, malicious/benign label,
incident, confidence score, risk score, or response recommendation. The API
must not add any of those conclusions.

The response contract must not introduce `is_attack`, `is_malicious`,
`confirmed_incident`, `compromised`, `attack_probability`, `confidence_score`,
or `risk_score` fields.

The future API has no access to the raw FortiGate CSV or normalized JSONL. It
must not re-run normalization, detection, import, or an audit while serving a
request.

## Stage 1.5 start gate and approved artifact identity

Stage 1.5F real-data validation is the upstream start-gate evidence. Its
approved input artifacts are the Stage 1.4 findings JSONL and Stage 1.4F
summary envelope only. The following identity values are fixed for the
validated run:

| Item | Verified value |
| --- | --- |
| `findings_sha256` | `5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc` |
| `run_id` | `5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc` |
| `summary_sha256` | `d3585bf577cb1b16aca2a8afb65d18959941e28fc2b9cd6c396c35cf03dd16fe` |
| reconstructed findings hash | `5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc` |
| logical export hash | `9f463dd96261d54673d88abd4f0213f5860381334fe07d19d4ec66a8eccd52e0` |
| findings | 43 |
| unique matched source records | 25 |
| rules | 2 (`18` `ANOMALOUS_DST_PORT`; 25 `THREAT_SOURCE_OBSERVATION`) |

All 43 validated findings are informational observations. The table does not
declare that any event is an attack.

`summary_sha256` is the SHA-256 of the complete Stage 1.4F summary envelope,
not the nested `primary_run` alone. `run_id` must equal `findings_sha256`.

## Actual Stage 1.5 public interfaces

### Public import surface

With `src` on the application import path, the public package is `storage`.
`src/storage/__init__.py` re-exports the supported types and functions below.
The later API must import from `storage`, not `src.storage`, and must not
import private helpers or construct SQL.

```python
from storage import (
    ApprovedArtifactIdentity,
    EvidenceQuery,
    FindingQuery,
    StorageAuditResult,
    StoredDetectionRun,
    StoredFinding,
    StoredFindingEvidence,
    ValidatedDetectionArtifacts,
    audit_detection_store,
    calculate_artifact_identity,
    get_detection_run,
    get_finding,
    get_finding_evidence,
    list_findings,
    validate_detection_artifacts,
)
```

The implementation modules are deliberately separate from the public import
surface:

| Implementation module | Existing responsibility |
| --- | --- |
| `storage.models` | immutable public storage types, query values, limits, and schema-version constants |
| `storage.query` | bounded read-only query implementation |
| `storage.audit` | independent database-only audit implementation |
| `storage.input` | strict Stage 1.4 finding/summary artifact identity and validation |

### Public call signatures

```python
get_detection_run(database_path: str | Path, run_id: str) -> StoredDetectionRun | None
get_finding(database_path: str | Path, finding_id: str) -> StoredFinding | None
list_findings(database_path: str | Path, query: FindingQuery) -> tuple[StoredFinding, ...]
get_finding_evidence(database_path: str | Path, query: EvidenceQuery) -> tuple[StoredFindingEvidence, ...]
audit_detection_store(database_path: str | Path) -> StorageAuditResult
calculate_artifact_identity(findings_path: str | Path, summary_path: str | Path) -> ApprovedArtifactIdentity
validate_detection_artifacts(
    findings_path: str | Path,
    summary_path: str | Path,
    expected_identity: ApprovedArtifactIdentity,
    *,
    on_finding: Callable[[DetectionFinding], None] | None = None,
) -> ValidatedDetectionArtifacts
```

`FindingQuery` has the allowlisted fields `run_id`, `finding_id`, `rule_id`,
`rule_version`, `severity`, `reason_code`, `source_type`,
`source_record_number`, `evidence_path`, and `limit`. The existing storage
contract accepts a limit from 1 through 500, with a default of 50. Queries
are ordered exactly by `source_record_number`, `rule_id`, `rule_version`, and
`finding_id`.

`get_finding` is keyed only by `finding_id`, not by `run_id`. A future route
must therefore first require the configured audited `run_id`, then verify
that any returned `StoredFinding.run_id` equals the route's `run_id` before
forming a response.

`StoredFinding.canonical_finding_json` is the authoritative complete finding
payload. The relational fields and `StoredFindingEvidence` values are audited
projections that must reconcile to that canonical text; they are not a
replacement response schema. A future API may decode the already reconciled
canonical JSON to form the public finding object, but must not silently
rebuild it from projections.

### Existing connection ownership and result lifecycle

Stage 1.5 already owns every SQLite connection inside the public operation that
uses it. `get_detection_run`, `list_findings`, and `get_finding_evidence` each
open an existing database through a SQLite URI with `mode=ro`, configure
`query_only` and foreign-key enforcement, consume the required rows, and close
the connection before returning. `get_finding` delegates to `list_findings`,
so it receives the same lifecycle rather than retaining its own connection.

`list_findings` fully fetches its explicitly bounded result (1–500 rows) and
reconciles the canonical finding JSON and evidence projections before its
connection closes. The public query calls return materialized immutable values,
not a lazy database iterator. The independent `audit_detection_store` call owns
and closes a separate read-only audit connection in the same way.

The future API must preserve this behavior: no global SQLite connection, no
connection or lazy iterator retained across threads, and no
`check_same_thread=False` workaround. A synchronous storage operation must open,
consume, reconcile, and close on its owning worker thread before an HTTP
response is published.

### `StorageAuditResult` readiness metadata

`StorageAuditResult` is bounded internal audit metadata, not an HTTP response
object. Its complete current public field set is:

| Field | Meaning in the existing storage contract |
| --- | --- |
| `run_id` | single audited run identity; must equal `findings_sha256` |
| `findings_sha256` | SHA-256 of the approved findings JSONL |
| `summary_sha256` | SHA-256 of the complete Stage 1.4F summary envelope |
| `logical_export_sha256` | deterministic logical export hash from the audit |
| `reconstructed_findings_sha256` | canonical findings reconstructed from storage; must equal `findings_sha256` |
| `finding_count` | audited stored finding count |
| `evidence_count` | audited stored evidence count |
| `rule_count` | audited active-rule snapshot count |
| `storage_schema_version` | storage schema contract version; currently `1.0` |

The audit verifies the database schema, metadata, integrity, foreign-key
relationships (including the composite finding-to-rule reference), canonical
finding/evidence reconstruction, and its deterministic hashes. It accepts only
`database_path`; it does not read the Stage 1.4 finding or summary artifacts.

## Section 4 forecast reconciliation

The Stage 1.6 plan's Section 4 forecast was reconciled against the current
Stage 1.5 implementation before this contract was written.

| Forecast item | Current result | Contract decision |
| --- | --- | --- |
| Stage 1.4F summary envelope | Supported; `primary_run` is parsed with the strict `DetectionRunSummary` contract. | Confirmed |
| Summary identity | Whole-envelope SHA-256 is stored and audited. | Confirmed |
| Findings identity | Canonical findings JSONL hash is the `run_id`. | Confirmed |
| Raw CSV / normalized JSONL | Storage validation rejects them; normal query and audit functions use the SQLite store. | Confirmed no rescan |
| Exact canonical finding serialization | `canonical_finding_json` is preserved and independently reconciled. | Confirmed |
| Query surface | The actual public names are `get_detection_run`, `get_finding`, `list_findings`, and `get_finding_evidence`; the forecast names are not public interfaces. | Updated to actual names |
| Audit surface | `audit_detection_store` accepts the database path only. Artifact reconciliation is available separately through `validate_detection_artifacts`. | Updated to two public calls |
| Rule-reference integrity | Schema has `(run_id, rule_id, rule_version)` foreign key to `run_rules`; audit verifies it. | Confirmed |
| Bounded results | Existing `FindingQuery` limit is 1–500; no cursor or pagination exists. | Confirmed |
| Read-only startup | Import creates a new database, while query/audit connections use the existing database read-only. | Confirmed |

No Stage 1.5 contract correction is required by this reconciliation.

## Planned startup verification bridge

This is the required design for a later implementation, not current runtime
behavior. Startup must receive explicitly configured paths for the existing
SQLite database, Stage 1.4 findings JSONL, and Stage 1.4F summary envelope.
The settings must validate `expected_run_id` as exactly 64 lowercase
hexadecimal characters and `port` as a non-boolean integer from 1 through
65,535 before filesystem or network access. There is no configurable
non-loopback host.

Each path must resolve to an existing regular file under the repository's
processed-data directory. Startup must reject directories, input-path aliasing,
SQLite URI strings, missing files, traversal, and junction/symlink escapes. It
must never create any of these files when a setting is invalid or missing.

It must, before listening:

1. record a non-public local identity for the resolved existing database file;
2. call the database-only `audit_detection_store(database_path)`;
3. create `ApprovedArtifactIdentity` from that audit's `findings_sha256` and
   `summary_sha256`;
4. call the separate strict
   `validate_detection_artifacts(findings_path, summary_path, identity)`;
5. call `get_detection_run(database_path, audit_result.run_id)` and require a
   stored run;
6. require equality of configured run ID, audit run ID, artifact-validation run
   ID, hashes, and applicable finding/evidence/rule counts; require the stored
   run's identity and finding metadata to agree with the audit and approved
   contracts; and
7. retain only the verified bounded readiness snapshot below as immutable
   process configuration.

This uses only the approved Stage 1.4 findings and summary inputs plus the
existing database. It never reads raw CSV or normalized JSONL, and it never
imports, rewrites, migrates, repairs, or creates a database. If any check
fails, startup must fail closed and serve no requests.

The strict artifact-validation call and the independent database-only audit are
different public operations. They must remain separate in future API code;
there is no single Stage 1.5 function that performs both. The application must
not compensate by importing private storage helpers, using arbitrary SQL, or
performing an import, detection run, or rebuild.

### Verified startup snapshot

The process retains only bounded readiness metadata after all startup checks
succeed. It must contain, at minimum:

| Snapshot value | Existing source or composition |
| --- | --- |
| storage schema version | `StorageAuditResult.storage_schema_version` |
| finding schema version | `StoredDetectionRun.finding_schema_version`, reconciled with the approved finding contract |
| configured run ID | validated API settings |
| audited run ID | `StorageAuditResult.run_id`, equal to configured and artifact-validation run IDs |
| findings and summary hashes | audit result and strict artifact-validation result, which must agree |
| finding, evidence, and rule counts | `StorageAuditResult`, reconciled where the public artifact result provides the same count |
| logical export hash | `StorageAuditResult.logical_export_sha256` |
| reconstructed findings hash | `StorageAuditResult.reconstructed_findings_sha256` |
| local database file identity | API-side identity captured from the resolved existing database file at startup |

The local database file identity is an API-side change guard, not an invented
`StorageAuditResult` field and not a value for HTTP publication. The snapshot
must not retain the finding store, raw records, normalized events, absolute
paths intended for responses, or real evidence payloads.

### Request-time database identity guard

Before serving a business request, the future API must confirm that the
configured database still exists, is readable, and has the same local identity
as the verified startup snapshot. If the database changes, disappears, becomes
unreadable, or no longer matches that snapshot, the finding service must fail
closed with HTTP `503` and stable code `STORE_UNAVAILABLE`.

It must not hot-reload another store, rebuild or import storage, silently
continue, serve an empty successful response, rerun detection, or select a
different database. The operator must review the change and perform a fresh
application startup and audit. File identity is a local change guard only; it
does not claim to protect against a privileged or adversarial local process.

This request-time guard never reruns the artifact validation or independent
audit. After the guard passes, requests use only the existing bounded public
read-only query operations.

## Planned HTTP contract

**Base path:** `/api/v1`<br>
**Representation:** UTF-8 JSON<br>
**API version:** `1.0`<br>
**Public documentation endpoint:** `/openapi.json` only

Swagger UI and ReDoc must be disabled. No other route is public.

### `GET /healthz`

Returns exactly the following success shape when the verified store remains
usable:

```json
{"api_version":"1.0","status":"ready","storage_schema_version":"1.0"}
```

Readiness is availability of the service and verified store, not a statement
about the safety of the dataset or the absence of attacks. A runtime storage
failure returns `503` rather than this success object. The route accepts no
query parameters and must not disclose filesystem paths, artifact hashes,
environment values, or exception details.

### `GET /api/v1/runs/{run_id}/findings`

Returns a deterministic bounded list for the one configured, audited run.
`run_id` must be a lowercase SHA-256 hexadecimal digest and must equal the
configured run ID; otherwise the request is rejected without querying another
run. The following optional query filters map one-for-one to `FindingQuery`:

`finding_id`, `rule_id`, `rule_version`, `severity`, `reason_code`,
`source_type`, `source_record_number`, `evidence_path`, and `limit`.

The response envelope must contain exactly:

```json
{
  "api_version": "1.0",
  "run_id": "<sha256>",
  "limit": 50,
  "returned_count": 0,
  "items": []
}
```

Each item is the decoded, validated canonical `DetectionFinding.to_dict()`
object. It preserves all source, rule, evidence, null, boolean, number,
array, uncertainty, false-positive-note, and `time_basis` values without
flattening, coercion, or inferred security conclusions. The API's run ID is a
single constant per verified store; within it, the existing Stage 1.5 order is
source record number, rule ID, rule version, then finding ID. This is
equivalent to ordering by run ID first for the supported single-run store.

There is no total count, cursor, offset, page, or `has_more` field. A
successful response must remain within a 4 MiB serialized JSON response
budget; a result that would exceed that budget fails safely instead of being
truncated or paginated.

### `GET /api/v1/runs/{run_id}/findings/{finding_id}`

Returns exactly this envelope after checking both identifiers as described
above:

```text
{
  "api_version": "1.0",
  "run_id": "<sha256>",
  "finding": <complete DetectionFinding v1.0 object>
}
```

The angle-bracket text is explanatory, not a literal API value. A missing
finding, or a finding whose stored `run_id` does not equal the path run ID,
returns the same bounded not-found response. The route does not reveal whether
a finding ID exists in another run.

Evidence is included only as it appears in the canonical finding payload.
The API does not add a separate evidence endpoint in this stage.

### `GET /openapi.json`

Returns the generated OpenAPI document for these endpoints only, using
synthetic examples only. Framework `HEAD` support for this schema route is
harmless but must be documented. The service must not enable interactive
documentation interfaces or disclose local filesystem configuration.

### Publication guarantees

Application JSON must be UTF-8, use sorted object keys, compact separators,
`ensure_ascii=False`, and `allow_nan=False`. Equal verified snapshot and query
must produce equal application response-body bytes; HTTP `Date` and other
transport metadata are outside that comparison. Application responses must add
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Business routes require explicit trailing-slash behavior with no automatic
redirect. No response body may include evaluation/import time, request ID,
latency, absolute path, source artifact content, or an HTTP envelope hash
presented as the original findings JSONL hash.

## Planned validation and errors

The future framework adapter must validate path and query values before it
calls storage. It must permit only the allowlisted filters above; reject
unknown, repeated, conflicting, or empty query values; enforce a 1–500 limit;
and reject unexpected query parameters on health, detail, and OpenAPI routes.
Run and finding identifiers are exactly 64 lowercase hexadecimal characters.
Textual filter values are exact (no trimming, case folding, pattern matching,
or SQL interpolation) and at most 256 characters. `source_record_number` is
positive ASCII-decimal text within SQLite's signed 64-bit range. The request
target is at most 4,096 bytes. All business routes are read-only `GET`
operations; write methods must never mutate storage.

Errors must be deterministic, compact JSON with a stable machine-readable
code and no stack trace, SQL text, filesystem path, artifact content, or
environment value. The contract reserves these outcomes:

| Condition | Outcome |
| --- | --- |
| invalid known path/query value; unknown or duplicate query key | `422` / `INVALID_REQUEST` |
| request target too long | `414` / `REQUEST_TARGET_TOO_LONG` |
| request includes an `Origin` header | `403` / `ORIGIN_NOT_ALLOWED` |
| well-formed unknown run or finding | `404` / `RUN_NOT_FOUND` or `FINDING_NOT_FOUND` |
| unknown route | `404` / `NOT_FOUND` |
| unsupported method on a known business route | `405` / `METHOD_NOT_ALLOWED`, preserving `Allow` |
| response exceeds 4 MiB | `422` / `RESULT_TOO_LARGE` |
| store unavailable, changed, incompatible, or corrupt | `503` / `STORE_UNAVAILABLE` |
| unexpected application error | `500` / `INTERNAL_ERROR` |

Application-generated errors must use this fixed neutral structure:

```json
{"error":{"code":"INVALID_REQUEST","fields":["query.limit"],"message":"Request parameters are invalid."}}
```

For an unknown query key, `fields` must use the generic `query` entry rather
than reflect the key or value. Trusted-host middleware's early HTTP `400` and
server-level protocol failures are the narrow transport exceptions to this
application-error envelope. The future implementation must document and test
that distinction.

## Local-only security boundary

The later service must bind only to `127.0.0.1` on an explicit configured
port (the plan's default is 8000), with one worker and reload disabled. It
must not bind to `0.0.0.0`, `::`, a LAN address, or a Unix socket in this
stage. Programmatic server settings must prevent inherited environment
configuration from widening the bind address or enabling proxy trust.

It must use `TrustedHostMiddleware` with `www_redirect=False` and allow exactly
`127.0.0.1` and `localhost` (no wildcard hosts). It must reject requests
carrying `Origin` with `403 ORIGIN_NOT_ALLOWED`, emit no CORS headers, ignore
forwarded/proxy headers, and disable access logging. Application logs may use
stable error categories only; they must not include query strings, source
identifiers, evidence, SQL, or absolute paths.

It has no authentication, authorization, cookies, sessions, TLS, deployment,
reverse proxy, remote-access, mutation, import, export, SQL, audit, or
administrative endpoint. Those exclusions are deliberate, not missing
features. Loopback access does not authenticate local users or protect against
a privileged local process that can change the project or database.

The service may only open the pre-verified SQLite database using the existing
read-only query functions. It must not create a SQLite journal, WAL, SHM, or
any other sidecar file.

## Approved dependency state

The approved exact pins are recorded in the repository requirements files.
They were installed and locally compatibility-validated for the implemented
Stage 1.6 application checkpoints on Python 3.12.10. Checkpoint 1.6E changes
neither pin nor installation state; its own runtime gate still requires a
fresh `pip check` and complete test-suite result.

| Group | Exact pin | Purpose | Current state |
| --- | --- | --- | --- |
| runtime | `fastapi==0.141.1` | typed ASGI routing and OpenAPI JSON generation | approved / installed |
| runtime | `uvicorn==0.52.4` | fixed-local ASGI server | approved / installed |
| development | `httpx==0.28.1` | in-process HTTP contract tests | approved / installed |
| development | `pytest==9.1.1` | API-focused test runner | approved / installed |

No new dependency is required for the launcher. A later checkpoint must not
silently update, install, or replace these pins.

## Local launcher contract

`src/serve_api.py` is the only Stage 1.6E launcher. It accepts the explicit
operator inputs below and does not infer paths from the current working
directory:

```text
--database PATH
--findings PATH
--summary PATH
--expected-run-id SHA256
--port PORT  (optional; ApiSettings supplies the validated default of 8000)
```

It offers no host, reload, worker-count, proxy, forwarded-header, TLS, or
database-creation option. The launcher constructs `ApiSettings` before it
constructs the application or requests a socket. Invalid command arguments,
run identifiers, and port values therefore fail before application factory or
server startup. The parser exits nonzero; it does not select an alternate port
or retry on another interface.

For valid settings, the launcher uses exactly the existing lifecycle:

```text
ApiSettings -> create_app(settings) -> uvicorn.run(application)
```

The Uvicorn call fixes `host="127.0.0.1"`, passes `settings.port`, uses one
worker, and sets `reload=False`, `proxy_headers=False`, `access_log=False`, and
`log_level="critical"`. A failed Uvicorn startup preserves its nonzero exit
code while the launcher emits only `API_STARTUP_FAILED`; it does not retry or
fall back to another host or port. Importing the launcher does not construct an
application, access storage, read an artifact, or start a server. Startup and
shutdown validation remain owned by the existing FastAPI lifespan and public
Stage 1.5 bridge; the launcher does not open SQLite, import data, read raw CSV,
or read normalized-event JSONL.

The documented local command is:

```powershell
& .\.venv\Scripts\python.exe .\src\serve_api.py `
  --database <approved-store-path> `
  --findings <approved-findings-path> `
  --summary <approved-summary-path> `
  --expected-run-id <approved-lowercase-run-id> `
  --port 8000
```

The command is local-only. It does not authenticate a local user or protect
against a privileged local process. Its synthetic loopback tests use only
temporary fixtures; real-store API validation remains a separate Checkpoint
1.6F gate.
