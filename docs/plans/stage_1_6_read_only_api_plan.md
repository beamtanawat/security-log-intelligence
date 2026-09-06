# Stage 1.6 — Local Read-Only Detection Findings API Foundation

## Document Status

**PLAN ONLY — AWAITING STAGE 1.5 PASS BEFORE IMPLEMENTATION.**

Prepared on 2026-09-03 from the repository, the complete Stage 1.5 plan, final
Stage 1.4 evidence, read-only inspection of the small Stage 1.4 artifacts, and
official framework documentation. This document does not implement an API, create
a database, install dependencies, start a server, change previous plans, or
authorize a commit or push.

This is the next-stage plan, not permission to skip Stage 1.5. Its forecast is
conditional on Stage 1.5 preserving the approved input and passing its own gates.

## 1. Purpose and Correct Sequence

Stage 1.5 is intended to make approved detection findings persistently queryable.
Stage 1.6 will expose that existing read-only query boundary through a small local
HTTP API, without running detection again or modifying stored evidence.

The question for this stage is:

> Can a local client retrieve the same validated findings through a bounded,
> versioned HTTP contract without changing their values, provenance, or meaning?

The intended sequence is:

```text
Stage 1.3: Normalized events
  -> Stage 1.4: Audited rule findings
  -> Stage 1.5: Audited SQLite storage and read-only queries
  -> Stage 1.6: Local read-only findings API
  -> Separately approved future UI or API expansion
```

This follows the README roadmap and Stage 1.5's own readiness target. ML is not
the immediate next step: there are no ground-truth attack labels, and the current
rules intentionally expose source-product observations only.

## 2. Evidence Ledger: Actual State, Forecast, and Unknowns

### Verified Repository State

The final inspection snapshot has HEAD
`3e079909fe3c707b6812b9dfe2f6b3dc428afa71`:
`3e07990 Add Stage 1.5 detection storage plan`. Its parent is
`7669a65 Complete Stage 1.4 rule-based detection foundation`.

| Item | Status at this planning snapshot |
| --- | --- |
| Stage 1.3 | Complete; normalized schema v1.0 and 100,000-record output established. |
| Stage 1.4 | Complete in README and commit history; final findings record technical PASS. |
| Stage 1.4 tests | Documentation records 99 passing tests during the recovery/revalidation checks; not rerun by this planning task. |
| Stage 1.5 plan | Tracked at `docs/plans/stage_1_5_detection_storage_plan.md` in `3e07990`; still a plan, not implemented storage. |
| Stage 1.5 storage implementation | `src/storage/` does not yet exist. |
| Stage 1.5 contract/findings documents | Do not yet exist. |
| Stage 1.5 validator/database | Do not yet exist. |
| API implementation/dependencies | Not implemented; `requirements.txt` is currently empty. |

Stage 1.5's current plan records completed Stage 1.4, the immutable input hierarchy,
the finding/summary-only validation boundary, and the composite rule/version
foreign key. The plan changed during this planning session; its complete current
version was reread before finalizing Stage 1.6. Its SHA-256 is
`A45077D55FDC87751C4B939A03943DB258C61B3ED4AC80B83C95E2DD275891DD`.
The existence or commit of a Stage 1.5 plan is not proof of Stage 1.5 completion.

The Stage 1.4 findings document retains a historical "NEEDS APPROVAL" commit note;
the subsequent completion commit and README establish that the documented work was
committed. Do not invent a missing Stage 1.5 PASS from that Stage 1.4 evidence.

### Small-Artifact Checks Performed for This Plan

Only the existing small finding JSONL and validation summary were read for these
checks. No raw CSV parsing, normalized-dataset rescan, detection execution, storage
import, or runtime test suite was performed.

| Observation | Measured or verified value |
| --- | --- |
| Finding artifact | `data/processed/stage_1_4f_detection_findings.jsonl` |
| Finding artifact size | 81,627 bytes |
| Finding artifact SHA-256 | `5212F083BB3832158BCD650535536C22D1B8DBF582496726F998ECE949EE20DC` |
| Validation summary | `data/processed/stage_1_4f_detection_summary.json` |
| Validation summary size | 17,092 bytes |
| Validation summary SHA-256 | `D3585BF577CB1B16ACA2A8AFB65D18959941E28FC2B9CD6C396C35CF03DD16FE` |
| Validation envelope | `validation_stage = "1.4F"`, `verdict = "PASS"` |
| Evaluated normalized records | 100,000, recorded in the retained summary |
| Invalid normalized records | 0, recorded in the retained summary |
| Active rules | 2 |
| Findings | 43 |
| Unique matched source records | 25 |
| Anomaly-subtype findings | 18 |
| Source-threat-observation findings | 25 |
| Rule severity | All 43 are `INFORMATIONAL` |
| Evidence entries | 227, counted from the finding JSONL during this planning task |
| Evidence entries by rule | 72 anomaly-subtype; 155 source-threat-observation |

The counts and hashes agree with the retained Stage 1.4 evidence. Counting the
227 evidence entries is a structural observation, not a new security audit or an
attack count.

## 3. Reasonable Forecast of Stage 1.5

### Expected Capabilities After Stage 1.5G PASS

Stage 1.5 should provide:

- a documented SQLite storage contract v1.0 with `PRAGMA user_version = 1`;
- strict finding and validation-summary ingestion;
- a new database created transactionally and published without overwrite;
- relational findings/evidence plus canonical finding JSON;
- typed, bounded, parameterized, read-only queries;
- an independent storage audit;
- exact finding JSONL round-trip verification;
- equal logical export hashes for independently built stores;
- a local validator and measured storage findings document;
- full regression and storage tests with actual recorded results.

These are expected deliverables, not currently available implementations.

### Conditional Row-Count Forecast

If Stage 1.5 consumes the exact verified Stage 1.4 artifacts without approved
contract changes:

| Storage measure | Expected Stage 1.5 result | Basis |
| --- | ---: | --- |
| `storage_metadata` rows | At least 2 | Required storage/finding version keys; final key set belongs to 1.5A. |
| `detection_runs` rows | 1 | One-run import contract. |
| `run_rules` rows | 2 | Approved active-rule list. |
| `findings` rows | 43 | One row per source finding, not per normalized event. |
| `finding_evidence` rows | 227 | One row per observed evidence entry. |
| Unique matched source records | 25 | Preserved source references. |
| Anomaly/source-threat findings | 18 / 25 | Audited Stage 1.4 output. |
| Informational findings | 43 | Severity copied unchanged. |
| Stored normalized/raw event rows | 0 | Those datasets are out of Stage 1.5 storage scope. |

The 100,000 evaluated-record count belongs to run metadata. It must not become
100,000 database findings, HTTP results, benign labels, or stored normalized events.

Expected `run_id` for this finding artifact:

`5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc`

This is the finding-artifact digest defined by Stage 1.5, not a universal identity
for every source dataset or detection execution. It does not incorporate the
summary or normalized input; identical finding bytes, including empty outputs,
can share it. This stage remains restricted to one audited run in one store.

### Results That Must Remain Unknown Until Executed

Do not predict or fabricate:

- the SQLite database size or physical file hash;
- the canonical logical export hash;
- final Stage 1.5/1.6 test counts, test results, or coverage percentages;
- import/query/API latency, throughput, memory measurements, or speedup;
- a Stage 1.5G PASS verdict;
- attack counts, accuracy, precision, recall, or false-positive rate.

Stage 1.5's reconstructed finding JSONL should match the known finding-artifact
hash. Two different SQLite builds need not have equal physical file hashes.
Actual approved Stage 1.5 measurements supersede this forecast. Any difference
requires explanation and the upstream review gate, not tuning to force 43/227.

## 4. Upstream Compatibility Issues That Must Be Resolved Before the API

These are observations and entry requirements, not authorization to edit Stage
1.4 or Stage 1.5 during this planning task.

### Validation Summary Is an Envelope

The actual Stage 1.4 summary is not a top-level `DetectionRunSummary`.

Relevant top-level members are:

- `validation_stage` and `verdict`;
- `primary_run`: the actual detection run summary;
- `primary_findings`: finding path, size, and hash;
- `primary_audit`: audited counts and bounded references;
- `normalized_input` and `raw`: retained integrity evidence;
- `determinism` and `validation_checks`.

Stage 1.5 must explicitly validate this envelope and reconstruct
`DetectionRunSummary` from `primary_run`. Its `summary_sha256` must identify the
original complete summary bytes, not a newly serialized subset. The importer
must not overwrite the retained summary or copy its absolute machine paths into
public API metadata.

### Audit Modes Have Different Data Access

The public `audit_detection_jsonl(path, expected_summary=None)` has two modes:

- without a summary: self-contained finding contract, registry, ordering, and
  aggregate checks;
- with a summary: additionally streams the referenced normalized input and
  re-evaluates relationships against it.

The latter is not a lightweight finding-file-only operation. Stage 1.5 must
document which checks are inherited from the approved Stage 1.4 full audit and
which are repeated locally. Do not pass the summary merely for count comparison
and accidentally rescan/re-evaluate 907 MB of normalized data.

The current Stage 1.5 plan already prohibits that raw/normalized rescan. Its public
storage audit is designed to inspect the SQLite store together with the approved
small finding JSONL and summary. Stage 1.6 preserves that audit input boundary at
startup and explicit validation; it does not invent a database-only audit mode.
Requests call only the read-only storage query interface, never a detection audit
or the upstream finding/summary readers.

### Exact Serialization Matters

Stage 1.4 writes finding lines using UTF-8, `ensure_ascii=False`,
`sort_keys=True`, compact `(",", ":")` separators, and one `"\n"` per record.
No BOM is added.

Stage 1.5 must reconcile its round-trip serializer with this exact format. JSON
structural equality alone does not prove the required original JSONL hash.

### Public Interfaces Must Exist, Not Merely Be Mentioned in a Plan

Stage 1.5 plans `FindingQuery`, `get_stored_finding`, and
`iter_stored_findings`, but these are not implemented at this snapshot.
At checkpoint 1.6A, verify their actual public import locations, signatures,
validation, ordering, limit, and connection ownership behavior.

The public storage audit and its bounded result must provide enough approved
metadata to establish schema version, the single run ID, finding count, and
logical export hash. Record its actual finding/summary/database arguments at 1.6A.
Do not require it to work without its documented source artifacts. If an essential
public capability is absent, stop with `NEEDS CONTRACT CHANGE` and propose the
smallest upstream correction for separate approval. Do not add raw SQL to HTTP
handlers, import private helpers, or replace missing storage behavior in the API.

Confirm that the final storage audit enforces the planned composite finding-to-rule
foreign key and preserves canonical finding JSON as the original payload, with
relational columns/evidence as checked projections. HTTP code must not reinterpret
those projections as a new source of truth or duplicate the schema audit.

### Query Limit Is Not Pagination

Stage 1.5 specifies `limit=50` with a maximum of 500 and no offset/cursor.
Stage 1.6 preserves that limitation. It does not fabricate `next_cursor`,
`has_more`, a filtered total, or a claim that a limited result is complete.

### Storage May Not Be Rebuilt as an API Startup Step

Stage 1.4 and Stage 1.5 creation workflows reject existing outputs deliberately.
Do not delete successful artifacts, rerun their importers/validators blindly, or
replace evidence just to start or revalidate the API.

## 5. Start Gate, Authority, and Stage Status

Stage 1.6 implementation is allowed only after:

1. Stage 1.5G has an evidence-backed technical `PASS`.
2. The final storage contract, query interfaces, database, audit, measurements, and
   tests are present and mutually consistent.
3. The compatibility requirements in Section 4 are resolved in the upstream
   implementation and documentation.
4. The intended database is ignored/untracked and contains exactly one approved run.
5. Stage 1.5 logical hash and finding round-trip hash are recorded and verified.
6. No unresolved upstream failure or security/contract review remains.
7. The user separately approves Stage 1.6's framework/dependency addition and the
   next checkpoint scope.

The current state is `AWAITING STAGE 1.5 PASS`, not `BLOCKED BY ENVIRONMENT`.
The approved plan may exist now; actual API work cannot leap over the start gate.

`AGENTS.md` lists FastAPI as requiring explicit authorization. This plan proposes
its use but does not grant that authorization. If approval is absent, stop at
`NEEDS APPROVAL` rather than installing packages or substituting another stack.

## 6. Environment Context

The user's validated local VS Code PowerShell environment has a working project
`.venv` and Python 3.12.10. Stage 1.4 evidence independently records that version.
Local results from that environment are authoritative execution evidence.

Some execution contexts cannot access the local Windows runtime. That is not proof
of a broken project installation.

- Do not reinstall Python, rebuild `.venv`, or modify `PATH` merely because an
  agent cannot access the runtime.
- Do not upgrade Python just because a current documentation page shows a later
  patch version.
- If runtime access is available, use the validated environment.
- Otherwise do only approved pre-validation work and stop at
  `AWAITING LOCAL VALIDATION` with exact local commands.
- Do not fabricate tests, omit required tests silently, or count skipped API tests
  as a passing full suite.
- Do not change PowerShell execution policy to bypass an execution-context limit.
- Use `BLOCKED BY ENVIRONMENT` only for a genuine checkpoint-level inability to
  proceed safely, not as the default stage verdict.

No runtime checks or package installations are part of creating this plan.

## 7. Minimal Architecture and Dependency Decision

```text
Local HTTP client
  -> local-only transport and request checks
  -> typed API parameters
  -> thin storage adapter
  -> approved Stage 1.5 read-only query functions
  -> DetectionFinding v1.0
  -> bounded deterministic JSON response
```

Use FastAPI for HTTP routing, request contracts, and OpenAPI; use base Uvicorn as
the local ASGI server. No ORM, async database driver, database service, frontend,
or alternative detection implementation is needed. FastAPI's ASGI-server
relationship is documented in its [server guide](https://fastapi.tiangolo.com/deployment/manually/).

Proposed direct dependencies, only after approval:

| Purpose | Package | Planned dependency file |
| --- | --- | --- |
| HTTP application | `fastapi` without optional "standard" extras | `requirements.txt` |
| Local ASGI server | `uvicorn` without optional extras | `requirements.txt` |
| In-process HTTP testing | `httpx` | `requirements-dev.txt` |
| API/full-suite test runner | `pytest` | `requirements-dev.txt` |

The development requirements file includes `-r requirements.txt`. Select and record
exact compatible version pins during 1.6A/1.6B against Python 3.12 and then validate
the resolved environment with `pip check`. Do not invent future tested versions in
this advance plan or install unbounded "latest" dependencies without review.
Record resolved framework/transitive versions in validation evidence.

Retain existing unittest suites unchanged. Use pytest for new important API logic
as instructed by `AGENTS.md`; pytest must also collect the existing unittest
tests. Legacy unittest discovery remains an additional regression check, not the
complete Stage 1.6 gate by itself.

FastAPI's [testing guide](https://fastapi.tiangolo.com/tutorial/testing/) documents
TestClient's HTTPX dependency. Use TestClient as a context manager so lifespan is
exercised. Synthetic tests must not start external services or need real data.

Simpler alternative considered: keeping only the Stage 1.5 CLI does not create the
requested next HTTP boundary. Building custom routing/validation/OpenAPI instead
would add avoidable application code. If the framework is not approved, retain
the working CLI and stop; do not build an unreviewed substitute.

## 8. Scope and Trust Boundary

This is a local, single-user development API over one approved immutable store.
It is not a remotely accessible or production-secured service.

Defaults and restrictions:

- bind only `127.0.0.1`, default port 8000;
- one process/worker, reload disabled;
- explicit programmatic server settings; no inherited environment may widen the
  bind address or enable proxy trust;
- no reverse proxy, tunnel, LAN bind, `0.0.0.0`, cloud hosting, or public exposure;
- no authentication, authorization, cookies, or sessions in this stage;
- no claim that loopback restriction authenticates local users or processes;
- trusted local operator and filesystem; do not claim protection from a privileged
  local process that can modify the database or project;
- exact allowed Host names: `127.0.0.1` and `localhost`; no wildcard hosts;
- reject any request containing an Origin header in v1; this is a non-browser
  client boundary, and no CORS middleware is enabled;
- ignore forwarded-client headers by disabling server proxy-header trust;
- access logging disabled; application logs contain stable error categories, not
  query strings, source identifiers, evidence, SQL, or absolute paths.

Uvicorn's [settings](https://uvicorn.dev/settings/) distinguish loopback binding
from LAN binding and document proxy, worker, reload, and access-log controls.
Use these as explicit choices, not implied defaults.

Use Starlette's [TrustedHostMiddleware](https://starlette.dev/middleware/#trustedhostmiddleware)
with `www_redirect=False`. Its early Host rejection is a documented HTTP 400;
do not assume that middleware automatically uses the application's JSON errors.
All local-host security cases must be tested before a real store is served.

Full finding responses intentionally retain approved opaque source references and
evidence for the local client. Those values must not enter tracked examples,
OpenAPI samples, error messages, access logs, or external services.

## 9. Storage Bridge and Startup Contract

### Proposed API-Side Interface

```python
@dataclass(frozen=True)
class ApiSettings:
    database_path: Path
    findings_path: Path
    summary_path: Path
    expected_run_id: str
    port: int = 8000

def create_app(settings: ApiSettings) -> FastAPI: ...
```

No module import may open a database, start a socket, evaluate rules, or create
artifacts. The launcher constructs settings explicitly.

Validate settings before filesystem/network access: `expected_run_id` must be
exactly 64 lowercase hexadecimal characters and `port` must be an integer from
1 through 65,535 (not a boolean). There is no configurable non-loopback host.

The thin API adapter delegates to the final public Stage 1.5 interfaces:

```python
get_stored_finding(database_path, run_id, finding_id)
iter_stored_findings(database_path, FindingQuery(...))
```

Use the approved public storage audit for readiness, supplying the configured
database plus the approved small Stage 1.4 finding and summary artifacts. Its
actual module and call signature must be recorded from completed Stage 1.5 at
1.6A; it is not an already-existing API invented by this plan. These startup
inputs are operator settings, never HTTP query parameters or response paths.

### Startup and Shutdown

Use FastAPI's [lifespan mechanism](https://fastapi.tiangolo.com/advanced/events/)
for pre-request validation and cleanup:

1. Resolve the three explicit existing files beneath the repository's processed-data
   directory; reject directories, missing files, input-path aliasing,
   traversal/junction escapes, and user-supplied SQLite URI strings. Synthetic tests
   use explicit temporary roots and their own small finding/summary fixtures.
2. Never create a database or regenerate either source artifact when missing.
3. Validate schema/version, constraints, the one-run boundary, artifact identities,
   and round-trip consistency with the public storage audit. Never open the raw CSV
   or normalized-event JSONL.
4. Require the audited run ID to equal `expected_run_id`.
5. Establish a verified snapshot containing schema versions, run ID, finding count,
   logical hash, and local file identity used internally.
6. Keep only bounded readiness metadata in memory, not the entire finding store.
7. Close all audit connections before serving requests.
8. On startup failure, exit nonzero with a sanitized category; do not serve an
   empty fallback store or return a false healthy status.

During requests, changed/disappeared/unreadable store identity or an invalid stored
finding makes data service unavailable. Do not hot-reload another database; require
operator review and a fresh startup audit. File identity checks are change guards,
not a guarantee against adversarial local filesystem tampering.
The finding/summary inputs are required for startup and explicit validation, not
reread for every HTTP request; the service is tied to the audited immutable store.

### SQLite Connection Ownership

Use only the Stage 1.5 read-only functions, which must use `mode=ro`,
`query_only = ON`, and `foreign_keys = ON`. Open, consume, and close a connection
or iterator in one synchronous storage call on its owning worker thread. Never
retain a global connection or move a lazy iterator between threads.

The [Python 3.12 sqlite3 documentation](https://docs.python.org/3.12/library/sqlite3.html)
documents read-only URI mode, thread-affinity defaults, and explicit connection
closing. A connection context manager alone does not close the connection.
Do not set `check_same_thread=False` merely to hide incorrect ownership.

Synchronous route handlers or a single offloaded storage operation may be used,
but connection creation and consumption must remain inside that same operation.
Response construction is completed before HTTP publication so audit failures do
not leave a partially successful JSON response.

## 10. HTTP Contract v1

All business operations are read-only GET requests. The API version is `1.0`;
the path namespace is `/api/v1`. Finding schema v1.0 remains a separate contract.

| Method and path | Behavior |
| --- | --- |
| `GET /healthz` | Ready only when the verified store remains usable; no dataset paths or findings. |
| `GET /api/v1/runs/{run_id}/findings` | Bounded, exactly filtered finding list for the configured run. |
| `GET /api/v1/runs/{run_id}/findings/{finding_id}` | One validated finding or 404. |
| `GET /openapi.json` | Local schema with synthetic examples only. Framework HEAD support for this schema route is harmless and must be documented. |

No list-runs, aggregate-report, raw-log, file-download, import, delete, update,
export-all, detection-run, or arbitrary-SQL endpoint is included. The operator
already supplies the single expected run ID; API metadata browsing is not needed.

### Health Response

```json
{"api_version":"1.0","status":"ready","storage_schema_version":"1.0"}
```

Readiness describes service/storage availability, not security safety or absence
of attacks. A runtime store failure returns 503 instead of this success body.

### List Response

```text
{
  "api_version": "1.0",
  "run_id": "<validated configured run ID>",
  "limit": <validated requested limit>,
  "returned_count": <number of items in this response>,
  "items": [<complete DetectionFinding v1.0 objects>]
}
```

The tokens in angle brackets above are explanatory, not literal API values.

Each item equals the underlying `DetectionFinding.to_dict()` representation.
Preserve all rule/source/evidence fields, nulls, booleans, numbers, strings, arrays,
uncertainties, false-positive notes, and `time_basis = NOT_USED`. Do not flatten
evidence, coerce identifiers, convert numeric strings, or replace unknowns.

No-match list queries return 200, zero `returned_count`, and an empty `items` list.
`returned_count` is never a total number of all matching records.

### Detail Response

```text
{
  "api_version": "1.0",
  "run_id": "<validated configured run ID>",
  "finding": <complete DetectionFinding v1.0 object>
}
```

Identity is scoped by run and finding together. A valid but non-configured run ID
returns 404; it must not select another database or fall back to the configured run.

### Stable Serialization and Publication

- Serialize application JSON as UTF-8 with sorted object keys, compact separators,
  `ensure_ascii=False`, and `allow_nan=False`.
- Serialize nested findings directly from the validated contract; framework response
  conversion must not drop fields or silently coerce evidence values.
- Validate response shape and document it in OpenAPI even if a custom response
  serializer is used to preserve exact values.
- Add `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` to application
  responses.
- Do not include evaluation/import times, request IDs, latency, or absolute paths
  in deterministic response bodies.
- Equal snapshot and query must yield equal application response-body bytes.
  HTTP Date headers and other transport metadata are not part of that guarantee.
- Do not compare an HTTP envelope hash directly to the original finding JSONL
  hash; extract findings and use the original line serializer for round trips.

## 11. Query Validation, Ordering, and Resource Limits

Accepted list query keys:

`finding_id`, `rule_id`, `rule_version`, `severity`, `reason_code`,
`source_type`, `source_record_number`, `evidence_path`, and `limit`.

The path supplies `run_id`. No query field may override it.
Health, detail, and OpenAPI routes accept no query parameters; reject any supplied
query keys rather than silently suggesting unsupported filtering.

Rules:

- reject unknown keys and repeated keys, including repeated `limit`, with 422;
- reject empty values rather than interpreting them as missing filters;
- run/finding IDs are exactly 64 lowercase hexadecimal characters;
- use final Stage 1.4/1.5 rule-ID, version, reason-code, and severity validation;
- severity values are `INFORMATIONAL`, `LOW`, `MEDIUM`, and `HIGH`, with exact case;
- exact textual filters do not trim, case-fold, pattern-match, or interpolate SQL;
- valid but unmatched rule/source/evidence values return an empty list;
- source record number is a positive integer within SQLite's signed 64-bit range;
- integer query text contains ASCII decimal digits only; reject booleans, signs,
  whitespace, floating-point notation, and exponent notation;
- textual filter length is at most 256 characters;
- request-target length is at most 4,096 bytes;
- default limit is 50; valid explicit limits are 1 through 500;
- stable order is run ID, source record number, rule ID, then finding ID;
- all filter values go through the storage layer's parameterized SQL;
- no `offset`, `cursor`, `sort`, SQL, database path, time range, or substring search.

### No Pagination Promise

The list returns at most the first `limit` matches. It has no cursor, `has_more`,
filtered total, or completeness flag. A response containing exactly the limit
must not be described as a complete matching dataset.

The current 43-finding run fits within the default limit, but the implementation
must not depend on that coincidence. Test a synthetic store with over 500 matches.
Do not fetch all rows or modify Stage 1.5 queries to simulate unsupported pagination.

### Response Budget

Application response bodies have a 4 MiB budget, checked while constructing the
bounded response and before publication. If a response would exceed it, close the
iterator and return 422 `RESULT_TOO_LARGE` without partial findings. A too-large
single finding is also rejected, not truncated; it remains intact in storage.

These length/count/byte limits are operational API safeguards, not detection
thresholds. They make no claim about whether traffic or a finding is suspicious.
Enforce the serialized budget incrementally without materializing the full store.
The 4 MiB body cap is not a hard process-memory cap: decoding/serialization and
Python objects add overhead. Account for bounded output buffers and in-flight
decoded records; the maximum decoded record size remains an explicit
storage-contract limitation, not a hidden guarantee of bounded record size.

## 12. Errors, Logging, and Documentation

Application-generated errors use:

```json
{"error":{"code":"INVALID_REQUEST","fields":["query.limit"],"message":"Request parameters are invalid."}}
```

Messages are fixed and neutral. `fields` contains only approved field paths;
for unknown user-supplied keys use a generic `query` entry, not the raw key/value.

| Condition | HTTP status / stable code |
| --- | --- |
| Invalid known path/query value, unknown/duplicate query key | 422 / `INVALID_REQUEST` |
| Application response exceeds the fixed byte budget | 422 / `RESULT_TOO_LARGE` |
| Request target too long | 414 / `REQUEST_TARGET_TOO_LONG` |
| Request has an Origin header | 403 / `ORIGIN_NOT_ALLOWED` |
| Well-formed unknown run or finding | 404 / `RUN_NOT_FOUND` or `FINDING_NOT_FOUND` |
| Unknown route | 404 / `NOT_FOUND` |
| Unsupported method on a known business route | 405 / `METHOD_NOT_ALLOWED`; preserve Allow header |
| Store unavailable, changed, incompatible, or corrupt at runtime | 503 / `STORE_UNAVAILABLE` |
| Unexpected application exception | 500 / `INTERNAL_ERROR` |

TrustedHost's early HTTP 400 and server-level protocol failures may use native
transport responses. Document and test this narrow exception; do not claim every
possible transport failure follows the application's JSON envelope.

Do not expose traceback text, framework validation input values, SQL statements,
database contents, or filesystem locations in errors. Do not silently turn storage
errors into empty successful result lists.

Disable debug, Swagger UI, and ReDoc. Serve only local OpenAPI JSON and tracked
Markdown documentation, using synthetic fixtures/examples. FastAPI's
[metadata/docs settings](https://fastapi.tiangolo.com/tutorial/metadata/) support
independently configuring the schema and UI endpoints. No CDN/UI assets are needed.

Configure trailing-slash behavior explicitly; use no automatic redirects on
business routes. POST/PUT/PATCH/DELETE must not trigger any storage mutation.

## 13. Planned Files and Dependency Direction

| Deliverable | Planned location |
| --- | --- |
| This plan | `docs/plans/stage_1_6_read_only_api_plan.md` |
| API contract and upstream compatibility record | `docs/read_only_api_contract.md` |
| Application/settings/storage adapter/routes/errors | `src/api/` |
| Fixed-local launcher | `src/serve_api.py` |
| Controlled API validator | `src/validate_api.py` |
| API tests | `tests/test_api.py` |
| Runtime/development dependencies | `requirements.txt` and `requirements-dev.txt` |
| PowerShell validation wrapper | `scripts/validate_stage_1_6.ps1` |
| Final measured results and limitations | `docs/stage_1_6_api_findings.md` |
| Optional local validation summary | `data/processed/stage_1_6f_api_validation_summary.json`, ignored |

Package names are planned, not currently implemented. Keep `src/api/` small;
create only files needed by a checkpoint, not a generic web-platform scaffold.

Dependency direction is API -> public storage query/audit -> stable finding
contracts. Storage, detection, and normalization must not depend on the web layer.
No schema migration, storage rewrite, shared-helper refactor, or upstream private
API import is authorized by this plan.

## 14. Local Commands and Reproducibility

All following implementation commands are future commands, not work performed
while creating this plan.

After approved dependency files exist and installation is explicitly authorized:

```powershell
& .\.venv\Scripts\python.exe -m pip install -r .\requirements-dev.txt
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p "test_*.py" -v
& .\.venv\Scripts\python.exe -m pytest .\tests -q
```

Future local launch, only after Stage 1.5 PASS and API safety gates:

```powershell
& .\.venv\Scripts\python.exe .\src\serve_api.py `
  --database .\data\processed\stage_1_5f_detection_store.sqlite3 `
  --findings .\data\processed\stage_1_4f_detection_findings.jsonl `
  --summary .\data\processed\stage_1_4f_detection_summary.json `
  --expected-run-id 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc `
  --port 8000
```

The launcher does not offer a host, reload, worker-count, proxy, or database-create
option. A port conflict fails clearly; never kill an unrelated process to free it.

Example local requests after the service is started:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/healthz'
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/runs/5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc/findings?limit=50'
```

Do not copy full real responses into tracked documentation or public messages.

Future controlled validation:

```powershell
.\scripts\validate_stage_1_6.ps1 `
  -Database .\data\processed\stage_1_5f_detection_store.sqlite3 `
  -FindingsInput .\data\processed\stage_1_4f_detection_findings.jsonl `
  -SummaryInput .\data\processed\stage_1_4f_detection_summary.json `
  -ExpectedRunId 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc `
  -SummaryOutput .\data\processed\stage_1_6f_api_validation_summary.json
```

`Database`, `FindingsInput`, `SummaryInput`, and `ExpectedRunId` are required
validation inputs. The launcher likewise requires its database, findings, summary,
and expected-run-id options; it must not guess artifacts from the working directory.
`SummaryOutput` is optional. When provided, it must be a new ignored processed
path; reject existing files. When omitted, print a bounded validation report
without persisting it. This allows final revalidation without deleting or replacing
the retained Stage 1.6F evidence.

Do not invoke Stage 1.5's import-producing validator as API startup or as an
automatic revalidation prerequisite. Use its completed public read-only audit.

## 15. Synthetic Verification Matrix

New tests use pytest and TestClient over small synthetic stores made by the
approved storage fixture/import boundary, retaining their matching synthetic
finding/summary inputs for the startup audit. Do not use the real database or raw
and normalized datasets in the normal test suite.

Use `TestClient(app, base_url="http://127.0.0.1")` as a context manager so startup
and shutdown run and the normal test Host matches the approved local allowlist.
Do not add TestClient's default `testserver` host to the production allowlist just
to make tests pass; hostile-Host tests supply their own rejected Host explicitly.

Required cases:

- module import has no I/O/server side effects;
- invalid settings and port boundaries fail before database/socket access;
- missing/directory/escaped/incorrect-schema/multi-run database fails startup;
- missing/mismatched startup finding or summary fails without regenerating it;
- wrong expected run ID and failed storage audit fail startup;
- no startup/validation path opens raw CSV or normalized JSONL; ordinary requests
  do not rerun source-artifact or storage audits;
- lifespan cleanup works on normal exit and exceptions;
- read-only connection flags and close behavior remain correct under concurrent
  requests, without cross-thread connection reuse;
- health, exact list, each filter, combined filters, detail, and no-match cases;
- missing optional source ID and nested JSON evidence preserve exact types/values;
- overlapping rules remain separate findings; repeated source records are not merged;
- malformed hashes, integer boundaries, invalid severity, blank/unknown/duplicate
  parameters, and oversized query strings;
- SQL metacharacters never become SQL; valid unmatched strings stay values;
- default/minimum/maximum limits and a store with over 500 matches;
- no pagination/total/completeness fields appear;
- corrupt/missing evidence, mismatched canonical JSON, and changed store fail closed;
- expected 404/405/422/503/500 errors contain no reflected sensitive values;
- Host attack rejected, Origin rejected, forwarded headers ignored, no CORS grants;
- write methods and data-creation options are absent;
- >4 MiB output fails before publication and iterator/connection closes;
- equal inputs produce equal body bytes; HTTP headers are not used as determinism proof;
- OpenAPI lists only the approved capabilities and synthetic examples;
- no Swagger/ReDoc/static UI exposure;
- log/error leak assertions cover source IDs, evidence, paths, and SQL;
- controlled synthetic loopback launch and cleanup leave no process/socket behind.

Keep all historical suites intact. Report actual collected/passed/failed/skipped
counts; unexplained skips, missing dependencies, or accidentally uncollected new
tests cannot qualify as full-suite PASS.

## 16. Real-Store Validation Procedure

Run only at checkpoint 1.6F after the earlier checkpoints pass.

1. Re-read final Stage 1.5 PASS evidence, final public contracts, approved run ID,
   measured logical hash, and input/round-trip hashes.
2. Verify exact target paths and Git data safety. Do not create or import a store.
3. Record hashes of the same physical SQLite file, the small Stage 1.4 findings,
   and the retained summary before testing; enumerate relevant sidecars.
4. Run the complete API/legacy suite and dependency consistency check.
5. Run the public read-only storage audit using the database and approved small
   finding/summary inputs; compare with Stage 1.5's measured logical content evidence.
6. Exercise the real store in-process through TestClient with lifespan enabled.
7. For the pinned 43-finding run, verify the default list returns 43, both rule
   filters return 18/25, and the INFORMATIONAL filter returns 43.
8. Compare every returned finding to the approved storage query result and original
   Stage 1.4 finding, not merely its ID or count.
9. Retrieve every finding through the detail route and reconcile 227 evidence
   entries and 25 unique source references without logging their values.
10. Verify stable ordering, default versus explicit limit, no-match behavior,
    expected errors, and security headers.
11. Repeat identical requests and compare application body hashes.
12. For the complete current list, extract finding items, serialize with the exact
    Stage 1.4 JSONL format, and compare the finding-artifact hash. Do not compare
    an HTTP envelope to a JSONL file directly.
13. Perform one controlled real loopback HTTP smoke test using the owned launcher.
    In-process TestClient success alone does not prove a real socket path.
14. Close only the validator-owned server, connections, and temporary resources.
15. Repeat the storage audit and same-file hashes; they must remain unchanged.
    No new SQLite journal/WAL/SHM file or rewritten upstream artifact may remain.
16. Rerun the full suite, review the complete diff, run `git diff --check`, and
    check ignored/untracked output safety.
17. Record only aggregate measurements, response hashes, gate results, versions,
    and limitations in the tracked findings document.

If the approved upstream dataset changes, reconcile the plan first. Do not force
43/227 or invent an API-wide full export. For larger stores, the bounded list
remains incomplete by design; full per-ID validation requires an authoritative
stream of IDs, not an unlimited HTTP query or hidden storage change.

The same-file SQLite before/after hash is an immutability check. It is not a
requirement that separately built SQLite databases have equal physical bytes.

### Validator Safety

- The PowerShell wrapper calls a real Python helper file; do not pass multiline
  Python through `python -c` and repeat the earlier quoting problem.
- Start no external service; bind the owned helper only to loopback.
- If a background process is needed on Windows, keep its window hidden and record
  its process handle/ID. Never terminate a process by name or a port-wide search.
- Use bounded startup/request waits, fail on port conflicts, and clean up in
  `finally` on success, failure, or interruption.
- The validator must not install dependencies, change execution policy, rebuild
  the environment, or delete existing outputs.
- Publish an optional new summary only after completion and verification, using a
  temporary file and non-overwriting publication. A failure is never serialized
  as a successful validation.
- No raw CSV parsing or normalized 907 MB rescan is required by this API stage.

## 17. Mandatory Checkpoint Process

Execute one checkpoint at a time:

```text
READ CURRENT CONTEXT
  -> VERIFY UPSTREAM AND AUTHORIZATION GATES
  -> STATE THE CHECKPOINT SCOPE
  -> IMPLEMENT ONLY THAT SCOPE
  -> RUN COMPLETE REQUIRED TESTS
  -> PERFORM CHECKPOINT VALIDATION
  -> VERIFY DATA/PROCESS/DEPENDENCY SAFETY
  -> REVIEW COMPLETE DIFF AND SECURITY INTERPRETATION
  -> git diff --check
  -> REPORT VERDICT
  -> STOP FOR THE USER'S NEXT CHECKPOINT / COMMIT AUTHORIZATION
```

Stop states include `AWAITING STAGE 1.5 PASS`, `NEEDS APPROVAL`, `FAIL`,
`PASS WITH CAUTION`, `AWAITING LOCAL VALIDATION`, `BLOCKED BY ENVIRONMENT`,
`NEEDS CONTRACT CHANGE`, and `NEEDS SECURITY REVIEW`.
Only technical PASS may be presented for commit approval; it never authorizes a
commit, push, package install, network exposure, or the next checkpoint by itself.

## 18. Checkpoint 1.6A — Upstream Reconciliation and API Contract

### Objective

Confirm completed Stage 1.5 compatibility, settle the narrow HTTP contract, and
obtain explicit framework/dependency approval before API code.

### Why It Exists

An advance plan cannot substitute for final upstream interfaces and measurements.

### Inputs

- Final Stage 1.5 contract, implementation, tests, database audit, and PASS evidence.
- This plan, `AGENTS.md`, and approved Stage 1.4 finding semantics.

### Expected Outputs

- `docs/read_only_api_contract.md` including actual storage imports/signatures,
  audit metadata, dependency proposal, endpoint/error tables, and limitations.
- Actual Stage 1.5 measurements replacing forecast-only values in the new contract.

### Likely Files Changed

Only the new API contract document; no previous plan, storage code, or dependency
file change in this checkpoint.

### Implementation Scope

Reconcile Section 4, verify the start gate, document exact dependency pins proposed
for Python 3.12, and record the user's approval status. API implementation waits.

### Explicitly Out of Scope

No package install, source implementation, server, data import, upstream fix, or
declaration that a planned storage interface already exists.

### Synthetic Tests

Run existing suites if runtime access is available; record actual baseline counts.
Review contract examples and compatibility against real public types.

### Real-Data Validation

Use only the final public read-only storage audit with its approved database and
small finding/summary inputs and metadata; no HTTP service or ingestion. If
Stage 1.5 is absent, stop before this work.

### Security Interpretation Boundaries

HTTP publication does not strengthen a finding's security meaning.

### Acceptance Criteria

Upstream gates pass, every required storage capability exists, the contract is
consistent, and the dependency/next-checkpoint authorization is explicit.

### Stop Conditions

Stop on incomplete Stage 1.5, summary/serialization/audit incompatibility, missing
public metadata/query interfaces, or missing dependency approval.

### Commit Gate

Report verdict and stop for explicit approval; no automatic commit or progression.

## 19. Checkpoint 1.6B — Application Lifecycle and Read-Only Storage Bridge

### Objective

Create the approved minimal application factory, settings, readiness lifecycle,
and storage adapter without exposing finding routes yet.

### Why It Exists

The service must refuse unsafe or incompatible stores before returning evidence.

### Inputs

- Approved 1.6A contract and dependency decision.
- Final public Stage 1.5 query/audit functions and synthetic store fixtures.

### Expected Outputs

- Minimal `src/api/` factory/settings/adapter and `GET /healthz`.
- Approved pinned runtime/development requirements.
- Initial `tests/test_api.py`.

### Likely Files Changed

API package, the two dependency files, and the new API tests only.

### Implementation Scope

Install only with authorization, record resolved versions, check dependency
consistency, implement startup audit/snapshot matching and explicit cleanup.

### Explicitly Out of Scope

No list/detail findings, public launcher, real database serving, storage rewrite,
authentication, or alternate framework.

### Synthetic Tests

Missing/wrong/schema-corrupt/multi-run stores, missing or mismatched finding/summary
inputs, wrong run ID, import side effects, health behavior, lifecycle cleanup,
thread ownership, and unchanged fixture bytes.

### Real-Data Validation

Not required. Synthetic stores only.

### Security Interpretation Boundaries

Health means ready to serve a verified local snapshot, not "no threats."

### Acceptance Criteria

Startup fails safely on all invalid fixtures, readiness is truthful, connections
close, dependencies are documented, and full tests/pip check pass.

### Stop Conditions

Stop on auto-created stores, read/write connection fallback, missing upstream
capability, lifecycle leak, unapproved package, or unresolved runtime validation.

### Commit Gate

Report verdict and stop for explicit approval.

## 20. Checkpoint 1.6C — Versioned Finding List and Detail

### Objective

Implement the two finding routes as thin wrappers over approved read-only queries.

### Why It Exists

This is the smallest useful HTTP capability beyond service readiness.

### Inputs

- Approved lifecycle/adapter and API contract.
- Synthetic valid findings and storage fixtures.

### Expected Outputs

- Run-scoped list/detail routes, exact parameter validation, and response models.
- Contract-preserving bounded JSON serialization and route tests.

### Likely Files Changed

API routes/response code and `tests/test_api.py` only.

### Implementation Scope

Allowlisted exact filters, limit/order preservation, run-scoped lookup, no-match
behavior, complete finding/evidence responses, and no pagination promise.

### Explicitly Out of Scope

No list-runs/aggregates, raw SQL, new storage queries, unbounded export, cursor,
offset, mutation, detection execution, or real data.

### Synthetic Tests

Each filter and combination, exact lookup, empty results, wrong run, overlap,
optional/null/nested evidence, >500 matches, and byte-stable repeated responses.

### Real-Data Validation

Not required. Keep real findings out of test fixtures.

### Security Interpretation Boundaries

Return findings as stored; preserve opaque references and all uncertainty fields.

### Acceptance Criteria

Every item equals its public storage result, ordering/limits are exact, no new
security field or SQL surface exists, and full tests pass.

### Stop Conditions

Stop on type coercion, lost evidence, global-ID lookup, invented totals/cursors,
private helper imports, or unapproved upstream changes.

### Commit Gate

Report verdict and stop for explicit approval.

## 21. Checkpoint 1.6D — HTTP Safety, Error Handling, and Resource Bounds

### Objective

Complete local-host safeguards, input/output budgets, sanitized errors, logging
restrictions, and fail-closed behavior before a real listener is used.

### Why It Exists

HTTP introduces a new input boundary even for a local read-only application.

### Inputs

- Approved application/routes and Section 8–12 safety contracts.
- Synthetic malformed requests, large findings, and tampered stores.

### Expected Outputs

- Host/Origin policy, security headers, deterministic application errors, budgets.
- Leak, tamper, cleanup, and request-boundary tests.

### Likely Files Changed

API middleware/error/serialization code and API tests only.

### Implementation Scope

Reject invalid/duplicate/unknown input, enforce fixed resource bounds, close lazy
iterators on failure, sanitize exceptions/logs, and reject changed stores.

### Explicitly Out of Scope

No authentication system, rate-limiter package, public deployment, remote client,
TLS/proxy stack, database repair, or real-file tampering tests.

### Synthetic Tests

Host/Origin/forwarded-header cases, write methods, unknown keys, SQL metacharacters,
oversized output before publication, corrupted storage, 4xx/5xx sanitization,
concurrent read cleanup, and snapshot-change rejection.

### Real-Data Validation

Not required. Never corrupt the real store to test failure behavior.

### Security Interpretation Boundaries

Resource rejection is an API error, not a suspicious-event finding.

### Acceptance Criteria

All safety/error tests pass; no path/evidence/identifier/SQL leak, write operation,
unbounded response, or success-on-storage-failure remains.

### Stop Conditions

Stop on widened network policy, evidence leakage, partial response publication,
unclosed resources, or pressure to treat local-only as production security.

### Commit Gate

Report verdict and stop for explicit approval.

## 22. Checkpoint 1.6E — Local Launcher, OpenAPI, and Synthetic Integration

### Objective

Provide the fixed-local launcher, accurate OpenAPI contract, and controlled
synthetic end-to-end verification.

### Why It Exists

In-process route tests alone do not prove the documented launch and socket path.

### Inputs

- Approved safety-complete application.
- Synthetic store fixtures and local command contract.

### Expected Outputs

- `src/serve_api.py`.
- Local OpenAPI behavior and completed synthetic integration tests.
- Updated API contract with verified commands and dependency versions.

### Likely Files Changed

Launcher, minimal OpenAPI/application wiring, API tests, and the API contract.

### Implementation Scope

Enforce loopback-only single-worker settings, no reload/proxy/access logging,
truthful startup failures, safe shutdown, schema-only docs, and synthetic socket
smoke tests with bounded waits and owned-process cleanup.

### Explicitly Out of Scope

No real-data service, browser dashboard, Swagger/ReDoc UI, tunnels, LAN binding,
background daemon/automation, Docker, cloud service, or unrelated process changes.

### Synthetic Tests

Launcher flags/config, hostile environment defaults, port-in-use failure, startup
exit codes, healthy loopback requests, unsupported methods, OpenAPI reconciliation,
offline operation, and complete socket/process cleanup.

### Real-Data Validation

Not required until 1.6F.

### Security Interpretation Boundaries

OpenAPI examples must be synthetic and describe rule matches, not attacks.

### Acceptance Criteria

Documented commands match actual behavior, synthetic live HTTP passes, only the
approved surface is exposed, and no server remains after validation.

### Stop Conditions

Stop on network exposure, orphaned process, remote asset loading, misleading
OpenAPI fields, or a need to bypass machine/runtime security policy.

### Commit Gate

Report verdict and stop for explicit approval.

## 23. Checkpoint 1.6F — Real-Store API Validation

### Objective

Prove that the approved real Stage 1.5 store is served faithfully and remains
unchanged during local in-process and loopback verification.

### Why It Exists

Real contract fidelity and immutability must be measured before claiming readiness.

### Inputs

- Approved 1.6A–1.6E implementation.
- Stage 1.5 final PASS/database/logical hash and Stage 1.4 small artifacts.

### Expected Outputs

- `src/validate_api.py` and `scripts/validate_stage_1_6.ps1`.
- `docs/stage_1_6_api_findings.md` with aggregate measurements.
- Optional new ignored validation summary; no new database.

### Likely Files Changed

Validator/helper, validator tests if needed, and findings documentation only.

### Implementation Scope

Execute Section 16 exactly, including full-suite checks, all-current-finding
comparisons, body determinism, real loopback smoke, and same-file before/after
integrity. Retain only aggregate output in tracked documentation.

### Explicitly Out of Scope

No upstream detection or import rerun, source modification, forced expected count,
live real database corruption, performance target, external endpoint, or data
publication.

### Synthetic Tests

Validator refusal/cleanup/summary-publication failures use temporary fixtures.
Run complete historical and API suites before and after real validation.

### Real-Data Validation

Required: all 43 current findings, both rule counts 18/25, 25 source records, and
227 evidence entries if the approved upstream artifacts are unchanged. Validate
actual approved measurements rather than hardcoded runtime behavior.

### Security Interpretation Boundaries

Counts and equality are API/storage fidelity evidence, not security effectiveness.

### Acceptance Criteria

All findings match storage/source truth, response serialization is deterministic,
same-store/upstream hashes are unchanged, no sidecars/process remain, full tests
pass, and the measured report contains no sensitive examples.

### Stop Conditions

Stop on any count/value/hash mismatch, unexplained skip, store change, leaked
content, incomplete live validation, process leak, or non-PASS security review.

### Commit Gate

Report measured verdict and stop for explicit approval.

## 24. Checkpoint 1.6G — Documentation Reconciliation and Readiness

### Objective

Reconcile the API contract, implementation, dependency versions, tests, actual
measurements, operator commands, limitations, and upstream evidence.

### Why It Exists

A running endpoint alone is not a complete, honestly documented API foundation.

### Inputs

- All approved 1.6A–1.6F results and final Stage 1.5 contracts.
- This plan's Definition of Done.

### Expected Outputs

- Final API contract and Stage 1.6 findings document.
- Minimal README completion note only after every gate passes.

### Likely Files Changed

Documentation/README only. Correct implementation defects in their responsible
checkpoint, not through undocumented changes here.

### Implementation Scope

Perform complete diff/security review, repeat read-only validation without
overwriting retained evidence, reconcile OpenAPI and commands, and record the
actual final verdict.

### Explicitly Out of Scope

No UI, pagination, authentication, deployment, new database/source/rule, ML, or
automatic next-stage implementation.

### Synthetic Tests

Full collected regression/API suite and contract/OpenAPI reconciliation.

### Real-Data Validation

Required through the approved API validator, omitting an existing SummaryOutput
or using a new explicit output path. Preserve earlier successful evidence.

### Security Interpretation Boundaries

State "local read-only API over source-observation findings"; never claim
production readiness, attack coverage, or a complete SOC.

### Acceptance Criteria

All Definition of Done items hold, actual final verdict is PASS, known limitations
are explicit, and generated data/server processes are absent from Git/workflow.

### Stop Conditions

Stop on any unresolved upstream/API discrepancy, failed test or real-data gate,
missing approval, hidden caution, or pressure to expand the stage.

### Commit Gate

Report final verdict and request explicit approval; never commit/push automatically.

## 25. Risks and Required Controls

| Risk | Control |
| --- | --- |
| Treating Stage 1.5 predictions as execution results | Actual-state ledger and Stage 1.5G PASS prerequisite. |
| Loading the summary envelope as a flat run object | Explicit `primary_run` extraction and whole-file summary hash. |
| Accidentally re-evaluating normalized data | Distinguish audit modes; API calls storage only. |
| Inventing a database-only upstream audit | Supply the approved small finding/summary inputs at startup and validation; keep requests query-only. |
| Hiding missing storage features in HTTP code | Public-interface gate; stop for upstream contract correction. |
| Findings from different runs collide | Run-scoped identity; one configured audited store/run only. |
| List limit becomes a false completeness claim | Returned count only; no cursor/has_more/total contract. |
| Web framework changes evidence types | Exact contract serialization and full-value comparisons. |
| SQLite shared across threads | Connection ownership and consumption inside one synchronous operation. |
| HTTP reads mutate or recreate data | Read-only SQLite; no importer/startup migration; same-file integrity checks. |
| Local API exposed outside the machine | Fixed loopback launcher, strict hosts, Origin rejection, no proxy trust. |
| Local-only presented as authentication | Explicit single-user/local-process trust limitation. |
| Request/response leaks through logs/docs | Disabled access logs, sanitized errors, synthetic examples. |
| Response size exhausts resources | Fixed limits and pre-publication byte budget; no partial response. |
| Validation deletes successful evidence | Read-only revalidation and new-output-only summary publication. |
| TestClient mistaken for real transport validation | Separate owned loopback smoke test. |
| SQLite physical hash confused with logical determinism | Distinguish same-file immutability from independent-build equality. |
| Codex access failure triggers environment repair | AWAITING LOCAL VALIDATION; preserve validated Python/.venv/PATH. |

## 26. Definition of Done

Stage 1.6 is complete only when:

1. Stage 1.5G PASS and its real storage/audit/query contracts are verified.
2. All upstream compatibility requirements in this plan are resolved.
3. Framework/dependency introduction is explicitly approved and recorded.
4. Exact tested runtime/development versions are recorded and `pip check` passes.
5. Application import has no data, network, or installation side effects.
6. Startup refuses missing, corrupt, incompatible, multi-run, or wrong-run stores
   and missing/mismatched finding/summary inputs, without raw/normalized rescans.
7. Database access uses public read-only storage interfaces with safe ownership.
8. Health, run-scoped list, detail, and OpenAPI behavior match the approved contract.
9. Parameter validation, stable order, and limits match final storage semantics.
10. No unsupported pagination, filtered total, aggregate route, or completeness claim exists.
11. Every returned finding preserves exact evidence, provenance, identifiers, nulls,
    types, uncertainty, and false-positive meaning.
12. Determinism is verified for response bodies and correctly reconstructed finding
    JSONL, not arbitrary transport metadata.
13. Host/Origin/proxy/logging/error/resource safeguards pass negative tests.
14. No write, import, raw-SQL, raw-data, export-all, or new detection endpoint exists.
15. The launcher is explicitly loopback-only, single-worker, and safely stoppable.
16. Both synthetic TestClient and real loopback transport gates pass.
17. Every current approved real finding is reconciled and counts/evidence match.
18. The same database and upstream small-artifact hashes remain unchanged.
19. No generated sidecar, temporary artifact, or owned server process remains.
20. The complete collected historical/API suite passes without unexplained skips.
21. Documentation/OpenAPI use synthetic examples and report only actual results.
22. Data remains ignored/untracked, complete diff review and `git diff --check` pass.
23. No UI, remote deployment, auth system, pagination redesign, mutable storage,
    correlation, incident, scoring, ML, LLM, or second source was introduced.
24. Final checkpoint verdict is technical `PASS` with no hidden caution.

Completion means a local client can retrieve approved stored findings through a
small trustworthy HTTP boundary. It does not mean the project is production-safe,
internet-ready, a general security detector, or ready for ML without separate work.

## 27. Execution Order and Planning-Task Safety

Execute 1.6A -> 1.6B -> 1.6C -> 1.6D -> 1.6E -> 1.6F -> 1.6G, one approved
checkpoint at a time, and only after Stage 1.5G PASS.

This plan-creation task is allowed to create only this new plan file. The existing
Stage 1.5 plan and completed Stage 1.4 files are reference inputs, not edit targets.
No API implementation, database import, test modification, dependency installation,
server startup, commit, or push belongs to this task.

Official documentation links above are implementation references, not project
validation evidence. Repository facts and artifact measurements come from the
local sources identified in Sections 2–4. Recheck version-specific framework APIs
at the approved dependency checkpoint; never replace local execution evidence with
a documentation example.
