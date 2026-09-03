# Stage 1.5 — Deterministic Detection Finding Storage & Query Foundation

## Document Status

This document is a self-contained execution plan only. It does not implement
Stage 1.5, create a database, import detection findings, expose an API, modify
Stage 1.4 work, or authorize a commit or push.

The planned local database path is:

`data/processed/stage_1_5f_detection_store.sqlite3`

The generated database and other real-data artifacts must remain ignored and
untracked.

## 1. Purpose

Stage 1.5 will establish a deterministic local storage and read-only query
foundation for approved Stage 1.4 detection findings. It will use SQLite through
Python's standard-library `sqlite3` module and will not introduce an external
database service or package dependency.

The stage answers:

> How can approved, provenance-preserving detection findings be loaded into a
> constrained relational store and queried without losing their contract,
> traceability, determinism, or security interpretation boundaries?

The project roadmap places Database / Data Engineering after Rule-Based Detection
and before Backend API. Stage 1.5 therefore builds storage first. It does not build
the API, dashboard, machine learning, correlation, or incident layers.

## 2. AI Execution Context

Read this section completely before attempting any Stage 1.5 checkpoint.

### Planning-Time Project State

Stage 1.4 is complete and pushed. Its final local completion commit is
`7669a65 Complete Stage 1.4 rule-based detection foundation`; its real-data audit
commit is `da15a5b Add real-data detection validation audit`. The completed
Stage 1.4 evidence provides:

- Detection Finding Contract v1.0 and an immutable, ordered rule registry;
- a strict streaming normalized-JSONL reader and deterministic record-level engine;
- two approved `INFORMATIONAL` FortiGate source-observation rules;
- safe finding publication, a streaming finding audit, and the Stage 1.4 validator;
- deterministic finding JSONL, a bounded run summary, and reviewed limitations;
- 99 passing synthetic tests;
- 100,000 normalized records evaluated with 0 invalid normalized records;
- 43 `INFORMATIONAL` findings associated with 25 source records: 18 anomaly-subtype
  observations and 25 threat-observation findings; and
- passed determinism and provenance audits.

These are approved measured results, not future predictions or storage constants.
They must be reconciled against the approved Stage 1.4 artifacts and documentation;
storage code, schema, tests, or data must never be changed merely to force them.

The approved Stage 1.4 findings document records these artifact identities:

| Artifact | Approved SHA-256 |
| --- | --- |
| Primary finding JSONL | `5212F083BB3832158BCD650535536C22D1B8DBF582496726F998ECE949EE20DC` |
| Bounded detection summary | `D3585BF577CB1B16ACA2A8AFB65D18959941E28FC2B9CD6C396C35CF03DD16FE` |

Stage 1.5 must use approved artifact identities from the final Stage 1.4 evidence.
If a future approved Stage 1.4 artifact differs, reconciliation must use its
documented identity and must not fabricate a replacement hash.

### Stage 1.5 Start Gate

Stage 1.5 may start only when all of the following are true:

1. Checkpoint 1.4G has a final `PASS`.
2. Stage 1.4 finding and summary contracts are final and documented.
3. The complete Stage 1.1–1.4 synthetic suite passes.
4. The real Stage 1.4 finding JSONL and bounded summary exist under
   `data/processed/`.
5. Their exact hashes and counts are recorded in the approved Stage 1.4 findings
   document.
6. Stage 1.4 output audit passes.
7. Raw evidence remains unchanged and processed artifacts remain ignored/untracked.
8. There is no unresolved Stage 1.4 `PASS WITH CAUTION`, `NEEDS CONTRACT CHANGE`,
   `NEEDS SECURITY REVIEW`, or failed gate.

If any item is false, stop before Stage 1.5 implementation.

### Environment Context

The project has a validated local VS Code PowerShell environment using its working
`.venv` and Python 3.12.10. Local validation results from that environment are
authoritative execution evidence.

Some Codex execution contexts may be isolated from the user's local Windows Python
runtime. This is an execution-context limitation, not proof that Python or `.venv`
is missing. Therefore:

1. Do not reinstall Python merely because Codex cannot access it.
2. Do not rebuild `.venv` merely because Codex cannot access it.
3. Do not modify `PATH` merely to work around Codex sandbox isolation.
4. If Codex has Python access, use the validated project environment normally.
5. If Codex lacks Python access, perform only pre-runtime work, do not fabricate
   results, and stop at `AWAITING LOCAL VALIDATION`.
6. Provide exact checkpoint-relevant local commands at that stop.
7. Use `BLOCKED BY ENVIRONMENT` only when a checkpoint truly cannot proceed safely,
   not as the default Stage 1.5 state.

Baseline local commands from the repository root are:

```powershell
& .\.venv\Scripts\python.exe --version
& .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p "test_*.py" -v
```

After the Stage 1.5 validator exists:

```powershell
& .\scripts\validate_stage_1_5.ps1
```

### Mandatory Verdict Gate

Every checkpoint must end with one verdict:

- `PASS`
- `FAIL`
- `PASS WITH CAUTION`
- `AWAITING LOCAL VALIDATION`
- `BLOCKED BY ENVIRONMENT`
- `NEEDS CONTRACT CHANGE`
- `NEEDS SECURITY REVIEW`

Only `PASS` may reach a request for commit approval. A technical `PASS` does not
authorize a commit. Do not commit or push without explicit user authorization.

## 3. Authoritative Stage 1.5 Inputs

Stage 1.5 consumes only artifacts and contracts approved by Stage 1.4G:

- `data/processed/stage_1_4f_detection_findings.jsonl`;
- `data/processed/stage_1_4f_detection_summary.json`;
- `docs/detection_contract.md`;
- `docs/initial_detection_rules.md`;
- `docs/stage_1_4_detection_findings.md`;
- the public Stage 1.4 detection models and documented contract interfaces;
- exact Stage 1.4 artifact hashes and measured counts.

If final Stage 1.4 uses different approved processed filenames, checkpoint 1.5A
must reconcile the paths from final Stage 1.4 documentation without changing the
input contracts or inventing artifacts.

Stage 1.4 owns this completed upstream boundary:

```text
NormalizedSecurityEvent
        ↓
Detection evaluation
        ↓
Finding / provenance audit
```

Stage 1.5 begins only from the approved Stage 1.4 finding JSONL and detection
summary. Ordinary Stage 1.5 validation/import must directly validate their identity,
integrity, contracts, and storage-relevant internal consistency. It must not reopen
the raw FortiGate CSV or rescan the approximately 907 MB normalized-event JSONL.

In particular, Stage 1.5 must not call a Stage 1.4 audit path with a supplied run
summary when that path rescans the normalized artifact merely to repeat completed
Stage 1.4F validation. A self-contained finding-only audit may be used only if it
does not open the normalized artifact; storage's strict reader/validator remains
responsible for the required finding and summary checks. Stage 1.5 must not import
private Stage 1.4 audit helpers.

## 4. Technology Decision

Stage 1.5 uses SQLite through Python 3.12's standard-library `sqlite3` module.

Reasons:

- no new package dependency;
- no external service or credential;
- local transaction, constraint, index, and read-only-query support;
- appropriate complexity for the next incremental data-engineering stage;
- portable synthetic testing with temporary databases;
- a useful persistence boundary before a separately planned backend API.

Stage 1.5 does not introduce PostgreSQL, MySQL, MongoDB, OpenSearch,
Elasticsearch, Redis, Kafka, a cloud database, an ORM, or a migration framework.

## 5. Storage Contract v1

### Source of Truth and Storage Authority

The authority hierarchy remains explicit:

```text
Immutable raw CSV
        = original source evidence
        ↓
Normalized JSONL
        = Stage 1.3 canonical normalized event representation
        ↓
Stage 1.4 finding JSONL + summary
        = approved detection-run evidence
        ↓
Stage 1.5 SQLite
        = queryable audited persistence/projection of approved findings
```

Inside SQLite, `canonical_finding_json` preserves the original
`DetectionFinding` payload, relational finding columns are audited query
projections, and evidence rows are audited relational projections. Those
projections must not silently redefine finding semantics or replace/rewrite upstream
evidence or provenance.

### Storage Identity

- SQLite `PRAGMA user_version` is `1`.
- `storage_schema_version` is `1.0` in metadata.
- A detection `run_id` is the lowercase SHA-256 of the exact approved finding JSONL
  bytes.
- The Stage 1.4 summary artifact has its own SHA-256.
- Finding IDs remain the deterministic IDs produced by Stage 1.4 and must not be
  regenerated with a different formula.
- No import wall-clock timestamp is stored in deterministic logical content.
- Artifact paths stored in the database must be repository-relative paths or safe
  basenames, never absolute local paths.

### SQLite Settings

Every SQLite connection where referential integrity matters, including creation,
import, audit, and read-only query connections, must enable:

```sql
PRAGMA foreign_keys = ON;
```

Read-only query connections must additionally enable:

```sql
PRAGMA query_only = ON;
```

The stage must not require SQLite JSON1, WAL mode, extensions, triggers, or
environment-specific features. JSON validation and canonical serialization occur in
Python.

### Table: `storage_metadata`

| Column | Contract |
| --- | --- |
| `key TEXT PRIMARY KEY` | Stable metadata key. |
| `value TEXT NOT NULL` | Stable text value. |

Required keys include storage schema version and source finding contract version.

### Table: `detection_runs`

| Column | Contract |
| --- | --- |
| `run_id TEXT PRIMARY KEY` | SHA-256 of exact finding JSONL bytes. |
| `findings_sha256 TEXT NOT NULL UNIQUE` | Must equal `run_id`. |
| `summary_sha256 TEXT NOT NULL` | SHA-256 of exact bounded summary bytes. |
| `finding_artifact_path TEXT NOT NULL` | Repository-relative path or safe basename. |
| `summary_artifact_path TEXT NOT NULL` | Repository-relative path or safe basename. |
| `finding_schema_version TEXT NOT NULL` | Approved Stage 1.4 finding schema version. |
| `normalized_input_schema_version TEXT NOT NULL` | Approved normalized input version. |
| `normalized_input_record_count INTEGER NOT NULL` | Non-negative summary count. |
| `evaluated_record_count INTEGER NOT NULL` | Non-negative summary count. |
| `invalid_input_count INTEGER NOT NULL` | Non-negative summary count. |
| `total_finding_count INTEGER NOT NULL` | Non-negative and reconciled. |
| `unique_matched_source_record_count INTEGER NOT NULL` | Non-negative and reconciled. |

Integer counts require `CHECK` constraints preventing negative values.

### Table: `run_rules`

| Column | Contract |
| --- | --- |
| `run_id TEXT NOT NULL` | Foreign key to `detection_runs`. |
| `ordinal INTEGER NOT NULL` | Zero-based stable active-rule position. |
| `rule_id TEXT NOT NULL` | Approved rule ID. |
| `rule_version TEXT NOT NULL` | Approved rule version. |

Constraints:

- primary key `(run_id, ordinal)`;
- unique `(run_id, rule_id, rule_version)`;
- non-negative ordinal;
- foreign key to `detection_runs`.

The unique rule identity is a candidate key for the composite finding reference
below.

### Table: `findings`

| Column | Contract |
| --- | --- |
| `run_id TEXT NOT NULL` | Foreign key to `detection_runs`. |
| `finding_id TEXT NOT NULL` | Stage 1.4 deterministic finding ID. |
| `finding_schema_version TEXT NOT NULL` | Approved contract version. |
| `rule_id TEXT NOT NULL` | Rule identity. |
| `rule_version TEXT NOT NULL` | Rule version. |
| `rule_name TEXT NOT NULL` | Neutral rule name. |
| `rule_category TEXT NOT NULL` | Approved rule category. |
| `rule_severity TEXT NOT NULL` | Review priority, not attack severity. |
| `source_type TEXT NOT NULL` | Source adapter type. |
| `normalized_schema_version TEXT NOT NULL` | Upstream normalized schema. |
| `source_record_number INTEGER NOT NULL` | Positive logical record number. |
| `source_record_id TEXT` | Opaque ID or null. |
| `reason_code TEXT NOT NULL` | Stable match reason. |
| `summary TEXT NOT NULL` | Neutral finding summary. |
| `time_basis TEXT NOT NULL` | `NOT_USED` for Stage 1.4 v1 findings. |
| `uncertainties_json TEXT NOT NULL` | Canonical JSON array. |
| `false_positive_note TEXT NOT NULL` | Required ambiguity boundary. |
| `deterministic INTEGER NOT NULL` | Must be `1`. |
| `canonical_finding_json TEXT NOT NULL` | Complete canonical finding JSON. |

Constraints:

- primary key `(run_id, finding_id)`;
- positive source record number;
- deterministic flag equals `1`;
- foreign key to `detection_runs`;
- composite foreign key `(run_id, rule_id, rule_version)` to
  `run_rules(run_id, rule_id, rule_version)`.

The database must enforce the rule/version snapshot relationship. Application-side
reconciliation and the storage audit remain required, but do not replace this
foreign-key constraint.

### Table: `finding_evidence`

| Column | Contract |
| --- | --- |
| `run_id TEXT NOT NULL` | Detection run identity. |
| `finding_id TEXT NOT NULL` | Parent finding. |
| `ordinal INTEGER NOT NULL` | Zero-based canonical evidence order. |
| `canonical_path TEXT NOT NULL` | Normalized canonical path. |
| `observed_value_json TEXT NOT NULL` | Canonical JSON value. |
| `source_fields_json TEXT NOT NULL` | Canonical ordered JSON array. |
| `mapping_operation TEXT NOT NULL` | Stage 1.3 mapping operation. |
| `interpretation_status TEXT NOT NULL` | Stage 1.3 interpretation status. |

Constraints:

- primary key `(run_id, finding_id, ordinal)`;
- unique `(run_id, finding_id, canonical_path)`;
- non-negative ordinal;
- foreign key `(run_id, finding_id)` to `findings`;
- no missing or duplicate evidence path.

### Required Indexes

- `(run_id, source_record_number, rule_id, finding_id)`;
- `(run_id, rule_id, source_record_number, finding_id)`;
- `(run_id, rule_severity, source_record_number, finding_id)`;
- `(run_id, reason_code, source_record_number, finding_id)`;
- `(run_id, source_type, source_record_number, finding_id)`;
- `(run_id, canonical_path, finding_id)` on evidence.

## 6. Determinism Policy

SQLite database bytes are not a cross-environment determinism contract. SQLite
versions or page layout may produce different database-file hashes despite equal
logical content.

Stage 1.5 proves determinism using:

- deterministic Stage 1.4 input hashes;
- deterministic `run_id`;
- stable validation and insertion order;
- canonical JSON serialization with sorted object keys and compact separators;
- stable query order;
- canonical logical export;
- SHA-256 of the canonical logical export;
- exact reconstruction of the Stage 1.4 finding JSONL and comparison with the
  approved input hash.

Two stores created from equal approved inputs must have equal logical export hashes
and equal reconstructed finding JSONL hashes. Their SQLite database-file hashes are
not required to match.

### Single-Run Workflow and Idempotency Boundary

Stage 1.5 v1 is a single-run, create-new-database workflow. Deterministic run and
finding identities support reproducibility and identity; transactional import and
non-overwriting publication prevent partial or accidental duplicate database
creation at the same destination.

This is not full mutable-database idempotency. Multi-run append semantics,
re-import/update semantics, delete/retention behavior, and importing into an
existing database remain future work. An existing final database is rejected rather
than appended to or mutated.

## 7. Import Contract

Planned public interface:

```python
import_detection_run(
    findings_path: str | Path,
    summary_path: str | Path,
    database_path: str | Path,
) -> StorageImportSummary
```

The importer must:

1. require existing regular finding and summary input files;
2. require a new database output under `data/processed/`;
3. reject input/output equality and any existing output;
4. hash both inputs before parsing;
5. directly validate the approved finding and summary artifacts against their
   documented Stage 1.4 identities and contracts without opening raw CSV or
   normalized JSONL;
6. strictly reconstruct and validate each `DetectionFinding` with public Stage 1.4
   models, without importing private audit helpers;
7. reconcile finding order, IDs, counts, rule metadata, active rules, severities,
   unique source-record count, and summary values;
8. create a uniquely named temporary SQLite file in the output directory;
9. create the exact schema and indexes;
10. use one transaction for logical import;
11. insert findings in Stage 1.4 deterministic order;
12. commit and close the temporary database;
13. run schema, integrity, foreign-key, row-count, evidence, and round-trip audits;
14. publish with a non-overwriting rename only after every check passes;
15. return a bounded deterministic `StorageImportSummary`;
16. print no unbounded finding or evidence collection.

On failure, the importer must roll back, publish no final database, and remove only
the verified temporary file created by the current invocation.

Stage 1.5 v1 creates a new database containing exactly one validated detection run.
It rejects an existing final output instead of appending to or mutating it.
Although the schema keeps a run identity, append, update, delete, re-import,
retention, and migration workflows are outside this stage.

Planned PowerShell-compatible CLI:

```powershell
& .\.venv\Scripts\python.exe .\src\load_detection_store.py `
  --findings .\data\processed\stage_1_4f_detection_findings.jsonl `
  --summary .\data\processed\stage_1_4f_detection_summary.json `
  --database .\data\processed\stage_1_5f_detection_store.sqlite3
```

## 8. Query Contract

Planned public types and interfaces:

```python
@dataclass(frozen=True)
class FindingQuery:
    run_id: str | None = None
    finding_id: str | None = None
    rule_id: str | None = None
    rule_version: str | None = None
    severity: str | None = None
    reason_code: str | None = None
    source_type: str | None = None
    source_record_number: int | None = None
    evidence_path: str | None = None
    limit: int = 50

get_stored_finding(
    database_path: str | Path,
    run_id: str,
    finding_id: str,
) -> DetectionFinding | None

iter_stored_findings(
    database_path: str | Path,
    query: FindingQuery,
) -> Iterator[DetectionFinding]
```

Query rules:

- open the database through SQLite read-only URI mode;
- enable `query_only` and foreign keys;
- accept only allowlisted typed filters;
- use parameterized SQL values exclusively;
- accept no raw SQL, SQL fragments, arbitrary columns, or arbitrary order clauses;
- default limit is 50 and maximum limit is 500;
- reject boolean, zero, negative, or excessive limits;
- order results by run ID, source record number, rule ID, and finding ID;
- reconstruct and validate complete `DetectionFinding` objects;
- reject stored canonical JSON that disagrees with relational columns/evidence;
- never infer attack, incident, confidence, risk, or malicious/benign status;
- provide no time filter because Stage 1.4 uses `time_basis = NOT_USED`.

Planned query CLI:

```powershell
& .\.venv\Scripts\python.exe .\src\query_detection_store.py `
  --database .\data\processed\stage_1_5f_detection_store.sqlite3 `
  --rule-id fortigate.source_threat_observation `
  --limit 50
```

The CLI emits compact deterministic JSON Lines to stdout, concise errors to stderr,
and a nonzero exit code on failure. It must not emit an unbounded result.

## 9. Storage Audit Contract

The independent storage audit must check:

- exact schema version, table names, columns, constraints, and indexes;
- `PRAGMA integrity_check`;
- `PRAGMA foreign_key_check`;
- required metadata keys;
- artifact hashes and deterministic `run_id`;
- run summary counts;
- active rule order and versions;
- finding count, uniqueness, order, rule references, severities, and source trace;
- canonical finding JSON against every relational finding column;
- evidence ordinal, path, observed value, source fields, mapping operation, and
  interpretation status;
- count reconciliation by rule, severity, reason, and unique source record;
- absence of prohibited attack, incident, risk, confidence, malicious/benign, ML,
  or API fields;
- canonical logical export hash;
- reconstructed finding JSONL hash against the approved Stage 1.4 input.

The audit must be streaming or bounded. It must not load every finding or evidence
row into memory even if the current real finding count is small. It directly audits
the Stage 1.4 finding and summary artifacts plus the SQLite store; it never opens
the raw CSV or normalized-event JSONL.

## 10. Planned Deliverables

| Deliverable | Planned path |
| --- | --- |
| Stage execution plan | `docs/plans/stage_1_5_detection_storage_plan.md` |
| Storage contract | `docs/detection_storage_contract.md` |
| Storage package | `src/storage/` |
| Import CLI | `src/load_detection_store.py` |
| Query CLI | `src/query_detection_store.py` |
| Independent audit CLI | `src/audit_detection_store.py` |
| Synthetic tests | `tests/test_detection_storage.py` |
| Local validator | `scripts/validate_stage_1_5.ps1` |
| Real-data findings | `docs/stage_1_5_storage_findings.md` |
| Generated database | `data/processed/stage_1_5f_detection_store.sqlite3` (ignored) |

Do not reorganize Stage 1.1–1.4 modules. The storage package may import public
Stage 1.4 contracts. Detection and normalization must not import storage.

## 11. Checkpoint Gate

For each checkpoint:

```text
READ CONTEXT
  -> VERIFY STAGE 1.4 PASS WHEN REQUIRED
  -> STATE CHECKPOINT OBJECTIVE
  -> IMPLEMENT MINIMUM APPROVED CHANGE
  -> RUN COMPLETE AVAILABLE TEST SUITE
  -> RUN CHECKPOINT-SPECIFIC VALIDATION
  -> REAL-DATA VALIDATION ONLY WHEN REQUIRED
  -> REVIEW STORAGE AND SECURITY BOUNDARIES
  -> git diff --check
  -> COMPLETE DIFF REVIEW
  -> VERDICT
  -> REQUEST APPROVAL
  -> LOCAL COMMIT ONLY WITH EXPLICIT AUTHORIZATION
```

Never start the next checkpoint automatically.

## 12. Checkpoint 1.5A — Storage Contract and SQLite Schema

### Objective

Define storage terminology, schema v1, constraints, indexes, deterministic run
identity, logical determinism, and immutable result contracts.

### Why It Exists

The relational boundary must preserve the Stage 1.4 contract before any importer or
query code is written.

### Inputs

- Final approved Stage 1.4 contracts and findings documentation.
- Sections 3–9 of this plan.
- Repository dependency, data, and Git policies.

### Expected Outputs

- `docs/detection_storage_contract.md`.
- Minimal `src/storage/` package with schema and immutable result/query models.
- Schema-focused start of `tests/test_detection_storage.py`.

### Likely Files Changed

Only the contract, storage package files required for schema/model definitions, and
the storage test file.

### Implementation Scope

- Exact schema DDL and indexes.
- `StorageImportSummary`, `StorageAuditResult`, and `FindingQuery` contracts.
- Path-independent deterministic metadata policy.
- Logical export format and version.
- Connection helpers that always enable required pragmas.

### Explicitly Out of Scope

No finding import, query CLI, real-data access, API, ORM, migration framework,
external database, append workflow, or Stage 1.4 modification.

### Synthetic Tests

- Exact tables, columns, primary keys, unique constraints, foreign keys, checks, and
  indexes.
- Composite rule/version foreign-key rejection for a finding whose
  `(run_id, rule_id, rule_version)` is absent from `run_rules`.
- Required metadata and `user_version`.
- invalid query/result model values.
- foreign keys enabled and enforced for every relevant connection.
- no dependency or extension requirement.

### Real-Data Validation

Not required. Do not read Stage 1.4 finding artifacts.

### Security Interpretation Boundaries

Storage preserves findings; it does not upgrade findings into alerts, attacks,
incidents, risk, confidence, or ground truth.

### Acceptance Criteria

- Schema can preserve every DetectionFinding v1.0 field and evidence entry.
- Constraints protect identity, counts, ordering, run rules, and references.
- Logical determinism policy explicitly rejects database-file hash equivalence.
- Complete suite passes and diff contains no generated database.

### Stop Conditions

Stop if Stage 1.4G is not `PASS`, final contracts are unavailable, schema requires a
Stage 1.4 change, an external dependency is required, or security meaning is added.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 13. Checkpoint 1.5B — Strict Finding and Summary Input Validation

### Objective

Build a bounded strict reader for approved Stage 1.4 finding JSONL and summary JSON.

### Why It Exists

Untrusted, malformed, incomplete, or unreconciled input must never enter the
database.

### Inputs

- Approved 1.5A contracts.
- Public Stage 1.4 finding models and documented finding contract boundary.
- Small synthetic finding and summary fixtures.

### Expected Outputs

- Strict storage-input reader/validator under `src/storage/`.
- Input-validation tests.

### Likely Files Changed

Only storage input code and `tests/test_detection_storage.py`.

### Implementation Scope

- UTF-8 JSONL streaming.
- Strict finding reconstruction.
- Summary reconstruction and cross-reconciliation.
- Hashing, order, duplicate, schema, ID, rule, count, and evidence validation against
  approved Stage 1.4 artifact identity/evidence.
- Structured errors with line number and stable reason code.
- No opening of raw CSV or normalized-event JSONL and no private Stage 1.4 audit
  helper import.

### Explicitly Out of Scope

No database creation, real-data scan, query, Stage 1.4 weakening, silent repair, or
private-helper import.

### Synthetic Tests

- Empty valid run and valid one/multiple finding runs.
- Blank line, malformed JSON, wrong schema, wrong ID, duplicate ID, invalid evidence,
  unsupported rule metadata, wrong order, missing summary field, and every count
  mismatch.
- Equivalent approved artifact bytes produce the same deterministic run identity.
- Validation refuses mismatched approved artifact identity/evidence and proves it does
  not open raw CSV or normalized-event JSONL.
- Bounded processing and deterministic error behavior.

### Real-Data Validation

Not required. Real artifacts remain unopened until checkpoint 1.5F.

### Security Interpretation Boundaries

Input validation verifies contracts, not attack truth or detection accuracy.

### Acceptance Criteria

- Every invalid fixture fails explicitly.
- No line is silently skipped or repaired.
- Reader uses public contracts and bounded memory.
- Complete suite passes.

### Stop Conditions

Stop if safe reconstruction requires a Stage 1.4 contract change, public contracts
are insufficient, summary meaning is ambiguous, or validation must be weakened.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 14. Checkpoint 1.5C — Transactional Deterministic Import

### Objective

Create a new SQLite database from one validated detection run using a single logical
transaction and safe publish-on-success behavior.

### Why It Exists

Database creation must not leave partial, inconsistent, or silently overwritten
artifacts.

### Inputs

- Approved 1.5A–1.5B contracts and reader.
- Small synthetic findings and summaries.

### Expected Outputs

- Import implementation under `src/storage/`.
- `src/load_detection_store.py`.
- Import and CLI tests.

### Likely Files Changed

Only storage import code, import CLI, and storage tests.

### Implementation Scope

- Safe path checks and temporary database creation.
- Exact DDL/index application.
- One transaction and stable insertion order.
- Finding/evidence decomposition plus canonical JSON preservation.
- Bounded deterministic import summary.
- Pre-publish integrity and reconciliation checks.
- Atomic non-overwriting publish.

### Explicitly Out of Scope

No append, update, delete, overwrite, migration, multi-run CLI, query, real-data run,
or external database.

### Synthetic Tests

- Empty, one-finding, multi-rule, overlapping source-record, and multi-evidence runs.
- Duplicate IDs, foreign-key failure, injected mid-import failure, rollback, existing
  output, input/output equality, missing parent, unsafe path, temporary cleanup, and
  no partial publish.
- Existing final output is rejected safely as a create-new-database workflow, not
  treated as append idempotency.

### Real-Data Validation

Not required.

### Security Interpretation Boundaries

Importer stores approved meaning exactly and must not add classifications or alter
severity.

### Acceptance Criteria

- Counts and evidence reconcile exactly.
- Failed imports publish no final database.
- Import summary is bounded and deterministic.
- Complete suite passes and no generated data enters Git.

### Stop Conditions

Stop on transaction weakness, unsafe path/delete behavior, silent deduplication,
evidence loss, nondeterminism, or dependency expansion.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 15. Checkpoint 1.5D — Read-Only Query Interface and CLI

### Objective

Provide a typed, allowlisted, bounded read-only query interface and deterministic
JSONL CLI.

### Why It Exists

Stored findings must be useful without exposing arbitrary SQL or mutable database
behavior.

### Inputs

- Approved 1.5A–1.5C storage implementation.
- Synthetic SQLite databases created by the importer.

### Expected Outputs

- Query implementation under `src/storage/`.
- `src/query_detection_store.py`.
- Query and CLI tests.

### Likely Files Changed

Only query code, query CLI, package exports, and storage tests.

### Implementation Scope

- Exact `FindingQuery` filters.
- Parameterized SQL and fixed ordering.
- Read-only SQLite connection.
- Full finding reconstruction and reconciliation.
- Default/maximum limits.
- Compact JSONL stdout and concise stderr errors.

### Explicitly Out of Scope

No raw SQL, write query, arbitrary sort, pagination cursor, API, dashboard, time
query, incident workflow, or unbounded export.

### Synthetic Tests

- Each filter independently and approved combinations.
- Exact/no-match lookup.
- stable ordering and limits.
- SQL metacharacters treated as values.
- attempted database mutation rejected.
- corrupted stored canonical JSON or relational mismatch rejected.
- repeat query produces byte-identical output.

### Real-Data Validation

Not required until 1.5F.

### Security Interpretation Boundaries

Query results remain findings and never become confirmed attacks or incidents.

### Acceptance Criteria

- No arbitrary SQL surface exists.
- Connections are read-only.
- Every returned finding passes Stage 1.4 validation.
- Output is bounded and deterministic.
- Complete suite passes.

### Stop Conditions

Stop on SQL injection surface, mutable query behavior, unbounded output, contract
loss, unstable ordering, or security conclusion expansion.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 16. Checkpoint 1.5E — Storage Audit and Round-Trip Verification

### Objective

Build an independent audit that proves relational integrity, semantic fidelity, and
exact finding round trip.

### Why It Exists

A successful SQLite import is not sufficient evidence that the full contract and
provenance were preserved.

### Inputs

- Approved 1.5A–1.5D implementation.
- Synthetic valid and tampered databases.

### Expected Outputs

- Storage audit implementation under `src/storage/`.
- `src/audit_detection_store.py`.
- Audit and tamper tests.

### Likely Files Changed

Only storage audit code, audit CLI, package exports, and storage tests.

### Implementation Scope

- Schema/index/constraint signature checks.
- Integrity and foreign-key checks.
- Row/count/rule/evidence reconciliation.
- Relational versus canonical-JSON comparison.
- Canonical logical export and hash.
- Exact reconstructed finding JSONL and hash.
- Bounded audit result and concise failures.

### Explicitly Out of Scope

No database repair, migration, mutation, real-data run, API, security scoring, or
SQLite file-byte determinism requirement.

### Synthetic Tests

- Tampered metadata, schema version, run hash, count, rule, finding field, canonical
  JSON, evidence value/order/path, missing row, extra row, foreign key, index, and
  prohibited field.
- Equal logical imports produce equal logical hashes.
- Equal inputs reconstruct byte-identical finding JSONL.
- Canonical finding JSON, relational finding columns, and relational evidence rows
  round-trip consistently.

### Real-Data Validation

Not required until 1.5F.

### Security Interpretation Boundaries

Audit proves storage fidelity, not finding correctness against attack ground truth.

### Acceptance Criteria

- Every tamper case fails with a structured reason.
- Valid stores pass all reconciliation and round-trip checks.
- Audit is bounded and independent of importer success.
- Complete suite passes.

### Stop Conditions

Stop if audit relies only on row counts, trusts canonical JSON without relational
comparison, requires mutation, or cannot prove round-trip fidelity.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 17. Checkpoint 1.5F — Real-Data Storage Validation

### Objective

Import only the final approved Stage 1.4 finding artifacts, audit all stored content,
and document measured behavior without security overclaiming.

### Why It Exists

Synthetic correctness must be reconciled with the actual Stage 1.4 findings before
the storage foundation is declared ready.

### Inputs

- Approved 1.5A–1.5E implementation.
- Final Stage 1.4F/G finding JSONL, summary, hashes, counts, rules, and verdict.

### Expected Outputs

- `scripts/validate_stage_1_5.ps1`.
- Ignored primary SQLite database and verified temporary second-run artifacts.
- `docs/stage_1_5_storage_findings.md`.

### Likely Files Changed

Only the validator and findings document are tracked. Generated database and export
artifacts remain ignored/untracked.

### Implementation Scope

1. Verify Stage 1.4 final `PASS`, authoritative finding/summary artifacts, and their
   approved documented identities.
2. Run the complete synthetic suite.
3. Hash Stage 1.4 finding and summary inputs; do not open raw CSV or normalized
   JSONL to repeat the completed upstream audit.
4. Build the primary Stage 1.5 database.
5. Run full storage audit.
6. Query and reconcile counts by rule, severity, reason, source, and unique source
   record.
7. Reconstruct finding JSONL and compare its hash with Stage 1.4.
8. Build a second database at a separate verified temporary processed path.
9. Compare canonical logical export hashes and query output hashes.
10. Remove only verified second-run temporary artifacts.
11. Rerun the complete test suite.
12. Check Git status, ignored outputs, the no-open raw/normalized boundary, and
    `git diff --check`.
13. Document actual measurements, limitations, and verdict.

### Explicitly Out of Scope

No tuning to force counts, new detection rules, raw/normalized import or rescan, API,
dashboard, performance claim, attack claim, database-file hash comparison, or schema
expansion.

### Synthetic Tests

Complete Stage 1.1–1.5 suite before and after the real-data run. Validator failure
paths require small safe tests where practical.

### Real-Data Validation

Required. The database must contain exactly the approved Stage 1.4 logical finding
set, using only the approved finding JSONL and summary as its real-data inputs. The
approved Stage 1.4 evidence records 25 threat-observation findings, 18
anomaly-subtype findings, 43 total `INFORMATIONAL` findings, and 25 unique matched
source records. A mismatch must stop for investigation; it must never be addressed
by tuning storage logic or test data.

### Security Interpretation Boundaries

Stored rows are rule findings. Row counts are not attack counts, incidents,
precision, recall, detection rate, or ground truth.

### Acceptance Criteria

- Input hashes match final Stage 1.4 evidence.
- Stored finding and evidence counts reconcile completely.
- Counts by every documented dimension equal Stage 1.4 summary.
- Reconstructed finding JSONL hash equals the approved Stage 1.4 hash.
- Two imports have equal logical export hashes and deterministic query output.
- Integrity, foreign-key, complete tests, Git safety, and the no-open
  raw/normalized boundary pass.
- Findings documentation contains measured aggregate facts only.
- Validation/import never rescans raw CSV or normalized-event JSONL.

### Stop Conditions

Stop on missing/mismatched Stage 1.4 artifacts, count mismatch, evidence loss,
round-trip mismatch, integrity failure, nondeterminism, test failure, generated-file
tracking, or non-PASS security review.

### Commit Gate

Report measured verdict and request explicit approval before a local commit.

## 18. Checkpoint 1.5G — Final Documentation and Readiness Gate

### Objective

Reconcile schema, importer, query behavior, audit, tests, measured storage results,
limitations, and upstream Stage 1.4 contracts.

### Why It Exists

Stage completion requires documented contract agreement and an honest readiness
verdict, not only a database that opens successfully.

### Inputs

- All approved 1.5A–1.5F outputs.
- Final Stage 1.4 contracts and measured evidence.

### Expected Outputs

- Final `docs/detection_storage_contract.md`.
- Final `docs/stage_1_5_storage_findings.md`.
- Minimal `README.md` completion update only after every gate passes.

### Likely Files Changed

Documentation and README only unless reconciliation identifies a defect, in which
case stop and fix it within the responsible checkpoint.

### Implementation Scope

- Cross-check DDL, code, CLI, tests, hashes, queries, audits, and documentation.
- Run final validator and complete diff/security review.
- Record actual `PASS` or non-PASS verdict.
- State readiness for a separately planned read-only backend API stage.

### Explicitly Out of Scope

No API implementation, FastAPI, frontend, authentication, pagination protocol,
database mutation, new rule, correlation, incident, ML, LLM, or deployment.

### Synthetic Tests

Complete Stage 1.1–1.5 suite and documentation/schema reconciliation tests.

### Real-Data Validation

Required through the approved Stage 1.5 validator only; it must preserve the
Stage 1.5 input boundary and not rescan raw CSV or normalized-event JSONL.

### Security Interpretation Boundaries

Final documentation must preserve Rule Match != Confirmed Attack and must not report
stored finding counts as attack or incident counts.

### Acceptance Criteria

- Definition of Done is fully satisfied.
- Storage contract, schema, implementation, tests, audit, and measurements agree.
- Final verdict is `PASS` with no hidden caution.
- Generated artifacts remain ignored and upstream evidence remains immutable.

### Stop Conditions

Stop with the actual non-PASS verdict on any inconsistency, failed gate, unresolved
security concern, or incomplete Stage 1.4 reconciliation. Do not begin an API stage.

### Commit Gate

Report final verdict and request explicit approval before a local commit.

## 19. Synthetic Testing Strategy

Use `unittest`, temporary directories, temporary SQLite files, and small synthetic
DetectionFinding objects. Synthetic tests must not require the real finding JSONL,
the 907 MB normalized artifact, or the raw CSV.

Required coverage includes:

- schema signatures, constraints, indexes, and pragmas;
- valid and invalid immutable storage/query result models;
- strict JSONL and summary reconstruction;
- artifact hashing checked against approved Stage 1.4 evidence and deterministic run
  identity for equivalent approved artifact bytes;
- invalid schema, malformed JSON, wrong finding ID, wrong order, duplicates, and
  every count mismatch;
- composite foreign-key rejection for undeclared `(run_id, rule_id, rule_version)`
  and proof that foreign-key enforcement is active;
- transactional import, rollback, atomic publish, safe cleanup, and safe rejection
  of an existing final output;
- exact canonical JSON/evidence decomposition;
- read-only allowlisted queries and SQL-injection resistance;
- stable ordering and bounded output;
- schema/integrity/foreign-key audits;
- tampered metadata, relational fields, canonical JSON, and evidence;
- canonical logical export determinism;
- exact finding JSONL round trip plus canonical-finding/relational-projection
  consistency;
- proof that storage validation/import does not open raw CSV or normalized JSONL;
- complete Stage 1.1–1.4 regression suite remains passing.

## 20. Real-Data Validation Strategy

Real-data validation begins only at 1.5F and only after Stage 1.4G `PASS`. Its
real-data inputs are the approved Stage 1.4 finding JSONL and summary only; it must
not reprocess raw CSV or the approximately 907 MB normalized JSONL.

The authoritative reconciliation facts are the approved Stage 1.4 measured values:
25 threat-observation findings, 18 anomaly-subtype findings, 43 total
`INFORMATIONAL` findings, and 25 unique matched source records. They are evidence to
verify, not values to force into storage code or synthetic tests.

The validator must record:

- Stage 1.4 input paths and hashes;
- storage run ID;
- finding and summary schema versions;
- imported finding count;
- evidence row count;
- counts by rule, severity, reason, and source;
- unique source-record count;
- integrity and foreign-key results;
- canonical logical export hash;
- reconstructed finding JSONL hash;
- complete test result;
- Git/raw/processed tracking safety result and no-open raw/normalized boundary;
- actual verdict and limitations.

Runtime measurements may be reported as environment-specific observations but are
not acceptance thresholds and must not be fabricated.

## 21. Out of Scope

Stage 1.5 does not implement:

- raw or normalized-event database storage;
- reopening or rescanning raw CSV or normalized JSONL to repeat completed Stage 1.4
  detection/provenance validation;
- additional detection rules;
- threshold, time-window, rate, frequency, or stateful detection;
- alert suppression or prioritization;
- event correlation or incident management;
- attack, malicious/benign, confidence, or risk labels;
- PostgreSQL, MySQL, MongoDB, OpenSearch, Elasticsearch, Redis, or Kafka;
- ORM or migration framework;
- mutable multi-run append/update/delete/retention workflow;
- raw SQL query interface;
- FastAPI, Flask, Django, frontend, dashboard, or API;
- authentication or authorization;
- machine learning, anomaly model, LLM, RAG, or vector database;
- Docker, Kubernetes, cloud deployment, or external service;
- second log-source support;
- Stage 1.3 or Stage 1.4 contract changes without a separate stop and approval.

## 22. Risks and Controls

| Risk | Required control |
| --- | --- |
| Incomplete Stage 1.4 used as input | Mandatory 1.4G `PASS` start gate. |
| Expected 43 findings forced into storage | Use final approved Stage 1.4 actual counts. |
| Finding becomes an attack/incident row | Preserve Stage 1.4 terminology and fields exactly. |
| Evidence/provenance lost relationally | Canonical JSON plus normalized evidence table and audit. |
| Finding references an undeclared rule/version | Composite foreign key to `run_rules` with foreign keys enabled on every relevant connection. |
| Duplicate finding silently merged | Composite primary key and explicit duplicate failure. |
| Partial database published | One transaction, temporary database, audit, atomic non-overwrite publish. |
| Existing database overwritten | Reject existing output; no overwrite flag. |
| SQL injection | Typed allowlisted filters and parameterized SQL only. |
| Query mutates data | SQLite read-only URI and `query_only`. |
| Unbounded query output | Default 50, maximum 500, streaming JSONL. |
| SQLite file hashes differ | Compare logical export and reconstructed finding hashes instead. |
| Storage repeats the 907 MB upstream audit | Treat approved Stage 1.4 finding JSONL/summary as the input boundary; never reopen raw/normalized artifacts. |
| JSON extension unavailable | Parse and canonicalize JSON in Python; no JSON1 dependency. |
| Generated database enters Git | Store under ignored `data/processed/` and inspect status/ls-files. |
| Codex cannot access local Python | Stop at `AWAITING LOCAL VALIDATION`; do not repair working local environment. |
| Agent advances automatically | Mandatory checkpoint verdict and approval gate. |

## 23. Definition of Done

Stage 1.5 is complete only when:

1. Stage 1.4G has a final `PASS`.
2. Storage schema v1 is documented and implemented exactly.
3. Approved finding JSONL and summary inputs are strictly validated.
4. Input artifacts have recorded and verified hashes.
5. A database is created transactionally at a new safe processed path.
6. Failed imports publish no partial database.
7. Every finding retains complete contract fields and canonical JSON.
8. Every evidence item retains path, value, source fields, mapping operation, and
   interpretation status.
9. Finding and evidence identities, order, uniqueness, and counts reconcile.
10. Active rules and run summary metadata reconcile with Stage 1.4.
11. Query access is read-only, typed, parameterized, bounded, and deterministic.
12. No arbitrary SQL surface exists.
13. Every queried finding reconstructs under Detection Finding Contract v1.0.
14. Storage audit passes schema, integrity, foreign-key, semantic, and security checks.
15. Canonical logical export is deterministic for equal inputs.
16. Reconstructed finding JSONL hash equals the approved Stage 1.4 hash.
17. Real stored counts equal final approved Stage 1.4 counts without forced tuning.
18. Raw evidence and normalized artifacts remain immutable/read-only and are never
    reopened by Stage 1.5 validation/import.
19. Generated databases and exports remain ignored and untracked.
20. All Stage 1.1–1.5 synthetic tests pass under Python 3.12.
21. Documentation reports storage facts without attack, incident, accuracy, or
   performance fabrication.
22. `git diff --check`, complete diff review, and security review pass.
23. Final checkpoint verdict is `PASS`.
24. No API, dashboard, mutable data service, new rule, correlation, incident, ML,
   LLM, external database, second source, or deployment work was introduced.

Completion means the project has a trustworthy local detection-finding storage and
query foundation ready for a separately planned read-only backend API stage. It does
not mean an API, SIEM, incident system, ML model, or production platform exists.

## 24. Suggested Execution Order

Execute exactly one checkpoint at a time:

1. **1.5A — Storage Contract and SQLite Schema**
2. **1.5B — Strict Finding and Summary Input Validation**
3. **1.5C — Transactional Deterministic Import**
4. **1.5D — Read-Only Query Interface and CLI**
5. **1.5E — Storage Audit and Round-Trip Verification**
6. **1.5F — Real-Data Storage Validation**
7. **1.5G — Final Documentation and Readiness Gate**

At each checkpoint report changed files, behavior, input contracts, tests,
validation, measured results, limitations, security interpretation review, verdict,
and the smallest next checkpoint. Do not implement the next checkpoint until the
gate and required user approval allow it.
