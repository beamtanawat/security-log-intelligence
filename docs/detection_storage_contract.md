# Detection Finding Storage Contract v1.0

## Status and purpose

This document defines the completed Stage 1.5 contract for one approved Stage 1.4
detection run. It covers strict artifact validation, SQLite storage, bounded
read-only queries, and an independent storage audit.

The database is an audited, queryable projection of approved Stage 1.4 evidence.
It does not create a new security conclusion.

Rule Match != Confirmed Attack.

## Authority hierarchy

```text
Immutable raw CSV
        = original source evidence
        ↓
Stage 1.3 normalized JSONL
        = canonical normalized event representation
        ↓
Approved Stage 1.4 finding JSONL + summary
        = approved detection-run evidence
        ↓
Stage 1.5 SQLite
        = audited queryable projection of approved findings
```

`canonical_finding_json` preserves the complete original `DetectionFinding`
payload. Relational finding columns and `finding_evidence` rows are audited query
projections. They must not silently alter Stage 1.4 finding semantics, evidence, or
provenance. SQLite does not replace raw evidence, normalized-event semantics, or
Stage 1.4 detection evidence.

## Version and identity

- SQLite `PRAGMA user_version` is `1`.
- Metadata key `storage_schema_version` is `1.0`.
- Metadata key `source_finding_contract_version` is Stage 1.4 Detection Finding
  Contract version `1.0`.
- `run_id` is the lowercase SHA-256 of the exact approved finding JSONL bytes.
  It equals `findings_sha256`.
- `finding_id` remains the Stage 1.4 deterministic finding identity. Stage 1.5 does
  not generate a replacement identity.
- `summary_sha256` identifies the exact bounded Stage 1.4 summary bytes.
- The approved Stage 1.4F summary is an exact validation envelope. Its
  `primary_run` object is the strict `DetectionRunSummary` used for storage
  reconciliation; `summary_sha256` still identifies the complete envelope bytes,
  not a serialization of `primary_run`.
- The strict reader also preserves its existing direct `DetectionRunSummary` input
  shape for synthetic/public-contract fixtures. It dispatches only between that
  exact flat shape and the exact Stage 1.4F envelope shape; arbitrary nested
  summaries are rejected.
- Logical content contains no import wall-clock timestamp or absolute local path.

Stage 1.5 v1 is a **single-run, create-new-database** workflow. Deterministic
identity supports reproducibility; it is not append, update, delete, re-import, or
mutable-database idempotency. An existing final database is rejected rather than
mutated or overwritten.

## SQLite connection requirements

Every creation, import, audit, or read-only query connection that relies on
referential integrity must execute and verify:

```sql
PRAGMA foreign_keys = ON;
```

Read-only query and audit connections additionally execute and verify:

```sql
PRAGMA query_only = ON;
```

The contract uses only Python's standard-library `sqlite3` module. It requires no
ORM, migration framework, SQLite JSON1 extension, trigger, WAL mode, or external
database service.

## Schema entities

### `storage_metadata`

Stores stable contract metadata as non-empty key/value text. Required keys are
`storage_schema_version` and `source_finding_contract_version`.

### `detection_runs`

Represents exactly one approved Stage 1.4 detection run. It retains:

- deterministic run and finding-artifact identities;
- summary artifact identity;
- repository-relative/safe artifact-reference fields;
- finding and normalized-input contract versions; and
- bounded count metadata needed for later reconciliation.

All stored counts are non-negative. `run_id` is the primary key;
`findings_sha256` is unique and constrained to equal `run_id`.

### `run_rules`

Preserves the ordered active rule/version snapshot for the run. Its primary key is
`(run_id, ordinal)`, and its candidate rule identity is:

```sql
UNIQUE (run_id, rule_id, rule_version)
```

`run_id` is a foreign key to `detection_runs`. The ordinal is non-negative and
represents the stable active-rule position.

### `findings`

Stores one Stage 1.4 `DetectionFinding` projection. It retains the finding ID,
schema version, rule reference, neutral rule category/severity, source-event
reference, reason, neutral summary, `NOT_USED` time basis, uncertainty,
false-positive note, deterministic flag, and complete `canonical_finding_json`.

Its primary key is `(run_id, finding_id)`. It has both of these relationships:

```sql
FOREIGN KEY (run_id) REFERENCES detection_runs(run_id)

FOREIGN KEY (run_id, rule_id, rule_version)
REFERENCES run_rules(run_id, rule_id, rule_version)
```

The composite relationship is database-enforced, not merely an application-side
check. It prevents a stored finding from referencing a rule/version absent from the
run's approved rule snapshot.

### `finding_evidence`

Stores one relational evidence/provenance projection per finding evidence item:

- canonical path and observed JSON value;
- ordered source-field JSON array;
- Stage 1.3 mapping operation; and
- Stage 1.3 interpretation status.

Its primary key is `(run_id, finding_id, ordinal)`. The pair
`(run_id, finding_id, canonical_path)` is unique, and the parent relationship is:

```sql
FOREIGN KEY (run_id, finding_id)
REFERENCES findings(run_id, finding_id)
```

This preserves the traceability chain without duplicating the full normalized event:

```text
DetectionFinding
        ↓
NormalizedSecurityEvent reference
        ↓
SourceRecord reference
        ↓
Original FortiGate source record
```

## Indexes and validation boundaries

The schema defines fixed indexes for findings by source record, rule, severity,
reason code, and source type, plus evidence by canonical path. SQLite constraints
enforce keys, non-null values, allowed fixed vocabularies, non-negative/positive
numbers, deterministic flag `1`, and referential relationships.

The strict storage reader reconstructs and validates the JSON contracts. The
importer validates actual input artifact paths and safely publishes a new database.
The independent audit proves that canonical JSON and relational projections agree.

## Input boundary and strict validation

The storage boundary accepts only the approved Stage 1.4 finding JSONL and summary.
It rejects raw-data paths and the Stage 1.3 normalized JSONL path, so Stage 1.5 does
not repeat upstream parsing, normalization, or detection work.

The reader streams UTF-8 JSONL, hashes both approved inputs, reconstructs every
finding through the public Stage 1.4 contract, and fails closed on malformed JSON,
blank lines, duplicate finding IDs or out-of-order canonical finding lines, missing
or extra contract fields, unsupported rule metadata, count disagreement, invalid evidence, or
prohibited decision fields. It does not silently repair or skip an input record.

The approved Stage 1.4F summary is accepted only as an exact validation envelope,
including its required nested objects and `validation_stage = "1.4F"` /
`verdict = "PASS"`. Storage reconciles against the strict `primary_run` object but
retains the SHA-256 identity of the complete envelope. Direct
`DetectionRunSummary` JSON remains intentionally supported for strict
synthetic/public-contract fixtures; arbitrary nested summaries are rejected.

## Transactional import and publication

`src/load_detection_store.py` requires explicit finding, summary, and database
paths. The final database path must be new and beneath `data/processed/`; it must
differ from both input paths. The importer hashes and strictly validates both inputs
before creating a uniquely named temporary SQLite database beside the requested
destination. It inserts exactly one run, active-rule snapshot, findings, and ordered
evidence in a single transaction, then revalidates streamed inputs during insertion
and checks row counts, `foreign_key_check`, and `integrity_check`.

Publication is non-overwriting and occurs only after the transaction succeeds. On
failure, the importer rolls back and removes only its verified temporary database
and possible SQLite sidecars. Its output is a bounded deterministic import summary,
not an unbounded finding or evidence collection.

## Bounded read-only query contract

`src/query_detection_store.py` provides only allowlisted `run`, `finding`,
`findings`, and `evidence` operations. The `findings` operation accepts typed
filters for run ID, finding ID, rule ID/version, severity, reason code, source type,
source-record number, and evidence path. It uses an SQLite read-only URI,
`query_only`, foreign-key enforcement, parameterized values, and fixed ordering.

The default result limit is 50 and the maximum is 500. There is no raw SQL,
caller-supplied column or sort clause, pagination protocol, time filter, or write
operation. Every returned finding is reconstructed and reconciled against canonical
JSON and relational evidence before exposure. The CLI emits compact deterministic
JSON Lines on standard output and concise errors on standard error.

## Independent audit and logical determinism

`src/audit_detection_store.py` audits a completed database through an independent
read-only path. It verifies the exact schema/index signature and metadata,
`integrity_check`, `foreign_key_check`, one-run identity, rule order, row counts,
rule references, canonical finding JSON, evidence order, and evidence projections.
It produces bounded `StorageAuditResult` metadata, including a canonical
logical-export SHA-256 and a reconstructed Stage 1.4 finding-JSONL SHA-256.

SQLite database-file bytes are deliberately not a cross-environment determinism
contract. Equal approved inputs must instead agree on logical-export hashes,
reconstructed finding hashes, and bounded query-output hashes.

## Prohibited semantics and deferred work

The schema has no `is_attack`, `is_malicious`, `compromised`,
`confirmed_incident`, `risk_score`, `confidence_score`, or `attack_probability`
field. Source event severity remains distinct from Stage 1.4 rule severity.

Stage 1.5 does not reopen or rescan raw CSV data or normalized-event JSONL, add an
API, dashboard, authentication, database mutation workflow, additional rule,
threshold, time window, correlation, incident process, external database, ML, LLM,
or deployment behavior. It is ready only as a foundation for a separately planned
read-only API stage.

## Validated Stage 1.5F evidence

The approved Stage 1.5F validator used only the approved Stage 1.4 artifacts. It
completed strict validation, a primary import, independent audit, bounded queries,
a second import for logical determinism, source-artifact integrity checks, and Git
safety checks. The measured results are recorded in
[`stage_1_5_storage_findings.md`](stage_1_5_storage_findings.md): the reconstructed
finding SHA-256 equals the approved input hash, the logical-export SHA-256 is
`9f463dd96261d54673d88abd4f0213f5860381334fe07d19d4ec66a8eccd52e0`, two approved
rules reconcile, and logical/reconstructed/query hashes match across the two
imports.

Those checks demonstrate storage consistency and deterministic preservation of the
approved finding evidence. They do not confirm attacks, malicious activity,
compromised hosts, incidents, detection accuracy, precision, recall, performance,
or ground truth.
