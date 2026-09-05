# Detection Finding Storage Contract v1.0

## Status and purpose

This document defines the Stage 1.5A SQLite schema contract for an eventual
single approved Stage 1.4 detection run. It defines schema and immutable
storage-facing model boundaries only. It does not implement finding/summary input
parsing, imports, output publication, queries, storage audits, or real-data work.

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
mutable-database idempotency. Existing final database behavior belongs to the later
transactional importer checkpoint.

## SQLite connection requirements

Every creation, import, audit, or read-only query connection that relies on
referential integrity must execute and verify:

```sql
PRAGMA foreign_keys = ON;
```

Future read-only query connections must additionally execute and verify:

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
- repository-relative/safe artifact-reference fields, validated by a later importer;
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

The future strict storage reader is responsible for reconstructing and validating
the JSON contracts. The future importer is responsible for validating actual input
artifact paths and safely publishing a new database. The future audit is responsible
for proving that canonical JSON and relational projections agree. Those behaviors are
not implemented by this schema checkpoint.

## Prohibited semantics and deferred work

The schema has no `is_attack`, `is_malicious`, `compromised`,
`confirmed_incident`, `risk_score`, `confidence_score`, or `attack_probability`
field. Source event severity remains distinct from Stage 1.4 rule severity.

Stage 1.5A also does not add an importer, JSONL parser, summary reader, storage CLI,
query interface, audit, real-data scan, API, dashboard, ML, LLM, additional rule,
correlation, migration framework, or external dependency.
