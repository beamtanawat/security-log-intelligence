# Stage 1.3 — Security Log Parsing and Normalization Foundation

## Document Status

This is a self-contained execution plan for the next project stage. It is not
an implementation. Reading or approving this document does not authorize a
future agent to skip a checkpoint gate, modify raw evidence, create detections,
or commit/push without the required approval.

## 1. Purpose

Stage 1.1 and Stage 1.2 established what the current sanitized FortiGate export
contains and how its fields behave. Stage 1.3 will use that evidence to build the
smallest trustworthy parsing and normalization foundation for later rule-based
detection and additional log sources.

The stage will transform each valid source record into a deterministic internal
representation while preserving:

- every raw source field and value;
- the relationship between each normalized value and its source field;
- whether a value was copied, converted, derived, or left unmapped;
- unresolved semantics and contextual missingness;
- record and session identity without deduplication.

Stage 1.3 does not decide whether an event is benign, malicious, anomalous, or an
attack. Its product is trustworthy structured data, not a security verdict.

## 2. AI Execution Context

Read this section before attempting any Stage 1.3 checkpoint.

### What is already done

- **Stage 1.1 — Read-Only Dataset Profiling** is complete.
- **Stage 1.2A — Field Inventory / Data Dictionary** is complete.
- **Stage 1.2B — Contextual Missingness** is complete.
- **Stage 1.2C — Protocol / Port / Application Relationships** is complete.
- **Stage 1.2D — Session Behavior / Session Metric Missingness** is complete.
- **Stage 1.2E — Timestamp Investigation** is complete.
- **Stage 1.2F — Event / Application / Threat Semantics** is complete.
- **Stage 1.2G — Final Data-Quality Findings / Documentation** is complete.
- Final Stage 1.2 validation reported **31 passing tests**.

Do not rerun or redesign Stage 1.1/1.2 analysis unless a Stage 1.3 checkpoint
requires a narrow compatibility check against existing behavior.

### What is currently trusted

- The source is a sanitized FortiGate network/security CSV with 100,000 valid
  records and 58 columns.
- The measured export contains 0 malformed records and 0 exact duplicate rows.
- Raw identifiers are opaque tokens whose equality and repetition are meaningful.
- Repeated `net_sessionid` values are record groupings, not automatic duplicates.
- Protocol 1/ICMP port missingness is expected in this export.
- Session-metric missingness is contextual and must be preserved.
- FortiGate event, application, and threat values are source-product observations.
- Raw-file identity is protected by SHA-256
  `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D`.

### What is still unknown

- The authoritative meaning and unit of `data_timestamp`.
- Whether `itime` is definitively Unix epoch seconds. Its UTC rendering is only a
  derived view under that assumption.
- The source-side cause of the one missing `itime`.
- The unit and exact lifecycle semantics of `net_sessionduration`.
- The authoritative lifecycle meaning of repeated `net_sessionid` records.
- The authoritative semantics of low-confidence fields including `adom_oid`,
  `epid`, `euid`, `event_profile`, and `threat_ref`.
- The source-side cause of contextual session-metric and optional-field population.

### What must never be assumed

- `data_timestamp` is not a Unix timestamp, offset, sequence, or duration unless
  independent evidence establishes that meaning.
- Sanitized IP/MAC-like tokens are not literal IP or MAC addresses.
- A threat field, denied connection, rare event, large transfer, repeated session,
  or FortiGate `anomaly` subtype is not proof of an attack.
- A missing value is not automatically invalid, and a populated value is not
  automatically trustworthy.
- Source-product severity is not an independent risk score.

### What Stage 1.3 is trying to achieve

Build and document one minimal, versioned normalized-event contract; one
FortiGate source adapter and mapping; explicit conversion/provenance handling;
safe JSON Lines output; and validation evidence showing that all valid source
records can be represented without silent loss or raw-file mutation.

### What Stage 1.3 must NOT do

Do not implement detections, labels, correlation, storage infrastructure, APIs,
dashboards, machine learning, LLM features, or support for a second log source.
Do not expand the schema merely to imitate an enterprise SIEM.

### What qualifies as PASS

A checkpoint is `PASS` only when its exact scope is complete, all existing and new
unit tests pass, required targeted validation passes, raw integrity is confirmed
when the real dataset was read, `git diff --check` passes, the diff contains only
approved files, and the diff has been reviewed for data/semantic safety.

### When the AI must STOP

Stop immediately on `FAIL`, `PASS WITH CAUTION`, `BLOCKED BY ENVIRONMENT`, or
`NEEDS APPROVAL`. Also stop for any unexpected raw hash, unexplained record loss,
conversion that hides its input, unsupported value that disappears, test failure,
scope expansion, dependency request, destructive operation, or commit/push that
has not been explicitly authorized.

## 3. Starting Repository Context

### Project

**Security Log Intelligence** is a learning- and portfolio-focused security-data
engineering project. It begins with sanitized FortiGate logs but must gradually
support other sources through source-specific adapters feeding a common internal
event representation.

The intended progression is:

```text
Security Logs
  -> Data Exploration / Validation       (Stages 1.1 and 1.2 complete)
  -> Parsing / Normalization              (Stage 1.3)
  -> Rule-Based Detection
  -> Data Engineering / Storage
  -> API / Backend
  -> Dashboard
  -> Machine Learning / Explainable AI
  -> Behavior / Correlation / Incident Intelligence
  -> LLM-Assisted Analysis
  -> Deployment / Monitoring
```

### Existing implementation to preserve

- `src/profile_dataset.py` provides the completed read-only Stage 1.1 CSV profiler.
- `src/data_quality.py` contains the Stage 1.2 field inventory, conditional
  missingness, protocol/port, application, and session analyses.
- `src/timestamp_analysis.py` keeps raw timestamp evidence separate from derived
  UTC presentation.
- `src/semantic_analysis.py` produces bounded descriptive event, application,
  threat, identifier, and numeric summaries.
- `src/analyze_data_quality.py` is the Stage 1.2 read-only orchestrator and only
  permits generated output under `data/processed/`.
- `scripts/validate_stage_1_2.ps1` belongs to Stage 1.2 and is not a Stage 1.3
  validator.
- `tests/test_profile_dataset.py` and `tests/test_data_quality.py` are regression
  protection and must continue to pass.
- `docs/data_dictionary.md` and `docs/stage_1_2_data_quality_findings.md` are the
  evidence baseline for mapping decisions.

Important completion commits visible when this plan was written include:

- `88c6f25` — Add security session behavior analysis
- `93aa799` — Add local Stage 1.2 validation helper
- `cb71e07` — Add security log timestamp investigation
- `2aebe16` — Add event application and threat semantics analysis
- `a8a3a46` — Complete Stage 1.2 security log data quality analysis

The worktree was clean before this plan file was created.

### Planning-time environment note

At plan review on 2026-08-27, the checked-in tests could not be rerun because the
existing `.venv` launcher referenced a Python 3.12 executable that was no longer
present, and the Windows Python launcher reported no installed interpreter. This is
a time-specific `BLOCKED BY ENVIRONMENT` condition for implementation, not evidence
that the historical 31-test Stage 1.2 gate failed. A future checkpoint must recheck
the environment and stop before implementation if Python 3.12 is still unavailable;
repairing or recreating the environment requires its own in-scope approval and must
not silently change dependencies.

## 4. Verified Facts

| Topic | Verified evidence |
| --- | --- |
| Dataset | `data/raw/network_log_SAFE.csv` |
| Source | Sanitized FortiGate network/security export |
| File size | 41,235,093 bytes (approximately 39.3 MiB) |
| Records / columns | 100,000 valid records / 58 source columns |
| Structural quality | 0 malformed records; 0 exact duplicate rows |
| `loguid` | 100,000 non-missing and unique in this export |
| `net_sessionid` | 50,399 unique values; repeated values are not duplicates |
| Protocols | Raw values 1, 6, and 17; ICMP/TCP/UDP names are derived labels |
| Ports | Both ports missing on all 27,447 protocol-1 records; populated on all observed TCP/UDP records |
| Session metrics | Five metrics all missing together on 778 records; no partial pattern in the real export |
| `itime` | One missing; 99,999 valid integers; raw values preserved |
| `data_timestamp` | 100,000 valid integers, range 0–731; semantics remain unknown |
| Threat presence | At least one threat field on 25 records; product observations only |
| Raw SHA-256 | `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D` |

## 5. Known Unknowns and Forbidden Promotions

| Topic | Current status | Forbidden promotion |
| --- | --- | --- |
| `itime` epoch meaning | `NEEDS_VERIFICATION` | Do not call it a verified event timestamp. |
| UTC rendered from `itime` | `DERIVED` | Do not overwrite `itime` or omit the derivation assumption. |
| `data_timestamp` | `UNKNOWN` | Do not map it to canonical time, sequence, offset, or duration. |
| `net_sessionduration` unit | `NEEDS_VERIFICATION` | Do not name it `duration_seconds` or convert units. |
| Repeated-session lifecycle | `NEEDS_VERIFICATION` | Do not merge or deduplicate records. |
| Missing `itime` cause | `UNKNOWN` | Do not fill or infer the missing value. |
| Session-metric absence cause | `UNKNOWN` / contextual | Do not auto-fill with zero. |
| Low-confidence vendor fields | `NEEDS_VERIFICATION` | Do not invent canonical semantics from field names. |
| FortiGate threat values | Source-product observations | Do not create attack or benign labels. |

## 6. Decision and Assumption Log

| Topic | Current status | Stage 1.3 rule |
| --- | --- | --- |
| Raw dataset | `FACT` / immutable evidence | Open read-only; never rewrite, rename, sort, clean, or delete. |
| All 58 raw fields | Evidence to preserve | Retain each original key/value in `source_record`. |
| Sanitized IP/MAC IDs | Opaque identifiers | Map their role to canonical identifiers; never syntax-validate, enrich, or deanonymize. |
| `loguid` | Unique in this export | Use as source record identifier; do not claim global uniqueness. |
| `net_sessionid` | Opaque repeated identifier | Preserve as session identifier; never deduplicate on it. |
| `itime` raw | Source integer-like value | Preserve unchanged. |
| `itime` UTC | `DERIVED` / `NEEDS_VERIFICATION` | Store separately with provenance and assumption; permit `null` on missing/invalid raw input. |
| `data_timestamp` | `UNKNOWN` | Preserve only as raw/unmapped source evidence until verified. |
| Protocol numbers | Source raw values | Preserve raw; integer conversion and standard name are separate derived/converted values. |
| ICMP missing ports | `EXPECTED` | Keep canonical ports `null`; do not generate an error for this known context. |
| TCP/UDP ports | `CONTEXT_DEPENDENT` | Convert when valid; preserve missing/invalid input and issue evidence. |
| Session metrics | `CONTEXT_DEPENDENT` | Preserve missing; convert valid integers; do not infer absent values. |
| Session duration unit | `NEEDS_VERIFICATION` | Use a unit-neutral canonical name and preserve the raw value. |
| Application/event values | Source-product observations | Copy with provenance; do not create cross-vendor taxonomy in Stage 1.3. |
| Threat fields | Source-product observations | Store under source observations; never promote to attack labels. |
| Unknown categories | Supported input | Preserve unchanged and report; do not reject solely for novelty. |
| Invalid conversion | `ACTUAL_INVALID` for that conversion only | Canonical typed value is `null`; raw value remains; emit a structured issue. |
| Unmapped source field | Expected extensibility case | Preserve in both `source_record` and `unmapped_fields`; never discard silently. |
| Output format | Derived artifact | Use UTF-8 JSON Lines under `data/processed/`; one normalized event per valid input record. |

## 7. Non-Negotiable Data Rules

1. Raw security data is immutable evidence.
2. Raw and normalized/derived data must have different paths and different objects.
3. Every valid input record produces one normalized event unless a checkpoint stops
   with a failure; Stage 1.3 performs no deduplication.
4. The exact decoded CSV field/value mapping must remain available in each event's
   `source_record`. This preserves parsed strings, including blanks and sanitized
   tokens; it does not claim to reconstruct original CSV quoting or bytes. The raw
   file hash remains the byte-level evidence.
5. Every populated canonical field copied, converted, or derived from record data
   must have provenance identifying source field(s), operation, and interpretation
   status. Only the documented framework-metadata exception in Section 13 applies.
6. A failed conversion must be visible as a structured issue and must never replace
   the source value with a valid-looking default.
7. Missingness is preserved. Do not blanket-fill or blanket-drop.
8. Unknown fields, categories, protocols, and vendor values are preserved safely.
9. Sanitized identifiers preserve equality/repetition but are never treated as
   literal network addresses.
10. Output is written only beneath `data/processed/`; output-path validation must
    reject `data/raw/` and all other directories.
11. No record-level raw or normalized dataset is committed. `data/processed/` and
    the raw CSV remain ignored by Git.
12. All security terms remain observations. Normalization creates no conclusion.

## 8. Stage 1.3 Objective and Expected Deliverables

### Concrete technical outcome

Provide a versioned, JSON-serializable normalized event contract and a FortiGate
implementation that can stream the current CSV into deterministic JSON Lines while
retaining raw evidence, uncertainty, and field-level provenance.

### Future deliverables

| Deliverable | Planned path |
| --- | --- |
| Canonical-event contract and rationale | `docs/normalized_event_schema.md` |
| Complete 58-field mapping specification | `docs/fortigate_normalization_mapping.md` |
| Machine-readable FortiGate mapping table | `src/normalization/fortigate_mapping.py` |
| Shared normalized models/status constants | `src/normalization/models.py` |
| Contract validator and serialization | `src/normalization/validation.py` |
| FortiGate CSV source adapter | `src/parsers/fortigate.py` |
| FortiGate-to-canonical normalizer | `src/normalization/fortigate.py` |
| Streaming normalization CLI | `src/normalize_dataset.py` |
| Synthetic normalization tests | `tests/test_normalization.py` |
| Stage-specific local validation helper | `scripts/validate_stage_1_3.ps1` |
| Real-data audit and limitations | `docs/stage_1_3_normalization_findings.md` |
| Local normalized records | `data/processed/stage_1_3_fortigate_normalized.jsonl` (ignored) |
| Local validation summary | `data/processed/stage_1_3_validation_summary.json` (ignored) |

Add `__init__.py` only to the two new `src/parsers/` and `src/normalization/`
packages. Do not reorganize existing Stage 1.1/1.2 modules.

## 9. Proposed Architecture

```text
data/raw/network_log_SAFE.csv
        |
        v
FortiGate CSV adapter
  - strict UTF-8-sig CSV parsing
  - header and row-width validation
  - raw strings retained
        |
        v
Validated source record
  - source type
  - logical record number
  - exact 58-field mapping
        |
        v
FortiGate normalizer
  - explicit mapping table
  - safe integer conversions
  - unit-neutral fields
  - derived values clearly labeled
        |
        v
NormalizedSecurityEvent v1
  - canonical values
  - source observations
  - source_record
  - unmapped_fields
  - field provenance
  - normalization issues
        |
        v
Contract validation
  - deterministic structure
  - provenance coverage
  - no silent loss
        |
        v
data/processed/*.jsonl + concise validation summary
```

The generic normalized model must not import the FortiGate adapter. The FortiGate
normalizer may depend on the generic model. This dependency direction permits a
future Windows, DNS, or other source adapter without changing the canonical model
or the FortiGate parser.

## 10. Minimal Canonical Event Contract

Stage 1.3 will define schema version `1.0`. The implementation may use standard-
library dataclasses internally, but serialized output must be plain deterministic
JSON with stable key ordering chosen by the serializer.

### Top-level sections

| Section | Purpose |
| --- | --- |
| `schema_version` | Explicit contract version, initially `1.0`. |
| `source` | Source type, parser name, source identifiers, and logical record number. |
| `event` | Source record identity, type, subtype, action, and source severity. |
| `time` | Raw `itime`, optional derived UTC, and interpretation status. |
| `network` | Opaque endpoint identifiers, ports, raw protocol number, and derived protocol name. |
| `application` | Source-product service, category, ID, and name. |
| `session` | Opaque session ID and unit-neutral source-reported metrics. |
| `host` | Opaque host identifier and selected source host observations when justified. |
| `threat_observations` | FortiGate threat fields with an explicit non-ground-truth label. |
| `source_record` | Exact parsed raw mapping for traceability. |
| `unmapped_fields` | Raw fields intentionally not mapped into canonical sections. |
| `provenance` | Per-canonical-path source field(s), operation, and interpretation status. |
| `normalization_issues` | Structured conversion/contract issues without source data loss. |

### Required status vocabularies

- Mapping operation: `COPIED`, `CONVERTED`, `DERIVED`, `PRESERVED_UNMAPPED`.
- Interpretation status: `VERIFIED`, `DERIVED`, `NEEDS_VERIFICATION`, `UNKNOWN`,
  `CONTEXT_DEPENDENT`.
- Missingness/validation status: `EXPECTED`, `CONTEXT_DEPENDENT`, `UNKNOWN`,
  `ACTUAL_INVALID`.

Do not use security labels such as `BENIGN`, `MALICIOUS`, `ATTACK`, or `RISK` in
the contract.

### Design rationale

- Endpoint fields use `source.identifier`, `destination.identifier`, and
  `host.identifier`, not literal-IP types, because values are sanitized tokens.
- Event action/severity are retained as source labels; Stage 1.3 does not invent a
  universal severity scale.
- `session.duration_raw_value` is unit-neutral because the duration unit is not
  verified.
- `time.itime_raw` is preserved. `time.itime_utc_derived` is optional and explicitly
  derived under an epoch-seconds assumption; it is not a verified event time.
- `data_timestamp` remains in source evidence/unmapped fields and is not placed in
  canonical time.
- Threat values live under `threat_observations`, preventing accidental promotion
  into attack truth.

## 11. Public Interfaces Planned for Stage 1.3

The exact type annotations may be refined in checkpoint 1.3A, but behavior and
dependency boundaries are fixed by this plan:

```python
iter_fortigate_records(path: str | Path) -> Iterator[SourceRecord]
normalize_fortigate_record(record: SourceRecord) -> NormalizedSecurityEvent
validate_normalized_event(event: NormalizedSecurityEvent) -> list[NormalizationIssue]
normalize_fortigate_csv(input_path: str | Path, output_path: str | Path) -> NormalizationRunSummary
```

Required behavior:

- `SourceRecord` carries the exact decoded row mapping and logical record number.
- The iterator requires all 58 baseline FortiGate columns, accepts additional unique
  columns as preserved unknowns, accepts any header order, rejects blank/duplicate
  names or missing baseline columns, and reports malformed row widths without
  modifying input.
- Record normalization is pure: repeated calls on equal inputs produce equal output
  and do not mutate the input mapping.
- Validation returns structured issues instead of discarding unsupported data.
- Dataset normalization streams input/output, enforces output under
  `data/processed/`, rejects an existing final output instead of overwriting it,
  uses a uniquely named temporary output followed by a non-overwriting rename only
  after a successful run, and returns counts rather than printing raw records.
- The Stage 1.3 CLI requires an explicit `--source fortigate` argument. It rejects
  every other source value rather than auto-detecting or pretending to support a
  source adapter that has not been implemented.

## 12. Source-to-Canonical Mapping Strategy

Checkpoint 1.3B must classify all 58 fields as one of:

1. **Mapped directly** — the source role is useful and sufficiently understood.
2. **Mapped with conversion** — a typed value is useful and conversion can fail
   visibly while raw evidence remains.
3. **Mapped as derived** — the value is computed and carries its assumption/status.
4. **Preserved as source observation** — useful vendor meaning without cross-vendor
   normalization.
5. **Preserved unmapped** — no safe canonical meaning yet.

The first mapping set must include, without claiming a universal taxonomy:

| Source field(s) | Canonical role | Policy |
| --- | --- | --- |
| `data_sourcetype`, `data_parsername`, `data_sourceid`, `data_sourcename` | Source metadata | Copy raw strings; identifiers remain opaque. |
| `loguid` | Source record identifier | Copy; uniqueness claim is limited to this export. |
| `event_type`, `event_subtype`, `event_action`, `event_severity` | Event source labels | Copy with source-product provenance. |
| `itime` | Raw time + optional derived UTC | Preserve raw; derive separately under explicit unverified epoch assumption. |
| `src_ip`, `dst_ip`, `host_ip` | Role-based opaque identifiers | Copy tokens; never validate as literal addresses. |
| `src_port`, `dst_port` | Optional integer ports | Convert when present/valid; preserve contextual nulls and invalid raw values. |
| `net_proto` | Raw protocol + optional integer/name | Preserve raw; convert integer; derive known standard name separately. |
| `app_service`, `app_cat`, `app_id`, `app_name` | Application source observations | Copy strings; convert `app_id` only if the mapping spec justifies a typed field. |
| `net_sessionid` | Opaque session identifier | Copy; no grouping, merging, or deduplication during normalization. |
| packet/byte fields | Optional integer traffic metrics | Convert valid values; preserve missingness; no thresholds. |
| `net_sessionduration` | Unit-neutral raw/typed metric | Convert integer if valid; do not claim seconds. |
| threat fields | Source threat observations | Copy with explicit non-ground-truth interpretation. |

All other fields must appear in the 58-row mapping specification with a reason for
mapping or preserving unmapped. No source field may be absent from that table.

### Verified 58-field baseline header

The adapter must require this complete set while accepting any order and preserving
additional unique columns as unknown evidence:

```text
itime
adom_oid
app_cat
app_service
data_parsername
data_sourceid
data_sourcename
data_sourcetype
data_timestamp
dst_geo
dst_intf
dst_ip
dst_mac
dst_port
epid
euid
event_action
event_id
event_severity
event_subtype
event_type
host_ip
host_location
host_mac
host_type
loguid
net_proto
net_rcvdpkts
net_recvbytes
net_sentbytes
net_sentpkts
net_sessionduration
net_sessionid
src_geo
src_intf
src_ip
src_mac
src_port
event_profile
host_osver
src_natip
src_natport
host_hwvendor
host_hwver
host_osfamily
host_osname
host_name
src_domain
threat_action
threat_name
threat_severity
threat_type
app_id
app_name
threat_pattern
event_message
threat_id
threat_ref
```

## 13. Provenance Contract

Each populated canonical leaf that was copied, converted, or derived from source
record data has one provenance entry containing:

- `canonical_path`;
- `source_fields` as a non-empty ordered list;
- `operation` from the fixed vocabulary;
- `interpretation_status` from the fixed vocabulary;
- `note` only when needed to state a conversion, derivation assumption, or
  uncertainty.

Framework metadata—`schema_version`, adapter identifier, and logical record
number—is generated by the normalization framework rather than a source field. It
is excluded from field-level provenance and documented by the contract itself. No
other canonical leaf may use that exception.

Examples:

- `network.source.identifier` from `src_ip`: `COPIED`, `VERIFIED` role, with a note
  that the value is opaque.
- `network.protocol.number` from `net_proto`: `CONVERTED`, `VERIFIED` conversion,
  while the exact raw string remains in `source_record`.
- `network.protocol.name` from `net_proto`: `DERIVED`, `DERIVED` interpretation.
- `time.itime_utc_derived` from `itime`: `DERIVED`, `NEEDS_VERIFICATION`, stating
  the epoch-seconds and UTC assumptions.

Null canonical values do not require a normal provenance entry, but expected or
invalid missing/conversion cases must be represented by `normalization_issues` when
the distinction matters. Every `unmapped_fields` entry is implicitly covered by
`source_record` and explicitly classified `PRESERVED_UNMAPPED` in the mapping spec.

## 14. Timestamp Policy

1. Always preserve the exact `itime` string in `source_record` and
   `time.itime_raw`.
2. When `itime` is a valid integer and platform conversion succeeds, an optional
   `time.itime_utc_derived` may be produced using UTC, but provenance must say
   `DERIVED` and `NEEDS_VERIFICATION` and state the epoch-seconds assumption.
3. Missing or invalid `itime` yields no invented timestamp. The source value remains,
   and the appropriate `UNKNOWN` or `ACTUAL_INVALID` issue is emitted.
4. Preserve `data_timestamp` exactly in `source_record` and `unmapped_fields` with
   `UNKNOWN` semantics. Do not compare, convert, rename, or use it as canonical time.
5. Never replace either raw field with an ISO-8601 value.

## 15. Missingness and Conversion Policy

- Preserve missing source strings exactly in `source_record`.
- Treat `None`, empty strings, and whitespace-only strings as missing for canonical
  conversion, while retaining the original decoded value in `source_record`.
- Represent absent optional canonical values as JSON `null`, never `0`, empty object,
  or fabricated `unknown` text.
- Protocol 1 with both ports missing is `EXPECTED`; ports remain `null` and do not
  produce an invalid-data issue.
- Other missing ports remain `CONTEXT_DEPENDENT` unless a stricter rule is supported
  by the mapping specification.
- The five session metrics may all be absent contextually; preserve `null` values and
  do not fill them.
- A non-empty value that cannot be converted to the required integer is
  `ACTUAL_INVALID` for the canonical conversion. Record field name, issue code, and a
  safe description; retain the raw value.
- Converted ports must be integers from 0 through 65,535. Packet/byte counts and the
  unit-neutral session-duration value must be non-negative integers. Out-of-range or
  negative values are `ACTUAL_INVALID` for the typed canonical field, while the raw
  value remains evidence. Do not invent range rules for source-specific IDs.
- No row is dropped solely because a canonical value is null or a conversion failed.
- A structural CSV error is reported by the adapter and prevents a `PASS`; it is not
  silently normalized as a shorter/longer row.

## 16. Unknown and Unmapped Field Policy

- Unknown columns introduced by a future FortiGate export are retained in
  `source_record` and `unmapped_fields` in input-header order.
- Unknown categorical values in known fields are copied rather than rejected.
- Unknown protocol numbers keep their raw and converted numeric value; the derived
  name is `null`.
- Fields without a justified canonical role remain unmapped rather than receiving a
  guessed name.
- Conversion failures never erase the original value.
- Mapping coverage metrics must report known mapped, known preserved-unmapped, and
  unexpected source fields.
- A new source type requires its own adapter/mapping in a later approved stage; it
  must not add vendor-specific parsing branches to the generic model.

## 17. Validation Strategy

### Per-record invariants

- `schema_version` is present and supported.
- `source_record` equals the parsed input mapping and is not mutated.
- `loguid` and `net_sessionid` retain their separate roles.
- Canonical typed values equal explicit conversions of their source values.
- Every populated canonical leaf has valid provenance.
- Every unknown/unmapped input field is preserved.
- No security label or risk score is generated.

### Per-run invariants

- Valid input count equals normalized output count.
- Malformed rows are counted and force a non-PASS audit verdict; no silent row loss.
- No record is deduplicated, including repeated or identical session records.
- Output ordering follows valid input record order.
- Equal inputs and configuration produce byte-for-byte deterministic JSON Lines.
- JSON Lines serialization uses one compact JSON object per line, UTF-8, `\n` line
  endings, and lexicographically sorted object keys. JSON object order is not treated
  as source evidence; the source key/value mapping and original raw-file hash are.
- Conversion and issue counts reconcile with output records.
- The input file's size, modification timestamp, and SHA-256 remain unchanged.
- Output resolves under `data/processed/` and no record-level output enters Git.

### Validation summary

The concise summary must include source/output paths, schema version, input/valid/
malformed/output counts, mapping coverage, issue counts by code/field, unknown field
names (not high-cardinality values), raw hashes before/after, output hash, test result,
Git-safety result, and final verdict. It must not dump normalized records.

## 18. Testing Strategy

Use Python 3.12 and small synthetic CSV fixtures. The 39.3 MiB real dataset must not
be required by unit tests. Continue using the standard library unless a new
dependency receives separate justification and approval.

Required tests:

- normal FortiGate traffic event;
- ICMP record with both ports missing and no invalid-port issue;
- TCP/UDP records with valid ports;
- contextual missing session metrics;
- missing and invalid `itime`, with raw preservation and no fabricated UTC;
- `data_timestamp` preserved as unknown/unmapped;
- repeated `net_sessionid` records emitted independently and in order;
- sparse and partially populated threat fields kept as source observations;
- unknown event/application categories preserved;
- sanitized IP/MAC/host identifiers remain unchanged and are not syntax-validated;
- valid, missing, negative where disallowed, and non-integer conversion cases;
- boundary ports 0 and 65,535, out-of-range ports, and negative traffic metrics;
- unknown columns preserved in both raw and unmapped sections;
- missing baseline columns rejected while extra unique columns are preserved;
- provenance coverage and source-field references;
- normalized function does not mutate its input mapping;
- deterministic object serialization and byte-for-byte deterministic JSONL;
- header errors, malformed row widths, empty/header-only files, invalid UTF-8;
- output-path rejection for `data/raw/`, repository paths outside
  `data/processed/`, and input/output path equality;
- an explicit `--source fortigate` accepted and unsupported source names rejected;
- existing output rejected without modification;
- failure cleanup leaves no partial final output;
- all existing 31 Stage 1.1/1.2 tests remain passing.

Tests assert data transformation and preservation only. They must not assert attack,
anomaly, risk, or malicious/benign classifications.

## 19. Real-Data Validation Strategy

Only run real-data normalization after all unit tests pass.

1. Confirm a clean or understood Git worktree and review the intended paths.
2. Record raw file size and SHA-256 before execution.
3. Run the Stage 1.3 CLI once against `data/raw/network_log_SAFE.csv`.
4. Write JSONL and the summary only beneath `data/processed/`.
5. Validate 100,000 valid inputs and 100,000 normalized output lines, with no
   deduplication and no unexpected malformed rows.
6. Validate mapping/provenance coverage and summarize issues without dumping rows.
7. Run a second normalization to a separate temporary processed path and compare
   output hashes for determinism; remove only the explicitly verified temporary
   artifact after comparison.
8. Recompute raw size and SHA-256 and require an exact match.
9. Run the complete unit-test suite.
10. Run `git diff --check`, inspect `git status`, and verify no raw/processed artifact
    is staged or tracked.
11. Write measured results and limitations to the Stage 1.3 findings document.

`scripts/validate_stage_1_2.ps1` must not be reused as if it validates normalization.
A Stage 1.3-specific helper may be implemented in checkpoint 1.3F after its commands
and safe paths are reviewed.

## 20. Mandatory Checkpoint Gate

Apply this gate after every checkpoint:

```text
READ CONTEXT
  -> IMPLEMENT MINIMUM APPROVED CHANGE
  -> COMPLETE UNIT TEST SUITE
  -> TARGETED VALIDATION
  -> REAL-DATA VALIDATION WHEN REQUIRED
  -> RAW HASH CHECK WHEN RAW DATA WAS READ
  -> GIT DIFF CHECK
  -> DIFF REVIEW
  -> VERDICT
  -> LOCAL COMMIT ONLY WITH EXPLICIT USER AUTHORIZATION
  -> NEXT CHECKPOINT
```

Allowed verdicts:

- `PASS` — all applicable checks succeeded and no unresolved safety concern remains.
- `FAIL` — an acceptance criterion or test failed.
- `PASS WITH CAUTION` — results are usable but contain a material unresolved concern.
- `BLOCKED BY ENVIRONMENT` — required local data/tool/environment is unavailable.
- `NEEDS APPROVAL` — the next action requires user authority, including commit or
  scope expansion.

Only `PASS` may be considered technically ready for the next checkpoint. However,
the repository rule still forbids automatic commits: without explicit commit
authorization, stop at `NEEDS APPROVAL`. Never hide a non-PASS verdict or continue
silently.

## 21. Checkpoint 1.3A — Canonical Contract and Status Vocabulary

### Objective

Turn the design principles in this plan into a reviewed, minimal v1 contract before
writing source-specific transformation logic.

### Files likely affected

- Create `docs/normalized_event_schema.md`.
- Create `src/normalization/__init__.py` and `src/normalization/models.py`.
- Create the first contract-focused portion of `tests/test_normalization.py`.

### Exact scope and inputs

- Use the Stage 1.2 dictionary/findings and Sections 10–16 of this plan.
- Define the `NormalizedSecurityEvent`, provenance, issue, source-record, and run-
  summary structures with schema version `1.0`.
- Define the fixed status vocabularies and deterministic `to_dict` behavior.
- Include a minimal synthetic example in documentation; no real record values.

### Outputs

- Human-readable schema contract and rationale.
- Standard-library models that can represent raw, mapped, unmapped, provenance, and
  issue data without FortiGate-specific parsing code.

### Tests required

- Construction and deterministic serialization.
- Required section/status validation.
- Empty optional values represented as `null`.
- Rejection of prohibited/unknown status names.
- No source mapping or detection terms in the generic model.

### Real-data validation

Not required. Do not read the real CSV during this checkpoint.

### Acceptance criteria

- Contract is minimal, versioned, JSON-serializable, and vendor-neutral.
- It can preserve a complete raw record and field provenance.
- Existing 31 tests and new contract tests pass.
- Only checkpoint files are changed and `git diff --check` passes.

### Stop condition

Stop if the schema requires an unverified unit/semantic meaning or unnecessary
enterprise abstraction. Stop at the gate before checkpoint 1.3B.

### Must not do yet

Do not implement a FortiGate parser, mapping, CLI, JSONL output, or real-data run.

## 22. Checkpoint 1.3B — FortiGate Mapping Specification

### Objective

Specify the handling of every one of the 58 FortiGate fields before implementing
normalization.

### Files likely affected

- Create `docs/fortigate_normalization_mapping.md`.
- Create `src/normalization/fortigate_mapping.py` containing declarative mapping
  metadata only; it must not normalize records yet.
- Extend mapping-spec tests in `tests/test_normalization.py`.

### Exact scope and inputs

- Use verified header order, data dictionary, findings, and canonical v1 contract.
- Create one row per raw field: source field, canonical path or unmapped status,
  source representation, target type, operation, interpretation status, missingness
  status, conversion failure behavior, and rationale.
- Record all timestamp, protocol, session, identifier, application, and threat
  boundaries explicitly.

### Outputs

- A complete 58-field mapping specification with no silent omissions.
- One machine-readable `FORTIGATE_FIELD_MAPPINGS` table consumed later by the
  normalizer rather than duplicating mapping decisions in conditional code.
- A list of fields intentionally preserved unmapped and why.

### Tests required

- Exactly 58 unique fields in verified header order.
- Every field has one supported mapping category and interpretation status.
- `data_timestamp` is unmapped/unknown; opaque identifiers do not receive literal
  address types; threat fields do not map to labels.
- The documentation table and `FORTIGATE_FIELD_MAPPINGS` contain the same source
  fields and decisions.

### Real-data validation

Header-only comparison is permitted. Do not scan or normalize all records.

### Acceptance criteria

- Every raw field has an explicit rule.
- Mappings agree with Stage 1.2 known/unknown boundaries.
- No arbitrary cross-vendor taxonomy or undocumented unit is introduced.
- Complete tests pass and diff review finds no source evidence loss.

### Stop condition

Stop on any unresolved contradiction between the schema and Stage 1.2 evidence.
Mark the mapping `NEEDS_VERIFICATION`; do not guess. Stop at the gate.

### Must not do yet

Do not implement CSV parsing, conversion, normalization, or processed output.

## 23. Checkpoint 1.3C — FortiGate Source Adapter

### Objective

Create a small read-only CSV adapter that produces validated source records while
retaining exact raw strings and input order.

### Files likely affected

- Create `src/parsers/__init__.py` and `src/parsers/fortigate.py`.
- Extend `tests/test_normalization.py` with adapter fixtures.

### Exact scope and inputs

- Strict `utf-8-sig` CSV parsing using the standard library.
- Validate non-empty, unique header names and row width.
- Require all 58 baseline fields, accept them in any order, and preserve any extra
  unique columns as unknown/unmapped evidence. A missing baseline column is a
  structured adapter error for Stage 1.3 rather than an implied optional mapping.
- Yield `SourceRecord` values with logical record number and exact field mapping.
- Detect source-file changes during a run using size/mtime checks consistent with the
  existing read-only tools.

### Outputs

- Streaming `iter_fortigate_records` implementation and structured adapter errors.

### Tests required

- Valid record order/raw equality; BOM handling; empty/header-only CSV; blank or
  duplicate headers; missing baseline columns; extra unique columns; malformed
  widths; invalid UTF-8; changed-file detection where practical; unknown columns
  retained.

### Real-data validation

One count-only read is permitted after tests. Confirm 100,000 valid, 0 malformed, 58
columns, and unchanged raw hash. Do not write normalized output.

### Acceptance criteria

- Adapter is streaming and read-only.
- Raw source mapping is exact and not normalized.
- Count-only real-data results match Stage 1.2 and raw SHA-256 is unchanged.
- All tests pass and diff is limited to checkpoint files.

### Stop condition

Stop on any header/count/hash mismatch, parser ambiguity, or unhandled structural
error. Stop at the gate.

### Must not do yet

Do not map canonical values, write JSONL, or create security interpretations.

## 24. Checkpoint 1.3D — FortiGate Normalizer and Provenance

### Objective

Implement pure record-level mapping, safe conversions, provenance, and issue handling
according to the approved 58-field specification.

### Files likely affected

- Create `src/normalization/fortigate.py`.
- Create `src/normalization/validation.py` if contract validation was not completed in
  1.3A.
- Extend `tests/test_normalization.py`.

### Exact scope and inputs

- Normalize one `SourceRecord` at a time.
- Implement only mappings approved in 1.3B.
- Preserve all raw and unmapped fields.
- Implement integer conversion, derived protocol names, optional derived UTC,
  contextual missingness, structured issues, and complete provenance.

### Outputs

- `normalize_fortigate_record` and `validate_normalized_event`.
- Deterministic normalized objects for synthetic FortiGate records.

### Tests required

- All semantic cases listed in Section 18, especially opaque identifiers, ICMP ports,
  missing timestamps/metrics, unknown categories/protocols/fields, invalid numerics,
  sparse threats, repeated sessions, provenance coverage, input immutability, and
  deterministic serialization.

### Real-data validation

Not required beyond an optional bounded sample read after unit tests. Do not write the
full processed dataset.

### Acceptance criteria

- No input field/value disappears.
- All mappings, conversions, derived values, nulls, and issues match the specification.
- Repeated records remain separate.
- Contract validator accepts valid output and identifies deliberate fixture failures.
- All old and new tests pass; no prohibited security conclusions appear.

### Stop condition

Stop on silent conversion, incomplete provenance, input mutation, or any need to guess
semantics. Stop at the gate.

### Must not do yet

Do not build the dataset CLI, full JSONL output, detections, or second-source support.

## 25. Checkpoint 1.3E — Streaming Output and Run Validation

### Objective

Connect the adapter and normalizer through a safe, deterministic CLI without loading
the entire dataset or leaving partial final output.

### Files likely affected

- Create `src/normalize_dataset.py`.
- Extend `tests/test_normalization.py` with end-to-end synthetic fixtures.
- Update `docs/normalized_event_schema.md` only for verified CLI/output contract facts.

### Exact scope and inputs

- Stream input records to UTF-8 JSON Lines.
- Require `--source fortigate`; reject unsupported source names without auto-detection.
- Require output beneath `data/processed/` and different from the input path.
- Write to a uniquely named temporary file under `data/processed/`; publish the final
  output only after successful completion and close. Reject a pre-existing final
  output; Stage 1.3 provides no overwrite flag.
- Produce a bounded `NormalizationRunSummary` with counts and issue/mapping coverage.
- Define nonzero CLI exit behavior for structural failure or invalid path.

### Outputs

- `normalize_fortigate_csv` and a PowerShell-compatible CLI.
- Deterministic JSONL and concise summary behavior on synthetic fixtures.

### Tests required

- End-to-end count/order preservation; output-path rejection; deterministic JSONL;
  conversion issue reconciliation; malformed-input failure; partial-output cleanup;
  input/output separation; safe handling of existing output without silent overwrite.

### Real-data validation

Not yet required. A small synthetic or deliberately bounded local fixture is enough.

### Acceptance criteria

- Streaming behavior is bounded by one source/normalized record plus aggregate counts.
- Valid input count equals JSONL line count.
- Failure never publishes a partial final file.
- CLI errors are concise and contain no giant record dumps.
- Complete test suite and diff checks pass.

### Stop condition

Stop on record loss, ordering changes, partial final output, unsafe overwrite behavior,
or nondeterministic serialization. Stop at the gate.

### Must not do yet

Do not claim real-dataset readiness, create detections, or commit processed output.

## 26. Checkpoint 1.3F — Real-Dataset Normalization Audit

### Objective

Run the completed normalization path against the immutable 100,000-record dataset and
collect measured evidence without changing raw data or Git-tracking generated output.

### Files likely affected

- Create `scripts/validate_stage_1_3.ps1`.
- Create `docs/stage_1_3_normalization_findings.md`.
- Create ignored local artifacts under `data/processed/` only.

### Exact scope and inputs

- Implement the controlled procedure in Section 19.
- Validate counts, issue categories, mapping coverage, provenance, determinism, and
  raw integrity.
- Report only aggregate results and bounded unknown-field names.

### Outputs

- Stage-specific validator.
- Local JSONL and summary artifacts.
- Measured normalization audit with facts, unknowns, limitations, and verdict.

### Tests required

- Complete suite must pass before and after the real-data run.
- Validator path/hash/count failure branches should be covered where practical with
  small fixtures or safe command checks.

### Real-data validation

Required. Raw before/after SHA-256 must equal the known hash; input and output counts
must be 100,000; malformed count must remain 0; determinism hashes must match.

### Acceptance criteria

- Unit tests pass.
- One normalized output exists only under `data/processed/` and remains ignored.
- Counts reconcile with no row loss/deduplication.
- Raw hash and size are unchanged.
- Mapping, provenance, conversion issues, and unknowns are documented with measured
  values only.
- Git safety and diff review pass.

### Stop condition

Any hash/count/determinism mismatch, unexpected issue, tracked processed artifact, or
non-PASS validator result stops the stage. Do not edit expected results to force PASS.

### Must not do yet

Do not tune detections, classify records, enrich identifiers, or add infrastructure.

## 27. Checkpoint 1.3G — Documentation and Detection-Readiness Gate

### Objective

Reconcile the contract, mapping, implementation, tests, and real-data audit, then
decide whether normalized output is trustworthy input for a separately planned
rule-based detection stage.

### Files likely affected

- Finalize `docs/normalized_event_schema.md`.
- Finalize `docs/fortigate_normalization_mapping.md`.
- Finalize `docs/stage_1_3_normalization_findings.md`.
- Update `README.md` only to record Stage 1.3 completion after all gates pass.

### Exact scope and inputs

- Reconcile every documented mapping against code and tests.
- Confirm known unknowns remain visible and no source evidence is lost.
- Run the complete validator and review final Git diff.
- State readiness and limitations without designing detection logic.

### Outputs

- Final Stage 1.3 documentation and a clear `PASS` or non-PASS readiness verdict.

### Tests required

- Complete Stage 1.1–1.3 unit suite.
- Final real-data validator run, raw hash check, output determinism check, documentation
  cross-reference check, `git diff --check`, `git status`, and human/AI diff review.

### Real-data validation

Required through the approved Stage 1.3 validator; avoid additional ad hoc scans.

### Acceptance criteria

- Definition of Done in Section 31 is fully satisfied.
- Documentation and implementation agree.
- The final verdict is `PASS` with no hidden caveats.
- Only documentation/source/test/script files intended for Stage 1.3 are tracked;
  raw and processed record data remain untracked.

### Stop condition

Stop with the actual non-PASS verdict if any gate fails. Do not start rule-based
detection in this checkpoint.

### Must not do yet

Do not create detection rules, thresholds, alerts, correlation, ML, APIs, dashboards,
or deployment work. A later stage requires its own reviewed plan.

## 28. Explicitly Out of Scope

Stage 1.3 must not implement:

- attack, anomaly, or rule-based detection;
- event correlation, incident generation, alert prioritization, or risk scoring;
- attack, malicious/benign, or supervised-learning labels;
- supervised/unsupervised ML, deep learning, embeddings, LLMs, or RAG;
- MITRE ATT&CK mapping;
- PostgreSQL, other databases, OpenSearch, Redis, or Kafka;
- FastAPI, frontend/dashboard work, or external services;
- Docker, Kubernetes, cloud deployment, or monitoring infrastructure;
- additional log-source adapters;
- identifier deanonymization, enrichment, or external reputation lookup;
- a complete enterprise SIEM/ECS-style schema.

## 29. Security and Analytical Interpretation Rules

- Threat field != confirmed attack.
- Denied connection != attack.
- Rare event != attack.
- High traffic volume != attack.
- Repeated session != duplicate.
- Anomaly != maliciousness.
- Product-generated threat name != perfect ground truth.
- Missing threat fields != benign.
- Normalization preserves observations; it does not manufacture conclusions.

Use neutral wording such as source observation, unusual value, unknown semantics,
context-dependent missingness, and requires verification.

## 30. Risks and Controls

| Risk | Required control |
| --- | --- |
| Canonical schema mirrors FortiGate permanently | Keep generic roles separate from the FortiGate mapping and raw observations. |
| Schema becomes enterprise-sized | Map only concepts needed for current records and the next rule-based stage. |
| Raw evidence disappears | Preserve exact `source_record`, unmapped fields, and provenance. |
| Sanitized token is treated as an IP/MAC | Use opaque identifier roles and no syntax validation. |
| Unknown timestamp gains invented meaning | Keep `data_timestamp` unmapped; label derived UTC assumptions. |
| Missing values become zeros | Preserve JSON null and data-quality context. |
| Conversion hides invalid input | Keep raw string and emit `ACTUAL_INVALID`. |
| Repeated sessions are merged | Enforce one output event per valid input record. |
| Threat observations become labels | Keep them under `threat_observations` with explicit interpretation. |
| Generated data enters Git | Restrict output to ignored `data/processed/` and inspect status. |
| Full run leaves partial output | Temporary processed file plus publish-on-success behavior. |
| Existing analysis modules grow further | Use new `parsers` and `normalization` responsibilities; do not add Stage 1.3 logic to `data_quality.py`. |
| Agent continues after a warning | Enforce the verdict gate and explicit stop rules. |

## 31. Definition of Done

Stage 1.3 is complete only when all of the following are true:

1. Raw FortiGate records remain immutable and retain the known SHA-256.
2. The source adapter safely parses valid records and reports structural errors.
3. A minimal, versioned normalized representation exists and is documented.
4. All 58 source fields have explicit mapping or preserved-unmapped rules.
5. Raw source values, unknown fields, contextual missingness, and unsupported values
   never disappear silently.
6. Sanitized identifiers remain opaque and preserve equality/repetition.
7. Timestamp uncertainty and unknown units remain explicit.
8. Provenance covers every populated canonical value sourced or derived from record
   data, with only the documented framework-metadata exception.
9. Normalization is deterministic and input order/cardinality are preserved.
10. Synthetic tests cover required valid, missing, invalid, unknown, repeated, and
    safety cases; all Stage 1.1–1.3 tests pass.
11. Real-data output contains exactly 100,000 normalized events for 100,000 valid
    inputs, with 0 unexpected malformed records or deduplication.
12. Raw hash/size, deterministic output hashes, output-path policy, and Git safety
    pass the Stage 1.3 validator.
13. Documentation matches the implemented schema, mapping, measured findings, and
    limitations.
14. Final checkpoint verdict is `PASS`.
15. No detection, security label, second-source implementation, dependency expansion,
    database, API, UI, ML, LLM, or deployment work was introduced.

Completion means the normalized output is trustworthy input for a later,
separately planned rule-based detection stage. It does not mean that an AI model was
trained or that attacks were detected.

## 32. Suggested Execution Order

Execute exactly one checkpoint at a time:

1. **1.3A — Canonical Contract and Status Vocabulary**
2. **1.3B — FortiGate Mapping Specification**
3. **1.3C — FortiGate Source Adapter**
4. **1.3D — FortiGate Normalizer and Provenance**
5. **1.3E — Streaming Output and Run Validation**
6. **1.3F — Real-Dataset Normalization Audit**
7. **1.3G — Documentation and Detection-Readiness Gate**

Do not batch checkpoints into one giant change. At each gate, report changed files,
behavior, data assumptions, tests/validation, measured results, limitations, verdict,
and the smallest next checkpoint. Do not implement that next checkpoint until the
gate and required user authorization allow it.
