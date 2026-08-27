# Stage 1.4 — Rule-Based Security Detection Foundation

## Document Status

This document is a self-contained execution plan only. It does not implement
detection, create rules in source code, evaluate real data, change the stable
Stage 1.3 normalization contract, or authorize a commit or push.

A future human or AI agent must execute exactly one checkpoint at a time and pass
the checkpoint gate before requesting approval to continue.

## 1. Purpose

Stage 1.4 will establish the smallest trustworthy rule-based detection foundation
on top of the completed normalized-event pipeline.

Stage 1.2 answered:

> What does the current sanitized FortiGate data contain, and which meanings or
> missingness patterns are supported by evidence?

Stage 1.3 answered:

> How can each source record be transformed into a stable, deterministic,
> provenance-preserving `NormalizedSecurityEvent` without losing raw evidence?

Stage 1.4 will answer:

> How can normalized events be evaluated by transparent, deterministic rules that
> produce evidence-backed findings without claiming that every match is an attack?

Rule-based detection comes before machine learning because it provides explicit
logic, stable evidence, repeatable behavior, testable security assumptions,
false-positive documentation, and an explainable baseline for later systems.

## 2. AI Execution Context

Read this section completely before attempting any Stage 1.4 checkpoint.

### What Is Already Complete

- **Stage 1.1 — Read-Only Dataset Profiling** is complete.
- **Stage 1.2 — Security Log Data Quality and Semantic Understanding** is complete:
  - 1.2A — Field Inventory / Data Dictionary
  - 1.2B — Contextual Missingness
  - 1.2C — Protocol / Port / Application Relationships
  - 1.2D — Session Behavior
  - 1.2E — Timestamp Investigation
  - 1.2F — Event / Application / Threat Semantics
  - 1.2G — Final Data-Quality Findings
- **Stage 1.3 — Security Log Parsing and Normalization Foundation** is complete:
  - 1.3A — Normalized Event Schema Contract
  - 1.3B — Explicit 58-Field FortiGate Mapping
  - 1.3C — Read-Only Streaming Source Adapter
  - 1.3D — Record-Level Normalization and Provenance
  - 1.3E — Safe Deterministic Streaming JSONL CLI
  - 1.3F — Real-Data Normalization Audit
  - 1.3G — Final Documentation / Readiness Gate
- Final Stage 1.3 validation passed 68 tests, normalized 100,000 records, preserved
  cardinality and provenance, produced deterministic output, and left the raw hash
  unchanged.
- Final Stage 1.3 commit: `461e7f1 Complete Stage 1.3 normalization foundation`.

Do not redo Stage 1.2 analysis, create another FortiGate parser, or create a second
normalization system.

### What the Current Input Contract Is

Detection consumes serialized **Normalized Security Event Contract v1.0** records,
not raw CSV rows. The contract is defined by:

- `docs/normalized_event_schema.md`
- `src/normalization/models.py`
- `docs/fortigate_normalization_mapping.md`
- `src/normalization/fortigate_mapping.py`

Each event has these required sections:

`schema_version`, `source`, `event`, `time`, `network`, `application`, `session`,
`host`, `threat_observations`, `source_record`, `unmapped_fields`, `provenance`, and
`normalization_issues`.

The real normalized artifact validated by Stage 1.3F is:

`data/processed/stage_1_3f_normalized_events.jsonl`

It contains 100,000 deterministic JSON Lines records and measured 907,375,745 bytes.
Its documented SHA-256 is:

`C195C6322665530D56F1BD5390B6B1C20728881A21EE36352C7C46E0A7138976`

### What Is Trusted

- The normalized schema version is `1.0`.
- Each valid source record remains one separate normalized record.
- Source record numbers are contiguous from 1 through 100,000 in the validated
  artifact.
- All 58 FortiGate fields have explicit mapped or preserved-unmapped decisions.
- Every mapped source-derived canonical value has required provenance.
- Sanitized identifiers are opaque but retain equality/repetition relationships.
- Mapping accounting reconciles exactly:
  - 5,300,000 mapped source-field decisions;
  - 500,000 preserved-unmapped decisions;
  - 0 unexpected decisions;
  - total 5,800,000 decisions.
- Detection may consume canonical values and their provenance without reopening the
  raw CSV for rule evaluation.

### What Is Still Unknown

- `data_timestamp` semantics and units remain `UNKNOWN`.
- The epoch-seconds interpretation used for the optional UTC view derived from
  `itime` remains `NEEDS_VERIFICATION`.
- The source-side cause of the one missing `itime` remains `UNKNOWN`.
- `net_sessionduration` units remain unverified.
- The exact lifecycle meaning of repeated `net_sessionid` records remains unverified.
- Sparse event, application, and threat values remain source-product observations,
  not independent truth labels.

### What Must Never Be Assumed

- Rule match does not mean confirmed attack.
- FortiGate `anomaly` does not mean confirmed attack.
- Denied connection does not mean attack.
- Rare event or large traffic value does not mean maliciousness.
- Repeated session ID does not mean duplicate record.
- Missing optional value does not mean maliciousness.
- Threat name or category is not perfect ground truth.
- Event severity, threat severity, rule severity, and any future incident severity are
  separate concepts.
- `data_timestamp` is not a usable event clock.
- The derived `itime` UTC value is not a verified time basis for window rules.
- Sanitized identifiers are not literal IP or MAC addresses.

### What This Stage Must Build

- A minimal rule contract and finding contract.
- A deterministic, record-level, Python-defined rule registry.
- A streaming normalized-JSONL reader and bounded-memory evaluation engine.
- Two small source-observation rules supported by current evidence.
- Deterministic evidence/provenance-preserving findings.
- A safe streaming CLI and output audit.
- Synthetic tests, a real-data rule-behavior audit, and false-positive documentation.

### What This Stage Must Not Build

- No time-window or stateful rules.
- No arbitrary thresholds.
- No incidents, correlation, risk scores, or attack labels.
- No ML, anomaly model, embedding, LLM, or RAG feature.
- No database, API, frontend, container, or deployment work.
- No new source adapter and no normalization-contract change without a separate stop
  and approval.

### What Counts as PASS

A checkpoint is `PASS` only when its approved scope is complete, all available
Stage 1.1–1.4 tests pass, checkpoint validation succeeds, evidence and
false-positive boundaries are reviewed, relevant data hashes match, `git diff
--check` passes, and the diff contains only checkpoint files.

### When the AI Must STOP

Stop on any of these verdicts or conditions:

- `FAIL`
- `PASS WITH CAUTION`
- `AWAITING LOCAL VALIDATION`
- `BLOCKED BY ENVIRONMENT`
- `NEEDS CONTRACT CHANGE`
- `NEEDS SECURITY REVIEW`
- unexpected normalized/raw hash or record count;
- nondeterministic output;
- lost evidence or provenance;
- invented threshold, time meaning, or security conclusion;
- request to modify Stage 1.3 without explicit approval;
- test failure, unsafe output path, scope expansion, dependency addition, or
  unauthorized commit/push.

### Execution-Context Environment Status

The project itself has a validated local Python environment and is **not** globally
`BLOCKED BY ENVIRONMENT`. In the user's local VS Code PowerShell environment, the
project virtual environment is working with Python 3.12.10. Stage 1.3 completed in
that environment: the final validation passed 68 tests and successfully processed
the real 100,000-record dataset. Those local validation results are authoritative
execution evidence.

Some Codex execution contexts may be isolated from the user's local Windows Python
runtime. That is an **execution-context limitation**, not evidence that Python or
`.venv` is missing and not a project dependency failure. Therefore:

1. Do not reinstall Python merely because Codex cannot access it.
2. Do not rebuild `.venv` merely because Codex cannot access it.
3. Do not modify `PATH` merely to work around Codex sandbox isolation.
4. If Codex has Python access, use the validated project environment and execute the
   current checkpoint normally.
5. If Codex does not have Python access, perform only work permitted before runtime
   validation, do not fabricate results, and stop at `AWAITING LOCAL VALIDATION`.
6. At `AWAITING LOCAL VALIDATION`, provide the exact checkpoint-relevant local
   command or commands. The baseline commands from the repository root are:

   ```powershell
   & .\.venv\Scripts\python.exe --version
   & .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p "test_*.py" -v
   ```

   After the Stage 1.4 validator exists, checkpoints requiring its controlled
   real-data validation must also provide:

   ```powershell
   & .\scripts\validate_stage_1_4.ps1
   ```

7. Results produced in the user's validated local VS Code PowerShell environment
   are authoritative execution evidence and must be recorded without alteration.
8. Use `BLOCKED BY ENVIRONMENT` only when the current checkpoint truly cannot
   proceed safely in any permitted execution context. It is not the default Stage
   1.4 state and must not replace `AWAITING LOCAL VALIDATION` merely because Codex
   cannot invoke the local runtime itself.

## 3. Current Project and Data State

### Project

**Security Log Intelligence** is a learning- and portfolio-focused cybersecurity
data-engineering project. It starts with sanitized FortiGate logs but is designed so
future source adapters can produce the same normalized contract.

### Raw evidence

| Measure | Verified value |
| --- | ---: |
| Raw path | `data/raw/network_log_SAFE.csv` |
| Records | 100,000 |
| Source columns | 58 |
| Malformed records | 0 |
| Exact duplicate rows | 0 |
| File size | 41,235,093 bytes |
| SHA-256 | `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D` |

Raw evidence is immutable and ignored by Git.

### Current validated pipeline

```text
Raw FortiGate CSV
        |
        v
Streaming FortiGate Adapter
        |
        v
SourceRecord
        |
        v
Explicit 58-Field Mapping
        |
        v
Record-Level Normalizer
        |
        v
NormalizedSecurityEvent v1.0
        |
        v
Deterministic Streaming JSONL
        |
        v
Normalization Audit / Validation
```

Stage 1.4 starts after this boundary:

```text
NormalizedSecurityEvent v1.0
        |
        v
Record-Level Rule Evaluation
        |
        v
Detection Finding
        |
        v
Evidence / Provenance / Reason
        |
        v
Detection Output Audit
```

## 4. Stage 1.2 Facts That Constrain Detection

| Observation | Verified evidence | Stage 1.4 requirement |
| --- | --- | --- |
| Event population | traffic 99,970; utm 30 | Rare UTM population is not proof of attack. |
| Protocol 1 / ICMP | 27,447 records | Preserve protocol context. |
| ICMP ports | Both ports missing on all protocol-1 records | Missing ICMP ports must never be a detection condition by themselves. |
| Session IDs | Repeated values are valid source records | No detection-time deduplication. |
| Session metrics | All five missing together on 778 records | Missingness alone is not security evidence. |
| `itime` | One missing; UTC rendering is derived | Initial rules do not use time. |
| `data_timestamp` | Semantics unknown | Never use for ordering, windows, or time claims. |
| Threat fields | Any threat field occurs on 25 records | Product observations may support informational findings, not attack truth. |
| Anomaly subtype | 18 observed records | Product term may support an informational finding only. |
| Numeric distributions | Large and zero-heavy values exist | No threshold without separate evidence and review. |

## 5. Decision and Assumption Table

| Topic | Current status | Rule-detection requirement |
| --- | --- | --- |
| Raw logs | `FACT` / immutable | Never modify; not direct rule input. |
| Normalized contract | Validated v1.0 | Detection consumes this boundary. |
| Normalized JSONL | 100,000 records / approximately 907 MB | Stream; never call `list(all_events)`. |
| Sanitized identifiers | `OPAQUE` | Compare equality only; do not syntax-validate or enrich. |
| `data_timestamp` | `UNKNOWN` / preserved unmapped | Do not use. |
| `itime` UTC | `DERIVED` / `NEEDS_VERIFICATION` | Initial rules use `time_basis = NOT_USED`. |
| ICMP missing ports | `EXPECTED` | Never alert merely because ports are missing. |
| Session metric missingness | `CONTEXT_DEPENDENT` | Never alert on missing metrics alone. |
| Threat fields | Source-product observations | May be informational evidence; never ground truth. |
| Repeated session IDs | Valid behavior | Never merge or deduplicate. |
| Rule match | Detection observation | Not confirmed attack or incident. |
| Rule configuration | Stage 1.4 decision | Python-defined immutable registry; no DSL. |
| Stateful rules | Unsupported in Stage 1.4 | Defer until time semantics and bounded state are justified. |
| Thresholds | None justified for v1 rules | Do not introduce any initial numeric threshold. |
| Finding ordering | Deterministic | Source record number, then rule ID. |
| Finding evaluation time | Would break byte determinism | Do not store wall-clock time in a finding. |
| Rule severity | Review priority only | Separate from event/threat/incident severity. |
| Stage 1.3 contract | Stable | Stop with `NEEDS CONTRACT CHANGE` before any modification. |

## 6. Detection Terminology

### Rule

A versioned, reviewable definition that evaluates one normalized event using explicit
canonical fields.

### Rule Match

The configured rule condition was satisfied. A match does not confirm an attack,
compromise, malicious event, or incident.

### Detection Finding

A deterministic record of one rule match containing exact evidence, reason,
provenance, traceability, severity policy, and limitations.

### Detection Evidence

The specific canonical paths and observed values that caused the rule match, plus
their source-field provenance and interpretation statuses.

### Rule Severity

A review-priority value assigned by the rule contract. It is not the source event
severity, FortiGate threat severity, confidence, risk score, or future incident
severity.

### Incident

An investigation/correlation concept that is explicitly outside Stage 1.4. A finding
must not call itself an incident.

## 7. Stage 1.4 Objective and Deliverables

### Technical objective

Stream validated normalized events through an ordered set of deterministic
record-level rules and emit a stable JSON Lines finding for each match without losing
source traceability or overstating security meaning.

### Planned deliverables

| Deliverable | Planned path |
| --- | --- |
| Detection and finding contract | `docs/detection_contract.md` |
| Initial rule specifications and review tables | `docs/initial_detection_rules.md` |
| Detection package | `src/detection/` |
| Streaming detection CLI | `src/evaluate_detections.py` |
| Detection-output audit | `src/audit_detection_output.py` |
| Synthetic detection tests | `tests/test_detection.py` |
| Stage-specific validator | `scripts/validate_stage_1_4.ps1` |
| Measured rule behavior and limitations | `docs/stage_1_4_detection_findings.md` |
| Local findings JSONL | `data/processed/stage_1_4f_detection_findings.jsonl` (ignored) |
| Local bounded summary | `data/processed/stage_1_4f_detection_summary.json` (ignored) |

No Stage 1.1–1.3 implementation file is modified unless a separately approved
contract-change process proves it necessary.

## 8. Minimal Architecture

```text
Normalized JSONL reader
  - UTF-8 JSON Lines
  - one record at a time
  - schema v1.0 reconstruction
  - existing normalization validation
        |
        v
Ordered Python rule registry
  - immutable metadata
  - unique rule IDs
  - exact supported sources
  - no external DSL
        |
        v
Record-level rule engine
  - no time windows
  - no session aggregation
  - one event retained at a time
  - rule order sorted by rule ID
        |
        v
DetectionFinding v1.0
  - deterministic ID
  - exact evidence
  - normalized provenance
  - source trace
  - uncertainty and false-positive note
        |
        v
Safe JSONL publication + bounded summary
        |
        v
Streaming finding audit
```

The detection package may import the stable normalization models and validator.
Normalization must not import detection. Rules must not import the FortiGate CSV
adapter or inspect raw FortiGate field names when an approved canonical path exists.

## 9. Rule Configuration Decision

Stage 1.4 uses **Python-defined immutable rules**.

Rationale:

- the repository is a Python 3.12 student project;
- current rules are few and record-level;
- Python definitions are directly type-checked, tested, versioned, and reviewed;
- no YAML dependency or custom expression parser is needed;
- a DSL would add validation and security complexity without current benefit;
- rule metadata can remain declarative while evaluation stays explicit Python.

Stage 1.4 does not accept user-supplied rule files, dynamic imports, `eval`, or
expression strings. Declarative external configuration can be planned later only
when there are enough stable rules to justify it.

## 10. Rule Contract

### Rule metadata

Each rule has:

| Field | Contract |
| --- | --- |
| `rule_id` | Stable lowercase dotted identifier. |
| `version` | Explicit semantic version string, initially `1.0`. |
| `name` | Short human-readable name. |
| `description` | What the condition observes; no attack claim. |
| `category` | Stable rule category. Initial value: `SOURCE_PRODUCT_OBSERVATION`. |
| `severity` | One rule-severity value. |
| `supported_source_types` | Non-empty tuple; initial rules support only `fortigate`. |
| `required_paths` | Canonical paths needed to evaluate safely. |
| `evidence_paths` | Canonical paths eligible for emitted evidence. |
| `reason_code` | Stable uppercase explanation code. |
| `security_rationale` | Why the observation may deserve analyst review. |
| `false_positive_scenarios` | Non-empty documented normal/ambiguous situations. |
| `limitations` | Non-empty interpretation boundaries. |

The v1 contract intentionally omits confidence, risk score, threshold, window, and
enabled flags. The built-in registry is the explicit active configuration.

### Evaluation interface

```python
class DetectionRule(Protocol):
    metadata: RuleMetadata

    def evaluate(
        self, event: NormalizedSecurityEvent
    ) -> RuleEvaluation | None: ...
```

`None` means no match. `RuleEvaluation` carries the reason code, evidence paths,
short neutral summary, and uncertainty notes. The engine—not individual rules—builds
and validates the final finding.

Each v1 rule may emit at most one finding per event. Multiple different rules may
match the same event and produce separate findings.

## 11. Rule Severity Policy

Allowed values:

| Severity | Meaning |
| --- | --- |
| `INFORMATIONAL` | Evidence is surfaced for visibility; no urgency or maliciousness is inferred. |
| `LOW` | Low review priority supported by the rule's documented rationale. |
| `MEDIUM` | Material review priority with explicit evidence and limitations. |
| `HIGH` | Urgent review priority requiring especially strong deterministic rationale. |

Stage 1.4's two initial rules use `INFORMATIONAL`. This avoids silently converting
FortiGate event or threat severity into detection priority. No `CRITICAL` level is
needed for the initial contract.

## 12. Finding Contract

### Required fields

Every `DetectionFinding` v1.0 contains:

| Field | Purpose |
| --- | --- |
| `finding_schema_version` | Fixed `1.0`. |
| `finding_id` | Deterministic SHA-256-based identity. |
| `rule` | Rule ID, version, name, category, and rule severity. |
| `source_event` | Source type, normalized schema version, record number, and source record ID. |
| `reason_code` | Stable machine-readable reason. |
| `summary` | Short neutral explanation of what matched. |
| `evidence` | Ordered canonical evidence entries. |
| `time_basis` | `NOT_USED` for all Stage 1.4 rules. |
| `uncertainties` | Explicit interpretation limitations. |
| `false_positive_note` | Concise reminder that legitimate/ambiguous contexts may match. |
| `deterministic` | Always `true` for Stage 1.4 output. |

### Evidence entry

Each evidence entry contains:

- `canonical_path`;
- exact JSON-compatible `observed_value`;
- ordered source fields from normalized provenance;
- normalization mapping operation;
- normalization interpretation status.

Evidence is ordered lexicographically by canonical path. Null or missing values are
not emitted as positive evidence unless the rule explicitly and safely tests
missingness; the initial rules do not.

### Source traceability

The finding records:

- `source.adapter_type` as source type;
- `source.record_number` as logical normalized record number;
- `event.source_record_id` as opaque source record ID;
- normalized schema version.

It does not embed the full 907 MB normalized record set or raw source record in each
finding. The record number and source record ID locate the original normalized event,
whose `source_record` and provenance lead back to the FortiGate record.

### Deterministic finding identity

`finding_id` is the lowercase SHA-256 hex digest of a length-prefixed UTF-8 sequence:

1. finding schema version;
2. rule ID;
3. rule version;
4. source type;
5. normalized schema version;
6. logical source record number as decimal text;
7. opaque source record ID or an explicit `<MISSING>` marker.

This identity contains no wall-clock timestamp and is stable for equal input and rule
configuration.

## 13. Time Policy

Stage 1.4 implements no time-window, rate, frequency, or ordering-based security rule.

- `data_timestamp` is never read by a rule.
- `time.itime_utc_derived` is not a window clock because its epoch interpretation is
  still `NEEDS_VERIFICATION`.
- `time.itime_raw` may be preserved in the normalized event but is not initial rule
  evidence.
- Findings use `time_basis = NOT_USED`.
- Findings contain no current wall-clock evaluation time because it would make JSONL
  output nondeterministic.
- Input order is used only for deterministic streaming output, not as event chronology.

Stateful/time-window rules require a separate later plan with verified time semantics,
ordering policy, late/out-of-order behavior, bounded state, eviction policy, units,
and justified thresholds.

## 14. Initial Rule Selection Policy

An initial rule must be:

- record-level and deterministic;
- supported by current normalized canonical fields;
- explainable through exact evidence and provenance;
- testable with small synthetic events;
- independent of unknown timestamps and duration units;
- free of arbitrary numeric thresholds;
- explicit about source-product meaning and false positives;
- safe when optional values are missing;
- useful as an engine/contract baseline rather than a claim of attack truth.

Rules based on traffic volume, session frequency, repeated denies, rare ports, or
time windows are deferred because their thresholds/time assumptions are not yet
justified.

## 15. Planned Initial Rule Specifications

These are implementation specifications for checkpoint 1.4D, not rules implemented
by this planning task.

### Rule 1 — FortiGate Source Threat Observation

| Item | Specification |
| --- | --- |
| Rule ID | `fortigate.source_threat_observation` |
| Version | `1.0` |
| Category | `SOURCE_PRODUCT_OBSERVATION` |
| Severity | `INFORMATIONAL` |
| Supported source | `fortigate` only |
| Condition | At least one leaf in `threat_observations` is non-null and non-empty. |
| Reason code | `SOURCE_THREAT_OBSERVATION_PRESENT` |
| Required section | `threat_observations` |
| Evidence | Every populated `threat_observations.*` leaf, ordered by canonical path. |
| Time basis | `NOT_USED` |

Security rationale: the source product emitted one or more threat-related
observations that may deserve analyst visibility.

False-positive/interpretation boundary: a product observation may reflect policy,
classification, scanning, or vendor logic and is not independently confirmed as an
attack. Records without threat values are not labeled benign.

The rule emits one finding per matching event, regardless of how many threat fields
are populated.

### Rule 2 — FortiGate Anomaly Subtype Observation

| Item | Specification |
| --- | --- |
| Rule ID | `fortigate.anomaly_subtype_observation` |
| Version | `1.0` |
| Category | `SOURCE_PRODUCT_OBSERVATION` |
| Severity | `INFORMATIONAL` |
| Supported source | `fortigate` only |
| Condition | `event.subtype_source` equals the exact case-sensitive source value `anomaly`. |
| Reason code | `SOURCE_ANOMALY_SUBTYPE_OBSERVED` |
| Required path | `event.subtype_source` |
| Evidence | Populated `event.type_source`, `event.subtype_source`, `event.action_source`, and `event.severity_source`. |
| Time basis | `NOT_USED` |

Security rationale: FortiGate supplied an `anomaly` subtype observation that may
deserve review.

False-positive/interpretation boundary: `anomaly` is a source-product category, not
proof of maliciousness, compromise, or attack.

### Overlap policy

The same event may match both rules. The engine emits two independent findings in
ascending rule-ID order. It does not merge them into an incident or suppress either
finding.

## 16. Threshold Policy

Stage 1.4's initial rules use no thresholds.

Any future threshold proposal must document:

- exact rationale and evidence source;
- units;
- denominator;
- time/order window if any;
- inclusive/exclusive comparison;
- default and allowed range;
- false-positive scenarios;
- synthetic boundary tests;
- real-data behavior;
- interpretation limitations.

If these cannot be established, verdict is `NEEDS SECURITY REVIEW` and work stops.
Never invent values such as “10 connections,” “100 packets,” or “5 denies.”

## 17. Determinism and Ordering

- Validate unique rule IDs in the registry.
- Sort active rules lexicographically by `rule_id`; do not rely on import, set, or
  dictionary iteration order.
- Read normalized records in JSONL order and require positive, strictly increasing
  source record numbers for the validated artifact.
- Emit findings in `(source record number, rule_id)` order.
- Serialize compact UTF-8 JSON with `sort_keys=True` and `\n` line endings.
- Do not include wall-clock times, random IDs, absolute temporary paths, or unordered
  evidence.
- Equal normalized bytes plus equal rule definitions must produce byte-identical
  finding JSONL and matching SHA-256 hashes.

## 18. Streaming and Memory Boundaries

The normalized artifact is approximately 907 MB. Stage 1.4 therefore requires:

- one normalized JSON object/event in memory at a time;
- one event's rule evaluations/findings in memory at a time;
- aggregate counters by rule and severity;
- at most five bounded sample finding references per rule in the run summary;
- no collection of all events or all findings in memory;
- no session/entity history because stateful rules are out of scope;
- streaming output to a temporary processed-data file;
- publish final output only after complete success;
- delete only the exact temporary file on failure;
- reject an existing final output with no overwrite option.

## 19. Normalized Input Reader Policy

Stage 1.4 needs a new detection-side JSONL reader, not another FortiGate parser.

The reader must:

- open UTF-8 JSON Lines read-only;
- process one non-empty line at a time;
- reject invalid JSON, non-object roots, missing required sections, unsupported schema
  versions, malformed provenance/issues, and invalid normalized contract values;
- reconstruct public Stage 1.3 model objects using `src/normalization/models.py`;
- call the existing public `validate_normalized_event` after reconstruction;
- preserve line number and normalized source record number for errors;
- never import private helpers such as `_as_normalized_event` from
  `src/audit_normalized_output.py`;
- never weaken or silently repair normalized input.

If safe reconstruction requires changing the Stage 1.3 contract, stop with
`NEEDS CONTRACT CHANGE` rather than editing normalization code.

## 20. Public Interfaces Planned for Stage 1.4

```python
iter_normalized_events(path: str | Path) -> Iterator[NormalizedSecurityEvent]

evaluate_event(
    event: NormalizedSecurityEvent,
    rules: Sequence[DetectionRule],
) -> tuple[DetectionFinding, ...]

evaluate_detection_jsonl(
    input_path: str | Path,
    output_path: str | Path,
    rules: Sequence[DetectionRule],
) -> DetectionRunSummary

audit_detection_jsonl(
    path: str | Path,
    expected_summary: DetectionRunSummary | None = None,
) -> DetectionOutputAudit
```

The CLI uses the reviewed built-in registry. Stage 1.4 does not expose dynamic rule
loading or arbitrary configuration paths.

## 21. Output and CLI Contract

Planned PowerShell-compatible command:

```powershell
python .\src\evaluate_detections.py `
  --input .\data\processed\stage_1_3f_normalized_events.jsonl `
  --output .\data\processed\stage_1_4f_detection_findings.jsonl
```

Rules:

- input must be an existing file;
- output must be a new file under `data/processed/`;
- input and output must differ;
- output parent must already exist;
- existing output is rejected; no overwrite flag;
- write through a uniquely named temporary file under `data/processed/`;
- publish by non-overwriting rename after successful completion;
- print one compact bounded `DetectionRunSummary` JSON object to stdout;
- print concise errors to stderr and return nonzero;
- never print normalized events or an unbounded finding list.

## 22. Detection Run Summary

The bounded summary contains:

- finding schema version;
- normalized input path and normalized schema version;
- finding output path;
- normalized input record count;
- evaluated record count;
- invalid input count;
- total finding count;
- counts by rule ID;
- counts by rule severity;
- count of unique matched source records;
- at most five sample entries per rule containing only finding ID and source record
  number;
- ordered active rule ID/version list;
- no raw source identifiers or giant evidence samples.

Runtime wall-clock metadata may be printed by an external validator but must not enter
the deterministic finding JSONL or be part of its comparison hash.

## 23. Provenance and Evidence Preservation

For each evidence path, the engine finds the matching `FieldProvenance` entry in the
normalized event and copies its source fields, operation, and interpretation status
into the finding evidence.

A finding is invalid if:

- positive evidence lacks a canonical path;
- the path is absent or its observed value differs from the normalized event;
- a source-derived evidence value lacks matching provenance;
- the source record number/ID differs from the normalized event;
- the rule reason code or version differs from the registry;
- the finding contains attack, incident, malicious/benign, or risk decision fields.

The output audit must verify these relationships without storing the full normalized
or finding files in memory.

## 24. False-Positive Discipline

Every accepted rule specification must document:

- precise match condition;
- security rationale;
- required canonical fields;
- behavior when fields are missing;
- evidence paths;
- false-positive or ambiguous scenarios;
- threshold rationale, if ever applicable;
- time semantics, if ever applicable;
- source limitations;
- deterministic behavior;
- unit tests;
- measured real-data match count;
- explicit statement that match != confirmed attack.

The initial rules intentionally surface source-product observations at
`INFORMATIONAL` priority. Their findings should be reviewed as evidence, not counted
as confirmed attacks.

## 25. Rule Quality Review Template

Before a rule enters the built-in registry, its documentation must answer:

| Review item | Required answer |
| --- | --- |
| Purpose | What observation is surfaced? |
| Exact condition | Which canonical values produce a match? |
| Security rationale | Why may an analyst care? |
| Required fields | Which canonical paths are mandatory? |
| Missing-field behavior | No-match, error, or justified missingness rule? |
| Evidence | What exact paths and values are emitted? |
| False positives | Which normal/ambiguous contexts may match? |
| Deterministic | Is equal input/config guaranteed equal output? |
| Threshold | None, or fully justified and tested? |
| Time semantics | `NOT_USED`, or independently verified? |
| Traceability | Can the source record be located? |
| Synthetic tests | Match, no-match, boundaries, missing values? |
| Real-data count | Measured only after validation? |
| Limitations | What must not be concluded? |

## 26. Synthetic Testing Strategy

Unit tests use small synthetic `NormalizedSecurityEvent` objects and temporary JSONL
fixtures. They must not require the 907 MB normalized artifact or 39.3 MiB raw CSV.

Required cases:

- valid rule metadata and rejection of duplicate/invalid IDs, versions, severity, or
  empty false-positive/limitation documentation;
- no match and correct match for each initial rule;
- exact evidence paths, observed values, provenance, reason code, and source trace;
- one event matching both rules in stable rule-ID order;
- multiple events preserving record order;
- empty input producing zero findings;
- missing optional event/threat fields producing no false match or crash;
- unknown event categories preserved without a finding;
- opaque identifiers copied only as opaque evidence when explicitly selected;
- repeated session IDs producing independent evaluations;
- normalized issues such as expected ICMP missing ports not becoming findings;
- `data_timestamp` and derived UTC not used by rules;
- deterministic finding IDs and byte-identical JSONL;
- malformed/unsupported normalized JSONL failing explicitly;
- missing/invalid provenance failing validation;
- unsupported source type causing no source-specific match;
- stable severity and reason codes;
- no prohibited attack, incident, risk, malicious/benign, MITRE, or ML fields;
- unsafe output paths, input/output equality, existing output, missing parent, and
  failure cleanup;
- bounded summary samples and count reconciliation;
- audit rejection of tampered finding evidence, ID, order, rule metadata, or count;
- complete existing Stage 1.1–1.3 test suite remains passing.

## 27. Real-Data Validation Strategy

Real-data validation measures rule behavior. It does not prove that findings are real
attacks.

Prerequisites:

1. Working Python 3.12 environment.
2. Complete synthetic suite passes.
3. `data/processed/stage_1_3f_normalized_events.jsonl` exists.
4. Normalized artifact size/hash match Stage 1.3 evidence.
5. Raw SHA-256 matches if the validator accesses the raw file.

Procedure:

1. Confirm Git safety and intended paths.
2. Hash the normalized input and compare with the documented Stage 1.3 hash.
3. Optionally hash the raw source for integrity only; do not parse it for detection.
4. Run detection once to the primary processed findings path.
5. Stream-audit every finding against rule metadata and corresponding normalized
   records.
6. Record counts by rule/severity and unique matched record count.
7. Retain at most five sample finding references per rule in the summary; do not put
   identifiers or full evidence rows into checked-in documentation.
8. Run a second detection to a separate temporary processed path.
9. Compare primary and second-run SHA-256 values for exact determinism.
10. Remove only the verified second-run temporary artifact.
11. Rerun the complete test suite.
12. Run `git diff --check`, inspect `git status`, and ensure raw/processed data remain
    ignored and untracked.
13. Document measured results, false-positive limitations, and actual verdict.

Expected reconciliation from already verified Stage 1.2 evidence:

- `fortigate.source_threat_observation`: expected 25 matches;
- `fortigate.anomaly_subtype_observation`: expected 18 matches;
- expected total findings: 43;
- expected unique matched source records: 25 if the 18 anomaly records are within
  the 25 threat-present records;
- expected findings by rule severity: 43 `INFORMATIONAL`.

These are evidence-based expectations, not values to force into implementation. Any
difference requires `NEEDS SECURITY REVIEW`; do not edit code/tests to make the counts
match without explaining the evidence.

If the normalized artifact is missing or its hash differs, stop. Do not silently
regenerate it or weaken the expected hash. Regeneration belongs to the approved Stage
1.3 validator and requires explicit direction.

## 28. Contract Change Policy

Stage 1.3 contracts are stable by default.

If detection reveals a genuine contract problem, report:

- exact affected file/type/path;
- normalized evidence demonstrating the problem;
- why detection cannot continue safely;
- smallest proposed contract change;
- Stage 1.3 tests, audit, hashes, and documentation requiring revalidation;
- compatibility impact on existing JSONL.

Then stop with `NEEDS CONTRACT CHANGE`. Do not modify normalization in the same
checkpoint or hide the change inside detection work.

## 29. Mandatory Checkpoint Gate

Apply after every checkpoint:

```text
READ CONTEXT
  -> STATE CHECKPOINT OBJECTIVE
  -> IMPLEMENT MINIMUM APPROVED CHANGE
  -> RUN COMPLETE TEST SUITE
  -> CHECKPOINT-SPECIFIC VALIDATION
  -> REAL-DATA VALIDATION IF REQUIRED
  -> RAW/NORMALIZED DATA INTEGRITY CHECK
  -> git diff --check
  -> COMPLETE DIFF REVIEW
  -> SECURITY INTERPRETATION REVIEW
  -> VERDICT
  -> NEEDS APPROVAL
  -> LOCAL COMMIT ONLY WITH EXPLICIT USER AUTHORIZATION
  -> NEXT CHECKPOINT
```

Only `PASS` may reach approval/commit. The technical `PASS` does not itself authorize
a commit. If explicit commit approval is absent, stop at `NEEDS APPROVAL`.

Non-PASS verdicts that must stop:

- `FAIL`
- `PASS WITH CAUTION`
- `AWAITING LOCAL VALIDATION`
- `BLOCKED BY ENVIRONMENT`
- `NEEDS CONTRACT CHANGE`
- `NEEDS SECURITY REVIEW`

## 30. Checkpoint 1.4A — Detection Terminology and Contracts

### Objective

Define and test the minimal rule, finding, evidence, and run-summary contracts before
creating evaluation behavior.

### Why It Exists

Stable terminology and output contracts prevent later rules from inventing attack
claims, mixing severity meanings, or emitting untraceable findings.

### Inputs

- This plan.
- `AGENTS.md`.
- `docs/normalized_event_schema.md`.
- `src/normalization/models.py`.
- `docs/stage_1_3_normalization_findings.md`.

### Expected Outputs

- `docs/detection_contract.md`.
- `src/detection/__init__.py`.
- `src/detection/models.py`.
- Contract-focused start of `tests/test_detection.py`.

### Likely Files Changed

Only the files listed above.

### Implementation Scope

- Define fixed finding schema version `1.0`.
- Implement immutable rule metadata, evidence, evaluation, finding, and run-summary
  models.
- Validate severity/status vocabularies, rule IDs/versions, JSON-compatible evidence,
  non-empty false-positive/limitation text, and deterministic serialization.
- Implement deterministic finding-ID helper with the exact input sequence in Section
  12.

### Explicitly Out of Scope

No rule conditions, engine, JSONL input reader, CLI, real-data access, thresholds, or
normalization changes.

### Synthetic Tests

- Valid model construction and deterministic serialization.
- Rejection of malformed IDs, versions, severities, missing documentation, duplicate
  evidence paths, non-JSON evidence, and prohibited security-decision fields.
- Deterministic finding IDs and separation of rule/source severity.

### Real-Data Validation

Not required. Do not read normalized or raw real data.

### Security Interpretation Boundaries

Models use finding/match/evidence terminology only. No attack, incident, benign,
malicious, confidence, or risk decision field.

### Acceptance Criteria

- Contract is minimal, JSON-serializable, deterministic, and source-neutral.
- Evidence/provenance and false-positive boundaries are required.
- Existing 68 tests and new contract tests pass in Python 3.12.
- Diff contains only checkpoint files and passes whitespace/security review.

### Stop Conditions

If the current Codex context cannot invoke the validated local Python environment,
finish only the pre-validation work and stop at `AWAITING LOCAL VALIDATION` with the
exact commands from the execution-context policy. Stop with the applicable non-PASS
verdict if the contract requires Stage 1.3 changes or a field conflates detection
with attack/incident meaning. Use `BLOCKED BY ENVIRONMENT` only if the checkpoint
truly cannot proceed safely, not merely because Codex is isolated from local Python.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 31. Checkpoint 1.4B — Python Rule Registry and Initial Rule Specification

### Objective

Create the immutable Python rule interface/registry and document the exact initial
rule specifications without implementing their match conditions yet.

### Why It Exists

The registry and quality review must be fixed before the engine and production rules
so rule ordering, metadata, scope, and interpretation remain consistent.

### Inputs

- Approved 1.4A contracts.
- Sections 9–16 of this plan.
- Stage 1.2 semantic findings and Stage 1.3 canonical paths.

### Expected Outputs

- `src/detection/rules.py` containing the rule protocol, registry validation, and
  reviewed metadata definitions.
- `docs/initial_detection_rules.md` with both quality-review tables.
- Registry tests in `tests/test_detection.py`.

### Likely Files Changed

The three files above.

### Implementation Scope

- Define an ordered built-in registry and lexicographic rule-ID ordering.
- Define exact metadata for the two rules in Section 15.
- Reject duplicate IDs, unsupported severity/category/source metadata, or missing
  rationale/false-positive/limitation documentation.
- Use placeholder/no-match evaluators until 1.4D; clearly mark them not active in the
  production registry if necessary to prevent accidental findings.

### Explicitly Out of Scope

No production match logic, engine, external config/DSL, threshold, time rule, CLI, or
real-data run.

### Synthetic Tests

- Stable registry ordering and unique IDs.
- Exact metadata/documentation reconciliation.
- Both rules are FortiGate-only and informational.
- No threshold/window fields or dynamic code loading.

### Real-Data Validation

Not required.

### Security Interpretation Boundaries

Rule descriptions explicitly say source observation and match != attack. FortiGate
severity is not copied to rule severity.

### Acceptance Criteria

- Registry and documentation agree exactly.
- Both rules pass the full quality-review template.
- Complete test suite passes and no evaluator can accidentally emit a real finding.

### Stop Conditions

Stop if rule rationale depends on unknown time semantics, arbitrary thresholds,
vendor assumptions not present in evidence, or a normalization contract change.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 32. Checkpoint 1.4C — Streaming Normalized Input and Record-Level Engine

### Objective

Build a strict streaming reader for normalized JSONL and a deterministic engine that
can evaluate synthetic record-level rules.

### Why It Exists

Input validation and engine behavior must be proven independently before production
security rules are activated.

### Inputs

- Approved detection contracts and registry interface.
- Public Stage 1.3 models/validator and normalized schema v1.0.
- Small synthetic normalized JSONL fixtures.

### Expected Outputs

- `src/detection/input.py`.
- `src/detection/engine.py`.
- Reader/engine tests in `tests/test_detection.py`.

### Likely Files Changed

Only the files above and package exports if required.

### Implementation Scope

- Strict line-by-line reconstruction and validation of normalized events.
- Record-level evaluation only.
- Stable rule ordering and one finding per rule/event.
- Central finding construction, ID generation, evidence/provenance copying, and output
  ordering.
- Synthetic test rules only; production rules stay inactive until 1.4D.

### Explicitly Out of Scope

No stateful/window logic, session grouping, real-data scan, production rules, CLI,
or Stage 1.3 edits.

### Synthetic Tests

- Empty/valid/malformed JSONL.
- Unsupported schema version and invalid provenance.
- Match/no-match, multiple rules, repeated sessions, unsupported source, ordering,
  deterministic IDs, evidence correctness, and bounded memory behavior by design.

### Real-Data Validation

Not required. Do not open the 907 MB artifact.

### Security Interpretation Boundaries

The engine executes conditions and constructs findings; it does not infer attacks,
confidence, incidents, or missing evidence.

### Acceptance Criteria

- Reader uses public Stage 1.3 contracts without private audit helpers.
- Invalid input stops explicitly; no line is skipped silently.
- Engine output is deterministic and provenance-correct.
- Complete suite passes.

### Stop Conditions

Stop on contract incompatibility, unbounded collection, nondeterminism, silent input
repair, or missing provenance. If Codex cannot invoke the validated local Python
environment for runtime validation, stop at `AWAITING LOCAL VALIDATION` and provide
the exact local commands; do not classify Codex isolation as a project environment
failure.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 33. Checkpoint 1.4D — Initial Source-Observation Rule Set

### Objective

Implement the two reviewed record-level rule conditions exactly as specified and
activate them in the built-in registry.

### Why It Exists

The first real rules prove the contracts and engine using clear source observations
without thresholds, time windows, or attack claims.

### Inputs

- Approved 1.4A–1.4C contracts/engine.
- `docs/initial_detection_rules.md`.
- Canonical paths and Stage 1.2 evidence in Sections 4 and 15.

### Expected Outputs

- Production evaluators in `src/detection/rules.py`.
- Completed rule-specific tests and documentation reconciliation.

### Likely Files Changed

- `src/detection/rules.py`
- `tests/test_detection.py`
- `docs/initial_detection_rules.md` only if implementation clarification is required
  without changing approved meaning.

### Implementation Scope

- Exact threat-observation and anomaly-subtype conditions.
- Informational findings only.
- Populated evidence paths only, complete normalized provenance, `NOT_USED` time basis,
  and one finding per rule/event.
- Stable overlap behavior.

### Explicitly Out of Scope

No new third rule, thresholds, denies-as-attacks, numeric anomalies, time/state,
correlation, suppression, scoring, or real-data run.

### Synthetic Tests

- Each rule match/no-match.
- Empty/partial threat observations.
- Exact case-sensitive anomaly value and unknown subtypes.
- Both rules on one event.
- Missing optional context.
- Unsupported source type.
- Evidence/provenance, severity, reason, false-positive note, deterministic ID/order.

### Real-Data Validation

Not required. Rule behavior remains synthetic until the streaming CLI and audit exist.

### Security Interpretation Boundaries

Every finding states source-product observation and match != confirmed attack.
Absence of a finding does not mean benign.

### Acceptance Criteria

- Conditions match the approved specifications exactly.
- No threshold, time field, raw FortiGate field, or prohibited conclusion is used.
- All tests pass and documentation matches active metadata.

### Stop Conditions

Stop on unexpected canonical paths, uncertain vendor interpretation, evidence loss,
or pressure to add extra rules without a separate review.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 34. Checkpoint 1.4E — Deterministic Finding CLI and Output Audit

### Objective

Connect the reader, engine, and rules through a safe streaming CLI and independently
audit finding output.

### Why It Exists

Synthetic end-to-end publication and audit safety must pass before processing the
large normalized artifact.

### Inputs

- Approved 1.4A–1.4D implementation.
- Small synthetic normalized JSONL files.
- Output and summary contracts in Sections 17–23.

### Expected Outputs

- `src/evaluate_detections.py`.
- `src/audit_detection_output.py`.
- End-to-end and audit tests.
- Updated `docs/detection_contract.md` for verified CLI behavior.

### Likely Files Changed

The files above and `tests/test_detection.py`.

### Implementation Scope

- Streaming JSONL evaluation and atomic publish-on-success behavior.
- Safe path validation and existing-output rejection.
- Bounded run summary.
- Streaming audit of schema, finding IDs, ordering, rule metadata, evidence,
  provenance, counts, and prohibited fields.

### Explicitly Out of Scope

No real-data run, new rule, rule config file, threshold, state, database, API, or
processed artifact commit.

### Synthetic Tests

- End-to-end count/order and multi-rule output.
- Byte-for-byte determinism.
- Empty input.
- Unsafe/existing paths and temporary cleanup.
- Tampered finding ID/evidence/provenance/rule metadata/order/count.
- Bounded summary and concise CLI errors.

### Real-Data Validation

Not required until checkpoint 1.4F.

### Security Interpretation Boundaries

CLI and audit measure findings; they do not confirm attacks or calculate risk.

### Acceptance Criteria

- Synthetic output is safe, deterministic, and fully auditable.
- Failures publish no partial final output.
- Complete suite passes and diff contains no generated data.

### Stop Conditions

Stop on nondeterminism, unsafe overwrite/delete behavior, count mismatch, unbounded
output in memory, audit weakness, or test failure.

### Commit Gate

Report verdict and request explicit approval before a local commit.

## 35. Checkpoint 1.4F — Real-Data Rule Behavior and False-Positive Audit

### Objective

Evaluate the two approved rules against the validated 100,000-record normalized
artifact and document measured behavior without claiming attack truth.

### Why It Exists

Real-data counts and samples are needed to assess rule usefulness, overlap, evidence,
and false-positive limitations before declaring the detection foundation ready.

### Inputs

- Approved complete detection path.
- `data/processed/stage_1_3f_normalized_events.jsonl`.
- Documented normalized/raw hashes.
- Existing Stage 1.3 validation evidence.

### Expected Outputs

- `scripts/validate_stage_1_4.ps1`.
- Ignored Stage 1.4F findings and summary under `data/processed/`.
- `docs/stage_1_4_detection_findings.md`.

### Likely Files Changed

Only the validator and findings document are tracked; processed artifacts remain
ignored/untracked.

### Implementation Scope

- Execute the controlled procedure in Section 27.
- Validate hashes, counts, determinism, provenance, bounded summaries, Git safety,
  and the full test suite.
- Document facts, expected-versus-measured counts, overlap, false-positive scenarios,
  limitations, and actual verdict.

### Explicitly Out of Scope

No rule tuning to force counts, new rules, sampling-based attack claims, incident
creation, correlation, thresholds, ML, API, or dashboard.

### Synthetic Tests

Complete Stage 1.1–1.4 suite before and after real-data evaluation. Validator failure
paths receive small/safe tests where practical.

### Real-Data Validation

Required. Detection input is read-only. Raw data is used only for optional hash
verification, not rule evaluation. Two finding runs must produce equal hashes.

### Security Interpretation Boundaries

Measured findings are rule matches. They are not verified attacks, incident counts,
detection accuracy, precision, recall, or ground truth.

### Acceptance Criteria

- Normalized input hash and record count match Stage 1.3 evidence.
- 100,000 records are evaluated with no silent skip/deduplication.
- Finding counts reconcile by rule/severity and audit passes every finding.
- Expected counts match or any difference stops for review.
- Determinism, complete tests, Git safety, and raw integrity pass.
- Documentation contains aggregate facts and no fabricated performance metric.

### Stop Conditions

Stop on missing/mismatched input artifact, unexpected count, nondeterminism, evidence
failure, raw/processed tracking, test failure, or non-PASS security review.

### Commit Gate

Report measured verdict and request explicit approval before a local commit.

## 36. Checkpoint 1.4G — Final Documentation and Readiness Gate

### Objective

Reconcile contracts, rule definitions, engine, CLI, audit, tests, real-data behavior,
and limitations; then decide readiness for a separately planned next stage.

### Why It Exists

Stage completion requires documentation and code to agree and requires an honest
security-readiness verdict, not only passing unit tests.

### Inputs

- All approved 1.4A–1.4F outputs.
- Stage 1.4 validator results.
- Existing Stage 1.2/1.3 evidence and boundaries.

### Expected Outputs

- Final `docs/detection_contract.md`.
- Final `docs/initial_detection_rules.md`.
- Final `docs/stage_1_4_detection_findings.md`.
- Minimal `README.md` completion update only after every gate passes.

### Likely Files Changed

Documentation and README only unless reconciliation identifies a defect, in which
case stop and fix it in the responsible checkpoint rather than hiding it here.

### Implementation Scope

- Cross-check metadata, canonical paths, reason/severity, tests, audit, false-positive
  notes, and measured counts.
- Run final validator and full diff/security review.
- Record actual PASS or non-PASS readiness verdict.

### Explicitly Out of Scope

No additional rule, threshold, time/state logic, database, API, correlation, incident,
ML, LLM, dashboard, or deployment work.

### Synthetic Tests

Complete Stage 1.1–1.4 suite and documentation/registry reconciliation tests.

### Real-Data Validation

Required through the approved Stage 1.4 validator; no extra ad hoc scan.

### Security Interpretation Boundaries

Final documentation must preserve rule match != confirmed attack and may not report
accuracy, detection rate, or attack count without ground truth.

### Acceptance Criteria

- Definition of Done is fully satisfied.
- Code, contracts, rule review tables, and measured findings agree.
- Final verdict is `PASS` with no hidden caution.
- Generated artifacts remain ignored and source evidence remains immutable.

### Stop Conditions

Stop with the actual non-PASS verdict on any inconsistency, failed gate, or unresolved
security concern. Do not begin the next stage.

### Commit Gate

Report final verdict and request explicit approval before a local commit.

## 37. Out of Scope for Stage 1.4

- time-window, frequency, rate, or stateful rules;
- arbitrary traffic/packet/session/deny thresholds;
- attack or malicious/benign labels;
- anomaly models, supervised/unsupervised ML, deep learning, or embeddings;
- LLM, RAG, or automated threat-hunting agents;
- incident correlation, incident management, alert suppression, or prioritization;
- risk scoring or automated response;
- MITRE ATT&CK automation;
- external enrichment, reputation lookups, or deanonymization;
- PostgreSQL, other databases, OpenSearch, Redis, or Kafka;
- FastAPI, frontend/dashboard, Docker, Kubernetes, or cloud deployment;
- a second log-source adapter;
- modification of the stable Stage 1.3 contract without the stop/approval process.

## 38. Multi-Source Boundary

The first two rules are FortiGate-specific because they interpret FortiGate source
observations. They still use canonical normalized paths and explicitly declare
`supported_source_types = ("fortigate",)`.

Future authentication, IDS/IPS, EDR, Windows/Linux, VPN, proxy, DNS, cloud, Active
Directory, NetFlow, or email-security sources should supply `NormalizedSecurityEvent`
records through their own future adapters. Generic detection rules may later operate
on source-neutral canonical concepts. Stage 1.4 neither implements those adapters nor
pretends FortiGate product labels are universal.

## 39. Risks and Controls

| Risk | Required control |
| --- | --- |
| Treating a match as an attack | Finding terminology and mandatory uncertainty/false-positive fields. |
| Rules read raw FortiGate fields | Require canonical paths and normalized provenance. |
| Event severity becomes rule severity | Separate fixed rule-severity vocabulary. |
| Unknown timestamps used for windows | Record-level only; `time_basis = NOT_USED`. |
| Arbitrary thresholds | No threshold in initial rules; future proposal stops for review. |
| 907 MB loaded into memory | Streaming reader, per-event evaluation, bounded counters/samples. |
| Repeated sessions deduplicated | One evaluation per normalized record in input order. |
| Missing ICMP ports become alerts | Explicitly prohibit missingness-based initial rules. |
| Threat field becomes ground truth | Informational source-observation rule and limitations. |
| Nondeterministic findings | Stable rule/event order, hashed IDs, sorted evidence/JSON keys, no wall clock. |
| Finding loses source trace | Record number, record ID, evidence provenance, output audit. |
| Dynamic rule execution risk | Python built-in registry only; no DSL/eval/dynamic loading. |
| Partial or overwritten output | New processed path, temporary file, publish on success, no overwrite. |
| Detection alters normalization | Dependency direction and `NEEDS CONTRACT CHANGE` stop policy. |
| Generated data enters Git | Output only under ignored `data/processed/`; status/ls-files checks. |
| Agent continues after warning | Mandatory verdict gate and explicit stop conditions. |

## 40. Definition of Done

Stage 1.4 is complete only when:

1. Normalized events can be evaluated by deterministic record-level rules.
2. Rule metadata and evaluation have a stable, documented v1.0 contract.
3. Detection findings have a stable, documented v1.0 contract.
4. Every finding contains exact evidence and normalized provenance.
5. Every finding remains traceable to a normalized/source record.
6. Initial rules are documented, quality-reviewed, and tested.
7. Rule matches are never presented as confirmed attacks or incidents.
8. False-positive scenarios and interpretation limitations are explicit.
9. Event/threat/rule severity meanings remain separate.
10. Unknown timestamp, duration, and source semantics remain unknown.
11. No arbitrary threshold or hidden time assumption exists.
12. Processing is streaming and bounded-memory.
13. Equal normalized input and rule registry produce byte-identical findings.
14. All Stage 1.1–1.4 synthetic tests pass under Python 3.12.
15. Real-data evaluation processes all 100,000 normalized records without silent
    loss or deduplication.
16. Real-data findings pass evidence, provenance, rule metadata, order, count, and
    determinism audits.
17. Raw data remains immutable and normalized input remains read-only.
18. Detection artifacts remain under ignored `data/processed/` and untracked.
19. Documentation reports measured rule behavior and limitations without fabricated
    accuracy, attack counts, or performance claims.
20. Final checkpoint verdict is `PASS`.
21. No stateful rule, correlation, incident, scoring, ML, API, database, dashboard,
    second source, or deployment work was introduced.

Completion means the project has a transparent rule-based detection baseline ready
for a separately planned data-engineering/API or advanced detection stage. It does
not mean that all attacks are detected, any incident is confirmed, an ML model is
trained, or a SOC is automated.

## 41. Suggested Execution Order

Execute exactly one checkpoint at a time:

1. **1.4A — Detection Terminology and Contracts**
2. **1.4B — Python Rule Registry and Initial Rule Specification**
3. **1.4C — Streaming Normalized Input and Record-Level Engine**
4. **1.4D — Initial Source-Observation Rule Set**
5. **1.4E — Deterministic Finding CLI and Output Audit**
6. **1.4F — Real-Data Rule Behavior and False-Positive Audit**
7. **1.4G — Final Documentation and Readiness Gate**

At each checkpoint report changed files, behavior, data assumptions, tests,
validation, measured results, limitations, security interpretation review, verdict,
and the smallest next checkpoint. Do not implement the next checkpoint until the
gate and required user approval allow it.
