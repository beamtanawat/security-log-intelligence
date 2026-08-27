# Detection Finding Contract v1.0

## Purpose

This document defines the minimal Stage 1.4 contract for transparent,
deterministic, record-level rule findings. It consumes the completed Stage 1.3
`NormalizedSecurityEvent` v1.0 contract; it does not parse raw CSV, change
normalization, evaluate rules, read JSON Lines, write output, or make a security
decision.

## Terminology

| Term | Meaning |
| --- | --- |
| Rule | A versioned, reviewable definition that will later evaluate explicit canonical fields. |
| Rule match | Only that the configured deterministic condition was satisfied. It is not a confirmed attack, compromise, incident, or malicious/benign label. |
| Detection finding | A deterministic record of one future rule match with exact traceability, evidence, and limitations. |
| Detection evidence | A canonical observed value with its copied Stage 1.3 source-field provenance. |
| Rule severity | A fixed review-priority value chosen by rule metadata. It is separate from source event or source threat severity. |
| Reason code | A stable uppercase identifier explaining the configured observation. |
| Source event reference | The source type, normalized schema version, logical record number, and opaque source record ID used to locate the normalized event. |

## Rule metadata

`RuleMetadata` is immutable and contains the stable rule ID/version, neutral
name and description, category, rule severity, supported source types, required
and evidence canonical paths, reason code, rationale, false-positive scenarios,
and limitations.

Allowed v1 values are:

- Category: `SOURCE_PRODUCT_OBSERVATION`
- Rule severity: `INFORMATIONAL`, `LOW`, `MEDIUM`, or `HIGH`
- Initial finding time basis: `NOT_USED`

The contract intentionally has no enabled flag, threshold, window, confidence,
risk score, incident field, or attack/malicious/benign decision field. A future
registry will determine which reviewed rules are active.

## Finding and evidence

Every `DetectionFinding` v1.0 contains:

- fixed `finding_schema_version` of `1.0`;
- deterministic `finding_id`;
- a limited rule reference: ID, version, name, category, and rule severity;
- a `SourceEventReference` to one normalized record;
- reason code and neutral summary;
- one or more lexicographically ordered evidence entries;
- `time_basis = NOT_USED`;
- non-empty uncertainty and false-positive text; and
- `deterministic = true`.

Each `DetectionEvidence` entry includes a canonical path, exact JSON-compatible
observed value, ordered source fields, Stage 1.3 mapping operation, and Stage 1.3
interpretation status. The contract therefore retains the chain:

```text
Detection Finding
        ↓
NormalizedSecurityEvent
        ↓
SourceRecord
        ↓
Original source log
```

## Deterministic identity

The lowercase SHA-256 `finding_id` is generated from a length-prefixed UTF-8
sequence in this exact order:

1. finding schema version;
2. rule ID;
3. rule version;
4. source type;
5. normalized schema version;
6. logical source record number as decimal text;
7. opaque source record ID, or the literal `<MISSING>` marker.

No wall-clock evaluation timestamp participates in the identity or finding.

## Run summary

`DetectionRunSummary` is immutable bounded aggregate metadata for a later
streaming evaluation. It contains input/output paths, normalized input counts,
finding counts by rule and severity, unique matched source-record count, ordered
active rule ID/version references, and at most five finding-ID/record-number
samples per rule. It never contains a full input event, full finding list, or
raw source record.

## Interpretation boundaries

- Rule Match != Confirmed Attack.
- Source event severity, source threat severity, and rule severity are distinct.
- `data_timestamp` remains **UNKNOWN** and is not a detection clock.
- The UTC view derived from `itime` remains **DERIVED** with
  `NEEDS_VERIFICATION`; all v1 findings use `NOT_USED` time basis.
- Sanitized identifiers remain opaque; the contract does not validate or
  deanonymize them.
- Session-duration units remain unresolved.
- Repeated session IDs remain separate source records.
- Threat, application, event, and anomaly values remain source-product
  observations, not ground-truth attack labels.

## Out of scope for this checkpoint

This contract creates no rule registry, rule conditions, rule engine, normalized
JSONL reader, CLI, detection output, audit, real-data evaluation, threshold,
time-window logic, incident, risk score, ML, API, database, dashboard, or
deployment behavior.
