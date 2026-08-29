# Initial Rule Specifications

## Stage 1.4B Status

This document records the two reviewed FortiGate source-observation rule
specifications. They are present as immutable, lexicographically ordered
metadata in `src/detection/rules.py`, but both are **inactive placeholders** in
this checkpoint. They always return no match and emit no findings until a
separately approved Stage 1.4D implementation.

Rule Match != Confirmed Attack. A future match will only state that an explicit
deterministic condition was satisfied; it will not confirm an attack,
compromise, incident, maliciousness, or benignness.

## Registry Catalog

| Rule ID | Version | Category | Rule severity | Supported sources | Required paths | Evidence paths | Reason code | Active in 1.4B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `fortigate.anomaly_subtype_observation` | `1.0` | `SOURCE_PRODUCT_OBSERVATION` | `INFORMATIONAL` | `fortigate` | `event.subtype_source` | `event.action_source`; `event.severity_source`; `event.subtype_source`; `event.type_source` | `SOURCE_ANOMALY_SUBTYPE_OBSERVED` | No |
| `fortigate.source_threat_observation` | `1.0` | `SOURCE_PRODUCT_OBSERVATION` | `INFORMATIONAL` | `fortigate` | `threat_observations` | `threat_observations.action_source`; `threat_observations.id_raw`; `threat_observations.name_source`; `threat_observations.pattern_source`; `threat_observations.reference_source`; `threat_observations.severity_source`; `threat_observations.type_source` | `SOURCE_THREAT_OBSERVATION_PRESENT` | No |

The threat-observation paths are candidates: a future rule will safely test that
at least one is populated. The catalog does not state that every listed path
must be non-null.

## Quality Review — FortiGate Anomaly Subtype Observation

| Review item | Approved answer |
| --- | --- |
| Purpose | Surface FortiGate's exact source subtype `anomaly` for analyst review. |
| Exact condition | `event.subtype_source` equals the exact case-sensitive source value `anomaly`. |
| Security rationale | FortiGate supplied an anomaly subtype observation that may deserve review. |
| Required fields | `event.subtype_source`. |
| Missing-field behavior | No match when the optional source subtype is missing or not exactly `anomaly`. |
| Evidence | Populated `event.type_source`, `event.subtype_source`, `event.action_source`, and `event.severity_source`, in canonical-path order. |
| False positives | The source-product anomaly category may occur without malicious activity. |
| Deterministic | Yes; record-level exact comparison with no time, state, threshold, or external input. |
| Threshold | None. |
| Time semantics | `NOT_USED`. |
| Traceability | Source record number and opaque source record ID link a future finding to its normalized event. |
| Synthetic tests | Metadata, registry ordering, documentation reconciliation, and inactive no-match behavior are covered in 1.4B. Condition tests wait for 1.4D. |
| Real-data count | Not measured in 1.4B. |
| Limitations | A source-product anomaly subtype is not proof of maliciousness, compromise, or attack. |

## Quality Review — FortiGate Source Threat Observation

| Review item | Approved answer |
| --- | --- |
| Purpose | Surface populated FortiGate threat-observation values for analyst visibility. |
| Exact condition | At least one leaf in `threat_observations` is non-null and non-empty. |
| Security rationale | The source product emitted one or more threat-related observations that may deserve analyst visibility. |
| Required fields | Candidate leaves under `threat_observations`; one or more populated leaves are sufficient. |
| Missing-field behavior | No match when all candidate threat-observation leaves are null or empty. Records without threat values are not labeled benign. |
| Evidence | Every populated `threat_observations.*` leaf, in canonical-path order. |
| False positives | A source-product observation may reflect policy, classification, scanning, or vendor logic rather than a confirmed attack. |
| Deterministic | Yes; record-level populated-value check with no time, state, threshold, or external input. |
| Threshold | None. |
| Time semantics | `NOT_USED`. |
| Traceability | Source record number and opaque source record ID link a future finding to its normalized event. |
| Synthetic tests | Metadata, registry ordering, documentation reconciliation, and inactive no-match behavior are covered in 1.4B. Condition tests wait for 1.4D. |
| Real-data count | Not measured in 1.4B. |
| Limitations | Threat values are source-product observations, not ground-truth attack labels. |

## Boundaries

- Both planned rules support only `fortigate` and use `INFORMATIONAL` rule
  severity. This rule severity is distinct from source event and threat severity.
- Neither rule uses `data_timestamp`, `itime`, session-duration values, repeated
  session IDs, traffic volume, a numeric threshold, a time window, state, or
  correlation.
- Sanitized identifiers remain opaque. No identifier is parsed, validated,
  enriched, or used by these metadata definitions.
- The metadata does not create a rule registry with active evaluators, a detection
  engine, JSON Lines reader, CLI, output, audit, incident, score, or label.
