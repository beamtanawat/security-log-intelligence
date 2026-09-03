# Initial Rule Specifications

## Final Stage 1.4 Rule Status

This document records the two reviewed FortiGate source-observation rule
specifications. They are immutable, lexicographically ordered metadata and active
record-level evaluators in `src/detection/rules.py`. The engine constructs a finding
only when one of these exact conditions matches a normalized FortiGate event.

Rule Match != Confirmed Attack. A match states only that an explicit
deterministic condition was satisfied; it will not confirm an attack,
compromise, incident, maliciousness, or benignness.

## Registry Catalog

| Rule ID | Version | Category | Rule severity | Supported sources | Required paths | Evidence paths | Reason code | Active in 1.4D |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `fortigate.anomaly_subtype_observation` | `1.0` | `SOURCE_PRODUCT_OBSERVATION` | `INFORMATIONAL` | `fortigate` | `event.subtype_source` | `event.action_source`; `event.severity_source`; `event.subtype_source`; `event.type_source` | `SOURCE_ANOMALY_SUBTYPE_OBSERVED` | Yes |
| `fortigate.source_threat_observation` | `1.0` | `SOURCE_PRODUCT_OBSERVATION` | `INFORMATIONAL` | `fortigate` | `threat_observations` | `threat_observations.action_source`; `threat_observations.id_raw`; `threat_observations.name_source`; `threat_observations.pattern_source`; `threat_observations.reference_source`; `threat_observations.severity_source`; `threat_observations.type_source` | `SOURCE_THREAT_OBSERVATION_PRESENT` | Yes |

The threat-observation paths are candidates: the active rule safely tests that
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
| Synthetic tests | Metadata, registry ordering, exact condition behavior, evidence/provenance, documentation reconciliation, deterministic findings, streaming output, and audit rejection checks are covered by the Stage 1.4 suite. |
| Real-data count | 18 findings in the validated Stage 1.4F audit. |
| Limitations | A source-product anomaly subtype is not proof of maliciousness, compromise, or attack. |
| False-negative limitation | Only the exact case-sensitive source value `anomaly` matches. Missing or different source values emit no finding and a non-match does not establish absence of security-relevant activity. |
| Source-product limitation | FortiGate's category is preserved as supplied; its underlying vendor logic is not independently verified by this rule. |

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
| Synthetic tests | Metadata, registry ordering, exact condition behavior, evidence/provenance, documentation reconciliation, deterministic findings, streaming output, and audit rejection checks are covered by the Stage 1.4 suite. |
| Real-data count | 25 findings in the validated Stage 1.4F audit. |
| Limitations | Threat values are source-product observations, not ground-truth attack labels. |
| False-negative limitation | Only populated approved `threat_observations.*` leaves match. Missing or unpopulated leaves emit no finding and a non-match does not label a record benign. |
| Source-product limitation | The rule preserves FortiGate observations and does not independently validate vendor classification, scanning, policy, or threat semantics. |

## Validated Real-Data Reconciliation

The Stage 1.4F audit evaluated all 100,000 normalized records with no invalid input
records. The two rules produced 43 `INFORMATIONAL` findings from 25 source records:

| Rule ID | Validated findings | What the count means | What it does not mean |
| --- | ---: | --- | --- |
| `fortigate.anomaly_subtype_observation` | 18 | Exact source subtype `anomaly` was observed. | Confirmed attacks, malicious events, or incidents. |
| `fortigate.source_threat_observation` | 25 | At least one approved source threat-observation leaf was populated. | Ground-truth threats, confirmed attacks, or benign/non-benign labels. |
| **Total findings** | **43** | Separate record-level rule matches; one source record may match both rules. | A count of unique incidents or compromises. |

The finding audit verified source references and copied Stage 1.3 provenance. The
two deterministic evaluation runs produced byte-identical finding output for the
same normalized input and registry. Determinism is reproducible rule-engine
behavior, not a guarantee of semantic correctness or ground truth.

## Boundaries

- Both planned rules support only `fortigate` and use `INFORMATIONAL` rule
  severity. This rule severity is distinct from source event and threat severity.
- Neither rule uses `data_timestamp`, `itime`, session-duration values, repeated
  session IDs, traffic volume, a numeric threshold, a time window, state, or
  correlation.
- Sanitized identifiers remain opaque. No identifier is parsed, validated,
  enriched, or used by these metadata definitions.
- The rules use the existing record-level engine, CLI, and audit; the rules themselves
  add no incident, score, attack label, threshold, time window, or stateful
  correlation.
