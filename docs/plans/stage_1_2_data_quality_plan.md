# Stage 1.2 — Data Quality & Field Understanding Plan

## Document Status

This document is an implementation plan only. It does not implement Stage 1.2,
change the raw dataset, or make security detections.

## 1. Objective

Stage 1.2 will answer the following question:

> What does each important field mean, when is missingness expected, when may it
> indicate a data-quality problem, and which relationships must be understood
> before normalization and detection?

The work will build an evidence-based understanding of the sanitized FortiGate
dataset while keeping the raw CSV immutable. It will produce a data dictionary,
contextual data-quality findings, and a clearly documented list of unresolved
questions. It will not classify records as benign, malicious, or attacks.

## 2. Why Stage 1.2 Is Necessary

Stage 1.1 established trustworthy basic measurements, but minimum/maximum values,
global missing counts, and top-value frequencies do not explain field semantics.
Security logs frequently contain structural missingness, repeated lifecycle events,
source-specific identifiers, and sparse product observations. Treating those patterns
as generic data defects would destroy context and could create misleading detection
or machine-learning inputs later.

Stage 1.2 therefore comes before normalization and detection. It will distinguish
verified relationships from assumptions, preserve source-specific meaning, and make
later engineering decisions auditable.

## 3. Verified Starting State from Stage 1.1

The following values are accepted as the baseline for this stage. Stage 1.2 may
reproduce a value as part of a relationship analysis, but it must not redesign the
completed Stage 1.1 profiler merely to recalculate these measurements.

### Dataset and integrity

| Item | Verified value |
| --- | ---: |
| Dataset | `data/raw/network_log_SAFE.csv` |
| File size | 41,235,093 bytes (approximately 39.3 MiB) |
| Data rows | 100,000 |
| Columns | 58 |
| Exact duplicate rows | 0 |
| SHA-256 | `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D` |

The dataset is sanitized FortiGate network/security data, is ignored by Git, and
must remain local and read-only.

### Event and protocol baseline

- `event_type`: `traffic` = 99,970 (99.97%); `utm` = 30 (0.03%).
- `net_proto`: `6` = 66,357 (66.357%); `1` = 27,447 (27.447%);
  `17` = 6,196 (6.196%).
- Standard protocol-number interpretations may be documented as derived meanings:
  6 = TCP, 1 = ICMP, and 17 = UDP. The original numbers must be preserved.

### Port baseline

- `src_port` and `dst_port` each have 72,553 non-missing and 27,447 missing values.
- The missing count exactly matches the protocol 1/ICMP count. This is a strong
  hypothesis for expected structural missingness, not yet a substitute for checking
  the row-level relationship.

### Identifier and session baseline

- `loguid`: 100,000 non-missing, 100,000 unique, 0 repeated occurrences.
- `net_sessionid`: 100,000 non-missing, 50,399 unique, 49,601 repeated
  occurrences.
- A repeated `net_sessionid` is not an exact duplicate and must not be removed
  automatically.

### Timestamp baseline

- `itime`: 99,999 non-missing and 1 missing; minimum 1,729,294,669; maximum
  1,729,338,553; observed span approximately 12.19 hours.
- `data_timestamp`: 100,000 non-missing; minimum 0; maximum 731.
- The meaning and unit of `data_timestamp` are unresolved. It must not be assumed
  to be a Unix timestamp.

### Session metric baseline

Each of the following fields has 99,222 non-missing values and 778 missing values:

- `net_rcvdpkts`
- `net_recvbytes`
- `net_sentbytes`
- `net_sentpkts`
- `net_sessionduration`

Stage 1.2 must establish whether the missing values occur on the same 778 records
and which event, protocol, application, threat, or session attributes explain them.

### Application baseline

- `app_service` has 108 unique values. Frequent examples include `PING`, `SMB`,
  `DCE-RPC`, `RDP`, `HTTP`, `HTTPS`, `SAMBA`, `tcp/8080`, and `tcp/6160`.
- `app_name` has 129 non-missing records: `AnyDesk` = 104 and `NTP` = 25.
- `app_cat` is mostly `unscanned`; other observed values include
  `Remote.Access`, `unknown`, and `Network.Service`.

### Threat baseline

- `threat_action`, `threat_name`, `threat_severity`, and `threat_type` each have
  25 non-missing values; `threat_id` has 18.
- `threat_action`: `blocked` = 25.
- `threat_type`: `Reconnaissance` = 25.
- `threat_name`: `icmp_sweep` = 10, `icmp_src_session` = 8, and
  `Policy Violation` = 7.
- These values are product observations, not proven ground-truth attack labels.
  Missing threat fields do not prove that a record is benign.

### Geography and numeric baseline

- `src_geo`: `Reserved` = 100%.
- `dst_geo`: `Reserved` = 99.755%, `Singapore` = 0.144%,
  `Russian Federation` = 0.079%, `United States` = 0.013%, and
  `Australia` = 0.009%.
- Selected non-empty numeric fields had zero conversion failures in Stage 1.1.
- Observed ranges include received packets 0–16,024,998, received bytes
  0–15,460,072,207, sent bytes 0–15,805,817,602, sent packets 0–19,128,880,
  and session duration 0–93,632.
- Large values and country values are observations only, not evidence of attacks.

## 4. Questions Stage 1.2 Must Answer

1. What is the best-supported meaning, type, and conceptual group for every one of
   the 58 fields?
2. Which fields are source-specific, and which may map to a future common event
   schema without losing evidence?
3. Which missing values are expected, conditional, suspicious from a data-quality
   perspective, or still unexplained?
4. Do protocol 1 records fully explain missing source and destination ports?
5. What explains the 778 records missing all five session metrics?
6. How do repeated session IDs relate to event actions, subtypes, and session
   lifecycle behavior?
7. Does `itime` behave consistently with epoch seconds, and what context surrounds
   its single missing value?
8. Is there evidence that `data_timestamp` is a sequence, offset, relative time, or
   another source-specific value?
9. How are event, application, threat, identifier, and numeric fields populated in
   relation to one another?
10. Which conclusions are verified, which are hypotheses, and which must remain
    unresolved before normalization?

## 5. Data-Quality Classification

Every material finding will have one of these evidence-based statuses:

| Status | Meaning |
| --- | --- |
| `EXPECTED` | Evidence supports that the value or missingness is structurally normal for its context. |
| `CONTEXT_DEPENDENT` | Validity depends on event type, protocol, lifecycle, or another documented condition. |
| `SUSPICIOUS_DATA_QUALITY` | Evidence indicates a possible collection, parsing, consistency, or completeness problem requiring review. |
| `UNKNOWN` | Available evidence is insufficient to determine meaning or quality. |

These statuses describe data quality only. They must never be translated into
`BENIGN`, `MALICIOUS`, or `ATTACK`.

Field-meaning confidence will be recorded separately as `HIGH`, `MEDIUM`, `LOW`, or
`NEEDS VERIFICATION`. Confidence must reflect evidence from observed relationships,
existing project documentation, and authoritative source semantics when available;
it must not be inferred from a field name alone.

## 6. Planned Implementation Shape and Expected Files

Stage 1.1 remains intact. Future Stage 1.2 implementation should add the smallest
separable units needed for testable analysis:

| Path | Planned responsibility |
| --- | --- |
| `src/data_quality.py` | Small reusable functions for grouped counts, conditional missingness, session grouping, relationship checks, and descriptive statistics. |
| `src/analyze_data_quality.py` | Thin CLI/orchestrator that reads a CSV, calls the reusable functions, and emits a reproducible report. |
| `tests/test_data_quality.py` | Unit tests using small synthetic CSV fixtures only. |
| `docs/data_dictionary.md` | All 58 fields, grouped semantics, types, missing behavior, confidence, and unresolved questions. |
| `docs/stage_1_2_data_quality_findings.md` | Evidence-backed findings, validated relationships, assumptions, limitations, and unresolved items. |
| `data/processed/stage_1_2_data_quality.json` | Optional reproducible machine-readable output from a verified full-data run; remains outside `data/raw/` and is already covered by the processed-data Git ignore policy. |

The existing `src/profile_dataset.py` may be imported or minimally extended only if
a genuinely reusable Stage 1.1 primitive is required. It must not be redesigned.
The implementation should prefer Python 3.12 standard-library code and avoid a new
dependency unless its immediate benefit is documented and approved.

The analysis CLI should accept a dataset path, print JSON by default, and support an
explicit output path under `data/processed/`. It must never select a path under
`data/raw/` as an output. Analysis results should contain counts and percentages with
their denominators, classification status, and evidence notes so documentation does
not depend on untraceable manual calculations.

## 7. Checkpoint 1.2A — Field Inventory and Data-Dictionary Foundation

### Purpose

Establish a complete, evidence-aware inventory before interpreting missingness or
relationships.

### Inputs

- The 58-column CSV header.
- Stage 1.1 profile results.
- `AGENTS.md`, `README.md`, and observed sanitized value forms.

### Analysis

Create one entry for every field and assign it to Event, Timestamp, Source,
Destination, Network, Session, Application, Host, NAT, Threat, or Parser/Source
Metadata. For each entry record:

- field name;
- likely meaning without inventing unsupported semantics;
- observed representation/type;
- nullable behavior and current missingness evidence;
- a safe example value type rather than a dump of sensitive or high-cardinality
  values;
- source-specific or potentially common status;
- interpretation confidence;
- unresolved questions.

The inventory must cover exactly these header fields:

`itime`, `adom_oid`, `app_cat`, `app_service`, `data_parsername`,
`data_sourceid`, `data_sourcename`, `data_sourcetype`, `data_timestamp`,
`dst_geo`, `dst_intf`, `dst_ip`, `dst_mac`, `dst_port`, `epid`, `euid`,
`event_action`, `event_id`, `event_severity`, `event_subtype`, `event_type`,
`host_ip`, `host_location`, `host_mac`, `host_type`, `loguid`, `net_proto`,
`net_rcvdpkts`, `net_recvbytes`, `net_sentbytes`, `net_sentpkts`,
`net_sessionduration`, `net_sessionid`, `src_geo`, `src_intf`, `src_ip`,
`src_mac`, `src_port`, `event_profile`, `host_osver`, `src_natip`,
`src_natport`, `host_hwvendor`, `host_hwver`, `host_osfamily`, `host_osname`,
`host_name`, `src_domain`, `threat_action`, `threat_name`, `threat_severity`,
`threat_type`, `app_id`, `app_name`, `threat_pattern`, `event_message`,
`threat_id`, and `threat_ref`.

### Expected Outputs

- A complete data-dictionary skeleton with evidence and confidence columns.
- An explicit unresolved-field list.
- A machine-readable field inventory in the analysis result for completeness checks.

### Tests

- A fixture with known, optional, and unknown columns.
- A completeness test proving every header appears once.
- A grouping test proving an unknown field remains represented and is marked for
  verification rather than discarded.
- A sanitized-identifier fixture proving tokenized IP/MAC-like values are accepted
  as opaque strings.

### Acceptance Criteria

- All 58 fields appear exactly once.
- No uncertain meaning is presented as fact.
- Every field has a group, observed representation, nullable note, confidence, and
  unresolved-question field.
- Sanitized identifiers are not validated as literal IPv4, IPv6, or MAC addresses.

### Stop Condition

Stop this checkpoint after inventory completeness and confidence labeling are
reviewed. Do not begin normalization mappings or add fields to a universal schema.

## 8. Checkpoint 1.2B — Contextual Missingness

### Purpose

Replace blanket missing-value judgments with conditional, reproducible evidence.

### Inputs

- Field inventory from 1.2A.
- Valid CSV rows read without modification.
- Conditioning fields: `event_type`, `event_subtype`, `event_action`, `net_proto`,
  `app_service`, threat presence, and session behavior.

### Analysis

- Produce missing and non-missing counts and percentages by relevant condition.
- Test whether source and destination port missingness is explained by ICMP.
- Confirm whether the same 778 rows are missing all five session metrics.
- Examine the one missing `itime` record through a bounded contextual summary.
- Describe sparse threat, application, and NAT fields by the event contexts in which
  they appear.
- Classify material findings as expected, context-dependent, suspicious data quality,
  or unknown. Do not propose blanket `fillna`, `dropna`, or in-place cleaning.

Grouped summaries should be the default. Any example record used for explanation
must include only the minimum safe fields and must not become a bulk row dump.

### Expected Outputs

- Conditional missingness tables with explicit denominators.
- Evidence and status for each investigated missingness pattern.
- A list of patterns that require a later checkpoint rather than premature closure.

### Tests

- Structurally missing ICMP ports versus missing TCP/UDP ports.
- Conditional missingness split across event types and actions.
- A row missing all session metrics and a row missing only a subset.
- Missing timestamp behavior.
- Optional threat, application, and unknown fields.
- Percentage calculations for empty and non-empty groups, including zero-denominator
  handling.

### Acceptance Criteria

- Counts reconcile to the valid-row total for every reported group.
- Percentages name their denominator and are deterministic.
- The port, session-metric, timestamp, app, threat, and NAT cases have evidence-backed
  statuses or remain explicitly unknown.
- No record is deleted, filled, or rewritten.

### Stop Condition

Stop when the required missingness questions are quantified. Do not create cleaning
rules or infer security labels from missing values.

## 9. Checkpoint 1.2C — Protocol, Port, and Application Relationships

### Purpose

Verify whether protocol and application context explains port population and service
representation.

### Inputs

- `net_proto`, `src_port`, `dst_port`, `app_service`, `app_name`, `app_cat`, and
  `app_id`.
- The conditional-count helpers from 1.2B.

### Analysis

- Count protocol 1 rows with both ports missing, one missing, or both populated.
- Count protocol 6 and 17 rows with missing or populated ports.
- Report any other protocol values without assuming their meaning.
- Summarize common `app_service` values by protocol and destination port.
- Examine whether named services and numeric forms such as `tcp/8080` align
  plausibly with their recorded protocol/port combinations.
- Record inconsistencies as data-quality questions, not attack indicators.

### Expected Outputs

- A protocol-port contingency summary.
- A bounded service/protocol/port relationship summary.
- Validated relationships and unresolved inconsistencies.

### Tests

- ICMP rows with expected missing ports and an intentionally populated-port edge
  case.
- TCP/UDP rows with expected ports and intentionally missing-port edge cases.
- Known and unknown protocols.
- Service labels that agree and disagree with protocol/port data.

### Acceptance Criteria

- The four required questions are answered: all ICMP missing, TCP/UDP missing,
  ICMP populated, and plausible application alignment.
- Original numeric protocols and ports are preserved in all results.
- Derived protocol names are clearly labeled as derived interpretations.
- No application/protocol combination is labeled malicious.

### Stop Condition

Stop after documenting relationship evidence. Do not create allowlists, detection
rules, or anomaly thresholds.

## 10. Checkpoint 1.2D — Session Behavior and Missing Session Metrics

### Purpose

Understand repeated session records and explain missing session metrics without
confusing lifecycle events with duplicate data.

### Inputs

- `net_sessionid`, `loguid`, event lifecycle fields, protocol/application fields,
  threat-field presence, and the five session metrics.

### Analysis

- Calculate records per session: minimum, maximum, median, selected useful
  percentiles, and a compact group-size frequency distribution.
- Report how many sessions contain one record versus repeated records.
- Compare repeated-session groups across `event_type`, `event_subtype`, and
  `event_action`.
- Identify sessions containing multiple actions or subtypes.
- Compare metric population and values across records within repeated sessions.
- Confirm whether the five metric fields share one missing-row mask; if not, report
  each missingness pattern separately.
- Compare the 778-row group against event, protocol, application, threat, and session
  context.

### Expected Outputs

- Session group-size distribution and summary statistics.
- Lifecycle relationship findings for repeated session IDs.
- A contextual explanation or explicit unresolved status for the 778 metric-missing
  rows.

### Tests

- Unique sessions, repeated lifecycle records, and exact duplicate-looking inputs.
- Repeated session IDs with distinct `loguid` values.
- Sessions containing multiple actions/subtypes.
- All-five-missing and partially-missing metric patterns.
- Deterministic median/percentile behavior on small, known distributions.

### Acceptance Criteria

- Repeated session IDs are counted and analyzed without deduplication.
- Session distribution statistics reconcile to total records and unique sessions.
- Exact duplicates remain conceptually separate from repeated-session records.
- The 778-row question has a supported explanation, classification, or explicit
  `UNKNOWN` status.

### Stop Condition

Stop after characterizing session structure and metric missingness. Do not build an
event-correlation engine or infer attacks from repeated sessions.

## 11. Checkpoint 1.2E — Timestamp Investigation

### Purpose

Determine what can safely be said about `itime` and `data_timestamp` while preserving
their raw representations.

### Inputs

- Raw `itime` and `data_timestamp` values.
- Minimal context for the missing-`itime` row: event, protocol, session, application,
  and source metadata fields.

### Analysis

- Validate that non-missing `itime` values can be interpreted consistently as epoch
  seconds, using an explicit UTC-derived representation only for analysis.
- Preserve the original values and report the conversion assumption and observed
  range.
- Locate the single missing-`itime` record and summarize its context without filling
  the value.
- Analyze `data_timestamp` cardinality, distribution, order, repeated values,
  differences, apparent resets, and relationship to `itime`.
- Test candidate descriptions such as sequence, offset, or relative time only as
  hypotheses. If evidence cannot distinguish them, mark semantics unresolved.

### Expected Outputs

- Verified or qualified interpretation of `itime`.
- Contextual report for the one missing `itime`.
- Evidence summary and confidence status for `data_timestamp`.

### Tests

- Valid epoch-like values, one missing value, malformed numeric input, and
  out-of-order rows.
- Repeating, increasing, and resetting `data_timestamp` sequences.
- Relationship logic where the two fields correlate and where they do not.
- Proof that derived datetime values do not replace raw values.

### Acceptance Criteria

- Every timestamp claim states its evidence, unit assumption, and timezone handling.
- The raw timestamp columns remain unchanged.
- The missing value is not filled.
- `data_timestamp` is either supported by sufficient evidence or documented as
  unresolved without forced interpretation.

### Stop Condition

Stop when defensible claims and unresolved questions are documented. Do not invent a
timestamp meaning or migrate the source schema.

## 12. Checkpoint 1.2F — Event, Application, Threat, Identifier, and Numeric Semantics

### Purpose

Complete the cross-field understanding needed for final data-quality documentation.

### Inputs

- Event fields: `event_type`, `event_subtype`, `event_action`, `event_severity`.
- Application fields: `app_cat`, `app_service`, `app_id`, `app_name`.
- Threat fields: `threat_action`, `threat_name`, `threat_severity`, `threat_type`,
  `threat_pattern`, `threat_id`, `threat_ref`.
- Identifier fields: `src_ip`, `dst_ip`, `host_ip`, `loguid`, `net_sessionid`.
- Packet, byte, duration, and port fields.

### Analysis

- Summarize common and rare event combinations, with counts and percentages.
- Check whether event combinations explain conditional missingness.
- Determine when application fields are populated and how their values relate.
- Analyze the small threat-record population descriptively across event, action,
  application, and protocol context.
- Report non-missing counts, unique counts, and useful repetition distributions for
  identifiers without listing all values.
- For selected numeric fields, report median, justified percentiles, zero/non-zero
  counts, and missing counts when they improve understanding beyond Stage 1.1.
- Record unusually large values as observations requiring later investigation, not
  as anomalies or attacks.

### Expected Outputs

- Event-combination and field-population summaries.
- Application and threat semantics findings.
- Identifier cardinality and selected numeric distribution summaries.
- Remaining interpretation questions and their confidence/status.

### Tests

- Common and rare event combinations with stable ordering on tied counts.
- Partially populated application and threat groups.
- Opaque sanitized identifiers and high-cardinality identifier counts.
- Zero-heavy, missing, and skewed numeric fixtures with known summary statistics.
- Empty optional groups that must produce valid zero counts rather than errors.

### Acceptance Criteria

- Counts reconcile and high-cardinality values are not dumped.
- Sparse threat fields are described as product observations, not ground truth.
- Records without threat values are not labeled benign.
- Rarity, geography, and large numeric values are not labeled malicious.
- Numeric statistics are limited to those that improve field understanding; no
  anomaly threshold is introduced.

### Stop Condition

Stop after semantic and distribution findings are documented. Do not create labels,
risk scores, detections, or features for machine learning.

## 13. Checkpoint 1.2G — Final Data-Quality Findings and Documentation

### Purpose

Consolidate independently reviewed checkpoint evidence into professional,
reproducible Stage 1.2 deliverables.

### Inputs

- Outputs and test results from 1.2A through 1.2F.
- The verified Stage 1.1 baseline.
- The raw-file integrity metadata captured before the full-data run.

### Analysis

- Reconcile all counts against the same valid-row denominator.
- Separate verified findings, assumptions, limitations, and unresolved questions.
- Apply the data-quality classification consistently.
- Cross-check the data dictionary against the actual 58-column header.
- Verify that documentation statements can be traced to a measured result or are
  explicitly labeled as hypotheses.
- Recompute the raw-file SHA-256 after the final analysis run and compare it to the
  known hash.

### Expected Outputs

- Completed `docs/data_dictionary.md`.
- Completed `docs/stage_1_2_data_quality_findings.md`.
- Reproducible JSON output under `data/processed/` if the full analysis is executed.
- A concise unresolved-field and unresolved-relationship list.

### Tests

- Run all synthetic-fixture unit tests.
- Run the existing Stage 1.1 test suite to prevent regression.
- Validate output schema, count reconciliation, stable ordering, and required
  documentation sections.
- Verify raw-file size and SHA-256 before and after the real-data analysis.

### Acceptance Criteria

- All 58 fields are documented.
- Every required relationship has a measured answer or an explicit unresolved status.
- Every material missingness finding has evidence and a data-quality classification.
- Synthetic tests and existing profiler tests pass.
- Results are reproducible, and reported values come from executed analysis.
- The raw dataset's bytes and known SHA-256 are unchanged.

### Stop Condition

Stop after Stage 1.2 findings are reviewed and completion criteria are met. Any
normalization or detection idea becomes a separately approved future plan.

## 14. Testing Strategy

Testing will use `unittest`-compatible or project-approved `pytest` discovery with
small synthetic CSV fixtures. Tests must validate analysis logic rather than memorize
the 100,000-row dataset. No test may require the local 39.3 MiB CSV.

Required scenario coverage:

- contextual and conditional missingness;
- protocol-port relationships, including inconsistent edge cases;
- repeated session handling without deduplication;
- complete and partial session-metric missingness;
- missing and unresolved timestamp behavior;
- optional and unknown fields;
- sanitized identifiers treated as opaque values;
- grouped counts, percentages, stable ordering, medians, and justified percentiles;
- empty groups and zero-denominator behavior;
- read-only behavior and explicit output-path safety.

The real dataset should be read only after checkpoint logic passes on fixtures. A full
run is a verification activity, not a unit test, and should occur once per checkpoint
only when needed to collect findings. Avoid repeated expensive scans by combining
compatible counters in a bounded-memory pass.

## 15. Data-Safety Rules

1. Open `data/raw/network_log_SAFE.csv` for reading only.
2. Never rewrite, clean, normalize, sort, or fill values in the raw CSV.
3. Never delete rows or overwrite identifiers.
4. Preserve raw timestamp and protocol values; derived interpretations use separate
   result fields.
5. Write any generated artifacts only under `data/processed/` or `docs/`.
6. Verify output paths cannot resolve inside `data/raw/`.
7. Treat tokenized IP, MAC, host, interface, device, and log values as opaque
   identifiers. Do not reverse, decode, enrich, or deanonymize them.
8. Prefer aggregate counts and percentages over row dumps.
9. Record file size and SHA-256 before and after verified full-data runs.
10. Do not commit the raw dataset or any sensitive derived record-level output.

## 16. Interpretation Rules

- Missing data is not automatically corruption; its meaning depends on context.
- A repeated session ID is not an exact duplicate record.
- Sparse threat values are FortiGate observations, not verified ground truth.
- Absence of threat fields does not establish benign behavior.
- Rare events, large transfers, long sessions, deny actions, and foreign geography do
  not independently establish maliciousness.
- Protocol names are derived from standard numeric assignments while raw numbers are
  preserved.
- `data_timestamp` remains unresolved until supported by measured evidence.
- Conversion failures must be reported; they must not be silently coerced.
- Counts must include clear denominators, and findings must distinguish observation,
  hypothesis, and verified interpretation.
- Uncertainty is an acceptable result and must be documented honestly.

## 17. Overall Stage 1.2 Completion Criteria

Stage 1.2 is complete only when:

1. all 58 fields have complete data-dictionary entries;
2. required missingness relationships have evidence-backed classifications;
3. protocol/port/application relationships are quantified;
4. repeated sessions and the 778 missing-metric records are explained or explicitly
   unresolved;
5. both timestamp fields have defensible documented interpretations or unresolved
   status;
6. event, application, threat, identifier, and selected numeric semantics are
   documented without security labels;
7. all new analysis logic passes synthetic-fixture tests and existing Stage 1.1 tests
   still pass;
8. measured results are reproducible and reconcile to the valid-row count;
9. assumptions, limitations, and unresolved questions are listed separately;
10. raw-file bytes and the known SHA-256 remain unchanged;
11. no detection, normalization implementation, or machine-learning label has been
    introduced.

## 18. Explicitly Out of Scope

Stage 1.2 will not implement:

- rule-based, attack, or anomaly detection;
- supervised labels, machine learning, deep learning, LLMs, or RAG;
- MITRE ATT&CK mapping, risk scoring, or alert prioritization;
- an event-correlation engine;
- normalization or a universal security-event schema;
- PostgreSQL, other databases, OpenSearch, Redis, or Kafka;
- FastAPI, frontend applications, or dashboards;
- Docker, Kubernetes, cloud deployment, or other infrastructure;
- deanonymization or enrichment of sanitized identifiers.

Observations that suggest future work will be recorded as follow-up questions only.
They will not expand the Stage 1.2 implementation.

## 19. Risks and Common Mistakes

| Risk or mistake | Prevention |
| --- | --- |
| Treating every missing value as an error | Require conditional counts and an evidence-based status. |
| Treating repeated sessions as duplicates | Keep exact-row duplicates and session grouping as separate concepts. |
| Inventing FortiGate field meanings | Record confidence and use `NEEDS VERIFICATION` or `UNKNOWN`. |
| Assuming `data_timestamp` is epoch time | Test relationships and retain unresolved status if evidence is insufficient. |
| Turning product threat fields into labels | Describe them as observations and prohibit Stage 1.2 labels. |
| Validating sanitized tokens as literal addresses | Treat values as opaque identifiers. |
| Dumping high-cardinality or sensitive rows | Prefer bounded aggregate summaries and minimal contextual fields. |
| Interpreting rarity or large values as attacks | Report distributions only; add no detection threshold. |
| Producing irreproducible manual statistics | Generate documented results from tested code with stable ordering. |
| Repeatedly scanning the full dataset | Combine compatible counters and validate first on fixtures. |
| Over-engineering the student project | Use two small modules, standard library, and checkpoint reviews. |
| Accidentally changing raw evidence | Enforce read-only input/output separation and verify SHA-256. |

## 20. Suggested Implementation Order

Implement and review checkpoints in this order:

1. **1.2A** — establish the field inventory and confidence vocabulary;
2. **1.2B** — build generic grouped-count and conditional-missingness primitives;
3. **1.2C** — apply those primitives to protocol, port, and application relationships;
4. **1.2D** — add session grouping and explain session-metric missingness;
5. **1.2E** — investigate timestamp behavior without contaminating raw values;
6. **1.2F** — complete event, application, threat, identifier, and numeric semantics;
7. **1.2G** — reconcile, document, verify integrity, and close the stage.

Each checkpoint must be independently testable and reviewable. Do not begin the next
checkpoint until the current checkpoint meets its acceptance criteria and stop
condition.

## 21. Unresolved Items at Planning Time

The following are intentionally unresolved and must be answered by Stage 1.2 evidence:

- the exact source semantics and unit of `data_timestamp`;
- the cause and quality classification of the single missing `itime`;
- whether all five session metrics are missing on exactly the same 778 rows;
- which event/session conditions explain those 778 records;
- whether every ICMP record has both ports missing and whether any TCP/UDP record does;
- the lifecycle meaning of repeated `net_sessionid` values;
- the authoritative meanings of low-confidence source-specific fields such as
  `adom_oid`, `epid`, `euid`, `event_profile`, and `threat_ref`;
- when sparse application, NAT, host, and threat fields are structurally expected;
- whether selected numeric distributions reveal data-quality questions that warrant
  a later, separately approved investigation.

Leaving an item unresolved is correct when the available evidence does not support a
stronger conclusion.
