# Stage 1.2 Data-Quality Findings

## 1. Dataset Identity

**FACT.** This review covers the immutable sanitized raw CSV at
data/raw/network_log_SAFE.csv. It is read-only evidence. Sanitized identifiers,
including SRCIP_..., DSTIP_..., HOSTIP_..., and MAC-like tokens, are opaque
values; they were not validated as literal addresses, decoded, enriched, or
deanonymized.

**FACT.** The raw file measured 41,235,093 bytes. Its SHA-256 after the
validated Stage 1.2F run was
EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D.

## 2. Dataset Shape

| Measure | Result | Evidence label |
| --- | ---: | --- |
| CSV records after the header | 100,000 | FACT |
| Valid records | 100,000 | FACT |
| Malformed records | 0 | FACT |
| Header columns | 58 | FACT |
| Exact duplicate rows from Stage 1.1 | 0 | FACT |

**OBSERVATION.** Repeated net_sessionid values are separate from exact-row
duplication and were never used to remove or merge records.

## 3. Field Inventory

**FACT.** All 58 header fields are recorded in
[data_dictionary.md](data_dictionary.md), in verified header order. They are
grouped there as timestamp, event, parser/source metadata, source/destination,
network/session/NAT, application, host, and threat fields.

**FACT.** The inventory preserves raw field names and distinguishes confidence
in likely meaning from observed availability. No canonical schema or
normalization was introduced.

## 4. Data Dictionary Status

**FACT.** The data dictionary has an entry for every header field. Its Stage
1.2 clarification table records validated timestamp, port, session-metric,
session-identifier, application, and threat evidence from checkpoints 1.2B
through 1.2F.

**INFERENCE.** POTENTIALLY_COMMON and SOURCE_SPECIFIC remain planning
classifications only. They do not authorize mapping source fields to a new
schema.

## 5. Contextual Missingness

| Finding | Measured result | Classification |
| --- | --- | --- |
| ICMP ports | All 27,447 protocol-1 records have both ports missing. | EXPECTED |
| TCP/UDP ports | All 66,357 TCP and 6,196 UDP records have both ports populated. | CONTEXT_DEPENDENT |
| Five session metrics | 778 records have all five missing; 99,222 have all five populated; 0 have a partial pattern. | CONTEXT_DEPENDENT |
| itime | 1 missing value (0.001%), in a traffic / forward / accept / protocol-6 / SMB record. | UNKNOWN |
| Threat fields | At least one threat field occurs on 25 records. | CONTEXT_DEPENDENT |

**OBSERVATION.** Of the 778 records with all session metrics missing, 748
(96.143959%) are traffic / ip-conn, 18 (2.313625%) are utm /
clear_session, and 12 (1.542416%) are utm / pass. This context does not prove
a source-system cause.

## 6. Protocol / Port Relationships

| Raw net_proto | Derived name | Records | Port population | Classification |
| --- | --- | ---: | --- | --- |
| 1 | ICMP | 27,447 | Both ports missing on 27,447 records | EXPECTED |
| 6 | TCP | 66,357 | Both ports populated on 66,357 records | CONTEXT_DEPENDENT |
| 17 | UDP | 6,196 | Both ports populated on 6,196 records | CONTEXT_DEPENDENT |

**FACT.** ICMP, TCP, and UDP are derived presentation labels for the preserved
raw numeric protocol values.

**OBSERVATION.** The highest-count observed protocol/port/service groups were
ICMP with missing destination port and PING (27,443 records), TCP/445 with SMB
(6,397), TCP/135 with DCE-RPC (4,274), TCP/3389 with RDP (3,885), and UDP/137
with junos-nbname-t1 (3,796).

**OBSERVATION.** Each of the 20 reported numeric service labels, such as
tcp/8080, matched its encoded transport and destination port. This is a
bounded contextual consistency result, not a claim that all labels are
authoritative.

## 7. Application Relationships

| Field | Population and leading observed values | Evidence label |
| --- | --- | --- |
| app_cat | 99,982 present, 18 missing; unscanned 99,749, Remote.Access 104, unknown 104, Network.Service 25 | OBSERVATION |
| app_service | 100,000 present, 108 unique; PING 27,443, SMB 6,397, DCE-RPC 4,274, RDP 3,885 | OBSERVATION |
| app_id | 129 present: 39164 on 104 records and 16270 on 25 | OBSERVATION |
| app_name | 129 present: AnyDesk on 104 records and NTP on 25 | OBSERVATION |

**OBSERVATION.** All 18 missing app_cat values occur in the ICMP group.
app_id and app_name are absent from all 27,447 ICMP records, while they occur
on 104 TCP records and 25 UDP records. Sparsity is source context, not
automatically a defect.

**UNKNOWN.** This export does not establish the source-product method for
assigning service, category, ID, or name. No application value is used for a
detection decision.

## 8. Session Behavior

| Measure | Result | Evidence label |
| --- | ---: | --- |
| Records grouped by raw net_sessionid | 100,000 | FACT |
| Unique session IDs | 50,399 | FACT |
| Single-record session IDs | 4,381 | FACT |
| Repeated session IDs | 46,018 | FACT |
| Maximum records in one group | 113 | FACT |
| Median records per group | 2 | FACT |

**OBSERVATION.** 44,960 session IDs (89.208119% of session IDs) occur exactly
twice. 45,986 repeated session IDs contain more than one event_action, while
12 contain more than one event_subtype.

**UNKNOWN.** Grouping by the raw identifier demonstrates repeated source
records, but does not establish FortiGate lifecycle semantics. Repetition is
not an exact-duplicate result and no deduplication occurred.

## 9. Session Metric Missingness

**FACT.** The shared missingness mask for net_rcvdpkts, net_recvbytes,
net_sentbytes, net_sentpkts, and net_sessionduration contains exactly 778
records. There are no partial missing-metric combinations.

**OBSERVATION.** Among repeated-session records, every metric has 778 missing
records, one all-missing session group, 45,257 all-populated session groups,
and 760 mixed-population session groups. This supports a contextual
interpretation but does not prove why the fields are absent.

## 10. Timestamp Investigation

| Field | Measured behavior | Interpretation |
| --- | --- | --- |
| itime | 1 missing; 99,999 valid integers; 0 conversion failures; range 1,729,294,669 to 1,729,338,553; span 43,884; 2,790 unique values | Raw value preserved |
| itime file order | 99,997 adjacent valid pairs: 0 increases, 97,209 equal, 2,788 decreases | Not chronological increasing order |
| itime UTC rendering | Under an epoch-seconds assumption: 2024-10-18T23:37:49+00:00 to 2024-10-19T11:49:13+00:00 | DERIVED; NEEDS VERIFICATION |
| data_timestamp | 100,000 valid integers; 0 conversion failures; range 0 to 731; 237 unique values | UNKNOWN semantics |
| data_timestamp file order | 99,999 adjacent pairs: 479 increases, 98,805 equal, 715 decreases | Does not establish sequence or time semantics |

**FACT.** On the 99,999 records where both timestamp fields are numeric,
itime minus data_timestamp ranges from 1,729,294,669 to 1,729,337,822 and is
not constant.

**UNKNOWN.** The numeric relationship does not prove that data_timestamp is
Unix time, an offset, a sequence, or any other particular unit.

## 11. Event / Application / Threat Semantics

### Event observations

| Field | Observed values | Evidence label |
| --- | --- | --- |
| event_type | traffic 99,970; utm 30 | OBSERVATION |
| event_subtype | forward 99,970; anomaly 18; app-ctrl 12 | OBSERVATION |
| event_action | start 46,407; accept 20,323; timeout 16,781; server-rst 11,693; client-rst 2,976; remaining actions total 1,820 | OBSERVATION |
| event_severity | notice 99,222; warning 748; alert 18; information 12 | OBSERVATION |

**OBSERVATION.** The largest event_type/event_action combinations are traffic
/ start (46,407), traffic / accept (20,323), traffic / timeout (16,781),
traffic / server-rst (11,693), and traffic / client-rst (2,976).

**INFERENCE BOUNDARY.** Anomaly is a FortiGate source-product term. An anomaly
record is not thereby established as an attack.

### Threat observations

**FACT.** At least one threat field is populated on 25 records (0.025%). The
profiler treats these as FortiGate source-product observations, not security
ground-truth labels. A record without such a value is not labeled benign.

| Field | Populated records | Observed values | Evidence label |
| --- | ---: | --- | --- |
| threat_action | 25 | blocked 25 | OBSERVATION |
| threat_name | 25 | icmp_sweep 10; icmp_src_session 8; Policy Violation 7 | OBSERVATION |
| threat_severity | 25 | medium 25 | OBSERVATION |
| threat_type | 25 | Reconnaissance 25 | OBSERVATION |
| threat_pattern | 19 | icmp_sweep 10; icmp_src_session 8; AnyDesk 1 | OBSERVATION |
| threat_id | 18 | 16777320 on 10 records; 16777321 on 8 | OBSERVATION |
| threat_ref | 18 | Two source references, matching the two reported IDs | OBSERVATION |

**OBSERVATION.** Of the 25 threat-present records, 18 are utm /
clear_session / protocol-1 / PING. The other seven are traffic / deny records
in the reported application/protocol contexts. This is descriptive context, not
confirmation of maliciousness.

### Identifier and selected numeric observations

**FACT.** Identifier values are deliberately not emitted in profiler output.
Only cardinality and occurrence distributions are reported. loguid has 100,000
unique values; net_sessionid has 50,399; src_ip and host_ip each have 17; dst_ip
has 15,530. All five have zero missing values.

| Raw numeric field | Valid / missing / failures | Zero count | Min / median / P95 / P99 / max |
| --- | --- | ---: | --- |
| src_port | 72,553 / 27,447 / 0 | 0 | 123 / 58,725 / 64,380 / 65,246 / 65,534 |
| dst_port | 72,553 / 27,447 / 0 | 0 | 21 / 3,389 / 50,000 / 60,163 / 64,838 |
| net_rcvdpkts | 99,222 / 778 / 0 | 80,683 | 0 / 0 / 4 / 4,332,304 / 16,024,998 |
| net_recvbytes | 99,222 / 778 / 0 | 80,683 | 0 / 0 / 396 / 4,236,647,219 / 15,460,072,207 |
| net_sentbytes | 99,222 / 778 / 0 | 46,413 | 0 / 52 / 652 / 4,319,429,233 / 15,805,817,602 |
| net_sentpkts | 99,222 / 778 / 0 | 46,413 | 0 / 1 / 9 / 5,265,554 / 19,128,880 |
| net_sessionduration | 99,222 / 778 / 0 | 55,286 | 0 / 0 / 180 / 8,588 / 93,632 |

**INFERENCE BOUNDARY.** These numeric summaries are descriptive. Large or rare
values, destination ports, and repeated identifiers are not treated as
anomalies, attacks, or detection thresholds.

## 12. Data Quality Classifications

| Classification | Evidence-backed finding |
| --- | --- |
| EXPECTED | Missing ports on protocol-1/ICMP records |
| CONTEXT_DEPENDENT | TCP/UDP port population; shared session-metric missingness; sparse application and threat population |
| UNKNOWN | Cause of the one missing itime; source semantics of data_timestamp; source cause of session-metric absence |
| NEEDS VERIFICATION | Whether itime is epoch seconds; FortiGate session lifecycle and metric units; low-confidence source-specific fields |

## 13. Assumptions

- **FACT.** Raw source values were preserved; no missing value was filled,
  transformed, or normalized.
- **FACT.** Standard protocol names are derived presentation labels only; raw
  numeric net_proto values remain evidence.
- **ASSUMPTION FOR A DERIVED VIEW.** UTC values for itime assume Unix epoch
  seconds and are labeled DERIVED, not source-confirmed timestamps.
- **INFERENCE BOUNDARY.** Product terms such as anomaly, blocked,
  Reconnaissance, or an application name are not independent security labels.

## 14. Unknowns / NEEDS VERIFICATION

- **UNKNOWN.** The exact semantics and unit of data_timestamp.
- **NEEDS VERIFICATION.** Whether raw itime is Unix epoch seconds; only the
  optional UTC presentation was derived under that assumption.
- **UNKNOWN.** The source-side cause of the one missing itime value.
- **NEEDS VERIFICATION.** The lifecycle meaning of repeated net_sessionid
  values and the units of net_sessionduration.
- **NEEDS VERIFICATION.** Authoritative meanings of source-specific fields such
  as adom_oid, epid, euid, event_profile, and threat_ref.
- **UNKNOWN.** Why contextual session-metric and optional-field populations
  occur; the evidence does not establish a causal explanation.

## 15. Limitations

- **FACT.** This is one sanitized FortiGate export of 100,000 records, not a
  complete source-system history.
- **FACT.** Opaque identifiers prevent literal address, MAC, location, or
  identity validation; no enrichment was attempted.
- **LIMITATION.** Bounded summaries intentionally omit lower-ranked values and
  avoid high-cardinality identifier dumps.
- **LIMITATION.** File order was measured but is not assumed to be chronological
  event order.
- **LIMITATION.** No external vendor documentation was used to convert
  source-product terms into authoritative semantics.

## 16. Readiness for Next Stage

**FACT.** Stage 1.2 has a reproducible read-only analysis path, complete field
inventory, contextual missingness evidence, protocol/port/application summaries,
session grouping evidence, timestamp investigation, and source-product semantic
summaries.

**CONDITION.** Final Stage 1.2 closure requires the designated local 1.2G gate
to confirm the existing test suite, output validity, raw-file integrity, and Git
safety after this documentation change.

**BOUNDARY.** No detection, anomaly classification, attack labeling, risk
scoring, machine learning, API, database, frontend, container, or deployment
work is included. Any follow-on stage requires separate approval and must retain
the unresolved items above until independently supported.
