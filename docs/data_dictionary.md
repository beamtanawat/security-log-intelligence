# FortiGate Data Dictionary — Stage 1.2A

## Scope and Evidence

This is a cautious inventory of the 58 fields in
`data/raw/network_log_SAFE.csv`. It uses the verified Stage 1.1 profile baseline
and does not alter or normalize raw data. A token such as `SRCIP_...`,
`DSTIP_...`, `HOSTIP_...`, or `SRCMAC_...` is an opaque sanitized identifier,
not a literal address to validate or enrich.

`Nullable evidence` describes observed availability, not whether a blank value is
an error. `POTENTIALLY_COMMON` means a concept may map to a future common schema;
`SOURCE_SPECIFIC` means the source representation must be preserved. Confidence
describes field meaning, separately from data quality.

| Confidence | Meaning |
| --- | --- |
| HIGH | Strongly supported by the field role and observed data. |
| MEDIUM | Plausible, but requires context or source-documentation confirmation. |
| NEEDS VERIFICATION | Source-specific meaning is not yet supported by enough evidence. |

## Timestamp Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `itime` | FortiGate event time; integer-like raw timestamp. | 1 missing; 99,999 non-missing. | POTENTIALLY_COMMON / MEDIUM | Confirm epoch-second interpretation and the missing-record context. |
| `data_timestamp` | Source-specific timestamp-related value; integer-like raw value. | No missing; range 0–731. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Is this a sequence, offset, relative time, or another source value? It is not assumed to be epoch time. |

## Event Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `event_action` | Action or lifecycle outcome; categorical string. | No missing. | POTENTIALLY_COMMON / HIGH | How do actions relate across repeated sessions? |
| `event_id` | Source event identifier; integer-like raw value. | No missing. | SOURCE_SPECIFIC / MEDIUM | Confirm mappings to FortiGate event families. |
| `event_severity` | Source severity label; categorical string. | No missing. | POTENTIALLY_COMMON / MEDIUM | Confirm source severity scale; it is not an independent risk score. |
| `event_subtype` | Source event subtype; categorical string. | No missing. | POTENTIALLY_COMMON / MEDIUM | Confirm semantics across traffic and UTM records. |
| `event_type` | Top-level source event family; categorical string. | No missing; `traffic` and `utm` observed. | POTENTIALLY_COMMON / HIGH | Retain the source labels; no further question yet. |
| `event_profile` | Source profile associated with selected events; opaque token. | 99,769 missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Which event contexts populate a profile? |
| `event_message` | Human-readable source message; free-text string. | 30 non-missing. | SOURCE_SPECIFIC / MEDIUM | Summarize only in bounded, non-sensitive aggregates or minimal examples. |
| `loguid` | Log-record identifier; opaque token. | No missing; 100,000 unique. | SOURCE_SPECIFIC / HIGH | Is uniqueness limited to this export or broader source scope? |

## Parser and Source Metadata

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `adom_oid` | FortiManager administrative-domain identifier or related source value; integer-like. | No Stage 1.1 missingness issue recorded. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm authoritative FortiGate/FortiManager semantics. |
| `data_parsername` | Name of the parser that produced the record; categorical string. | No missing; FortiGate parser observed. | SOURCE_SPECIFIC / HIGH | None currently. |
| `data_sourceid` | Source-system identifier; opaque string. | No missing. | SOURCE_SPECIFIC / MEDIUM | Is this a device, collector, or source identifier? |
| `data_sourcename` | Sanitized source-device name; opaque token. | No missing. | SOURCE_SPECIFIC / MEDIUM | Confirm source naming semantics without deanonymizing tokens. |
| `data_sourcetype` | Log-source product type; categorical string. | No missing; FortiGate observed. | POTENTIALLY_COMMON / HIGH | None currently. |
| `epid` | Source-specific event or process identifier; integer-like. | No Stage 1.1 missingness issue recorded. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm authoritative source semantics. |
| `euid` | Source-specific event/user identifier; integer-like. | No Stage 1.1 missingness issue recorded. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm authoritative source semantics. |

## Source and Destination Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `src_geo` | Source geography label; categorical string. | No missing; `Reserved` observed for all rows. | SOURCE_SPECIFIC / MEDIUM | Confirm lookup/enrichment semantics and `Reserved` meaning. |
| `src_intf` | Source interface identifier; opaque token. | No missing. | SOURCE_SPECIFIC / MEDIUM | Is this ingress-interface context? |
| `src_ip` | Source network identifier; opaque sanitized identifier, not a literal IP. | No missing. | POTENTIALLY_COMMON / HIGH | Retain token form without enrichment or decoding. |
| `src_mac` | Source link-layer identifier when supplied; opaque sanitized identifier, not a literal MAC. | 46,437 missing. | SOURCE_SPECIFIC / MEDIUM | Which contexts populate source MAC? |
| `src_port` | Source transport-layer port when applicable; integer-like. | 27,447 missing, matching protocol-1 count. | POTENTIALLY_COMMON / HIGH | Verify row-level protocol relationship; do not fill blanks. |
| `src_domain` | Source-domain value when supplied; opaque token. | 79,300 missing. | SOURCE_SPECIFIC / MEDIUM | How does it relate to host inventory and `host_name`? |
| `dst_geo` | Destination geography label; categorical string. | No missing. | SOURCE_SPECIFIC / MEDIUM | Confirm lookup/enrichment semantics and coverage limitations. |
| `dst_intf` | Destination interface identifier; opaque token. | 18 missing. | SOURCE_SPECIFIC / MEDIUM | Which event context has no destination interface? |
| `dst_ip` | Destination network identifier; opaque sanitized identifier, not a literal IP. | No missing. | POTENTIALLY_COMMON / HIGH | Retain token form without enrichment or decoding. |
| `dst_mac` | Destination link-layer identifier when supplied; opaque sanitized identifier, not a literal MAC. | 48,071 missing. | SOURCE_SPECIFIC / MEDIUM | Which contexts populate destination MAC? |
| `dst_port` | Destination transport-layer port when applicable; integer-like. | 27,447 missing, matching protocol-1 count. | POTENTIALLY_COMMON / HIGH | Verify row-level protocol relationship; do not fill blanks. |

## Network, Session, and NAT Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `net_proto` | Network protocol number; integer-like raw identifier. | No missing; 1, 6, and 17 observed. | POTENTIALLY_COMMON / HIGH | Derived names may be documented separately; retain raw values. |
| `net_rcvdpkts` | Packets received for the record; integer-like count. | 778 missing. | POTENTIALLY_COMMON / MEDIUM | Does it share the same missing-row mask as all session metrics? |
| `net_recvbytes` | Bytes received for the record; integer-like count. | 778 missing. | POTENTIALLY_COMMON / MEDIUM | Does it share the same missing-row mask as all session metrics? |
| `net_sentbytes` | Bytes sent for the record; integer-like count. | 778 missing. | POTENTIALLY_COMMON / MEDIUM | Does it share the same missing-row mask as all session metrics? |
| `net_sentpkts` | Packets sent for the record; integer-like count. | 778 missing. | POTENTIALLY_COMMON / MEDIUM | Does it share the same missing-row mask as all session metrics? |
| `net_sessionduration` | Source-reported session duration; integer-like raw value. | 778 missing. | POTENTIALLY_COMMON / MEDIUM | Confirm unit and lifecycle relationship. |
| `net_sessionid` | Source session identifier; integer-like opaque identifier. | No missing; 50,399 unique, repeated values are not duplicates. | SOURCE_SPECIFIC / HIGH | Characterize repeated-session lifecycle behavior without deduplication. |
| `src_natip` | Source NAT identifier when source NAT applies; opaque sanitized identifier. | 98,350 missing. | SOURCE_SPECIFIC / MEDIUM | Is presence limited to source-NAT events? |
| `src_natport` | Source NAT port when source NAT applies; integer-like. | 98,350 missing. | SOURCE_SPECIFIC / MEDIUM | Is presence limited to source-NAT events, and what does zero mean? |

## Application Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `app_cat` | Application category supplied by the source product; categorical string. | 18 missing; otherwise mostly `unscanned`. | SOURCE_SPECIFIC / MEDIUM | Which contexts create blank or non-`unscanned` values? |
| `app_service` | Service label supplied or inferred by the source product; categorical string. | No missing; 108 unique values. | SOURCE_SPECIFIC / MEDIUM | Do labels align plausibly with protocol and port? |
| `app_id` | Source application identifier when identified; integer-like. | 129 non-missing. | SOURCE_SPECIFIC / MEDIUM | How does it relate to `app_name` and `app_cat`? |
| `app_name` | Application name when identified; categorical string. | 129 non-missing. | SOURCE_SPECIFIC / MEDIUM | How does it relate to application ID, service, and event context? |

## Host Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `host_ip` | Host network identifier; opaque sanitized identifier, not a literal IP. | No missing. | POTENTIALLY_COMMON / MEDIUM | How does host role relate to source and destination by event context? |
| `host_location` | Source host-location value; categorical or opaque string. | No Stage 1.1 missingness issue recorded. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Is it logical, physical, or inventory location? |
| `host_mac` | Host link-layer identifier when supplied; opaque sanitized identifier, not a literal MAC. | 46,437 missing. | SOURCE_SPECIFIC / MEDIUM | How does it relate to source MAC and inventory context? |
| `host_type` | Source host-type value; categorical string. | 46,437 missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm host-type taxonomy and population conditions. |
| `host_osver` | Host operating-system version when supplied; categorical or opaque string. | 86 missing. | SOURCE_SPECIFIC / MEDIUM | Confirm inventory/enrichment source and population conditions. |
| `host_hwvendor` | Host hardware-vendor value when supplied; categorical or opaque string. | 77,669 missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm inventory source and population context. |
| `host_hwver` | Host hardware-version value when supplied; categorical or opaque string. | 77,669 missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm inventory source and population context. |
| `host_osfamily` | Host operating-system family when supplied; categorical string. | 77,669 missing. | SOURCE_SPECIFIC / MEDIUM | Confirm inventory/enrichment source and population conditions. |
| `host_osname` | Host operating-system name when supplied; categorical string. | 77,669 missing. | SOURCE_SPECIFIC / MEDIUM | Confirm inventory/enrichment source and population conditions. |
| `host_name` | Host-name value when supplied; opaque token. | 79,300 missing. | SOURCE_SPECIFIC / MEDIUM | How does it relate to host inventory and `src_domain`? |

## Threat Fields

| Field | Likely meaning and representation | Nullable evidence | Status / confidence | Unresolved question |
| --- | --- | --- | --- | --- |
| `threat_action` | Threat-related action reported by the source product; categorical string. | 25 non-missing. | SOURCE_SPECIFIC / MEDIUM | Product observation only; not ground-truth attack evidence. |
| `threat_name` | Threat-related name reported by the source product; categorical string. | 25 non-missing. | SOURCE_SPECIFIC / MEDIUM | Product observation only; not ground-truth attack evidence. |
| `threat_severity` | Threat severity label reported by the source product; categorical string. | 25 non-missing. | SOURCE_SPECIFIC / MEDIUM | Confirm source severity semantics; do not use as independent risk score. |
| `threat_type` | Threat category reported by the source product; categorical string. | 25 non-missing. | SOURCE_SPECIFIC / MEDIUM | Product observation only; not ground-truth attack evidence. |
| `threat_pattern` | Source-specific threat pattern when supplied; categorical or opaque string. | 19 non-missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm product semantics and relation to threat fields. |
| `threat_id` | Source threat identifier when supplied; integer-like raw value. | 18 non-missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm relation to threat names and patterns. |
| `threat_ref` | Source threat reference when supplied; categorical or opaque string. | 18 non-missing. | SOURCE_SPECIFIC / NEEDS VERIFICATION | Confirm reference semantics without external enrichment. |

## Stage 1.2 Validated Clarifications

The following measured clarifications supplement the cautious field entries above.
They do not change source-field meanings or confidence levels.

| Fields | Stage 1.2 evidence | Retained interpretation |
| --- | --- | --- |
| itime | 1 missing value; 99,999 valid integers with no conversion failures; range 1,729,294,669 to 1,729,338,553. A UTC rendering was derived under an epoch-seconds assumption. | The UTC value is `DERIVED`; the epoch-seconds interpretation remains `NEEDS VERIFICATION`. The missing-value cause is `UNKNOWN`. |
| data_timestamp | 100,000 valid integers with no conversion failures; range 0 to 731; 237 unique values; repeated values and file-order decreases occur. | Source semantics remain `UNKNOWN`. Numeric comparison with `itime` does not establish a unit or meaning. |
| src_port and dst_port | Both are missing on all 27,447 protocol-1/ICMP records and populated on all 66,357 TCP and 6,196 UDP records. | ICMP port missingness is `EXPECTED`; no blank source value was filled or normalized. |
| Session metrics | The five metric fields are all missing together on 778 records; 99,222 records have all five populated; there are no partial patterns. | Missingness is `CONTEXT_DEPENDENT`, not automatically a data-quality failure. Units and lifecycle semantics remain source-specific. |
| net_sessionid | 50,399 unique values; 46,018 values occur on multiple records. | Repetition identifies source-record grouping only and is not an exact-duplicate finding. Lifecycle meaning remains `NEEDS VERIFICATION`. |
| Application and threat fields | `app_service` is present on all records; `app_id` and `app_name` occur on 129 records. Any threat field occurs on 25 records. | These are FortiGate source-product observations, not independent security labels or ground truth. |

## Inventory Completeness

The checked-in inventory implementation defines the same 58 fields, in the
verified CSV-header order. Future Stage 1.2 checkpoints must preserve these raw
field names, record relationship evidence separately, and retain `UNKNOWN` where
the available data cannot support a stronger conclusion.
