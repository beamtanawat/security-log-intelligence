# FortiGate Normalization Mapping Specification

## Scope

This document is the Stage 1.3B mapping specification for the verified
58-column sanitized FortiGate CSV header. It records mapping decisions only.
It does not parse CSV files, convert values, normalize records, write output,
or create security conclusions.

Every source field remains available in source_record. A field placed in an
observation section is still a source-product value, not a cross-vendor
taxonomy or security label.

## Mapping categories

| Category | Meaning |
| --- | --- |
| MAPPED_DIRECT | Copy to one established canonical role without changing the source value. |
| MAPPED_CONVERTED | A later normalizer may produce a typed canonical value while retaining the raw source string and reporting invalid conversions. |
| MAPPED_DERIVED | Retain a raw value and create one or more explicitly derived or converted views with provenance. |
| PRESERVED_OBSERVATION | Keep the value in a source-observation canonical area without promoting vendor semantics. |
| PRESERVED_UNMAPPED | Keep the raw value in source_record and unmapped_fields because no canonical meaning is justified. |

## Boundary decisions

- data_timestamp is PRESERVED_UNMAPPED with UNKNOWN semantics. It is not a
  canonical time, offset, sequence, or duration.
- itime keeps the raw source string. Any future UTC view is DERIVED under an
  explicit epoch-seconds assumption and remains NEEDS_VERIFICATION.
- Source, destination, host, and link-layer identifiers are opaque identifiers,
  never literal address types.
- Protocol names are derived separately from the raw protocol string and numeric
  conversion.
- Protocol-1 port absence and the shared session-metric absence remain
  context-dependent handling, not zero-fill behavior.
- net_sessionduration is unit-neutral; its values are not called seconds.
- Threat fields are source-product observations. They do not map to attack,
  benign, label, score, or risk fields.
- Repeated net_sessionid values are preserved independently; no grouping, merge,
  or deduplication is part of mapping.

## Complete 58-field mapping table

| Source field | Canonical paths | Category | Source representation | Target type | Operations | Interpretation status | Missingness status | Conversion failure behavior | Rationale |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| itime | time.itime_raw; time.itime_utc_derived | MAPPED_DERIVED | integer_like_timestamp_string | raw_string_or_null; derived_utc_string_or_null | COPIED; DERIVED | NEEDS_VERIFICATION | UNKNOWN | derived_utc_null_and_issue | Preserve raw value; optional UTC requires an explicit epoch-seconds assumption. |
| adom_oid | UNMAPPED | PRESERVED_UNMAPPED | source_specific_integer_like_string | raw_string_or_null | PRESERVED_UNMAPPED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Source-specific meaning is not established. |
| app_cat | application.category_source | PRESERVED_OBSERVATION | source_product_category_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product category is sparse in known contexts. |
| app_service | application.service_source | PRESERVED_OBSERVATION | source_product_service_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source service observation without universal taxonomy. |
| data_parsername | source.parser_name | MAPPED_DIRECT | parser_name_string | string_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Identifies the source parser without inferring more source semantics. |
| data_sourceid | source.source_identifier | MAPPED_DIRECT | opaque_source_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Preserve opaque source identity; device or collector role is unresolved. |
| data_sourcename | source.source_name | MAPPED_DIRECT | opaque_sanitized_source_name | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Preserve sanitized source name without deanonymization. |
| data_sourcetype | source.source_type | MAPPED_DIRECT | source_product_type_string | string_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Retain the source-product type exactly as supplied. |
| data_timestamp | UNMAPPED | PRESERVED_UNMAPPED | integer_like_source_specific_string | raw_string_or_null | PRESERVED_UNMAPPED | UNKNOWN | UNKNOWN | not_converted_preserve_raw | Measured numeric behavior does not establish a time, offset, sequence, or duration meaning. |
| dst_geo | network.destination.geo_source | PRESERVED_OBSERVATION | source_geography_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Retain source geography observation without enrichment or location claims. |
| dst_intf | network.destination.interface_source | PRESERVED_OBSERVATION | opaque_interface_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Interface population is source context and does not justify a universal interface type. |
| dst_ip | network.destination.identifier | MAPPED_DIRECT | opaque_sanitized_network_identifier | opaque_identifier_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Canonical role is destination identifier, not literal IP address. |
| dst_mac | network.destination.link_layer_identifier | MAPPED_DIRECT | opaque_sanitized_link_layer_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Opaque source token is retained without MAC syntax validation. |
| dst_port | network.destination.port | MAPPED_CONVERTED | integer_like_transport_port_string | integer_or_null | CONVERTED | VERIFIED | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Convert only valid 0 through 65535 values; protocol context controls missingness. |
| epid | UNMAPPED | PRESERVED_UNMAPPED | source_specific_integer_like_string | raw_string_or_null | PRESERVED_UNMAPPED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Source-specific event or process meaning is not established. |
| euid | UNMAPPED | PRESERVED_UNMAPPED | source_specific_integer_like_string | raw_string_or_null | PRESERVED_UNMAPPED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Source-specific event or user meaning is not established. |
| event_action | event.action_source | MAPPED_DIRECT | source_action_string | source_observation_string_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Retain source action without turning it into a security verdict. |
| event_id | event.source_event_id | MAPPED_DIRECT | source_event_identifier_string | raw_string_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Preserve source event identifier without product-family inference. |
| event_severity | event.severity_source | PRESERVED_OBSERVATION | source_severity_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | UNKNOWN | not_converted_preserve_raw | Source severity is not converted into a cross-vendor risk scale. |
| event_subtype | event.subtype_source | MAPPED_DIRECT | source_subtype_string | source_observation_string_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Preserve source subtype without classifying its security meaning. |
| event_type | event.type_source | MAPPED_DIRECT | source_event_family_string | source_observation_string_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Preserve source event family without universal taxonomy. |
| host_ip | host.identifier | MAPPED_DIRECT | opaque_sanitized_network_identifier | opaque_identifier_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Canonical role is host identifier, not literal IP address. |
| host_location | host.location_source | PRESERVED_OBSERVATION | source_host_location_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Logical, physical, and inventory meanings remain unresolved. |
| host_mac | host.link_layer_identifier | MAPPED_DIRECT | opaque_sanitized_link_layer_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Opaque source token is retained without MAC syntax validation. |
| host_type | host.type_source | PRESERVED_OBSERVATION | source_host_type_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source taxonomy is retained without a universal host type. |
| loguid | event.source_record_id | MAPPED_DIRECT | opaque_log_record_identifier | opaque_identifier_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Unique in this export only; no global uniqueness claim. |
| net_proto | network.protocol_raw; network.protocol_number; network.protocol_name | MAPPED_DERIVED | integer_like_protocol_string | raw_string_or_null; integer_or_null; derived_name_or_null | COPIED; CONVERTED; DERIVED | DERIVED | UNKNOWN | number_and_name_null_with_actual_invalid_issue | Raw value remains evidence; standard protocol name is a separate derived value. |
| net_rcvdpkts | session.received_packets | MAPPED_CONVERTED | integer_like_packet_count_string | nonnegative_integer_or_null | CONVERTED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Known all-metric absence is contextual; no zero fill. |
| net_recvbytes | session.received_bytes | MAPPED_CONVERTED | integer_like_byte_count_string | nonnegative_integer_or_null | CONVERTED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Known all-metric absence is contextual; no zero fill. |
| net_sentbytes | session.sent_bytes | MAPPED_CONVERTED | integer_like_byte_count_string | nonnegative_integer_or_null | CONVERTED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Known all-metric absence is contextual; no zero fill. |
| net_sentpkts | session.sent_packets | MAPPED_CONVERTED | integer_like_packet_count_string | nonnegative_integer_or_null | CONVERTED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Known all-metric absence is contextual; no zero fill. |
| net_sessionduration | session.duration_raw_value | MAPPED_CONVERTED | integer_like_duration_string | unit_neutral_integer_or_null | CONVERTED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Unit remains unknown; valid nonnegative value is not named seconds. |
| net_sessionid | session.identifier | MAPPED_DIRECT | opaque_repeated_session_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Preserve equality and repetition; never group, merge, or deduplicate. |
| src_geo | network.source.geo_source | PRESERVED_OBSERVATION | source_geography_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Retain source geography observation without enrichment or location claims. |
| src_intf | network.source.interface_source | PRESERVED_OBSERVATION | opaque_interface_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | UNKNOWN | not_converted_preserve_raw | Interface semantics remain source-specific. |
| src_ip | network.source.identifier | MAPPED_DIRECT | opaque_sanitized_network_identifier | opaque_identifier_or_null | COPIED | VERIFIED | UNKNOWN | not_converted_preserve_raw | Canonical role is source identifier, not literal IP address. |
| src_mac | network.source.link_layer_identifier | MAPPED_DIRECT | opaque_sanitized_link_layer_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Opaque source token is retained without MAC syntax validation. |
| src_port | network.source.port | MAPPED_CONVERTED | integer_like_transport_port_string | integer_or_null | CONVERTED | VERIFIED | CONTEXT_DEPENDENT | null_and_actual_invalid_issue | Convert only valid 0 through 65535 values; protocol context controls missingness. |
| event_profile | UNMAPPED | PRESERVED_UNMAPPED | opaque_source_profile_token | raw_string_or_null | PRESERVED_UNMAPPED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Profile semantics and population conditions are unresolved. |
| host_osver | host.os_version_source | PRESERVED_OBSERVATION | source_operating_system_version_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source observation without operating-system taxonomy normalization. |
| src_natip | network.source.nat_identifier_source | PRESERVED_OBSERVATION | opaque_sanitized_nat_identifier | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Presence is context-dependent and source NAT semantics remain unverified. |
| src_natport | network.source.nat_port_source | PRESERVED_OBSERVATION | integer_like_nat_port_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain raw source observation because source NAT semantics are unresolved. |
| host_hwvendor | host.hardware_vendor_source | PRESERVED_OBSERVATION | source_hardware_vendor_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Inventory source and population conditions remain unresolved. |
| host_hwver | host.hardware_version_source | PRESERVED_OBSERVATION | source_hardware_version_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Inventory source and population conditions remain unresolved. |
| host_osfamily | host.os_family_source | PRESERVED_OBSERVATION | source_operating_system_family_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source observation without operating-system taxonomy normalization. |
| host_osname | host.os_name_source | PRESERVED_OBSERVATION | source_operating_system_name_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source observation without operating-system taxonomy normalization. |
| host_name | host.name_source | PRESERVED_OBSERVATION | opaque_host_name_token | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain opaque host name without deanonymization. |
| src_domain | network.source.domain_source | PRESERVED_OBSERVATION | opaque_source_domain_token | opaque_identifier_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source observation without domain enrichment. |
| threat_action | threat_observations.action_source | PRESERVED_OBSERVATION | source_product_threat_action_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product observation only; never an attack or benign label. |
| threat_name | threat_observations.name_source | PRESERVED_OBSERVATION | source_product_threat_name_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product observation only; never an attack or benign label. |
| threat_severity | threat_observations.severity_source | PRESERVED_OBSERVATION | source_product_threat_severity_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product severity is not converted into a risk score. |
| threat_type | threat_observations.type_source | PRESERVED_OBSERVATION | source_product_threat_type_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product observation only; never an attack or benign label. |
| app_id | application.id_raw | PRESERVED_OBSERVATION | source_application_identifier_string | raw_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Sparse source identifier is retained without unsupported numeric semantics. |
| app_name | application.name_source | PRESERVED_OBSERVATION | source_application_name_string | source_observation_string_or_null | COPIED | CONTEXT_DEPENDENT | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-product name is retained without a universal taxonomy. |
| threat_pattern | threat_observations.pattern_source | PRESERVED_OBSERVATION | source_product_threat_pattern_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Source-specific pattern semantics remain unresolved. |
| event_message | event.message_source | PRESERVED_OBSERVATION | source_event_message_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source text without extracting security conclusions. |
| threat_id | threat_observations.id_raw | PRESERVED_OBSERVATION | source_product_threat_identifier_string | raw_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain raw source identifier without external enrichment. |
| threat_ref | threat_observations.reference_source | PRESERVED_OBSERVATION | source_product_threat_reference_string | source_observation_string_or_null | COPIED | NEEDS_VERIFICATION | CONTEXT_DEPENDENT | not_converted_preserve_raw | Retain source reference without external lookup or semantic promotion. |

## Intentionally preserved unmapped fields

| Field | Reason |
| --- | --- |
| adom_oid | Source-specific administrative-domain or related meaning is unverified. |
| data_timestamp | Numeric values are measured, but semantics and unit remain UNKNOWN. |
| epid | Source-specific event or process meaning is unverified. |
| euid | Source-specific event or user meaning is unverified. |
| event_profile | Source profile semantics and population conditions are unresolved. |

## Implementation boundaries

The future normalizer must consume FORTIGATE_FIELD_MAPPINGS instead of duplicating
mapping decisions in conditional code. It must preserve source strings and retain
unmapped fields. It may only implement conversion rules documented above, with
structured issues for non-empty invalid values.

This specification does not authorize source parsing, record transformation,
output generation, enrichment, labels, detection, scoring, machine learning, APIs,
or a second source adapter.
