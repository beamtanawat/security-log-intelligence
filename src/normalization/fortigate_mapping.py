"""Declarative Stage 1.3B mapping metadata for the FortiGate source.

This module specifies mapping decisions only. It does not parse files, convert
record values, normalize records, write output, or make security conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import INTERPRETATION_STATUSES, ISSUE_STATUSES, MAPPING_OPERATIONS


MAPPING_CATEGORIES = frozenset(
    {
        "MAPPED_DIRECT",
        "MAPPED_CONVERTED",
        "MAPPED_DERIVED",
        "PRESERVED_OBSERVATION",
        "PRESERVED_UNMAPPED",
    }
)


class FortiGateMappingError(ValueError):
    """Raised when mapping metadata does not satisfy the Stage 1.3B contract."""


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise FortiGateMappingError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class FortiGateFieldMapping:
    """One explicit, non-executing decision for one FortiGate source field."""

    source_field: str
    canonical_paths: tuple[str, ...]
    mapping_category: str
    source_representation: str
    target_type: str
    operations: tuple[str, ...]
    interpretation_status: str
    missingness_status: str
    conversion_failure_behavior: str
    rationale: str

    def __post_init__(self) -> None:
        _require_text(self.source_field, "source_field")
        _require_text(self.mapping_category, "mapping_category")
        _require_text(self.source_representation, "source_representation")
        _require_text(self.target_type, "target_type")
        _require_text(self.interpretation_status, "interpretation_status")
        _require_text(self.missingness_status, "missingness_status")
        _require_text(
            self.conversion_failure_behavior, "conversion_failure_behavior"
        )
        _require_text(self.rationale, "rationale")

        if self.mapping_category not in MAPPING_CATEGORIES:
            raise FortiGateMappingError("mapping_category is not supported")
        if self.interpretation_status not in INTERPRETATION_STATUSES:
            raise FortiGateMappingError("interpretation_status is not supported")
        if self.missingness_status not in ISSUE_STATUSES:
            raise FortiGateMappingError("missingness_status is not supported")
        if not self.operations:
            raise FortiGateMappingError("operations must not be empty")
        if any(operation not in MAPPING_OPERATIONS for operation in self.operations):
            raise FortiGateMappingError("operations contain an unsupported value")
        if len(set(self.canonical_paths)) != len(self.canonical_paths):
            raise FortiGateMappingError("canonical_paths must be unique")
        for path in self.canonical_paths:
            _require_text(path, "canonical path")

        if self.mapping_category == "PRESERVED_UNMAPPED":
            if self.canonical_paths:
                raise FortiGateMappingError(
                    "preserved-unmapped fields cannot have canonical paths"
                )
            if self.operations != ("PRESERVED_UNMAPPED",):
                raise FortiGateMappingError(
                    "preserved-unmapped fields require PRESERVED_UNMAPPED"
                )
        elif not self.canonical_paths:
            raise FortiGateMappingError(
                "mapped or observed fields require at least one canonical path"
            )

    def documentation_row(self) -> tuple[str, ...]:
        """Return stable cells used by the human-readable mapping table."""

        return (
            self.source_field,
            "; ".join(self.canonical_paths) if self.canonical_paths else "UNMAPPED",
            self.mapping_category,
            self.source_representation,
            self.target_type,
            "; ".join(self.operations),
            self.interpretation_status,
            self.missingness_status,
            self.conversion_failure_behavior,
            self.rationale,
        )


def _rule(
    source_field: str,
    canonical_paths: tuple[str, ...],
    mapping_category: str,
    source_representation: str,
    target_type: str,
    operations: tuple[str, ...],
    interpretation_status: str,
    missingness_status: str,
    conversion_failure_behavior: str,
    rationale: str,
) -> FortiGateFieldMapping:
    return FortiGateFieldMapping(
        source_field=source_field,
        canonical_paths=canonical_paths,
        mapping_category=mapping_category,
        source_representation=source_representation,
        target_type=target_type,
        operations=operations,
        interpretation_status=interpretation_status,
        missingness_status=missingness_status,
        conversion_failure_behavior=conversion_failure_behavior,
        rationale=rationale,
    )


FORTIGATE_FIELD_MAPPINGS = (
    _rule(
        "itime",
        ("time.itime_raw", "time.itime_utc_derived"),
        "MAPPED_DERIVED",
        "integer_like_timestamp_string",
        "raw_string_or_null; derived_utc_string_or_null",
        ("COPIED", "DERIVED"),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "derived_utc_null_and_issue",
        "Preserve raw value; optional UTC requires an explicit epoch-seconds assumption.",
    ),
    _rule(
        "adom_oid",
        (),
        "PRESERVED_UNMAPPED",
        "source_specific_integer_like_string",
        "raw_string_or_null",
        ("PRESERVED_UNMAPPED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Source-specific meaning is not established.",
    ),
    _rule(
        "app_cat",
        ("application.category_source",),
        "PRESERVED_OBSERVATION",
        "source_product_category_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product category is sparse in known contexts.",
    ),
    _rule(
        "app_service",
        ("application.service_source",),
        "PRESERVED_OBSERVATION",
        "source_product_service_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source service observation without universal taxonomy.",
    ),
    _rule(
        "data_parsername",
        ("source.parser_name",),
        "MAPPED_DIRECT",
        "parser_name_string",
        "string_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Identifies the source parser without inferring more source semantics.",
    ),
    _rule(
        "data_sourceid",
        ("source.source_identifier",),
        "MAPPED_DIRECT",
        "opaque_source_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve opaque source identity; device or collector role is unresolved.",
    ),
    _rule(
        "data_sourcename",
        ("source.source_name",),
        "MAPPED_DIRECT",
        "opaque_sanitized_source_name",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve sanitized source name without deanonymization.",
    ),
    _rule(
        "data_sourcetype",
        ("source.source_type",),
        "MAPPED_DIRECT",
        "source_product_type_string",
        "string_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Retain the source-product type exactly as supplied.",
    ),
    _rule(
        "data_timestamp",
        (),
        "PRESERVED_UNMAPPED",
        "integer_like_source_specific_string",
        "raw_string_or_null",
        ("PRESERVED_UNMAPPED",),
        "UNKNOWN",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Measured numeric behavior does not establish a time, offset, sequence, or duration meaning.",
    ),
    _rule(
        "dst_geo",
        ("network.destination.geo_source",),
        "PRESERVED_OBSERVATION",
        "source_geography_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Retain source geography observation without enrichment or location claims.",
    ),
    _rule(
        "dst_intf",
        ("network.destination.interface_source",),
        "PRESERVED_OBSERVATION",
        "opaque_interface_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Interface population is source context and does not justify a universal interface type.",
    ),
    _rule(
        "dst_ip",
        ("network.destination.identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_network_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Canonical role is destination identifier, not literal IP address.",
    ),
    _rule(
        "dst_mac",
        ("network.destination.link_layer_identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_link_layer_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Opaque source token is retained without MAC syntax validation.",
    ),
    _rule(
        "dst_port",
        ("network.destination.port",),
        "MAPPED_CONVERTED",
        "integer_like_transport_port_string",
        "integer_or_null",
        ("CONVERTED",),
        "VERIFIED",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Convert only valid 0 through 65535 values; protocol context controls missingness.",
    ),
    _rule(
        "epid",
        (),
        "PRESERVED_UNMAPPED",
        "source_specific_integer_like_string",
        "raw_string_or_null",
        ("PRESERVED_UNMAPPED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Source-specific event or process meaning is not established.",
    ),
    _rule(
        "euid",
        (),
        "PRESERVED_UNMAPPED",
        "source_specific_integer_like_string",
        "raw_string_or_null",
        ("PRESERVED_UNMAPPED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Source-specific event or user meaning is not established.",
    ),
    _rule(
        "event_action",
        ("event.action_source",),
        "MAPPED_DIRECT",
        "source_action_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Retain source action without turning it into a security verdict.",
    ),
    _rule(
        "event_id",
        ("event.source_event_id",),
        "MAPPED_DIRECT",
        "source_event_identifier_string",
        "raw_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve source event identifier without product-family inference.",
    ),
    _rule(
        "event_severity",
        ("event.severity_source",),
        "PRESERVED_OBSERVATION",
        "source_severity_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Source severity is not converted into a cross-vendor risk scale.",
    ),
    _rule(
        "event_subtype",
        ("event.subtype_source",),
        "MAPPED_DIRECT",
        "source_subtype_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve source subtype without classifying its security meaning.",
    ),
    _rule(
        "event_type",
        ("event.type_source",),
        "MAPPED_DIRECT",
        "source_event_family_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve source event family without universal taxonomy.",
    ),
    _rule(
        "host_ip",
        ("host.identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_network_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Canonical role is host identifier, not literal IP address.",
    ),
    _rule(
        "host_location",
        ("host.location_source",),
        "PRESERVED_OBSERVATION",
        "source_host_location_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Logical, physical, and inventory meanings remain unresolved.",
    ),
    _rule(
        "host_mac",
        ("host.link_layer_identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_link_layer_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Opaque source token is retained without MAC syntax validation.",
    ),
    _rule(
        "host_type",
        ("host.type_source",),
        "PRESERVED_OBSERVATION",
        "source_host_type_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source taxonomy is retained without a universal host type.",
    ),
    _rule(
        "loguid",
        ("event.source_record_id",),
        "MAPPED_DIRECT",
        "opaque_log_record_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Unique in this export only; no global uniqueness claim.",
    ),
    _rule(
        "net_proto",
        (
            "network.protocol_raw",
            "network.protocol_number",
            "network.protocol_name",
        ),
        "MAPPED_DERIVED",
        "integer_like_protocol_string",
        "raw_string_or_null; integer_or_null; derived_name_or_null",
        ("COPIED", "CONVERTED", "DERIVED"),
        "DERIVED",
        "UNKNOWN",
        "number_and_name_null_with_actual_invalid_issue",
        "Raw value remains evidence; standard protocol name is a separate derived value.",
    ),
    _rule(
        "net_rcvdpkts",
        ("session.received_packets",),
        "MAPPED_CONVERTED",
        "integer_like_packet_count_string",
        "nonnegative_integer_or_null",
        ("CONVERTED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Known all-metric absence is contextual; no zero fill.",
    ),
    _rule(
        "net_recvbytes",
        ("session.received_bytes",),
        "MAPPED_CONVERTED",
        "integer_like_byte_count_string",
        "nonnegative_integer_or_null",
        ("CONVERTED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Known all-metric absence is contextual; no zero fill.",
    ),
    _rule(
        "net_sentbytes",
        ("session.sent_bytes",),
        "MAPPED_CONVERTED",
        "integer_like_byte_count_string",
        "nonnegative_integer_or_null",
        ("CONVERTED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Known all-metric absence is contextual; no zero fill.",
    ),
    _rule(
        "net_sentpkts",
        ("session.sent_packets",),
        "MAPPED_CONVERTED",
        "integer_like_packet_count_string",
        "nonnegative_integer_or_null",
        ("CONVERTED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Known all-metric absence is contextual; no zero fill.",
    ),
    _rule(
        "net_sessionduration",
        ("session.duration_raw_value",),
        "MAPPED_CONVERTED",
        "integer_like_duration_string",
        "unit_neutral_integer_or_null",
        ("CONVERTED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Unit remains unknown; valid nonnegative value is not named seconds.",
    ),
    _rule(
        "net_sessionid",
        ("session.identifier",),
        "MAPPED_DIRECT",
        "opaque_repeated_session_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Preserve equality and repetition; never group, merge, or deduplicate.",
    ),
    _rule(
        "src_geo",
        ("network.source.geo_source",),
        "PRESERVED_OBSERVATION",
        "source_geography_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Retain source geography observation without enrichment or location claims.",
    ),
    _rule(
        "src_intf",
        ("network.source.interface_source",),
        "PRESERVED_OBSERVATION",
        "opaque_interface_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Interface semantics remain source-specific.",
    ),
    _rule(
        "src_ip",
        ("network.source.identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_network_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "VERIFIED",
        "UNKNOWN",
        "not_converted_preserve_raw",
        "Canonical role is source identifier, not literal IP address.",
    ),
    _rule(
        "src_mac",
        ("network.source.link_layer_identifier",),
        "MAPPED_DIRECT",
        "opaque_sanitized_link_layer_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Opaque source token is retained without MAC syntax validation.",
    ),
    _rule(
        "src_port",
        ("network.source.port",),
        "MAPPED_CONVERTED",
        "integer_like_transport_port_string",
        "integer_or_null",
        ("CONVERTED",),
        "VERIFIED",
        "CONTEXT_DEPENDENT",
        "null_and_actual_invalid_issue",
        "Convert only valid 0 through 65535 values; protocol context controls missingness.",
    ),
    _rule(
        "event_profile",
        (),
        "PRESERVED_UNMAPPED",
        "opaque_source_profile_token",
        "raw_string_or_null",
        ("PRESERVED_UNMAPPED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Profile semantics and population conditions are unresolved.",
    ),
    _rule(
        "host_osver",
        ("host.os_version_source",),
        "PRESERVED_OBSERVATION",
        "source_operating_system_version_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source observation without operating-system taxonomy normalization.",
    ),
    _rule(
        "src_natip",
        ("network.source.nat_identifier_source",),
        "PRESERVED_OBSERVATION",
        "opaque_sanitized_nat_identifier",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Presence is context-dependent and source NAT semantics remain unverified.",
    ),
    _rule(
        "src_natport",
        ("network.source.nat_port_source",),
        "PRESERVED_OBSERVATION",
        "integer_like_nat_port_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain raw source observation because source NAT semantics are unresolved.",
    ),
    _rule(
        "host_hwvendor",
        ("host.hardware_vendor_source",),
        "PRESERVED_OBSERVATION",
        "source_hardware_vendor_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Inventory source and population conditions remain unresolved.",
    ),
    _rule(
        "host_hwver",
        ("host.hardware_version_source",),
        "PRESERVED_OBSERVATION",
        "source_hardware_version_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Inventory source and population conditions remain unresolved.",
    ),
    _rule(
        "host_osfamily",
        ("host.os_family_source",),
        "PRESERVED_OBSERVATION",
        "source_operating_system_family_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source observation without operating-system taxonomy normalization.",
    ),
    _rule(
        "host_osname",
        ("host.os_name_source",),
        "PRESERVED_OBSERVATION",
        "source_operating_system_name_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source observation without operating-system taxonomy normalization.",
    ),
    _rule(
        "host_name",
        ("host.name_source",),
        "PRESERVED_OBSERVATION",
        "opaque_host_name_token",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain opaque host name without deanonymization.",
    ),
    _rule(
        "src_domain",
        ("network.source.domain_source",),
        "PRESERVED_OBSERVATION",
        "opaque_source_domain_token",
        "opaque_identifier_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source observation without domain enrichment.",
    ),
    _rule(
        "threat_action",
        ("threat_observations.action_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_action_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product observation only; never an attack or benign label.",
    ),
    _rule(
        "threat_name",
        ("threat_observations.name_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_name_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product observation only; never an attack or benign label.",
    ),
    _rule(
        "threat_severity",
        ("threat_observations.severity_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_severity_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product severity is not converted into a risk score.",
    ),
    _rule(
        "threat_type",
        ("threat_observations.type_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_type_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product observation only; never an attack or benign label.",
    ),
    _rule(
        "app_id",
        ("application.id_raw",),
        "PRESERVED_OBSERVATION",
        "source_application_identifier_string",
        "raw_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Sparse source identifier is retained without unsupported numeric semantics.",
    ),
    _rule(
        "app_name",
        ("application.name_source",),
        "PRESERVED_OBSERVATION",
        "source_application_name_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "CONTEXT_DEPENDENT",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-product name is retained without a universal taxonomy.",
    ),
    _rule(
        "threat_pattern",
        ("threat_observations.pattern_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_pattern_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Source-specific pattern semantics remain unresolved.",
    ),
    _rule(
        "event_message",
        ("event.message_source",),
        "PRESERVED_OBSERVATION",
        "source_event_message_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source text without extracting security conclusions.",
    ),
    _rule(
        "threat_id",
        ("threat_observations.id_raw",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_identifier_string",
        "raw_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain raw source identifier without external enrichment.",
    ),
    _rule(
        "threat_ref",
        ("threat_observations.reference_source",),
        "PRESERVED_OBSERVATION",
        "source_product_threat_reference_string",
        "source_observation_string_or_null",
        ("COPIED",),
        "NEEDS_VERIFICATION",
        "CONTEXT_DEPENDENT",
        "not_converted_preserve_raw",
        "Retain source reference without external lookup or semantic promotion.",
    ),
)


def validate_fortigate_mapping_specification() -> None:
    """Raise when the declarative mapping table is incomplete or inconsistent."""

    source_fields = [mapping.source_field for mapping in FORTIGATE_FIELD_MAPPINGS]
    if len(source_fields) != 58:
        raise FortiGateMappingError("mapping specification must contain 58 fields")
    if len(set(source_fields)) != len(source_fields):
        raise FortiGateMappingError("mapping specification contains duplicate fields")
