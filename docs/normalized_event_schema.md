# Normalized Security Event Contract v1.0

## Purpose

This document defines the minimal, vendor-neutral Stage 1.3 contract used to
represent one parsed security-log record without discarding its source evidence.
It is a data-preservation contract, not a detection, classification, or
enrichment model.

The contract is intentionally smaller than a full enterprise event schema. A
future source adapter may populate the same roles differently, while any
unsupported source field remains available as raw evidence.

## Version and serialization

- Schema version: 1.0
- Serialized form: plain JSON objects with deterministic key ordering supplied by
  the caller's JSON serializer.
- Optional canonical values: JSON null; never fabricated zero or text values.
- Source strings: preserved exactly in source_record, including empty strings and
  sanitized identifier tokens.

## Required event sections

Every serialized normalized event contains these sections:

| Section | Contract role |
| --- | --- |
| schema_version | Fixed version string, initially 1.0. |
| source | Source-neutral source metadata and logical record context. |
| event | Source event identity and source-supplied event observations. |
| time | Raw time evidence and optional clearly derived time representations. |
| network | Endpoint roles, ports, protocol data, and other network observations. |
| application | Source-supplied application observations. |
| session | Session identifier and unit-neutral session observations. |
| host | Host roles and source host observations. |
| threat_observations | Source-product threat observations, never ground truth. |
| source_record | Exact decoded source field/value mapping. |
| unmapped_fields | Preserved source fields without a justified canonical role. |
| provenance | Evidence for populated copied, converted, or derived canonical values. |
| normalization_issues | Structured conversion, missingness, or contract observations. |

The generic contract does not define any vendor field mapping. Source adapters and
their mapping specifications are separate checkpoint work.

## Status vocabularies

| Vocabulary | Allowed values | Meaning |
| --- | --- | --- |
| Mapping operation | COPIED, CONVERTED, DERIVED, PRESERVED_UNMAPPED | How source evidence was represented. |
| Interpretation status | VERIFIED, DERIVED, NEEDS_VERIFICATION, UNKNOWN, CONTEXT_DEPENDENT | Confidence and interpretation boundary. |
| Issue status | EXPECTED, CONTEXT_DEPENDENT, UNKNOWN, ACTUAL_INVALID | Missingness or conversion status. |

Unknown or prohibited status names are rejected by the contract models. These
vocabularies contain no security decision, risk, or label state.

## Core structures

### SourceRecord

SourceRecord retains a non-empty decoded mapping of source field names to strings
or null, plus the source type and one-based logical record number. It is a
source-neutral container; it neither parses a file nor validates a
source-specific header.

### FieldProvenance

Each populated copied, converted, or derived canonical leaf can carry:

- canonical_path
- ordered source_fields
- mapping operation
- interpretation_status
- optional note

Framework metadata such as schema version and logical record number is not
source-derived and has no field-level provenance entry.

### NormalizationIssue

An issue has an optional source field, an issue code, an issue status, and a safe
human-readable description. An issue preserves the distinction between a missing
contextual value and a non-empty value that could not be represented in a typed
canonical field.

### NormalizationRunSummary

The generic run-summary model records source/output paths, record counts, mapping
coverage counts, issue counts, and bounded unknown field names. It does not run a
dataset operation or write files.

## Minimal synthetic example

The following is illustrative only; its values are synthetic and are not taken
from the project dataset.

~~~json
{
  "schema_version": "1.0",
  "source": {"record_number": 1, "source_type": "example_source"},
  "event": {"source_record_id": "example-record"},
  "time": {"raw_value": null},
  "network": {"source_identifier": "opaque-source", "source_port": null},
  "application": {},
  "session": {},
  "host": {},
  "threat_observations": {},
  "source_record": {
    "example_identifier": "opaque-source",
    "example_optional_value": ""
  },
  "unmapped_fields": {"example_optional_value": ""},
  "provenance": [
    {
      "canonical_path": "network.source_identifier",
      "source_fields": ["example_identifier"],
      "operation": "COPIED",
      "interpretation_status": "VERIFIED",
      "note": "Identifier format is source-defined."
    }
  ],
  "normalization_issues": []
}
~~~

The example shows that a missing optional canonical value is null while an empty
decoded source string remains an empty string in source_record.

## Contract boundaries

- Every valid source record remains separately representable; no deduplication is
  part of this contract.
- Sanitized identifiers are opaque values. The contract has identifier roles, not
  literal address types or syntax validation.
- Derived time values must preserve the raw value and state their assumption in
  provenance. Unresolved time fields remain source evidence.
- Source-product threat observations are not attack, benign, or risk labels.
- Unknown source fields and categories are represented safely rather than dropped.
- File parsing, source-specific mapping, conversion policy, JSON Lines output, and
  real-data execution are outside checkpoint 1.3A.
