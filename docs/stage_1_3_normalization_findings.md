# Stage 1.3F Normalization Audit Findings

## Scope

This checkpoint audited the completed FortiGate normalization path against the
immutable sanitized source file `data/raw/network_log_SAFE.csv`. It used the
Stage 1.3E streaming CLI and a streaming JSON Lines audit. Raw data was read
only; normalized artifacts were written only under ignored `data/processed/`.

## Measured Results

| Measure | Result |
| --- | ---: |
| Raw file size before and after | 41,235,093 bytes |
| Raw SHA-256 before and after | `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D` |
| Source records read | 100,000 |
| Valid source records | 100,000 |
| Malformed source records | 0 |
| Normalized JSON Lines records | 100,000 |
| Primary JSONL size | 907,375,745 bytes |
| Primary JSONL SHA-256 | `C195C6322665530D56F1BD5390B6B1C20728881A21EE36352C7C46E0A7138976` |
| Determinism comparison | Primary and second-run SHA-256 values matched exactly |
| Temporary determinism artifact after comparison | Removed |

**FACT.** The output audit confirmed contiguous logical record numbers from 1
through 100,000. Source and output cardinality therefore reconcile without
record loss or session-ID deduplication.

## Mapping, Preservation, and Provenance Audit

| Aggregate | Measured count |
| --- | ---: |
| Known mapped field values | 5,300,000 |
| Known preserved-unmapped field values | 500,000 |
| Unexpected source field values | 0 |
| Bounded unknown source field names | None |

**FACT.** The streaming output audit reconstructed every normalized event under
the Stage 1.3 contract and applied the established mapping/provenance validator
to all 100,000 output records without a validation failure.

**FACT.** The audit verified that each record preserved its expected unmapped
fields, including `data_timestamp`, and that copied opaque source, destination,
host, and session identifiers matched their source-record values. No identifier
syntax validation, deanonymization, enrichment, grouping, or deduplication was
performed.

## Normalization Issues

| Issue code | Count | Existing interpretation boundary |
| --- | ---: | --- |
| `MISSING_PORTS_EXPECTED_FOR_ICMP` | 27,447 | EXPECTED |
| `ALL_SESSION_METRICS_MISSING` | 778 | CONTEXT_DEPENDENT |
| `MISSING_ITIME` | 1 | UNKNOWN |

**FACT.** No conversion-failure issue code was emitted by the normalized output
audit aggregate. This is an observation about this sanitized export; it does not
change the explicit conversion-failure handling for future input.

## Contract Boundaries Confirmed

The all-record streaming audit confirmed the following implementation boundaries:

- `data_timestamp` remained preserved and unmapped; its semantics remain
  **UNKNOWN**.
- `itime` raw source evidence was retained. The optional UTC representation
  remained **DERIVED** with `NEEDS_VERIFICATION` status.
- Sanitized identifier tokens remained opaque copied values, not literal IP or
  MAC addresses.
- `net_sessionduration` remained a unit-neutral raw-value role; no duration unit
  was introduced.
- Repeated `net_sessionid` values remained separate output records.
- Threat, application, event, and severity values remained source-product
  observations. The normalized schema contains no attack, malicious/benign,
  risk, or detection output.

## Reproducibility and Artifact Safety

The local Stage 1.3F validator is
`scripts/validate_stage_1_3.ps1`. It runs the complete synthetic suite before
and after real-data processing, validates the raw hash before and after, performs
the required deterministic second normalization, and leaves only the primary
JSONL and bounded summary in ignored `data/processed/`.

**FACT.** The complete suite passed 67 tests before and after the successful
real-data validation. `git diff --check` passed. No file beneath `data/raw/` or
`data/processed/` is staged or tracked.

## Limitations

- This audit validates preservation, structural consistency, deterministic
  serialization, and the existing contract. It does not establish FortiGate
  product semantics beyond the documented evidence.
- `data_timestamp` semantics, the epoch-seconds assumption for the derived
  `itime` UTC view, and session-duration units remain unresolved as documented.
- The source is one sanitized 100,000-record export. The audit does not classify
  activity, infer maliciousness, create detections, or provide security scoring.

## Validator Verdict

**PASS.** The Stage 1.3F validator passed its raw-integrity, count,
mapping/provenance, determinism, output-safety, test-suite, and Git-safety
checks. This is an audit result only; Stage 1.3G and any detection work remain
outside this checkpoint.
