# Stage 1.5 Storage Validation Findings

## Checkpoint status

**Stage 1.5F — REAL-DATA VALIDATION PASS.**

The authoritative local Stage 1.5F validator completed with `FINAL RESULT: PASS`.
It consumed only the approved Stage 1.4 finding JSONL and validation-summary
envelope, then completed strict validation, storage import, bounded read-only
queries, independent audit, and deterministic reconciliation.

Rule Match != Confirmed Attack.

## Approved validation inputs

| Artifact | Path | Approved SHA-256 |
| --- | --- | --- |
| Stage 1.4 finding JSONL | `data/processed/stage_1_4f_detection_findings.jsonl` | `5212F083BB3832158BCD650535536C22D1B8DBF582496726F998ECE949EE20DC` |
| Stage 1.4 bounded summary | `data/processed/stage_1_4f_detection_summary.json` | `D3585BF577CB1B16ACA2A8AFB65D18959941E28FC2B9CD6C396C35CF03DD16FE` |

The Stage 1.5F validator may open only these approved Stage 1.4 artifacts as its
real-data inputs. It must not open the raw FortiGate CSV or the Stage 1.3 normalized
JSONL.

## Identity semantics

- `run_id == findings_sha256`.
- `summary_sha256` remains the SHA-256 of the complete Stage 1.4F
  validation-envelope bytes. It is not a hash of the nested `primary_run` object.

## Storage validation flow

```text
Approved Stage 1.4 findings
        → strict validation
        → transactional SQLite import
        → bounded read-only query
        → independent audit
        → reconciliation
        → PASS
```

## Pre-registered reconciliation expectations

The following values come from approved Stage 1.4 evidence. They are validation
expectations, not values to force into storage code or claim as attacks.

| Measure | Expected value |
| --- | ---: |
| Evaluated normalized records | 100,000 |
| Invalid normalized records | 0 |
| Total `INFORMATIONAL` findings | 43 |
| Unique matched source records | 25 |
| `fortigate.source_threat_observation` findings | 25 |
| `fortigate.anomaly_subtype_observation` findings | 18 |

## Measured Stage 1.5F storage-validation evidence

| Measure | Verified value |
| --- | --- |
| `reconstructed_findings_sha256` | `5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc` |
| `logical_export_sha256` | `9f463dd96261d54673d88abd4f0213f5860381334fe07d19d4ec66a8eccd52e0` |
| `rule_count` | 2 |

The reconstructed finding identity equals the approved `findings_sha256`.

### Determinism and cleanup

| Check | Verified value |
| --- | --- |
| `logical_export_hashes_match` | `true` |
| `reconstructed_finding_hashes_match` | `true` |
| `query_output_hashes_match` | `true` |
| `secondary_database_removed` | `true` |

Do not record complete finding rows, source-record IDs, sanitized identifiers, or
evidence values in this tracked document.

## Interpretation boundary

PASS confirms storage consistency and deterministic preservation of the approved
Stage 1.4 finding evidence through strict validation, import, query, audit, and
reconciliation.

PASS does **not** mean findings are confirmed attacks, malicious activity,
compromised hosts, or confirmed incidents. It also does not establish detection
accuracy, precision, recall, or performance.
