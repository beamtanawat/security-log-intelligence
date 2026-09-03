# Stage 1.4 Rule-Based Detection Findings

## Checkpoint Status

**Stage 1.4F complete. Stage 1.4G PASS — NEEDS APPROVAL for its local commit.** The
retained local validation summary reports a successful Stage 1.4F run. The primary
findings were subsequently recovered after accidental deletion, matched to the
retained SHA-256, and fully re-audited using the repaired PowerShell audit bridge.
Measured results and the distinction between the original validation and recovery
checks are recorded below.

Rule Match != Confirmed Attack.

## Scope

Stage 1.4F evaluates only the two approved, deterministic, record-level FortiGate
source-observation rules against the existing normalized JSON Lines artifact. The
normalized input is read only. The raw CSV is never used as rule input; if it is
hashed, that is solely an integrity check. Primary findings and the bounded
validation summary are created only beneath ignored `data/processed/` paths.

This checkpoint does not establish attack truth, an incident count, malicious or
benign labels, detection accuracy, precision, recall, false-positive rate, or
false-negative rate.

## Validation Inputs and Integrity

The required values come from Stage 1.3 evidence and the raw-data baseline. The
retained Stage 1.4F summary and before/after recovery integrity checks agree with
these requirements. The raw file was hashed only, not parsed for detection.

| Measure | Required value before Stage 1.4F | Stage 1.4F measured result |
| --- | ---: | --- |
| Normalized input path | `data/processed/stage_1_3f_normalized_events.jsonl` | Matched; read only |
| Normalized JSON Lines records | 100,000 | 100,000 evaluated; 0 invalid |
| Normalized JSON Lines size | 907,375,745 bytes | 907,375,745 bytes; unchanged |
| Normalized JSON Lines SHA-256 | `C195C6322665530D56F1BD5390B6B1C20728881A21EE36352C7C46E0A7138976` | Matched before and after |
| Raw CSV SHA-256, if checked for integrity only | `EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D` | Matched before and after |

If the normalized artifact is missing or its size or hash differs, validation must
stop. It must not regenerate or replace that Stage 1.3 artifact.

## Pre-Registered Rule Reconciliation Expectations

The counts below are evidence-based expectations from the validated Stage 1.2
findings and the approved plan. They are not a target for code changes or tuning.
Any measured difference requires `NEEDS SECURITY REVIEW`.

| Rule ID | Version | Exact source-observation condition | Expected count | Measured finding count | Rule severity |
| --- | --- | --- | ---: | --- | --- |
| `fortigate.anomaly_subtype_observation` | `1.0` | Exact `event.subtype_source == "anomaly"` | 18 | 18 | `INFORMATIONAL` |
| `fortigate.source_threat_observation` | `1.0` | At least one populated `threat_observations.*` leaf | 25 | 25 | `INFORMATIONAL` |
| **Total** | — | — | **43** | **43** | — |

## Overlap and Record Reconciliation

One source record can produce independent findings from both approved rules. The
streaming output order is `(source record number, rule ID)`. This overlap does not
create an incident or assert that any record is malicious.

| Measure | Expected reconciliation | Measured result |
| --- | ---: | --- |
| Findings total | 43 | 43 |
| Unique matched source records | 25, if all anomaly matches are among threat-present records | 25 |
| Records matching both rules | 18, if the expectation holds | 18, reconciled as 18 + 25 - 25 |
| `INFORMATIONAL` findings | 43 | 43 |

The overlap calculation uses the audited one-finding-per-rule-per-record contract
and the two measured rule counts and union count. It is not an incident count.

No source-record IDs, sanitized identifiers, complete evidence values, or full
finding rows belong in this tracked document. The ignored bounded run summary may
retain no more than five finding references per rule for auditability.

## Required Finding Output, Audit, and Determinism Checks

The original local summary records the successful two-run validation. Recovery
recreated the primary output using the unchanged detector and repeated its full
input/output audit; it did not replace or rewrite the original summary.

| Check | Measured result |
| --- | --- |
| Primary finding JSON Lines count and size | 43 findings; 81,627 bytes |
| Primary finding SHA-256 | `5212F083BB3832158BCD650535536C22D1B8DBF582496726F998ECE949EE20DC` |
| Streaming finding audit | PASS; every finding reconciled to its normalized event and active rule metadata |
| Finding identity and ordering | PASS; deterministic identity and ordering validated |
| Evidence and provenance | PASS; exact canonical evidence and copied Stage 1.3 provenance validated |
| Source references | PASS; validated against normalized input without deduplication |
| Prohibited security-decision fields | Absent from every finding |
| Bounded summary | PASS; counts, active rules, and at most five samples per rule reconcile |
| Original second run | Same SHA-256 as the primary output, recorded in retained local summary |
| Original secondary artifact | Summary records removal after comparison; no secondary artifact remains |
| Recovered primary output | Same size, SHA-256, complete run summary, and audit summary as retained evidence |
| Full synthetic suite during recovery | 99 passed before; 99 passed after |

## Interpretation of Potential Matches

### FortiGate Source Threat Observation

A match means that FortiGate supplied one or more populated source threat-observation
fields. It can reflect policy, classification, scanning, or vendor logic; it is not
an independently confirmed attack. A record without this match is not labeled benign.

### FortiGate Anomaly Subtype Observation

A match means that FortiGate supplied the exact case-sensitive source subtype
`anomaly`. This is a source-product category, not proof of compromise,
maliciousness, or attack. A missing or different subtype simply does not match this
specific rule.

Both rules are FortiGate-only, deterministic, record-level, and fixed at
`INFORMATIONAL` rule severity. That rule severity is distinct from any source event
or source threat severity.

## Preserved Boundaries

- `data_timestamp` remains **UNKNOWN** and is not a detection clock.
- Any UTC view derived from `itime` remains **DERIVED** with
  `NEEDS_VERIFICATION`; findings use `time_basis = NOT_USED`.
- Sanitized IP-, MAC-, host-, and log-like tokens remain opaque identifiers.
- Session-duration units remain unresolved.
- Repeated `net_sessionid` values remain separate source records; no deduplication
  occurs.
- Threat, application, event, anomaly, and severity values remain source-product
  observations, not attack labels.
- No threshold, time window, state, sequence, correlation, tuning, enrichment,
  incident, risk score, ML, API, database, dashboard, or deployment behavior is
  introduced.

## Reproducibility and Git Safety

Run the controlled validator from the repository root in the validated local
PowerShell environment:

```powershell
.\scripts\validate_stage_1_4.ps1
```

It is designed to run the complete synthetic suite before and after real-data
evaluation, validate the normalized input against documented Stage 1.3 evidence,
audit the primary findings, compare a second finding output byte-for-byte by
SHA-256, and run `git diff --check`. Because this validator chooses to access the
raw CSV for integrity only, it also hashes the raw file before and after; it never
passes that file to a detection rule. It rejects tracked or staged files below
`data/raw/` or `data/processed/`.

The primary findings and validation summary now both exist and remain ignored and
untracked under `data/processed/`. The validator deliberately rejects existing
outputs. Do not delete successful evidence merely to rerun this command; any fresh
full validation needs separately approved preservation of existing artifacts.

### Artifact Recovery and Audit-Bridge Revalidation

The primary findings file was accidentally deleted after a successful local run.
The retained `stage_1_4f_detection_summary.json` was preserved. Its SHA-256 remained
`D3585BF577CB1B16ACA2A8AFB65D18959941E28FC2B9CD6C396C35CF03DD16FE`
before and after recovery.

Recovery used the existing `src/evaluate_detections.py` to recreate only the missing
primary output. The restored bytes match both finding hashes in the retained
two-run evidence. No rule, engine, adapter, normalizer, schema, or expected count
was changed. Recovery did not rerun the entire validator or create a new validation
summary; the original successful two-run record remains authoritative.

The repaired validator writes its Python audit bridge to a temporary file instead
of passing multiline Python through `python -c`, avoiding Windows PowerShell
quotation changes. The actual repaired bridge completed the full restored-output
audit on Windows PowerShell 5.1 with Python 3.12.10. The entire new audit summary,
including bounded references, matched the retained audit summary. The bridge
removes its own temporary helper in `finally`.

An existing-output refusal smoke test passed on PowerShell 7.6.4 and left both
artifacts unchanged. A standalone `-File` invocation on the verification host's
Windows PowerShell 5.1 was blocked by execution policy before the script ran; no
execution policy, Python installation, virtual environment, or PATH was changed.
This limitation is distinct from the successful bridge execution on that host.

The raw and normalized inputs retained their baseline hashes. No temporary
processed output remains. Raw and processed data are neither staged nor tracked;
`git diff --check` passes. The pre-existing Stage 1.5 plan was left unchanged.

## Limitations

- The evaluation covers one sanitized, normalized 100,000-record FortiGate
  export.
- There is no attack ground truth or label set.
- Rule-match counts are not incident, attack, accuracy, precision, recall,
  detection-rate, false-positive-rate, or false-negative-rate metrics.
- The initial rules are deliberately narrow source-product observations; they do
  not assess broader behavior or coverage.

## Validator Verdict

**Stage 1.4F PASS.** The retained local validation and recovery checks agree on input
integrity, all 100,000 evaluated records, finding counts, provenance, determinism,
tests, and Git safety. Findings are source observations only, not confirmed attacks.

## Stage 1.4G Reconciliation and Readiness

The final documentation review reconciles the implementation and its evidence:

```text
NormalizedSecurityEvent v1.0
        ↓
Immutable built-in rule registry
        ↓
Record-level streaming evaluation
        ↓
DetectionFinding v1.0 with exact evidence and provenance
        ↓
Safe deterministic JSON Lines publication
        ↓
Streaming finding-output audit
```

The detection contract, rule catalog, active metadata, canonical evidence paths,
reason codes, fixed `INFORMATIONAL` rule severity, tests, and Stage 1.4F measured
counts are reconciled in the final documentation. Rule severity remains separate
from source event severity and source threat severity.

This final documentation gate passed, so the foundation is technically ready for
Stage 1.4 closure. It is ready only as a transparent, deterministic source-observation
baseline: not as a confirmed-attack detector, incident system, risk engine,
performance benchmark, or general security conclusion. A later stage must be
separately planned and approved.

The contract details are in [`detection_contract.md`](detection_contract.md); the
reviewed active-rule definitions are in
[`initial_detection_rules.md`](initial_detection_rules.md). Their input boundary and
provenance semantics remain those established by the Stage 1.3
[`normalized_event_schema.md`](normalized_event_schema.md); Stage 1.4 does not
redefine or modify them.
