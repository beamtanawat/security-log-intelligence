# Security Log Intelligence

A learning-focused and portfolio-focused cybersecurity project
for analyzing security logs and gradually developing an
AI-assisted security intelligence platform.

The project starts with sanitized FortiGate network/security logs
and is designed to support additional security log sources in the future.

## Project Goal

The goal is to build the project incrementally while learning and applying:

- Cybersecurity
- Security Log Analysis
- Data Engineering
- Software Engineering
- Machine Learning
- AI Engineering

The project will begin with understanding and validating security data
before introducing detection rules, machine learning, LLMs, or deployment.

## Current Stage

### Stage 1 — FortiGate Security Log Exploration and Validation

Current priorities:

1. Load the dataset safely
2. Inspect the schema
3. Understand important fields
4. Profile missing values
5. Inspect event types and actions
6. Inspect protocols, applications, and services
7. Inspect network session information
8. Inspect threat-related fields
9. Identify data quality issues
10. Document findings

No machine learning is used at this stage.

### Stage 1.3 — Evidence-Preserving FortiGate Normalization — Complete

Stage 1.3 establishes a streaming, read-only FortiGate normalization path:
an explicit event-schema contract, a 58-field mapping specification, a source
adapter, record-level normalization, deterministic JSON Lines output, and an
all-record output audit. The final reconciliation passed against the sanitized
100,000-record export while preserving documented unknowns and source evidence.

This completion makes the normalized output available for a separately planned
rule-based detection stage. It does not implement or authorize detection,
classification, scoring, machine learning, APIs, or deployment. See
[`docs/normalized_event_schema.md`](docs/normalized_event_schema.md),
[`docs/fortigate_normalization_mapping.md`](docs/fortigate_normalization_mapping.md),
and [`docs/stage_1_3_normalization_findings.md`](docs/stage_1_3_normalization_findings.md).

### Stage 1.4 — Rule-Based Detection Foundation — Complete

Stage 1.4 adds a small, deterministic detection path on top of normalized events:
an immutable rule contract and registry, record-level streaming evaluation,
provenance-preserving findings, safe JSON Lines publication, and a streaming output
audit. The two initial FortiGate-only rules surface source-product threat observations
and the exact source subtype `anomaly`; they do not confirm attacks or create
incidents.

The validated audit evaluated all 100,000 normalized records, produced 43
informational findings from 25 source records, and verified deterministic output,
evidence, provenance, input integrity, and Git safety. These findings are
observations for review, not attack counts, maliciousness labels, confidence scores,
or risk scores. See [`docs/detection_contract.md`](docs/detection_contract.md),
[`docs/initial_detection_rules.md`](docs/initial_detection_rules.md), and
[`docs/stage_1_4_detection_findings.md`](docs/stage_1_4_detection_findings.md).

Stage 1.4 does not add thresholds, time windows, correlation, incidents, machine
learning, storage, APIs, or a dashboard. Any next stage remains separately planned.

### Stage 1.5 — Detection Finding Storage and Read-Only Query Foundation — Complete

Stage 1.5 adds a local SQLite v1 projection for the approved Stage 1.4 finding
artifacts. It strictly validates the finding JSONL and bounded summary, creates one
new database transactionally without overwriting an existing database, provides
typed bounded read-only queries, and independently audits schema integrity,
provenance projections, exact finding reconstruction, and logical determinism.

The validated storage run reconciled the approved 43 `INFORMATIONAL` findings from
25 source records and two rules. These remain deterministic source-observation
findings—not confirmed attacks, malicious activity, compromises, or incidents.
Storage validation does not reopen the raw CSV or normalized JSONL, and generated
SQLite artifacts remain ignored and untracked. See
[`docs/detection_storage_contract.md`](docs/detection_storage_contract.md) and
[`docs/stage_1_5_storage_findings.md`](docs/stage_1_5_storage_findings.md).

Stage 1.5 does not implement an API, dashboard, authentication, mutable database
workflow, new detection rule, correlation, incident process, ML, LLM, or deployment.
A read-only API remains a separately planned next stage.

## Current Dataset

The initial dataset is:

`network_log_SAFE.csv`

It contains sanitized FortiGate network/security traffic data.

Important field groups include:

- Event metadata
- Source and destination information
- Network protocols
- Ports
- Network sessions
- Applications and services
- Host information
- Event severity
- Threat information

The project treats raw security logs as immutable evidence.

## Future Log Sources

The architecture is intended to support additional security log sources such as:

- Windows Event Logs
- Linux authentication logs
- DNS logs
- Firewall logs
- IDS / IPS logs
- Endpoint logs
- VPN logs
- Proxy logs
- Cloud security logs
- EDR logs
- NetFlow
- SIEM exports

Different sources will eventually use source-specific parsers
that map data into a common internal security event format.

## Planned Evolution

```text
Security Logs
      ↓
Data Exploration
      ↓
Validation
      ↓
Parsing
      ↓
Normalization
      ↓
Rule-Based Detection
      ↓
Database / Data Engineering
      ↓
Backend API
      ↓
Web Dashboard
      ↓
Machine Learning
      ↓
Explainable AI
      ↓
Behavior Analytics
      ↓
Event Correlation
      ↓
Incident Intelligence
      ↓
LLM-Assisted Analysis
      ↓
Deployment
