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
