# AGENTS.md

# ============================================================
# PROJECT IDENTITY
# ============================================================

## Project Name

Security Log Intelligence

## Project Type

A learning-focused and portfolio-focused project combining:

- Cybersecurity
- Security Data Engineering
- Software Engineering
- Machine Learning
- AI Engineering

The project starts with one real security log source:

network_log_SAFE.csv

The current dataset is primarily FortiGate network/security
traffic data.

The project must be designed so additional log sources can be
added later without rewriting the entire system.


# ============================================================
# PRIMARY PROJECT GOAL
# ============================================================

Build an extensible Security Log Intelligence platform.

The system should gradually evolve from basic log analysis into:

Security Logs
    ↓
Data Ingestion
    ↓
Parsing
    ↓
Validation
    ↓
Normalization
    ↓
Security Analysis
    ↓
Rule-Based Detection
    ↓
Data Storage
    ↓
Machine Learning
    ↓
Behavior Analytics
    ↓
Event Correlation
    ↓
Incident Intelligence
    ↓
Explainable AI
    ↓
LLM-Assisted Analysis
    ↓
API / Web Application
    ↓
Deployment

Do not attempt to implement the full architecture immediately.

The project must grow incrementally.


# ============================================================
# CURRENT DEVELOPMENT STAGE
# ============================================================

## Current Stage

Stage 1 — FortiGate Security Log Exploration and Validation

The immediate goal is to understand the current dataset before
building detection logic or machine learning.

Current priorities:

Understand
    ↓
Inspect
    ↓
Validate
    ↓
Summarize

before:

Detect
    ↓
Model
    ↓
Predict


# ============================================================
# CURRENT DATASET
# ============================================================

## Current Input

The initial dataset is:

network_log_SAFE.csv

The dataset represents FortiGate network/security traffic logs.

Important observed field groups include:

### Event Metadata

- itime
- event_action
- event_id
- event_severity
- event_subtype
- event_type
- loguid

### Data Source Metadata

- data_parsername
- data_sourceid
- data_sourcename
- data_sourcetype
- data_timestamp

### Source Network Information

- src_geo
- src_intf
- src_ip
- src_mac
- src_port
- src_natip
- src_natport
- src_domain

### Destination Network Information

- dst_geo
- dst_intf
- dst_ip
- dst_mac
- dst_port

### Network Session Information

- net_proto
- net_rcvdpkts
- net_recvbytes
- net_sentbytes
- net_sentpkts
- net_sessionduration
- net_sessionid

### Application Information

- app_cat
- app_service
- app_id
- app_name

### Host Information

- host_ip
- host_location
- host_mac
- host_type
- host_hwvendor
- host_hwver
- host_osfamily
- host_osname
- host_osver
- host_name

### Threat Information

- threat_action
- threat_name
- threat_severity
- threat_type
- threat_pattern
- threat_id
- threat_ref

### Additional Event Information

- event_profile
- event_message
- epid
- euid
- adom_oid


# ============================================================
# IMPORTANT DATASET CHARACTERISTICS
# ============================================================

The current dataset contains both:

1. normal network traffic information
2. security/threat-related information

Many fields may be empty depending on the event type.

For example:

Traffic events may contain:

- source
- destination
- port
- protocol
- packets
- bytes
- session duration

while threat-specific fields may only appear for certain
security events.

Missing values must NOT automatically be treated as corrupted
data.

The meaning of missing data depends on the event type.


# ============================================================
# SAFE / SANITIZED IDENTIFIER HANDLING
# ============================================================

The current dataset contains sanitized or tokenized-looking
identifiers such as:

SRCIP_xxxxxxxxxxxx
DSTIP_xxxxxxxxxxxx
HOSTIP_xxxxxxxxxxxx
SRCMAC_xxxxxxxxxxxx
DSTMAC_xxxxxxxxxxxx
DEVICE_xxxxxxxxxxxx
LOG_xxxxxxxxxxxx

Treat these values as opaque identifiers.

Do NOT assume that a field named src_ip or dst_ip always
contains a literal IPv4 or IPv6 address.

For this dataset:

SRCIP_xxx

may be a valid source identifier even though it is not a
standard textual IP address.

Therefore:

Do NOT reject records simply because sanitized identifiers do
not match standard IP-address syntax.

Validation must distinguish between:

- semantic field presence
- dataset identifier format
- literal real-world network format


# ============================================================
# TIME FIELD HANDLING
# ============================================================

The dataset contains fields such as:

- itime
- data_timestamp

Do not assume the exact meaning or units of a timestamp field
without inspecting the data and documenting the interpretation.

If a timestamp appears to be Unix epoch time:

1. verify the assumption
2. convert it explicitly
3. preserve the original value
4. document the conversion

Never overwrite the original timestamp value.


# ============================================================
# NETWORK PROTOCOL HANDLING
# ============================================================

The dataset includes net_proto.

Protocol values may appear as numeric identifiers such as:

6
17
1

Do not blindly replace or reinterpret original values.

If mapping them to protocol names:

6  → TCP
17 → UDP
1  → ICMP

preserve the original value and create a derived representation.

Example:

net_proto_raw = 6
protocol_name = TCP


# ============================================================
# DATA IMMUTABILITY
# ============================================================

Raw security data is evidence.

Files inside:

data/raw/

must be treated as immutable.

Never:

- overwrite raw logs
- clean raw logs in-place
- normalize raw logs in-place
- delete records silently
- change labels silently

Preferred flow:

data/raw/
    ↓
read
    ↓
validate
    ↓
normalize / transform
    ↓
data/processed/

Raw data must remain available for audit and comparison.


# ============================================================
# DATA SAFETY
# ============================================================

Only use:

- sanitized logs
- synthetic logs
- public datasets
- explicitly approved data

for GitHub portfolio content.

Never commit:

- passwords
- credentials
- API keys
- access tokens
- private keys
- real confidential logs
- sensitive personal information
- internal secrets

If future data contains sensitive information:

keep it outside Git tracking.

Create a sanitized example dataset for the repository.


# ============================================================
# MULTI-SOURCE LOG ARCHITECTURE
# ============================================================

This project must NOT be permanently coupled to FortiGate.

FortiGate is only the first supported log source.

Future sources may include:

- Windows Event Logs
- Linux authentication logs
- DNS logs
- firewall logs
- IDS / IPS logs
- endpoint logs
- VPN logs
- proxy logs
- cloud security logs
- EDR logs
- NetFlow
- SIEM exports

Different log sources may use different:

- field names
- formats
- timestamps
- schemas
- severity systems
- event types

Source-specific differences must be handled by parsers or
adapters.


# ============================================================
# SOURCE-SPECIFIC PARSER PRINCIPLE
# ============================================================

Preferred future architecture:

Raw Source Log
      ↓
Source Parser
      ↓
Validation
      ↓
Normalized Security Event
      ↓
Analysis / Detection

Example:

FortiGate CSV
      ↓
FortiGate Parser
      ↓
Normalized Event

Windows Event Log
      ↓
Windows Parser
      ↓
Normalized Event

DNS Log
      ↓
DNS Parser
      ↓
Normalized Event


# ============================================================
# NORMALIZED SECURITY EVENT
# ============================================================

The project should gradually develop a common internal schema.

Do NOT attempt to normalize every field immediately.

The initial common schema may eventually contain concepts such as:

event_time
source_type
source_device
event_type
action
severity

source_identifier
source_ip
source_port

destination_identifier
destination_ip
destination_port

protocol
application

bytes_sent
bytes_received
packets_sent
packets_received
session_duration

host_identifier

threat_type
threat_name
threat_severity

raw_event_id

Not every source will provide every field.

Missing source-specific fields are acceptable.


# ============================================================
# SOURCE-SPECIFIC FIELDS
# ============================================================

Do not discard fields merely because they do not exist in the
common schema.

Source-specific values should be preserved.

Future designs may maintain:

normalized_fields

plus:

source_specific_fields

or:

raw_record

This ensures normalization does not destroy evidence.


# ============================================================
# SCHEMA EVOLUTION
# ============================================================

The common schema is expected to evolve.

Do not design it as if the current FortiGate fields are the
final universal schema.

When adding a new log source:

1. inspect the source
2. identify its semantics
3. map common concepts
4. preserve source-specific fields
5. update the schema only when justified
6. avoid breaking existing parsers


# ============================================================
# CURRENT PROJECT STRUCTURE
# ============================================================

Current repository:

security-log-intelligence/
│
├── data/
│   ├── raw/
│   └── processed/
│
├── docs/
│
├── src/
│
├── tests/
│
├── .gitignore
├── AGENTS.md
├── README.md
└── requirements.txt


# ============================================================
# FUTURE STRUCTURE GUIDANCE
# ============================================================

Do not create all future folders immediately.

When multiple log formats actually exist, a structure such as
this may become useful:

src/
├── ingestion/
├── parsers/
├── validation/
├── normalization/
├── detection/
└── analysis/

Possible parser files could eventually include:

parsers/
├── fortigate.py
├── windows.py
├── linux_auth.py
└── dns.py

Only create these abstractions when they are needed.

Do not over-engineer Stage 1.


# ============================================================
# CURRENT SCOPE
# ============================================================

At Stage 1, focus only on:

- Python 3.12
- CSV
- FortiGate dataset exploration
- field inspection
- data types
- missing values
- unique values
- frequency distributions
- basic validation
- simple summaries
- pytest where logic exists

Do not introduce advanced infrastructure yet.


# ============================================================
# CURRENT OUT-OF-SCOPE TECHNOLOGIES
# ============================================================

Do NOT introduce yet unless explicitly requested:

- PostgreSQL
- MySQL
- MongoDB
- Redis
- Elasticsearch
- OpenSearch
- Kafka
- RabbitMQ
- FastAPI
- Flask
- Django
- React
- Next.js
- Docker
- Kubernetes
- Machine Learning
- Deep Learning
- LLM
- RAG
- Vector Database
- Cloud Deployment
- Microservices

The project should earn complexity gradually.


# ============================================================
# STAGE 1 QUESTIONS
# ============================================================

Before implementing detection, the project should be able to
answer questions such as:

What columns exist?

What does each important column represent?

Which columns contain missing values?

Which fields are categorical?

Which fields are numerical?

Which fields identify sessions?

Which fields identify hosts?

Which fields identify source and destination activity?

What values exist in event_action?

What values exist in event_severity?

What values exist in event_type?

What applications or services appear?

What protocols appear?

Which fields are threat-related?

How often are threat fields populated?

Are there duplicated records?

Are there malformed records?

Are there impossible or suspicious values?

Do not assume answers before measuring the dataset.


# ============================================================
# DATA PROFILING
# ============================================================

Data profiling should be one of the first real implementations.

A basic profile may report:

row count

column count

column names

data types

missing value count

missing value percentage

unique value count

top categorical values

numeric minimum

numeric maximum

numeric median

numeric distribution where useful

duplicate count

Do not generate fake statistics.

All reported numbers must come from actual data.


# ============================================================
# DATA TYPE RULES
# ============================================================

Do not trust automatically inferred data types blindly.

Security datasets commonly contain mixed types.

A field may contain:

numbers
+
empty values
+
strings

Inspect the data before enforcing a type.

Conversion failures must be detectable.

Do not silently coerce invalid security data into valid-looking
values.


# ============================================================
# MISSING VALUE POLICY
# ============================================================

Missing values require context.

Do NOT automatically:

- fill every missing value with zero
- fill every missing string with "unknown"
- delete every row containing a missing value

Instead determine:

Is the field required for this event type?

Is the field optional?

Does the field only apply to threat events?

Does the source not provide this field?

Is the value genuinely malformed?

Cleaning decisions must be documented.


# ============================================================
# DUPLICATE POLICY
# ============================================================

Do not delete duplicate-looking events automatically.

Security systems can legitimately generate repeated events.

Before treating events as duplicates, consider:

- timestamp
- loguid
- session ID
- source
- destination
- action
- event type

Exact duplicate detection and semantic duplicate detection are
different concepts.


# ============================================================
# SECURITY ANALYSIS PRINCIPLES
# ============================================================

An anomaly is not automatically an attack.

A deny event is not automatically an attack.

A high-byte session is not automatically malicious.

A rare destination is not automatically malicious.

A threat field is evidence from the source system but should
still be interpreted in context.

Use language such as:

- unusual
- anomalous
- suspicious
- potential security event
- requires investigation

unless there is sufficient evidence for a stronger conclusion.


# ============================================================
# RULE-BASED DETECTION
# ============================================================

Rule-based detection should be implemented before machine
learning.

Possible future examples using this dataset include:

- unusually high traffic volume
- unusually long sessions
- repeated denied connections
- repeated activity from the same source
- unusual destination ports
- unusual application services
- unexpected protocol behavior
- suspicious event sequences

These are examples only.

Do NOT implement them until the data distribution and false
positive risks are understood.


# ============================================================
# DETECTION REQUIREMENTS
# ============================================================

Every future detection rule must document:

Detection name

Purpose

Required fields

Trigger condition

Evidence

Potential false positives

Severity reasoning

Limitations

Do not create unexplained magic thresholds.


# ============================================================
# MACHINE LEARNING POLICY
# ============================================================

Machine Learning is not part of Stage 1.

Before ML:

1. understand the raw data
2. validate the dataset
3. establish rule-based baselines
4. define the problem
5. identify labels or lack of labels
6. check class imbalance
7. check leakage risks

When ML is introduced, possible approaches may include:

- supervised classification
- anomaly detection
- clustering
- behavioral modeling

Choose the method based on the data and objective.

Do not choose a model because it sounds advanced.


# ============================================================
# ML EVALUATION
# ============================================================

Never rely only on accuracy.

Future metrics may include:

- precision
- recall
- F1
- PR-AUC
- false positive rate
- false negative rate
- detection rate
- alert volume

Use time-aware evaluation when event chronology matters.

Prevent:

- temporal leakage
- duplicate leakage
- feature leakage
- label leakage


# ============================================================
# CLASS IMBALANCE
# ============================================================

Security datasets may contain very few positive threat events
relative to normal traffic.

Do not assume a balanced dataset.

Always inspect class distribution before supervised learning.

Accuracy can be misleading when one class dominates.


# ============================================================
# EXPLAINABILITY
# ============================================================

Future AI detection should provide reasons.

Instead of only:

Anomaly Score = 0.91

prefer explanations such as:

- unusual session duration
- unusually high bytes sent
- rare destination
- unusual service
- repeated denied events

Explanation must be derived from real evidence.


# ============================================================
# LLM POLICY
# ============================================================

LLMs are not detection engines by default.

When introduced later, preferred architecture is:

Logs
    ↓
Parsing
    ↓
Detection
    ↓
Evidence
    ↓
Incident
    ↓
LLM Explanation

LLMs may assist with:

- incident summaries
- timeline summaries
- explanation
- analyst support
- documentation

LLMs must not invent evidence.


# ============================================================
# EVALUATION INTEGRITY
# ============================================================

Never fabricate:

- accuracy
- precision
- recall
- F1
- detection rate
- alert reduction
- anomaly scores
- processing speed
- dataset statistics
- benchmark results

All reported results must come from executed analysis or
experiments.

If something has not been measured, label it clearly as:

- planned
- hypothetical
- expected
- not yet evaluated


# ============================================================
# PYTHON RULES
# ============================================================

Use Python 3.12.

Prefer:

- readable code
- descriptive names
- small functions
- explicit validation
- type hints where useful
- standard library when sufficient

Avoid:

- unnecessary abstractions
- premature optimization
- clever one-liners that reduce readability
- unnecessary inheritance
- unnecessary design patterns


# ============================================================
# DEPENDENCY POLICY
# ============================================================

Before adding a Python dependency:

1. explain what it provides
2. explain why it is useful now
3. confirm that it belongs to the current stage
4. add it to requirements.txt
5. test the project afterward

Do not install large libraries without a clear need.


# ============================================================
# TESTING POLICY
# ============================================================

Use pytest for important logic.

Tests should eventually cover:

- valid input
- missing columns
- malformed records
- optional fields
- mixed data types
- timestamp handling
- identifier handling
- numeric conversion
- detection thresholds
- edge cases

Never modify expected results simply to make broken code pass.


# ============================================================
# CODEX WORKFLOW
# ============================================================

For non-trivial tasks:

1. Read AGENTS.md.
2. Inspect relevant repository files.
3. Understand the current stage.
4. Inspect the current data when necessary.
5. Identify the smallest useful change.
6. Explain the plan briefly.
7. Implement only the approved scope.
8. Run relevant tests.
9. Inspect results.
10. Report changed files.
11. Report limitations.
12. Suggest the smallest next step.

Do not automatically implement the suggested next step.


# ============================================================
# PLAN-FIRST RULE
# ============================================================

Before:

- adding a framework
- introducing a major dependency
- changing schema
- reorganizing directories
- modifying many files
- advancing a project stage

explain:

what will change

why

files affected

risks

simpler alternatives

Then wait for approval when appropriate.


# ============================================================
# MINIMUM CHANGE PRINCIPLE
# ============================================================

Prefer the smallest correct change.

Do not modify unrelated working code.

Do not refactor simply because another structure looks cleaner.

Do not expand scope without explicit reason.


# ============================================================
# DEVELOPMENT ENVIRONMENT
# ============================================================

The user's main local development environment is:

Windows

VS Code

PowerShell

Python 3.12

Virtual Environment:

.venv

When providing commands intended for the user's local machine,
prefer PowerShell-compatible commands.

Do not assume remote or automated environments are Windows.

Inspect the environment before using platform-specific commands.


# ============================================================
# GIT POLICY
# ============================================================

Git history should show meaningful project development.

Prefer small meaningful commits.

Examples:

Initialize project structure

Add FortiGate log profiling

Add schema validation

Add event summary

Add protocol mapping

Add first detection rule

Do NOT automatically commit or push unless explicitly asked.

Before a commit:

- run relevant tests
- review changed files
- ensure no secrets are included
- ensure raw sensitive data is not included


# ============================================================
# DOCUMENTATION
# ============================================================

README.md is for humans.

AGENTS.md is for Codex project instructions.

docs/ is for detailed technical documentation.

Future useful documents may include:

docs/data-dictionary.md
docs/normalized-schema.md
docs/detection-rules.md
docs/architecture.md
docs/evaluation.md
docs/decisions.md

Create documentation only when it becomes useful.


# ============================================================
# PORTFOLIO INTEGRITY
# ============================================================

This project is intended to become a strong portfolio project.

Prioritize:

correctness

understanding

reproducibility

testing

real measurements

clear architecture

honest limitations

over unnecessary technological complexity.

The project should demonstrate that the developer can build and
deploy systems, not only train models.


# ============================================================
# COMMUNICATION STYLE
# ============================================================

The developer is learning.

When introducing something important, explain:

WHAT
What is it?

WHY
Why is it needed?

WHERE
Where does it belong in this project?

HOW
How does the implementation work?

Use simple language first.

Introduce advanced terminology only when useful.


# ============================================================
# PROHIBITED BEHAVIOR
# ============================================================

Do not:

- overwrite raw logs
- silently remove records
- fabricate statistics
- fabricate security evidence
- fabricate AI performance
- treat every anomaly as an attack
- assume every missing value is invalid
- assume sanitized identifiers are literal IP addresses
- hardcode the whole project to one FortiGate CSV
- add unnecessary dependencies
- introduce ML before understanding the data
- introduce LLM before detection/evidence exists
- skip important tests
- expose credentials
- automatically commit
- automatically push
- automatically advance project stages


# ============================================================
# CURRENT IMMEDIATE PRIORITY
# ============================================================

The immediate goal is NOT attack detection.

The immediate goal is:

network_log_SAFE.csv
        ↓
Load safely
        ↓
Inspect schema
        ↓
Profile data
        ↓
Understand fields
        ↓
Measure missing values
        ↓
Inspect event categories
        ↓
Inspect network/session fields
        ↓
Inspect threat fields
        ↓
Document findings

Only after this stage is understood should detection logic be
introduced.


# ============================================================
# COMPLETION REPORT FORMAT
# ============================================================

After completing a coding task, report:

## Changed

Files created or modified.

## What It Does

Short explanation.

## Data Assumptions

Any assumptions made about the dataset.

## Validation

Tests or commands executed.

## Results

Measured results only.

## Limitations

What is not yet handled.

## Suggested Next Step

Only the smallest logical next improvement.

Do not automatically implement it.