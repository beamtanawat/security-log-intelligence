# Stage 1.6 Local Read-Only API Validation Findings

## Status

**The corrected repository-supported Stage 1.6F local real-store validator was
executed and returned `FINAL RESULT: PASS`.** It used the existing approved
Stage 1.5 artifacts on `127.0.0.1:8000`, reconciled 43 findings from 25 source
records with 227 evidence entries and two rules, and left the database, finding
JSONL, and summary unchanged with no SQLite sidecars.

The corrected validator enforced fail-closed cross-transport byte-identity
equality for the in-process and real-loopback response hashes. This records
completed Stage 1.6F validation.

## What Stage 1.6 Provides

Stage 1.6 is a small local, read-only HTTP boundary over one configured and
audited Stage 1.5 findings store. Its request flow is:

```text
Local client
  -> 127.0.0.1 launcher
  -> FastAPI request and HTTP-safety boundary
  -> verified Stage 1.5 read-only query interface
  -> canonical stored finding payload
```

The only application routes are:

- `GET /healthz`
- `GET /api/v1/runs/{run_id}/findings`
- `GET /api/v1/runs/{run_id}/findings/{finding_id}`
- `GET /openapi.json`

The list route accepts only `finding_id`, `rule_id`, `rule_version`, `severity`,
`reason_code`, `source_type`, `source_record_number`, `evidence_path`, and
`limit`. Its default limit is 50 and maximum is 500. It has no pagination,
cursor, total-count, export, write, import, raw-event, or aggregate route.

## Local Launch

The supported launcher has explicit database, finding-artifact, summary-artifact,
and expected-run-ID inputs. It binds only to `127.0.0.1`, uses one worker, has
reload and proxy-header trust disabled, and does not support host selection or
port fallback.

```powershell
& .\.venv\Scripts\python.exe .\src\serve_api.py `
  --database .\data\processed\stage_1_5f_detection_store.sqlite3 `
  --findings .\data\processed\stage_1_4f_detection_findings.jsonl `
  --summary .\data\processed\stage_1_4f_detection_summary.json `
  --expected-run-id 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc `
  --port 8000
```

The launcher reuses the existing API lifespan. Before it serves requests, that
lifespan audits the configured Stage 1.5 store, validates the approved finding
and summary artifacts, reconciles the one configured run, and retains only a
bounded readiness snapshot. It never opens the raw CSV or normalized JSONL.

## Final Validation Procedure

Run the following from the repository root in the validated local virtual
environment:

```powershell
.\scripts\validate_stage_1_6.ps1 `
  -Database .\data\processed\stage_1_5f_detection_store.sqlite3 `
  -FindingsInput .\data\processed\stage_1_4f_detection_findings.jsonl `
  -SummaryInput .\data\processed\stage_1_4f_detection_summary.json `
  -ExpectedRunId 5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc `
  -Port 8000
```

The command performs, in order:

1. Python 3.12 and `pip check` verification.
2. Complete unittest and pytest suites before real validation.
3. Git/data safety and whitespace checks.
4. Source-artifact and database audit/reconciliation through public read-only
   Stage 1.5 interfaces.
5. In-process API validation with actual startup audit.
6. Actual launcher validation through owned loopback HTTP requests.
7. Size/SHA-256 and logical-audit comparison before and after validation.
8. Cleanup verification for the owned process, selected port, and SQLite
   sidecars.
9. Complete unittest and pytest suites after real validation.

The validator fails closed if its explicit port is occupied. It does not scan
for a free port, retry another port, bind another interface, terminate an
unrelated process, copy or rebuild the store, or overwrite a previous
validation result. Optional `-SummaryOutput` can publish a new ignored JSON
report under `data/processed/`; it rejects an existing destination.

## Read-Only and HTTP Safety Boundaries

The API validates only the existing Stage 1.5 store and small approved Stage
1.4 artifacts. It does not modify the SQLite database, finding JSONL, summary
envelope, raw CSV, or normalized JSONL. It must leave no SQLite journal, WAL,
or SHM sidecar.

The server is local-only. It allows only `127.0.0.1` and `localhost` Host
headers, rejects all `Origin` headers, ignores forwarded headers, disables
access logging, rejects request targets over 4,096 bytes, and caps serialized
application bodies at 4 MiB. Application JSON is UTF-8, sorted-key, compact,
and deterministic, with `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`.

## Interpretation and Limitations

`RULE MATCH != CONFIRMED ATTACK` remains mandatory. Returned findings are
informational deterministic rule observations with their existing provenance,
uncertainties, and false-positive notes. Stage 1.6 does not establish attack
truth, maliciousness, compromise, incident status, or risk scoring.

Stage 1.6 is not production deployment or internet-facing software. It has no
authentication, authorization, CORS, TLS, reverse proxy configuration,
multi-user operation, dashboard, frontend, Docker, ORM, asynchronous database
driver, ML, LLM, OCSF, correlation, incident response, new log source, or new
detection rule.

## Runtime Evidence

The corrected Stage 1.6F run recorded `FINAL RESULT: PASS` for the owned
loopback host `127.0.0.1` on port 8000, startup audit, health, finding list,
finding detail, OpenAPI, and the required HTTP-safety checks. It recorded 43
findings, 25 unique source records, 227 evidence entries, and two rules. The
database, finding JSONL, and summary were unchanged; SQLite sidecars were
absent. Final regression recorded 176 unittest passes, 176 pytest passes, 109
subtests, and two known non-blocking upstream deprecation warnings.

The corrected validator enforced equality of the complete in-process and
real-loopback SHA-256 response-identity mappings before reporting `PASS`; a
difference fails with `TRANSPORT_RESPONSE_HASH_MISMATCH`.
