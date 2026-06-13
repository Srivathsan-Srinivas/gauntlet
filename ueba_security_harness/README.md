# UEBA Security Harness

A runnable mini-project for synthetic Salesforce-style UEBA detection plus a governing multi-agent security harness.

The project starts with a PyTorch UEBA anomaly detector and then wraps it with a production-style harness that adds declared guardrails, checkpoint persistence, named alarms, human-in-the-loop escalation, and two downstream security agents: a Threat-Hunting Agent and a Security Compliance Agent.

The original UEBA model code remains in `src/ueba_model.py` and is intentionally left unchanged.

---

## What this project does

The full pipeline is:

```text
Synthetic Salesforce logs
-> PyTorch UEBA model
-> scored UEBA CSV
-> harness guardrails
-> UEBA Agent
-> Threat-Hunting Agent
-> Security Compliance Agent
-> checkpoint persistence
-> named structured alarms
-> human-review package
-> final report
```

The project is designed for the 24-hour harness challenge. The worker agents focus on security analysis, while the harness owns constraints, checkpoints, material handling, alarms, persistence, and human escalation.

---

## Project structure

```text
ueba_security_harness/
  Makefile
  README.md
  HARNESS.md
  requirements.txt

  Dockerfile
  docker-compose.yml
  render.yaml

  config/
    declared_rules.json

  data/
    salesforce_ueba_train.csv
    salesforce_ueba_test.csv

  deployment/
    PRODUCTION.md

  models/
    ueba_autoencoder.pt
    preprocessor.pkl
    threshold.json

  outputs/
    scored_salesforce_ueba_test.csv
    harness_findings.csv
    harness_alarms.json
    human_review_package.json
    harness_final_report.json

  runs/
    <run_id>/
      checkpoint and material artifacts

  scripts/
    start_api.sh

  src/
    synthesize_salesforce_logs.py
    ueba_model.py
    harness_runner.py

    api/
      app.py

    harness/
      agents.py
      alarms.py
      checkpoints.py
      guardrails.py
      human_review.py
      material.py

  tests/
    smoke_test.py
```

---

## Agents

### 1. UEBA Agent

The UEBA Agent consumes scored events from the PyTorch model and summarizes abnormal user/entity behavior.

It looks for unusual behavior such as:

- abnormal login country
- unfamiliar source IP
- rare operating system or device
- unusual login time
- excessive query activity
- suspicious admin activity
- high model interestingness score

### 2. Threat-Hunting Agent

The Threat-Hunting Agent takes UEBA findings and forms a lightweight hunt hypothesis.

Example outcomes:

- possible credential compromise
- possible admin misuse
- possible data discovery
- suspicious access from unusual location
- insufficient evidence

The agent is not allowed to claim confirmed compromise unless the evidence supports it.

### 3. Security Compliance Agent

The Security Compliance Agent checks whether a finding maps to a declared security-control concern.

Example control areas:

- privileged access review
- unusual access monitoring
- data access governance
- authentication monitoring
- incident review required

The compliance agent can mark a finding as:

```text
compliant
non_compliant
needs_review
insufficient_evidence
```

It cannot approve exceptions or close incidents autonomously.

---

## Harness components

### 1. Guardrails

Guardrails live in:

```text
config/declared_rules.json
```

They define things such as:

- high-risk score thresholds
- fields that should be redacted
- human-review triggers
- agent permission boundaries
- suspicious behavior categories

The harness applies these guardrails before and after the agents run.

### 2. Checkpoints

Checkpoints live in:

```text
src/harness/checkpoints.py
```

Checkpoint examples:

- input quality checkpoint
- UEBA output checkpoint
- threat-hunting checkpoint
- compliance checkpoint
- cross-agent consistency checkpoint
- human-escalation checkpoint

Each checkpoint has explicit pass/fail criteria and writes its result to `runs/<run_id>/`.

### 3. Material handling

Material handling lives in:

```text
src/harness/material.py
```

The material layer controls:

- loading scored CSVs
- creating evidence bundles
- redacting sensitive fields
- writing outputs
- saving checkpoint artifacts
- creating run directories

Agents do not receive uncontrolled raw material directly. They receive harness-prepared evidence bundles.

### 4. Alarms

Alarms live in:

```text
src/harness/alarms.py
```

Alarms are structured JSON with:

```json
{
  "alarm_type": "POSSIBLE_PRIVILEGED_ACCOUNT_COMPROMISE",
  "severity": "critical",
  "context": {},
  "recommended_action": "Stop autonomous finalization and send to human review."
}
```

Example alarm types:

```text
UEBA_HIGH_RISK_BEHAVIOR
POSSIBLE_PRIVILEGED_ACCOUNT_COMPROMISE
THREAT_HYPOTHESIS_HIGH_CONFIDENCE
COMPLIANCE_VIOLATION
CROSS_AGENT_DISAGREEMENT
CHECKPOINT_FAILED
HUMAN_REVIEW_REQUIRED
AGENT_POLICY_VIOLATION
```

---

## Human-in-the-loop escalation

Human review is required when:

- UEBA risk is high
- a privileged/admin user is involved
- a high-severity alarm is raised
- the compliance agent identifies a control violation
- threat-hunting confidence is high
- cross-agent disagreement occurs
- checkpoints repeatedly fail
- evidence is insufficient for safe autonomous completion

The human-review package is written to:

```text
outputs/human_review_package.json
```

and also persisted inside:

```text
runs/<run_id>/12_human_review_package.json
```

A review item includes:

```json
{
  "review_id": "review_001",
  "run_id": "run_001",
  "reason": "POSSIBLE_PRIVILEGED_ACCOUNT_COMPROMISE",
  "severity": "critical",
  "summary": "UEBA detected high-risk login behavior and sensitive access.",
  "recommended_human_actions": [
    "Review authentication logs",
    "Validate travel or VPN context",
    "Check endpoint telemetry",
    "Decide whether containment is required"
  ]
}
```

---

## Quickstart

From the project root:

```bash
make setup
make test
```

This creates a virtual environment, installs dependencies, generates data, trains the model, scores test events, runs the harness, and runs a smoke test.

---

## Run the full pipeline

```bash
make run
```

This executes:

```text
data -> train -> score -> harness
```

Important outputs:

```text
outputs/scored_salesforce_ueba_test.csv
outputs/harness_findings.csv
outputs/harness_alarms.json
outputs/human_review_package.json
outputs/harness_final_report.json
runs/<run_id>/
```

---

## Run only the harness

Use this after a scored CSV already exists:

```bash
make harness
```

Or run directly:

```bash
python src/harness_runner.py \
  --scored-csv outputs/scored_salesforce_ueba_test.csv \
  --rules config/declared_rules.json \
  --runs-dir runs \
  --outputs-dir outputs
```

---

## Original UEBA model outputs

The model writes:

```text
outputs/scored_salesforce_ueba_test.csv
```

with added columns:

```text
reconstruction_error
interestingness_score
reasons
is_interesting
```

The `reasons` column is JSON. Example:

```json
{
  "unusual_country": {
    "value": "RU",
    "normal_values": ["US"]
  },
  "unusual_os": {
    "value": "Linux",
    "normal_values": ["Windows", "macOS"]
  }
}
```

---

## Harness outputs

The harness writes:

```text
outputs/harness_findings.csv
outputs/harness_alarms.json
outputs/human_review_package.json
outputs/harness_final_report.json
```

### `harness_findings.csv`

One row per interesting event with UEBA, threat-hunting, and compliance summaries.

### `harness_alarms.json`

Structured named alarms with severity, context, and recommended action.

### `human_review_package.json`

A queue of findings that require analyst review.

### `harness_final_report.json`

Full run state, including checkpoint status, alarms, output paths, and final status.

---

## API deployment

This repository includes a Dockerized FastAPI wrapper around the existing UEBA model and harness.

The API exposes:

```text
GET  /healthz
GET  /readyz
POST /v1/runs
GET  /v1/runs/{run_id}/final_report
GET  /v1/runs/{run_id}/alarms
GET  /v1/runs/{run_id}/human_review_package
GET  /v1/runs/{run_id}/findings.csv
```

Run locally without Docker:

```bash
make setup
make run
make api
```

Health check:

```bash
curl http://localhost:10000/healthz
```

Run a harness job through the API:

```bash
curl -X POST \
  -F "file=@data/salesforce_ueba_test.csv" \
  http://localhost:10000/v1/runs
```

The API returns paths to:

```text
final_report
findings_csv
alarms
human_review_package
```

---

## Docker

Build and run:

```bash
make docker-build
make docker-run
```

Or directly:

```bash
docker build -t ueba-security-harness:latest .

docker run --rm -p 10000:10000 \
  -v "$(pwd)/outputs:/app/outputs" \
  -v "$(pwd)/runs:/app/runs" \
  ueba-security-harness:latest
```

Then test:

```bash
curl http://localhost:10000/healthz
```

---

## Render deployment

A Render Blueprint is included:

```text
render.yaml
```

Recommended Render deployment path:

1. Push this repo to GitHub.
2. In Render, create a new Blueprint from the repo, or create a Docker Web Service manually.
3. Use `render.yaml` if deploying as a Blueprint.
4. Set the health check path to `/healthz`.
5. Use a paid instance with a persistent disk for real runs because normal service filesystem changes are ephemeral.

The Docker web service starts:

```bash
uvicorn src.api.app:app --host 0.0.0.0 --port $PORT
```

The default `PORT` used locally is:

```text
10000
```

---

## Scaling plan

### Stage 1: Demo / prototype

```text
Client
-> FastAPI Docker service
-> UEBA model
-> harness
-> JSON/CSV artifacts
```

Characteristics:

- one Docker web service
- model artifacts baked into the image
- run artifacts written to local disk
- good for demos and small experiments

### Stage 2: Internal pilot

```text
Client
-> API service
-> background worker
-> object storage
-> Postgres metadata store
-> analyst review process
```

Recommended changes:

- split API and long-running scoring into separate worker process
- store uploaded CSVs and reports in object storage
- store run/checkpoint/alarm metadata in Postgres
- add authentication in front of the API
- add upload-size limits and schema validation

### Stage 3: Production SOC workflow

```text
Client
-> API replicas
-> queue
-> worker pool
-> immutable artifact storage
-> Postgres audit trail
-> human review UI
```

Recommended production components:

- API service for run creation and status lookup
- worker pool for UEBA scoring and harness execution
- queue such as Redis/RQ, Celery, SQS, or equivalent
- object storage for raw input, redacted material, scored CSVs, reports, and alarms
- Postgres for run metadata, checkpoint metadata, human decisions, and audit trail
- analyst review UI for human-in-the-loop decisions
- role-based access control
- retention policies
- monitoring and alerting

---

## Security hardening checklist

Before using this beyond a demo:

- Require authentication for `/v1/runs`.
- Enforce upload size limits.
- Validate CSV schema before scoring.
- Never return raw sensitive logs by default.
- Redact IPs, user agents, session IDs, and employee identifiers where possible.
- Store raw uploads separately from redacted evidence bundles.
- Encrypt artifact storage.
- Add retention policies for logs and reports.
- Add audit logs for all human review decisions.
- Add human approval before containment or remediation actions.
- Move long-running work out of the web request path.

---

## Makefile targets

```text
make setup         Create virtual environment and install dependencies
make data          Generate synthetic Salesforce UEBA train/test logs
make train         Train the PyTorch UEBA autoencoder
make score         Score the test CSV
make harness       Run the harness over the scored CSV
make run           Run data -> train -> score -> harness
make test          Run full pipeline and smoke test
make api           Start FastAPI locally
make docker-build  Build Docker image
make docker-run    Run Docker image locally
make clean         Remove generated artifacts
```

---

## Expected demo result

A typical run produces a final report similar to:

```json
{
  "status": "blocked_pending_human_review",
  "interesting_events": 29,
  "alarms": 86,
  "human_review_items": 28
}
```

This is expected: the synthetic test data includes malicious or abnormal behavior so the harness should generate alarms and require human review.

---

## Notes

This is a prototype/demo implementation, not a production SOC system. It is intentionally small enough to understand and demo, while still showing the required harness concepts:

- guardrails separate from agents
- checkpoints separate from agents
- material handling separate from agents
- alarms separate from agents
- human escalation path
- persisted run artifacts
- swappable agent interface
- API and Docker deployment path
