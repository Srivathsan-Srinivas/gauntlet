# Human-Governed UEBA Security Harness

## Overview

This project implements a harness around a UEBA detection workflow for synthetic Salesforce audit logs. The worker model in `src/ueba_model.py` is intentionally unchanged. The harness consumes its scored CSV output and governs three security agents:

1. UEBA Agent
2. Threat-Hunting Agent
3. Security Compliance Agent

The agents focus on analysis. The harness focuses on constraints, checkpoints, material handling, alarms, and human-in-the-loop escalation.

## Architecture

```text
config/
  declared_rules.json

src/
  synthesize_salesforce_logs.py
  ueba_model.py
  harness_runner.py
  harness/
    agents.py
    alarms.py
    checkpoints.py
    guardrails.py
    human_review.py
    material.py

runs/
  run_<timestamp>/
    00_raw_input_summary.json
    02_input_guardrails.json
    03_redacted_scored_input.csv
    04_evidence_bundle.json
    05_ueba_agent_output.json
    06_ueba_checkpoint.json
    07_threat_hunting_agent_output.json
    08_threat_hunt_checkpoint.json
    09_security_compliance_agent_output.json
    10_compliance_checkpoint.json
    11_cross_agent_consistency_checkpoint.json
    12_human_review_package.json
    13_human_escalation_checkpoint.json
    14_final_report.json
```

## Worker Agents

### UEBA Agent

Consumes interesting events from the scored model output and produces structured UEBA findings.

Output includes:

- `event_id`
- `user_id`
- `persona`
- `finding_type`
- `risk_score`
- `evidence`
- `recommended_action`

### Threat-Hunting Agent

Consumes UEBA findings and maps them to threat hypotheses.

Output includes:

- `hypothesis`
- `attack_stage`
- `confidence`
- `evidence`
- `recommended_action`

### Security Compliance Agent

Consumes threat-hunting results and evaluates policy/control impact.

Output includes:

- `control_id`
- `control_description`
- `status`
- `evidence`
- `recommended_action`

## Pillar 1: Declared Guardrails

Guardrails are declared in `config/declared_rules.json`, not hidden inside agent prompts.

The config defines:

- required input columns
- sensitive fields
- allowed agent actions
- blocked agent actions
- risk thresholds
- weak TLS versions
- suspicious domains
- human-review triggers
- compliance controls

The harness enforces guardrails before and after agent execution.

Examples:

```json
{
  "blocked_agent_actions": [
    "disable_account",
    "delete_logs",
    "change_permissions",
    "approve_exception",
    "close_incident",
    "claim_confirmed_breach_without_evidence"
  ],
  "weak_tls_versions": ["TLS1.0", "TLS1.1"],
  "suspicious_domains": ["evil-connected-app.example"]
}
```

## Pillar 2: Checkpoints

Each checkpoint has explicit pass/fail criteria and persists its result to `runs/<run_id>/`.

### Input Quality Checkpoint

Pass criteria:

- required columns are present
- core fields are not empty
- row count is greater than zero

### UEBA Checkpoint

Pass criteria:

- each finding has `event_id`, `risk_score`, and `evidence`
- risk score is between 0 and 100
- evidence is a list

### Threat-Hunting Checkpoint

Pass criteria:

- confidence is one of `low`, `medium`, or `high`
- hypotheses are not stated as confirmed breaches
- no autonomous remediation is recommended

### Compliance Checkpoint

Pass criteria:

- status is one of `compliant`, `non_compliant`, `needs_review`, or `insufficient_evidence`
- control ID is present
- non-compliance has evidence

### Cross-Agent Consistency Checkpoint

Pass criteria:

- high UEBA risk is not silently downgraded by other agents
- agent disagreements are surfaced

### Human Escalation Checkpoint

Pass criteria:

- high or critical alarms create a human-review package
- review package has items when review is required

## Pillar 3: Material Handling

The harness controls material passed between components.

Flow:

```text
Scored CSV
-> input quality checkpoint
-> input guardrails
-> redacted scored input
-> evidence bundle
-> UEBA Agent
-> Threat-Hunting Agent
-> Compliance Agent
-> human review package
-> final report
```

The evidence bundle contains only the interesting events selected from the model score threshold. It also includes redacted IP and user-agent fields.

## Pillar 4: Structured Alarms

Alarms are structured JSON with:

- `alarm_type`
- `severity`
- `context`
- `recommended_action`
- `created_at`

Example:

```json
{
  "alarm_type": "ANOMALOUS_ADMIN_ACTION",
  "severity": "critical",
  "context": {
    "event_id": "evt_test_01234",
    "user_id": "u_admin_005",
    "persona": "salesforce_admin",
    "score": 96.2
  },
  "recommended_action": "Privileged activity in anomalous context requires immediate analyst review."
}
```

Alarm types include:

- `UEBA_HIGH_RISK_BEHAVIOR`
- `UEBA_CRITICAL_RISK_BEHAVIOR`
- `FOREIGN_COUNTRY_LOGIN_OR_ACCESS`
- `WEAK_TLS_USED`
- `SUSPICIOUS_CONNECTED_APP`
- `LARGE_DATA_EXPORT_OR_ACCESS`
- `ANOMALOUS_ADMIN_ACTION`
- `COMPLIANCE_VIOLATION`
- `AGENT_POLICY_VIOLATION`
- `CROSS_AGENT_DISAGREEMENT`

## Human-in-the-Loop Escalation

The harness creates a human-review package when:

- UEBA score is high or critical
- threat-hunting confidence is high
- compliance status is `non_compliant`
- high or critical alarms are present
- a checkpoint fails

The package includes:

- review ID
- event ID
- user/persona
- reason for escalation
- severity
- UEBA finding
- threat-hunting result
- compliance result
- recommended human actions
- allowed reviewer decisions

Allowed reviewer decisions:

- `approve_final_report`
- `request_more_evidence`
- `send_back_to_agent`
- `escalate_incident`
- `dismiss_false_positive`

## How the Harness Changes Agent Behavior

The harness prevents agents from autonomously recommending blocked actions such as disabling accounts, deleting logs, approving exceptions, or closing incidents. If an agent output contains a blocked action, the output guardrail emits `AGENT_POLICY_VIOLATION`, rewrites the recommendation to human escalation, and prevents autonomous closure.

Checkpoint failures are persisted and surfaced as alarms. In a fuller deployment, these checkpoint results would be sent back to the relevant agent for revision. In this starter implementation, the harness demonstrates the governance path and blocks unsafe finalization through human review.

## Persistence and Replay

Every run writes material and checkpoint output under `runs/<run_id>/`. This supports replay from a checkpoint without rerunning previous stages.

## Running

```bash
make setup
make test
```

or:

```bash
make run
```

Important outputs:

```text
outputs/scored_salesforce_ueba_test.csv
outputs/harness_findings.csv
outputs/harness_alarms.json
outputs/human_review_package.json
outputs/harness_final_report.json
```

## Notes and Limitations

This is a small challenge-ready harness, not a production SOC system. The Threat-Hunting and Compliance agents are deterministic Python workers so the project can run locally and reproducibly. They use the same agent interface pattern that an LLM-backed worker could use later.

## Production wrapper

The deployable version adds a thin API layer in `src/api/app.py`. This wrapper does not change the UEBA model code. It accepts a CSV upload, calls the existing scorer, runs `harness_runner.py`, and returns links to persisted artifacts.

Production entrypoint:

```bash
./scripts/start_api.sh
```

Docker and Render files:

```text
Dockerfile
docker-compose.yml
render.yaml
deployment/PRODUCTION.md
```
