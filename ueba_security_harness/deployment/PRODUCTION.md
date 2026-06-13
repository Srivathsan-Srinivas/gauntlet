# Production Deployment Guide

This project now ships with a Dockerized FastAPI wrapper around the existing UEBA model and harness.
The original `src/ueba_model.py` remains unchanged.

## Local Docker run

```bash
make docker-build
make docker-run
```

Health check:

```bash
curl http://localhost:10000/healthz
```

Run the harness through the API:

```bash
curl -X POST \
  -F "file=@data/salesforce_ueba_test.csv" \
  http://localhost:10000/v1/runs
```

The API returns links to the final report, alarms, findings CSV, and human-review package.

## Render deployment

1. Push this repo to GitHub.
2. In Render, create a new Blueprint from the repo or create a Docker Web Service manually.
3. Use `render.yaml` if deploying as a Blueprint.
4. Set the health check path to `/healthz`.
5. Use a paid instance with a persistent disk for real runs because local filesystem changes outside the disk are ephemeral.

The Docker web service exposes `PORT=10000` and starts:

```bash
uvicorn src.api.app:app --host 0.0.0.0 --port $PORT
```

## Production architecture

For demo scale, one web container is enough:

```text
Client -> FastAPI container -> existing UEBA model -> harness -> JSON/CSV artifacts
```

For production scale, split synchronous API traffic from long-running analysis jobs:

```text
Client
  -> API service
  -> queue
  -> worker pool
  -> artifact store / database
  -> analyst review UI
```

Recommended production components:

- API service: receives uploads, validates schema, creates run IDs.
- Worker service: runs scoring and the harness asynchronously.
- Artifact store: S3/GCS/Blob Storage for raw inputs, scored CSVs, reports, alarms, and review packages.
- Database: Postgres for run metadata, checkpoint metadata, review decisions, and audit trails.
- Queue: Redis/RQ, Celery, SQS, or Render worker/Workflow pattern.
- Observability: structured logs, metrics, alarm counts, latency, and error rates.

## Scaling guidance

### Small demo

- One Docker web service.
- Model artifacts baked into image.
- Runs and outputs written to local disk.

### Team/internal pilot

- Web service + background worker.
- Store uploaded CSVs and reports in object storage.
- Store run metadata in Postgres.
- Keep model artifacts in the image or object storage.
- Add auth in front of API.

### Production SOC workflow

- API replicas behind load balancer.
- Worker autoscaling based on queue length.
- Immutable run artifacts in object storage.
- Postgres for checkpoints, alarms, human-review decisions.
- Strict RBAC for analysts.
- Audit log every human decision.
- Batch and streaming ingestion paths.

## Security hardening checklist

- Require authentication for `/v1/runs`.
- Enforce upload size limits.
- Validate CSV schema before scoring.
- Never return raw sensitive logs by default.
- Redact IPs/user agents where possible.
- Store raw uploads separately from redacted evidence bundles.
- Encrypt artifact storage.
- Add retention policies for logs and reports.
- Add human approval before containment/remediation actions.

## API endpoints

- `GET /healthz` basic liveness and model readiness indicator.
- `GET /readyz` strict readiness check; fails if model/rules are missing.
- `POST /v1/runs` upload CSV, score it, and run the full harness.
- `GET /v1/runs/{run_id}/final_report`
- `GET /v1/runs/{run_id}/alarms`
- `GET /v1/runs/{run_id}/human_review_package`
- `GET /v1/runs/{run_id}/findings.csv`
