#!/usr/bin/env python3
"""Production API wrapper for the UEBA security harness.

This module intentionally does not modify src/ueba_model.py. It shells out to the
existing scorer and harness runner so the model code remains unchanged.
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

APP_ROOT = Path(os.getenv("APP_ROOT", str(Path.cwd()))).resolve()
DATA_DIR = Path(os.getenv("DATA_DIR", APP_ROOT / "data"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", APP_ROOT / "models"))
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", APP_ROOT / "outputs"))
RUNS_DIR = Path(os.getenv("RUNS_DIR", APP_ROOT / "runs"))
RULES_PATH = Path(os.getenv("RULES_PATH", APP_ROOT / "config" / "declared_rules.json"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

for directory in [DATA_DIR, MODEL_DIR, OUTPUTS_DIR, RUNS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="UEBA Security Harness API",
    version="0.1.0",
    description="Scores Salesforce-style audit logs and runs the UEBA, Threat-Hunting, and Compliance harness.",
)


def _run(cmd: list[str], cwd: Path = APP_ROOT) -> None:
    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "command": cmd,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            },
        )


def _require_model() -> None:
    required = [MODEL_DIR / "ueba_autoencoder.pt", MODEL_DIR / "preprocessor.pkl", MODEL_DIR / "threshold.json"]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Model artifacts are missing. Run `make train` before deployment or bake models/ into the image.",
                "missing": missing,
            },
        )


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    model_ready = all((MODEL_DIR / name).exists() for name in ["ueba_autoencoder.pt", "preprocessor.pkl", "threshold.json"])
    return {
        "status": "ok" if model_ready else "degraded",
        "model_ready": model_ready,
        "rules_ready": RULES_PATH.exists(),
    }


@app.get("/readyz")
def readyz() -> Dict[str, Any]:
    _require_model()
    if not RULES_PATH.exists():
        raise HTTPException(status_code=503, detail="declared_rules.json missing")
    return {"status": "ready"}


@app.post("/v1/runs")
async def create_run(file: UploadFile = File(...)) -> JSONResponse:
    """Upload a CSV, score it with the existing UEBA model, and run the full harness."""
    _require_model()
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a .csv file")

    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"CSV exceeds MAX_UPLOAD_BYTES={MAX_UPLOAD_BYTES}")

    run_id = "api_" + uuid.uuid4().hex[:12]
    input_csv = DATA_DIR / f"{run_id}_input.csv"
    scored_csv = OUTPUTS_DIR / f"{run_id}_scored.csv"
    run_outputs = OUTPUTS_DIR / run_id
    run_outputs.mkdir(parents=True, exist_ok=True)
    input_csv.write_bytes(payload)

    _run([
        "python", "src/ueba_model.py", "score",
        "--input-csv", str(input_csv),
        "--model-dir", str(MODEL_DIR),
        "--output-csv", str(scored_csv),
    ])

    _run([
        "python", "src/harness_runner.py",
        "--scored-csv", str(scored_csv),
        "--rules", str(RULES_PATH),
        "--runs-dir", str(RUNS_DIR),
        "--outputs-dir", str(run_outputs),
        "--run-id", run_id,
    ])

    final_report_path = run_outputs / "harness_final_report.json"
    if not final_report_path.exists():
        raise HTTPException(status_code=500, detail="Harness did not produce final report")
    report = json.loads(final_report_path.read_text())

    return JSONResponse({
        "run_id": run_id,
        "status": report.get("status"),
        "interesting_events": report.get("interesting_events"),
        "alarms": len(report.get("alarms", [])),
        "human_review_items": len(report.get("human_review_package", {}).get("items", [])),
        "links": {
            "final_report": f"/v1/runs/{run_id}/final_report",
            "findings_csv": f"/v1/runs/{run_id}/findings.csv",
            "alarms": f"/v1/runs/{run_id}/alarms",
            "human_review_package": f"/v1/runs/{run_id}/human_review_package",
        },
    })


@app.get("/v1/runs/{run_id}/final_report")
def get_final_report(run_id: str) -> FileResponse:
    path = OUTPUTS_DIR / run_id / "harness_final_report.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="run not found")
    return FileResponse(path, media_type="application/json")


@app.get("/v1/runs/{run_id}/alarms")
def get_alarms(run_id: str) -> FileResponse:
    path = OUTPUTS_DIR / run_id / "harness_alarms.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="alarms not found")
    return FileResponse(path, media_type="application/json")


@app.get("/v1/runs/{run_id}/human_review_package")
def get_human_review_package(run_id: str) -> FileResponse:
    path = OUTPUTS_DIR / run_id / "human_review_package.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="human review package not found")
    return FileResponse(path, media_type="application/json")


@app.get("/v1/runs/{run_id}/findings.csv")
def get_findings_csv(run_id: str) -> FileResponse:
    path = OUTPUTS_DIR / run_id / "harness_findings.csv"
    if not path.exists():
        raise HTTPException(status_code=404, detail="findings not found")
    return FileResponse(path, media_type="text/csv", filename=f"{run_id}_harness_findings.csv")
