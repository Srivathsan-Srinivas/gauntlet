import os
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.responses import JSONResponse

# Import the unified helper function from the updated harness_runner file
from harness_runner import execute_harness_pipeline

app = FastAPI()

# Source settings exactly tracking your environment parameters from render.yaml
RUNS_DIR = os.getenv("RUNS_DIR", "/app/runs")
OUTPUTS_DIR = os.getenv("OUTPUTS_DIR", "/app/outputs")
RULES_PATH = os.getenv("RULES_PATH", "/app/config/declared_rules.json")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "10485760"))

@app.get("/healthz")
def health_check():
    return {"status": "healthy"}

@app.post("/api/v1/analyze-csv")
async def analyze_security_csv(file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid file format. Only security CSV logs are parsed."
        )
    
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size boundary limit exceeded."
        )
    
    # Save target file directly into your persistent Render disk space
    temp_input_path = os.path.join(RUNS_DIR, "uploaded_ueba_input.csv")
    with open(temp_input_path, "wb") as f:
        f.write(contents)
    
    try:
        # Trigger your multi-agent architecture execution run
        final_harness_report = execute_harness_pipeline(
            scored_csv_path=temp_input_path,
            rules_path=RULES_PATH,
            runs_dir=RUNS_DIR,
            outputs_dir=OUTPUTS_DIR
        )
        
        # Cleanly return the JSON results directly to your terminal screen
        return JSONResponse(content={
            "status": "success",
            "run_id": final_harness_report["run_id"],
            "pipeline_status": final_harness_report["status"],
            "summary": {
                "input_rows_evaluated": final_harness_report["input_rows"],
                "active_alarms_triggered": len(final_harness_report["alarms"]),
                "human_review_items": len(final_harness_report["human_review_package"].get("items", []))
            },
            "alarms": final_harness_report["alarms"],
            "human_review_package": final_harness_report["human_review_package"]
        })
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Harness processing execution failed: {str(e)}"
        )