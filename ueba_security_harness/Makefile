PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

.PHONY: setup data train score harness run test api docker-build docker-run clean zip

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -r requirements.txt

data:
	$(PY) src/synthesize_salesforce_logs.py --out-dir data

train: data
	OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 $(PY) src/ueba_model.py train --train-csv data/salesforce_ueba_train.csv --model-dir models --epochs 15

score: train
	$(PY) src/ueba_model.py score --input-csv data/salesforce_ueba_test.csv --model-dir models --output-csv outputs/scored_salesforce_ueba_test.csv

harness: score
	$(PY) src/harness_runner.py --scored-csv outputs/scored_salesforce_ueba_test.csv --rules config/declared_rules.json --runs-dir runs --outputs-dir outputs

run: harness
	@echo "Done. See outputs/scored_salesforce_ueba_test.csv and outputs/harness_final_report.json"

api:
	$(PY) -m uvicorn src.api.app:app --host 0.0.0.0 --port $${PORT:-10000}

docker-build:
	docker build -t ueba-security-harness:latest .

docker-run:
	docker run --rm -p 10000:10000 -v "$$(pwd)/outputs:/app/outputs" -v "$$(pwd)/runs:/app/runs" ueba-security-harness:latest

test: run
	$(PY) tests/smoke_test.py

clean:
	rm -rf data/*.csv models/*.pt models/*.pkl models/*.json outputs/*.csv outputs/*.json runs/run_*

zip:
	cd .. && zip -r ueba_security_harness_v2.zip ueba_security_harness -x 'ueba_security_harness/.venv/*' 'ueba_security_harness/__pycache__/*' 'ueba_security_harness/src/**/__pycache__/*'
