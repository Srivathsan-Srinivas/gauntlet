#!/usr/bin/env sh
set -eu
: "${PORT:=10000}"
exec uvicorn src.api.app:app --host 0.0.0.0 --port "$PORT"
