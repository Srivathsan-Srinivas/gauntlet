from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import json
import re

import pandas as pd


def now_run_id() -> str:
    return "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_scored_events(path: str | Path) -> pd.DataFrame:
    return pd.read_csv(path)


def mask_ip(ip: str) -> str:
    text = str(ip)
    if ":" in text:
        return "[REDACTED_IPV6]"
    parts = text.split(".")
    if len(parts) == 4:
        return ".".join(parts[:2] + ["x", "x"])
    return "[REDACTED_IP]"


def redact_user_agent(user_agent: str) -> str:
    text = str(user_agent)
    text = re.sub(r"\d+(?:\.\d+)+", "x.y", text)
    return text[:80]


def redacted_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "src_ip" in out.columns:
        out["src_ip_redacted"] = out["src_ip"].map(mask_ip)
    if "user_agent" in out.columns:
        out["user_agent_redacted"] = out["user_agent"].map(redact_user_agent)
    return out


def safe_json_loads(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def create_evidence_bundle(df: pd.DataFrame, run_id: str, rules: Dict[str, Any]) -> Dict[str, Any]:
    interesting_threshold = rules["risk_thresholds"]["ueba_interesting"]
    interesting = df[pd.to_numeric(df["interestingness_score"], errors="coerce").fillna(0) >= interesting_threshold].copy()
    events: List[Dict[str, Any]] = []
    for _, row in interesting.iterrows():
        event = row.to_dict()
        event["reasons_dict"] = safe_json_loads(event.get("reasons", "{}"))
        event["src_ip_redacted"] = mask_ip(event.get("src_ip", ""))
        event["user_agent_redacted"] = redact_user_agent(event.get("user_agent", ""))
        events.append(event)
    return {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "scored_salesforce_ueba_test.csv",
        "total_events": int(len(df)),
        "interesting_event_count": int(len(interesting)),
        "allowed_agent_actions": rules.get("allowed_agent_actions", []),
        "blocked_agent_actions": rules.get("blocked_agent_actions", []),
        "events": events,
    }


def write_json(path: str | Path, data: Dict[str, Any] | List[Dict[str, Any]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, default=str))
