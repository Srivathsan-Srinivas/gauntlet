from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import json

import pandas as pd

from .alarms import AlarmDispatcher


def load_rules(path: str | Path) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def run_input_guardrails(df: pd.DataFrame, rules: Dict[str, Any], alarms: AlarmDispatcher) -> Dict[str, Any]:
    weak_tls = sorted(set(df[df["tls_version"].isin(rules.get("weak_tls_versions", []))]["tls_version"].dropna().astype(str))) if "tls_version" in df else []
    suspicious_domains = sorted(set(df[df["domain_name"].isin(rules.get("suspicious_domains", []))]["domain_name"].dropna().astype(str))) if "domain_name" in df else []
    public_or_foreign = []
    if "country" in df:
        allowed = set(rules.get("countries_allowed_for_most_users", ["US"]))
        public_or_foreign = sorted(set(df[~df["country"].isin(allowed)]["country"].dropna().astype(str)))

    if weak_tls:
        alarms.emit(
            "WEAK_TLS_OBSERVED",
            "high",
            {"weak_tls_versions": weak_tls},
            "Route affected events to compliance review and require human approval before closure.",
        )
    if suspicious_domains:
        alarms.emit(
            "SUSPICIOUS_CONNECTED_APP_DOMAIN",
            "high",
            {"domains": suspicious_domains},
            "Investigate OAuth application context and require analyst review.",
        )
    if public_or_foreign:
        alarms.emit(
            "FOREIGN_OR_UNEXPECTED_COUNTRY_OBSERVED",
            "medium",
            {"countries": public_or_foreign},
            "Let UEBA and threat-hunting agents evaluate whether behavior is normal for the persona.",
        )

    return {
        "weak_tls_versions": weak_tls,
        "suspicious_domains": suspicious_domains,
        "unexpected_countries": public_or_foreign,
        "redaction_policy": rules.get("sensitive_fields", []),
    }


def enforce_output_guardrails(agent_name: str, output: List[Dict[str, Any]], rules: Dict[str, Any], alarms: AlarmDispatcher) -> List[Dict[str, Any]]:
    blocked = [b.lower() for b in rules.get("blocked_agent_actions", [])]
    checked: List[Dict[str, Any]] = []
    for item in output:
        text = json.dumps(item, default=str).lower()
        violations = [term for term in blocked if term.replace("_", " ") in text or term in text]
        if violations:
            alarms.emit(
                "AGENT_POLICY_VIOLATION",
                "critical",
                {"agent": agent_name, "event_id": item.get("event_id"), "blocked_terms": violations},
                "Block autonomous completion and request human analyst review.",
            )
            item = dict(item)
            item["guardrail_blocked_terms"] = violations
            item["recommended_action"] = "Escalate to human analyst; do not execute remediation autonomously."
        checked.append(item)
    return checked
