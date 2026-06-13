from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def build_human_review_package(
    run_id: str,
    ueba_findings: List[Dict[str, Any]],
    threat_hunts: List[Dict[str, Any]],
    compliance_results: List[Dict[str, Any]],
    alarms: List[Dict[str, Any]],
    rules: Dict[str, Any],
) -> Dict[str, Any]:
    hunts_by_event = {x["event_id"]: x for x in threat_hunts}
    comp_by_event = {x["event_id"]: x for x in compliance_results}
    high_risk = rules.get("risk_thresholds", {}).get("high_risk", 80)
    items: List[Dict[str, Any]] = []

    alarm_events = {a.get("context", {}).get("event_id") for a in alarms if a.get("severity") in {"high", "critical"}}
    for finding in ueba_findings:
        event_id = finding["event_id"]
        comp = comp_by_event.get(event_id, {})
        hunt = hunts_by_event.get(event_id, {})
        reasons = []
        if finding.get("risk_score", 0) >= high_risk:
            reasons.append("UEBA risk score exceeds high-risk threshold")
        if hunt.get("confidence") == "high":
            reasons.append("Threat-hunting confidence is high")
        if comp.get("status") == "non_compliant":
            reasons.append("Compliance agent found non-compliance")
        if event_id in alarm_events:
            reasons.append("High or critical alarm references this event")
        if reasons:
            items.append({
                "review_id": f"review_{run_id}_{len(items)+1:03d}",
                "event_id": event_id,
                "user_id": finding.get("user_id"),
                "persona": finding.get("persona"),
                "reason": reasons,
                "severity": "critical" if finding.get("risk_score", 0) >= 90 or comp.get("status") == "non_compliant" else "high",
                "ueba_finding": finding,
                "threat_hunt": hunt,
                "compliance_result": comp,
                "recommended_human_actions": [
                    "Validate whether the user context explains the activity.",
                    "Review adjacent Salesforce audit events for the same user and IP.",
                    "Check endpoint and identity-provider telemetry.",
                    "Decide whether containment, exception approval, or dismissal is appropriate."
                ],
                "allowed_reviewer_decisions": [
                    "approve_final_report",
                    "request_more_evidence",
                    "send_back_to_agent",
                    "escalate_incident",
                    "dismiss_false_positive"
                ],
            })

    return {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "human_review_required" if items else "no_human_review_required",
        "items": items,
    }
