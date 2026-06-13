from __future__ import annotations

from typing import Any, Dict, List


class BaseAgent:
    name = "base_agent"

    def run(self, task: str, material: Dict[str, Any]) -> List[Dict[str, Any]]:
        raise NotImplementedError


class UEBAAgent(BaseAgent):
    name = "ueba_agent"

    def run(self, task: str, material: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for event in material.get("events", []):
            reasons = event.get("reasons_dict", {}) or {}
            risk = float(event.get("interestingness_score", 0) or 0)
            evidence = []
            for key, value in reasons.items():
                evidence.append({"reason": key, "details": value})
            finding_type = "behavioral_anomaly"
            if event.get("event_name") in {"BulkDataExport", "ReportExport"}:
                finding_type = "unusual_data_access_or_export"
            elif event.get("is_admin_action") in {True, "True", "true", 1, "1"}:
                finding_type = "unusual_admin_behavior"
            elif event.get("event_name") in {"Login", "ConnectedAppOAuth"}:
                finding_type = "unusual_authentication"
            findings.append({
                "agent": self.name,
                "event_id": event.get("event_id"),
                "user_id": event.get("user_id"),
                "persona": event.get("persona"),
                "finding_type": finding_type,
                "risk_score": round(risk, 2),
                "evidence": evidence,
                "recommended_action": "Send to threat-hunting agent for hypothesis generation." if risk >= 65 else "Monitor only.",
            })
        return findings


class ThreatHuntingAgent(BaseAgent):
    name = "threat_hunting_agent"

    def run(self, task: str, material: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for finding in material.get("ueba_findings", []):
            event = material.get("events_by_id", {}).get(finding["event_id"], {})
            reasons = event.get("reasons_dict", {}) or {}
            risk = float(finding.get("risk_score", 0) or 0)
            keys = set(reasons.keys())
            hypothesis = "Unusual Salesforce behavior requiring review"
            attack_stage = "unknown"
            if "unusual_country" in keys or "public_or_unfamiliar_ip" in keys or event.get("event_name") == "Login":
                hypothesis = "Possible credential misuse or suspicious login context"
                attack_stage = "initial_access"
            if event.get("event_name") == "ConnectedAppOAuth" or "unusual_domain_name" in keys:
                hypothesis = "Possible malicious OAuth consent or connected-app abuse"
                attack_stage = "credential_access"
            if event.get("event_name") in {"BulkDataExport", "ReportExport"} or "high_records_accessed" in keys:
                hypothesis = "Possible data staging or exfiltration through Salesforce export activity"
                attack_stage = "collection_or_exfiltration"
            if event.get("is_admin_action") in {True, "True", "true", 1, "1"} or "unexpected_admin_action" in keys:
                hypothesis = "Possible privilege misuse or unauthorized admin change"
                attack_stage = "privilege_escalation_or_defense_evasion"

            confidence = "low"
            if risk >= 90 or len(keys) >= 4:
                confidence = "high"
            elif risk >= 75 or len(keys) >= 2:
                confidence = "medium"

            results.append({
                "agent": self.name,
                "event_id": finding["event_id"],
                "user_id": finding.get("user_id"),
                "hypothesis": hypothesis,
                "attack_stage": attack_stage,
                "confidence": confidence,
                "evidence": finding.get("evidence", []),
                "recommended_action": "Request human analyst review and gather related auth, endpoint, and audit events.",
            })
        return results


class SecurityComplianceAgent(BaseAgent):
    name = "security_compliance_agent"

    def run(self, task: str, material: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules = material.get("rules", {})
        controls = rules.get("compliance_controls", {})
        weak_tls = set(rules.get("weak_tls_versions", []))
        suspicious_domains = set(rules.get("suspicious_domains", []))
        large_export = rules.get("risk_thresholds", {}).get("large_export_records", 10000)
        results: List[Dict[str, Any]] = []
        for hunt in material.get("threat_hunts", []):
            event = material.get("events_by_id", {}).get(hunt["event_id"], {})
            status = "needs_review"
            control_id = "SF-ACCESS-001"
            evidence = []

            if event.get("tls_version") in weak_tls or event.get("domain_name") in suspicious_domains or event.get("event_name") == "ConnectedAppOAuth":
                control_id = "SF-AUTH-002"
                status = "non_compliant"
                evidence.append(f"Authentication risk: tls={event.get('tls_version')} domain={event.get('domain_name')}")
            elif event.get("event_name") in {"BulkDataExport", "ReportExport"} or float(event.get("records_accessed", 0) or 0) >= large_export:
                control_id = "SF-DATA-003"
                status = "non_compliant" if float(event.get("records_accessed", 0) or 0) >= large_export else "needs_review"
                evidence.append(f"Data access/export volume: records_accessed={event.get('records_accessed')}")
            elif event.get("is_admin_action") in {True, "True", "true", 1, "1"}:
                control_id = "SF-ADMIN-004"
                status = "non_compliant" if float(event.get("interestingness_score", 0) or 0) >= 80 else "needs_review"
                evidence.append("Admin action occurred in anomalous context")
            elif event.get("country") not in rules.get("countries_allowed_for_most_users", ["US"]):
                control_id = "SF-ACCESS-001"
                status = "needs_review"
                evidence.append(f"Unexpected country: {event.get('country')}")
            else:
                evidence.append("No direct compliance violation, but UEBA marked behavior as interesting")

            results.append({
                "agent": self.name,
                "event_id": hunt["event_id"],
                "user_id": hunt.get("user_id"),
                "control_id": control_id,
                "control_description": controls.get(control_id, "Declared security control"),
                "status": status,
                "evidence": evidence,
                "recommended_action": "Create human review item before closure." if status != "compliant" else "No compliance escalation required.",
            })
        return results
