from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List
import json

import pandas as pd


@dataclass
class CheckpointResult:
    name: str
    passed: bool
    criteria: Dict[str, Any]
    details: Dict[str, Any]
    created_at: str

    @classmethod
    def make(cls, name: str, passed: bool, criteria: Dict[str, Any], details: Dict[str, Any]) -> "CheckpointResult":
        return cls(name, passed, criteria, details, datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CheckpointStore:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[CheckpointResult] = []

    def persist(self, idx: int, result: CheckpointResult) -> None:
        self.results.append(result)
        path = self.run_dir / f"{idx:02d}_{result.name}.json"
        path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    def all(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.results]

    def any_failed(self) -> bool:
        return any(not r.passed for r in self.results)


def input_quality_checkpoint(df: pd.DataFrame, required_columns: Iterable[str]) -> CheckpointResult:
    required = list(required_columns)
    missing = [col for col in required if col not in df.columns]
    empty_required = []
    for col in ["event_id", "event_name", "timestamp", "user_id", "persona"]:
        if col in df.columns and df[col].isna().any():
            empty_required.append(col)
    passed = not missing and not empty_required and len(df) > 0
    return CheckpointResult.make(
        "input_quality_checkpoint",
        passed,
        {
            "required_columns_present": True,
            "no_empty_core_fields": True,
            "row_count_gt_zero": True,
        },
        {"missing_columns": missing, "empty_required_columns": empty_required, "row_count": int(len(df))},
    )


def ueba_checkpoint(findings: List[Dict[str, Any]]) -> CheckpointResult:
    bad = []
    for f in findings:
        if "event_id" not in f or "risk_score" not in f or "evidence" not in f:
            bad.append({"event_id": f.get("event_id"), "reason": "missing required finding fields"})
        score = f.get("risk_score", -1)
        if not isinstance(score, (int, float)) or score < 0 or score > 100:
            bad.append({"event_id": f.get("event_id"), "reason": "risk_score outside 0-100"})
        if not isinstance(f.get("evidence"), list):
            bad.append({"event_id": f.get("event_id"), "reason": "evidence must be a list"})
    return CheckpointResult.make(
        "ueba_checkpoint",
        len(bad) == 0,
        {
            "findings_have_event_id_risk_score_evidence": True,
            "risk_score_between_0_and_100": True,
            "evidence_is_list": True,
        },
        {"finding_count": len(findings), "violations": bad[:20]},
    )


def threat_hunt_checkpoint(results: List[Dict[str, Any]]) -> CheckpointResult:
    allowed_conf = {"low", "medium", "high"}
    blocked_terms = ["disable account", "delete logs", "confirmed breach", "contain automatically"]
    bad = []
    for r in results:
        if r.get("confidence") not in allowed_conf:
            bad.append({"event_id": r.get("event_id"), "reason": "invalid confidence"})
        text = json.dumps(r).lower()
        for term in blocked_terms:
            if term in text:
                bad.append({"event_id": r.get("event_id"), "reason": f"blocked term: {term}"})
    return CheckpointResult.make(
        "threat_hunt_checkpoint",
        len(bad) == 0,
        {
            "confidence_one_of_low_medium_high": True,
            "hypotheses_are_not_stated_as_confirmed_breach": True,
            "no_autonomous_remediation": True,
        },
        {"hunt_result_count": len(results), "violations": bad[:20]},
    )


def compliance_checkpoint(results: List[Dict[str, Any]]) -> CheckpointResult:
    allowed_status = {"compliant", "non_compliant", "needs_review", "insufficient_evidence"}
    bad = []
    for r in results:
        if r.get("status") not in allowed_status:
            bad.append({"event_id": r.get("event_id"), "reason": "invalid status"})
        if not r.get("control_id"):
            bad.append({"event_id": r.get("event_id"), "reason": "missing control_id"})
        if r.get("status") == "non_compliant" and not r.get("evidence"):
            bad.append({"event_id": r.get("event_id"), "reason": "non_compliant without evidence"})
    return CheckpointResult.make(
        "compliance_checkpoint",
        len(bad) == 0,
        {
            "status_is_allowed_value": True,
            "control_id_is_present": True,
            "non_compliance_has_evidence": True,
        },
        {"compliance_result_count": len(results), "violations": bad[:20]},
    )


def cross_agent_consistency_checkpoint(ueba: List[Dict[str, Any]], hunts: List[Dict[str, Any]], compliance: List[Dict[str, Any]]) -> CheckpointResult:
    by_event_hunt = {r["event_id"]: r for r in hunts}
    by_event_comp = {r["event_id"]: r for r in compliance}
    disagreements = []
    for finding in ueba:
        event_id = finding["event_id"]
        risk = finding.get("risk_score", 0)
        hunt = by_event_hunt.get(event_id, {})
        comp = by_event_comp.get(event_id, {})
        if risk >= 80 and hunt.get("confidence") == "low" and comp.get("status") == "compliant":
            disagreements.append({
                "event_id": event_id,
                "reason": "UEBA high risk conflicts with low threat confidence and compliant status",
            })
    return CheckpointResult.make(
        "cross_agent_consistency_checkpoint",
        len(disagreements) == 0,
        {
            "high_ueba_risk_not_silently_downgraded": True,
            "agent_disagreements_are_surfaced": True,
        },
        {"disagreements": disagreements},
    )


def human_escalation_checkpoint(review_package: Dict[str, Any], alarms: List[Dict[str, Any]]) -> CheckpointResult:
    high_alarms = [a for a in alarms if a.get("severity") in {"high", "critical"}]
    required = bool(high_alarms or review_package.get("items"))
    passed = (not required) or (review_package.get("status") == "human_review_required" and len(review_package.get("items", [])) > 0)
    return CheckpointResult.make(
        "human_escalation_checkpoint",
        passed,
        {
            "high_or_critical_alarms_create_human_review_package": True,
            "review_package_has_items_when_required": True,
        },
        {"review_required": required, "high_alarm_count": len(high_alarms), "review_item_count": len(review_package.get("items", []))},
    )
