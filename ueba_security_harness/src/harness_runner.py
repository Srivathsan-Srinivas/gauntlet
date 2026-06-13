#!/usr/bin/env python3
"""Govern the existing UEBA model output with a multi-agent security harness.

This file intentionally does not change src/ueba_model.py. It consumes the scored CSV
produced by the existing model and adds the harness layer around it:
- declared guardrails
- named alarms
- checkpoint persistence
- human review package generation
- UEBA, Threat-Hunting, and Security Compliance agents
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from harness.agents import SecurityComplianceAgent, ThreatHuntingAgent, UEBAAgent
from harness.alarms import AlarmDispatcher
from harness.checkpoints import (
    CheckpointStore,
    compliance_checkpoint,
    cross_agent_consistency_checkpoint,
    human_escalation_checkpoint,
    input_quality_checkpoint,
    threat_hunt_checkpoint,
    ueba_checkpoint,
)
from harness.guardrails import enforce_output_guardrails, load_rules, run_input_guardrails
from harness.human_review import build_human_review_package
from harness.material import create_evidence_bundle, load_scored_events, now_run_id, redacted_dataframe, write_json


def event_alarm_scan(events: List[Dict[str, Any]], rules: Dict[str, Any], alarms: AlarmDispatcher) -> None:
    thresholds = rules.get("risk_thresholds", {})
    high_risk = thresholds.get("high_risk", 80)
    critical_risk = thresholds.get("critical_risk", 90)
    large_export = thresholds.get("large_export_records", 10000)
    extreme_export = thresholds.get("extreme_export_records", 50000)
    weak_tls = set(rules.get("weak_tls_versions", []))
    suspicious_domains = set(rules.get("suspicious_domains", []))
    allowed_countries = set(rules.get("countries_allowed_for_most_users", ["US"]))

    for event in events:
        score = float(event.get("interestingness_score", 0) or 0)
        event_context = {
            "event_id": event.get("event_id"),
            "user_id": event.get("user_id"),
            "persona": event.get("persona"),
            "score": score,
        }
        if score >= critical_risk:
            alarms.emit(
                "UEBA_CRITICAL_RISK_BEHAVIOR",
                "critical",
                event_context,
                "Stop autonomous closure and create a human review item.",
            )
        elif score >= high_risk:
            alarms.emit(
                "UEBA_HIGH_RISK_BEHAVIOR",
                "high",
                event_context,
                "Send to threat-hunting and require analyst review before closure.",
            )

        if event.get("country") not in allowed_countries:
            alarms.emit(
                "FOREIGN_COUNTRY_LOGIN_OR_ACCESS",
                "high" if score >= high_risk else "medium",
                {**event_context, "country": event.get("country"), "city": event.get("city")},
                "Validate user travel/VPN context and correlate with identity-provider logs.",
            )

        if event.get("tls_version") in weak_tls:
            alarms.emit(
                "WEAK_TLS_USED",
                "high",
                {**event_context, "tls_version": event.get("tls_version")},
                "Review auth/session context and enforce modern TLS policy.",
            )

        if event.get("domain_name") in suspicious_domains:
            alarms.emit(
                "SUSPICIOUS_CONNECTED_APP",
                "high",
                {**event_context, "domain_name": event.get("domain_name")},
                "Investigate connected app authorization and user consent history.",
            )

        records = float(event.get("records_accessed", 0) or 0)
        if records >= extreme_export:
            severity = "critical"
        elif records >= large_export:
            severity = "high"
        else:
            severity = ""
        if severity:
            alarms.emit(
                "LARGE_DATA_EXPORT_OR_ACCESS",
                severity,
                {**event_context, "records_accessed": records, "event_name": event.get("event_name")},
                "Require human review for data-access justification and possible containment.",
            )

        if event.get("is_admin_action") in {True, "True", "true", 1, "1"} and score >= high_risk:
            alarms.emit(
                "ANOMALOUS_ADMIN_ACTION",
                "critical",
                {**event_context, "event_name": event.get("event_name")},
                "Privileged activity in anomalous context requires immediate analyst review.",
            )


def flatten_findings_for_csv(
    ueba_findings: List[Dict[str, Any]],
    threat_hunts: List[Dict[str, Any]],
    compliance_results: List[Dict[str, Any]],
) -> pd.DataFrame:
    hunt_by_event = {x["event_id"]: x for x in threat_hunts}
    comp_by_event = {x["event_id"]: x for x in compliance_results}
    rows = []
    for finding in ueba_findings:
        event_id = finding["event_id"]
        hunt = hunt_by_event.get(event_id, {})
        comp = comp_by_event.get(event_id, {})
        rows.append({
            "event_id": event_id,
            "user_id": finding.get("user_id"),
            "persona": finding.get("persona"),
            "ueba_risk_score": finding.get("risk_score"),
            "ueba_finding_type": finding.get("finding_type"),
            "threat_hypothesis": hunt.get("hypothesis"),
            "threat_confidence": hunt.get("confidence"),
            "attack_stage": hunt.get("attack_stage"),
            "compliance_control_id": comp.get("control_id"),
            "compliance_status": comp.get("status"),
            "human_review_recommended": finding.get("risk_score", 0) >= 80 or comp.get("status") == "non_compliant" or hunt.get("confidence") == "high",
        })
    return pd.DataFrame(rows)


def run_harness(args: argparse.Namespace) -> None:
    rules = load_rules(args.rules)
    run_id = args.run_id or now_run_id()
    run_dir = Path(args.runs_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir = Path(args.outputs_dir)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    alarms = AlarmDispatcher()
    store = CheckpointStore(run_dir)

    df = load_scored_events(args.scored_csv)
    write_json(run_dir / "00_raw_input_summary.json", {
        "run_id": run_id,
        "scored_csv": str(args.scored_csv),
        "row_count": int(len(df)),
        "columns": list(df.columns),
    })

    cp = input_quality_checkpoint(df, rules.get("required_input_columns", []))
    store.persist(1, cp)
    if not cp.passed:
        alarms.emit(
            "INPUT_QUALITY_CHECKPOINT_FAILED",
            "critical",
            cp.details,
            "Stop harness run and provide a scored UEBA CSV with the required columns.",
        )

    guardrail_result = run_input_guardrails(df, rules, alarms)
    write_json(run_dir / "02_input_guardrails.json", guardrail_result)

    redacted = redacted_dataframe(df)
    redacted.to_csv(run_dir / "03_redacted_scored_input.csv", index=False)

    bundle = create_evidence_bundle(df, run_id, rules)
    write_json(run_dir / "04_evidence_bundle.json", bundle)
    event_alarm_scan(bundle["events"], rules, alarms)

    events_by_id: Dict[str, Dict[str, Any]] = {str(e["event_id"]): e for e in bundle["events"]}

    ueba_agent = UEBAAgent()
    ueba_findings = ueba_agent.run("Create UEBA findings from scored Salesforce events.", bundle)
    ueba_findings = enforce_output_guardrails(ueba_agent.name, ueba_findings, rules, alarms)
    write_json(run_dir / "05_ueba_agent_output.json", ueba_findings)
    cp = ueba_checkpoint(ueba_findings)
    store.persist(6, cp)
    if not cp.passed:
        alarms.emit("UEBA_CHECKPOINT_FAILED", "high", cp.details, "Return checkpoint feedback to UEBA agent or escalate to human review.")

    threat_agent = ThreatHuntingAgent()
    threat_material = {**bundle, "ueba_findings": ueba_findings, "events_by_id": events_by_id}
    threat_hunts = threat_agent.run("Generate threat-hunting hypotheses from UEBA findings.", threat_material)
    threat_hunts = enforce_output_guardrails(threat_agent.name, threat_hunts, rules, alarms)
    write_json(run_dir / "07_threat_hunting_agent_output.json", threat_hunts)
    cp = threat_hunt_checkpoint(threat_hunts)
    store.persist(8, cp)
    if not cp.passed:
        alarms.emit("THREAT_HUNT_CHECKPOINT_FAILED", "high", cp.details, "Return checkpoint feedback to Threat-Hunting agent or escalate to human review.")

    compliance_agent = SecurityComplianceAgent()
    compliance_material = {
        **bundle,
        "ueba_findings": ueba_findings,
        "threat_hunts": threat_hunts,
        "events_by_id": events_by_id,
        "rules": rules,
    }
    compliance_results = compliance_agent.run("Evaluate security compliance impact of each finding.", compliance_material)
    compliance_results = enforce_output_guardrails(compliance_agent.name, compliance_results, rules, alarms)
    write_json(run_dir / "09_security_compliance_agent_output.json", compliance_results)
    cp = compliance_checkpoint(compliance_results)
    store.persist(10, cp)
    if not cp.passed:
        alarms.emit("COMPLIANCE_CHECKPOINT_FAILED", "high", cp.details, "Return checkpoint feedback to Compliance agent or escalate to human review.")

    for result in compliance_results:
        if result.get("status") == "non_compliant":
            alarms.emit(
                "COMPLIANCE_VIOLATION",
                "high",
                {"event_id": result.get("event_id"), "control_id": result.get("control_id"), "status": result.get("status")},
                "Create a human review package and require analyst decision before closure.",
            )

    cp = cross_agent_consistency_checkpoint(ueba_findings, threat_hunts, compliance_results)
    store.persist(11, cp)
    if not cp.passed:
        alarms.emit("CROSS_AGENT_DISAGREEMENT", "high", cp.details, "Stop finalization and send the run to human review.")

    review_package = build_human_review_package(run_id, ueba_findings, threat_hunts, compliance_results, alarms.all(), rules)
    write_json(run_dir / "12_human_review_package.json", review_package)
    cp = human_escalation_checkpoint(review_package, alarms.all())
    store.persist(13, cp)
    if not cp.passed:
        alarms.emit("HUMAN_ESCALATION_CHECKPOINT_FAILED", "critical", cp.details, "Stop finalization until review package is repaired.")

    final_report = {
        "run_id": run_id,
        "status": "blocked_pending_human_review" if review_package.get("items") else "completed_no_review_required",
        "input_rows": int(len(df)),
        "interesting_events": int(len(bundle["events"])),
        "ueba_findings": ueba_findings,
        "threat_hunts": threat_hunts,
        "compliance_results": compliance_results,
        "alarms": alarms.all(),
        "checkpoints": store.all(),
        "human_review_package": review_package,
        "run_dir": str(run_dir),
    }
    write_json(run_dir / "14_final_report.json", final_report)
    write_json(outputs_dir / "harness_final_report.json", final_report)
    write_json(outputs_dir / "harness_alarms.json", alarms.all())
    write_json(outputs_dir / "human_review_package.json", review_package)
    findings_df = flatten_findings_for_csv(ueba_findings, threat_hunts, compliance_results)
    findings_df.to_csv(outputs_dir / "harness_findings.csv", index=False)

    print(f"Harness run_id={run_id}")
    print(f"Run artifacts: {run_dir}")
    print(f"Final report: {outputs_dir / 'harness_final_report.json'}")
    print(f"Findings CSV: {outputs_dir / 'harness_findings.csv'}")
    print(f"Human review status: {review_package['status']} ({len(review_package.get('items', []))} items)")
    print(f"Alarms: {len(alarms.all())}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scored-csv", default="outputs/scored_salesforce_ueba_test.csv")
    parser.add_argument("--rules", default="config/declared_rules.json")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--outputs-dir", default="outputs")
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()
    run_harness(args)


if __name__ == "__main__":
    main()
