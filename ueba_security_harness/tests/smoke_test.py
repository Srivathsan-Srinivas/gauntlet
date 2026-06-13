#!/usr/bin/env python3
import json
from pathlib import Path

import pandas as pd

scored = pd.read_csv('outputs/scored_salesforce_ueba_test.csv')
assert {'interestingness_score', 'reasons', 'is_interesting'}.issubset(scored.columns)
assert scored['interestingness_score'].between(0, 100).all()
assert scored['reasons'].map(lambda x: isinstance(json.loads(x), dict)).all()

report = json.loads(Path('outputs/harness_final_report.json').read_text())
assert {'ueba_findings', 'threat_hunts', 'compliance_results', 'alarms', 'checkpoints', 'human_review_package'}.issubset(report)
assert len(report['ueba_findings']) > 0
assert len(report['threat_hunts']) == len(report['ueba_findings'])
assert len(report['compliance_results']) == len(report['ueba_findings'])
assert all({'alarm_type', 'severity', 'context', 'recommended_action'}.issubset(a) for a in report['alarms'])
assert all({'name', 'passed', 'criteria', 'details'}.issubset(c) for c in report['checkpoints'])
assert report['human_review_package']['status'] in {'human_review_required', 'no_human_review_required'}

findings = pd.read_csv('outputs/harness_findings.csv')
print(findings.sort_values('ueba_risk_score', ascending=False).head(10).to_string(index=False))
print('\nHarness status:', report['status'])
print('Alarms:', len(report['alarms']))
print('Human review items:', len(report['human_review_package'].get('items', [])))
