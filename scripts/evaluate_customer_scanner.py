"""Small exploratory customer-style evaluation, separate from the CI accuracy gate.

Run with the installed Semgrep environment. The labels concern whether a
high-severity finding is warranted in these snippets, not whether arbitrary
software is safe. This small, authored set is not a statistical estimate.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from main import analyze_code_product  # noqa: E402


def assess(case, report):
    engines = report.get('analysis_engines', [])
    complete = ({engine.get('name') for engine in engines} >= {'behavior', 'semgrep'}
                and all(engine.get('status') == 'complete' for engine in engines))
    findings = report.get('flags', []) + report.get('engine_findings', [])
    high = [finding for finding in findings if finding.get('severity', 0) >= 18]
    ids = [f.get('pattern') or f.get('rule_id') for f in findings]
    detected = bool(high) if complete else None
    rule_match = ((case['rule'] in ids) == case['expect_rule']) if complete and 'rule' in case else None
    passed = complete and (rule_match if 'rule' in case else detected == case['dangerous'])
    return {'id': case['id'], 'expected_dangerous': case['dangerous'],
            'detected_high': detected, 'engines_complete': complete,
            'finding_ids': ids, 'expected_rule': case.get('rule'),
            'rule_matched_expectation': rule_match, 'passed': passed}


def evaluate():
    cases = json.loads((ROOT / 'tests/evaluation/scanner_cases.json').read_text())
    results = []
    for case in cases:
        report = analyze_code_product(case['intent'], case['code'], language=case['language'])
        results.append(assess(case, report))
    return {'description': 'Exploratory hand-authored snippets; not a general accuracy rate.',
            'cases': results}


if __name__ == '__main__':
    report = evaluate()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report['cases'] and all(case['passed'] for case in report['cases']) else 1)
