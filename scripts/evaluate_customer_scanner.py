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


def evaluate():
    cases = json.loads((ROOT / 'tests/evaluation/scanner_cases.json').read_text())
    results = []
    for case in cases:
        report = analyze_code_product(case['intent'], case['code'], language=case['language'])
        engines = report.get('analysis_engines', [])
        complete = bool(engines) and all(engine.get('status') == 'complete' for engine in engines)
        findings = report.get('flags', []) + report.get('engine_findings', [])
        high = [finding for finding in findings if finding.get('severity', 0) >= 18]
        detected = bool(high) if complete else None
        results.append({'id': case['id'], 'expected_dangerous': case['dangerous'],
                        'detected_high': detected, 'engines_complete': complete,
                        'finding_ids': [f.get('pattern') or f.get('rule_id') for f in high]})
    return {'description': 'Exploratory hand-authored snippets; not a general accuracy rate.',
            'cases': results}


if __name__ == '__main__':
    print(json.dumps(evaluate(), indent=2))
