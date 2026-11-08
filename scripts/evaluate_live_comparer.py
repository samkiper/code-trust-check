"""Opt-in real-provider challenge, separate from deterministic CI tests.

Synthetic code is reviewed, never executed. Reports contain no credentials or
customer data. This developer evaluation does not consume customer allowances;
report its provider spend separately from the customer usage ledger.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_compare


def assess(case, review):
    changes = review.get('changes', [])
    return (review.get('state') == 'complete' and bool(changes)
            and all(c.get('classification') == case['classification'] for c in changes)
            and all(c.get('security_impact') == case['security_impact'] for c in changes))


def evaluate(cases, repeats, call_provider):
    results = []
    for iteration in range(repeats):
        for case in cases:
            started = time.monotonic()
            raw = None
            try:
                payload, blocks = ai_compare.prepare(case)
                raw = call_provider(payload)
                review = ai_compare.validate_response(raw, blocks)
                row = {'id': case['id'], 'iteration': iteration + 1,
                       'passed': assess(case, review), 'review': review}
            except Exception as exc:
                # Never serialize arbitrary provider exception messages/headers.
                row = {'id': case['id'], 'iteration': iteration + 1,
                       'passed': False, 'error_type': type(exc).__name__}
            row.update(seconds=round(time.monotonic() - started, 3),
                       cost_micro_usd=ai_compare.usage_cost(raw) if raw else None)
            results.append(row)
    return {'model': ai_compare.MODEL, 'provider_called': True,
            'description': 'Authored challenge cases, not a general accuracy estimate.',
            'requests': len(results), 'passed': sum(r['passed'] for r in results),
            'known_cost_micro_usd': sum(r['cost_micro_usd'] or 0 for r in results),
            'unknown_cost_requests': sum(r['cost_micro_usd'] is None for r in results),
            'cases': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', help='Explicitly spend provider credits')
    parser.add_argument('--repeats', type=int, choices=range(1, 4), default=2)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.live:
        parser.error('--live is required; no provider was called')
    cases = json.loads((ROOT / 'tests/evaluation/security_scope_cases.json').read_text())
    key = os.environ['OPENAI_API_KEY']
    report = evaluate(cases, args.repeats, lambda p: ai_compare.call_provider(key, p))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}))
    print(json.dumps({'failed_ids': [r['id'] for r in report['cases'] if not r['passed']]}))
    sys.exit(0 if report['passed'] == report['requests'] else 1)
