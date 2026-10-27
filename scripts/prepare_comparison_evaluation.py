"""Prepare a labeled reasoning set without making provider calls.

These goals require human review of real provider responses. Successful input
preparation alone is not evidence of AI reasoning accuracy.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_compare  # noqa: E402

cases = json.loads((ROOT / 'tests/evaluation/comparison_cases.json').read_text())
results = []
for case in cases:
    payload, blocks = ai_compare.prepare(case)
    results.append({'id': case['id'], 'blocks': len(blocks),
                    'provider_called': False, 'review_goal': case['review_goal']})
print(json.dumps({'description': 'Prepared only; provider reasoning not evaluated.',
                  'cases': results}, indent=2, ensure_ascii=False))
