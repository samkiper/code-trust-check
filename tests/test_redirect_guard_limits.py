"""Conservative redirect behavior: do not mistake arbitrary guards for validation."""
import unittest

from main import analyze_code_product


class RedirectGuardLimits(unittest.TestCase):
    def test_replace_and_document_location_safe_and_dangerous_pairs(self):
        sinks = ['location.replace', 'window.location.replace', 'document.location.replace', 'document.location.assign']
        for sink in sinks + ['document.location.href']:
            for source, expected in [('new URLSearchParams(document.location.search).get("next")', True), ('"/dashboard"', False)]:
                with self.subTest(sink=sink, expected=expected):
                    destination = f'{sink} = next;' if sink.endswith('.href') else f'{sink}(next);'
                    result = analyze_code_product('Navigate to the local dashboard.', f'const next = {source};\n{destination}', language='JavaScript')
                    self.assertTrue(all(e['status'] == 'complete' for e in result['analysis_engines']))
                    self.assertEqual(any(f.get('rule_id') == 'javascript.query-redirect' for f in result['engine_findings']), expected)

    def test_query_destinations_with_dangerous_guard_lookalikes_are_warned(self):
        cases = {
            'external equality': 'if (next === "https://evil.example") { location.href = next; }',
            'protocol-relative equality': 'if (next === "//evil.example") { location.href = next; }',
            'slash prefix': 'if (next.startsWith("/")) { location.href = next; }',
            'reassignment': 'if (next === "/dashboard") { next = new URLSearchParams(location.search).get("other"); location.href = next; }',
        }
        for label, code in cases.items():
            with self.subTest(label=label):
                source = 'let next = new URLSearchParams(location.search).get("next");\n' + code
                result = analyze_code_product('Navigate only to /dashboard.', source, language='JavaScript')
                self.assertTrue(all(e['status'] == 'complete' for e in result['analysis_engines']))
                self.assertTrue(any(f.get('rule_id') == 'javascript.query-redirect' for f in result['engine_findings']))


if __name__ == '__main__':
    unittest.main()
