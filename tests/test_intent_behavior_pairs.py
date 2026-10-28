"""Selected behavioral intent cases; not a general requirement verifier."""
import unittest
from main import analyze_code_product


class IntentBehaviorPairs(unittest.TestCase):
    def test_selected_network_and_dynamic_execution_pairs(self):
        cases = [
            ('x=1', 'Assign a value locally. Do not access the network.', False),
            ('import requests\nrequests.get("https://example.invalid")', 'Assign a value locally. Do not access the network.', True),
            ('import requests\nrequests.get("https://example.invalid")', 'Fetch public data from example.invalid.', False),
            ('value=input()\neval(value)', 'Do not execute user input.', True),
            ('value=input()\nprint(value)', 'Do not execute user input.', False),
        ]
        for code, intent, expected in cases:
            with self.subTest(code=code, intent=intent):
                result = analyze_code_product(intent, code, language='Python')
                self.assertTrue(all(e['status'] == 'complete' for e in result['analysis_engines']))
                self.assertEqual(bool(result['intent_mismatches']), expected)


if __name__ == '__main__':
    unittest.main()
