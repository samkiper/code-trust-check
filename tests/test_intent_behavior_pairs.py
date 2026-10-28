"""Selected behavioral intent cases; not a general requirement verifier."""
import unittest
from main import analyze_code_product


class IntentBehaviorPairs(unittest.TestCase):
    def test_named_command_does_not_claim_intent_omitted_it(self):
        result=analyze_code_product('Run echo with a user supplied argument without invoking a shell.',
            'import subprocess\nsubprocess.run(["echo", input()], shell=False)',language='Python')
        notes=' '.join(result['intent_mismatches'])
        self.assertNotIn('not clearly mentioned', notes)
        self.assertIn('confirm that the executable and its inputs', notes)
        self.assertTrue(any(f.get('pattern')=='subprocess' and f.get('severity',0)==10 for f in result['flags']))

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
