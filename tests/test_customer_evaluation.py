import unittest

from scripts.evaluate_customer_scanner import assess


class CustomerEvaluationTests(unittest.TestCase):
    def test_incomplete_engine_never_passes_even_if_a_finding_exists(self):
        case = {'id': 'unsafe', 'dangerous': True}
        report = {'analysis_engines': [{'name': 'behavior', 'status': 'complete'}, {'name': 'semgrep', 'status': 'unavailable'}],
                  'flags': [{'severity': 32, 'pattern': 'risk'}]}
        self.assertFalse(assess(case, report)['passed'])

    def test_expected_rule_checks_medium_finding_without_requiring_high_severity(self):
        case = {'id': 'unsafe', 'dangerous': True, 'rule': 'command', 'expect_rule': True}
        report = {'analysis_engines': [{'name': 'behavior', 'status': 'complete'}, {'name': 'semgrep', 'status': 'complete'}],
                  'engine_findings': [{'severity': 8, 'rule_id': 'command'}]}
        self.assertTrue(assess(case, report)['passed'])
        self.assertFalse(assess(case, {'analysis_engines': [{'name': 'behavior', 'status': 'complete'}, {'name': 'semgrep', 'status': 'complete'}]})['passed'])

    def test_unexpected_high_finding_fails_safe_case(self):
        case = {'id': 'safe', 'dangerous': False}
        report = {'analysis_engines': [{'name': 'behavior', 'status': 'complete'}, {'name': 'semgrep', 'status': 'complete'}],
                  'flags': [{'severity': 18, 'pattern': 'risk'}]}
        self.assertFalse(assess(case, report)['passed'])

    def test_missing_engine_never_passes(self):
        self.assertFalse(assess({'id': 'safe', 'dangerous': False},
                                {'analysis_engines': [{'name': 'behavior', 'status': 'complete'}]})['passed'])

