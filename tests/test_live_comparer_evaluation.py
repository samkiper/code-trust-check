import unittest
from scripts.evaluate_live_comparer import assess, evaluate


class LiveComparerEvaluationTests(unittest.TestCase):
    def test_wrong_security_label_fails_even_when_scope_is_correct(self):
        case = {'classification': 'unrelated', 'security_impact': 'none_observed'}
        review = {'state': 'complete', 'changes': [dict(case)]}
        self.assertTrue(assess(case, review))
        review['changes'][0]['security_impact'] = 'possible_regression'
        self.assertFalse(assess(case, review))

    def test_missing_or_partial_assessment_never_passes(self):
        case = {'classification': 'requested', 'security_impact': 'none_observed'}
        for review in ({}, {'state': 'complete', 'changes': []},
                       {'state': 'not_rated', 'changes': [case]}):
            self.assertFalse(assess(case, review))

    def test_provider_failure_is_counted_and_does_not_expose_exception(self):
        case = {'id': 'failure', 'before': 'x=1', 'after': 'x=2', 'request': 'Change x'}
        def fail(_):
            raise RuntimeError('sensitive provider detail')
        result = evaluate([case], 2, fail)
        self.assertEqual(result['requests'], 2)
        self.assertEqual(result['passed'], 0)
        self.assertEqual(result['unknown_cost_requests'], 2)
        self.assertNotIn('sensitive', str(result))
