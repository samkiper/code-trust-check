import unittest
from unittest.mock import Mock, patch
import operations_alerts as ops

class OperationalAlertTests(unittest.TestCase):
    def test_cost_includes_unresolved_attempts_and_never_changes_quotas(self):
        summary = {'ai': {'recorded_micro_usd': 49_900_000, 'unresolved_reserved_micro_usd': 100_000}}
        self.assertEqual(ops.evaluate(summary), ['ai-monthly-cost-review'])
        self.assertEqual(summary['ai']['recorded_micro_usd'], 49_900_000)
    def test_failure_threshold_and_duplicate_suppression(self):
        m = ops.Monitor(); send = Mock()
        summary = lambda: {'ai': {'failed': 5, 'completed': 20}}
        m.check(summary, send, now=1000); m.check(summary, send, now=1001)
        send.assert_called_once_with('ai-failure-rate')
        m.check(summary, send, now=22601); self.assertEqual(send.call_count, 2)
    def test_missing_database_is_not_reported_as_healthy_or_immediately_paged(self):
        m = ops.Monitor(); send = Mock()
        m.check(lambda: {}, send, now=1000); send.assert_not_called()
        m.check(lambda: {}, send, now=1300); send.assert_called_once_with('database-monitor-unavailable')
    def test_failed_delivery_remains_retryable(self):
        m = ops.Monitor(); send = Mock(side_effect=RuntimeError('unavailable'))
        with self.assertRaises(RuntimeError):
            m.check(lambda: {'ai': {'failed': 5}}, send, now=1000)
        self.assertEqual(m.sent, {})
    def test_email_missing_configuration_and_unknown_category_fail_closed(self):
        with patch.dict(ops.os.environ, {}, clear=True), patch.object(ops.urllib.request, 'urlopen') as network:
            with self.assertRaises(RuntimeError): ops.send_alert('delivery-test')
            with self.assertRaises(ValueError): ops.send_alert('user-controlled-code')
            network.assert_not_called()
