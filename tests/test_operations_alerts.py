import unittest
import io
import json
from unittest.mock import Mock, patch
import operations_alerts as ops

class OperationalAlertTests(unittest.TestCase):
    def test_delivery_contract_and_retry_idempotency(self):
        env = {'RESEND_API_KEY': 'test-secret', 'ACA_ALERT_EMAIL': 'operator@example.com'}
        with patch.dict(ops.os.environ, env, clear=True), patch.object(ops.urllib.request, 'urlopen') as network:
            network.side_effect = lambda *a, **kw: io.BytesIO(b'{"id":"accepted-test"}')
            for now in (1000, 1001, 22601):
                self.assertEqual(ops.send_alert('delivery-test', now=now), 'accepted-test')
            requests = [call.args[0] for call in network.call_args_list]
            request = requests[0]
            self.assertEqual(request.full_url, 'https://api.resend.com/emails')
            self.assertEqual(request.get_method(), 'POST')
            self.assertEqual(request.get_header('User-agent'), 'AI-Code-Audit/1.0')
            self.assertEqual(request.get_header('Authorization'), 'Bearer test-secret')
            self.assertEqual(network.call_args.kwargs['timeout'], 15)
            body = json.loads(request.data)
            self.assertEqual(body['to'], ['operator@example.com'])
            self.assertEqual(body['subject'], 'AI Code Audit: delivery-test')
            self.assertNotIn('test-secret', request.data.decode())
            self.assertEqual(request.get_header('Idempotency-key'), requests[1].get_header('Idempotency-key'))
            self.assertNotEqual(request.get_header('Idempotency-key'), requests[2].get_header('Idempotency-key'))

    def test_missing_provider_acceptance_is_not_success(self):
        with patch.dict(ops.os.environ, {'RESEND_API_KEY': 'test', 'ACA_ALERT_EMAIL': 'operator@example.com'}), \
             patch.object(ops.urllib.request, 'urlopen', return_value=io.BytesIO(b'{}')):
            with self.assertRaisesRegex(RuntimeError, 'acceptance was not confirmed'):
                ops.send_alert('delivery-test')

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
