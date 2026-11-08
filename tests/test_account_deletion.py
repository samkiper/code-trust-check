import datetime as dt
import unittest
import io
import urllib.error
from unittest.mock import patch, MagicMock
from starlette.requests import Request
from scripts import account_deletion as deletion
import main


class AccountDeletionTests(unittest.TestCase):
    uid = '00000000-0000-4000-8000-000000002401'
    now = dt.datetime(2026, 11, 8, tzinfo=dt.timezone.utc)

    def test_inspection_never_mutates_and_paid_subscription_blocks(self):
        user = {'id': self.uid, 'app_metadata': {'stripe_customer_id': 'cus_fixture'}}
        subs = MagicMock(); subs.auto_paging_iter.return_value = iter([{'status': 'active'}])
        with patch.object(main, 'get_supabase_admin_user', return_value=user), \
             patch.object(main.stripe.Subscription, 'list', return_value=subs), \
             patch.object(main, 'supabase_auth_admin_request') as mutate:
            with self.assertRaisesRegex(RuntimeError, 'subscriptions'):
                deletion.perform(self.uid)
            mutate.assert_not_called()

    def test_prepare_preserves_metadata_and_requires_exact_confirmation(self):
        user = {'id': self.uid, 'app_metadata': {'plan': 'free', 'unrelated': 'preserve'}}
        with patch.object(main, 'get_supabase_admin_user', return_value=user), \
             patch.object(main, 'supabase_auth_admin_request', return_value={'id': self.uid, 'banned_until': '2126-01-01'}) as mutate:
            self.assertEqual(deletion.perform(self.uid)['action'], 'inspection_only'); mutate.assert_not_called()
            with self.assertRaises(RuntimeError): deletion.perform(self.uid, 'prepare', 'other', self.now)
            result = deletion.perform(self.uid, 'prepare', self.uid, self.now)
            self.assertEqual(result['action'], 'quarantined')
            self.assertEqual(mutate.call_args.args[2]['app_metadata']['unrelated'], 'preserve')

    def test_quarantine_and_delete_confirmation_fail_closed(self):
        user = {'id': self.uid, 'banned_until': '2126-01-01T00:00:00+00:00',
                'app_metadata': {'deletion_requested_at': self.now.isoformat()}}
        with patch.object(main, 'get_supabase_admin_user', return_value=user), \
             patch.object(main, 'supabase_auth_admin_request', return_value={}) as mutate:
            with self.assertRaisesRegex(RuntimeError, 'Quarantine'):
                deletion.perform(self.uid, 'finalize', self.uid, self.now)
            mutate.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'not confirmed'):
                deletion.perform(self.uid, 'finalize', self.uid, self.now+dt.timedelta(hours=8))
            mutate.side_effect = [{}, self.not_found()]
            self.assertEqual(deletion.perform(self.uid, 'finalize', self.uid,
                self.now+dt.timedelta(hours=8))['action'], 'deleted')

    def not_found(self, body=b'{"error_code":"user_not_found"}'):
        return urllib.error.HTTPError('https://example.invalid/auth/v1/admin/users/test',
                                      404, 'Not Found', {}, io.BytesIO(body))

    def test_success_requires_delete_http_success_and_explicit_not_found(self):
        user = {'id': self.uid, 'banned_until': '2126-01-01T00:00:00+00:00',
                'app_metadata': {'deletion_requested_at': self.now.isoformat()}}
        scenarios = [
            ([{}, self.not_found()], None),
            ([{}, {'id': self.uid}], RuntimeError),
            ([{}, {}], RuntimeError),
            ([{}, self.not_found(b'{}')], RuntimeError),
            ([{}, self.not_found(b'not json')], RuntimeError),
            ([{}, self.not_found(b'[]')], RuntimeError),
            ([{}, urllib.error.HTTPError('https://example.invalid', 401, 'Unauthorized', {}, None)], urllib.error.HTTPError),
            ([{}, urllib.error.HTTPError('https://example.invalid', 503, 'Unavailable', {}, None)], urllib.error.HTTPError),
            ([{}, TimeoutError('verification timeout')], TimeoutError),
            ([TimeoutError('delete timeout')], TimeoutError),
        ]
        for responses, error_type in scenarios:
            with self.subTest(responses=responses), \
                 patch.object(main, 'get_supabase_admin_user', return_value=user), \
                 patch.object(main, 'supabase_auth_admin_request', side_effect=responses) as request:
                if error_type:
                    with self.assertRaises(error_type):
                        deletion.perform(self.uid, 'finalize', self.uid, self.now+dt.timedelta(hours=8))
                else:
                    self.assertEqual(deletion.perform(self.uid, 'finalize', self.uid,
                        self.now+dt.timedelta(hours=8))['action'], 'deleted')
                self.assertEqual(request.call_args_list[0].args, ('DELETE', f'users/{self.uid}'))
                self.assertTrue(all(c.kwargs.get('raise_errors') for c in request.call_args_list))
                self.assertEqual(sum(c.args[0] == 'DELETE' for c in request.call_args_list), 1)

    def test_absence_check_never_retries_deletion(self):
        with patch.object(main, 'supabase_auth_admin_request', side_effect=self.not_found()) as request:
            deletion.verify_account_absent(self.uid)
            request.assert_called_once_with('GET', f'users/{self.uid}', raise_errors=True)

    def test_strict_admin_http_distinguishes_empty_success_from_failure(self):
        with patch.object(main, 'SUPABASE_URL', 'https://example.invalid'), \
             patch.object(main, 'SUPABASE_SECRET_KEY', 'synthetic-test-key'), \
             patch.object(main.urllib.request, 'urlopen') as open_url, \
             patch.object(main, 'log_server_issue'):
            open_url.return_value.__enter__.return_value.read.return_value = b'{}'
            self.assertEqual(main.supabase_auth_admin_request('DELETE', 'users/test', raise_errors=True), {})
            open_url.side_effect = TimeoutError('network unavailable')
            with self.assertRaises(TimeoutError):
                main.supabase_auth_admin_request('DELETE', 'users/test', raise_errors=True)
            self.assertEqual(main.supabase_auth_admin_request('GET', 'users/test'), {})
        with patch.object(main, 'SUPABASE_SECRET_KEY', ''):
            with self.assertRaisesRegex(RuntimeError, 'configuration'):
                main.supabase_auth_admin_request('DELETE', 'users/test', raise_errors=True)

    def test_quarantined_account_cannot_use_existing_token(self):
        with patch.object(main, 'fetch_supabase_user', return_value=({'id': self.uid,
                'app_metadata': {'deletion_requested_at': self.now.isoformat(), 'plan': 'serious'}}, True)):
            access = main.get_request_access_context(Request({'type': 'http', 'headers': []}), 'old-token')
            self.assertFalse(access['authenticated'])

