import datetime as dt
import unittest
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
            mutate.return_value = {'id': self.uid}
            self.assertEqual(deletion.perform(self.uid, 'finalize', self.uid,
                self.now+dt.timedelta(hours=8))['action'], 'deleted')

    def test_quarantined_account_cannot_use_existing_token(self):
        with patch.object(main, 'fetch_supabase_user', return_value=({'id': self.uid,
                'app_metadata': {'deletion_requested_at': self.now.isoformat(), 'plan': 'serious'}}, True)):
            access = main.get_request_access_context(Request({'type': 'http', 'headers': []}), 'old-token')
            self.assertFalse(access['authenticated'])
