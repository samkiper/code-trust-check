import unittest
import json
import time
from unittest.mock import patch
from github_authorization import AuthorizationCache
import main

class AuthorizationCacheTests(unittest.TestCase):
    def test_expired_tokens_are_removed_without_another_request(self):
        cache=AuthorizationCache(ttl=0.05)
        cache.put('account-a',101,'example-token')
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            with cache.lock:
                if not cache.entries:break
            time.sleep(0.01)
        with cache.lock:self.assertEqual(cache.entries,{})

    def test_expiry_revocation_and_no_cross_account_lookup(self):
        cache=AuthorizationCache(limit=2,ttl=10)
        with patch('github_authorization.time.monotonic',return_value=100):
            cache.put('account-a',101,'example-token')
            self.assertIsNone(cache.get('account-b'))
            self.assertEqual(cache.get('account-a')['github_id'],101)
            self.assertEqual(cache.revoke_github_user(102),0)
        with patch('github_authorization.time.monotonic',return_value=111):self.assertIsNone(cache.get('account-a'))
        with patch('github_authorization.time.monotonic',return_value=112):
            cache.put('account-a',101,'example-token')
            cache.put('account-b',101,'example-token-2')
            self.assertEqual(cache.revoke_github_user(101),2)
            self.assertIsNone(cache.get('account-a'))

    def test_capacity_and_input_are_bounded(self):
        cache=AuthorizationCache(limit=1)
        cache.put('one',1,'token')
        with self.assertRaises(RuntimeError):cache.put('two',2,'token')
        with self.assertRaises(ValueError):cache.put('two',True,'token')

    def test_live_github_revalidation_is_required_for_installation_access(self):
        cache=AuthorizationCache();cache.put('account-a',101,'example-token')
        user={'id':101,'login':'owner'};installation={'id':42}
        with patch.object(main,'GITHUB_USER_AUTHORIZATIONS',cache), \
                patch.object(main,'list_github_user_installations',return_value=(user,[installation])):
            self.assertTrue(main.github_installation_still_authorized('account-a',42))
            self.assertFalse(main.github_installation_still_authorized('account-b',42))
        with patch.object(main,'GITHUB_USER_AUTHORIZATIONS',cache), \
                patch.object(main,'list_github_user_installations',side_effect=RuntimeError('revoked')):
            self.assertFalse(main.github_installation_still_authorized('account-a',42))
        cache.revoke_github_user(101)
        with patch.object(main,'GITHUB_USER_AUTHORIZATIONS',cache):
            self.assertFalse(main.github_installation_still_authorized('account-a',42))

    def test_existing_installation_cannot_be_transferred_to_another_customer(self):
        installation={'id':42,'account':{'login':'owner','type':'User'}}
        with patch.object(main,'supabase_rest_request',side_effect=[[],[{'user_id':'account-a'}]]) as db:
            self.assertEqual(main.save_github_installation_link('account-b',installation),{})
            self.assertEqual([call.args[0] for call in db.call_args_list],['POST','GET'])
        with patch.object(main,'supabase_rest_request',side_effect=[[],[{'user_id':'account-a'}],[{'installation_id':42}]]) as db:
            self.assertEqual(main.save_github_installation_link('account-a',installation)['installation_id'],42)
            self.assertIn('user_id=eq.account-a',db.call_args_list[-1].kwargs['query'])

    def test_authorization_revalidation_has_an_overall_time_budget(self):
        with patch.object(main.time,'monotonic',side_effect=[0,0,50]), \
                patch.object(main,'github_api_request',return_value={'id':101,'login':'owner'}) as api:
            with self.assertRaises(TimeoutError):main.list_github_user_installations('synthetic-token')
            self.assertEqual(api.call_count,1)
