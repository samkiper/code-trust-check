import asyncio
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch
from fastapi import BackgroundTasks, HTTPException
from starlette.requests import Request
import main


def webhook(payload, secret="test-secret", signature=None, event="installation"):
    raw=json.dumps(payload).encode()
    signature=signature or "sha256="+hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
    async def receive(): return {"type":"http.request","body":raw,"more_body":False}
    return Request({"type":"http","method":"POST","path":"/github/webhook","headers":[(b"x-github-event",event.encode()),(b"x-hub-signature-256",signature.encode()),(b"x-github-delivery",b"12345678-1234-4234-8234-123456789abc")]},receive)


class GitHubLifecycleTests(unittest.TestCase):
    def test_entitlement_is_required_even_when_legacy_flag_is_false(self):
        with patch.object(main,"GITHUB_ENFORCE_PRO",False), patch.object(main,"supabase_rest_request",return_value=[]):
            self.assertFalse(main.github_installation_entitlement(123)["allowed"])

    def test_signed_delete_and_suspend_only_touch_exact_installation(self):
        for action, status in [("deleted","deleted"),("suspend","suspended")]:
            with self.subTest(action=action), patch.object(main,"GITHUB_WEBHOOK_SECRET","test-secret"), patch.object(main,"supabase_rest_request",return_value=[{"installation_id":123}]) as db:
                response=asyncio.run(main.github_webhook(webhook({"action":action,"installation":{"id":123}}),BackgroundTasks()))
                self.assertEqual(json.loads(response.body)["installation_status"],status)
                self.assertEqual(db.call_args.kwargs["payload"]["status"],status)
                self.assertIn("installation_id=eq.123",db.call_args.kwargs["query"])

    def test_reactivation_is_not_automatic(self):
        with patch.object(main,"GITHUB_WEBHOOK_SECRET","test-secret"), patch.object(main,"supabase_rest_request") as db:
            response=asyncio.run(main.github_webhook(webhook({"action":"unsuspend","installation":{"id":123}}),BackgroundTasks()))
            self.assertTrue(json.loads(response.body)["ignored"])
            db.assert_not_called()

    def test_revoking_github_authorization_removes_cached_access(self):
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'), \
                patch.object(main.GITHUB_USER_AUTHORIZATIONS,'revoke_github_user',return_value=1) as revoke:
            response=asyncio.run(main.github_webhook(webhook({'action':'revoked','sender':{'id':101}},event='github_app_authorization'),BackgroundTasks()))
        self.assertTrue(json.loads(response.body)['authorization_revoked'])
        revoke.assert_called_once_with(101)

    def test_unsigned_bad_or_failed_updates_are_not_acknowledged(self):
        with patch.object(main,"GITHUB_WEBHOOK_SECRET","test-secret"), patch.object(main,"supabase_rest_request") as db:
            for payload, signature, expected in [({"action":"deleted","installation":{"id":123}},"sha256=wrong",401),({"action":"deleted","installation":{"id":True}},None,400)]:
                with self.subTest(expected=expected), self.assertRaises(HTTPException) as caught:
                    asyncio.run(main.github_webhook(webhook(payload,signature=signature),BackgroundTasks()))
                self.assertEqual(caught.exception.status_code,expected)
            db.assert_not_called()
        with patch.object(main,"GITHUB_WEBHOOK_SECRET","test-secret"), patch.object(main,"supabase_rest_request",return_value={}):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.github_webhook(webhook({"action":"deleted","installation":{"id":123}}),BackgroundTasks()))
            self.assertEqual(caught.exception.status_code,503)

    def test_pull_request_entitlement_and_shared_queue(self):
        payload={'action':'opened','installation':{'id':123},'repository':{'full_name':'owner/repo'},'number':7,'pull_request':{'head':{'sha':'a'*40}}}
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'), \
                patch.object(main,'GITHUB_PR_SCANS_ENABLED',True), \
                patch.object(main,'github_installation_entitlement',return_value={'allowed':True,'user_id':'user-1'}), \
                patch.object(main,'github_delivery_control',return_value={'accepted':True}), \
                patch.object(main.SCAN_JOBS,'submit',return_value={'id':'job'}) as submit:
            response=asyncio.run(main.github_webhook(webhook(payload,event='pull_request'),BackgroundTasks()))
            self.assertTrue(json.loads(response.body)['queued'])
            self.assertEqual(submit.call_args.args[0],'user-1')
            self.assertTrue(callable(submit.call_args.args[1]))
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'), \
                patch.object(main,'GITHUB_PR_SCANS_ENABLED',True), \
                patch.object(main,'github_installation_entitlement',return_value={'allowed':False}), \
                patch.object(main.SCAN_JOBS,'submit') as submit:
            response=asyncio.run(main.github_webhook(webhook(payload,event='pull_request'),BackgroundTasks()))
            self.assertEqual(response.status_code,403)
            submit.assert_not_called()
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'), \
                patch.object(main,'GITHUB_PR_SCANS_ENABLED',True), \
                patch.object(main,'github_installation_entitlement',return_value={'allowed':True,'user_id':'user-1'}), \
                patch.object(main,'github_delivery_control',return_value={'accepted':True}) as delivery, \
                patch.object(main.SCAN_JOBS,'submit',side_effect=HTTPException(429,'queue full')):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.github_webhook(webhook(payload,event='pull_request'),BackgroundTasks()))
            self.assertEqual(caught.exception.status_code,429)
            self.assertEqual(delivery.call_args.args[2],'release')

    def test_duplicate_delivery_is_not_queued(self):
        payload={'action':'opened','installation':{'id':123},'repository':{'full_name':'owner/repo'},'number':7,'pull_request':{'head':{'sha':'a'*40}}}
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'), \
                patch.object(main,'GITHUB_PR_SCANS_ENABLED',True), \
                patch.object(main,'github_installation_entitlement',return_value={'allowed':True,'user_id':'user-1'}), \
                patch.object(main,'github_delivery_control',return_value={'accepted':False}), \
                patch.object(main.SCAN_JOBS,'submit') as submit:
            response=asyncio.run(main.github_webhook(webhook(payload,event='pull_request'),BackgroundTasks()))
            self.assertTrue(json.loads(response.body)['duplicate'])
            submit.assert_not_called()

    def test_pull_request_scans_are_paused_until_usage_rules_are_approved(self):
        payload={'action':'opened','installation':{'id':123},'repository':{'full_name':'owner/repo'},'number':7,'pull_request':{'head':{'sha':'a'*40}}}
        with patch.object(main,'GITHUB_WEBHOOK_SECRET','test-secret'),patch.object(main.SCAN_JOBS,'submit') as submit:
            response=asyncio.run(main.github_webhook(webhook(payload,event='pull_request'),BackgroundTasks()))
        self.assertEqual(response.status_code,503)
        self.assertEqual(json.loads(response.body)['reason'],'pull_request_scans_paused')
        submit.assert_not_called()

    def test_delivery_tracking_errors_fail_closed(self):
        with patch.object(main,'supabase_rest_request',return_value={}):
            with self.assertRaises(HTTPException) as caught:
                main.github_delivery_control('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd','reserve')
            self.assertEqual(caught.exception.status_code,503)
