import asyncio
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch
from fastapi import BackgroundTasks, HTTPException
from starlette.requests import Request
import main


def webhook(payload, secret="test-secret", signature=None):
    raw=json.dumps(payload).encode()
    signature=signature or "sha256="+hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
    async def receive(): return {"type":"http.request","body":raw,"more_body":False}
    return Request({"type":"http","method":"POST","path":"/github/webhook","headers":[(b"x-github-event",b"installation"),(b"x-hub-signature-256",signature.encode())]},receive)


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
