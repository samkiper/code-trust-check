import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from starlette.requests import Request
import main

class BillingMigrationTests(unittest.TestCase):
 def test_return_origin_allowlist(self):
  def req(origin): return Request({'type':'http','headers':[(b'x-audit-return-origin',origin.encode())]})
  with patch.object(main,'APP_BASE_URL','https://code-trust-check.onrender.com'):
   self.assertEqual(main.get_billing_return_url(req('https://ai-code-audit.samkiper.chatgpt.site')),'https://ai-code-audit.samkiper.chatgpt.site')
   for origin in ['https://evil.example','https://ai-code-audit.samkiper.chatgpt.site.evil.example','https://ai-code-audit.samkiper.chatgpt.site@evil.example']:
    self.assertEqual(main.get_billing_return_url(req(origin)),'https://code-trust-check.onrender.com')
 def webhook(self,payment='paid',failure=False):
  event={'type':'checkout.session.completed','data':{'object':{'payment_status':payment,'subscription':'sub_existing','customer':'cus_existing','metadata':{'user_id':'user'}}}}
  with patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'STRIPE_WEBHOOK_SECRET','test'),patch.object(main.stripe.Webhook,'construct_event',return_value=event),patch.object(main,'resolve_supabase_user_id_for_stripe_event',return_value='user'),patch.object(main.stripe.Subscription,'retrieve',side_effect=RuntimeError('offline') if failure else None,return_value={'status':'active'}),patch.object(main,'sync_user_plan_from_subscription',return_value=True) as sync:
   result=TestClient(main.app).post('/stripe/webhook',content=b'{}')
   return result,sync.call_count
 def test_unpaid_checkout_does_not_grant_access(self):
  response,calls=self.webhook(payment='unpaid');self.assertEqual(response.status_code,200);self.assertEqual(calls,0)
 def test_lookup_failure_retries_without_grant(self):
  response,calls=self.webhook(failure=True);self.assertEqual(response.status_code,503);self.assertEqual(calls,0)
 def test_verified_paid_checkout_syncs(self):
  response,calls=self.webhook();self.assertEqual(response.status_code,200);self.assertEqual(calls,1)
