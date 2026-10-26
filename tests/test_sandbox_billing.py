import copy, hashlib, hmac, json, os, time, unittest
from unittest.mock import patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
import main
from sandbox_billing import subscription_update

class SandboxBillingTests(unittest.TestCase):
 def event(self,status='active',created=100,event_id='evt_1'):
  return {'id':event_id,'created':created,'livemode':False,'type':'customer.subscription.updated','data':{'object':{'id':'sub_test','object':'subscription','livemode':False,'customer':'cus_test','status':status,'items':{'data':[{'price':{'id':'price_test'},'current_period_end':200}]}}}}
 def update(self,event,user=None):
  return subscription_update(event,user or {'app_metadata':{}},'cus_test','price_test',main.plan_from_subscription_status)
 def test_lifecycle_and_nested_period(self):
  for status,plan in [('active','pro'),('past_due','pro'),('unpaid','free'),('canceled','free')]:
   result=self.update(self.event(status)); self.assertEqual(result['plan'],plan);self.assertEqual(result['sandbox_current_period_end'],200)
   self.assertNotIn('stripe_subscription_id',result)
 def test_scope_and_live_account_protection(self):
  event=self.event();event['data']['object']['customer']='cus_other';self.assertIsNone(self.update(event))
  for modify in ['live_event','live_object','price','admin','live_customer']:
   event=self.event();user={'app_metadata':{}}
   if modify=='live_event':event['livemode']=True
   if modify=='live_object':event['data']['object']['livemode']=True
   if modify=='price':event['data']['object']['items']['data'][0]['price']['id']='other'
   if modify=='admin':user['app_metadata']['role']='admin'
   if modify=='live_customer':user['app_metadata']['stripe_customer_id']='cus_live'
   with self.subTest(modify=modify),self.assertRaises(HTTPException):self.update(event,user)
 def test_duplicate_stale_and_canceled_events_do_not_restore_access(self):
  for meta in [{'sandbox_event_id':'evt_1'},{'sandbox_event_created':101},{'sandbox_subscription_id':'sub_test','sandbox_subscription_status':'canceled'}]:
   self.assertIsNone(self.update(self.event(),{'app_metadata':meta}))
 def test_signed_endpoint_and_persistence_retry(self):
  env={'STRIPE_SANDBOX_WEBHOOK_SECRET':'whsec_unit_test','STRIPE_SANDBOX_TEST_USER_ID':'user_test','STRIPE_SANDBOX_CUSTOMER_ID':'cus_test','STRIPE_SANDBOX_PRICE_ID':'price_test','STRIPE_SANDBOX_PLAN':'pro'}
  body=json.dumps(self.event()).encode();stamp=int(time.time());sig=hmac.new(env['STRIPE_SANDBOX_WEBHOOK_SECRET'].encode(),str(stamp).encode()+b'.'+body,hashlib.sha256).hexdigest()
  with patch.dict(os.environ,env),patch.object(main,'get_supabase_admin_user',return_value={'id':'user_test','app_metadata':{}}),patch.object(main,'update_supabase_user_app_metadata',return_value=True) as save:
   client=TestClient(main.app)
   self.assertEqual(client.post('/stripe/sandbox-webhook',content=body).status_code,400);save.assert_not_called()
   headers={'stripe-signature':f't={stamp},v1={sig}'}
   self.assertEqual(client.post('/stripe/sandbox-webhook',content=body,headers=headers).status_code,200)
   save.assert_called_once();self.assertEqual(save.call_args.args[0],'user_test')
   save.return_value=False
   self.assertEqual(client.post('/stripe/sandbox-webhook',content=body,headers=headers).status_code,503)
 def test_endpoint_disabled_by_default(self):
  with patch.dict(os.environ,{'STRIPE_SANDBOX_WEBHOOK_SECRET':''}):
   self.assertEqual(TestClient(main.app).post('/stripe/sandbox-webhook',content=b'{}').status_code,503)
