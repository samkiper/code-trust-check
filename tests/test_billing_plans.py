import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from billing_plans import subscription_plan,subscription_period_end
from sandbox_billing import subscription_update
import main

class PriceEntitlementTests(unittest.TestCase):
    def sub(self,price,status='active'):
        return {'status':status,'items':{'data':[{'price':{'id':price},'current_period_end':2000000000}]},'metadata':{'plan':'admin'}}
    def test_exact_prices_choose_plan_and_metadata_cannot_elevate(self):
        prices={'price_pro':'pro','price_serious':'serious','price_annual':'serious'}
        for price,plan in [*prices.items(),('unknown','free')]:
            self.assertEqual(subscription_plan(self.sub(price),prices),plan)
        self.assertEqual(subscription_plan({'status':'active'},prices),'free')
        double=self.sub('price_pro');double['items']['data']*=2
        self.assertEqual(subscription_plan(double,prices),'free')
    def test_cancel_and_failure_remove_both_paid_tiers(self):
        for price in ['price_pro','price_serious']:
            for status in ['canceled','unpaid','incomplete','incomplete_expired','paused','unknown']:
                self.assertEqual(subscription_plan(self.sub(price,status),{'price_pro':'pro','price_serious':'serious'}),'free')
    def test_flexible_billing_item_period_is_read(self):
        self.assertEqual(subscription_period_end(self.sub('price_serious')),2000000000)
    def test_production_and_sandbox_share_serious_mapping(self):
        with patch.object(main,'STRIPE_PRICE_ID','price_pro'),patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious','STRIPE_SERIOUS_ANNUAL_PRICE_ID':'price_annual'}):
            for price in ['price_serious','price_annual']:
                self.assertEqual(main.plan_for_stripe_subscription(self.sub(price)),'serious')
            obj={**self.sub('price_serious'),'id':'sub_test','object':'subscription','livemode':False,'customer':'cus_test'}
            event={'id':'evt_test','created':1,'type':'customer.subscription.created','livemode':False,'data':{'object':obj}}
            self.assertEqual(subscription_update(event,{'app_metadata':{}},'cus_test','price_serious',main.plan_from_subscription_status,paid_plan='serious')['plan'],'serious')
    def test_signed_subscription_webhook_uses_price_not_claimed_plan(self):
        for price,expected in [('price_serious','serious'),('price_pro','pro'),('unknown','free')]:
            event={'type':'customer.subscription.updated','data':{'object':{**self.sub(price),'id':'sub_test','customer':'cus_test','metadata':{'user_id':'test','plan':'serious'}}}}
            with patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious'}),patch.object(main,'STRIPE_PRICE_ID','price_pro'),patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'STRIPE_WEBHOOK_SECRET','test'),patch.object(main.stripe.Webhook,'construct_event',return_value=event),patch.object(main,'sync_user_plan_from_subscription',return_value=True) as save:
                self.assertEqual(TestClient(main.app).post('/stripe/webhook',content=b'{}').status_code,200)
                self.assertEqual(save.call_args.kwargs['plan'],expected)
    def test_serious_checkout_selects_only_server_price(self):
        access={'authenticated':True,'user_id':'test','email':'test@example.com','plan':'free','role':'user'}
        with patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious','STRIPE_SERIOUS_ANNUAL_PRICE_ID':'price_annual'}),patch.object(main,'PURCHASES_ENABLED',True),patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'get_request_access_context',return_value=access),patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x),patch.object(main,'enforce_rate_limit'),patch.object(main,'get_supabase_admin_user',return_value={}),patch.object(main.stripe.checkout.Session,'create',return_value=type('Session',(),{'url':'https://checkout.stripe.com/c/test','id':'cs_test_reference'})()) as create:
            client=TestClient(main.app)
            for interval,price in [('month','price_serious'),('year','price_annual')]:
                r=client.post('/stripe/create-checkout-session',json={'plan':'serious','interval':interval,'price':'attacker_price','amount':1})
                self.assertEqual(r.status_code,200);self.assertEqual(create.call_args.kwargs['line_items'],[{'price':price,'quantity':1}])
            self.assertEqual(client.post('/stripe/create-checkout-session',json={'plan':'admin'}).status_code,400)
