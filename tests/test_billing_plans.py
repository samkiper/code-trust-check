import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from billing_plans import subscription_plan,subscription_period_end
from sandbox_billing import subscription_update
import main

def checkout_price(price_id, **kwargs):
    serious='serious' in price_id or price_id=='price_annual'
    annual='year' in price_id or 'annual' in price_id
    business='business' in price_id
    return {'active':True,'livemode':True,'unit_amount':(69000 if annual else 6900) if serious else (19000 if annual else 1900),
            'currency':'usd','tax_behavior':'exclusive','recurring':{'interval':'year' if annual else 'month','interval_count':1},
            'product':{'active':True,'tax_code':'txcd_10103001' if business else 'txcd_10103000'}}

class PriceEntitlementTests(unittest.TestCase):
    def setUp(self):
        self.price_patch=patch.object(main.stripe.Price,'retrieve',side_effect=checkout_price)
        self.price_patch.start();self.addCleanup(self.price_patch.stop)

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
    def test_annual_pro_maps_to_pro_and_is_offered(self):
        access={'authenticated':True,'user_id':'test','email':'test@example.com','plan':'free','role':'user'}
        with patch.object(main,'STRIPE_PRICE_ID','price_pro'),patch.object(main,'PURCHASES_ENABLED',True),patch.dict(os.environ,{'STRIPE_PRO_ANNUAL_PRICE_ID':'price_pro_year'}):
            self.assertEqual(main.plan_for_stripe_subscription(self.sub('price_pro_year')),'pro')
            self.assertIn({'plan':'pro','interval':'year','amount':19000,'controlled':False,'use':'personal'},main.checkout_offers(access))
    def test_pro_annual_checkout_uses_server_price(self):
        access={'authenticated':True,'user_id':'test','email':'test@example.com','plan':'free','role':'user'}
        with patch.dict(os.environ,{'STRIPE_PRO_ANNUAL_PRICE_ID':'price_pro_year'}),patch.object(main,'PURCHASES_ENABLED',True),patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'get_request_access_context',return_value=access),patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x),patch.object(main,'enforce_rate_limit'),patch.object(main,'get_supabase_admin_user',return_value={}),patch.object(main.stripe.checkout.Session,'create',return_value=type('Session',(),{'url':'https://checkout.stripe.com/c/test','id':'cs_test_reference'})()) as create:
            response=TestClient(main.app).post('/stripe/create-checkout-session',json={'use':'personal','plan':'pro','interval':'year','price':'attacker_price'})
            self.assertEqual(response.status_code,200)
            self.assertEqual(create.call_args.kwargs['line_items'],[{'price':'price_pro_year','quantity':1}])
    def test_production_and_sandbox_share_serious_mapping(self):
        with patch.object(main,'STRIPE_PRICE_ID','price_pro'),patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious','STRIPE_SERIOUS_ANNUAL_PRICE_ID':'price_annual'}):
            for price in ['price_serious','price_annual']:
                self.assertEqual(main.plan_for_stripe_subscription(self.sub(price)),'serious')
            obj={**self.sub('price_serious'),'id':'sub_test','object':'subscription','livemode':False,'customer':'cus_test'}
            event={'id':'evt_test','created':1,'type':'customer.subscription.created','livemode':False,'data':{'object':obj}}
            self.assertEqual(subscription_update(event,{'app_metadata':{}},'cus_test','price_serious',main.plan_from_subscription_status,paid_plan='serious')['plan'],'serious')
    def test_signed_subscription_webhook_uses_price_not_claimed_plan(self):
        for price,expected in [('price_serious','serious'),('price_pro','pro'),('unknown','free')]:
            event={'type':'customer.subscription.updated','data':{'object':{**self.sub('stale_price'),'id':'sub_test','customer':'cus_test','metadata':{'user_id':'test','plan':'serious'}}}}
            with patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious'}),patch.object(main,'STRIPE_PRICE_ID','price_pro'),patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'STRIPE_WEBHOOK_SECRET','test'),patch.object(main.stripe.Webhook,'construct_event',return_value=event),patch.object(main,'get_supabase_admin_user',return_value={'id':'test'}),patch.object(main.stripe.Subscription,'retrieve',return_value=self.sub(price)),patch.object(main,'sync_user_plan_from_subscription',return_value=True) as save:
                self.assertEqual(TestClient(main.app).post('/stripe/webhook',content=b'{}').status_code,200)
                self.assertEqual(save.call_args.kwargs['plan'],expected)
    def test_serious_checkout_selects_only_server_price(self):
        access={'authenticated':True,'user_id':'test','email':'test@example.com','plan':'free','role':'user'}
        with patch.dict(os.environ,{'STRIPE_SERIOUS_PRICE_ID':'price_serious','STRIPE_SERIOUS_ANNUAL_PRICE_ID':'price_annual'}),patch.object(main,'PURCHASES_ENABLED',True),patch.object(main,'STRIPE_SECRET_KEY','test'),patch.object(main,'get_request_access_context',return_value=access),patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x),patch.object(main,'enforce_rate_limit'),patch.object(main,'get_supabase_admin_user',return_value={}),patch.object(main.stripe.checkout.Session,'create',return_value=type('Session',(),{'url':'https://checkout.stripe.com/c/test','id':'cs_test_reference'})()) as create:
            client=TestClient(main.app)
            for interval,price in [('month','price_serious'),('year','price_annual')]:
                r=client.post('/stripe/create-checkout-session',json={'use':'personal','plan':'serious','interval':interval,'price':'attacker_price','amount':1})
                self.assertEqual(r.status_code,200);self.assertEqual(create.call_args.kwargs['line_items'],[{'price':price,'quantity':1}])
            self.assertEqual(client.post('/stripe/create-checkout-session',json={'plan':'admin'}).status_code,400)


class ScheduledCancellationTests(unittest.TestCase):
    def test_explicit_cancel_date_takes_precedence(self):
        from billing_plans import subscription_cancellation
        subscription = {'cancel_at_period_end': False, 'cancel_at': 250, 'items': {'data': [{'current_period_end': 300}]}}
        self.assertEqual(subscription_cancellation(subscription), (True, 250))

    def test_period_end_and_uncanceled_subscription(self):
        from billing_plans import subscription_cancellation
        self.assertEqual(subscription_cancellation({'cancel_at_period_end': True, 'current_period_end': 300}), (True, 300))
        self.assertEqual(subscription_cancellation({'cancel_at': None, 'current_period_end': 300}), (False, 300))

class PurchaseUseTests(unittest.TestCase):
    setUp = PriceEntitlementTests.setUp
    sub = PriceEntitlementTests.sub

    def checkout_context(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        stack=ExitStack(); self.addCleanup(stack.close)
        access={'authenticated':True,'user_id':'test','email':'test@example.com','plan':'free','role':'user'}
        for name,value in [('get_request_access_context',access),('get_supabase_admin_user',{}),('enforce_rate_limit',None)]:
            stack.enter_context(patch.object(main,name,return_value=value))
        stack.enter_context(patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x))
        stack.enter_context(patch.object(main,'STRIPE_SECRET_KEY','test'))
        stack.enter_context(patch.object(main,'STRIPE_PRICE_ID','price_pro'))
        stack.enter_context(patch.object(main,'PURCHASES_ENABLED',True))
        stack.enter_context(patch.dict(os.environ,{
            'STRIPE_PRO_ANNUAL_PRICE_ID':'price_pro_year',
            'STRIPE_SERIOUS_PRICE_ID':'price_serious', 'STRIPE_SERIOUS_ANNUAL_PRICE_ID':'price_serious_year',
            'STRIPE_PRO_BUSINESS_PRICE_ID':'price_pro_business', 'STRIPE_PRO_BUSINESS_ANNUAL_PRICE_ID':'price_pro_business_year',
            'STRIPE_SERIOUS_BUSINESS_PRICE_ID':'price_serious_business', 'STRIPE_SERIOUS_BUSINESS_ANNUAL_PRICE_ID':'price_serious_business_year'}))
        create=stack.enter_context(patch.object(main.stripe.checkout.Session,'create',return_value=SimpleNamespace(url='https://checkout.stripe.com/c/test',id='cs_test_reference')))
        return TestClient(main.app),create,access

    def test_both_uses_select_exact_prices_and_preserve_entitlements(self):
        client,create,access=self.checkout_context()
        self.assertEqual(len(main.checkout_offers(access)),8)
        for plan in ('pro','serious'):
            for interval in ('month','year'):
                for use in ('personal','business'):
                    with self.subTest(plan=plan,interval=interval,use=use):
                        response=client.post('/stripe/create-checkout-session',json={'plan':plan,'interval':interval,'use':use,'price':'attacker','tax_code':'txcd_00000000'})
                        self.assertEqual(response.status_code,200)
                        args=create.call_args.kwargs
                        selected=f'price_{plan}'+('_business' if use=='business' else '')+('_year' if interval=='year' else '')
                        self.assertEqual(args['line_items'],[{'price':selected,'quantity':1}])
                        self.assertEqual(args['metadata']['purchase_use'],use)
                        self.assertEqual(args['subscription_data']['metadata']['purchase_use'],use)
                        self.assertEqual(args['automatic_tax'],{'enabled':True})
                        self.assertEqual(main.plan_for_stripe_subscription(self.sub(selected)),plan)

    def test_missing_unknown_or_unconfigured_use_never_creates_a_session(self):
        client,create,_=self.checkout_context()
        for use in (None,'exempt','PERSONAL',{},True):
            # Invalid unhashable input must be a customer 400, never a server exception.
            response=client.post('/stripe/create-checkout-session',json={'use':use})
            self.assertEqual(response.status_code,400)
        for field in ('plan','interval'):
            for value in ({},[],True):
                self.assertEqual(client.post('/stripe/create-checkout-session',json={'use':'personal',field:value}).status_code,400)
        with patch.dict(os.environ,{'STRIPE_PRO_BUSINESS_PRICE_ID':''}):
            self.assertEqual(client.post('/stripe/create-checkout-session',json={'use':'business'}).status_code,503)
        create.assert_not_called()

    def test_misconfigured_price_or_tax_category_fails_closed(self):
        client,create,_=self.checkout_context()
        original=checkout_price('price_pro_business')
        for bad in ({**original,'product':{'active':True,'tax_code':'txcd_10103000'}},
                    {**original,'tax_behavior':'inclusive'}, {**original,'unit_amount':1},
                    {**original,'livemode':False}, {**original,'active':False},
                    {**original,'product':{'active':False,'tax_code':'txcd_10103001'}}):
            with self.subTest(price=bad),patch.object(main.stripe.Price,'retrieve',return_value=bad):
                self.assertEqual(client.post('/stripe/create-checkout-session',json={'use':'business'}).status_code,503)
        create.assert_not_called()


class ReturningBusinessCustomerTests(unittest.TestCase):
    setUp = PriceEntitlementTests.setUp
    checkout_context = PurchaseUseTests.checkout_context
    def test_existing_customer_collects_business_name_only_for_business_use(self):
        client,create,_=self.checkout_context()
        with patch.object(main,'get_supabase_admin_user',return_value={'app_metadata':{'stripe_customer_id':'cus_returning'}}):
            for use in ('personal','business'):
                response=client.post('/stripe/create-checkout-session',json={'use':use})
                self.assertEqual(response.status_code,200)
                args=create.call_args.kwargs
                self.assertEqual(args['customer'],'cus_returning')
                self.assertNotIn('customer_email',args)
                self.assertEqual(args['tax_id_collection'],{'enabled':use=='business'})
                expected={'address':'auto'}
                if use=='business':expected['name']='auto'
                self.assertEqual(args['customer_update'],expected)
