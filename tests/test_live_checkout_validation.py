import unittest
import stripe
from unittest.mock import Mock
from scripts.live_checkout_validation import expire_pending, verify_session


class LiveCheckoutValidationTests(unittest.TestCase):
    def test_cleanup_retries_only_unconfirmed_sessions(self):
        api = Mock()
        api.expire.side_effect = [{'status':'expired','subscription':None}, RuntimeError('unavailable')]
        pending = ['cs_a','cs_b']
        self.assertEqual(expire_pending(api,pending), ['cs_b'])
        self.assertEqual(pending, ['cs_b'])
        api.expire.side_effect = None
        api.expire.return_value = {'status':'expired','subscription':None}
        self.assertEqual(expire_pending(api,pending), [])
        self.assertEqual(pending, [])
        self.assertEqual([c.args[0] for c in api.expire.call_args_list], ['cs_a','cs_b','cs_b'])

    def test_completed_session_and_wrong_price_never_pass(self):
        session = {'livemode':True,'status':'open','mode':'subscription','subscription':None,
                   'customer':'cus_test','automatic_tax':{'enabled':True},'billing_address_collection':'required',
                   'tax_id_collection':{'enabled':True},'metadata':{'purchase_use':'business'},
                   'line_items':{'data':[{'quantity':1,'price':{'id':'price_test'}}]}}
        verify_session(session,'cus_test','price_test','business')
        verify_session(stripe.StripeObject.construct_from(session, None),'cus_test','price_test','business')
        for changed in ({'status':'complete'}, {'subscription':'sub_unexpected'}, {'customer':'cus_wrong'}, {'automatic_tax':{'enabled':False}}):
            with self.assertRaises(AssertionError):
                verify_session({**session,**changed},'cus_test','price_test','business')
        with self.assertRaises(AssertionError):
            verify_session(session,'cus_test','wrong','business')

    def test_omitted_tax_id_collection_is_valid_only_for_personal_use(self):
        session = {'livemode':True,'status':'open','mode':'subscription','subscription':None,
                   'customer':'cus_test','automatic_tax':{'enabled':True},'billing_address_collection':'required',
                   'metadata':{'purchase_use':'personal'},
                   'line_items':{'data':[{'quantity':1,'price':{'id':'price_test'}}]}}
        for collection in ({}, {'tax_id_collection':None}, {'tax_id_collection':{'enabled':False}}):
            for convert in (lambda value: value, lambda value: stripe.StripeObject.construct_from(value, None)):
                verify_session(convert({**session, **collection}),'cus_test','price_test','personal')
                with self.assertRaises(AssertionError):
                    verify_session(convert({**session, **collection, 'metadata':{'purchase_use':'business'}}),'cus_test','price_test','business')
