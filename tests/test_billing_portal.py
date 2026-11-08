import json
import unittest
import stripe
from billing_portal import select_configuration, validate_configuration


class RestrictedPortalTests(unittest.TestCase):
    def setUp(self):
        self.catalog = [(plan, term, 1, use, f'price_{plan}_{term}_{use}')
                        for plan in ('pro', 'serious') for term in ('month', 'year')
                        for use in ('personal', 'business')]
        self.configured = json.dumps({f'{use}:{term}': f'bpc_{use}_{term}'
                                     for use in ('personal', 'business') for term in ('month', 'year')})

    def sub(self, price):
        return {'customer': 'cus_owner', 'status': 'active', 'latest_invoice': {'status': 'paid'},
                'items': {'data': [{'quantity': 1, 'price': {'id': price}}]}}

    def test_all_eight_prices_keep_interval_and_tax_category(self):
        for plan, term, amount, use, price in self.catalog:
            subscription = stripe.StripeObject.construct_from(self.sub(price), 'fixture')
            config, allowed = select_configuration(subscription, 'cus_owner', self.catalog, self.configured)
            self.assertEqual(config, f'bpc_{use}_{term}')
            self.assertEqual(allowed, {f'price_pro_{term}_{use}', f'price_serious_{term}_{use}'})

    def test_other_customer_is_rejected_and_unknown_subscription_is_management_only(self):
        with self.assertRaises(ValueError):
            select_configuration(self.sub('price_pro_month_personal'), 'cus_attacker', self.catalog, self.configured)
        self.assertIsNone(select_configuration(self.sub('unknown'), 'cus_owner', self.catalog, self.configured))
        sub = self.sub('price_pro_month_personal'); sub['status'] = 'canceled'
        self.assertIsNone(select_configuration(sub, 'cus_owner', self.catalog, self.configured))
        sub['status'] = 'active'; sub['latest_invoice']['status'] = 'open'
        self.assertIsNone(select_configuration(sub, 'cus_owner', self.catalog, self.configured))

    def test_tampered_catalog_or_anchor_fails_closed(self):
        config = {'id': 'bpc_fixture', 'active': True, 'livemode': True, 'features': {'subscription_update': {
            'enabled': True, 'billing_cycle_anchor': 'unchanged', 'default_allowed_updates': ['price'],
            'proration_behavior': 'always_invoice', 'schedule_at_period_end': {'conditions': []},
            'products': [{'prices': ['price_pro', 'price_serious']}]}}}
        self.assertEqual(validate_configuration(stripe.StripeObject.construct_from(config, 'fixture'),
                                                {'price_pro', 'price_serious'}), 'bpc_fixture')
        for field, value in [('billing_cycle_anchor', 'now'), ('default_allowed_updates', ['price', 'quantity']),
                             ('products', [{'prices': ['price_pro', 'price_other_tax']}]),
                             ('schedule_at_period_end', {'conditions': [{'type': 'decreasing_item_amount'}]})]:
            altered = json.loads(json.dumps(config)); altered['features']['subscription_update'][field] = value
            with self.assertRaises(ValueError):
                validate_configuration(altered, {'price_pro', 'price_serious'})
