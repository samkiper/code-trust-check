"""Choose a restricted portal catalog from verified Stripe subscription data."""
import json


def object_dict(value):
    return value.to_dict() if callable(getattr(value, 'to_dict', None)) else value


def select_configuration(subscription, customer, catalog, configured):
    subscription = object_dict(subscription)
    actual_customer = subscription.get('customer')
    if isinstance(actual_customer, dict):
        actual_customer = actual_customer.get('id')
    if actual_customer != customer:
        raise ValueError('Subscription ownership mismatch')
    # Cancellation, invoice and payment management must remain available even
    # when a tier change cannot safely be offered.
    if subscription.get('status') != 'active':
        return None
    invoice = subscription.get('latest_invoice')
    if not isinstance(invoice, dict) or invoice.get('status') != 'paid':
        return None
    items = subscription.get('items', {}).get('data', [])
    if len(items) != 1 or items[0].get('quantity', 1) != 1:
        return None
    price = items[0].get('price', {})
    price_id = price if isinstance(price, str) else price.get('id')
    matches = [x for x in catalog if x[4] and x[4] == price_id]
    if len(matches) != 1:
        return None
    _, interval, _, use, _ = matches[0]
    mappings = json.loads(configured or '{}')
    config_id = mappings.get(f'{use}:{interval}')
    if not isinstance(config_id, str) or not config_id.startswith('bpc_'):
        return None
    prices = {x[4] for x in catalog if x[1] == interval and x[3] == use and x[4]}
    if len(prices) != 2:
        return None
    return config_id, prices


def validate_configuration(configuration, expected_prices):
    config = object_dict(configuration)
    update = config.get('features', {}).get('subscription_update', {})
    allowed = {p for product in update.get('products', []) for p in product.get('prices', [])}
    if not (config.get('active') and config.get('livemode')
            and update.get('enabled') and update.get('billing_cycle_anchor') == 'unchanged'
            and update.get('default_allowed_updates') == ['price']
            and update.get('proration_behavior') == 'always_invoice'
            and not update.get('schedule_at_period_end', {}).get('conditions')
            and allowed == expected_prices):
        raise ValueError('Portal catalog requires verification')
    return config['id']
