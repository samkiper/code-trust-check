"""Opt-in signed subscription snapshots for a single private-validation identity.

No Stripe API credentials or live billing identifiers are used by this adapter.
Disable by removing STRIPE_SANDBOX_WEBHOOK_SECRET after validation.
"""
from fastapi import HTTPException

EVENTS = {'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted'}

def subscription_update(event, user, customer_id, price_id, plan_for_status):
    if event.get('livemode') is not False:
        raise HTTPException(400, 'Sandbox events only.')
    if event.get('type') not in EVENTS:
        return None
    obj = event.get('data', {}).get('object', {})
    if obj.get('customer') != customer_id:
        return None
    if obj.get('livemode') is not False or obj.get('object') != 'subscription':
        raise HTTPException(400, 'Invalid sandbox subscription.')
    meta = user.get('app_metadata') or {}
    if meta.get('role') == 'admin' or meta.get('stripe_subscription_id') or meta.get('stripe_customer_id'):
        raise HTTPException(409, 'Sandbox validation cannot modify an administrator or live billing account.')
    items = obj.get('items', {}).get('data', [])
    if len(items) != 1 or items[0].get('price', {}).get('id') != price_id:
        raise HTTPException(400, 'Unexpected sandbox price.')
    created = event.get('created')
    if not isinstance(created, int) or not event.get('id') or not obj.get('id'):
        raise HTTPException(400, 'Invalid sandbox event.')
    if created < meta.get('sandbox_event_created', 0) or event['id'] == meta.get('sandbox_event_id'):
        return None
    # Delayed updates must never revive the same canceled test subscription.
    if meta.get('sandbox_subscription_id') == obj['id'] and meta.get('sandbox_subscription_status') == 'canceled':
        return None
    status = 'canceled' if event['type'] == 'customer.subscription.deleted' else obj.get('status', '')
    period = obj.get('current_period_end') or items[0].get('current_period_end')
    cancel = bool(obj.get('cancel_at_period_end'))
    return {'plan': plan_for_status(status, cancel_at_period_end=cancel, current_period_end=period),
            'sandbox_subscription_id': obj['id'], 'sandbox_subscription_status': status,
            'sandbox_cancel_at_period_end': cancel, 'sandbox_current_period_end': period,
            'sandbox_event_id': event['id'], 'sandbox_event_created': created}
