"""Resolve entitlements from server-approved Stripe price IDs, never client metadata."""
def value(obj,key,default=None):
    if isinstance(obj,dict):return obj.get(key,default)
    return getattr(obj,key,default)


def subscription_items(subscription):
    return value(value(subscription,'items',{}),'data',[]) or []


def subscription_period_end(subscription):
    direct=value(subscription,'current_period_end')
    items=subscription_items(subscription)
    return direct or (value(items[0],'current_period_end') if len(items)==1 else None)


def subscription_plan(subscription,price_map):
    if value(subscription,'status') not in {'active','trialing','past_due'}:return 'free'
    items=subscription_items(subscription)
    if len(items)!=1:return 'free'
    price=value(items[0],'price',{})
    price_id=value(price,'id',price if isinstance(price,str) else '')
    plan=price_map.get(price_id)
    return plan if plan in {'pro','serious'} else 'free'
