"""Opt-in server-process checkout validation; never completes a payment.

Exercises the actual route and Stripe SDK using an explicitly selected existing
Free test account. Authentication is a local fixture; this is not a browser/auth
end-to-end test. No web listener starts and public purchase settings never change.
Created sessions are expired immediately. Never prints their URLs or secrets.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def verify_session(session, customer, price, use):
    assert session['livemode'] and session['status'] == 'open'
    assert session['mode'] == 'subscription' and session['subscription'] is None
    assert session['customer'] == customer
    assert session['automatic_tax']['enabled'] is True
    assert session['billing_address_collection'] == 'required'
    assert session['tax_id_collection']['enabled'] == (use == 'business')
    assert session['metadata']['purchase_use'] == use
    lines = session['line_items']['data']
    assert len(lines) == 1 and lines[0]['quantity'] == 1
    assert lines[0]['price']['id'] == price


def expire_pending(api, pending):
    failures = []
    for sid in list(pending):
        try:
            result = api.expire(sid)
            assert result['status'] == 'expired' and result['subscription'] is None
            pending.remove(sid)
        except Exception:
            failures.append(sid)
    return failures


def execute(uid):
    import main
    from fastapi.testclient import TestClient
    assert not main.PURCHASES_ENABLED and not main.CONTROLLED_CHECKOUT_USER_ID
    assert main.stripe.Account.retrieve()['id'] == 'acct_1TBrsAEEE0WuIMoR'
    user = main.get_supabase_admin_user(uid)
    assert user and user['id'] == uid and user.get('email')
    original = user.get('app_metadata') or {}
    assert original.get('plan') == 'free' and original.get('role', 'user') == 'user'
    assert original.get('stripe_subscription_status') == 'canceled'
    customer = original.get('stripe_customer_id')
    assert customer
    choices = main.configured_checkout_prices()
    assert len(choices) == 8 and all(row[4] for row in choices)
    assert len({row[4] for row in choices}) == 8
    access = {'authenticated': True, 'user_id': uid, 'email': user['email'], 'plan': 'free', 'role': 'user'}
    api = main.stripe.checkout.Session
    real_create = api.create
    pending, passed = [], []
    result = {'status': 'not_passed', 'scope': 'real_route_and_live_stripe_with_local_auth_fixture'}

    def capture(**kwargs):
        session = real_create(**kwargs)
        pending.append(session.id)
        return session

    try:
        with patch.object(main, 'get_request_access_context', return_value=access), \
             patch.object(main, 'CONTROLLED_CHECKOUT_USER_ID', uid), \
             patch.object(main, 'CONTROLLED_CHECKOUT_EXPIRES_AT', str(int(time.time()) + 600)), \
             patch.object(api, 'create', side_effect=capture):
            client = TestClient(main.app)
            for plan, interval, amount, use, price in choices:
                with patch.dict(os.environ, {'CONTROLLED_CHECKOUT_PLAN': plan, 'CONTROLLED_CHECKOUT_INTERVAL': interval, 'CONTROLLED_CHECKOUT_USE': use}):
                    response = client.post('/stripe/create-checkout-session', json={'plan': plan, 'interval': interval, 'use': use})
                    assert response.status_code == 200, f'{plan}/{interval}/{use}: HTTP {response.status_code}'
                    sid = response.json()['session_id']
                    session = api.retrieve(sid, expand=['line_items'])
                    verify_session(session, customer, price, use)
                    assert session['amount_subtotal'] == amount
                    assert not expire_pending(api, pending), 'Session expiration not confirmed.'
                    passed.append({'plan': plan, 'interval': interval, 'use': use, 'session_id': sid, 'status': 'expired'})
        assert main.get_supabase_admin_user(uid).get('app_metadata') == original
        assert not main.PURCHASES_ENABLED and not main.CONTROLLED_CHECKOUT_USER_ID
        result['status'] = 'passed'
    except Exception as exc:
        result['error_type'] = type(exc).__name__
    finally:
        result['cleanup_unconfirmed_session_ids'] = expire_pending(api, pending)
        if result['cleanup_unconfirmed_session_ids']:
            result['status'] = 'not_passed'
        result['checks'] = passed
        print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-live', action='store_true')
    parser.add_argument('--user-id', required=True)
    args = parser.parse_args()
    if not args.run_live:
        parser.error('Requires --run-live; sessions are immediately expired, never paid.')
    raise SystemExit(execute(args.user_id))
