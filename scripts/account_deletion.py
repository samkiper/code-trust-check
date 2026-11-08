"""Operator-only, two-phase deletion after independently verifying the requester.

Dry-run is the default. Does not cancel or charge subscriptions. See the runbook.
Run inside the trusted backend environment; never provide keys on the command line.
"""
import argparse
import datetime as dt
import json
import sys
import uuid
import urllib.error
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main

QUIET_SECONDS = 8 * 60 * 60  # exceeds GitHub OAuth cache and job/result lifetimes


def inspect_account(user_id):
    user_id = str(uuid.UUID(user_id))
    user = main.get_supabase_admin_user(user_id)
    if not user or user.get('id') != user_id:
        raise RuntimeError('Account lookup failed; no deletion performed')
    meta = user.get('app_metadata') or {}
    if meta.get('role') == 'admin':
        raise RuntimeError('Do not delete an administrator through this workflow')
    customer = meta.get('stripe_customer_id')
    subscriptions = []
    if customer:
        # List all, not only the last ID in account metadata. API failure aborts.
        for item in main.stripe.Subscription.list(customer=customer, status='all', limit=100).auto_paging_iter():
            item = item.to_dict() if hasattr(item, 'to_dict') else item
            subscriptions.append(item)
    if any(s.get('status') not in {'canceled', 'incomplete_expired'} for s in subscriptions):
        raise RuntimeError('Resolve existing Stripe subscriptions before deletion; cancellation/refund is a separate confirmed action')
    if not customer and meta.get('stripe_subscription_id'):
        raise RuntimeError('Billing metadata needs reconciliation before deletion')
    return user


def perform(user_id, action='inspect', confirmed_user=None, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    user = inspect_account(user_id)
    meta = dict(user.get('app_metadata') or {})
    if action == 'inspect':
        return {'action': 'inspection_only', 'billing_resolved': True,
                'deletion_prepared': bool(meta.get('deletion_requested_at'))}
    if confirmed_user != user['id']:
        raise RuntimeError('Exact --confirm-user UUID is required')
    if action == 'prepare':
        meta.setdefault('deletion_requested_at', now.isoformat())
        response = main.supabase_auth_admin_request('PUT', f"users/{user['id']}",
            {'app_metadata': meta, 'ban_duration': '876000h'})
        if response.get('id') != user['id'] or not response.get('banned_until'):
            raise RuntimeError('Account quarantine was not confirmed')
        return {'action': 'quarantined', 'earliest_finalization':
                (dt.datetime.fromisoformat(meta['deletion_requested_at']) + dt.timedelta(seconds=QUIET_SECONDS)).isoformat()}
    if action != 'finalize':
        raise ValueError('Unknown action')
    prepared = dt.datetime.fromisoformat(meta.get('deletion_requested_at') or '')
    if prepared.tzinfo is None or (now-prepared).total_seconds() < QUIET_SECONDS:
        raise RuntimeError('Quarantine must complete before finalization')
    if not user.get('banned_until') or dt.datetime.fromisoformat(user['banned_until'].replace('Z','+00:00')) <= now:
        raise RuntimeError('Account ban is not active')
    # Auth admin deletion removes refresh sessions; every application request
    # revalidates with Auth. The private DB trigger cleans non-cascading rows.
    # Auth returns an empty object on successful deletion. The legacy request
    # helper also returns {} on errors, so require strict HTTP handling and an
    # independent, explicit user_not_found response before reporting success.
    path = f"users/{user['id']}"
    main.supabase_auth_admin_request('DELETE', path, raise_errors=True)
    verify_account_absent(user['id'])
    return {'action': 'deleted', 'retained': 'Stripe billing records and provider logs/backups follow their retention policies'}


def verify_account_absent(user_id):
    """Read-only verification; never treat a network/API failure as absence."""
    user_id = str(uuid.UUID(user_id))
    try:
        main.supabase_auth_admin_request('GET', f'users/{user_id}', raise_errors=True)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        try:
            error = json.loads(exc.read())
        except (ValueError, UnicodeError):
            raise RuntimeError('Auth deletion was not confirmed; inspect before retrying') from exc
        if isinstance(error, dict) and error.get('error_code') == 'user_not_found':
            return
        raise RuntimeError('Auth deletion was not confirmed; inspect before retrying') from exc
    raise RuntimeError('Auth deletion was not confirmed; inspect before retrying')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('user_id')
    parser.add_argument('--action', choices=['inspect','prepare','finalize'], default='inspect')
    parser.add_argument('--confirm-user')
    args = parser.parse_args()
    print(json.dumps(perform(args.user_id, args.action, args.confirm_user)))

