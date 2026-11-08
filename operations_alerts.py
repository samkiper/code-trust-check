"""Bounded operational email alerts. Alerts never disable purchases or usage.

Runs in the service process; Render's independent health notifications cover a
dead process. Provider balances are separate from the application's cost ledger.
"""
import hashlib
import json
import os
import threading
import time
import urllib.request
from collections import deque


def evaluate(summary, billing_failures=0, month_threshold=50):
    if not isinstance(summary, dict) or not isinstance(summary.get('ai'), dict):
        return ['database-monitor-unavailable']
    ai = summary['ai']; alerts = []
    failed = int(ai.get('failed') or 0); completed = int(ai.get('completed') or 0)
    if failed >= 5 and failed / max(1, failed + completed) >= .2:
        alerts.append('ai-failure-rate')
    # Unknown provider attempts count at their reserved upper bound, rather than
    # being reported as free. This is not a provider balance or billing invoice.
    exposure = int(ai.get('recorded_micro_usd') or 0) + int(ai.get('unresolved_reserved_micro_usd') or 0)
    if exposure >= month_threshold * 1_000_000:
        alerts.append('ai-monthly-cost-review')
    if billing_failures >= 3:
        alerts.append('billing-delivery-retries')
    if int(summary.get('scans_last_24_hours', {}).get('expired_reservations') or 0) >= 3:
        alerts.append('scan-settlement-review')
    return alerts


MESSAGES = {
 'database-monitor-unavailable': 'The account usage monitor could not read its database. Check Supabase and Render before assuming usage is healthy.',
 'ai-failure-rate': 'At least five AI attempts have failed and failures are at least 20% of settled attempts this UTC month. Review provider errors and customer allowance refunds.',
 'ai-monthly-cost-review': 'Recorded AI costs plus unresolved attempt reserves have reached the configured monthly review threshold. Check actual OpenAI usage and prepaid balance. This alert does not stop customer requests.',
 'billing-delivery-retries': 'At least three signed Stripe billing deliveries failed reconciliation within 15 minutes. Check Stripe delivery retries and reconcile affected subscriptions.',
 'scan-settlement-review': 'At least three scan reservations from the last 24 hours expired without settlement. Check worker interruptions and database availability.',
 'delivery-test': 'This is the requested AI Code Audit operational alert delivery test. No customer scan, payment, or account change was performed.'
}


def send_alert(kind, now=None):
    if kind not in MESSAGES:
        raise ValueError('Unknown alert category')
    api_key = os.getenv('RESEND_API_KEY', '')
    recipient = os.getenv('ACA_ALERT_EMAIL', '')
    sender = os.getenv('ACA_ALERT_FROM', 'AI Code Audit <support@aicodeaudit.org>')
    if not api_key or not recipient or '\n' in recipient:
        raise RuntimeError('Operational email is not configured')
    bucket = int((time.time() if now is None else now)//21600)
    key = hashlib.sha256(f'aca-operations-v1:{kind}:{bucket}:{recipient}'.encode()).hexdigest()
    body = json.dumps({'from': sender, 'to': [recipient], 'subject': f'AI Code Audit: {kind}',
        'text': MESSAGES[kind]+'\n\nReview: https://dashboard.render.com/ and https://platform.openai.com/usage\nNo code, credentials or customer identifiers are included in this alert.'}).encode()
    request = urllib.request.Request('https://api.resend.com/emails', data=body, method='POST',
        # Required by Resend's direct HTTP API; identify our application honestly.
        headers={'Authorization': 'Bearer '+api_key, 'Content-Type': 'application/json',
                 'User-Agent': 'AI-Code-Audit/1.0', 'Idempotency-Key': key})
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.load(response)
    if not result.get('id'):
        raise RuntimeError('Email acceptance was not confirmed')
    return result['id']


class Monitor:
    def __init__(self):
        self.lock = threading.Lock(); self.failures = deque(maxlen=1000)
        self.stop = threading.Event(); self.thread = None
        self.sent = {}; self.unavailable = 0

    def billing_failed(self):
        with self.lock:
            self.failures.append(time.monotonic())

    def check(self, read_summary, send=send_alert, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            while self.failures and self.failures[0] < now-900:
                self.failures.popleft()
            count = len(self.failures)
        summary = read_summary()
        alerts = evaluate(summary, count, float(os.getenv('ACA_AI_MONTHLY_ALERT_USD', '50')))
        self.unavailable = self.unavailable + 1 if 'database-monitor-unavailable' in alerts else 0
        if self.unavailable < 2:
            alerts = [x for x in alerts if x != 'database-monitor-unavailable']
        for kind in alerts:
            if now-self.sent.get(kind, float('-inf')) >= 21600:
                send(kind); self.sent[kind] = now
        return alerts

    def start(self, read_summary):
        if self.thread or not os.getenv('RESEND_API_KEY') or not os.getenv('ACA_ALERT_EMAIL'):
            return
        self.stop.clear()
        def run():
            while not self.stop.wait(300):
                try: self.check(read_summary)
                except Exception as exc:
                    print('[operations] Alert check failed: '+type(exc).__name__)
        self.thread = threading.Thread(target=run, daemon=True, name='operations-alerts')
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread: self.thread.join(timeout=1)
        self.thread = None
