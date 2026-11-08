# Monthly allowances and queue

Current limits come from `plan_catalog.json` and are independently enforced by
the service-only database reservation functions.

| Plan | Monthly scans | Repository scans (included in total) | AI reviews | Pasted lines | Repository files |
| --- | ---: | ---: | ---: | ---: | ---: |
| Free | 5 | 1 | 0 | 2,000 | 20 |
| Pro | 75 | 10 | 25 | 20,000 | 100 |
| Serious | 300 | 40 | 100 | 200,000 | 500 |

Free cycles follow account creation. Upgrading from Free starts a new monthly
allowance cycle at the verified paid subscription start. Annual subscriptions
still receive monthly allowances. Continuous paid-tier changes preserve the
cycle anchor and usage while applying the new tier limits. Canceling renewal
preserves paid access through the paid period end; a new paid subscription
after access ends starts a new cycle. Month-end boundaries clamp to the last
valid day and remain anchored to the original date, using UTC.

Plans and anchors come from server-verified billing metadata. Billing changes
and reservations share the account transaction lock. Duplicate/out-of-order
Stripe deliveries reconcile current subscription state; displaced contracts
cannot regain control. Existing paid accounts retain applicable usage during
anchor backfill. A request belongs to the entitlement generation at reservation.

Apply the ordered `supabase/migrations/` history, including
`20261106225631_paid_allowance_cycles.sql`; the legacy monthly SQL file alone
is not the current schema. Admin remains exempt.

Monthly usage is an atomic, service-only Postgres RPC. Reservations count while
analysis is running, then settle idempotently. Failed, unrated, invalid, rejected,
and queued-cancelled requests do not consume scans. Complete/useful partial
results consume one total allowance (and one repository allowance if applicable).
Unsettled reservations expire in 15 minutes after a crash/database outage.

The /scan-jobs API queues up to five waiting requests FIFO, one unfinished job
per authenticated account, one worker. Existing synchronous endpoints remain
capacity-limited and metered. Queue and results are ephemeral, not durable:
restarts interrupt work; source is released after execution; results expire in
10 minutes, with at most 24 completed responses retained. Do not scale to multiple processes/instances without a shared queue.
Monthly quota locking already works across processes via Postgres advisory locks.
No source or findings enter the usage ledger. Ledger rows older than 90 days
are pruned on that account's next usage operation (not a guaranteed timed purge).

Checkout remains disabled. Signup and public access remain unchanged.
