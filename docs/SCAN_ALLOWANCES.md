# Monthly allowances and queue

Free: 20 total / 2 repository scans; 2,000 pasted lines; 20 repository files.
Pro: 300 total / 20 repository scans; 10,000 pasted lines; 50 repository files.
UTC calendar months, not rolling windows or subscription billing periods.
Admin remains exempt. Plans come only from server-verified app metadata.

Prerequisite: apply supabase/monthly_usage.sql before deploying main.py.
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
