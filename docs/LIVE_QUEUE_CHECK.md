# Live queue validation

`scripts/live_queue_check.py` is an opt-in backend/Supabase integration check.
It does not run during CI and does not alter launch controls. Run only against
an authorized private-validation deployment with no other active scans.

Supply seven existing, verified, dedicated test accounts in a local JSON array
of objects with `email` and `password` fields. Each must have at least two scans
remaining and no pending work. Use normal accounts, not administrators. Do not
put this file in the repository, chat, command arguments, or a saved report.
Store it outside the checkout, owned by the operator, with permissions `0600`.
The runner never creates users, changes plans, changes passwords, or resets
allowances. Existing browser credentials are not extracted or reused.

Set `ACA_TEST_PUBLISHABLE_KEY` to the project's public Supabase client key.
Use the intended backend and Supabase HTTPS origins explicitly:

```sh
python scripts/live_queue_check.py \
  --backend https://YOUR-SERVICE.onrender.com \
  --supabase https://YOUR-PROJECT.supabase.co \
  --credentials-file /absolute/private/test-accounts.json \
  --run-live
```

The script signs in each account through Supabase, checks available usage,
starts one bounded synthetic Python scan, then submits six requests together.
A passing result requires one running job, five waiting jobs, one capacity
rejection, duplicate rejection, cross-account denial, queued cancellation,
retry, six successful scans, and exact usage changes. It uses no AI provider
and makes no payment requests. Successful scans consume real test allowances.

If the first scan finishes too quickly, another customer is active, a rate
limit interferes, or the allowance cycle changes, the run does **not** pass.
Do not repeatedly rerun to force a favorable result. Inspect the reason and
actual ledger before deciding on another bounded test. A network timeout after
submission can leave an accepted job whose ID was not received; investigate
that account's queue/ledger before retrying. The runner does not retry POSTs.

Known accepted jobs are drained or canceled on failure. Only the sessions
created by the test are signed out (`scope=local`); access JWTs can remain
usable until expiry under Supabase's normal behavior. Tokens are never saved
or printed. A failed run can still have consumed successful test scans.

This check does not establish browser/Site-proxy behavior, queue durability
across a server restart, or a load-capacity SLA. Keep those evidence scopes
separate. No live pass should be claimed from local unit tests of this runner.
