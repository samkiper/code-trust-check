# Account-data request procedure

Only a trusted operator may run `scripts/account_deletion.py` in the backend
environment. The script has no public endpoint and defaults to inspection.

1. Verify the request using the confirmed account email and a recent authenticated
   session or a fresh ownership-verification link. An unsolicited email address
   alone is insufficient. Never request a password, secret key or full card number.
2. Explain which application data will be removed and which Stripe financial
   records and provider backups/logs remain. Offer an export of saved reports
   through the signed-in account before deleting. Do not send source in ordinary
   email. For correction requests, use the account/provider's supported controls.
3. Reconcile all subscriptions for the Stripe customer. The deletion script
   refuses any nonterminal subscription, including scheduled cancellation that
   still grants paid access. Confirm with the customer whether they want renewal
   cancellation with access through period end, or immediate account deletion.
   Handle immediate cancellation and any refund separately under the published
   policy; never silently cancel or refund from a data-cleanup script.
4. Run `python scripts/account_deletion.py USER_UUID` and inspect the result.
   No changes occur. Resolve billing mismatches before proceeding.
5. After confirming the exact account, run with `--action prepare --confirm-user
   USER_UUID`. This preserves unrelated metadata, marks deletion pending and bans
   sign-in. Application requests with existing tokens are denied by a current
   Auth lookup and the pending-deletion marker. Do not remove that marker manually.
6. Wait at least eight hours. This exceeds the seven-hour GitHub authorization
   cache and queued-work/result lifetimes. The current cache actively expires
   credentials. This quarantine avoids promising instant in-memory erasure.
7. Recheck billing, then run with `--action finalize --confirm-user USER_UUID`.
   The script rechecks quarantine and billing before using the Auth Admin deletion
   API. The private deletion trigger removes non-cascading usage records,
   repository policies/suppressions, invitations to this email, legacy daily
   counters and known rate-limit keys. Existing foreign-key cascades remove
   profiles, saved reports/projects, owned report grants and GitHub links/history.
8. Verify the Auth user is absent, old tokens cannot access application endpoints,
   relevant application rows are gone and a different fixture/account is unchanged.
   Do not rely only on a successful command exit. Record completion without source,
   tokens or unnecessary identifying data. If a step fails, inspect before retrying.

Stripe records needed for billing, tax, disputes and refunds are separate from
application data. Supabase daily backups rotate over seven days; deletions must be
reapplied if a backup is restored. Render/OpenAI/Sites logs follow the privacy
notice and provider retention. Deleting downloaded copies is the customer's
responsibility. The current system stores no Supabase Storage objects; revisit
this procedure before introducing object storage or other user-linked tables.

Tests: `tests/test_account_deletion.py` exercises operator safeguards and old-token
denial. `tests/sql/account_deletion.sql` verifies cleanup and another account's
preservation in a rollback transaction. Native PostgreSQL CI runs that SQL against
the report/usage schema; production rollback verification must also precede launch.
