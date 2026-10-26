# Controlled live billing validation — October 26, 2026

Verified with one authorized customer account using the actual Site Upgrade button and normal backend Checkout route:

- USD 19 monthly checkout completed and the live invoice was paid.
- Normal success-page verification completed; browser and persisted access showed Pro and an active subscription.
- Manage existing subscription opened the live Stripe customer portal with the correct plan and cancellation option. Its Return link reached the billing page correctly.
- Following explicit approval, Stripe reported the full USD 19 refund succeeded. Card-statement posting was not independently verified.
- Immediately canceled the subscription through the Stripe API, without proration or another invoice. Signed webhook processing restored Free/canceled, independently verified in the database and browser.
- Customer portal cancellation submission was not exercised; immediate API cancellation was used after refund.

Cleanup verified: temporary checkout authorization removed, its expiry disabled, cleanup deployment live, live Pro price inactive, and checkout requests return 503 purchases paused. The Site remains private and customer AI remains disabled.

These observations establish the exercised live checkout, verification, refund, portal entry/return and cancellation-event paths. They do not establish full concurrent-customer capacity, induced deployed timeout recovery, Serious billing or AI credit-pack fulfillment.

## Customer portal cancellation UI — sandbox follow-up

Exercised the real Stripe-hosted portal with a synthetic sandbox subscription and a sandbox configuration matching live cancellation behavior: at period end, no proration, cancellation reason collected. Selected a reason, continued, and submitted Cancel subscription. The portal displayed a scheduled cancellation and service-end date. Stripe independently returned a scheduled cancellation timestamp and the submitted reason. The sandbox webhook remained disabled: this check did not change application access or produce another real charge.

Cleanup immediately canceled the synthetic subscription. Stripe made the new sandbox portal configuration its default and does not permit deactivating that default; it remains sandbox-only, with no active subscription created by this test. The sandbox portal check alone makes no production-capacity claim. See the subsequent deployed queue test below.


## Seven-customer deployed queue check — October 26, 2026

Seven confirmed Free customer accounts submitted synthetic Python audits of approximately 1,802 lines through the deployed Site and normal backend job route. No administrator privileges, AI calls or payments were used.

- Six submissions were accepted (202), filling one running slot and five waiting slots.
- The overflow submission returned 429 with the queue-full explanation and consumed no allowance.
- A duplicate submission for an occupied customer returned 409.
- Another customer's attempt to read an accepted job returned 404.
- All six accepted jobs completed, each reporting one behavior flag and one engine finding.
- Independent database inspection found six charged receipts and no pending reservations. The overflow account retained its allowance.
- The complete check took approximately 38 seconds including authentication verification and polling; this is not a raw scan-engine benchmark. Health returned 200 during the check.
- After verifying accounting, only the six identified QA receipts were marked refunded to restore test allowances; all six refunds were independently verified.

This verifies the exercised seven-customer saturation and isolation behavior on the deployed scanner. It does not establish sustained throughput, multi-worker scaling, or induced deployed timeout recovery. At this point, the forced-timeout check, Serious billing and AI credit-pack fulfillment remained unverified. See the subsequent scoped timeout check below.


## Controlled deployed Semgrep timeout and recovery — October 26, 2026

Fixed two issues before testing: exhausted engine timeouts no longer consume monthly allowance when behavior-engine coverage is partial, and scanner deadlines now kill and reap the scanner process group before releasing capacity. A successfully completed fallback remains chargeable.

Validation used the normal signed-in Free customer form and queued backend route. A temporary operator-configured exact synthetic source digest and expiring window shortened the real Semgrep subprocess deadline to 50 ms. Submitted source was inspected, never executed; no AI calls or payments were made.

- The deployed engine reported timeout after approximately 53 ms, with its subprocess attempt timing out after 52 ms.
- The browser and downloaded report correctly displayed partial coverage and Semgrep timeout, without an all-clear result.
- Independent database inspection found the usage receipt automatically refunded before any manual cleanup. The customer's one remaining scan was preserved.
- A normal, different synthetic snippet on the same account then completed through the same queue without a server restart. Both engines reported complete; Semgrep took 151 ms. This verifies release of the account's queued-job restriction and scanner capacity for this timeout path.
- The normal follow-up was correctly charged; only that QA receipt was manually refunded afterward. Both test receipts were independently verified refunded.
- Local validation: 204 tests passed, including a real parent/child-process termination check; 72-case Semgrep CLI parity passed; accuracy gates passed on 65 internal, 750 OWASP and 300 no-hint holdout cases. Render repeated its configured tests and accuracy checks successfully.

Scope: this was controlled fault injection against the deployed engine, not a naturally occurring timeout or a throughput benchmark. It does not establish a whole-job deadline for every behavior-analysis or repository-processing path; the queue still relies on its synchronous work returning. Serious billing and AI credit-pack fulfillment remain separate unverified launch gates.

Cleanup: the validation digest was cleared and its expiry set to zero. The cleanup deployment reached live on the tested code revision. Normal scan budgets are restored. Site access remains owner-private, customer AI remains disabled, and payments remain paused.

## Whole-audit deployed deadline and recovery — October 26, 2026

Replaced in-process analysis with an isolated trusted worker and a 120-second overall analysis deadline. Authentication, allowance reservation/settlement and queue waiting retain their separate bounds. The supervisor kills and reaps the worker process group before releasing capacity; submitted source is never executed.

A temporary exact-source diagnostic injected a ten-second worker stall with a one-second supervisor deadline through the normal signed-in customer queue. The browser returned the maximum-runtime error, and the database receipt was automatically refunded. A different normal snippet then completed with both engines complete, on the same account and deployment without restarting the server. That follow-up was correctly charged and subsequently refunded as QA cleanup. Both receipt states were independently verified. Diagnostic digest and expiry were cleared, and the cleanup deployment reached live.

This verifies controlled deployed whole-analysis timeout and recovery, not sustained production throughput. Local checks also cover termination of real busy parent/child processes, cleanup after success, accounting and queued follow-up. The full backend suite now passes 215 tests; the scanner changes passed 72 CLI parity cases and accuracy gates on 65 internal, 750 OWASP and 300 holdout cases.

## Serious monthly and annual — sandbox billing with deployed access

Fixed production entitlement resolution to use approved Stripe price IDs, not a generic paid status or client metadata. Checkout accepts only configured Pro monthly, Serious monthly or Serious annual selections; client price and amount fields cannot select the charge. The private Site includes matching checkout choices, with annual upfront billing and monthly allowance disclosure. Site build and all 116 tests passed. A separate full standalone TypeScript check remains limited by the retained starter's missing Cloudflare worker declarations; it is not counted as a passing check.

Using a non-administrator test account and real signed sandbox webhooks against the deployed backend:

- Serious monthly sandbox invoice paid USD 69 and granted Serious access.
- Scheduled cancellation retained Serious while the subscription was active; immediate cancellation restored Free.
- Serious annual sandbox invoice paid USD 690 and granted the same Serious access, with an account-anniversary monthly allowance reset rather than an annual scan pool. Cancellation restored Free.
- A synthetic 50,000-line Python submission (901,389 characters; 47,500 nonblank source lines) completed through the deployed Site queue with both behavior and Semgrep engines complete. Exactly one allowance was charged, then refunded as QA cleanup.
- Sandbox subscriptions were canceled, temporary webhook disabled, sandbox prices and product returned to inactive. No real money was charged in these Serious checks.

Scope: these are sandbox financial transactions plus deployed authorization/scanner observations. They do not verify live USD 69 settlement, refund, customer-portal cancellation for Serious, or arbitrary complete-application coverage. The earlier live Pro payment and refund are separate evidence. Customer AI and credit-pack sales remain disabled and are outside the static-audit launch scope.

At this stage the real Serious checkout was pending explicit authorization. It was subsequently authorized and exercised as recorded below. The site remains owner-private and general purchases paused.

## Serious monthly — controlled live payment completed

On October 26, 2026, the owner completed the normal USD 69/month Serious checkout in their own browser using the specifically allowlisted non-administrator account. Stripe confirmed a paid USD 69 live invoice for the approved Serious monthly price. Independent application metadata inspection confirmed Serious access with an active subscription.

After access verification, the subscription was immediately canceled through the Stripe API without proration or a new invoice. The signed webhook restored Free/canceled, independently verified in the database. Stripe subsequently reported the full USD 69 refund succeeded after the owner approved its confirmation request. Card-statement posting was not independently verified. Serious customer-portal cancellation UI and annual live settlement were not exercised; annual billing has sandbox evidence only.

Cleanup verified: the live monthly price is inactive, the account-specific checkout exception and expiry were cleared, and the cleanup deployment reached live. General purchases remain paused, Site access owner-private, and customer AI disabled. The backend suite passes 216 tests, including isolation from deployment billing settings and rejection of Pro/annual selections during a Serious-monthly-only checkout window. This records completion of the controlled monthly payment/access/refund/cancellation check, not authorization to launch or enable general payments.
