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
