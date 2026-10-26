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

Cleanup immediately canceled the synthetic subscription. Stripe made the new sandbox portal configuration its default and does not permit deactivating that default; it remains sandbox-only, with no active subscription created by this test. Full authenticated deployed queue saturation still needs seven independent authenticated identities; only two customer sessions are available. An induced deployed scanner timeout remains unverified. No new production-capacity claim follows from this check.
