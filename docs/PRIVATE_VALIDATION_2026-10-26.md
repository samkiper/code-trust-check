# Private validation — 26 October 2026

Release decision: continue private validation; do not launch payments or customer AI.

## Customer checks

Two ordinary Free accounts completed separate concurrent deployed audits. Desktop JSON/text exports were downloaded and inspected. The user confirmed phone downloads and supplied matching reports, which were parsed successfully. Queued cancellation prevented the second customer's usage debit; an already-running cancellation truthfully warns that analysis may finish and count. Inline Keep editing / Start audit confirmation is deployed in Site v37.

Exact built-in code examples run without authentication through the server-controlled demo endpoint. Changed code, intent, language or filename does not qualify. A free comparison example is provided. Local regression coverage tests edited-input rejection and credential stripping.

## Scanner and capacity evidence

Deployed complex 2,000-, 10,000- and 20,000-line audits completed during this session. The latter two had approximately 15- and 18-second observation bounds, not precise benchmarks. Two simultaneous real customer sessions completed correctly with separate usage debits.

Local real-engine queue exercise: one active and five queued synthetic owners, seventh rejected with 429, queued cancellation, FIFO completion, cross-owner lookup rejected. This is NOT production capacity evidence. Queue client timeout/cancellation/uncertain-submission tests and backend Semgrep timeout tests use controlled fixtures. Production queue saturation above two customers and a deliberately induced production timeout are NOT verified. Do not infer a capacity promise from these results.

## Billing

Fixed: backend checkout now requires explicit PURCHASES_ENABLED=true; missing/false leaves purchases paused before any Stripe call. The Site also blocks purchases. Existing subscription management remains available.

Fixed: canceled/unpaid/incomplete subscriptions cannot regain Pro access through stale future cancellation dates. Active subscriptions scheduled to cancel retain access. Existing past_due grace behavior is unchanged.

Stripe sandbox acct_1TBrsJEKmNfjd7YM only: synthetic customer cus_VViN3iDRNvL1Pz, subscription sub_1UUgxOEKmNfjd7YMhYkZmfpr, initial invoice in_1UUgxOEKmNfjd7YMe5Ccp9Tp paid 1200 test cents. Scheduled cancellation left status active; immediate cancellation returned canceled. Synthetic decline customer cus_VViRZ6idQJ3FWN, subscription sub_1UUh1AEKmNfjd7YMtpYqKfO5 incomplete; invoice in_1UUh1BEKmNfjd7YMlIgpxpef open, paid 0, one payment attempt. Neither customer has email or Supabase user metadata; these are provider-only lifecycle checks, NOT end-to-end customer entitlement verification. No real funds moved.

Test clock clock_1UUgwGEKmNfjd7YMK3zAzal7 created. The connected operation search exposed creation but did not expose advancement. Automatic renewal and failed-renewal recovery remain unverified. Serious price mapping and credit-pack fulfillment remain launch gates in RELEASE_AI_REVIEW.md / RELEASE_SERIOUS.md.

## Regression validation

Backend: 184 unittest tests passed with the installed Semgrep executable on PATH. Site: 114 tests passed, production build passed, audit TypeScript configuration passed. Model/provider fixtures remain mocks unless explicitly labeled above. No AI reviews were purchased for this verification.

## Remaining launch gates

- Fresh self-service signup, confirmation delivery/redemption and subsequent Free allowances must be checked end-to-end after the signup feature/configuration is enabled. Existing invited-account/password-reset success does not substitute for this.
- Verify sandbox webhook delivery, real app entitlement updates, renewal and failed-renewal recovery with a designated test identity before enabling purchases.
- Keep Site owner-private, customer AI disabled and the approved $25 UTC-month AI pilot ceiling unchanged.
- No email budget alerts are configured; dashboard warning flags remain at 80% and 90%.
- Public launch needs an explicit audience/payment decision after the above gates close.
