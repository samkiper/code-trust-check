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

## Deployment verification addendum

Site v38 (d587073dc5bc574d654280287b6a00b301e9ac2e) deployed owner-private. Signup and confirmation routes plus Account / Sign-in registration links are available. Branded confirmation template saved and reloaded in Supabase. Public auth settings verified disable_signup=false, mailer_autoconfirm=false, email=true; registration requires verified email. Existing two test accounts remain email-confirmed with no admin role or paid plan metadata. Fresh signup still requires the user's password/email-verification step; it has not been completed end-to-end by the agent.

Backend code a36a4be54819492c16c1f90054ede7b253f842f6 passed GitHub accuracy-gate and is live in Render deployment dep-dbfestdg1s2s73a944mg. A direct deployed checkout request returned HTTP 503 with Purchases are paused during private validation.

Bounded deployed overload check: four concurrent unchanged anonymous examples sent to /scan. One completed (200, complete), three rejected with 429, X-Scan-Rejection=capacity and Retry-After=10. A subsequent single example completed 200. This verifies the synchronous production capacity guard and recovery, not a six-customer authenticated queue saturation test. No AI API requests or customer allowance debits were used.

Sandbox test subscriptions were stopped after testing: success case canceled; failed initial-payment case incomplete_expired. Renewal remains blocked on Stripe dashboard sign-in: connector operation discovery did not expose clock advancement, and the dashboard opened at login. No production keys, payment settings, customer entitlements or AI budget were changed.

## Completed sandbox clock lifecycle (follow-up)

Google sign-in and Stripe MFA completed; browser visibly confirmed AI Code Audit sandbox acct_1TBrsJEKmNfjd7YM. Existing clock clock_1UUgwGEKmNfjd7YMK3zAzal7 advanced through the dashboard, since the connector does not expose clock advancement.

Synthetic subscription sub_1UUhODEKmNfjd7YMqqKBUShs on existing customer cus_VViN3iDRNvL1Pz:
- Monthly renewal: subscription_cycle invoice in_1UUhQ6EKmNfjd7YMiluRaZ06 generated on November 26 simulated time, then paid 1200 test cents after advancing to November 27.
- Failed next renewal: switched synthetic customer to the official decline-after-attachment test source. December invoice in_1UUhRIEKmNfjd7YMQaPN7203 remained open, amount_paid=0, attempt_count=1; subscription became past_due.
- Recovery: restored the original attached pm_card_visa-derived payment method and advanced to January 3. Automatic second attempt paid the same invoice (1200 test cents, attempt_count=2); subscription returned active.
- Scheduled cancellation: cancel_at_period_end retained active status until January 26. Advancing to February 3 changed subscription to canceled; latest invoice remained the recovered December invoice.

These are actual Stripe sandbox lifecycle results with synthetic customers, not production payments or end-to-end app entitlement tests. They close the provider renewal/recovery/cancellation simulation gap; they do not close webhook delivery, customer plan synchronization, Serious mapping or credit-pack launch gates. Both prior test subscriptions and this new subscription are stopped. Live Stripe configuration, paused purchases, private Site access and customer AI restrictions were not changed.

Read-only sandbox integration inventory: GET /v1/webhook_endpoints returned an empty list (has_more=false). No legacy sandbox webhook endpoint is configured through that API. A separate event destination, if any, has not been verified. Thus Stripe simulation success must not be presented as verified delivery into the deployed scanner or its customer entitlement database. No new webhook, infrastructure or API key was created.

## Webhook acknowledgement follow-up

Read-only sandbox `/v2/core/event_destinations` inventory returned no destinations (no next page), complementing the earlier empty legacy webhook list. End-to-end sandbox event delivery is blocked until a destination and matching backend signing-secret configuration are authorized; no endpoint, API key or infrastructure was created.

Confirmed and fixed: checkout, subscription and invoice handlers previously acknowledged failed Supabase plan writes with HTTP 200. They now return HTTP 503 when persistence fails; invoice subscription lookup failures also return 503. This preserves Stripe retry eligibility instead of silently losing the account update. Local regression coverage includes all eight supported entitlement event types, failed invoice lookups and successful redelivery after failed persistence. All 187 backend tests passed with installed scanner binaries on PATH. These tests mock Stripe/Supabase and are not production webhook-delivery verification.

User confirmed fresh signup and automatic email-link sign-in after Site v39. Site v40 labels the signed-out header CTA Try sample audit; signed-in CTA remains Start audit. Paid plan synchronization, larger authenticated production queue saturation and induced production timeout remain unverified. No change to paused purchases, owner-private Site audience or administrator-only AI.

## Isolated sandbox subscription receiver

Added an opt-in `/stripe/sandbox-webhook` receiver with a distinct signing secret and server-side bindings to one test user, customer and Pro price. It accepts only signed non-live subscription snapshots, never calls Stripe with the live API key, refuses admin/live-billing accounts, and records sandbox-prefixed subscription provenance. Duplicate and older events are ignored; canceled subscriptions cannot be revived by delayed updates. Persistence failure returns 503. No live webhook/key configuration or purchase availability changes. Disable after validation by clearing STRIPE_SANDBOX_WEBHOOK_SECRET.

Sandbox destination: we_1UUi4rEKmNfjd7YMlFx6u7VX. Synthetic customer: cus_VVjX1TmjrA3LAw. Secrets exist only in provider configuration, not this repository. This isolated adapter exercises the existing plan-status policy and Supabase metadata persistence; it is not evidence of the live checkout/invoice API lookup path.

### Deployed sandbox delivery evidence

Backend a5162a474b04b8a1c1d033d6ca68dd0e5ec0905d passed all 192 tests and GitHub accuracy-gate, then became live in dep-dbffrqu7bikc73c5n61g. Real Stripe-generated sandbox events reached the deployed receiver and updated the allowlisted account (no direct plan edits were used):

- Subscription sub_1UUi94EKmNfjd7YM135tSMA5: initial invoice in_1UUi94EKmNfjd7YMN07owvMb paid 1,200 test cents; evt_1UUi96EKmNfjd7YMZCrFglWT set Pro/active.
- A billing-anchor reset did not generate a new invoice. A quantity-change invoice was then used to exercise failed payment; this is not a calendar renewal. Declining test source produced open invoice in_1UUiAJEKmNfjd7YMuBhVlAzz, paid=0, attempt_count=1. evt_1UUiALEKmNfjd7YMf0O02uww set past_due and retained Pro per existing policy.
- Replacing the source with tok_visa paid that invoice (1,200 test cents). evt_1UUiAoEKmNfjd7YMlbt857Jh restored active/Pro.
- Scheduled cancellation: evt_1UUiBEEKmNfjd7YMMopHDfPg kept active/Pro with sandbox_cancel_at_period_end=true.
- Immediate cancellation: evt_1UUiBZEKmNfjd7YMZ2kNSyji set canceled/Free. The account has no live Stripe customer mapping. No real funds or cards used; the test subscription is stopped.

Destination disabled after validation; sandbox signing secret cleared in Render to disable the receiver. Live webhook/key configuration unchanged. This proves sandbox subscription-event delivery to persisted app entitlements, not the separate live checkout/invoice retrieval path or a refreshed customer-browser display. Earlier test-clock renewals are provider-only evidence; calendar renewal through this receiver remains unverified. Larger authenticated production queue saturation and induced production timeout remain open.

### Calendar renewal delivered to app entitlements

The existing sandbox clock customer cus_VViN3iDRNvL1Pz was temporarily bound to the same isolated receiver; deployment dep-dbffvv0m7kps738v93s0 became live. New test subscription sub_1UUiH9EKmNfjd7YMa7LtnKWi started at simulated February 3, 2027. Its initial invoice in_1UUiH9EKmNfjd7YMjwqu7TqB was paid; event evt_1UUiHBEKmNfjd7YMgojGyKfw persisted active/Pro.

Advancing the existing clock to March 3 generated monthly subscription_cycle invoice in_1UUiHeEKmNfjd7YMM9lNtUcC. Event evt_1UUiHfEKmNfjd7YMfpxqCCBE retained active/Pro and advanced the persisted period end to April 3 (1806710400). Advancing to March 4 collected 1,200 test cents; the invoice was verified paid via Stripe API.

Scheduled cancellation retained active status until April 3. Advancing the clock to April 4 ended the subscription at April 3, and real event evt_1UUiJTEKmNfjd7YM4oFC5XbK persisted canceled/Free in Supabase. No direct plan edits, real funds, new accounts or AI requests were used. This closes calendar renewal and period-end cancellation through the deployed isolated receiver, not live checkout/payment-return verification.

Sandbox destination we_1UUi4rEKmNfjd7YMlFx6u7VX disabled again and signing secret cleared. Live billing settings remain unchanged. The available aicodeaudit.org browser session belongs to easystreammovies@gmail.com (Free); it is not the calendar-test identity. Refreshed browser entitlement display for that identity, larger authenticated queue saturation, induced production timeout, live checkout and the existing Serious/credit-pack mappings remain unverified launch gates. Two-customer and anonymous capacity results above must not be described as full queue-capacity verification.

## Approved plan revision

Free: 5 audits/month including 1 repository; no AI allowance. Pro: $19/month, 75 audits including 10 repositories, 25 planned AI reviews, 20,000 pasted lines, 100 repository files / 10 MB, 10 projects. Serious: $69/month, 300 audits including 40 repositories, 100 planned AI reviews, 50,000 pasted lines, 500 repository files / 25 MB, 50 projects. Existing $690 annual Serious option retained. Basic comparison stays local and unlimited; no customer AI activation or budget change.

Supabase migration approved_plan_ai_and_project_limits applied. Transactional database tests passed with all synthetic fixtures rolled back, checking Pro 10 / Serious 50 project boundaries, ownership, sharing, expiry, Free AI 0, admin-only access, duplicate protection and $25 budget. Backend 192 tests passed. Site build, 114 tests and audit TypeScript check passed. Security advisors retain existing service-only RLS/no-policy information plus profiles GraphQL visibility and disabled leaked-password protection warnings; no new public grants were made.

Local real-engine 49,998-line generated Python probe returned partial (Semgrep no analyzed targets/parser warning), not full coverage. This is a useful limitation result, not a successful capacity benchmark. Pasted input remains bounded to 1 MB in the Site; expanded limits still require production load validation.

Stripe live Pro price price_1UUir6EEE0WuIMoRfM4X3i3N created at 1,900 USD cents/month, inactive. No existing subscription migrated or charged. Payments remain paused.

A second local real-engine Python probe within the Site byte cap (49,996 lines, 434,570 bytes) completed in 12.46 seconds with both behavior and Semgrep coverage complete and the intentional dynamic-input finding detected. This is local evidence, not deployed throughput validation.

## Expanded limits: deployed browser validation

Site v41 and backend 3cc8a801c675cb7165d5e6d11856c14d847ce8c0 tested through normal signed-in UI. Existing disposable customer easystreammovies@gmail.com temporarily received Serious plan metadata for capacity validation only (not administrator access, subscription fulfillment or billing evidence). Its original absence of plan metadata was restored afterward.

- Synthetic Python: 49,996 source lines (49,997 in textarea including trailing newline), 434,570 bytes. Deployed queued audit completed with behavior and Semgrep both complete; intentional request-controlled eval at line 49,996 detected. 42,854 meaningful source lines excludes blanks. Usage reservation 08:12:15.870 UTC to downloaded report timestamp 08:12:36.174 UTC: about 20.3 seconds including client polling/rendering, not pure engine timing. Exactly one scan debit observed.
- Real public django/django repository: 500 of 3,567 supported files selected at Serious cap; report marked partial and omitted score. 175 report findings are untriaged scanner observations, not confirmed Django vulnerabilities. Reservation 08:13:45.394 to report 08:14:04.598: about 19.2 seconds including polling/rendering. One total and one repository allowance consumed. Downloaded JSON parsed successfully (1,195,604 bytes). Repository checks do not trace cross-file flows and do not run the snippet Semgrep path; this result does not establish full application coverage.
- Second ~50k scan ran while independent samuel.a.kiper@gmail.com customer submitted a small scan. Second customer visibly waited at queue position 1, cancelled while queued, and retained both remaining Free scans. Large scan subsequently completed. This is two-customer production queue/cancellation evidence, not full saturation.

Cleanup: restored the first test account to Free; manually refunded only the three identified QA usage receipts after verifying their original charged states (8d7f52f8-6cbf-430f-bf0e-c96b5d7a4889, f7304c05-3404-47c2-af05-507911bbb8be, 839ccec4-226c-4583-b24f-d4826ef72aa3). No customer code, AI calls or payments used. Customer AI remains disabled and purchases paused.

Full authenticated queue saturation needs additional independent authenticated test identities. Current connected Supabase tools expose no Auth admin account-provisioning operation, so no disposable identities were created. Induced deployed timeout and live checkout remain unverified. No new source bug was confirmed in these checks; no code change or deployment was needed.

## Completed isolated $19 Checkout user test

Prepared sandbox price price_1UUjHDEKmNfjd7YM96JDwcG9 on the existing Pro product, 1,900 USD cents/month. Checkout cs_test_a1RTV8M4TmMxOojXuPzodPx7nikpfh32y4G5GA7l9UJtheFbGub8WvjIId is open, livemode=false, bound to synthetic customer cus_VVjX1TmjrA3LAw and test account 41284ae1-8a90-4725-91d4-634fb7cfb026 (easystreammovies@gmail.com). Success returns to https://aicodeaudit.org/account; cancellation returns to billing with checkout=cancel. User completed the sandbox payment. Invoice in_1UUjSBEKmNfjd7YMODxBTXhR is paid for 1,900 USD cents, livemode=false; subscription sub_1UUjSDEKmNfjd7YMh0dClWpZ became active. Signed webhook persisted Pro. Browser returned to the account page showing Pro, 71 remaining scans and 20,000-line limit. The sandbox status is intentionally separate from live subscription fields; the page showed no live subscription status.

Existing sandbox destination we_1UUi4rEKmNfjd7YMlFx6u7VX re-enabled; Render sandbox receiver temporarily bound to this user/customer/new price with its existing signing secret. Normal purchases remain paused and live Pro price stays inactive. After the user completes the test: verify the paid sandbox invoice and persisted + browser Pro entitlement, cancel the test subscription, verify Free, disable the sandbox destination and clear its signing secret again. No new API key or infrastructure created.

This connector-created hosted session tests Checkout payment UI, signed subscription-event delivery and account return/display. It does not exercise the app's normal create-checkout-session or checkout-session-status routes, which use the live Stripe client. Those routes remain an explicit release gap; do not call this complete live checkout integration verification.

Cleanup verified: canceled the sandbox subscription through Stripe API with no invoice or proration. Signed deletion webhook restored Free/canceled in Auth; refreshed browser showed Free, 1 remaining scan and 2,000-line limit. Disabled the sandbox destination and cleared its Render signing secret. This tests API cancellation delivery, not the customer billing-portal cancellation UI. No real charge or customer AI call.

## Normal billing route review after hosted checkout

Confirmed and fixed two source issues: Checkout success/cancel and customer portal return URLs now target /account/billing, where the Site handles verification, instead of legacy homepage URLs. Recovery from a paid checkout now returns 503 if the current subscription lookup fails; it cannot grant Pro based only on an old paid checkout. Three mocked regression tests cover both return destinations and fail-closed recovery. All 195 backend tests pass locally. These tests do not constitute real normal-route Stripe verification. Normal checkout is still disabled in both Site proxy and backend; its deployed client uses the live credential. No new credential requested or payment switch enabled.

## Authorized controlled live payment preparation

User chose a controlled live $19 payment, then requested access verification, refund and subscription cancellation. Added an expiring server-side single-user exception while PURCHASES_ENABLED remains false. Other users are rejected; missing/expired/malformed windows fail closed. Controlled sessions validate an active live USD 1,900 monthly price and use a stable window-scoped idempotency key. Billing UI exposes Upgrade only when backend permission is returned. Checkout still uses the normal session, webhook, verification and portal paths. Local tests: 201 backend, 114 Site, build passed. Real payment, refund and portal cancellation remain pending user card submission. Disable the exception after validation; do not enable general purchases or customer AI.
