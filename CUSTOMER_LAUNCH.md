# Customer launch preparation

Keep the Site owner-private and purchases paused until the launch gates below pass. Preserve $19 Pro, $69 Serious/$690 annual, existing infrastructure, and per-account AI allowances. The owner removed the shared $25 cap on October 26, 2026.

## Implemented in this release
- Scanner false-positive call parsing and missing alias/DOM flows, with real-engine regression tests.
- Clearer supported-findings verdict, intent restriction wording, and environment-source/transmission distinction.
- Customer AI comparison eligibility enforced by database quotas, atomic reservations and bounded requests; availability states in UI.
- Safe allowlisted authentication return destinations and plan links; signup password visibility/feedback.
- Anonymous sample navigation and account guidance; saving eligibility guidance; stale report styling; numeric score moved into details.
- Current plan features and public-repository/cross-file limitations stated explicitly; reduced-motion support.

## Remaining release gates / scope boundaries
- Signed-in customer AI review and refreshed availability, paid report saving/downloads, and full phone-width flows on the deployed version.
- Fresh live scanner adversarial cases with a customer session (local suite does not prove deployed behavior).
- Recheck entitlement synchronization, queue/load/timeout behavior after final changes; earlier controlled checks are historical evidence.
- Credit packs require transactional Stripe fulfillment/refund rules and provider mapping; not sold or advertised as available.
- AI single-code intent analysis is not implemented by the comparison endpoint; requires a separate grounded output contract and evaluation corpus.
- GitHub App is configured but private repository ingestion/ownership paths need a separate end-to-end review. Never ask customers for raw personal tokens. Cross-file analysis is not implemented; do not market complete-application coverage.
- Inbox sender logo requires email-domain/provider capability verification; HTML template branding alone does not control mail client avatars.
- Sustained production capacity needs launch validation. Monitor actual provider costs; shared dollar cutoff removed by owner instruction.
- General news blog deferred; focused educational content can follow stable scanner release. Address/phone remain optional future profile fields, not required signup.

## Verification records
Backend and Site test results, database transaction checks, and deployment identifiers are recorded in the release completion entry. Local/mocked/provider/live tests must be distinguished. No automatic public launch or purchase activation.

Local verification completed: 221 backend tests, 117 Site tests, targeted TypeScript check and production build passed. Real-engine tests include 5 new regression methods covering multiple safe/unsafe cases. Database transactions verified quota enforcement after removal of the shared dollar cutoff; all test account/ledger changes rolled back.

The pinned accuracy gate passed (65 internal, 750 OWASP and 300 neutral-intent holdout cases); committed benchmark report remains unchanged. This gate assesses behavior rules, while the new regression suite separately exercises real Semgrep. Global saved-storage cutoff removed; per-account constraints retained. Sharing recipient regex corrected to match valid email addresses; transactional sharing/revocation tests passed.

### Signed-in production verification — October 26, 2026

The secure credential prompt successfully authenticated the existing non-administrator customer test account after the manual cloud-browser handoff repeatedly failed. The restored browser session retained authentication. The account was Free with two scans remaining before these checks.

- The inline confirmation displayed Keep editing and Start audit. Keep editing retained source and did not consume allowance.
- A three-line JavaScript fixture combined a fixed HTTPS fetch with URL input displayed through `textContent`. The deployed scanner (version 33) returned complete behavior and Semgrep coverage, zero findings, and no intent warning.
- The paired fixture changed only `textContent` to `innerHTML`. Both engines completed; the report identified one high-severity `javascript.url-to-html` finding on line 3 and displayed the correct source excerpt.
- Both custom scans consumed one allowance each; the account now has zero ordinary scans remaining this period. Built-in samples remain available.
- JSON and text downloads completed. Parsed JSON matched the visible result, included coverage and all findings, and omitted echoed source and account metadata. The unsafe JSON also contained the expected line-3 finding.
- Editing source visibly marked the previous result as stale. The Free saving UI explained that Pro or Serious is required and left downloads available.
- Basic comparison correctly identified the unintended total-calculation change and the requested button-label change. Free AI status returned zero allowance and explained the paid-plan requirement.

These are desktop browser checks against the deployed scanner, not phone-width or production-capacity evidence. No provider AI request, subscription change or payment occurred. An attempted temporary Pro test entitlement was rejected by automatic approval review before mutation; the account remains Free. Paid AI and new-report saving tests require explicit owner approval for a temporary non-admin test grant and restoration to Free. The rejection must not be bypassed with another entitlement path.

### Follow-up release and authorized paid testing — October 26, 2026

The owner subsequently explicitly requested paid testing access while retaining Site privacy. That instruction allowed the scoped grant to proceed. The existing customer test identity first received Pro, then Serious, without administrator or Stripe changes. Live database status verified Pro 25 AI reviews, then Serious 100 AI reviews, 365-day retention, 200 saved reports and 50 projects. There is no shared dollar ceiling. These are entitlement checks, not a paid-provider or checkout verification.

**Active test grant:** the customer identity marked `aca_launch_test_marker=launch-customer-20261026` currently has Serious. Its original plan was Free. Restore that original plan and remove the marker after paid verification completes, preserving all other account and Stripe metadata and checking for intervening billing changes first. No AI request or payment was made during this follow-up. The earlier rejected attempts did not mutate anything; they are superseded only by the owner's subsequent explicit paid-access instruction.

Scanner commit `53a29b43235ec5846db363f9c22b89aee4004aba` is deployed on Render as `dep-dbfqmkeq1p3s738b9pbg`; `/github/status` reports scanner 34. Both exact built-in examples completed on the deployed backend with both engines complete (about 6.0 and 4.6 seconds). The new scanner-34 custom regressions remain locally verified until a customer session can run them live.

Private Site source `bb652696ad90d9c692efb67eda6f969bcbbfa7b4` deployed successfully as `appgdep_6adfabedd06c8191bbd39d51bdd04c8d` (saved version `appgprj_6a9cdbe527c88191be4447005df951e9~appgver_825100ae7a7c8191b2e4599dfccb489a`). It includes interruptible cancellation polling, AI availability refresh/recovery, clearer signed-in Free saving guidance, direct comparison JSON downloads, and input-bound audit confirmation. Local validation: 120 Site tests, TypeScript check including comparison components, and production build passed. Backend validation: 224 tests and the unchanged pinned accuracy gate passed.

A local 390-pixel iframe check verified the comparison input/results layout with no document horizontal overflow (375-pixel content width after its scrollbar). The phone-width download attempt timed out and is **not verified**. The cloud browser then reported that its native credential state could not be resumed safely, including after one runtime reset. Stop browser recovery loops; resume remaining UI tests only after a working browser environment is available. The temporary preview harness was removed before packaging.

A 50,000-line branching local fixture (543,320 bytes, within the 1 MB snippet bound) completed with both real engines in 18.143 seconds and detected the seeded eval on line 49,997. This is local performance evidence only. An earlier, larger-byte fixture exceeded the accepted snippet size and is excluded from capacity conclusions. `python scripts/benchmark_capacity.py --serious` supplies the reproducible compact fixture and validates input bounds before scanning. Live large scans, simultaneous-customer load, paid AI review and paid report saving remain open.

The committed compact-fixture command was also run successfully: 50,000 lines / 543,318 bytes, both engines complete, 19.921 seconds, with the seeded finding reported by both engines. Real customer allowances remain active during the paid test grant; this verifies ordinary paid access rather than an administrator or unlimited bypass.
