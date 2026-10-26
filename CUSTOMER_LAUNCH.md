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
