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
