# October 26 continuation evidence

This supplements, rather than erases, the historical evidence in LAUNCH_HANDOFF.md and CONTROLLED_BILLING_RESULT.md. Owner-private Site access and paused general purchases are unchanged. No new live payment was made.

## Deployed customer evidence before scanner 35

- Cloud browser works again. Secure ChatGPT owner sign-in reached the private Site; its app session was the designated non-admin customer. Serious grant and canceled billing state verified before any alteration. Grant remains in place while paid tests continue.
- Basic comparison example produced two changed blocks. Direct JSON download was parsed: request, original/revised code and both blocks preserved.
- Comparison report saved and reopened successfully (`6040b998-9c58-42cf-84e0-cf77183f9fb5`). Saved-report download event fired, but the browser file did not synchronize for byte-level inspection; do not call that parsed-download verification.
- Sample report shared to a named existing customer and revoked in UI. Rolled-back database authorization checks proved named-recipient access, unrelated-customer denial and denial after revocation. No email was sent; no Site audience change. This is not a second-customer browser test. Temporary grant removed; sample report retained for QA.
- Two real AI comparisons failed strict evidence validation. Receipts `6913962a-b84c-4d1c-8c68-5029ebf3f98e` and `19f0cf5c-295e-41d4-b1b3-b45edc2c2117` settled failed with 2,109 and 2,100 micro-USD actual provider cost, respectively. Customer AI allowance refunded to 0/100. These are failed provider checks, not successful AI capability evidence.
- Backend `063f58210209261ff96ca1247fac178ffd907746` passed remote CI and Render deployment `dep-dbfrf8bncjis738kblhg` became live. It exposes a safe application validation error (422) instead of a proxy-masked 502, with explicit no-allowance-charge wording. Diagnostic logs contain only static failure categories, never code or provider text.

## Scanner 35 / AI / authorization changes awaiting deployed verification

- AI now chooses server-generated evidence IDs from the correct changed block and side. Exact source excerpts are attached server-side. Wrong-side, fabricated and cross-block IDs still fail closed. Source chunks preserve all input; no silent source truncation or automatic provider retries. Existing response shape, model, pricing and quota are unchanged.
- Python full-environment flow follows encoding/receiver transformations and inspects calls in condition/iterator/context expressions. Constructing an unsent urllib Request is not reported as transmission; urlopen is the transmitting operation.
- Credential branch joins no longer preserve an old secret when both branches overwrite it. A one-sided overwrite or secret retained on the other path remains a finding.
- The legacy GitHub setup endpoint previously trusted a caller-provided installation ID after checking only signed state, then used an App JWT. It now requires user OAuth rather than writing an installation link. State is not ownership proof (see GitHub's setup URL documentation).
- OAuth installation linking now requires the authenticated personal-account owner or verified active organization owner. Ordinary organization members can see only part of an installation; their access must not be expanded by an installation token. Private ingestion and revoked-owner/access lifecycle verification remain unfinished.
- Serious is now accepted by the existing PR-check entitlement gate alongside Pro; no quota change.
- Site project copy now reads actual project limits from the shared catalog (10 Pro / 50 Serious), correcting stale 3/unlimited text.

## Local verification

232 backend tests passed, including real-engine scanner regressions and mocked AI/authorization contracts. Behavior gate passed with unchanged report: 65 internal, 750 category-assisted OWASP and 300 neutral-intent holdout cases at pinned OWASP revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. No misses/false positives in those selected cases; this is not a general accuracy guarantee. Default/native Semgrep parity passed on 72 fixtures, 31 findings, 61 scanned targets and no errors.

Site production build and all 120 tests passed. Browser mobile, current provider success and new-code live customer scans remain pending. See LAUNCH_CHECKLIST.md for all carried-forward capabilities and cleanup.
