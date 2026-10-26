# October 26 continuation evidence

This supplements, rather than erases, the historical evidence in LAUNCH_HANDOFF.md and CONTROLLED_BILLING_RESULT.md. Owner-private Site access and paused general purchases are unchanged. No new live payment was made.

## Deployed customer evidence before scanner 35

- Cloud browser works again. Secure ChatGPT owner sign-in reached the private Site; its app session was the designated non-admin customer. Serious grant and canceled billing state verified before any alteration. Grant remains in place while paid tests continue.
- Basic comparison example produced two changed blocks. Direct JSON download was parsed: request, original/revised code and both blocks preserved.
- Comparison report saved and reopened successfully (`6040b998-9c58-42cf-84e0-cf77183f9fb5`). Saved-report download event fired, but the browser file did not synchronize for byte-level inspection; do not call that parsed-download verification.
- Sample report shared to a named existing customer and revoked in UI. Rolled-back database authorization checks proved named-recipient access, unrelated-customer denial and denial after revocation. No email was sent; no Site audience change. This is not a second-customer browser test. Temporary grant removed; sample report retained for QA.
- Two real AI comparisons failed strict evidence validation. Receipts `6913962a-b84c-4d1c-8c68-5029ebf3f98e` and `19f0cf5c-295e-41d4-b1b3-b45edc2c2117` settled failed with 2,109 and 2,100 micro-USD actual provider cost, respectively. Customer AI allowance refunded to 0/100. These are failed provider checks, not successful AI capability evidence.
- Backend `063f58210209261ff96ca1247fac178ffd907746` passed remote CI and Render deployment `dep-dbfrf8bncjis738kblhg` became live. It exposes a safe application validation error (422) instead of a proxy-masked 502, with explicit no-allowance-charge wording. Diagnostic logs contain only static failure categories, never code or provider text.

## Scanner 35 / AI / authorization changes

- AI now chooses server-generated evidence IDs from the correct changed block and side. Exact source excerpts are attached server-side. Wrong-side, fabricated and cross-block IDs still fail closed. Source chunks preserve all input; no silent source truncation or automatic provider retries. Existing response shape, model, pricing and quota are unchanged.
- Python full-environment flow follows encoding/receiver transformations and inspects calls in condition/iterator/context expressions. Constructing an unsent urllib Request is not reported as transmission; urlopen is the transmitting operation.
- Credential branch joins no longer preserve an old secret when both branches overwrite it. A one-sided overwrite or secret retained on the other path remains a finding.
- The legacy GitHub setup endpoint previously trusted a caller-provided installation ID after checking only signed state, then used an App JWT. It now requires user OAuth rather than writing an installation link. State is not ownership proof (see GitHub's setup URL documentation).
- OAuth installation linking now requires the authenticated personal-account owner or verified active organization owner. Ordinary organization members can see only part of an installation; their access must not be expanded by an installation token. Private ingestion and revoked-owner/access lifecycle verification remain unfinished.
- Serious is now accepted by the existing PR-check entitlement gate alongside Pro; no quota change.
- Site project copy now reads actual project limits from the shared catalog (10 Pro / 50 Serious), correcting stale 3/unlimited text.

## Local verification

232 backend tests passed, including real-engine scanner regressions and mocked AI/authorization contracts. Behavior gate passed with unchanged report: 65 internal, 750 category-assisted OWASP and 300 neutral-intent holdout cases at pinned OWASP revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. No misses/false positives in those selected cases; this is not a general accuracy guarantee. Default/native Semgrep parity passed on 72 fixtures, 31 findings, 61 scanned targets and no errors.

Site production build and all 120 tests passed. Browser mobile remains pending. Subsequent deployed evidence follows. See LAUNCH_CHECKLIST.md for all carried-forward capabilities and cleanup.

## Deployed scanner 35 / Site 50 customer evidence

Backend `3bff96727e6d6c1362398ebb2921ffd81af4be77`, Render `dep-dbfrm5nb9u1s739lg0h0`, live 20:43:25 UTC. Site 50 source `2dc8b2e29112715d70842650e92f84fc4ecd6c28`, deployment `appgdep_6adfbad1b2c48191a11ae61721632bc5`, succeeded 20:40:54 UTC. Audience rechecked: one owner, no groups/external visitors.

- Real non-admin Serious AI comparison succeeded after explicit consent: receipt `6070d8d5-516f-48d2-b72e-967d34f2b4ae`, 983 input / 298 output tokens, 2,079 micro-USD actual provider cost ($0.002079). The model identified the requested button-label change and unrelated tax multiplier change; server-attached evidence matched both code versions. Usage became 1/100. Running controls prevented reentry. No automatic retry. Direct and reopened saved-AI JSON downloads were parsed and preserved exact code, changes and limitations.
- Created a QA project, assigned basic/AI/static reports, verified project/no-project filters and trash/restore preserving assignment. AI report `ec109bcc-fbcf-488d-959d-0f2f71ab60c7` reopened successfully. Static report `fc175596-5636-48eb-a343-7049f2fbb7e6` saved; reopened rendering verification follows the display fix below. No second-customer browser evidence claimed.
- Paired Python urllib case: constructing an unsent Request with environment payload had no finding (receipt `a389c77c-26b4-417f-9222-1df6b94efa38`); adding `urlopen(r)` produced the expected high whole-environment transmission at line 4 (`3aa76d8f-e59f-4663-b2fb-71982e953c91`). Both engines completed; each ordinary scan consumed one allowance. Editing source marked the old result stale.
- 20,000 submitted lines / 212,123 bytes / 16,001 meaningful lines: harmless branching fixture, both engines complete, no findings (`57135932-f0b0-4975-90f9-33e2a5cf4ff2`).
- 50,000 submitted lines / 530,095 bytes / 40,001 meaningful lines: both engines complete; expected high transmission at final line 50,000 (`9c9fcbc3-b576-43e5-beb8-a61fdbb07b7f`). JSON and text exports were downloaded and parsed: final-line evidence and limitations preserved; no source/account envelope echoed in JSON. These are bounded synthetic inputs, not sustained production capacity or whole-application coverage.
- Immediate cancellation of a second 50k scan returned control and warned that started work may finish/count. Receipt `18ae68db-e854-43fe-8884-f8717819a06a` settled charged after completion; UI retained previous result without accepting a replacement. UI incorrectly kept a stale reserved count after server settlement. Fix below, deployed recheck pending. Current ordinary usage: 10/300, AI: 1/100. Usage was not reset.
- Read-only Stripe recheck found exactly the original canceled subscription and no active/intervening paid subscription. No charge, subscription or administrator privilege was added.

## Scanner 36 and saved-report/usage fixes prepared

- Whole-environment flow now merges if branches from independent incoming states. Both branches overwriting environment data with harmless values removes taint; either path retaining it remains detected. Three real-engine cases added; 233 backend tests passed. The 65/750/300 selected accuracy gates passed unchanged. Semgrep runtime/rules were not changed after scanner-35 CLI parity.
- Line-limit errors identify the actual plan and clearly state that behavior analysis did not run; they no longer suggest a truncated scan was performed.
- Saved AI reports expose verdict, source line numbers, evidence labels and limitations outside raw JSON. Saved static reports expose engine/coverage status, scanner version, action and limitations. UI fixes preserve the full downloaded report.
- UI refreshes usage every five seconds while pending work exists after the user stops waiting, and offers a manual refresh. Coverage separates meaningful and submitted lines.
- These prepared changes require private deployment and fresh changed-path browser checks. See the checklist for remaining capabilities and cleanup.
