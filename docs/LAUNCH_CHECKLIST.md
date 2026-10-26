# Launch checklist — current continuation

Updated October 26, 2026. Read with `LAUNCH_HANDOFF.md`; historical results remain valid within their recorded scope. This checklist does not authorize public access, purchases, pricing changes, or new infrastructure.

Legend: `[x]` verified this continuation; `[ ]` unfinished. Historical evidence is explicitly noted rather than treated as fresh verification.

## Current state and protected decisions
- [x] Current handoff and mapped customer/AI/billing/chronological documentation read.
- [x] Cloud browser recovered; private-site ChatGPT sign-in succeeded.
- [x] Site owner-only: one owner, no visitors/groups; current Site version 50.
- [x] Designated marked customer confirmed in UI and database, non-admin Serious, original canceled billing metadata and launch marker intact.
- [x] Billing page confirms new purchases paused.
- [x] Backend diagnostic fix `063f58210209261ff96ca1247fac178ffd907746` / `dep-dbfrf8bncjis738kblhg` verified live; frontend source `bb652696ad90d9c692efb67eda6f969bcbbfa7b4` opened through Sites.
- [ ] Verify current backend configuration/diagnostic cleanup, price mappings, customer quotas and removed shared cutoffs from source/live state.

## Paid customer workflows
- [x] One deployed non-admin provider AI comparison: explicit consent, grounded evidence, request scope, allowance and cost settlement.
- [ ] AI duplicate/running/error recovery and refreshed availability (mark mocked/database/provider evidence separately).
- [ ] Pro and Serious permissions, Free denial, live access refresh.
- [x] AI comparison save/reopen/direct and saved JSON downloads parsed.
- [ ] Static report reopen/download and report-size boundary errors.
- [x] Deployed comparison save/reopen and direct comparison JSON download. Saved-report download event observed; downloaded bytes not yet verified.
- [x] Project creation/assignment/filtering, trash/restore preserves assignment.
- [ ] Second-customer browser isolation (database authorization checks passed).
- [x] Deployed comparison sharing/revocation UI; database authorization checks allow only named recipient and deny after revoke (not a second-customer browser test).
- [ ] Comparison JSON download and optional scan-both partial completion/accounting.
- [x] Deployed started-job cancellation returns control, preserves prior result and settles usage.
- [ ] Recheck pending-usage refresh fix; queued cancellation evidence remains historical.
- [ ] Current mobile layout, accessible controls and deployed download checks; physical device evidence separate.

## Scanner and reliability
- [x] Scanner-35 deployed unsent/sent Request pair, precise line/evidence.
- [ ] Additional current credential, HTML and branch-overwrite pairs.
- [x] Bounded deployed 20k/50k branching fixtures and correct allowance settlement (scanner 35; no sustained capacity claim).
- [ ] Review distinct-customer queue/overflow/isolation/cancellation against changes; historical seven-customer saturation recorded in controlled billing report.
- [ ] Review timeout cleanup/accounting against changes; historical deployed engine and whole-worker fault injections remain recorded.
- [ ] Sustained-load limits and multi-instance limitations documented without unsupported capacity claims.
- [ ] Deep source review: aliases/scopes/overwrites, source-to-sink accuracy, malformed/adversarial inputs, false positives/misses.
- [ ] Auth/ownership/RLS, source/log privacy, atomic quotas, queue lifecycle, AI grounding and billing consistency review.
- [x] Local scanner-35 paired regression fixes, 233 backend tests, 65/750/300 behavior accuracy gate and 72-case Semgrep CLI parity pass. Scanner 35 deployed evidence recorded; scanner 36 branch fix prepared.
- [ ] Continue deep review beyond these bounded cases.

## First-time customer
- [ ] Homepage/navigation/Plans/Privacy/Account/Billing/Security walkthrough.
- [ ] Fresh signup and confirmation/reset mail flow after changes; user completes credential changes securely.
- [ ] Provider password policy, rate limiting/CAPTCHA and lockout capabilities verified.
- [ ] Samples and edited-sample rejection, validation, return-to-plan behavior.
- [ ] Inline Keep editing / Start audit, input invalidation, stale results, findings/export/save clarity.
- [ ] Rank remaining conversion friction and implement confirmed fixes.

## Remaining capabilities (retain until completed or owner decision)
- [ ] GitHub App installation ownership and private-repository ingestion end to end; no customer PATs.
- [ ] Existing CI/PR, repository policy and suppression authorization review.
- [ ] Application-level/cross-file analysis design, implementation and evaluation; preserve explicit limitations meanwhile.
- [ ] Single-code AI intent review contract, evaluation corpus, metering and UI.
- [ ] Credit packs: owner pricing decision, transactional fulfillment, idempotency/refunds and usage semantics before activation.
- [ ] Cost monitoring and email alert proposal with explicit thresholds; no reinstated shared cutoff.
- [ ] Email sender/domain and inbox-logo capability verification; actual placement evidence separate from delivery.
- [ ] Serious workflow polish, repair prompts, retention/privacy notices and partial-coverage language.
- [ ] Focused educational content after scanner stability; general news deferred and profile address/phone optional.

## Private release and cleanup
- [ ] Update source/contracts/UI promises/tests together; commit and privately deploy fixes.
- [ ] Verify changed deployed paths, record exact revisions and evidence types.
- [ ] Recheck genuine billing state; restore designated grant to Free only after paid tests, remove only its marker, preserve other metadata and ordinary usage.
- [ ] Clear temporary diagnostics and checkout exceptions; verify no extra charge/subscription.
- [ ] Present remaining blockers and separate payment/public-launch decision sequence.

Continuation evidence and confirmed defects: `docs/CONTINUATION_2026-10-26.md`.
