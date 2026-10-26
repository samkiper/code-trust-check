# AI Code Audit — current launch handoff

Checkpoint: October 26, 2026. This document consolidates the owner's latest decisions and the recorded verification history. Read it before older release notes. Verify live state before changing it; a checkpoint is not proof that a deployment or configuration has remained unchanged.

## Active continuation update

Read `docs/LAUNCH_CHECKLIST.md` and `docs/CONTINUATION_2026-10-26.md` first for progress after this checkpoint. The cloud browser recovered; the original browser-blocker section below is historical. Paid customer checks found and repaired AI evidence validation failures; scanner 35 now has real provider success, saved-AI download and 20k/50k deployed evidence. Scanner 36 and report/usage display fixes are prepared; see the continuation log for exact revisions and verification status. The temporary customer grant remains until paid verification and billing-aware cleanup are complete.

## Goal and operating instructions

Continue the existing project to customer-launch readiness, including the requested customer capabilities and future-feature work. Work independently on authorized fixes, tests and private deployments. Pause only for secure sign-in, a genuine missing business decision, or an actual tool/approval block. Keep an explicit checklist so unfinished features do not disappear from scope. Do not declare the entire project complete from a passing test suite.

- Keep the Site owner-private. Do not publish it or broaden its audience.
- General purchases remain paused. Paid testing access is authorized; public payment activation is a separate launch decision. Do not automatically charge the owner again to repeat already-completed payment tests.
- Preserve the site's visual identity and existing infrastructure. Do not request new API keys or recreate services.
- Customer AI is now authorized for verified Pro and Serious accounts. The older admin-only restriction is superseded.
- The shared $25 AI dollar ceiling and shared 100 MB saved-history cutoff were removed at the owner's request. Do not restore them based on old documentation. Preserve cost accounting, customer allowances, isolation, duplicate protection, bounded requests and timeout cleanup.
- Discuss changes to prices, customer allowances, new paid services or infrastructure purchases before implementing those business changes.
- Use inexpensive synthetic inputs and free/local checks first. A removed shared cap is not a reason for wasteful provider calls.
- Distinguish local, mocked, rolled-back database, sandbox financial and actual deployed customer/provider evidence. Never turn a static scan into a safety certification or complete-application claim.
- Inspect current source, `CUSTOMER_LAUNCH.md` and `RELEASE_AI_REVIEW.md` before editing. Read applicable skills. Prefer service connectors; use the requested cloud browser for customer UI and secure authentication. Do not extract session credentials or create an authentication bypass.

## Existing systems and last verified deployments

| System | Identifier / checkpoint |
| --- | --- |
| Website | https://aicodeaudit.org |
| Site project | `appgprj_6a9cdbe527c88191be4447005df951e9` |
| Site provider URL | https://ai-code-audit.samkiper.chatgpt.site |
| Backend repository | `samkiper/code-trust-check` |
| Backend origin | https://code-trust-check.onrender.com |
| Render service | `srv-d6ocvv1aae7s73a6gcog` |
| Render workspace | `tea-d6ocs8s50q8c73c6pr9g` |
| Supabase project | `ohabowduaydfaauqadqt` |
| Deployed backend code | `53a29b43235ec5846db363f9c22b89aee4004aba`, scanner 34 |
| Render deployment | `dep-dbfqmkeq1p3s738b9pbg`, verified live |
| Private Site source | `bb652696ad90d9c692efb67eda6f969bcbbfa7b4` |
| Private Site deployment | `appgdep_6adfabedd06c8191bbd39d51bdd04c8d`, succeeded |
| Saved Site version | `appgprj_6a9cdbe527c88191be4447005df951e9~appgver_825100ae7a7c8191b2e4599dfccb489a` |

Backend `61185867a736f79224af4737905f92e6d4e4b3c6` added benchmark/documentation and `9ac2155216971723fa653b3f58f18da6f47f7fcb` added the browser checkpoint after the runtime deployment. The commit introducing this handoff is also documentation-only. Newer repository HEAD does not necessarily mean newer deployed runtime code. Inspect current branches/deployments instead of deploying an old checkpoint blindly.

Last inspected Site access: owner-only custom audience, one owner, no groups or external visitors. Source is managed by Sites; obtain its current source repository through that connector rather than treating the backend repository as the frontend.

## Browser blocker and exact recovery point

The cloud browser failed after a phone-width iframe download wait timed out and reset its kernel. It repeatedly returns:

> Browser observation is unavailable because native credential state cannot be safely resumed. Start a new browser runtime to continue.

A runtime reset, individual-site browser-data clearing by the owner, and further requested retries did not restore access. The latest retry failed before reaching the site. No site change resulted. A new Work chat is the next recovery attempt, not a guaranteed fix. Old tab handles and bindings must not be reused.

First check cloud-browser access. If it works, open the existing site and use the secure sign-in flow for the designated customer account. Do not put passwords or one-time codes in ordinary chat. If it still fails, report the exact platform blocker and continue independent source/connector work where useful; do not loop resets, weaken authentication, or use another tool to recover protected browser credentials.

On recovery, give download event waits explicit short bounds (for example 10 seconds within a longer tool timeout). Verify download events in a main tab. A local narrow iframe is only a layout check and cannot establish deployed phone-download behavior. The temporary `qa-phone.html` fixture was removed before the last Site package.

## Authorized temporary paid customer access — cleanup required

The owner explicitly authorized testing paid customer capabilities while keeping the Site private. Earlier automatic rejections occurred before that explicit instruction and made no changes; they do not remain an approval blocker for this scoped grant.

- Resolve the designated customer by `auth.users.raw_app_meta_data.aca_launch_test_marker = launch-customer-20261026`. The owner can identify the email in the continuation prompt; do not assume a different signed-in account is equivalent.
- The existing non-administrator customer was temporarily Pro, then Serious. The latest verified state is Serious; original plan was Free, with a canceled live subscription. No administrator role, live Stripe subscription or charge was added.
- Live database checks confirmed Pro 25 AI reviews and Serious 100, plus Serious 200 reports / 365 days / 50 projects. There is no shared dollar ceiling. These checks prove entitlement availability, not an actual AI-provider result or paid checkout.
- Preserve this temporary Serious access while the browser is blocked. During testing, switching this same designated account between Pro and Serious is authorized without admin privileges or charges.
- After paid testing, re-read billing state, restore the original Free plan and remove only this marker, preserving all other metadata. If a genuine intervening paid subscription exists, reconcile it rather than overwriting it.
- Do not reset ordinary usage to hide test consumption. If QA receipts require cleanup, identify and verify only the specific receipts; do not clear a customer's whole ledger.

## Approved pricing, limits and comparison distinction

| Feature | Free | Pro | Serious |
| --- | --- | --- | --- |
| Price | $0 | $19/month | $69/month or $690/year |
| Monthly audits, repository audits included | 5 total / 1 repository | 75 total / 10 repositories | 300 total / 40 repositories |
| Pasted line limit | 2,000 | 20,000 | 50,000 |
| Repository limit | 20 files / 1 MB | 100 files / 10 MB | 500 files / 25 MB |
| Monthly AI comparisons | 0 | 25 | 100 |
| Saved reports / retention | None | 50 / 30 days | 200 / 365 days |
| Project folders | 0 | 10 | 50 |

Account allowances reset on the account anniversary, including Serious annual subscriptions. Snippets still have a 1 MB byte limit regardless of their line allowance. Saved payloads remain bounded to 256 KB each. Do not infer that every 50,000-line input fits those byte bounds or that every downloaded repository report fits saved-report storage; verify and explain those cases.

Basic text comparison runs locally and is unlimited; it does not spend AI credit. AI comparison is a separate, consented, metered provider operation. Free has no recurring AI reviews. The optional scan-both comparison action uses two separately metered static audits; the UI must explain partial completion/accounting. Anonymous users can run exact server-controlled audit examples and a comparison example. Altering the audit example's source, intent, language or filename must not bypass authentication or quotas.

## Work order and acceptance criteria

1. **Recover the browser and confirm identity/access.** Verify current private audience, paused purchases, scanner/Site revision and the ordinary customer plan. Use secure login. Do not require another paid transaction merely to obtain test access.
2. **Finish paid workflows on the current private deployment.** Exercise one carefully selected real non-admin AI comparison, explicit code-transmission consent, grounded change/evidence output, refreshed allowance, repeat/duplicate/running states and understandable provider-error recovery. Use controlled fixtures for destructive/failure paths where practical; distinguish those from real provider tests. Verify Pro and Serious permissions, Free denial, paid saving/projects, report downloads, access refresh, sharing/revocation and customer isolation. Verify comparison downloads and scan-both accounting. Check large-report storage errors without silent truncation or misleading saving claims.
3. **Finish current-version scanner and reliability checks.** Run paired harmless/dangerous examples with exact expected lines/evidence; new scanner-34 credential and HTML regressions; bounded complex 20k/50k deployed inputs within byte limits; distinct-customer queue/cancel/overflow/isolation; timeout cleanup and allowance accounting. Reuse historical evidence below and recheck changed paths rather than pretend earlier work never happened. Sustained production capacity remains unproven. Never execute submitted source.
4. **Repeat the first-time-customer walkthrough.** Homepage, navigation, Plans, Privacy, Account/Billing/Security, buttons, validation, signup, branded confirmation/reset, return-to-plan flow, sample labeling, inline confirmation, comparison, findings, saving, exports, mobile width and accessibility. Preserve the requested confirmation location: Keep editing and Start audit side by side where the initial click occurred. Editing must invalidate confirmation/results appropriately. Verify no horizontal clipping and report mobile-layout versus physical-device evidence accurately. Rank residual conversion friction by impact and propose exact fixes.
5. **Review the scanner and security architecture deeply.** False positives and misses, alias/scope/source-to-sink accuracy, malformed inputs, adversarial intent, grounded AI evidence, source/privacy logging, auth/ownership/RLS, quota concurrency, queue lifecycle and payment entitlement consistency. The owner requested a high-reasoning review; do not claim a model setting that cannot be observed. Fix confirmed issues and run meaningful tests without weakening detection to make benchmarks pass.
6. **Deliver the requested remaining capabilities in dependency order.** Keep the backlog below visible. Implement within existing authorized scope where feasible; surface only real design/business decisions. Do not silently mark features complete or bury them as permanent deferrals. Update contracts, UI promises, tests and deployment evidence together.
7. **Private release and launch decision.** Commit fixes, run relevant regression/accuracy/build checks, deploy privately, verify changed live paths, document evidence and cleanup. Restore the temporary grant after testing and clear any temporary diagnostics/checkout exceptions. Present completed items, remaining blockers and proposed payment/public-launch sequence. Public audience and general purchase activation require the owner's explicit launch decision.

## Features and unresolved decisions that must not be forgotten

- **Private GitHub repositories / GitHub App:** existing App integration exists, but customer installation ownership and private ingestion need end-to-end review. Use installation authorization, not raw customer personal access tokens. Review existing CI/PR, policy and suppression features before claiming full paid capability.
- **Cross-file / application-level analysis:** absent. Current repository files are scanned independently and the repository path does not use the same snippet Semgrep path. A larger Serious quota is not complete-application security coverage. Design and evaluate cross-file support if implementing the requested full-application capability; keep limitations explicit until then.
- **Single-code AI intent review:** separate from implemented comparison review; needs its own grounded output/evidence contract and evaluation corpus. Do not represent comparison AI as already supplying it.
- **AI credit packs:** not implemented or sold. Earlier $5 / 25-credit concept is not an active product. Requires a pricing decision plus transactional Stripe fulfillment, idempotency, refunds and usage semantics before activation.
- **Cost operations:** cost accounting remains; shared dollar ceiling is removed. No email spending alerts are configured. Do not treat historical 80%/90% cap warnings as a functioning current alert system without a defined threshold. Propose operational monitoring without reinstating the removed cap silently.
- **Email/auth:** signup and automatic confirmation sign-in were confirmed by the owner, and branded password reset worked. Recheck after recent changes. Sender-logo/inbox placement needs actual domain/provider capability verification; HTML branding alone cannot set inbox avatars. Older notes leave provider-side password complexity, rate limiting/CAPTCHA and exact lockout capability unresolved; inspect current settings before deciding what is still open. Do not invent provider enforcement from UI-only tests.
- **Customer trust and UX:** retain truthful partial-coverage statements, repair prompts, understandable stale results and saved-data/retention/privacy notices. Never label all suspicious findings on third-party code confirmed vulnerabilities without triage. Serious workflow polish remains part of the overall review.
- **Content/profile ideas:** focused educational content can follow a stable scanner; a general news blog was deferred. Address/phone remain optional future profile fields, not registration requirements. Recover relevant earlier attachments if a proposed feature depends on details not in repository notes; do not invent their contents.

## What is already done — avoid unnecessary repetition or charges

Historical production/customer evidence is real but predates the final scanner-34/Site follow-up. The original four checks were substantially exercised; remaining work includes fresh regression of changed paths, not starting all four from zero.

- **Billing:** `docs/CONTROLLED_BILLING_RESULT.md` records actual normal-route $19 Pro and $69 Serious monthly live payments, access grants, immediate cancellation, successful full Stripe refunds and restored Free/canceled access. Card-statement posting was not independently verified. General checkout exceptions were removed, prices returned inactive and purchases paused. Do not charge again just to rediscover these results.
- **Sandbox billing:** provider renewal, failed renewal/recovery, scheduled cancellation, signed webhook persistence and calendar renewal/period-end cancellation were exercised. Serious monthly $69 and annual $690 sandbox mappings granted the correct plan; annual live settlement was not exercised. Sandbox customer-portal cancellation UI was tested; live Serious portal cancellation was not. Temporary receiver signing secrets/destinations were disabled after tests.
- **Deployed queue:** seven separate confirmed Free customers exercised six accepted jobs (one running/five waiting), seventh 429, same-account duplicate 409, cross-account lookup 404, six completions and correct charges. Identified QA receipts were refunded after verification. Approximately 38 seconds was total observed test time, not raw engine throughput. This was not sustained-load or multi-instance verification.
- **Deployed timeouts:** exact-source expiring diagnostics separately verified real Semgrep timeout cleanup/refund and whole-worker timeout cleanup/refund, each followed by a normal successful queued scan without restart. Diagnostic settings were cleared. These are controlled fault-injection results, not naturally occurring timeout measurements.
- **Large deployed scans:** earlier 2k/10k/20k and approximately 50k synthetic scans completed. A 49,996-line / 434,570-byte scan took about 20.3 seconds from reservation to report timestamp including polling/rendering. A later 50k Serious test also completed both engines. A Django repository scan selected 500 of 3,567 supported files and correctly reported partial coverage; 175 findings were untriaged, not confirmed vulnerabilities or full-app coverage.
- **Signup and samples:** the owner confirmed fresh self-service signup and confirmation-link automatic sign-in; signed-out Try sample audit labeling and exact-example checks were implemented. The owner previously confirmed mobile downloads and supplied matching reports, parsed successfully. That history does not substitute for current-version paid phone download checks.
- **Scanner 33 customer pair:** signed-in non-admin safe fetch + URL-to-textContent yielded no findings; changing only to innerHTML yielded the correct high finding at line 3. JSON/text exports were parsed with no echoed source/account metadata. Those two scans used the account's remaining Free allowance. Keep editing preserved input/no charge; edits marked stale results.
- **Scanner 34 deployment:** `/github/status` returned 34; both exact built-in examples completed with both engines, about 6.0 and 4.6 seconds. Custom scanner-34 customer cases and paid AI provider results remain pending.

## Latest fixes and validation

Backend scanner 34 includes bounded call parsing, Python credential-flow aliases/scopes/overwrites, destination-aware credential handling and JavaScript URL-to-HTML taint checks. Latest fixes distinguish an unsent `urllib.request.Request` from `urlopen`, inspect condition/loop/context calls, prevent harmless MONKEY_COUNT/KEYBOARD_LAYOUT/TOKENIZER_MODE credential matches while preserving real secret-name detection, and handle malformed literal URLs.

Private Site follow-up includes interruptible status polling/retry waits during cancellation, retained job submission identity, AI availability refresh and stale-response protection, clear Free versus paid saving guidance, direct comparison JSON download and input-bound confirmation. Normal confirmation/edit invalidation were checked; an extremely rapid local sequence of fill/click remained inconclusive and must not be called conclusively fixed.

Latest local results: **224 backend tests, 120 Site tests**, scoped TypeScript check including comparison components, production Site build, eight real-engine launch regression methods, and pinned behavior accuracy gate (65 internal / 750 OWASP / 300 neutral-intent holdout) passed. The benchmark report was unchanged. The behavior gate is not the same as the separate real-Semgrep tests. Remote GitHub workflow results were not available for the latest runtime commit; do not claim CI success from local results alone.

`source .venv/bin/activate` is needed before backend tests so the installed Semgrep binary is on PATH. `python scripts/benchmark_capacity.py --serious` generates a valid 50,000-line / 543,318-byte fixture: both real engines completed locally in 19.921 seconds with the seeded finding. This is not production capacity. A local 390px iframe had no comparison-page horizontal overflow, but its download wait failed; current paid/mobile downloads remain open.

Live database transactions verified quota/running/duplicate/failure-refund enforcement, synthetic cost above the old ceiling, storage sharing/revocation and isolation, with fixtures rolled back. Those checks made no AI-provider call. Latest non-admin grant checks also made no AI-provider call.

## Documentation map and precedence

1. This handoff: current decisions, scope, work order and consolidated checkpoint.
2. `CUSTOMER_LAUNCH.md`: latest release and browser/test-grant details; read all follow-up sections.
3. `RELEASE_AI_REVIEW.md`: AI architecture and timeout/billing contracts; its later owner update supersedes the original $25/admin-only paragraphs.
4. `docs/CONTROLLED_BILLING_RESULT.md`: completed live payment/refund, seven-customer queue, induced timeout and Serious results; later sections close earlier gaps.
5. `docs/PRIVATE_VALIDATION_2026-10-26.md`: longer chronological history; early pending gates and restrictions are superseded by later results and this checkpoint.
6. `RELEASE_SERIOUS.md`, `docs/SCAN_ALLOWANCES.md`, Site `docs/AUTH_AND_LAUNCH_REVIEW.md` and `docs/REVISION_REVIEW.md`: useful historical rationale, but several limits, reset rules, disabled features and pending claims are stale. Resolve against current plan catalogs/source, newest owner decisions and verified live state; do not restore obsolete values.

Keep this handoff/checklist current as work closes. End each substantial work period with the exact deployed revisions, evidence type, remaining blockers and cleanup state so future chats can resume without repeating completed work.
