# AI review private validation (scanner / Site v32)

Implemented: optional GPT-5.4-mini Responses request, store=false, no tools, strict structured output; independently checked hunk IDs and evidence; every changed block required. Max combined source 32,000 UTF-8 bytes, 30 changed blocks, 2,000-character request, 4,000 output tokens. No source execution. Basic diff remains local, unlimited up to 1 MB/version. Explicit consent and save actions; no automatic report storage.

Cost protection: service-only Supabase ledger; global advisory lock, $0.10 reservation/request, $25 UTC-calendar-month pilot cap across all users and restarts (approved October 26, 2026). Duplicate request IDs and simultaneous requests per user rejected. Recorded cost uses provider token counts at uncached $0.75/$4.50 per million, rounded up. Failed customer reviews refunded; uncertain provider spend keeps the full reservation. Interrupted reservations release customer allowance after 3 minutes, retain dollars. No automatic provider retries. Source/prompts never saved to ledger or exception logs.

Validation is admin-only. Customer AI review remains unavailable, purchases paused. Implemented future anniversary quotas: Free0/month, Pro25/month, Serious100/month (no daily extras). Launch budget needs a deliberate revision after measured demand; never automatically raise the approved $25 monthly ceiling. Credit-pack fulfillment and Serious billing mappings remain launch gates.

Privacy: OpenAI standard retention can include 30-day abuse logs; store=false is not zero retention. UI explicitly discloses transmission. Account data-sharing settings not independently verified. Usage metadata has no scheduled purge during private validation. Saved report retention remains existing opt-in policy.

Saved-report backend auth/database calls now run off the async event loop; no scanner rules removed. Regression tests validate budget/ownership/isolation and malformed, missing, duplicate, or fabricated evidence. Model fixtures in unit tests are mocks; live provider results must be reported separately.

Budget warnings (80%, 90%, exhausted) and next UTC reset are returned to the administrator through the usage API. No email alert, auto-recharge, automatic budget increase, or customer AI activation is configured. Testing still aims to remain below $2 total; a $25 cap is not permission to spend it unnecessarily.

## Scanner timeout recovery

Semgrep runs in its own process group; a deadline kills and reaps the scanner before the capacity permit is released. Exhausted engine timeouts do not consume monthly scan allowance, even when the behavior engine returns useful partial coverage. A successful fallback after an earlier attempt timeout still counts as a completed scan.

A disabled-by-default diagnostic accepts only an exact synthetic source SHA-256 configured by the service operator (`SCAN_TIMEOUT_VALIDATION_SHA256`) and an absolute UTC expiry (`SCAN_TIMEOUT_VALIDATION_EXPIRES`) within 15 minutes. It shortens the real Semgrep subprocess deadline to 50 ms for that exact source only, with one attempt. It does not execute submitted source, bypass authentication or quotas, call AI, or expose a new route. Clear both settings after validation. This is controlled fault injection, not evidence of natural workload latency or whole-job deadline enforcement.

## Whole-audit analysis deadline

Snippet and repository analysis now run in a fresh trusted worker process with a 120-second wall-clock limit, including worker startup, repository download, dependency lookups, parsing, scanning and report construction. Submitted source is passed over stdin and is never executed. Authentication, reservation and settlement remain in the web process with their existing network timeouts; queue waiting is separate from analysis runtime. On overrun the entire worker process group is killed and reaped before capacity is released, the job returns 504, and its reserved allowance is refunded. The same cleanup runs on success and worker failure. Nested Semgrep processes stay within the worker group.

An operator-only diagnostic matches one exact synthetic source digest (`AUDIT_DEADLINE_VALIDATION_SHA256`) and a UTC expiry within 15 minutes (`AUDIT_DEADLINE_VALIDATION_EXPIRES`). It injects a ten-second scanner stall with a one-second supervisor deadline. This tests the actual supervisor kill and accounting paths without executing source, changing customer privileges or increasing spending. Clear the digest and set expiry to zero after testing.

## Paid plan mapping

Checkout selects only server-configured Pro monthly, Serious monthly, or Serious annual prices. Subscription verification, restoration and signed webhook handlers resolve access from an exact approved price ID plus subscription status; client-supplied prices, amounts and plan metadata cannot grant access. Unknown or ambiguous price sets grant Free. Both Serious billing intervals retain the same account-anniversary monthly allowances. The scoped sandbox adapter uses the same entitlement resolver, remains bound to one non-administrator test identity and cannot touch live billing accounts. Live checkout remains paused; controlled checkout defaults to Pro unless the operator explicitly selects Serious.

## Customer preparation — 2026-10-26

Supabase migration `enable_metered_customer_ai_reviews` permits verified Pro and Serious accounts using the existing service-only ledger: Free 0, Pro 25, Serious 100, Admin 400 per anniversary month. The $25 shared UTC-calendar-month ceiling and $0.10 reservation remain unchanged. Status now distinguishes plan, allowance, running request and shared budget blocks; availability is recalculated after reservation. No credit packs are sold. Site remains owner-private and payments paused.

Database verification: transaction-isolated, rolled-back checks of Free denial, Pro/Serious eligibility, duplicate request rejection, one active request, failure refund, quota exhaustion and shared budget exhaustion. No provider call or persistent plan change occurred in these checks. `anon` and `authenticated` cannot directly execute the ledger function. A signed-in non-admin end-to-end provider review still requires customer session verification before launch.

Scanner corrections: bounded call-argument extraction; Python credential tracking through import aliases with overwrite handling and destination-aware authentication exceptions; JavaScript URL-to-HTML taint rule. Full-engine regression pairs cover safe textContent/fixed markup, HTML sinks, fixed fetch formatting, alias egress, overwritten variables, unauthorized destinations and credential payloads. These tests are local evidence, not a production accuracy guarantee.

## Owner update — remove global spending cutoff

October 26, 2026: owner explicitly requested removal of the shared $25 cap. Cost reporting and conservative per-request accounting remain; the global dollar cutoff is removed. Per-account monthly allowances, one in-flight request/account, duplicate protection, source/output bounds, no automatic provider retry, and failed-review allowance refunds remain. Existing prices/allowances are unchanged. Previous references above to the $25 cap describe historical private validation, not the current policy.
