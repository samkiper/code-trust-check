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
