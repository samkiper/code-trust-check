# Interactive scan capacity

The existing Render service runs one Uvicorn process on one 1-CPU/2-GB instance
(configuration checked November 7, 2026).

Customer `/scan-jobs` submissions use an in-memory FIFO: one running job and
at most five waiting jobs, with one outstanding job per account. A full queue
rejects the submission before reserving an allowance. Canceling a waiting job
releases its slot without charging; canceling a running job may still count
if analysis completes. Completed results expire after ten minutes or earlier
when the retained-result limit is reached. Restarting the process loses queued
work and results; customers must retry. Unsettled usage reservations expire
without becoming charges.

Snippet, SARIF, repository, and fix-preview handlers share one worker-owned
permit. A competing direct request receives HTTP 429, Retry-After: 10, and
no-store; it has not started analysis and gets no fabricated scan result.
The Site shows queued status for asynchronous submissions and retains input
when a direct scan or queue submission is rejected.

The permit is held until the synchronous handler actually finishes, including
when the client disconnects. Exceptions release it in finally. Health checks
and account routes do not take this permit. The permit is admission control;
the separate FIFO orders waiting work. Neither adds scanner throughput.

This bound is per process. Revisit it before changing Uvicorn worker count or
Render instance count. GitHub pull-request submissions now share the same FIFO
and recheck entitlement when work starts.

Regression tests use a blocked worker to verify rejection across all four
routes, no engine invocation for rejected requests, health availability, retry
with full findings after completion, and release after exceptions. The customer
queue integration tests additionally exercise seven competing HTTP clients with
the real scanner and isolated identity/ledger fixtures; they are not a live
multi-account production test.
