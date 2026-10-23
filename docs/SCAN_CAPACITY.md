# Interactive scan capacity

The existing Render service runs one Uvicorn process on one free instance.
Snippet, SARIF, repository, and fix-preview HTTP requests share one worker-owned
permit. A competing request receives HTTP 429, Retry-After: 10, and no-store;
it has not started analysis and does not receive a fabricated scan result.
The existing Site displays its busy/retry error and retains the user's input.

The permit is held until the synchronous handler actually finishes, including
when the client disconnects. Exceptions release it in finally. Health checks
and account routes do not take this permit. This is admission control, not a
queue, a throughput improvement, or an additional security engine.

This bound is per process. Revisit it before changing Uvicorn worker count or
Render instance count. Background GitHub workflows are outside this interactive
request bound and need coordinated capacity if enabled alongside customer scans.

Regression tests use a blocked worker to verify rejection across all four
routes, no engine invocation for rejected requests, health availability, retry
with full findings after completion, and release after exceptions.
