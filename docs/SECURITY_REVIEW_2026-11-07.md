# Dependency exposure review — November 7, 2026

Reviewed production source: `53b0c45c3ce79707c33e9509fdb775ed6d7c0577`.
The service starts `uvicorn main:app` with one process. This review is scoped
to that configuration and the pinned Semgrep 1.184.0 scanner.

A fresh isolated install, `pip check`, and `pip-audit` reproduced five
application advisories. The installer's own findings were removed by upgrading
the local test environment's pip to 26.3; that does not establish the deployed
installer version. No runtime dependency was overridden or audit suppressed.

| Dependency/advisory | Required exposure | Current application assessment |
| --- | --- | --- |
| mcp 1.29.0, [GHSA-84m7-p3x7-pcfv](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv) | Stateful Streamable HTTP MCP server | No MCP server is started or mounted by the application. |
| mcp 1.29.0, [GHSA-5h93-6whr-6q8j](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-5h93-6whr-6q8j) | MCP HTTP client following cross-origin redirects | Application does not create an MCP client or call MCP tools. |
| mcp 1.29.0, [GHSA-w4fh-qvv9-3v23](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23) | MCP server bearer authentication without audience checking | Application uses its own Supabase authentication, not MCP bearer middleware. |
| mcp 1.29.0, [GHSA-rwrf-2pqf-9j8j](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j) | MCP client validating remote tool output schemas | Application does not instantiate a client or accept remote MCP tool schemas. |
| opentelemetry-api 1.37.0, [GHSA-xcq7-p3pf-p88h](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-xcq7-p3pf-p88h) | Extraction of untrusted inbound `tracestate` headers | No incoming OpenTelemetry ASGI instrumentation or propagation extraction is configured in the application. HTTP headers are not passed into scanner workers. |

The scanner command is fixed to `semgrep scan` with local rules, metrics off,
version checking disabled, OSS-only mode, and one scan job. It does not use
`semgrep mcp`, `--trace`, or user-specified command options. The Python CLI
imports its MCP command registration; importing the package is not equivalent
to running the affected client/server transports. The scanner worker's
environment allowlist excludes tracing and provider credentials. Semgrep's
own `telemetry.py` extracts an internally constructed `traceparent` from
environment variables, not incoming application `tracestate` headers.

Upstream also lists MCP HTTP-body-limit and OAuth-issuer advisories
([GHSA-fmmv-w9g8-j3gc](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-fmmv-w9g8-j3gc),
[GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99)).
They were not among the five entries returned by this audit database; their
server/client prerequisites are also absent. Audit counts alone are not a
complete security assessment.

The reviewed paths do not expose these vulnerabilities. This is an exposure
assessment, **not a claim that the packages are patched or vulnerability-free**.
Semgrep pins `mcp==1.29.0` and the OpenTelemetry 1.37 series. Installing the
patched versions over those constraints would produce an unsupported dependency
set. Recheck this decision before public launch, when Semgrep updates, or before
adding MCP, incoming tracing, remote scanner rules, or different startup wrappers.
Do not enable those paths until compatible patched dependencies are available.

## Database checks

Live Supabase advisors reported service-only tables with RLS and no client
policies, profile GraphQL schema discoverability, and disabled leaked-password
protection. The profile table has RLS enabled: SELECT and UPDATE use
`auth.uid() = id`, and INSERT checks the same ownership predicate. Schema
discoverability does not by itself establish access to another account's rows.
Leaked-password protection remains a launch follow-up; no claim that it was
enabled is made here.

## Queue evidence and limits

`test_queue_customer_integration.py` exercises the real HTTP queue and real
isolated scanner with synthetic account and allowance fixtures. Seven competing
customers produce one running job, five waiting, and one rejected request.
Cross-account reads/cancellations fail, duplicate submission fails, queued
cancellation uses no allowance, and the rejected customer can retry after a
slot opens. Six successful scans settle exactly six charges. Malformed source
settles without a charge and the next customer's valid scan completes.

This supplements the unit tests for timeout, memory termination, and recovery.
It does **not** replace a live multi-account Render/Supabase saturation test.

## Backup/recovery launch gate

The production Supabase organization is still Free with no project backups.
The owner dashboard quoted $25 due today and $25/month estimated for Pro,
including daily backups retained for seven days and one Micro compute credit.
No upgrade was confirmed. Restoring over production is not a launch test.

After the backup arrangement is approved and enabled:

1. Verify a completed backup and record its timestamp and retention window.
2. Restore into an isolated destination; do not point its backend at live
   Stripe, email delivery, GitHub webhooks, or AI provider credentials.
3. Verify schema and migration parity, row counts, ownership enforcement,
   paid entitlement metadata, scan and AI counters, and saved-report expiry.
4. Verify that any separate Storage objects and external provider settings
   have their own recovery procedure. A database backup contains Storage
   metadata, not the objects themselves.
5. Record recovery time and the maximum potential data loss. Daily backups
   can lose changes after the last backup; seven-day retention is not PITR.
6. Document billing reconciliation before reopening checkout after recovery.
   Restore-time subscription state can be stale relative to Stripe; do not
   re-run payments or grant new allowances blindly.

Public launch remains blocked pending the separate launch-status record.
