# Scanner reliability repair (v21)

## Changes

- Explicit `language` and optional `filename` on snippet requests; no unknown-language fallback to Python.
- Independent Python AST and pinned Tree-sitter JavaScript/TypeScript syntax validation. Comments/docstrings-only Python and comments-only JS/TS have no meaningful coverage. Unsupported languages retain pattern findings without a score.
- `coverage_validated`, `scan_status`, parser status, meaningful coverage and submitted/analyzed counts. Partial and not-rated scans have null scores. Repository files carry individual coverage states.
- Semgrep checks errors and analyzed targets rather than treating exit code alone as success. Its separate findings influence the final action verdict.
- Dynamic code execution is described separately from system commands. Negative intent clauses cannot authorize behavior.
- Exception logs record types, not exception text; missing finding confidence stays missing. Provider log retention is still unverified.
- Disable Semgrep's remote version check and explicitly use the OSS engine. The configured detection rules, timeout budget, and retry behavior remain in place.

## Verification

120 unit/regression tests pass. The accuracy gate passes: 65 internal cases; 750 OWASP cases; 300 no-hint holdout cases with 3 existing misses. These bounded benchmarks do not establish general detection accuracy. Report matches the existing committed accuracy-report.json.

Real local Semgrep runs verified safe Python, malformed Python, comments, untrusted eval, valid and malformed TypeScript, and unsupported Rust. Submitted code was never executed.

Paired startup comparison: three identical local targets/rule sets, fresh version-check cache for each request. Before: 4.563 / 4.615 / 4.891 seconds. After: 1.883 / 1.884 / 1.714 seconds. All six completed with zero findings. Reproduce with `PATH="$PWD/.venv/bin:$PATH" python scripts/benchmark_semgrep_startup.py`. These are local timings, not Render production results.

## Deployment boundary

Base main commit: ea56c1bc798b9bf2a0f30617db2d0705bd0e3920. Render auto-deploy configuration must be inspected before updating its tracked branch. Repository documentation recommends an accuracy-gated build, but does not prove the live configuration. Do not claim this revision is deployed until the service reports scanner_version 21 and production cases pass.

The Site tolerates old responses by preserving findings while withholding ratings until `coverage_validated` and `scan_status` are supplied. Runtime Render logging/retention remains an access-dependent verification item.
