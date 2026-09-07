# Scanner accuracy and limitations

AI Code Audit is evaluated against three distinct sets. Internal labeled scenarios cover the tool's intent-aware and AI-specific behaviors across Python, JavaScript, TypeScript, Java, Go, Rust, PHP, shell, SQL, HTML, CSS, and configuration files. Two external sets come from the official OWASP BenchmarkPython project pinned to revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`: a published 750-case category-assisted set and a separate 300-case no-hint holdout.

## Current measured baseline

| Dataset | Cases | Precision | Recall | False-positive rate | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Internal independent cases | 53 | 100.00% | 100.00% | 0.00% | 100.00% |
| OWASP category-assisted cases | 750 | 100.00% | 100.00% | 0.00% | 100.00% |
| OWASP no-hint holdout | 300 | 100.00% | 96.91% | 0.00% | 98.43% |

The category-assisted set now has complete recall and no false positives across its 14 represented vulnerability categories. The holdout excludes all 750 published cases and gives every file the same neutral instruction: `Review this code before it is used in production`. On that first frozen evaluation, the scanner found 94 of 97 vulnerable cases, accepted all 203 safe cases, and missed three weak-randomness cases. It achieved 100% recall on the holdout's hash, path-traversal, and XPath-injection cases.

“Holdout” has a narrow meaning here: those 300 files were excluded from the published 750-case set and were first scored only after the v13 logic and regression tests were frozen. They still come from the same OWASP generator family, so this is evidence against simple case memorization—not proof of performance on arbitrary production repositories or every kind of AI-generated code. The scanner remains a review aid, not a security guarantee.

Exact confusion matrices and per-category measurements are in `accuracy-report.json` and the public `/accuracy/status` endpoint.

## Release rule

Every pull request and main-branch update runs unit tests, the pinned 750-case OWASP gate, and the separate 300-case no-hint holdout. A change fails when it falls below `tests/accuracy_thresholds.json`. Thresholds are conservative no-regression floors based on measured performance. They should only move upward when new labeled evidence supports the change.

## Feedback rule

The feedback control stores the signed-in user ID, a one-way scan fingerprint, a finding fingerprint, verdict, category, optional short note, and scanner version. It does not store source code. Feedback is evidence for adding a reviewed test case; it does not automatically retrain or weaken the scanner.

## Scanner v15 regression

Scanner v15 extends credential-flow analysis across multiline network calls. The regression suite includes both an unexpected multiline credential transmission and a legitimate multiline HTTPS authentication request, ensuring the former is flagged without turning the latter into an exfiltration false positive.

Scanner v16 improves GitHub Check presentation without changing risk scoring: severity counts, review summaries, explanations, suggested fixes, and pull-request file links are included directly in the check result.

Scanner v17's existing-installation authorization patch changes account-linking behavior only. It does not change detection rules, weights, benchmark selection, or published accuracy measurements.

Scanner v17 is a product-integrity release and does not change the v16 detection weights. It replaces definitive safety language with supported-signal language, exposes per-scan coverage and limitations, gives users an action-oriented verdict, and makes all findings accessible in the web interface. The published accuracy baseline therefore remains the v16 scoring baseline.

## Next accuracy work

1. Preserve the no-hint holdout without tuning against its three misses; use a new development set for weak-randomness improvements.
2. Add reviewed false-positive and missed-risk reports to an isolated labeled test set.
3. Add language-specific external benchmarks and independently sourced production-like examples as stable, redistributable datasets become available.
4. Keep safe-fix previews narrow, deterministic, and review-only until their semantic correctness is independently tested.
