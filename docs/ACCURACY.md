# Scanner accuracy and limitations

AI Code Audit is evaluated against two distinct datasets. Internal labeled scenarios cover the tool's intent-aware and AI-specific behaviors across Python, JavaScript, TypeScript, Java, Go, Rust, PHP, shell, SQL, HTML, CSS, and configuration files. A separate category-balanced set of 750 cases comes from the official OWASP BenchmarkPython project pinned to revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.

## Current measured baseline

| Dataset | Cases | Precision | Recall | False-positive rate | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Internal independent cases | 53 | 100.00% | 100.00% | 0.00% | 100.00% |
| OWASP category-balanced cases | 750 | 100.00% | 92.83% | 0.00% | 96.28% |

The internal result demonstrates performance on the product's deliberately supported behaviors. On the selected OWASP cases, the engine has complete recall with no false positives for command injection, code injection, unsafe deserialization, weak hashes, LDAP injection, unsafe redirects, insecure cookie transport, SQL injection, trust-boundary violations, weak security randomness, and XSS. Flow-sensitive checks reach 85.29% recall for XPath injection and 69.44% for path traversal, with no false positives. XXE recall remains 25% with no false positives. Each OWASP case is scanned with its benchmark category supplied as intent context because the dataset does not include a natural-language description of the program's intended behavior. The product must therefore describe these results as a review aid, not a complete security guarantee.

Exact confusion matrices and per-category measurements are in `accuracy-report.json` and the public `/accuracy/status` endpoint.

## Release rule

Every pull request and main-branch update runs unit tests and the pinned 750-case OWASP gate. A change fails when it falls below `tests/accuracy_thresholds.json`. Thresholds are conservative no-regression floors based on measured performance. They should only move upward when new labeled evidence supports the change.

## Feedback rule

The feedback control stores the signed-in user ID, a one-way scan fingerprint, a finding fingerprint, verdict, category, optional short note, and scanner version. It does not store source code. Feedback is evidence for adding a reviewed test case; it does not automatically retrain or weaken the scanner.

## Next accuracy work

1. Raise OWASP recall category by category without exceeding the false-positive ceiling.
2. Add reviewed false-positive and missed-risk reports to an isolated labeled test set.
3. Add language-specific external benchmarks as stable, redistributable datasets become available.
4. Keep safe-fix previews narrow, deterministic, and review-only until their semantic correctness is independently tested.
