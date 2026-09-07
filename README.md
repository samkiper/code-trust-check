# AI Code Audit

**Intent-aware static review for AI-generated code, public repositories, and GitHub pull requests.**

[Try the live scanner](https://code-trust-check.onrender.com/) · [Methodology](https://code-trust-check.onrender.com/methodology) · [Accuracy](docs/ACCURACY.md) · [Security](SECURITY.md) · [Support](mailto:support.aicodeaudit@gmail.com)

AI Code Audit helps beginners understand what generated code may do while giving experienced developers exact files, lines, rules, engine evidence, and remediation context. It does not execute submitted code.

> A clean result means no supported risk signal was found. It does not prove that code is safe, correct, or ready for production.

## What it checks

- credential access and possible secret exposure
- unexpected network connections and credential transmission
- risky execution, shell commands, unsafe deserialization, and download-to-execute behavior
- file access, hidden telemetry, obfuscation, and persistence signals
- behavior that may conflict with the user's stated intent
- known dependency vulnerabilities and selected package-supply-chain signals

## Three ways to use it

1. Paste or upload a supported source file in the [web scanner](https://code-trust-check.onrender.com/).
2. Enter a public GitHub repository URL for a bounded repository audit.
3. Install the [AI Code Audit Scanner GitHub App](https://github.com/apps/ai-code-audit-scanner) for automatic pull-request checks.

GitHub checks are monitor-only by default. A Pro user must explicitly save a repository policy before a finding can block merging.

## Result model

Every result leads with a next-step verdict:

| Audit score | Verdict |
| ---: | --- |
| 0–65 | Do not run this yet |
| 66–90 | Review before running |
| 91–100 | No major supported risks found; continue testing |

The score is a deterministic risk-weighted index for comparing revisions. It is not a probability, certification, or complete measurement of software security. Findings, coverage, and engine status matter more than the number.

## Language coverage

| Depth | Languages | Current analysis |
| --- | --- | --- |
| Deep | Python | syntax tree, local data flow, behavior rules, and local Semgrep |
| Standard | JavaScript, TypeScript | behavior rules and local Semgrep; no cross-file flow tracking |
| Basic | other accepted languages and configuration files | supported static patterns; depth varies |

See [docs/ACCURACY.md](docs/ACCURACY.md) for exact benchmark results and limitations. Python has the strongest external benchmark evidence. JavaScript and TypeScript measurements are internally curated regression evidence.

## Free and Pro

Security findings are not hidden behind a paywall.

| Free | Pro — $12/month |
| --- | --- |
| Manual paste and public-repository audits | Everything in Free |
| Up to 10,000 lines per file | Up to 20,000 lines per file |
| Up to 50 source files / 1 MB per repository | Up to 200 source files / 10 MB per repository |
| Full findings, fixes, dependency checks, and JSON report | Automatic GitHub pull-request checks |
| Beginner and Developer result views | Dashboard, history, and scan comparisons |
|  | Accepted-risk and false-positive workflows |
|  | Repository policies and optional merge blocking |

## Privacy boundary

- Submitted code is processed for the requested audit and is not executed.
- Manual scans do not retain a raw source-code copy after the request completes.
- GitHub scan history stores repository and pull-request metadata, fingerprints, counts, and sanitized finding explanations—not raw source code.
- Feedback records store labels and fingerprints, not the submitted code.

Read the full [privacy explanation](https://code-trust-check.onrender.com/privacy).

## Local development

Requirements: Python 3.12+

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

Run tests:

```bash
python -m unittest discover -s tests -v
```

The full accuracy gate also requires a checkout of the pinned OWASP BenchmarkPython revision documented in [docs/PRODUCT_V2_SETUP.md](docs/PRODUCT_V2_SETUP.md).

## Architecture

- FastAPI application and scanner orchestration: `main.py`
- Vanilla HTML/CSS/JavaScript interface: `static/`
- Local structural rules: `semgrep.yml`
- Regression and product tests: `tests/`
- Supabase server-only schema migrations: `supabase/`
- Accuracy and deployment documentation: `docs/`
- GitHub accuracy gate: `.github/workflows/accuracy-gate.yml`

External services are used for specific product functions: GitHub for repository integration, Render for hosting, Supabase for authentication and application records, Stripe for subscription billing, and OSV for supported dependency-vulnerability lookups.

## Security and feedback

- Service vulnerability: follow [SECURITY.md](SECURITY.md) and use a private GitHub Security Advisory.
- False positive or missed risk: use the scanner feedback control or the scanner-feedback issue template with a minimal non-sensitive reproducer.
- Product bug or feature request: use the matching GitHub issue template.

Never post credentials, private source code, private repository names, payment information, or personal data in a public issue.

## Licensing status

Copyright © 2026 North Third Street Media and Design LLC, doing business as North Third Street Media Group. All rights reserved.

This is proprietary software. The source is publicly viewable, but no permission is granted to copy, modify, distribute, sublicense, or commercially use it except where applicable law or a separate written agreement permits. See [LICENSE](LICENSE).

AI Code Audit is operated by North Third Street Media Group, a DBA of North Third Street Media and Design LLC. Contact [support.aicodeaudit@gmail.com](mailto:support.aicodeaudit@gmail.com) for private support, billing, privacy, or security questions.
