# Security policy

## Reporting a vulnerability

Please report vulnerabilities through a [private GitHub Security Advisory](https://github.com/samkiper/code-trust-check/security/advisories/new).

Do not open a public issue containing:

- exploit details that could put the hosted service or users at risk
- API keys, passwords, tokens, cookies, or webhook secrets
- private source code or private repository names
- billing, identity, or customer information

Include the affected surface, expected and observed behavior, reproduction steps, and impact. Use a minimal non-sensitive example whenever possible.

## Appropriate reports

- authentication or authorization failures
- unintended repository access
- webhook signature or installation-token problems
- source-code retention outside the documented boundary
- scanner isolation or command-execution vulnerabilities
- exposure of secrets, account data, or billing identifiers
- practical abuse paths against the hosted service

Scanner false positives and missed detections are valuable, but they are normally product-quality reports rather than vulnerabilities in the service. Use the scanner-feedback issue template for those cases unless the behavior exposes the service or another user.

## Supported version

Security fixes are applied to the current production version on `main`. Older versions are not maintained as separate supported release lines.

