# Contributing

AI Code Audit welcomes reproducible bug reports, carefully scoped feature requests, and non-sensitive scanner feedback.

## Before opening an issue

1. Confirm the behavior on the current live version or current `main` branch.
2. Remove credentials, private source code, personal information, and private repository identifiers.
3. Reduce scanner examples to the smallest code sample that reproduces the result.
4. Include the scanner version, language, scan mode, expected result, and observed result.

## Pull requests

Code contributions are not accepted unless the operator explicitly requests them and supplies written contributor terms. The repository is proprietary; public visibility does not grant reuse rights. You may still open an issue describing a proposed change.

Maintainers should run:

```bash
python -m unittest discover -s tests -v
```

Detection changes must also pass the pinned accuracy gate and must not lower committed regression thresholds without new reviewed evidence.

## Scanner feedback rule

User feedback is evidence for review, not an automatic rule change. A false-positive or missed-risk report must be converted into a minimal, independently reviewed test case before scanner behavior is changed.
