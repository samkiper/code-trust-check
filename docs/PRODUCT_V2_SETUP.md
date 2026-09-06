# AI Code Audit v2 setup

## What is now built

- The intent-aware behavior engine remains the source of the calibrated trust score.
- A local Semgrep engine independently checks structural security rules. Code is written only to a temporary directory for the scan and is not sent to Semgrep's registry or telemetry service.
- Results include six evidence categories, reviewable patch previews, JSON downloads, and SARIF 2.1 output.
- A GitHub App webhook scans changed supported pull-request files and publishes a monitor-only GitHub Check with line annotations.
- The regression suite contains 265 formatting variants derived from 53 labeled base scenarios.
- The accuracy gate measures 53 internal cases, 750 category-assisted OWASP BenchmarkPython cases, and a separate 300-case OWASP holdout scanned without vulnerability-category hints.
- Signed-in users can mark findings accurate, report false alarms, or report a missed risk. Feedback records fingerprints and labels only; submitted code is not stored.
- Dependency review checks published advisories, likely package-name typos, missing registry packages, and unpinned direct-source installs.
- Review-only “Fix this safely” previews cover unsafe YAML loading, disabled TLS verification, production debug mode, and dynamic `eval`.

## Accuracy gate

Run the same gate locally with a checked-out copy of the official OWASP Python benchmark:

```bash
python scripts/run_accuracy_gate.py --owasp-dir ../BenchmarkPython --limit 750 --holdout-limit 300
```

The current measured report is committed as `accuracy-report.json`. The gate fails if recall falls below the committed floor or false-positive rate rises above it. This prevents regression; it is not a claim that every vulnerability class is already detected well. Current limitations and exact category results are documented in `docs/ACCURACY.md` and exposed at `/accuracy/status`.

To make the gate block a Render release, set the service's **Build Command** to:

```bash
bash scripts/render_build.sh
```

Also configure Render to wait for GitHub checks before auto-deploying when that option is available for the service.

## Feedback setup

In Supabase, open **SQL Editor**, paste the contents of `supabase/scan_feedback.sql`, and run it once. The table has row-level security enabled and denies browser clients direct access; the authenticated backend writes the minimal feedback record with the existing Supabase secret key.

## Render environment variables

Semgrep runs by default after the new dependency is installed. Set `SEMGREP_ENABLED=false` only if the Render instance cannot support the additional package.

To activate GitHub pull-request checks, create a GitHub App and add these Render variables:

| Variable | Value |
| --- | --- |
| `GITHUB_APP_ID` | The numeric GitHub App ID |
| `GITHUB_PRIVATE_KEY` | The complete PEM private key |
| `GITHUB_WEBHOOK_SECRET` | A new random webhook secret |
| `GITHUB_APP_SLUG` | The public slug from the GitHub App URL, used to show the install button |

Configure the GitHub App with:

- Webhook URL: `https://code-trust-check.onrender.com/github/webhook`
- Subscribe to: Pull request
- Repository permissions: Metadata read-only, Contents read-only, Pull requests read-only, Checks read and write

After installing the App on a repository, opening or updating a pull request queues a static scan of changed supported files and produces an **AI Code Audit** check. Findings use a neutral conclusion and do not block merging. Each annotation includes a severity label, explanation, suggested fix, and a link to the pull request's changed files. Re-delivered webhooks update the same check instead of creating duplicates.

The public status endpoint at `/github/status` reports only whether each required setting exists, the public installation URL, and the integration capabilities; it never returns secrets.

## SARIF API

Send the same JSON accepted by `/scan` to `/scan/sarif`:

```json
{
  "intent": "Parse a user preference",
  "code": "value = eval(user_input)"
}
```

The response is SARIF 2.1 and can be uploaded to GitHub code scanning or consumed by compatible developer tools.

## Dynamic sandbox boundary

The web service does not execute submitted code. A future dynamic-analysis service should be separate infrastructure with:

- an ephemeral microVM or hardened container per scan,
- no application secrets,
- outbound networking disabled by default,
- read-only base image and disposable storage,
- strict CPU, memory, process, and wall-time limits,
- an event log returned to this service for explanation.

Running untrusted customer code directly inside the Render web process would put the application, its Stripe and Supabase credentials, and other customers at risk, so it is intentionally not enabled.
