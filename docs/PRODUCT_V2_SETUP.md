# AI Code Audit v2 setup

## What is now built

- The intent-aware behavior engine remains the source of the calibrated trust score.
- A local Semgrep engine independently checks structural security rules. Code is written only to a temporary directory for the scan and is not sent to Semgrep's registry or telemetry service.
- Results include six evidence categories, reviewable patch previews, JSON downloads, and SARIF 2.1 output.
- A GitHub App webhook can scan pull-request snapshots and publish a GitHub Check with line annotations.
- The regression suite contains 265 formatting variants derived from 53 labeled base scenarios.

## Render environment variables

Semgrep runs by default after the new dependency is installed. Set `SEMGREP_ENABLED=false` only if the Render instance cannot support the additional package.

To activate GitHub pull-request checks, create a GitHub App and add these Render variables:

| Variable | Value |
| --- | --- |
| `GITHUB_APP_ID` | The numeric GitHub App ID |
| `GITHUB_PRIVATE_KEY` | The complete PEM private key |
| `GITHUB_WEBHOOK_SECRET` | A new random webhook secret |

Configure the GitHub App with:

- Webhook URL: `https://code-trust-check.onrender.com/github/webhook`
- Subscribe to: Pull request
- Repository permissions: Metadata read-only, Contents read-only, Pull requests read-only, Checks read and write

After installing the App on a repository, opening or updating a pull request queues a static scan and produces an **AI Code Audit** check.

The public status endpoint at `/github/status` reports only whether each required setting exists; it never returns the values.

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
