# AI Code Audit v2 setup

## What is now built

- The intent-aware behavior engine remains the source of the calibrated trust score.
- A local Semgrep engine independently checks structural security rules. Code is written only to a temporary directory for the scan and is not sent to Semgrep's registry or telemetry service.
- Results include six evidence categories, reviewable patch previews, JSON downloads, and SARIF 2.1 output.
- A GitHub App webhook scans changed supported pull-request files and publishes a monitor-only GitHub Check with line annotations.
- The regression suite contains 325 formatting variants derived from 65 labeled base scenarios.
- The accuracy gate measures 65 internal cases, 750 category-assisted OWASP BenchmarkPython cases, and a separate 300-case OWASP holdout scanned without vulnerability-category hints.
- Signed-in users can mark findings accurate, report false alarms, or report a missed risk. Feedback records fingerprints and labels only; submitted code is not stored.
- Dependency review checks published advisories, likely package-name typos, missing registry packages, and unpinned direct-source installs.
- Review-only “Fix this safely” previews cover unsafe YAML loading, disabled TLS verification, production debug mode, and dynamic `eval`.
- Scanner v18 adds a signed-in security dashboard with connected repositories, the latest 25 pull-request scans, severity counts, expandable finding explanations, and false-positive feedback. Stored history contains metadata and finding explanations only; source code is never stored. Detection rules and weights remain unchanged from v17.
- Scanner v19 adds shared Supabase rate limiting, an admin-only feedback review queue and sanitized candidate export, common direct-manifest and lockfile parsing across six dependency ecosystems, and typed JavaScript/TypeScript regression coverage.

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

In Supabase, open **SQL Editor**, paste the current contents of `supabase/scan_feedback.sql`, and run it. For v19 this safely adds review status, reviewer metadata, and queue indexes to an existing table. The table has row-level security enabled and denies browser clients direct access; the authenticated backend writes the minimal feedback record with the existing Supabase secret key. Admins see the review queue from the account menu. Exported candidates contain fingerprints and reviewed labels, never scanned source, and are explicitly marked incomplete until a minimal reproducer is independently reviewed.

## Persistent rate-limit setup for v19

In Supabase **SQL Editor**, run `supabase/rate_limits.sql` once. The function atomically counts requests across Render restarts and multiple service instances. Bucket identifiers are one-way hashes, browser roles have no access, and the backend falls back to a local limiter if Supabase is temporarily unavailable. `PERSISTENT_RATE_LIMITS_ENABLED` defaults to `true`; set it to `false` only during incident recovery.

## Dependency coverage for v19

Repository scans now parse supported entries from `requirements.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, `package.json`, npm/Yarn/pnpm lockfiles, `go.mod`, `Cargo.lock`, `composer.lock`, and `Gemfile.lock`. OSV coverage spans PyPI, npm, Go, crates.io, Packagist, and RubyGems. Complex ranges, private registries, generated manifests, and platform-specific resolution may still be skipped and are disclosed in scan coverage.

## Security dashboard setup for v18

In Supabase **SQL Editor**, run `supabase/github_scan_runs.sql` once after `supabase/github_installations.sql`. The dashboard table has row-level security enabled and denies browser clients direct access. The backend stores repository and pull-request identifiers, scan counts, and sanitized finding explanations; it never stores scanned source code.

## GitHub Pro-link setup for v17

1. In Supabase **SQL Editor**, run `supabase/github_installations.sql` once.
2. In the GitHub App settings, add `https://code-trust-check.onrender.com/github/oauth/callback` as a **Callback URL**.
3. Generate a GitHub App client secret and store the App's client ID and secret in Render as `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
4. Set the GitHub App **Setup URL** to `https://code-trust-check.onrender.com/` and enable the redirect after installation updates.
5. Subscribe the GitHub App to both **Pull request** and **Check run** events. Check-run delivery enables GitHub's **Re-run checks** control.
6. Deploy v17 with `GITHUB_ENFORCE_PRO=false` first and complete one signed-in Pro installation-link test. **Connect GitHub** authorizes the GitHub user and links only installations GitHub confirms that user can access. If none exist, the same flow continues to a new installation.
7. After that test succeeds, set `GITHUB_ENFORCE_PRO=true` in Render and redeploy. Unlinked or non-Pro installations then receive a neutral check explaining how to connect Pro instead of a scan.

The installation link is verified directly against GitHub before it is stored. Browser users cannot read or write the installation table directly.

## Render environment variables

Semgrep runs by default after the new dependency is installed. Set `SEMGREP_ENABLED=false` only if the Render instance cannot support the additional package.

To activate GitHub pull-request checks, create a GitHub App and add these Render variables:

| Variable | Value |
| --- | --- |
| `GITHUB_APP_ID` | The numeric GitHub App ID |
| `GITHUB_PRIVATE_KEY` | The complete PEM private key |
| `GITHUB_WEBHOOK_SECRET` | A new random webhook secret |
| `GITHUB_APP_SLUG` | The public slug from the GitHub App URL, used to show the install button |
| `GITHUB_CLIENT_ID` | The GitHub App client ID used for existing-installation authorization |
| `GITHUB_CLIENT_SECRET` | A GitHub App client secret; never expose this in browser code |
| `GITHUB_ENFORCE_PRO` | Keep `true` after the GitHub installation-link acceptance test succeeds |
| `GITHUB_LINK_STATE_SECRET` | A separate random secret used to sign the short-lived installation ownership token |
| `PERSISTENT_RATE_LIMITS_ENABLED` | Optional; defaults to `true`. Set `false` only for incident recovery |

Configure the GitHub App with:

- Webhook URL: `https://code-trust-check.onrender.com/github/webhook`
- Subscribe to: Pull request and Check run
- Repository permissions: Metadata read-only, Contents read-only, Pull requests read-only, Checks read and write

After installing the App on a repository, opening or updating a pull request queues a static scan of changed supported files and produces an **AI Code Audit** check. Findings use a neutral conclusion and do not block merging. Each annotation includes a severity label, explanation, suggested fix, and a link to the pull request's changed files. Re-delivered webhooks and check reruns update the same check instead of creating duplicates. GitHub annotations are limited to 50 per response, so v17 explicitly reports when additional findings exist.

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
