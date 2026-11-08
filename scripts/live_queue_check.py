"""Opt-in live queue check using seven real, dedicated Supabase test accounts.

Never collected by pytest. See docs/LIVE_QUEUE_CHECK.md. No admin credentials,
identity overrides, account creation, payment calls, or allowance resets.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class CheckFailed(Exception):
    """Only fixed, non-secret messages are raised to the console."""


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(origin, path, *, method="GET", token=None, key=None, body=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if key:
        headers["apikey"] = key
    req = urllib.request.Request(origin + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        response = urllib.request.build_opener(NoRedirect()).open(req, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    except Exception:
        raise CheckFailed("Network request failed; no automatic mutation retry was attempted.") from None
    with response:
        raw = response.read(4_000_001)
        require(len(raw) <= 4_000_000, "Response exceeded the test safety bound.")
        try:
            data = json.loads(raw) if raw else {}
        except (ValueError, UnicodeError):
            raise CheckFailed("Expected a JSON API response.") from None
        return response.status, dict(response.headers.items()), data


def validate_origin(value, suffix):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and
            parsed.hostname.endswith(suffix) and not parsed.username and
            not parsed.password and not parsed.port and parsed.path in ("", "/") and
            not parsed.query and not parsed.fragment, "Use the expected HTTPS provider origin.")
    return value.rstrip("/")


def load_accounts(path):
    path = Path(path)
    require(not path.is_symlink(), "Credential file must not be a symlink.")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            info.st_mode & 0o077 == 0, "Credential file must be owned by you and mode 0600.")
    require(info.st_size < 32768, "Credential file is unexpectedly large.")
    accounts = json.loads(path.read_text())
    require(isinstance(accounts, list) and len(accounts) == 7, "Exactly seven dedicated test accounts are required.")
    require(all(isinstance(a, dict) and isinstance(a.get("email"), str) and
                isinstance(a.get("password"), str) and a["email"].strip() and a["password"]
                for a in accounts), "Each test account needs an email and password.")
    require(len({a["email"].strip().lower() for a in accounts}) == 7, "Test accounts must be distinct.")
    return accounts


def check_usage(before, after, expected):
    require(before["resets_at"] == after["resets_at"], "Allowance boundary changed; rerun in a stable cycle.")
    require(after["total_used"] - before["total_used"] == expected, "Unexpected charged scan count.")
    require(after["repo_used"] == before["repo_used"], "Snippet test changed repository usage.")
    require(after["pending"] == 0, "An allowance reservation is still pending.")


def run(args, *, accounts=None, key=None):
    backend = validate_origin(args.backend, ".onrender.com")
    auth = validate_origin(args.supabase, ".supabase.co")
    if accounts is None:
        accounts = load_accounts(args.credentials_file)
    key = key or os.environ.get("ACA_TEST_PUBLISHABLE_KEY", "").strip()
    require(key, "Set ACA_TEST_PUBLISHABLE_KEY to the project's public client key.")
    tokens, identities, before, jobs, checks = [], set(), [], [], []

    def api(index, path, method="GET", body=None):
        return request(backend, path, method=method, body=body,
                       token=tokens[index] if index is not None else None)

    def usage(index):
        code, _, data = api(index, "/auth/access")
        require(code == 200 and data.get("authenticated"), "Account access preflight failed.")
        require(data.get("plan") in {"free", "pro", "serious"}, "Use ordinary metered test accounts, not administrators.")
        return data["usage"]

    # Valid, bounded source below the Free line limit; not a free-demo bypass.
    payload = {"kind": "code", "language": "Python",
               "intent": "Define independent numeric constants for a synthetic queue validation.",
               "code": "\n".join(f"queue_fixture_{i} = {i}" for i in range(1800))}

    def submit(index):
        result = api(index, "/scan-jobs", "POST", payload)
        if result[0] == 202:
            jobs.append((index, result[2]["id"]))
        return index, result

    def wait_terminal(index, job_id, deadline):
        while time.monotonic() < deadline:
            code, _, data = api(index, "/scan-jobs/" + job_id)
            require(code == 200, "Could not read an owned test job.")
            if data["status"] not in {"queued", "running"}:
                return data
            time.sleep(.5)
        raise CheckFailed("Test queue did not drain within the deadline.")

    cleanup_failures = []
    try:
        require(request(backend, "/health")[0] == 200, "Backend is not healthy.")
        for account in accounts:
            code, _, data = request(auth, "/auth/v1/token?grant_type=password", method="POST", key=key,
                                    body={"email": account["email"], "password": account["password"]})
            require(code == 200 and data.get("access_token"), "Test account sign-in failed; credentials were not printed.")
            tokens.append(data["access_token"])
            identities.add(data["user"]["id"])
        require(len(identities) == 7, "Logins did not resolve to seven independent identities.")
        for index in range(7):
            current = usage(index)
            require(current["pending"] == 0 and current["total_remaining"] >= 2,
                    "Test accounts need no pending work and at least two remaining scans.")
            before.append(current)
        checks.append("seven_real_metered_accounts")
        _, initial = submit(0)
        require(initial[0] == 202, "Initial job was not accepted; no automatic retry.")
        first_id = initial[2]["id"]
        deadline = time.monotonic() + 240
        # Ensure the worker took the first job before the simultaneous burst.
        for _ in range(20):
            code, _, state = api(0, "/scan-jobs/" + first_id)
            require(code == 200, "Initial job disappeared.")
            if state["status"] == "running":
                break
            require(state["status"] == "queued", "Job finished before burst; saturation is inconclusive.")
            time.sleep(.1)
        else:
            raise CheckFailed("Initial job did not start; saturation is inconclusive.")
        with ThreadPoolExecutor(max_workers=6) as pool:
            attempts = list(pool.map(submit, range(1, 7)))
        accepted = [(i, r[2]) for i, r in attempts if r[0] == 202]
        rejected = [(i, r) for i, r in attempts if r[0] != 202]
        require(len(accepted) == 5 and len(rejected) == 1 and rejected[0][1][0] == 429 and
                any(k.lower() == "x-scan-rejection" and v == "capacity" for k, v in rejected[0][1][1].items()),
                "Capacity pattern not observed; this run cannot pass live saturation.")
        checks.append("one_active_five_waiting_capacity_rejection")
        _, duplicate = submit(0)
        require(duplicate[0] == 409, "Duplicate active submission was not rejected.")
        for method in ("GET", "DELETE"):
            require(api(1, "/scan-jobs/" + first_id, method)[0] == 404, "Cross-account job isolation failed.")
        require(api(None, "/scan-jobs/" + first_id)[0] == 401, "Unauthenticated job read was not denied.")
        checks.append("duplicate_and_account_isolation")
        cancelled_owner, cancelled_job = max(accepted, key=lambda pair: pair[1].get("position", 0))
        code, _, cancelled = api(cancelled_owner, "/scan-jobs/" + cancelled_job["id"], "DELETE")
        require(code == 200 and cancelled["status"] == "cancelled", "Queued cancellation raced with processing; check ledger.")
        retry_owner = rejected[0][0]
        _, retry = submit(retry_owner)
        require(retry[0] == 202, "Rejected customer could not retry after cancellation.")
        for index, job_id in jobs:
            result = wait_terminal(index, job_id, deadline)
            if index == cancelled_owner:
                require(result["status"] == "cancelled", "Cancelled job unexpectedly ran.")
            else:
                require(result["status"] == "completed" and result["result"].get("scan_status") == "complete",
                        "A valid synthetic scan did not complete.")
                require("access" not in result["result"] and "code" not in result["result"],
                        "Queue result exposed internal request fields.")
        for index in range(7):
            check_usage(before[index], usage(index), 0 if index == cancelled_owner else 1)
        checks.append("six_successes_exact_charges_cancelled_zero")
    finally:
        # Do not strand queued test work on an assertion/network failure.
        for index, job_id in jobs:
            try:
                code, _, result = api(index, "/scan-jobs/" + job_id)
                if code == 200 and result["status"] == "queued":
                    api(index, "/scan-jobs/" + job_id, "DELETE")
                if code == 200 and result["status"] == "running":
                    wait_terminal(index, job_id, time.monotonic() + 60)
            except Exception:
                cleanup_failures.append("test_job_cleanup_unconfirmed")
        for token in tokens:
            try:
                code, _, _ = request(auth, "/auth/v1/logout?scope=local", method="POST", token=token, key=key)
                if code not in {204, 401}:
                    cleanup_failures.append("local_session_logout_unconfirmed")
            except Exception:
                cleanup_failures.append("local_session_logout_unconfirmed")
        if cleanup_failures:
            print(json.dumps({"cleanup_warnings": sorted(set(cleanup_failures))}), file=sys.stderr)
    require(not cleanup_failures, "Live checks ran but cleanup needs verification.")
    return {"status": "passed", "scope": "backend_supabase_live_queue", "checks": checks,
            "successful_scans": 6, "cancelled_without_charge": 1,
            "note": "Does not verify the browser/Site proxy or process-restart recovery."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--supabase", required=True)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--run-live", action="store_true", help="Allow bounded real scans and allowance charges.")
    args = parser.parse_args()
    if not args.run_live:
        parser.error("--run-live is required; this test consumes real test-account allowances")
    try:
        print(json.dumps(run(args), indent=2))
        return 0
    except CheckFailed as exc:
        print(json.dumps({"status": "not_passed", "reason": str(exc)}))
    except Exception:
        print(json.dumps({"status": "not_passed", "reason": "Configuration or unexpected test error; no sensitive details printed."}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
