"""Explicit server-only provisioning wrapper for the opt-in live queue check.

Uses the already-configured Supabase admin key inside the service environment.
Creates seven empty Free fixtures, runs real password authentication, then
deletes only this run's marked fixtures and their scan receipts. No email is
sent. No secret is printed or written to disk. Never runs during startup/CI.
"""
import argparse
import json
import os
import secrets
import sys
import uuid

try:
    from scripts.live_queue_check import CheckFailed, request, require, run, validate_origin
except ModuleNotFoundError:
    from live_queue_check import CheckFailed, request, require, run, validate_origin


def owns_fixture(user, uid, email, marker):
    return (user.get("id") == uid and user.get("email") == email and
            user.get("app_metadata", {}).get("aca_live_queue_run") == marker and
            user.get("app_metadata", {}).get("plan") == "free" and
            user.get("app_metadata", {}).get("role", "user") == "user")


def execute(args):
    auth = validate_origin(os.environ.get("SUPABASE_URL", ""), ".supabase.co")
    backend = validate_origin(args.backend, ".onrender.com")
    key = os.environ.get("SUPABASE_SECRET_KEY", "")
    require(key, "Run inside the authorized server environment with its existing admin key.")
    marker = str(uuid.uuid4())
    accounts, created, cleanup_errors = [], [], []
    outcome = {"status": "not_passed", "run_marker": marker}
    print(json.dumps({"phase": "starting", "run_marker": marker}), flush=True)

    def admin(path, method="GET", body=None):
        return request(auth, path, method=method, body=body, key=key, token=key)

    try:
        require(request(backend, "/health")[0] == 200, "Backend health preflight failed.")
        for index in range(7):
            email = f"queue-{marker}-{index}@example.invalid"
            password = secrets.token_urlsafe(32)
            code, _, user = admin("/auth/v1/admin/users", "POST", {
                "email": email, "password": password, "email_confirm": True,
                "app_metadata": {"plan": "free", "aca_live_queue_run": marker},
                "user_metadata": {"purpose": "disposable queue validation"}})
            require(code in {200, 201} and user.get("id"), "Fixture provisioning failed; inspect this run marker before retrying.")
            uid = str(uuid.UUID(user["id"]))
            created.append((uid, email))
            require(owns_fixture(user, uid, email, marker), "Created fixture identity did not match the request.")
            accounts.append({"email": email, "password": password})
        print(json.dumps({"phase": "seven_fixtures_created", "run_marker": marker}), flush=True)
        test_args = argparse.Namespace(backend=backend, supabase=auth, credentials_file=None)
        outcome.update(run(test_args, accounts=accounts, key=key))
    except CheckFailed as exc:
        outcome["reason"] = str(exc)
    except Exception:
        outcome["reason"] = "Unexpected fixture error; secret-bearing exception details suppressed."
    finally:
        for uid, email in created:
            try:
                code, _, user = admin("/auth/v1/admin/users/" + uid)
                require(code == 200 and owns_fixture(user, uid, email, marker),
                        "Cleanup refused an account without this run's exact identity and Free marker.")
                # This table deliberately has no Auth-user cascading FK.
                receipt_path = "/rest/v1/scan_usage_monthly?user_id=eq." + uid
                code, _, receipts = admin(receipt_path + "&select=state")
                require(code == 200 and isinstance(receipts, list), "Could not inspect fixture receipts.")
                require(not any(row.get("state") == "reserved" for row in receipts),
                        "Reserved fixture work remains; cleanup requires follow-up.")
                code, _, _ = admin(receipt_path, "DELETE")
                require(code in {200, 204}, "Could not remove this fixture's scan receipts.")
                code, _, _ = admin("/auth/v1/admin/users/" + uid, "DELETE")
                require(code in {200, 204}, "Could not remove this run's fixture account.")
            except Exception:
                cleanup_errors.append(uid)
        outcome["fixtures_created"] = len(created)
        outcome["cleanup_unconfirmed_ids"] = cleanup_errors
        outcome["fixtures_deleted"] = len(created) - len(cleanup_errors)
        if cleanup_errors:
            outcome["status"] = "not_passed"
        # IDs/marker are operational evidence; passwords and tokens never leave memory.
        print(json.dumps(outcome, indent=2), flush=True)
    return 0 if outcome["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default=os.environ.get("RENDER_EXTERNAL_URL", ""))
    parser.add_argument("--run-live", action="store_true")
    parser.add_argument("--delete-fixtures", action="store_true")
    args = parser.parse_args()
    if not args.run_live or not args.delete_fixtures:
        parser.error("explicit --run-live and --delete-fixtures are required")
    try:
        return execute(args)
    except Exception:
        print(json.dumps({"status": "not_passed", "reason": "Server fixture preflight failed; no sensitive details printed."}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
