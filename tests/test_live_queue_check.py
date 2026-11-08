import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts.live_queue_check import CheckFailed, check_usage, load_accounts, validate_origin, run
from scripts.live_queue_fixture import owns_fixture, fixture_password


class LiveQueueCheckSafetyTests(unittest.TestCase):
    def test_password_policy_holds_even_when_random_part_has_one_character_class(self):
        with patch("scripts.live_queue_fixture.secrets.token_urlsafe", return_value="x" * 43) as random_token:
            password = fixture_password()
        random_token.assert_called_once_with(32)
        self.assertGreaterEqual(len(password), 32)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertIn("!", password)

    def test_live_runner_handles_first_job_finishing_during_burst(self):
        jobs, usage_reads, duplicate_owners = {}, {}, []
        draining = False

        def response(origin, path, *, method="GET", token=None, key=None, body=None):
            nonlocal draining
            if path == "/health": return 200, {}, {"ok": True}
            if path.startswith("/auth/v1/token"):
                identity = body["email"]
                return 200, {}, {"access_token": identity, "user": {"id": identity}}
            if path.startswith("/auth/v1/logout"): return 204, {}, {}
            owner = int(token) if token is not None else None
            if path == "/auth/access":
                reads = usage_reads.get(owner, 0); usage_reads[owner] = reads + 1
                return 200, {}, {"authenticated": True, "plan": "free", "usage": {
                    "pending": 0, "total_remaining": 5, "total_used": int(reads > 0 and owner != 5),
                    "repo_used": 0, "resets_at": "stable"}}
            if path == "/scan-jobs":
                if owner in jobs and jobs[owner]["status"] in {"queued", "running"}:
                    duplicate_owners.append(owner)
                    return 409, {}, {}
                if owner == 6 and jobs.get(5, {}).get("status") != "cancelled":
                    return 429, {"X-Scan-Rejection": "capacity"}, {}
                if owner == 6: draining = True
                # Real HTTP/auth delays allow the initial scan to finish before
                # the post-burst duplicate check, while the tail remains queued.
                if owner != 0: jobs[0]["status"] = "completed"
                jobs[owner] = {"id": str(owner), "status": "running" if owner == 0 else "queued",
                               "position": owner, "result": {"scan_status": "complete"}}
                return 202, {}, dict(jobs[owner])
            target = int(path.rsplit("/", 1)[1])
            if owner is None: return 401, {}, {}
            if owner != target: return 404, {}, {}
            if method == "DELETE": jobs[owner]["status"] = "cancelled"
            elif draining and jobs[owner]["status"] != "cancelled": jobs[owner]["status"] = "completed"
            return 200, {}, dict(jobs[owner])

        args = argparse.Namespace(backend="https://test.onrender.com", supabase="https://test.supabase.co")
        accounts = [{"email": str(i), "password": "unused"} for i in range(7)]
        with patch("scripts.live_queue_check.request", side_effect=response), \
                patch("scripts.live_queue_check.ThreadPoolExecutor") as executor:
            # Force the rejecting customer to arrive before account 5 exists.
            executor.return_value.__enter__.return_value.map.side_effect = (
                lambda fn, items: [fn(i) for i in reversed(list(items))])
            result = run(args, accounts=accounts, key="unused-test-key")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(duplicate_owners, [5])
        self.assertEqual(result["successful_scans"], 6)
        self.assertEqual(jobs[5]["status"], "cancelled")

    def test_fixture_cleanup_requires_all_ownership_guards(self):
        account = {"id": "test-uuid", "email": "test@example.invalid",
                   "app_metadata": {"plan": "free", "aca_live_queue_run": "unique-run"}}
        self.assertTrue(owns_fixture(account, "test-uuid", "test@example.invalid", "unique-run"))
        for edited in ({**account, "id": "other"}, {**account, "email": "real@example.com"},
                       {**account, "app_metadata": {"plan": "free"}},
                       {**account, "app_metadata": {**account["app_metadata"], "plan": "pro"}},
                       {**account, "app_metadata": {**account["app_metadata"], "role": "admin"}}):
            with self.subTest(account=edited):
                self.assertFalse(owns_fixture(edited, "test-uuid", "test@example.invalid", "unique-run"))

    def test_rejects_credential_redirect_destinations(self):
        for value in ("http://x.supabase.co", "https://x.supabase.co.evil.test",
                      "https://name@x.supabase.co", "https://x.supabase.co/path",
                      "https://x.supabase.co?key=secret"):
            with self.subTest(value=value), self.assertRaises(CheckFailed):
                validate_origin(value, ".supabase.co")

    def test_rejects_shared_credential_file_and_duplicate_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "accounts.json"
            path.write_text(json.dumps([{"email": f"user{i}@example.test", "password": "fixture"} for i in range(7)]))
            path.chmod(0o644)
            with self.assertRaises(CheckFailed):
                load_accounts(path)
            path.chmod(0o600)
            self.assertEqual(len(load_accounts(path)), 7)
            path.write_text(json.dumps([{"email": "same@example.test", "password": "fixture"}] * 7))
            with self.assertRaises(CheckFailed):
                load_accounts(path)
            link = Path(tmp) / "link.json"
            os.symlink(path, link)
            with self.assertRaises(CheckFailed):
                load_accounts(link)

    def test_usage_gate_rejects_double_charges_reservations_and_cycle_rollover(self):
        before = {"resets_at": "same-cycle", "total_used": 2, "repo_used": 0, "pending": 0}
        correct = dict(before, total_used=3)
        check_usage(before, correct, 1)
        check_usage(before, before, 0)
        for change in ({"total_used": 4}, {"pending": 1}, {"repo_used": 1}, {"resets_at": "next-cycle"}):
            with self.subTest(change=change), self.assertRaises(CheckFailed):
                check_usage(before, dict(correct, **change), 1)
