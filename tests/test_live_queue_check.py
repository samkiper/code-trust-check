import json
import os
from pathlib import Path
import tempfile
import unittest
from scripts.live_queue_check import CheckFailed, check_usage, load_accounts, validate_origin
from scripts.live_queue_fixture import owns_fixture


class LiveQueueCheckSafetyTests(unittest.TestCase):
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
