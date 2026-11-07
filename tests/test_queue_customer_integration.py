"""HTTP queue integration with real scanner processes and isolated test accounts.

Identity, rate limiting, and the allowance ledger are local fixtures. This is
not evidence of a live Supabase or Render multi-customer load test.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import shutil
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import main
from scan_jobs import ScanJobs


@unittest.skipUnless(shutil.which("semgrep"), "Real Semgrep executable required")
class CustomerQueueIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.queue = ScanJobs()
        self.receipts = {}
        self.ledger_lock = threading.Lock()
        self.stack.enter_context(patch.object(main, "SCAN_JOBS", self.queue))
        self.stack.enter_context(patch.object(main, "enforce_rate_limit"))
        self.stack.enter_context(patch.object(main, "get_request_access_context", side_effect=self.identity))
        self.stack.enter_context(patch.object(main, "get_supabase_admin_user", return_value={}))
        self.stack.enter_context(patch.object(main, "monthly_usage", side_effect=self.usage))
        self.client = self.stack.enter_context(TestClient(main.app))

    @staticmethod
    def identity(request, **kwargs):
        owner = request.headers.get("x-test-account")
        return {"authenticated": bool(owner), "user_id": owner, "plan": "pro",
                "limits": main.get_plan_limits("pro"), "app_metadata": {}}

    def usage(self, access, action="status", receipt=None, kind="code", charge=False):
        with self.ledger_lock:
            if action == "reserve":
                self.assertNotIn(receipt, self.receipts)
                self.receipts[receipt] = {"owner": access["user_id"], "settled": False, "charge": False}
            elif action == "settle":
                row = self.receipts[receipt]
                self.assertEqual(row["owner"], access["user_id"])
                self.assertFalse(row["settled"], "a receipt was settled twice")
                row.update(settled=True, charge=charge)
        return {"allowed": True, "total_remaining": 75, "repo_remaining": 10}

    def submit(self, owner, code="def total(prices):\n    return sum(prices)\n"):
        return self.client.post("/scan-jobs", headers={"x-test-account": owner},
                                json={"kind": "code", "code": code, "language": "Python",
                                      "intent": "Return the sum of the supplied prices."})

    def poll(self, owner, job_id):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            response = self.client.get(f"/scan-jobs/{job_id}", headers={"x-test-account": owner})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            if data["status"] not in {"queued", "running"}:
                return data
            time.sleep(.02)
        self.fail("queue did not drain within the test deadline")

    def test_seven_customers_capacity_cancellation_ownership_and_exact_charges(self):
        entered, release = threading.Event(), threading.Event()
        real_worker = main.run_audit_process

        def gated_worker(kind, payload, access, *args, **kwargs):
            if access["user_id"] == "first":
                entered.set()
                if not release.wait(15):
                    raise RuntimeError("test gate timed out")
            return real_worker(kind, payload, access, *args, **kwargs)

        self.stack.enter_context(patch.object(main, "run_audit_process", side_effect=gated_worker))
        first = self.submit("first")
        self.assertEqual(first.status_code, 202)
        first_id = first.json()["id"]
        try:
            self.assertTrue(entered.wait(3))
            with ThreadPoolExecutor(max_workers=6) as pool:
                attempts = list(pool.map(lambda n: (f"customer-{n}", self.submit(f"customer-{n}")), range(6)))
            accepted = [(owner, response.json()["id"]) for owner, response in attempts if response.status_code == 202]
            rejected = [(owner, response) for owner, response in attempts if response.status_code != 202]
            self.assertEqual(len(accepted), 5)
            self.assertEqual(len(rejected), 1)
            self.assertEqual(rejected[0][1].status_code, 429)
            self.assertIn("no allowance was used", rejected[0][1].json()["detail"])
            self.assertEqual(self.submit("first").status_code, 409)
            for method in (self.client.get, self.client.delete):
                self.assertEqual(method(f"/scan-jobs/{first_id}", headers={"x-test-account": "stranger"}).status_code, 404)
            self.assertEqual(self.client.get(f"/scan-jobs/{first_id}").status_code, 401)

            cancelled_owner, cancelled_id = accepted.pop()
            cancelled = self.client.delete(f"/scan-jobs/{cancelled_id}", headers={"x-test-account": cancelled_owner})
            self.assertEqual(cancelled.json()["status"], "cancelled")
            retry_owner = rejected[0][0]
            retry = self.submit(retry_owner)
            self.assertEqual(retry.status_code, 202)
            accepted += [(retry_owner, retry.json()["id"]), ("first", first_id)]
            with self.ledger_lock:
                self.assertEqual(len(self.receipts), 1, "waiting and rejected work must not reserve usage")
        finally:
            release.set()

        for owner, job_id in accepted:
            result = self.poll(owner, job_id)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["result"]["scan_status"], "complete")
            self.assertNotIn("access", result["result"])
            self.assertNotIn("code", result["result"])
        with self.ledger_lock:
            rows = list(self.receipts.values())
            self.assertEqual(len(rows), 6)
            self.assertEqual({row["owner"] for row in rows}, {owner for owner, _ in accepted})
            self.assertTrue(all(row["settled"] and row["charge"] for row in rows))
            self.assertNotIn(cancelled_owner, {row["owner"] for row in rows})

    def test_unrated_source_does_not_charge_or_block_next_customer(self):
        invalid = self.submit("invalid", "def broken(:\n")
        valid = self.submit("valid")
        self.assertEqual(invalid.status_code, 202)
        self.assertEqual(valid.status_code, 202)
        result = self.poll("invalid", invalid.json()["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["result"]["scan_status"], "not-rated")
        self.assertEqual(self.poll("valid", valid.json()["id"])["result"]["scan_status"], "complete")
        with self.ledger_lock:
            self.assertEqual({r["owner"]: r["charge"] for r in self.receipts.values()}, {"invalid": False, "valid": True})
            self.assertTrue(all(r["settled"] for r in self.receipts.values()))
