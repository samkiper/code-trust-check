import json
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from starlette.requests import Request
import main


class OwnerMonitoringTests(unittest.TestCase):
    def test_non_admin_cannot_read_aggregate_costs(self):
        with patch.object(main,'require_admin_access',side_effect=HTTPException(403,'Administrator access is required.')), patch.object(main,'supabase_rest_request') as db:
            with self.assertRaises(HTTPException) as caught:
                main.owner_monitoring(Request({'type':'http','headers':[]}))
            self.assertEqual(caught.exception.status_code,403)
            db.assert_not_called()

    def test_missing_ledger_is_unavailable_not_zero(self):
        with patch.object(main,'require_admin_access'),patch.object(main,'supabase_rest_request',return_value={}):
            response=main.owner_monitoring(Request({'type':'http','headers':[]}))
        self.assertEqual(response.status_code,503)

    def test_owner_gets_aggregates_and_local_queue_only(self):
        summary={'ai':{'completed':1,'recorded_micro_usd':2000},'scans_last_24_hours':{'charged':3},'period_start_utc':'2026-10-01T00:00:00Z'}
        with patch.object(main,'require_admin_access'),patch.object(main,'supabase_rest_request',return_value=summary):
            response=main.owner_monitoring(Request({'type':'http','headers':[]}))
        body=json.loads(response.body)
        self.assertEqual(body['summary'],summary)
        self.assertEqual(set(body['local_queue']),{'waiting','running'})
