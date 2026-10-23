import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
import main
from scan_capacity import limit_scan_capacity

class ScanCapacityTests(unittest.TestCase):
    def test_routes_share_capacity_health_stays_available_and_retry_runs_full_scan(self):
        started=threading.Event(); finish=threading.Event()
        expected={'risk':'red','flags':[{'message':'Retained behavior finding','severity':20}],
                  'engine_findings':[{'message':'Retained engine finding','severity':20}]}
        def analyze(*args,**kwargs):
            started.set()
            if not finish.wait(5): raise RuntimeError('test worker stalled')
            return dict(expected)
        access={'plan':'free','authenticated':False,'limits':main.get_plan_limits('free')}
        payload={'intent':'Review','code':'eval(input())','language':'Python'}
        with patch.object(main,'get_request_access_context',return_value=access), patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x), patch.object(main,'enforce_rate_limit'), patch.object(main,'analyze_code_product',side_effect=analyze) as engine, TestClient(main.app) as client, ThreadPoolExecutor(max_workers=1) as pool:
            active=pool.submit(client.post,'/scan',json=payload)
            try:
                self.assertTrue(started.wait(3))
                # A running worker cannot be cancelled just by cancelling its caller's future.
                self.assertFalse(active.cancel())
                for route,body in [('/scan',payload),('/scan/sarif',payload),('/scan-repo',{'intent':'Review','repo_url':'https://github.com/example/repo'}),('/fix-preview',payload)]:
                    response=client.post(route,json=body)
                    self.assertEqual(response.status_code,429,route)
                    self.assertEqual(response.headers['retry-after'],'10')
                    self.assertIn('not started',response.json()['detail'])
                self.assertEqual(client.get('/health').status_code,200)
                self.assertEqual(engine.call_count,1)
            finally: finish.set()
            self.assertEqual(active.result().json()['engine_findings'],expected['engine_findings'])
            retry=client.post('/scan',json=payload)
            self.assertEqual(retry.status_code,200)
            self.assertEqual(retry.json()['flags'],expected['flags'])
            self.assertEqual(engine.call_count,2)

    def test_exception_releases_slot(self):
        @limit_scan_capacity
        def fail(): raise RuntimeError('expected')
        @limit_scan_capacity
        def success(): return 'completed'
        with self.assertRaises(RuntimeError): fail()
        self.assertEqual(success(),'completed')
