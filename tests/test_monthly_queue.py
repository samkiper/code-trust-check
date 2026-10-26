import json
import threading
import time
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException
from starlette.requests import Request
from fastapi.testclient import TestClient
import main
from scan_jobs import ScanJobs

class QueueTests(unittest.TestCase):
    def test_fifo_cancel_ownership_duplicate_and_capacity(self):
        q=ScanJobs(capacity=2); started=threading.Event(); finish=threading.Event();order=[]
        def first():
            started.set();finish.wait(3);order.append('first');return {'retained':True}
        one=q.submit('alice',first);self.assertTrue(started.wait(1))
        two=q.submit('bob',lambda:order.append('second'))
        three=q.submit('carol',lambda:order.append('third'))
        try:
            self.assertEqual(q.get('carol',three['id'])['position'],2)
            for owner in ['alice','bob']:
                with self.assertRaises(HTTPException) as cm:q.submit(owner,lambda:None)
                self.assertEqual(cm.exception.status_code,409)
            with self.assertRaises(HTTPException) as cm:q.submit('dave',lambda:None)
            self.assertEqual(cm.exception.status_code,429)
            with self.assertRaises(HTTPException) as cm:q.get('mallory',one['id'])
            self.assertEqual(cm.exception.status_code,404)
            self.assertEqual(q.cancel('bob',two['id'])['status'],'cancelled')
            self.assertEqual(q.get('carol',three['id'])['position'],1)
        finally:finish.set()
        for _ in range(100):
            if q.get('carol',three['id'])['status']=='completed':break
            time.sleep(.01)
        self.assertEqual(order,['first','third'])
        self.assertEqual(q.get('alice',one['id'])['result'],{'retained':True})

    def test_active_cancellation_keeps_slot_and_releases_source_result(self):
        q=ScanJobs();start=threading.Event();finish=threading.Event()
        def work():start.set();finish.wait(2);return {'secret':'result'}
        job=q.submit('a',work);self.assertTrue(start.wait(1))
        state=q.cancel('a',job['id']);self.assertEqual(state['status'],'running');self.assertTrue(state['cancel_requested'])
        self.assertNotIn('work',q.jobs[job['id']]);finish.set()
        for _ in range(100):
            if q.get('a',job['id'])['status']=='cancelled':break
            time.sleep(.01)
        self.assertNotIn('result',q.get('a',job['id']))

    def test_failure_does_not_stall_next_job_and_expiry(self):
        q=ScanJobs(ttl=.1)
        def fail():raise RuntimeError('private implementation detail')
        job=q.submit('a',fail)
        for _ in range(100):
            if q.get('a',job['id'])['status']=='failed':break
            time.sleep(.002)
        self.assertNotIn('private implementation',q.get('a',job['id'])['error'])
        time.sleep(.11)
        with self.assertRaises(HTTPException):q.get('a',job['id'])

class MeteringTests(unittest.TestCase):
    def setUp(self):
        self.access={'authenticated':True,'user_id':'00000000-0000-0000-0000-000000000001','plan':'free','limits':main.get_plan_limits('free')}
        self.request=Request({'type':'http','headers':[],'method':'POST','path':'/scan'})
        self.payload=main.ScanRequest(intent='Review',code='print(1)',language='Python')
    def run_case(self,status,http=200,raises=False):
        calls=[]
        def usage(access,action='status',receipt=None,kind='code',charge=False):calls.append((action,receipt,kind,charge));return {'allowed':True}
        @main.metered_scan('code')
        def fn(req,request):
            if raises:raise RuntimeError('failed worker')
            return main.private_json({'scan_status':status,'coverage_validated':True,'coverage':{'meaningful_coverage':True}},http)
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'monthly_usage',side_effect=usage):
            if raises:
                with self.assertRaises(RuntimeError):fn(self.payload,self.request)
            else:fn(self.payload,self.request)
        self.assertEqual(calls[0][0],'reserve');self.assertEqual(calls[1][0],'settle');self.assertEqual(calls[0][1],calls[1][1])
        return calls[1][3]
    def test_only_complete_and_useful_partial_charge(self):
        self.assertTrue(self.run_case('complete'));self.assertTrue(self.run_case('partial'))
        for status in ['failed','not-rated',None]:self.assertFalse(self.run_case(status))
        self.assertFalse(self.run_case('complete',502));self.assertFalse(self.run_case('complete',raises=True))
    def test_empty_oversized_and_signed_out_reject_before_reservation(self):
        @main.metered_scan('code')
        def fn(req,request):self.fail('must not analyze')
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'monthly_usage') as usage:
            for code in ['', 'x=1\n'*2001]:
                with self.assertRaises(HTTPException):fn(main.ScanRequest(intent='Review',code=code),self.request)
            self.access['authenticated']=False
            with self.assertRaises(HTTPException):fn(self.payload,self.request)
            usage.assert_not_called()
    def test_quota_and_database_outage_fail_closed(self):
        with patch.object(main,'supabase_rest_request',return_value={}):
            with self.assertRaises(HTTPException) as cm:main.monthly_usage(self.access)
            self.assertEqual(cm.exception.status_code,503)
        @main.metered_scan('repo')
        def fn(req,request):self.fail('must not analyze')
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'monthly_usage',return_value={'allowed':False}):
            with self.assertRaises(HTTPException) as cm:fn(main.RepoScanRequest(intent='Review',repo_url='https://github.com/example/repo'),self.request)
            self.assertEqual(cm.exception.headers['X-Scan-Rejection'],'quota')
    def test_limits_and_admin_exemption(self):
        for plan,total,repos,lines,files in [('free',5,1,2000,20),('pro',75,10,20000,100)]:
            limits=main.get_plan_limits(plan)
            self.assertEqual([limits[k] for k in ['monthly_scan_limit','monthly_repo_limit','line_limit','repo_file_limit']],[total,repos,lines,files])
        with patch.object(main,'supabase_rest_request') as db:
            self.assertTrue(main.monthly_usage({'plan':'admin'})['unlimited']);db.assert_not_called()
    def test_queue_endpoints_validate_identity_and_do_not_trust_claimed_plan(self):
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'enforce_rate_limit'),patch.object(main,'monthly_usage',return_value={'total_remaining':20,'repo_remaining':2}),patch.object(main.SCAN_JOBS,'submit',return_value={'id':'reference','status':'queued'}) as submit,TestClient(main.app) as client:
            response=client.post('/scan-jobs',json={'kind':'code','intent':'Review','code':'x=1\n'*2001,'plan':'admin'})
            self.assertEqual(response.status_code,413);submit.assert_not_called()
            self.access['authenticated']=False
            self.assertEqual(client.get('/scan-jobs/anything').status_code,401)

if __name__=='__main__':unittest.main()
