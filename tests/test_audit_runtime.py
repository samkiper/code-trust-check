import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from starlette.requests import Request
import main
from audit_runtime import run_process,run_audit_process,validation_stall_enabled,scanner_environment
from scan_jobs import ScanJobs
from scan_capacity import limit_scan_capacity

class AuditRuntimeTests(unittest.TestCase):
    def test_worker_environment_excludes_secrets_and_unknown_variables(self):
        with patch.dict(os.environ,{'PATH':'/bin','SUPABASE_SECRET_KEY':'not-a-real-key','STRIPE_SECRET_KEY':'test','GITHUB_PRIVATE_KEY':'test','OPENAI_API_KEY':'test','FUTURE_SECRET':'test','SEMGREP_BUDGET_SECONDS':'40'},clear=True):
            env=scanner_environment()
            self.assertEqual(set(env),{'PATH','SEMGREP_BUDGET_SECONDS','AUDIT_ISOLATED_WORKER','SEMGREP_SEND_METRICS'})
            output=run_process([sys.executable,'-c','import os,json;print(json.dumps(sorted(os.environ)))'],{},2)
            self.assertFalse(any('SECRET' in name or 'API_KEY' in name or 'PRIVATE_KEY' in name for name in json.loads(output)))

    def test_worker_payload_omits_account_and_billing_metadata(self):
        access={'plan':'pro','limits':main.get_plan_limits('pro'),'email':'private@example.test','user_id':'private-id','app_metadata':{'stripe_customer_id':'private-customer'}}
        with patch('audit_runtime.run_process',return_value=b'{"status_code":200,"body":{}}') as run:
            run_audit_process('code',{'code':'print(1)'},access)
        self.assertEqual(set(run.call_args.args[1]['access']),{'plan','limits'})

    def test_actual_deadline_stops_busy_worker_and_descendant(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'orphan'
            child=f"import time;from pathlib import Path;time.sleep(1);Path({str(marker)!r}).write_text('bad')"
            script=f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{child!r}]);exec('while True: pass')"
            start=time.monotonic()
            with self.assertRaises(HTTPException) as cm:run_process([sys.executable,'-c',script],{},.3)
            self.assertEqual(cm.exception.status_code,504);self.assertLess(time.monotonic()-start,2)
            time.sleep(1.1);self.assertFalse(marker.exists())
            self.assertEqual(run_process([sys.executable,'-c','print(42)'],{},2).strip(),b'42')

    def test_finished_worker_also_cleans_up_background_descendants(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'orphan'
            child=f"import time;from pathlib import Path;time.sleep(.7);Path({str(marker)!r}).write_text('bad')"
            script=f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print(42)"
            self.assertEqual(run_process([sys.executable,'-c',script],{},2).strip(),b'42')
            time.sleep(.8);self.assertFalse(marker.exists())

    def test_real_worker_retains_findings_and_never_executes_source(self):
        access={'plan':'free','limits':main.get_plan_limits('free'),'authenticated':False}
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'executed'
            source=f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\neval(input())"
            response=run_audit_process('code',{'intent':'Review without executing','code':source,'language':'Python'},access)
            data=json.loads(response.body)
            self.assertEqual(response.status_code,200);self.assertFalse(marker.exists())
            self.assertTrue(data['flags']);self.assertEqual(data['scan_status'],'complete')
            self.assertTrue(data['engine_findings'])

    def test_real_timeout_settles_receipt_and_unblocks_next_queued_customer(self):
        access={'authenticated':True,'user_id':'test','plan':'free','limits':main.get_plan_limits('free')}
        req=main.ScanRequest(intent='Review',code='print(123)',language='Python')
        request=Request({'type':'http','method':'POST','path':'/scan','headers':[]})
        settlements=[]
        def usage(a,action='status',receipt=None,kind='code',charge=False):
            if action=='settle':settlements.append(charge)
            return {'allowed':True}
        @limit_scan_capacity
        @main.metered_scan('code')
        def stuck(req,request):run_process([sys.executable,'-c','while True: pass'],{},.15)
        @limit_scan_capacity
        def normal():return {'recovered':True}
        q=ScanJobs()
        with patch.object(main,'get_request_access_context',return_value=access),patch.object(main,'monthly_usage',side_effect=usage):
            first=q.submit('one',lambda:stuck(req,request)); second=q.submit('two',normal)
            limit=time.monotonic()+3
            while q.get('two',second['id'])['status']!='completed' and time.monotonic()<limit:time.sleep(.01)
            self.assertEqual(q.get('one',first['id'])['http_status'],504)
            self.assertEqual(q.get('two',second['id'])['result'],{'recovered':True})
        self.assertEqual(settlements,[False])

    def test_stall_diagnostic_requires_exact_source_and_short_expiry(self):
        payload={'code':'print(123)'}
        with patch.dict(os.environ,{},clear=True):
            self.assertFalse(validation_stall_enabled(payload))
            os.environ['AUDIT_DEADLINE_VALIDATION_SHA256']=hashlib.sha256(payload['code'].encode()).hexdigest()
            for expiry,expected in [(time.time()+60,True),(time.time()-1,False),(time.time()+1000,False),('invalid',False)]:
                os.environ['AUDIT_DEADLINE_VALIDATION_EXPIRES']=str(expiry)
                self.assertEqual(validation_stall_enabled(payload),expected)
                self.assertFalse(validation_stall_enabled({'code':payload['code']+'\n'}))
