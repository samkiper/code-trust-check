import json
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
import main

class FreeDemoTests(unittest.TestCase):
    def setUp(self):
        self.access={'authenticated':True,'user_id':'demo-test','plan':'free','limits':main.get_plan_limits('free')}
        self.request=Request({'type':'http','headers':[],'method':'POST','path':'/scan'})
    def test_exact_examples_are_free_but_all_edits_and_client_flags_are_metered(self):
        for sample in main.DEMO_EXAMPLES.values():
            req=main.ScanRequest(**sample,language='Python')
            self.assertTrue(main.is_free_demo(req))
            for edits in [{'code':req.code+'\n# edited'},{'intent':'Different purpose'},{'language':'JavaScript'},{'filename':'input.js'}]:
                self.assertFalse(main.is_free_demo(req.model_copy(update=edits)))
        self.assertFalse(main.is_free_demo(main.ScanRequest(intent='Review',code='eval(input())',language='Python',is_example=True)))
    def test_free_demo_still_calls_analyzer_without_reserving_or_settling(self):
        calls=[]
        @main.metered_scan('code')
        def fn(req,request):calls.append(req.code);return main.private_json({'scan_status':'complete'})
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'monthly_usage') as usage:
            for sample in main.DEMO_EXAMPLES.values():fn(main.ScanRequest(**sample,language='Python'),self.request)
            usage.assert_not_called();self.assertEqual(len(calls),2)
            self.access['authenticated']=False
            fn(main.ScanRequest(**main.DEMO_EXAMPLES['safe'],language='Python'),self.request)
            usage.assert_not_called()
    def test_queue_demos_work_with_exhausted_allowance_but_keep_rate_limit(self):
        with patch.object(main,'get_request_access_context',return_value=self.access),patch.object(main,'enforce_rate_limit') as rate,patch.object(main,'monthly_usage',return_value={'total_remaining':0,'repo_remaining':0}) as usage,patch.object(main.SCAN_JOBS,'submit',return_value={'id':'demo','status':'queued'}),TestClient(main.app) as client:
            payload={'kind':'code',**main.DEMO_EXAMPLES['safe'],'language':'Python'}
            self.assertEqual(client.post('/scan-jobs',json=payload).status_code,202)
            usage.assert_not_called();rate.assert_called_once()
            payload['code']+='\n# changed';payload['is_example']=True
            self.assertEqual(client.post('/scan-jobs',json=payload).status_code,429)
    def test_anonymous_edits_and_spoofed_flags_require_authentication(self):
        anonymous={'authenticated':False,'user_id':None,'plan':'free','limits':main.get_plan_limits('free')}
        @main.metered_scan('code')
        def fn(req,request):self.fail('edited anonymous input must not run')
        with patch.object(main,'get_request_access_context',return_value=anonymous),patch.object(main,'monthly_usage') as usage:
            sample=main.DEMO_EXAMPLES['safe']
            for edit in [{'code':sample['code']+'\n'}, {'intent':sample['intent']+' '}, {'language':'JavaScript'}, {'code':'eval(input())','is_example':True}, {'filename':'changed.py'}]:
                req=main.ScanRequest(**{**sample,'language':'Python',**edit})
                with self.assertRaises(HTTPException) as cm:fn(req,self.request)
                self.assertEqual(cm.exception.status_code,401)
            usage.assert_not_called()

    def test_anonymous_http_examples_keep_rate_and_capacity_checks(self):
        anonymous={'authenticated':False,'user_id':None,'plan':'free','limits':main.get_plan_limits('free')}
        with patch.object(main,'get_request_access_context',return_value=anonymous),patch.object(main,'enforce_rate_limit') as rate,patch.object(main,'monthly_usage') as usage,patch.object(main,'analyze_code_product',return_value={'scan_status':'complete'}),TestClient(main.app) as client:
            payload={**main.DEMO_EXAMPLES['safe'],'language':'Python'}
            self.assertEqual(client.post('/scan',json=payload).status_code,200)
            rate.assert_called_once();usage.assert_not_called()
            rate.side_effect=HTTPException(429,'limited')
            self.assertEqual(client.post('/scan',json=payload).status_code,429)
            with main.limit_scan_capacity.__globals__['_INTERACTIVE_SCAN_SLOT']:
                self.assertEqual(client.post('/scan',json=payload).status_code,429)

    def test_real_example_detection(self):
        safe=main.analyze_code_product(**main.DEMO_EXAMPLES['safe'],plan='free',language='Python')
        risky=main.analyze_code_product(**main.DEMO_EXAMPLES['risky'],plan='free',language='Python')
        self.assertEqual(safe['scan_status'],'complete')
        self.assertFalse(safe['flags']);self.assertFalse(safe['engine_findings']);self.assertFalse(safe['intent_mismatches'])
        self.assertEqual(risky['scan_status'],'complete')
        self.assertEqual(risky['verdict']['id'],'do_not_run')
        self.assertTrue(any(f['type']=='secret_exfiltration' and f['line']==6 for f in risky['flags']))

if __name__=='__main__':unittest.main()
