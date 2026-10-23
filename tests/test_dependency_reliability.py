import io
import threading
import unittest
import zipfile
from unittest.mock import patch
import main

DEP = {'file':'requirements.txt','package':'requests','ecosystem':'PyPI','version':'2.0.0'}

class DependencyReliabilityTests(unittest.TestCase):
    def test_batch_rejects_missing_truncated_and_malformed_responses(self):
        for response in [{}, [], {'results':[]}, {'results':[None]}, {'results':[{'vulns':None}]}, {'results':[{'vulns':[{}]}]}]:
            with self.subTest(response=response), patch.object(main,'fetch_json',return_value=response):
                with self.assertRaises(ValueError): main.query_osv_batch([DEP])
        with patch.object(main,'fetch_json',return_value={'results':[{}]}):
            self.assertEqual(main.query_osv_batch([DEP])[0]['vuln_refs'],[])

    def analyze(self, matches, detail):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z: z.writestr('requirements.txt','requests==2.0.0')
        archive.seek(0)
        with zipfile.ZipFile(archive) as z, patch.object(main,'build_dependency_reputation_findings',return_value=[]), patch.object(main,'query_osv_batch',return_value=matches), patch.object(main,'fetch_osv_vulnerability',side_effect=detail):
            return main.analyze_dependency_manifests(z)

    def test_detail_failure_retains_match_and_marks_partial(self):
        r=self.analyze([{'dependency':DEP,'vuln_refs':[{'id':'TEST-1'}]}],lambda *_:None)
        self.assertTrue(r['dependency_scan_error'])
        self.assertEqual(r['dependency_findings'][0]['id'],'TEST-1')
        self.assertEqual(r['dependency_findings'][0]['severity_label'],'UNKNOWN')
        self.assertEqual(r['dependency_findings'][0]['detail_status'],'unavailable')

    def test_parallel_details_deduplicate_requests_not_manifest_findings(self):
        barrier=threading.Barrier(2,timeout=3)
        called=[]
        def detail(key,cache):
            called.append(key); barrier.wait()
            return {'id':key,'summary':'Test advisory'}
        matches=[{'dependency':{**DEP,'file':file},'vuln_refs':[{'id':'TEST-1'},{'id':'TEST-2'}]} for file in ['a/requirements.txt','b/requirements.txt']]
        r=self.analyze(matches,detail)
        self.assertCountEqual(called,['TEST-1','TEST-2'])
        self.assertEqual(len(r['dependency_findings']),4)
        self.assertIsNone(r['dependency_scan_error'])

    def test_mismatched_detail_is_not_accepted(self):
        for response in [{}, [], {'id':'OTHER'}]:
            with patch.object(main,'fetch_json',return_value=response):
                self.assertIsNone(main.fetch_osv_vulnerability('TEST-1',{}))

    def test_dependency_evidence_never_claims_unchecked_is_clear(self):
        for summary,status in [(None,'not_checked'), ({'dependencies_queried':0},'not_checked'), ({'dependencies_queried':2,'dependency_scan_error':'failed'},'partial'), ({'dependencies_queried':2},'clear')]:
            with self.subTest(summary=summary):
                dep=next(e for e in main.build_evidence_profile([],[],[],dependency_summary=summary) if e['id']=='dependencies')
                self.assertEqual(dep['status'],status)
                if status!='clear': self.assertIsNone(dep['confidence'])
