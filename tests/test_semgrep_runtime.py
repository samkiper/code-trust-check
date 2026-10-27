import json, subprocess, unittest
from types import SimpleNamespace
from unittest.mock import patch
import main

def response(payload,code=0):return SimpleNamespace(returncode=code,stdout=json.dumps(payload))
GOOD={'results':[],'paths':{'scanned':['snippet.py']}}
class NativeCliTests(unittest.TestCase):
 def scan(self,outputs):
  with patch('main.shutil.which',return_value='/bin/semgrep'),patch.object(main,'SEMGREP_NATIVE_CLI',True),patch('main.run_scanner',side_effect=outputs) as run:
   result=main.run_semgrep_scan('eval(input())','snippet.py')
  return result,run
 def test_native_failure_falls_back_with_identical_rules_and_no_skipped_checks(self):
  for bad in [response({},99), response([]), response({'results':[]}), response({'results':[None],'paths':{'scanned':['snippet.py']}}),SimpleNamespace(returncode=0,stdout='{bad')]:
   with self.subTest(bad=bad):
    result,run=self.scan([bad,response(GOOD)])
    self.assertEqual(result['status'],'complete');self.assertTrue(result['fallback_used'])
    first,second=[c.args[0] for c in run.call_args_list]
    self.assertEqual(first[:-1],second);self.assertEqual(first[-1],'--experimental')
    self.assertIn('--metrics=off',second);self.assertNotIn('--exclude-rule',second)
    self.assertEqual(second[second.index('--max-target-bytes')+1],str(main.MAX_PASTED_CODE_BYTES_PRO))
 def test_invalid_responses_never_become_clean(self):
  result,_=self.scan([response({}),response({})]);self.assertEqual(result['status'],'error')
 def test_timeout_has_bounded_fallback(self):
  result,run=self.scan([subprocess.TimeoutExpired('semgrep',10),response(GOOD)])
  self.assertEqual(result['status'],'complete');self.assertEqual(len(result['attempts']),2)
  self.assertLessEqual(run.call_args_list[0].kwargs['timeout'],10)
  self.assertLessEqual(run.call_args_list[1].kwargs['timeout'],40)
 def test_exhausted_deadline_does_not_start_another_process(self):
  with patch('main.shutil.which',return_value='/bin/semgrep'),patch('main.time.monotonic',side_effect=[0,0,0,41,41,41]),patch('main.run_scanner',side_effect=subprocess.TimeoutExpired('semgrep',10)) as run:
   result=main.run_semgrep_scan('eval(input())','snippet.py')
  self.assertEqual(run.call_count,1);self.assertEqual(result['status'],'timeout')
 def test_high_findings_and_partial_errors_survive_native_path(self):
  finding={'check_id':'python.dynamic-eval','start':{'line':1},'extra':{'severity':'ERROR','message':'Dynamic evaluation','metadata':{'confidence':'high'}}}
  for errors in [[],[{'type':'ParseError'}]]:
   payload={**GOOD,'results':[finding]*12,'errors':errors}
   result,run=self.scan([response(payload)])
   self.assertEqual(result['status'],'partial' if errors else 'complete');self.assertEqual(len(result['findings']),12)
   self.assertEqual(result['findings'][0]['severity'],18);self.assertEqual(run.call_count,1)
 def test_rollback_switch_uses_original_cli(self):
  with patch('main.shutil.which',return_value='/bin/semgrep'),patch.object(main,'SEMGREP_NATIVE_CLI',False),patch('main.run_scanner',return_value=response(GOOD)) as run:
   result=main.run_semgrep_scan('print(1)','snippet.py')
  self.assertEqual(result['status'],'complete');self.assertNotIn('--experimental',run.call_args.args[0])
