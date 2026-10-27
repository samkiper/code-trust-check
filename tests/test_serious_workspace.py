import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import main
class SeriousTests(unittest.TestCase):
 def test_exact_plan_limits_and_unknown_fallback(self):
  limits=main.get_plan_limits('serious')
  self.assertEqual([limits[k] for k in ('line_limit','repo_file_limit','monthly_scan_limit','monthly_repo_limit')],[200000,500,300,40])
  self.assertEqual(main.get_plan_limits('invented'),main.get_plan_limits('free'))
 def test_line_boundaries(self):
  access={'authenticated':True,'plan':'serious','limits':main.get_plan_limits('serious')}
  main.validate_scan_request(main.ScanRequest(code='x=1\n'*200000,intent='Assign a value'),access)
  with self.assertRaises(main.HTTPException):main.validate_scan_request(main.ScanRequest(code='x=1\n'*200001,intent='Assign a value'),access)
 def test_workspace_rejects_anonymous_and_ignores_forged_identity(self):
  with TestClient(main.app) as client:
   with patch.object(main,'get_request_access_context',return_value={'authenticated':False}):
    self.assertEqual(client.post('/workspace',json={'action':'list'}).status_code,401)
   with patch.object(main,'get_request_access_context',return_value={'authenticated':True,'user_id':'verified-user'}),patch.object(main,'enforce_rate_limit'),patch.object(main,'supabase_rest_request',return_value={'ok':True}) as rpc:
    r=client.post('/workspace',json={'action':'list','data':{'p_user':'someone-else'},'p_user':'someone-else'})
    self.assertEqual(r.status_code,200);self.assertEqual(rpc.call_args.kwargs['payload']['p_user'],'verified-user')
    self.assertIn('no-store',r.headers['cache-control'])
    self.assertEqual(client.post('/workspace',json=[]).status_code,400)
    self.assertEqual(client.post('/workspace',content='x'*300001).status_code,413)
