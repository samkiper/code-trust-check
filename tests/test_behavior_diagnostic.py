import hashlib, os, time, unittest
from unittest.mock import patch
import main
from audit_runtime import validation_behavior_error_enabled, scanner_environment
class BehaviorDiagnostic(unittest.TestCase):
 def test_scoped_hash_expiry_and_environment(self):
  code='x=1'; digest=hashlib.sha256(code.encode()).hexdigest()
  for expiry,expected in [(time.time()+60,True),(time.time()-1,False),(time.time()+1000,False),('invalid',False)]:
   with patch.dict(os.environ,{'AUDIT_BEHAVIOR_VALIDATION_SHA256':digest,'AUDIT_BEHAVIOR_VALIDATION_EXPIRES':str(expiry)},clear=True):
    self.assertEqual(validation_behavior_error_enabled(code),expected)
    self.assertFalse(validation_behavior_error_enabled(code+'\n'))
    self.assertEqual(scanner_environment()['AUDIT_BEHAVIOR_VALIDATION_SHA256'],digest)
    if expected:
     with self.assertRaisesRegex(RuntimeError,'Behavior analysis could not complete'):
      main.analyze_code_product('Review code',code,language='Python')
