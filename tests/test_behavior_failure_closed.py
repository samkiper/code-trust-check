import unittest
from unittest.mock import patch
import main
class BehaviorFailureClosed(unittest.TestCase):
 def test_unexpected_component_errors_do_not_return_clean_report(self):
  for name in ('analyze_python_ast','add_multi_signal_heuristics','add_secret_flow_heuristics'):
   with self.subTest(component=name),patch.object(main,name,side_effect=RuntimeError('private-source-marker')),patch.object(main,'log_server_issue'):
    with self.assertRaisesRegex(RuntimeError,'^Behavior analysis could not complete.$'):
     main.analyze_code_product('Assign a value locally.','x=1',language='Python')
 def test_normal_safe_input_still_completes(self):
  r=main.analyze_code_product('Assign a value locally.','x=1',language='Python')
  self.assertTrue(all(e['status']=='complete' for e in r['analysis_engines']))
