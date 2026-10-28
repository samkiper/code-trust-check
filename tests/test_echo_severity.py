import unittest
from main import analyze_code_product
class EchoSeverity(unittest.TestCase):
 def test_fixed_echo_and_dangerous_controls(self):
  cases=[('subprocess.run(["echo", input()],shell=False)',10),('subprocess.run(["/bin/echo", input()])',10),('subprocess.run(["python","-c",input()],shell=False)',38),('subprocess.run([input(),"x"],shell=False)',38),('subprocess.run(["echo",input()],shell=True)',38),('subprocess.run(["echo",input()],shell=False,executable="python")',38)]
  for call,severity in cases:
   with self.subTest(call=call):
    r=analyze_code_product('Review process inputs.','import subprocess\n'+call,language='Python')
    self.assertTrue(any(f.get('pattern')=='subprocess' and f['severity']==severity for f in r['flags']))
    self.assertTrue(all(e['status']=='complete' for e in r['analysis_engines']))
