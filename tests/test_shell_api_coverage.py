import unittest
from main import run_semgrep_scan

class ShellApiCoverage(unittest.TestCase):
    def test_explicit_shell_apis_and_false_controls(self):
        for api in ('check_call','check_output'):
            for shell in ('True','False'):
                with self.subTest(api=api,shell=shell):
                    r=run_semgrep_scan(f'import subprocess\nsubprocess.{api}(["/bin/echo","hello"], shell={shell})','snippet.py')
                    self.assertEqual(r['status'],'complete')
                    self.assertEqual(bool(r['findings']),shell=='True')

    def test_implicit_shell_apis_and_shadow_control(self):
        for api in ('getoutput','getstatusoutput'):
            r=run_semgrep_scan(f'import subprocess\nsubprocess.{api}("echo hello")','snippet.py')
            self.assertEqual(r['status'],'complete')
            self.assertTrue(r['findings'])
        r=run_semgrep_scan('def getoutput(value):\n return value\ngetoutput("hello")','snippet.py')
        self.assertEqual(r['status'],'complete')
        self.assertFalse(r['findings'])
