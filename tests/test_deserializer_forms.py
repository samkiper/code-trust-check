import unittest
from main import run_semgrep_scan

class DeserializerForms(unittest.TestCase):
    def test_yaml_loader_pairs(self):
        for loader,expected in [('Loader',True),('UnsafeLoader',True),('SafeLoader',False),('CSafeLoader',False)]:
            for arg in ('Loader=yaml.'+loader,'yaml.'+loader):
                with self.subTest(arg=arg):
                    r=run_semgrep_scan('import yaml\nyaml.load(value, '+arg+')','snippet.py')
                    self.assertEqual(r['status'],'complete')
                    self.assertEqual(bool(r['findings']),expected)
    def test_unpickler_and_unrelated_load(self):
        for code,expected in [('import pickle\npickle.Unpickler(stream).load()',True),('import json\njson.load(stream)',False),('class Reader:\n def load(self): return 1\nReader().load()',False)]:
            r=run_semgrep_scan(code,'snippet.py')
            self.assertEqual(r['status'],'complete')
            self.assertEqual(bool(r['findings']),expected)
