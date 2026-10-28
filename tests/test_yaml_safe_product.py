import unittest
from main import analyze_code_product
class SafeYamlProduct(unittest.TestCase):
 def test_safe_unsafe_and_shadow_controls(self):
  cases=[('import yaml, pickle','yaml.SafeLoader',False),('import yaml, pickle','yaml.CSafeLoader',False),('import yaml, pickle','yaml.Loader',True),('import yaml, pickle\nyaml.SafeLoader = yaml.Loader','yaml.SafeLoader',True),('import yaml, pickle\nfrom yaml import SafeLoader as S','S',False),('import yaml, pickle\nfrom other import SafeLoader','SafeLoader',True)]
  for imports,loader,high in cases:
   with self.subTest(loader=loader,imports=imports):
    r=analyze_code_product('Parse untrusted data without executing objects.',imports+'\nvalue=input()\nyaml.load(value,Loader='+loader+')',language='Python')
    self.assertTrue(all(e['status']=='complete' for e in r['analysis_engines']))
    self.assertEqual(any(f.get('severity',0)>=18 for f in r['flags']+r['engine_findings']),high)
    self.assertNotIn('not clearly mentioned',' '.join(r['intent_mismatches']))
