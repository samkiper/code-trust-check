import unittest
from main import analyze_code_product
class PathMetadataReview(unittest.TestCase):
 def test_metadata_and_content_access_have_distinct_risk(self):
  for op,expected in [('os.path.isdir(path)',10),('os.path.isfile(path)',10),('os.path.exists(path)',10),('open(path).read()',22)]:
   with self.subTest(op=op):
    r=analyze_code_product('Inspect configured file paths.','import os\ndef inspect(path):\n return '+op,language='Python')
    flags=[f for f in r['flags'] if f.get('pattern')=='untrusted_file_path']
    self.assertTrue(flags)
    self.assertTrue(all(f['severity']==expected for f in flags))
    self.assertNotIn('Request-controlled',' '.join(f['message'] for f in flags))
 def test_direct_input_read_remains_high(self):
  r=analyze_code_product('Read the selected file.','path=input()\nopen(path).read()',language='Python')
  self.assertTrue(any(f.get('pattern')=='untrusted_file_path' and f['severity']==22 for f in r['flags']))
