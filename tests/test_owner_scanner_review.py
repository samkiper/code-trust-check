import unittest
from main import analyze_code_product, build_finding_guidance


class OwnerScannerReview(unittest.TestCase):
    def scan(self, code, intent='Review process inputs.'):
        r = analyze_code_product(intent, code, language='Python')
        self.assertTrue(all(e['status'] == 'complete' for e in r['analysis_engines']), r['analysis_engines'])
        return r

    def test_fixed_cat_filename_is_notice_not_command_injection(self):
        for api in ['run', 'call', 'Popen', 'check_call', 'check_output']:
            for binary in ['cat', '/bin/cat', '/usr/bin/cat']:
                r = self.scan(f'import subprocess\nname=input()\nsubprocess.{api}([{binary!r}, "--", name], shell=False)', 'Show a file selected by the user.')
                self.assertNotEqual(r['verdict']['id'], 'do_not_run')
                f = next(f for f in r['flags'] if f['pattern'] == 'subprocess')
                self.assertEqual(f['severity'], 5)
                self.assertEqual(f['type'], 'process_file_access')
                self.assertIn('permissions', f['what_to_check'] + f['explanation'])
                self.assertFalse(r['engine_findings'])

    def test_instruction_paths_are_not_downgraded(self):
        calls = [
            'subprocess.run("cat " + name, shell=True)',
            'subprocess.run(["cat", "--", name], shell=True)',
            'subprocess.run(["cat", "--", name], shell=flag)',
            'subprocess.run(["cat", "--", name], executable="python")',
            'subprocess.run(["cat", "--", name], **options)',
            'subprocess.run([name, "--", "file"], shell=False)',
            'subprocess.run(["python", "-c", name], shell=False)',
            'subprocess.run(["bash", "-c", name], shell=False)',
            'subprocess.run(["find", "--", name], shell=False)',
            'subprocess.run(["cat", name], shell=False)',
            'subprocess.getoutput(name)',
        ]
        for call in calls:
            with self.subTest(call=call):
                r = self.scan('import subprocess\nname=input()\n' + call)
                self.assertEqual(r['verdict']['id'], 'do_not_run')

    def test_engine_corroboration_requires_single_same_operation(self):
        for code, operation in [('value=input()\nexec(value)', 'exec'),
                                ('import subprocess\nsubprocess.run(input(),shell=True)', 'shell')]:
            r = self.scan(code)
            f = next(f for f in r['flags'] if f['severity'] >= 18)
            e = next(f for f in r['engine_findings'] if f['severity'] >= 18)
            self.assertEqual(f['correlation_key'], e['correlation_key'])
            self.assertNotIn('Request-controlled', f['message'])
            if operation == 'exec':
                self.assertIn('exec()', e['message'])
                self.assertNotIn('eval', e['message'])
        r = self.scan('x=input(); exec(x); eval(x)')
        self.assertTrue(all('correlation_key' not in f for f in r['flags'] + r['engine_findings']))

    def test_actions_and_context_are_evidence_specific(self):
        r = self.scan('import os\nx=os.getenv("API_KEY")', 'Prepare an upload but do not send it.')
        self.assertFalse(any('may not match' in x for x in r['behavior_summary']))
        self.assertNotIn('apply the relevant fixes', r['verdict']['action'])
        r = self.scan('exec(input())')
        self.assertNotIn('Incomplete coverage', r['verdict']['action'])
        self.assertIn('parameter placeholders', build_finding_guidance('dynamic_sql_execute')['suggested_fix'])

