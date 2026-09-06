import hashlib
import hmac
import json
import io
import unittest
import zipfile
from unittest.mock import patch

import main


class EvidenceModelTests(unittest.TestCase):
    def test_safe_code_has_six_clear_evidence_categories(self):
        with patch.object(main, "SEMGREP_ENABLED", False):
            result = main.analyze_code_product("Print a greeting", "print('hello')")
        self.assertEqual(len(result["evidence"]), 6)
        self.assertTrue(all(item["status"] == "clear" for item in result["evidence"]))

    def test_execution_risk_is_visible_as_evidence(self):
        with patch.object(main, "SEMGREP_ENABLED", False):
            result = main.analyze_code_product("Display input", "value = input()\neval(value)")
        execution = next(item for item in result["evidence"] if item["id"] == "execution")
        self.assertEqual(execution["status"], "high")


class FixPreviewTests(unittest.TestCase):
    def test_yaml_load_gets_reviewable_patch_without_auto_apply(self):
        code = "import yaml\nvalue = yaml.load(payload)"
        result = main.analyze_code("Read uploaded YAML", code)
        previews = main.build_fix_previews(code, result["flags"])
        self.assertEqual(len(previews), 1)
        self.assertIn("yaml.safe_load(payload)", previews[0]["patched_code"])
        self.assertFalse(previews[0]["applies_automatically"])

    def test_tls_debug_and_eval_fixes_are_review_only(self):
        samples = [
            ("requests.get(url, verify=False)", "verify=True", "high"),
            ("app.run(debug=True)", "debug=False", "high"),
            ("value = eval(user_input)", "ast.literal_eval(user_input)", "medium"),
        ]
        for code, safer_text, confidence in samples:
            with self.subTest(code=code):
                result = main.analyze_code("Run a web application safely", code)
                previews = main.build_fix_previews(code, result["flags"])
                self.assertTrue(any(safer_text in preview["patched_code"] for preview in previews))
                self.assertTrue(any(preview["confidence"] == confidence for preview in previews))
                self.assertTrue(all(not preview["applies_automatically"] for preview in previews))


class DependencyReputationTests(unittest.TestCase):
    def scan_requirements(self, contents, exists=True):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("repo/requirements.txt", contents)
        archive.seek(0)
        with zipfile.ZipFile(archive) as source, \
                patch.object(main, "query_osv_batch", return_value=[]), \
                patch.object(main, "registry_package_exists", return_value=exists):
            return main.analyze_dependency_manifests(source)

    def test_common_package_typo_is_high_risk(self):
        result = self.scan_requirements("requets==2.31.0\n")
        finding = next(item for item in result["dependency_findings"] if item["type"] == "dependency_typosquatting")
        self.assertEqual(finding["severity"], 18.0)
        self.assertIn("requests", finding["suggested_fix"])

    def test_missing_registry_package_is_review_risk(self):
        result = self.scan_requirements("invented-ai-helper-xyz==1.0.0\n", exists=False)
        self.assertTrue(any(item["type"] == "dependency_unverified" for item in result["dependency_findings"]))


class AISpecificBehaviorTests(unittest.TestCase):
    def test_hidden_persistence_conflicts_with_display_intent(self):
        code = "import winreg\nwinreg.SetValue(winreg.HKEY_CURRENT_USER, 'Run', 0, 1, 'agent.exe')"
        result = main.analyze_code("Display a greeting", code)
        self.assertEqual(result["risk"], "red")
        self.assertTrue(any("persistence" in item.lower() for item in result["intent_mismatches"]))

    def test_wildcard_cors_is_reported_as_insecure_default(self):
        result = main.analyze_code("Create a private API", "allow_origins=['*']")
        self.assertTrue(any(item.get("pattern") == "wildcard_cors" for item in result["flags"]))


class CryptographyAndCookieTests(unittest.TestCase):
    def test_md5_is_risky_for_security_but_low_priority_for_checksum(self):
        code = "import hashlib\ndigest = hashlib.md5(payload).hexdigest()"
        security = main.analyze_code("Hash a security token", code)
        checksum = main.analyze_code("Calculate a non-security file checksum", code)
        self.assertEqual(security["risk"], "yellow")
        self.assertEqual(checksum["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "weak_hash" for item in security["flags"]))

    def test_random_module_is_risky_for_tokens_but_not_gameplay(self):
        code = "import random\nvalue = random.randint(0, 999999)"
        token = main.analyze_code("Generate a random authentication token", code)
        game = main.analyze_code("Roll a random number for a board game", code)
        self.assertEqual(token["risk"], "yellow")
        self.assertEqual(game["risk"], "green")

    def test_cookie_with_secure_false_requires_review(self):
        code = "response.set_cookie('session', value, secure=False, httponly=True)"
        result = main.analyze_code("Create a secure login cookie", code)
        self.assertEqual(result["risk"], "yellow")
        self.assertTrue(any(item.get("pattern") == "insecure_cookie_transport" for item in result["flags"]))


class InjectionAndParserTests(unittest.TestCase):
    def test_request_path_requires_containment_or_traversal_rejection(self):
        unsafe = '''from flask import request
name = request.form.get("name")
path = f"/srv/uploads/{name}"
with open(path, "rb") as handle:
    data = handle.read()'''
        safe = unsafe.replace(
            'path = f"/srv/uploads/{name}"',
            'if "../" in name:\n    raise ValueError("bad path")\npath = f"/srv/uploads/{name}"',
        )
        unsafe_result = main.analyze_code("Read an uploaded file", unsafe)
        safe_result = main.analyze_code("Read an uploaded file", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "untrusted_file_path" for item in unsafe_result["flags"]))

    def test_web_response_requires_contextual_escaping(self):
        unsafe = '''from flask import request
comment = request.form.get("comment")
response = ""
response += f"<p>{comment}</p>"
return response'''
        safe = unsafe.replace(
            'from flask import request',
            'from flask import request\nfrom markupsafe import escape',
        ).replace('{comment}', '{escape(comment)}')
        unsafe_result = main.analyze_code("Display a submitted comment", unsafe)
        safe_result = main.analyze_code("Display a submitted comment", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "unescaped_web_response" for item in unsafe_result["flags"]))

    def test_interpolated_sql_is_risky_but_parameterized_sql_is_clear(self):
        unsafe = "sql = f\"SELECT * FROM users WHERE name = '{name}'\"\ncursor.execute(sql)"
        safe = "sql = 'SELECT * FROM users WHERE name = ?'\ncursor.execute(sql, (name,))"
        unsafe_result = main.analyze_code("Look up a database user", unsafe)
        safe_result = main.analyze_code("Look up a database user", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "dynamic_sql_execute" for item in unsafe_result["flags"]))

    def test_external_entities_are_only_high_risk_with_untrusted_xml(self):
        unsafe = """from flask import request
import xml.dom.minidom
import xml.sax
payload = request.data
parser = xml.sax.make_parser()
parser.setFeature(xml.sax.handler.feature_external_ges, True)
xml.dom.minidom.parseString(payload, parser)"""
        safe = unsafe.replace("payload = request.data", "payload = '<root>safe</root>'")
        unsafe_result = main.analyze_code("Parse uploaded XML", unsafe)
        safe_result = main.analyze_code("Parse a fixed XML template", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "xxe_external_entities" for item in unsafe_result["flags"]))

    def test_ldap_filter_requires_escaping(self):
        unsafe = '''from flask import request
value = request.args.get("name")
filter_text = f"(uid={value})"
conn.search("dc=example,dc=com", filter_text)'''
        safe = unsafe.replace(
            'from flask import request',
            'from flask import request\nfrom ldap3.utils.conv import escape_filter_chars',
        ).replace('value = request.args.get("name")', 'value = escape_filter_chars(request.args.get("name"))')
        unsafe_result = main.analyze_code("Review this LDAP search", unsafe)
        safe_result = main.analyze_code("Review this LDAP search", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "dynamic_ldap_filter" for item in unsafe_result["flags"]))

    def test_xpath_query_requires_escaping(self):
        unsafe = '''from flask import request
value = request.args.get("id")
query = f"/users/user[@id='{value}']"
nodes = root.xpath(query)'''
        safe = unsafe.replace(
            'value = request.args.get("id")',
            "value = request.args.get(\"id\").replace(\"'\", \"&apos;\")",
        )
        unsafe_result = main.analyze_code("Review this XPath query", unsafe)
        safe_result = main.analyze_code("Review this XPath query", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "dynamic_xpath_query" for item in unsafe_result["flags"]))

    def test_redirect_requires_an_allowlisted_host_and_scheme(self):
        unsafe = '''from flask import request, redirect
target = request.args.get("next")
return redirect(target)'''
        safe = '''from flask import request, redirect
from urllib.parse import urlparse
target = request.args.get("next")
parsed = urlparse(target)
if parsed.netloc not in {"example.com"} or parsed.scheme != "https":
    raise ValueError("untrusted redirect")
return redirect(target)'''
        unsafe_result = main.analyze_code("Review this redirect", unsafe)
        safe_result = main.analyze_code("Review this redirect", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "unvalidated_redirect" for item in unsafe_result["flags"]))

    def test_request_data_cannot_cross_into_session_state(self):
        unsafe = '''from flask import request, session
role = request.form.get("role")
session["role"] = role'''
        safe = '''from flask import request, session
request.form.get("role")
session["role"] = "member"'''
        unsafe_result = main.analyze_code("Review this trust boundary", unsafe)
        safe_result = main.analyze_code("Review this trust boundary", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "untrusted_session_state" for item in unsafe_result["flags"]))

    def test_command_injection_tracks_values_through_lists(self):
        unsafe = '''import subprocess
from flask import request
values = request.form.getlist("name")
param = values[0] if values else ""
arguments = ["sh", "-c"]
arguments.append(f"echo {param}")
subprocess.run(arguments)'''
        safe = unsafe.replace('arguments.append(f"echo {param}")', 'arguments.append("echo safe")')
        unsafe_result = main.analyze_code("Run the requested operation", unsafe)
        safe_result = main.analyze_code("Run the requested operation", safe)
        self.assertEqual(unsafe_result["risk"], "red")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "subprocess" for item in unsafe_result["flags"]))

    def test_code_execution_distinguishes_tainted_and_overwritten_values(self):
        unsafe = '''from flask import request
value = request.args.get("value")
result = eval(value)'''
        safe = unsafe.replace('result = eval(value)', 'value = "42"\nresult = eval(value)')
        unsafe_result = main.analyze_code("Calculate a value", unsafe)
        safe_result = main.analyze_code("Calculate a value", safe)
        self.assertEqual(unsafe_result["risk"], "red")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "eval(" for item in unsafe_result["flags"]))
        self.assertFalse(any(item.get("pattern") == "eval(" for item in safe_result["flags"]))

    def test_html_escaping_does_not_sanitize_deserialization(self):
        unsafe = '''import base64
import html
import pickle
from flask import request
payload = html.escape(request.args.get("payload"))
value = pickle.loads(base64.urlsafe_b64decode(payload))'''
        safe = unsafe.replace(
            'payload = html.escape(request.args.get("payload"))',
            'payload = "Zml4ZWQ="',
        )
        unsafe_result = main.analyze_code("Read the submitted data", unsafe)
        safe_result = main.analyze_code("Read fixed application data", safe)
        self.assertEqual(unsafe_result["risk"], "red")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "pickle.loads" for item in unsafe_result["flags"]))
        self.assertFalse(any(item.get("pattern") == "pickle.loads" for item in safe_result["flags"]))


class SarifTests(unittest.TestCase):
    def test_sarif_is_github_compatible_shape(self):
        result = main.analyze_code("Display input", "value = input()\neval(value)")
        sarif = main.result_to_sarif(result, "app.py")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "AI Code Audit")
        self.assertTrue(sarif["runs"][0]["results"])
        location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "app.py")


class SemgrepAdapterTests(unittest.TestCase):
    def test_unavailable_semgrep_degrades_cleanly(self):
        with patch("main.shutil.which", return_value=None):
            result = main.run_semgrep_scan("print('hello')")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["findings"], [])

    def test_semgrep_json_is_normalized(self):
        payload = {"results": [{
            "check_id": "python.dynamic-eval",
            "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "Dynamic eval", "metadata": {"confidence": "high"}},
        }]}
        completed = type("Completed", (), {"returncode": 1, "stdout": json.dumps(payload)})()
        with patch("main.shutil.which", return_value="/usr/bin/semgrep"), patch("main.subprocess.run", return_value=completed):
            result = main.run_semgrep_scan("eval(user_input)", "app.py")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["findings"][0]["line"], 3)
        self.assertEqual(result["findings"][0]["severity"], 18)


class GitHubWebhookTests(unittest.TestCase):
    def test_signature_verification_uses_hmac_sha256(self):
        payload = b'{"zen":"safe"}'
        with patch.object(main, "GITHUB_WEBHOOK_SECRET", "test-secret"):
            digest = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
            self.assertTrue(main.verify_github_webhook_signature(payload, "sha256=" + digest))
            self.assertFalse(main.verify_github_webhook_signature(payload, "sha256=wrong"))


if __name__ == "__main__":
    unittest.main()
