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
