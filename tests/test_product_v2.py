import hashlib
import hmac
import json
import io
import asyncio
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import main
from fastapi import BackgroundTasks, HTTPException
from starlette.requests import Request


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


class ProductIntegrityV20Tests(unittest.TestCase):
    def test_github_install_state_is_signed_and_bound_to_user(self):
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"):
            state = main.create_github_install_state("user-1")
            self.assertTrue(main.verify_github_install_state(state, "user-1"))
            self.assertFalse(main.verify_github_install_state(state, "user-2"))
            self.assertFalse(main.verify_github_install_state(state + "tampered", "user-1"))

    def test_github_install_and_oauth_states_cannot_be_interchanged(self):
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"):
            install_state = main.create_github_install_state("user-1", purpose="installation")
            oauth_state = main.create_github_install_state("user-1", purpose="oauth")
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"):
            self.assertTrue(main.verify_github_install_state(install_state, "user-1", "installation"))
            self.assertFalse(main.verify_github_install_state(install_state, "user-1", "oauth"))
            self.assertEqual(main.read_github_install_state(oauth_state, "oauth")["user_id"], "user-1")

    def test_existing_installation_authorization_url_uses_callback_and_signed_state(self):
        with patch.object(main, "GITHUB_CLIENT_ID", "client-id"), \
                patch.object(main, "GITHUB_CLIENT_SECRET", "client-secret"), \
                patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"), \
                patch.object(main, "APP_BASE_URL", "https://audit.example"):
            url = main.github_oauth_authorize_url("user-1")
            query = parse_qs(urlparse(url).query)
            self.assertEqual(query["client_id"], ["client-id"])
            self.assertEqual(query["redirect_uri"], ["https://audit.example/github/oauth/callback"])
            self.assertEqual(main.read_github_install_state(query["state"][0], "oauth")["user_id"], "user-1")

    def test_oauth_installation_listing_keeps_only_this_github_app(self):
        responses = [
            {"login": "samkiper"},
            {"installations": [
                {"id": 10, "app_id": 123, "account": {"login": "samkiper"}},
                {"id": 20, "app_id": 999, "account": {"login": "someone-else"}},
            ]},
        ]
        with patch.object(main, "GITHUB_APP_ID", "123"), \
                patch.object(main, "github_api_request", side_effect=responses):
            user, installations = main.list_github_user_installations("user-token")
        self.assertEqual(user["login"], "samkiper")
        self.assertEqual([item["id"] for item in installations], [10])

    def test_oauth_callback_links_an_existing_verified_installation(self):
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"):
            state = main.create_github_install_state("user-1", purpose="oauth")
        installation = {"id": 10, "app_id": 123, "account": {"login": "samkiper"}}
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"), \
                patch.object(main, "github_user_has_pro", return_value=True), \
                patch.object(main, "github_oauth_exchange", return_value="user-token"), \
                patch.object(main, "list_github_user_installations", return_value=({"login": "samkiper"}, [installation])), \
                patch.object(main, "save_github_installation_link", return_value={"installation_id": 10}):
            response = main.github_oauth_callback(code="code", state=state)
        self.assertEqual(response.status_code, 303)
        self.assertIn("github=connected", response.headers["location"])
        self.assertIn("github_account=samkiper", response.headers["location"])

    def test_oauth_callback_rejects_invalid_state_before_exchanging_code(self):
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "state-secret"), \
                patch.object(main, "github_oauth_exchange") as exchange:
            response = main.github_oauth_callback(code="code", state="invalid")
        self.assertEqual(response.status_code, 303)
        self.assertIn("github=error", response.headers["location"])
        exchange.assert_not_called()

    def test_safe_result_uses_supported_signal_language_and_action(self):
        with patch.object(main, "SEMGREP_ENABLED", False):
            result = main.analyze_code_product("Print a greeting", "print('hello')", filename="hello.py")
        self.assertEqual(result["scanner_version"], 20)
        self.assertEqual(result["verdict"]["id"], "continue_with_review")
        self.assertIn("No major supported risks", result["verdict"]["label"])
        self.assertEqual(result["coverage"]["language"], "Python")
        self.assertEqual(result["coverage"]["analysis_depth"], "Deep")
        self.assertTrue(any("not that the code was proven safe" in item for item in result["coverage"]["limitations"]))

    def test_high_risk_result_gives_beginner_safe_next_action(self):
        with patch.object(main, "SEMGREP_ENABLED", False):
            result = main.analyze_code_product("Print a greeting", "value = input()\neval(value)", filename="app.py")
        self.assertEqual(result["verdict"]["id"], "do_not_run")
        self.assertIn("scan the revised code again", result["verdict"]["action"])

    def test_web_ui_does_not_claim_behavior_matches_intent(self):
        html = Path("static/index.html").read_text(encoding="utf-8")
        self.assertNotIn("Behavior matches intent", html)
        self.assertIn("No supported risk signals found", html)
        self.assertIn("Show all ", html)
        self.assertIn('/github/connect-url', html)
        self.assertIn('id="githubAccountCard"', html)
        self.assertIn('id="githubConnectedStatus"', html)
        self.assertIn("✓ GitHub Connected", html)
        self.assertIn('id="dashboardModal"', html)
        self.assertIn('/github/dashboard', html)

    def test_github_scan_history_is_privacy_safe_and_feedback_ready(self):
        findings = [("src/app.py", {
            "line": 7,
            "severity": 22,
            "pattern": "credential_egress",
            "message": "Credential may leave the trusted environment",
            "why_risky": "A secret could be disclosed.",
            "suggested_fix": "Remove the secret from the payload.",
            "code": "do not store this source code",
        })]
        serialized = main.serialize_github_findings(findings)
        self.assertEqual(len(serialized), 1)
        self.assertEqual(serialized[0]["severity"], "high")
        self.assertRegex(serialized[0]["finding_id"], r"^[a-f0-9]{20}$")
        self.assertNotIn("code", serialized[0])

    def test_github_scan_history_upserts_without_source_code(self):
        with patch.object(main, "supabase_rest_request", return_value=[{"scan_id": "saved"}]) as request:
            saved = main.save_github_scan_history(
                "user-1", 123, "owner/repo", 9, "a" * 40, "completed",
                conclusion="neutral",
                findings=[("app.py", {"line": 2, "severity": 20, "message": "Risk"})],
                files_scanned=1,
            )
        self.assertEqual(len(saved["scan_id"]), 24)
        self.assertEqual(saved["high_count"], 1)
        self.assertNotIn("code", json.dumps(request.call_args.kwargs["payload"]))
        self.assertEqual(request.call_args.kwargs["query"], "on_conflict=scan_id")

    def test_github_repository_listing_filters_untrusted_names_and_urls(self):
        response = {
            "repositories": [
                {"full_name": "owner/good-repo", "private": True, "html_url": "https://evil.example"},
                {"full_name": "../../bad", "private": False},
            ],
        }
        with patch.object(main, "github_installation_token", return_value="token"), \
                patch.object(main, "github_api_request", return_value=response):
            repositories = main.list_github_installation_repositories(123)
        self.assertEqual(repositories, [{
            "full_name": "owner/good-repo",
            "private": True,
            "html_url": "https://github.com/owner/good-repo",
        }])

    def test_github_dashboard_is_scoped_to_the_authenticated_user(self):
        request = Request({
            "type": "http",
            "method": "GET",
            "path": "/github/dashboard",
            "headers": [],
            "client": ("127.0.0.1", 1),
        })
        installations = [{
            "installation_id": 123,
            "account_login": "owner",
            "account_type": "User",
            "status": "active",
            "updated_at": "2026-09-07T00:00:00Z",
        }]
        scans = [{
            "scan_id": "a" * 24,
            "repository": "owner/repo",
            "findings": [],
        }]
        with patch.object(main, "get_request_access_context", return_value={
            "authenticated": True,
            "user_id": "user-1",
            "plan": "pro",
        }), patch.object(main, "enrich_access_with_admin_metadata", side_effect=lambda value: value), \
                patch.object(main, "enforce_rate_limit"), \
                patch.object(main, "supabase_rest_request", side_effect=[installations, scans, [], []]) as database, \
                patch.object(main, "list_github_installation_repositories", return_value=[{
                    "full_name": "owner/repo",
                    "private": True,
                    "html_url": "https://github.com/owner/repo",
                }]):
            response = main.github_dashboard(request)
        payload = json.loads(response.body)
        self.assertTrue(payload["connected"])
        self.assertFalse(payload["stored_code"])
        self.assertEqual(payload["repositories"][0]["full_name"], "owner/repo")
        self.assertEqual(payload["scans"][0]["scan_id"], "a" * 24)
        self.assertEqual(payload["repositories"][0]["policy"]["enforcement_mode"], "monitor")
        self.assertEqual(payload["scans"][0]["comparison"]["new"], 0)
        for call in database.call_args_list:
            self.assertIn("user_id=eq.user-1", call.kwargs["query"])

    def test_repository_policy_defaults_to_monitor_and_only_blocks_when_enabled(self):
        findings = [{"severity": "high", "suppressed": False}]
        self.assertFalse(main.policy_blocks(main.default_repository_policy("owner/repo"), findings))
        self.assertTrue(main.policy_blocks({"enforcement_mode": "block", "block_at": "high"}, findings))
        self.assertFalse(main.policy_blocks({"enforcement_mode": "block", "block_at": "high"}, [{"severity": "high", "suppressed": True}]))

    def test_scan_comparison_reports_new_fixed_and_unchanged_findings(self):
        scans = [
            {"repository": "owner/repo", "pull_request_number": 1, "findings": [{"finding_id": "new"}, {"finding_id": "same"}]},
            {"repository": "owner/repo", "pull_request_number": 1, "findings": [{"finding_id": "old"}, {"finding_id": "same"}]},
        ]
        main.add_scan_comparisons(scans)
        self.assertEqual(scans[0]["comparison"], {"new": 1, "fixed": 1, "unchanged": 1, "has_previous": True})

    def test_suppression_keeps_finding_visible_with_audit_reason(self):
        finding = {"finding_id": "abc", "severity": "high"}
        result = main.annotate_suppressions([finding], {"abc": {"disposition": "accepted_risk", "reason": "Reviewed by owner", "expires_at": None}})
        self.assertTrue(result[0]["suppressed"])
        self.assertEqual(result[0]["suppression"]["reason"], "Reviewed by owner")

    def test_feedback_queue_requires_admin_before_database_access(self):
        request = Request({"type": "http", "method": "GET", "path": "/admin/feedback", "headers": [], "client": ("127.0.0.1", 1)})
        with patch.object(main, "get_request_access_context", return_value={"authenticated": True, "user_id": "user-1", "role": "user"}), \
                patch.object(main, "enrich_access_with_admin_metadata", side_effect=lambda value: value), \
                patch.object(main, "enforce_rate_limit"), \
                patch.object(main, "supabase_rest_request") as database:
            with self.assertRaises(HTTPException) as caught:
                main.admin_feedback_queue(request)
        self.assertEqual(caught.exception.status_code, 403)
        database.assert_not_called()

    def test_admin_can_review_feedback_without_source_code(self):
        request = Request({"type": "http", "method": "POST", "path": "/admin/feedback/7/review", "headers": [], "client": ("127.0.0.1", 1)})
        updated = [{"id": 7, "review_status": "accepted"}]
        with patch.object(main, "get_request_access_context", return_value={"authenticated": True, "user_id": "admin-1", "role": "admin"}), \
                patch.object(main, "enrich_access_with_admin_metadata", side_effect=lambda value: value), \
                patch.object(main, "enforce_rate_limit"), \
                patch.object(main, "supabase_rest_request", return_value=updated) as database:
            response = main.review_admin_feedback(7, main.FeedbackReviewRequest(decision="accepted"), request)
        payload = json.loads(response.body)
        self.assertTrue(payload["reviewed"])
        sent = database.call_args.kwargs["payload"]
        self.assertEqual(sent["review_status"], "accepted")
        self.assertNotIn("code", json.dumps(sent))

    def test_feedback_candidate_export_is_explicitly_not_test_ready(self):
        request = Request({"type": "http", "method": "GET", "path": "/admin/feedback/export", "headers": [], "client": ("127.0.0.1", 1)})
        row = {"id": 7, "verdict": "false_positive", "category": "network", "scanner_version": 19,
               "review_status": "accepted", "scan_id": "a" * 24, "finding_id": "b" * 20,
               "note": "looks safe", "review_note": "verified"}
        with patch.object(main, "get_request_access_context", return_value={"authenticated": True, "user_id": "admin-1", "role": "admin"}), \
                patch.object(main, "enrich_access_with_admin_metadata", side_effect=lambda value: value), \
                patch.object(main, "enforce_rate_limit"), \
                patch.object(main, "supabase_rest_request", return_value=[row]):
            response = main.export_admin_feedback(request)
        payload = json.loads(response.body)
        self.assertFalse(payload["contains_source_code"])
        self.assertFalse(payload["candidates"][0]["test_case_ready"])
        self.assertIn("minimal reproducing code", payload["candidates"][0]["missing"])


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

    def test_path_traversal_is_detected_without_category_hint(self):
        unsafe = '''from flask import request
from pathlib import Path
name = request.args.get("name")
candidate = Path("/srv/uploads") / name
contents = candidate.read_text()'''
        safe = unsafe.replace(
            'candidate = Path("/srv/uploads") / name',
            'base = Path("/srv/uploads").resolve()\ncandidate = (base / name).resolve()\n'
            'if not candidate.is_relative_to(base):\n    raise ValueError("outside upload directory")',
        )
        unsafe_result = main.analyze_code("Review this code before production", unsafe)
        safe_result = main.analyze_code("Review this code before production", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "untrusted_file_path" for item in unsafe_result["flags"]))

    def test_xpath_string_buffer_flow_is_detected_without_category_hint(self):
        unsafe = '''import io
from flask import request
value = request.form.get("employee")
buffer = io.StringIO()
buffer.write("/employees/employee[@id='")
buffer.write(value)
buffer.write("']")
query = buffer.getvalue()
nodes = root.xpath(query)'''
        safe = unsafe.replace("buffer.write(value)", 'buffer.write("42")')
        unsafe_result = main.analyze_code("Review this code before production", unsafe)
        safe_result = main.analyze_code("Review this code before production", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "dynamic_xpath_query" for item in unsafe_result["flags"]))

    def test_xxe_flow_is_detected_without_category_hint(self):
        unsafe = '''from flask import request
import xml.dom.minidom
import xml.sax
payload = request.data
parser = xml.sax.make_parser()
parser.setFeature(xml.sax.handler.feature_external_ges, True)
document = xml.dom.minidom.parseString(payload, parser)'''
        safe = unsafe.replace("True", "False")
        unsafe_result = main.analyze_code("Review this code before production", unsafe)
        safe_result = main.analyze_code("Review this code before production", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "xxe_external_entities" for item in unsafe_result["flags"]))

    def test_weak_random_session_value_is_detected_without_category_hint(self):
        unsafe = '''import random
from helpers import mysession
value = str(random.getrandbits(32))
mysession["remember_me"] = value'''
        safe = unsafe.replace("import random", "import secrets").replace(
            "str(random.getrandbits(32))", "secrets.token_urlsafe(32)"
        )
        unsafe_result = main.analyze_code("Review this code before production", unsafe)
        safe_result = main.analyze_code("Review this code before production", safe)
        self.assertEqual(unsafe_result["risk"], "yellow")
        self.assertEqual(safe_result["risk"], "green")
        self.assertTrue(any(item.get("pattern") == "weak_random_security_value" for item in unsafe_result["flags"]))


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

    def test_semgrep_retries_once_within_a_bounded_budget(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": '{"results": []}'})()
        with patch("main.shutil.which", return_value="/usr/bin/semgrep"), \
                patch.object(main, "SEMGREP_BUDGET_SECONDS", 40), \
                patch.object(main, "SEMGREP_FIRST_ATTEMPT_SECONDS", 28), \
                patch("main.subprocess.run", side_effect=[main.subprocess.TimeoutExpired("semgrep", 28), completed]) as runner:
            result = main.run_semgrep_scan("print('hello')", "app.py")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["fallback_used"])
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(runner.call_count, 2)


class GitHubWebhookTests(unittest.TestCase):
    def test_signature_verification_uses_hmac_sha256(self):
        payload = b'{"zen":"safe"}'
        with patch.object(main, "GITHUB_WEBHOOK_SECRET", "test-secret"):
            digest = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
            self.assertTrue(main.verify_github_webhook_signature(payload, "sha256=" + digest))
            self.assertFalse(main.verify_github_webhook_signature(payload, "sha256=wrong"))

    def test_signed_malformed_webhook_payload_returns_bad_request(self):
        payload = b"{not-json"
        digest = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
        delivered = False

        async def receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": payload, "more_body": False}

        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/github/webhook",
            "headers": [
                (b"x-hub-signature-256", f"sha256={digest}".encode("ascii")),
                (b"x-github-event", b"pull_request"),
            ],
            "query_string": b"",
            "scheme": "https",
            "server": ("testserver", 443),
            "client": ("203.0.113.10", 1234),
        }, receive=receive)
        with patch.object(main, "GITHUB_WEBHOOK_SECRET", "test-secret"):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.github_webhook(request, BackgroundTasks()))
        self.assertEqual(caught.exception.status_code, 400)

    def test_pull_request_event_is_validated_and_parsed(self):
        sha = "a" * 40
        body = {
            "installation": {"id": 123},
            "number": 42,
            "repository": {"full_name": "owner/repo"},
            "pull_request": {"head": {"sha": sha}},
        }
        self.assertEqual(main.parse_github_pull_request_event(body), (123, "owner/repo", 42, sha))
        body["repository"]["full_name"] = "owner/repo/extra"
        with self.assertRaises(ValueError):
            main.parse_github_pull_request_event(body)

    def test_check_rerequest_event_is_validated_and_parsed(self):
        sha = "e" * 40
        body = {
            "installation": {"id": 123},
            "repository": {"full_name": "owner/repo"},
            "check_run": {
                "name": "AI Code Audit",
                "head_sha": sha,
                "pull_requests": [{"number": 42}],
            },
        }
        self.assertEqual(main.parse_github_check_rerequest_event(body), (123, "owner/repo", 42, sha))
        body["check_run"]["name"] = "Another check"
        with self.assertRaises(ValueError):
            main.parse_github_check_rerequest_event(body)

    def test_github_summary_discloses_annotation_limit(self):
        findings = [("app.py", {"line": index + 1, "severity": 20, "message": "Risk"}) for index in range(55)]
        output = main.build_github_check_output(findings, 1, 0)
        self.assertIn("first 50 of 55 findings", output["summary"])

    def test_pro_enforcement_rejects_unlinked_installation(self):
        with patch.object(main, "GITHUB_ENFORCE_PRO", True), \
                patch.object(main, "supabase_rest_request", return_value=[]):
            result = main.github_installation_entitlement(123)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "installation_not_linked")

    def test_pro_enforcement_accepts_linked_pro_account(self):
        with patch.object(main, "GITHUB_ENFORCE_PRO", True), \
                patch.object(main, "supabase_rest_request", return_value=[{"user_id": "user-1"}]), \
                patch.object(main, "get_supabase_admin_user", return_value={"app_metadata": {"plan": "pro"}}):
            result = main.github_installation_entitlement(123)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["reason"], "active_pro")

    def test_pull_request_file_listing_paginates_and_filters(self):
        first_page = [{"filename": f"docs/page-{index}.md", "status": "modified"} for index in range(100)]
        second_page = [
            {"filename": "src/app.py", "status": "modified"},
            {"filename": "src/old.py", "status": "removed"},
        ]
        with patch.object(main, "github_api_request", side_effect=[first_page, second_page]) as request:
            files = main.list_github_pull_request_files("owner/repo", 7, "token")
        self.assertEqual([item["filename"] for item in files], ["src/app.py"])
        self.assertEqual(request.call_count, 2)

    def test_changed_file_scan_does_not_scan_unchanged_source(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("owner-repo-sha/src/changed.py", "eval(user_input)")
            output.writestr("owner-repo-sha/src/unchanged.py", "print('safe')")
        changed_files = [{"filename": "src/changed.py", "status": "modified"}]
        with patch.object(main, "analyze_code", return_value={"flags": [{"line": 1, "severity": 25}]}) as analyze:
            findings, scanned, skipped = main.scan_github_changed_files(archive.getvalue(), changed_files)
        self.assertEqual(scanned, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(findings[0][0], "src/changed.py")
        analyze.assert_called_once()

    def test_existing_check_is_updated_instead_of_duplicated(self):
        existing = {"check_runs": [{"id": 77, "external_id": main.github_check_external_id("owner/repo", 9, "b" * 40)}]}
        with patch.object(main, "github_api_request", side_effect=[existing, {"id": 77}]) as request:
            main.upsert_github_check("owner/repo", 9, "b" * 40, "token", {"status": "in_progress"})
        self.assertEqual(request.call_args_list[1].args[0], "PATCH")
        self.assertTrue(request.call_args_list[1].args[1].endswith("/check-runs/77"))

    def test_rerun_does_not_append_duplicate_annotations(self):
        existing = {"check_runs": [{
            "id": 77,
            "external_id": main.github_check_external_id("owner/repo", 9, "b" * 40),
            "output": {"annotations_count": 2},
        }]}
        payload = {
            "status": "completed",
            "conclusion": "neutral",
            "output": {
                "title": "2 findings",
                "summary": "Current scan summary",
                "annotations": [{"path": "app.py", "start_line": 1, "end_line": 1}],
            },
        }
        with patch.object(main, "github_api_request", side_effect=[existing, {"id": 77}]) as request:
            main.upsert_github_check("owner/repo", 9, "b" * 40, "token", payload)
        update_payload = request.call_args_list[1].args[3]
        self.assertNotIn("annotations", update_payload["output"])
        self.assertEqual(update_payload["output"]["summary"], "Current scan summary")

    def test_findings_are_monitor_only_and_never_fail_the_pull_request(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("owner-repo-sha/app.py", "eval(user_input)")
        with patch.object(main, "GITHUB_ENFORCE_PRO", False), \
                patch.object(main, "github_installation_token", return_value="token"), \
                patch.object(main, "list_github_pull_request_files", return_value=[{"filename": "app.py"}]), \
                patch.object(main, "download_github_archive", return_value=archive.getvalue()), \
                patch.object(main, "analyze_code", return_value={"flags": [{
                    "line": 1,
                    "severity": 25,
                    "message": "Risk",
                    "why_risky": "This can expose a credential.",
                    "suggested_fix": "Remove the credential from the request.",
                }]}), \
                patch.object(main, "upsert_github_check", return_value={}) as upsert:
            main.process_github_pull_request(1, "owner/repo", 5, "c" * 40)
        final_payload = upsert.call_args_list[-1].args[4]
        self.assertEqual(final_payload["status"], "completed")
        self.assertEqual(final_payload["conclusion"], "neutral")
        self.assertIn("does not block merging", final_payload["output"]["summary"])
        self.assertIn("1 high", final_payload["output"]["summary"])
        self.assertIn("**HIGH**", final_payload["output"]["text"])
        self.assertEqual(final_payload["details_url"], "https://github.com/owner/repo/pull/5/files")
        annotation = final_payload["output"]["annotations"][0]
        self.assertEqual(annotation["annotation_level"], "warning")
        self.assertEqual(annotation["title"], "AI Code Audit • High severity")
        self.assertIn("Why it matters:", annotation["message"])
        self.assertIn("Suggested fix:", annotation["message"])

    def test_scan_failure_is_reported_as_non_blocking_neutral(self):
        with patch.object(main, "GITHUB_ENFORCE_PRO", False), \
                patch.object(main, "github_installation_token", return_value="token"), \
                patch.object(main, "list_github_pull_request_files", side_effect=RuntimeError("temporary")), \
                patch.object(main, "upsert_github_check", return_value={}) as upsert:
            main.process_github_pull_request(1, "owner/repo", 5, "d" * 40)
        failure_payload = upsert.call_args_list[-1].args[4]
        self.assertEqual(failure_payload["conclusion"], "neutral")
        self.assertIn("could not complete", failure_payload["output"]["title"].lower())


class LaunchReadinessV201Tests(unittest.TestCase):
    def test_score_colors_and_verdicts_share_one_policy(self):
        cases = [
            ("red", 65, "#ef4444", "do_not_run"),
            ("yellow", 90, "#d4aa21", "review_first"),
            ("green", 91, "#22c55e", "continue_with_review"),
        ]
        for risk, score, color, verdict in cases:
            with self.subTest(risk=risk, score=score):
                self.assertEqual(main.badge_color_from_risk(risk, score), color)
                self.assertEqual(main.build_action_verdict(risk, score)["id"], verdict)

    def test_public_information_pages_exist_and_disclose_boundaries(self):
        expected = {
            "methodology.html": "It does not prove that code is safe",
            "privacy.html": "does not retain a raw source-code copy",
            "terms.html": "does not provide a guarantee of safety",
            "security.html": "private GitHub Security Advisory",
            "support.html": "Do not post secrets or private account information",
        }
        for filename, phrase in expected.items():
            with self.subTest(filename=filename):
                html = Path("static", filename).read_text(encoding="utf-8")
                self.assertIn(phrase, html)

    def test_homepage_uses_audit_score_and_complete_pro_positioning(self):
        html = Path("static/index.html").read_text(encoding="utf-8")
        self.assertIn("AUDIT SCORE", html)
        self.assertNotIn("RISK-WEIGHTED SCORE", html)
        self.assertIn("Dashboard, history, and scan comparisons", html)
        self.assertIn("Repository policies and optional merge blocking", html)
        self.assertIn('href="/privacy"', html)
        self.assertIn('href="/methodology"', html)
        self.assertIn("North Third Street Media and Design LLC", html)
        self.assertIn("support.aicodeaudit@gmail.com", html)

    def test_results_toolbar_controls_remain_readable_on_dark_background(self):
        html = Path("static/index.html").read_text(encoding="utf-8")
        self.assertIn(".v20-toolbar button,.v20-toolbar select", html)
        self.assertIn("color:#dce8e3;color-scheme:dark", html)
        self.assertIn(".v20-toolbar button:disabled", html)
        self.assertIn("color:#81958d", html)

    def test_repository_readiness_files_exist(self):
        for filename in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "LICENSE"):
            with self.subTest(filename=filename):
                self.assertTrue(Path(filename).is_file())

    def test_public_operator_and_support_contact_are_disclosed(self):
        expected_operator = "North Third Street Media Group, a DBA of North Third Street Media and Design LLC"
        expected_email = "support.aicodeaudit@gmail.com"
        for path in ("static/privacy.html", "static/terms.html", "static/support.html"):
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn(expected_operator, content)
            self.assertIn(expected_email, content)
        self.assertIn(expected_email, Path("static/security.html").read_text(encoding="utf-8"))
        self.assertIn("All rights reserved", Path("LICENSE").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
