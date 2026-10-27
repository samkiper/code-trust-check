"""Mocked authorization contracts; these are not live GitHub account tests."""
import base64
import hashlib
import json
import logging
import unittest
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch, MagicMock
from starlette.requests import Request
import main


class GitHubOAuthBindingTests(unittest.TestCase):
    def test_completion_rejects_missing_wrong_session_and_browser_binding(self):
        verifier = "v" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        request = Request({"type": "http", "headers": []})
        cases = [
            ({}, verifier, 401),
            ({"authenticated": True, "user_id": "other", "plan": "pro"}, verifier, 400),
            ({"authenticated": True, "user_id": "owner", "plan": "free"}, verifier, 403),
            ({"authenticated": True, "user_id": "owner", "plan": "pro"}, "wrong", 400),
            ({"authenticated": True, "user_id": "owner", "plan": "pro"}, "w" * 43, 400),
        ]
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "test-state-secret"):
            state = main.create_github_install_state("owner", purpose="oauth", code_challenge=challenge)
            for access, supplied, expected in cases:
                with self.subTest(access=access, verifier_length=len(supplied)), \
                        patch.object(main, "get_request_access_context", return_value=access), \
                        patch.object(main, "enrich_access_with_admin_metadata", side_effect=lambda a: a), \
                        patch.object(main, "enforce_rate_limit"), \
                        patch.object(main, "github_oauth_exchange") as exchange, \
                        patch.object(main, "save_github_installation_link") as save:
                    response = main.complete_github_oauth(main.GitHubOAuthCompleteRequest(code="test-code", state=state, code_verifier=supplied), request)
                    self.assertEqual(response.status_code, expected)
                    exchange.assert_not_called()
                    save.assert_not_called()

    def test_get_callback_cannot_link_even_with_valid_signed_state(self):
        with patch.object(main, "GITHUB_LINK_STATE_SECRET", "test-state-secret"), \
                patch.object(main, "github_oauth_exchange") as exchange, \
                patch.object(main, "save_github_installation_link") as save:
            state = main.create_github_install_state("owner", purpose="oauth", code_challenge="a" * 43)
            response = main.github_oauth_callback(code="test-code", state=state)
            self.assertEqual(response.status_code, 303)
            self.assertNotIn("test-code", response.headers["location"])
            self.assertNotIn(state, response.headers["location"])
            self.assertEqual(response.headers["referrer-policy"], "no-referrer")
            exchange.assert_not_called()
            save.assert_not_called()

    def test_token_exchange_sends_verifier_to_github(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"access_token":"test-token"}'
        opener=MagicMock();opener.open.return_value=response
        with patch.object(main.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(main.github_oauth_exchange("test-code", "v" * 43), "test-token")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://github.com/login/oauth/access_token")
        self.assertEqual(json.loads(request.data)["code_verifier"], "v" * 43)

    def test_token_exchange_logs_only_allowlisted_error_categories(self):
        response=MagicMock();opener=MagicMock();opener.open.return_value=response
        with patch.object(main.urllib.request,'build_opener',return_value=opener), patch.object(main,'log_server_issue') as log:
            for error,expected in [('bad_verification_code','bad_verification_code'),('private-token-data','other')]:
                response.__enter__.return_value.read.return_value=json.dumps({'error':error,'error_description':'private-code'}).encode()
                with self.assertRaises(RuntimeError):main.github_oauth_exchange('test-code','v'*43)
                log.assert_called_with('GitHub token exchange rejected: '+expected)

    def test_oauth_authorization_rejects_absent_or_plain_challenge(self):
        with patch.object(main, "GITHUB_CLIENT_ID", "client"), patch.object(main, "GITHUB_CLIENT_SECRET", "secret"), patch.object(main, "GITHUB_LINK_STATE_SECRET", "state"):
            for challenge in ["", "short", "a" * 44, "!" * 43]:
                with self.assertRaises(ValueError):
                    main.github_oauth_authorize_url("owner", challenge)

    def test_callback_forwards_only_to_signed_allowlisted_frontend_fragment(self):
        with patch.object(main,'GITHUB_LINK_STATE_SECRET','test-state-secret'), \
                patch.object(main,'github_oauth_exchange') as exchange:
            state=main.create_github_install_state('owner',purpose='oauth',code_challenge='a'*43,return_origin='https://aicodeaudit.org')
            response=main.github_oauth_callback(code='synthetic-code',state=state)
            target=urlparse(response.headers['location'])
            self.assertEqual((target.scheme,target.netloc,target.path),('https','aicodeaudit.org','/account/github/callback'))
            self.assertEqual(target.query,'')
            self.assertEqual(parse_qs(target.fragment)['code'],['synthetic-code'])
            self.assertEqual(parse_qs(target.fragment)['state'],[state])
            exchange.assert_not_called()
            with self.assertRaises(ValueError):
                main.create_github_install_state('owner',purpose='oauth',code_challenge='a'*43,return_origin='https://attacker.example')

    def test_oauth_callback_access_log_hides_code_and_state(self):
        record=logging.LogRecord('uvicorn.access',logging.INFO,'test',1,'%s - "%s %s HTTP/%s" %d',('client','GET','/github/oauth/callback?code=secret-code&state=private-state','1.1',303),None)
        main.OAuthAccessLogFilter().filter(record)
        self.assertNotIn('secret-code',record.getMessage())
        self.assertNotIn('private-state',record.getMessage())
        self.assertIn('[redacted]',record.getMessage())
