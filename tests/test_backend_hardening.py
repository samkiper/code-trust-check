import io
import time
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

import main


def make_request(headers=None, client=("203.0.113.10", 1234)):
    raw_headers = [
        (str(key).lower().encode("latin-1"), str(value).encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/scan",
        "headers": raw_headers,
        "client": client,
        "server": ("testserver", 80),
        "scheme": "http",
        "query_string": b"",
    })


class AuthenticationHardeningTests(unittest.TestCase):
    def test_unverified_bearer_token_cannot_authenticate(self):
        request = make_request({"Authorization": "Bearer header.payload.signature"})
        with patch.object(main, "SUPABASE_URL", ""), patch.object(main, "SUPABASE_SECRET_KEY", ""):
            access = main.get_request_access_context(request)
        self.assertFalse(access["authenticated"], access)
        self.assertEqual(access["plan"], "free", access)


class RateLimitAndPrivacyTests(unittest.TestCase):
    def setUp(self):
        main.RATE_LIMIT_STATE.clear()

    def test_rate_limit_rejects_excess_requests(self):
        request = make_request({"User-Agent": "benchmark"})
        access = {"authenticated": False}
        with patch.dict(main.RATE_LIMITS_PER_MINUTE, {"scan": {"anonymous": 1, "authenticated": 1}}):
            main.enforce_rate_limit(request, access, "scan")
            with self.assertRaises(HTTPException) as caught:
                main.enforce_rate_limit(request, access, "scan")
        self.assertEqual(caught.exception.status_code, 429)
        self.assertIn("Retry-After", caught.exception.headers)

    def test_persistent_rate_limit_is_shared_and_skips_local_bucket(self):
        request = make_request({"User-Agent": "browser"})
        access = {"authenticated": True, "user_id": "user-123"}
        with patch.object(main, "consume_persistent_rate_limit", side_effect=[
            {"allowed": True, "retry_after": 1, "remaining": 0},
            {"allowed": False, "retry_after": 37, "remaining": 0},
        ]):
            main.enforce_rate_limit(request, access, "github")
            with self.assertRaises(HTTPException) as caught:
                main.enforce_rate_limit(request, access, "github")
        self.assertEqual(caught.exception.headers["Retry-After"], "37")
        self.assertEqual(request.state.rate_limit_backend, "supabase")
        self.assertEqual(main.RATE_LIMIT_STATE, {})

    def test_persistent_rate_limit_key_does_not_expose_actor(self):
        key = main.persistent_rate_limit_key("scan:user:private-user-id")
        self.assertRegex(key, r"^v1:[a-f0-9]{64}$")
        self.assertNotIn("private-user-id", key)

    def test_github_and_billing_requests_use_independent_buckets(self):
        request = make_request({"User-Agent": "browser"})
        access = {"authenticated": True, "user_id": "user-123"}
        limits = {
            "billing": {"anonymous": 1, "authenticated": 1},
            "github": {"anonymous": 1, "authenticated": 1},
        }
        with patch.dict(main.RATE_LIMITS_PER_MINUTE, limits):
            main.enforce_rate_limit(request, access, "billing")
            main.enforce_rate_limit(request, access, "github")
            with self.assertRaises(HTTPException):
                main.enforce_rate_limit(request, access, "github")

        self.assertIn("billing:user:user-123", main.RATE_LIMIT_STATE)
        self.assertIn("github:user:user-123", main.RATE_LIMIT_STATE)

    def test_private_responses_disable_caching(self):
        response = main.private_json({"ok": True})
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(response.headers["pragma"], "no-cache")

    def test_homepage_has_browser_security_policy(self):
        response = TestClient(main.app).get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["cross-origin-opener-policy"], "same-origin")


class RepositoryScoringTests(unittest.TestCase):
    def test_critical_production_file_is_not_averaged_away(self):
        points = main.calculate_repository_risk_points([40.0] + [0.0] * 99)
        self.assertEqual(main.risk_from_points(points), "red")

    def test_test_fixture_weight_reduces_a_isolated_example(self):
        weighted = main.weighted_repository_file_points("project/tests/exploit_test.py", 40.0)
        points = main.calculate_repository_risk_points([weighted] + [0.0] * 10)
        self.assertEqual(main.risk_from_points(points), "yellow")

    def test_attack_fixtures_cannot_make_the_repo_red_by_themselves(self):
        weighted = main.weighted_repository_file_points("project/tests/attack_benchmark.py", 100.0)
        self.assertEqual(weighted, 25.0)
        self.assertEqual(main.risk_from_points(weighted), "yellow")

    def test_dependency_risk_is_not_averaged_across_files(self):
        points = main.calculate_repository_risk_points([0.0] * 100, dependency_risk_points=20)
        self.assertEqual(points, 20.0)
        self.assertEqual(main.risk_from_points(points), "yellow")

    def test_repeated_low_severity_behavior_has_diminishing_weight(self):
        flags = [
            {"pattern": "fetch(", "severity": 4.0}
            for _ in range(20)
        ]
        self.assertEqual(main.aggregate_flag_risk_points(flags), 7.0)

    def test_dependency_manifests_are_bounded_and_parsed(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("repo/requirements.txt", "requests==2.31.0\n")
            output.writestr("repo/package.json", '{"dependencies":{"lodash":"4.17.21"}}')
        archive.seek(0)
        with zipfile.ZipFile(archive) as source, \
                patch.object(main, "query_osv_batch", return_value=[]), \
                patch.object(main, "registry_package_exists", return_value=True):
            result = main.analyze_dependency_manifests(source)
        self.assertEqual(result["manifests_scanned"], 2)
        self.assertEqual(result["dependencies_parsed"], 2)

    def test_common_lockfiles_cover_six_dependency_ecosystems(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("repo/pyproject.toml", '[project]\ndependencies = ["requests==2.31.0"]\n')
            output.writestr("repo/poetry.lock", '[[package]]\nname = "flask"\nversion = "3.0.0"\n')
            output.writestr("repo/package-lock.json", '{"packages":{"node_modules/lodash":{"name":"lodash","version":"4.17.21"}}}')
            output.writestr("repo/yarn.lock", 'left-pad@^1.3.0:\n  version "1.3.0"\n')
            output.writestr("repo/pnpm-lock.yaml", "packages:\n  react@18.2.0:\n    resolution: {}\n")
            output.writestr("repo/go.mod", "module example.com/app\nrequire github.com/gin-gonic/gin v1.9.1\n")
            output.writestr("repo/Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.188"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
            output.writestr("repo/composer.lock", '{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}')
            output.writestr("repo/Gemfile.lock", "GEM\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n")
        archive.seek(0)
        with zipfile.ZipFile(archive) as source, \
                patch.object(main, "query_osv_batch", return_value=[]), \
                patch.object(main, "registry_package_exists", return_value=True):
            result = main.analyze_dependency_manifests(source)
        self.assertEqual(result["manifests_scanned"], 9)
        self.assertGreaterEqual(result["dependencies_parsed"], 9)
        ecosystems = {item["ecosystem"] for item in main.dedupe_dependencies([
            *main.parse_pyproject_manifest("pyproject.toml", '[project]\ndependencies=["requests==2.31.0"]')[0],
            *main.parse_go_mod_manifest("go.mod", "require github.com/gin-gonic/gin v1.9.1")[0],
            *main.parse_cargo_lock_manifest("Cargo.lock", '[[package]]\nname="serde"\nversion="1.0.188"')[0],
            *main.parse_composer_lock_manifest("composer.lock", '{"packages":[{"name":"a/b","version":"1.0.0"}]}')[0],
            *main.parse_gemfile_lock_manifest("Gemfile.lock", "GEM\n  specs:\n    rake (13.0.6)\n")[0],
            *main.parse_npm_lock_manifest("package-lock.json", '{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}')[0],
        ])}
        self.assertEqual(ecosystems, {"PyPI", "npm", "Go", "crates.io", "Packagist", "RubyGems"})


class BillingLifecycleTests(unittest.TestCase):
    def test_active_trial_and_past_due_keep_pro_access(self):
        for status in ("active", "trialing", "past_due"):
            with self.subTest(status=status):
                self.assertEqual(main.plan_from_subscription_status(status), "pro")

    def test_terminal_statuses_remove_pro_access(self):
        for status in ("canceled", "unpaid", "incomplete_expired"):
            with self.subTest(status=status):
                self.assertEqual(main.plan_from_subscription_status(status), "free")

    def test_future_cancel_at_period_end_keeps_access(self):
        self.assertEqual(
            main.plan_from_subscription_status(
                "canceled",
                cancel_at_period_end=True,
                current_period_end=int(time.time()) + 3600,
            ),
            "pro",
        )

    def test_new_invoice_shape_resolves_subscription(self):
        invoice = SimpleNamespace(
            subscription=None,
            parent=SimpleNamespace(
                subscription_details=SimpleNamespace(subscription=SimpleNamespace(id="sub_123"))
            ),
        )
        self.assertEqual(main.stripe_invoice_subscription_id(invoice), "sub_123")


class DownloadBoundsTests(unittest.TestCase):
    def test_declared_oversized_response_is_rejected(self):
        response = SimpleNamespace(headers={"Content-Length": "101"})
        with self.assertRaises(ValueError):
            main.read_bounded_response(response, 100)


if __name__ == "__main__":
    unittest.main()
