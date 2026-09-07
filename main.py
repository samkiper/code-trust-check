from fastapi import BackgroundTasks, FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, Response, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import os
import io
import ast
import base64
import json
import zipfile
import urllib.request
import urllib.error
import ssl
import certifi
import hashlib
import hmac
import shutil
import subprocess
import tempfile
import difflib
import time
import threading
import secrets
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from html import escape as html_escape
from dotenv import load_dotenv
from datetime import date, datetime, timezone, timedelta
from urllib.parse import urlparse, quote, urlencode
import stripe
import jwt

load_dotenv()

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://ohabowduaydfaauqadqt.supabase.co wss://ohabowduaydfaauqadqt.supabase.co; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    if request.url.scheme == "https" or forwarded_proto == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith(("/scan", "/auth/", "/stripe/", "/github/", "/admin/")):
        response.headers.setdefault("Cache-Control", "no-store, max-age=0")
        response.headers.setdefault("Pragma", "no-cache")
    return response


@app.exception_handler(Exception)
async def unhandled_application_error(request: Request, exc: Exception):
    stage = str(getattr(request.state, "operation_stage", "processing the request"))
    safe_stage = re.sub(r"[^a-zA-Z0-9 _-]", "", stage)[:80] or "processing the request"
    log_server_issue(f"Unhandled application error while {safe_stage}", exc)
    return JSONResponse(
        {"detail": "The server could not complete that request."},
        status_code=500,
        headers={"Cache-Control": "no-store"},
    )


class ScanRequest(BaseModel):
    intent: str
    code: str
    is_example: bool = False


class RepoScanRequest(BaseModel):
    intent: str
    repo_url: str


class GitHubInstallationLinkRequest(BaseModel):
    installation_id: int
    state: str


class FixPreviewRequest(BaseModel):
    intent: str
    code: str


class FeedbackRequest(BaseModel):
    scan_id: str
    finding_id: str
    verdict: str
    category: str = ""
    note: str = ""


class FeedbackReviewRequest(BaseModel):
    decision: str
    review_note: str = ""


class RepositoryPolicyRequest(BaseModel):
    enforcement_mode: str = "monitor"
    block_at: str = "high"


class FindingSuppressionRequest(BaseModel):
    repository: str
    finding_id: str
    disposition: str
    reason: str
    expires_in_days: int | None = None


# display_key, regex, label, base severity points
SUSPICIOUS_PATTERNS = [
    ("eval(", r"(?<![\w.])eval\s*\(", "Suspicious usage detected: eval(", 25),
    ("exec(", r"(?<![\w.])exec\s*\(", "Suspicious usage detected: exec(", 25),
    ("os.system", r"\bos\.system\s*\(", "Suspicious usage detected: os.system", 30),
    ("subprocess", r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(", "Suspicious usage detected: subprocess", 15),
    ("child_process", r"\bchild_process\.(?:exec|execFile|spawn|fork)\s*\(", "Suspicious usage detected: child_process", 15),
    ("requests.post", r"\brequests\.post\s*\(", "Suspicious usage detected: requests.post", 4),
    ("requests.get", r"\brequests\.get\s*\(", "Suspicious usage detected: requests.get", 2),
    ("socket", r"\bsocket\.(?:socket|create_connection)\s*\(", "Suspicious usage detected: socket", 8),
    ("fetch(", r"(?<![\w.])fetch\s*\(", "Suspicious usage detected: fetch(", 0),
    ("open(", r"(?<![\w.])open\s*\(", "Suspicious usage detected: open(", 0.5),
    ("__import__", r"(?<![\w.])__import__\s*\(", "Suspicious usage detected: __import__", 8),
    ("importlib.import_module", r"\bimportlib\.import_module\s*\(", "Suspicious usage detected: importlib.import_module", 6),
    ("pickle.loads", r"\bpickle\.loads\s*\(", "Suspicious usage detected: pickle.loads", 20),
    ("pickle.load", r"\bpickle\.load\s*\(", "Suspicious usage detected: pickle.load", 20),
    ("marshal.loads", r"\bmarshal\.loads\s*\(", "Suspicious usage detected: marshal.loads", 18),
    ("marshal.load", r"\bmarshal\.load\s*\(", "Suspicious usage detected: marshal.load", 18),
    ("yaml.load", r"\byaml\.load\s*\(", "Suspicious usage detected: yaml.load", 14),
    ("dill.loads", r"\bdill\.loads\s*\(", "Suspicious usage detected: dill.loads", 18),
    ("shelve.open", r"\bshelve\.open\s*\(", "Suspicious usage detected: shelve.open", 8),
    ("urllib.request.urlopen", r"\burllib\.request\.urlopen\s*\(", "Suspicious usage detected: urllib.request.urlopen", 3),
    ("urllib.request.urlretrieve", r"\burllib\.request\.urlretrieve\s*\(", "Suspicious usage detected: urllib.request.urlretrieve", 5),
    ("urllib.request.Request", r"\burllib\.request\.Request\s*\(", "Suspicious usage detected: urllib.request.Request", 2),
    ("download helper", r"\b(?:curl|wget)\s+(?:-[^\s]+\s+)*https?://", "Suspicious usage detected: download helper", 8),
    ("bytes.fromhex", r"\bbytes\.fromhex\s*\(", "Suspicious usage detected: bytes.fromhex", 4),
    ("tls_verify_disabled", r"\bverify\s*=\s*false\b", "TLS certificate verification is disabled", 14),
    ("debug_mode_enabled", r"\bdebug\s*=\s*true\b", "Production debug mode may be enabled", 9),
    ("persistence_registry", r"\bwinreg\.(?:setvalue|setvalueex|createkey)\s*\(", "Code may create Windows startup persistence", 24),
    ("persistence_scheduler", r"\b(?:crontab|schtasks|launchctl)\b", "Code may create scheduled persistence", 23),
    ("telemetry_sdk", r"\b(?:sentry_sdk\.init|posthog\.capture|analytics\.track|mixpanel\.track)\s*\(", "Code initializes or sends telemetry", 4),
]

# regex, label, severity points
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Possible AWS access key", 30),
    (r"-----BEGIN PRIVATE KEY-----", "Possible private key", 40),
    (r"sk-[A-Za-z0-9]{20,}", "Possible API secret key", 30),
    (r"AIza[0-9A-Za-z\-_]{35}", "Possible Google API key", 25),
]

# Environment-backed credentials are not literal secrets, but they are still
# sensitive sources. Track the assigned variable so later network sinks can be
# scored as a potential secret-exfiltration path.
SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?:secret|token|password|passwd|api[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)
ENV_SECRET_ASSIGNMENT_PATTERNS = [
    re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:os\.)?getenv\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*os\.environ(?:\.get\s*\(\s*['\"]([^'\"]+)['\"]|\s*\[\s*['\"]([^'\"]+)['\"])",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:process\.env\.|Deno\.env\.get\s*\(\s*['\"])([A-Za-z0-9_-]+)",
        re.IGNORECASE,
    ),
]

SUPPORTED_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb",
    ".php", ".cs", ".cpp", ".c", ".rs", ".sh", ".swift", ".kt",
    ".sql", ".html", ".css", ".json", ".yaml", ".yml", ".xml"
}

FREE_LINE_LIMIT = 10000
FREE_REPO_FILE_LIMIT = 50
FREE_REPO_SIZE_LIMIT_BYTES = 1_000_000
FREE_DAILY_SCAN_LIMIT = None
PRO_LINE_LIMIT = 20000
PRO_REPO_FILE_LIMIT = 200
PRO_REPO_SIZE_LIMIT_BYTES = 10_000_000
PRO_DAILY_SCAN_LIMIT = None

MAX_PASTED_CODE_BYTES_FREE = 1_000_000
MAX_PASTED_CODE_BYTES_PRO = 2_000_000
MAX_REPOSITORY_ARCHIVE_BYTES = 25_000_000
MAX_DEPENDENCY_MANIFEST_BYTES = 1_000_000
MAX_DEPENDENCY_MANIFESTS = 25

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMITS_PER_MINUTE = {
    "scan": {"anonymous": 20, "authenticated": 60},
    "repo": {"anonymous": 5, "authenticated": 15},
    "billing": {"anonymous": 3, "authenticated": 10},
    "github": {"anonymous": 5, "authenticated": 30},
    "feedback": {"anonymous": 2, "authenticated": 20},
}
RATE_LIMIT_STATE: dict[str, list[float]] = {}
RATE_LIMIT_LOCK = threading.Lock()
PERSISTENT_RATE_LIMITS_ENABLED = os.getenv("PERSISTENT_RATE_LIMITS_ENABLED", "true").strip().lower() not in {
    "0", "false", "no", "off"
}

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "price_1TBryAEKmNfjd7YM13LoKYvs").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
SEMGREP_ENABLED = os.getenv("SEMGREP_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
SEMGREP_CONFIG_PATH = Path(__file__).with_name("semgrep.yml")
SEMGREP_BUDGET_SECONDS = max(15, min(int(os.getenv("SEMGREP_BUDGET_SECONDS", "40")), 60))
SEMGREP_FIRST_ATTEMPT_SECONDS = max(10, min(int(os.getenv("SEMGREP_FIRST_ATTEMPT_SECONDS", "28")), SEMGREP_BUDGET_SECONDS))
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "").strip()
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n").strip()
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
GITHUB_APP_SLUG = os.getenv("GITHUB_APP_SLUG", "").strip()
GITHUB_ENFORCE_PRO = os.getenv("GITHUB_ENFORCE_PRO", "false").strip().lower() in {"1", "true", "yes", "on"}
GITHUB_LINK_STATE_SECRET = os.getenv("GITHUB_LINK_STATE_SECRET", "").strip() or GITHUB_WEBHOOK_SECRET
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "").strip()

SCANNER_VERSION = 20

GITHUB_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_APP_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9-]+$")
GITHUB_CHECK_NAME = "AI Code Audit"

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
    stripe.max_network_retries = 2


def log_server_issue(context: str, exc: Exception | None = None):
    message = f"[server] {context}"
    if exc is not None:
        message += f": {exc}"
    print(message)


def enrich_access_with_admin_metadata(access: dict) -> dict:
    if not access.get("authenticated") or not access.get("user_id"):
        return access

    current_user = get_supabase_admin_user(str(access["user_id"])) or {}
    app_metadata = current_user.get("app_metadata") or {}
    role = str(app_metadata.get("role") or access.get("role") or "user").lower()
    plan = str(app_metadata.get("plan") or ("admin" if role == "admin" else access.get("plan") or "free")).lower()

    enriched = dict(access)
    enriched["role"] = role
    enriched["plan"] = "admin" if role == "admin" else plan
    enriched["limits"] = get_plan_limits(enriched["plan"])
    enriched["app_metadata"] = app_metadata
    return enriched


def build_access_payload(access: dict) -> dict:
    limits = access.get("limits") or get_plan_limits(access.get("plan") or "free")
    app_metadata = access.get("app_metadata") or {}
    return {
        "authenticated": bool(access.get("authenticated")),
        "user_id": access.get("user_id"),
        "email": access.get("email"),
        "role": access.get("role") or "user",
        "plan": access.get("plan") or "free",
        "limits": limits,
        "billing": {
            "stripe_customer_id": app_metadata.get("stripe_customer_id"),
            "stripe_subscription_id": app_metadata.get("stripe_subscription_id"),
            "subscription_status": app_metadata.get("stripe_subscription_status"),
            "cancel_at_period_end": app_metadata.get("stripe_cancel_at_period_end"),
            "current_period_end": app_metadata.get("stripe_current_period_end"),
            "current_period_end_iso": app_metadata.get("stripe_current_period_end_iso"),
            "can_manage_billing": bool(app_metadata.get("stripe_customer_id")),
        },
        "debug": access.get("debug") or {},
    }


JS_EXAMPLE_FUNCTIONS = {
    "loadSafeExample",
    "loadSuspiciousExample",
    "loadSecretExample",
    "loadEncodedExecutionExample",
}

SOURCE_PATTERNS = [
    r"\binput\s*\(",
    r"\brequest\.",
    r"\brequests?\.(get|post|put|delete|patch|request)\s*\(",
    r"\bform\b",
    r"\bargs\b",
    r"\bjson\b",
    r"\bsys\.argv\b",
    r"\bos\.environ\b",
    r"\bgetenv\s*\(",
    r"\blocalStorage\b",
    r"\bsessionStorage\b",
    r"\bdocument\.cookie\b",
    r"\bwindow\.location\b",
    r"\breq\.(?:body|query|params)\b",
    r"(?<![A-Za-z0-9_$])\$_(?:GET|POST|REQUEST)\b",
    r"\bprocess\.argv\b",
]

DANGEROUS_SINK_KEYS = {
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "child_process",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "marshal.load",
    "yaml.load",
    "dill.loads",
    "__import__",
    "importlib.import_module",
    "requests.get",
    "requests.post",
    "fetch(",
    "open(",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
}

PYTHON_AST_PATTERN_KEYS = {
    "eval(",
    "exec(",
    "open(",
    "os.system",
    "subprocess",
    "__import__",
    "importlib.import_module",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "marshal.load",
    "yaml.load",
    "dill.loads",
    "requests.get",
    "requests.post",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
}

GENERIC_INTENTS = {
    "",
    "scan this",
    "scan this code",
    "scan this file",
    "test",
    "testing",
    "check this",
    "review this",
    "analyze this",
    "scan this public github repo",
    "repo scan",
    "code scan",
}

DEPENDENCY_MANIFEST_FILES = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
    "pyproject.toml": "PyPI",
    "poetry.lock": "PyPI",
    "uv.lock": "PyPI",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "pnpm-lock.yml": "npm",
    "go.mod": "Go",
    "cargo.lock": "crates.io",
    "composer.lock": "Packagist",
    "gemfile.lock": "RubyGems",
}

OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{osv_id}"
OSV_BATCH_SIZE = 100
MAX_PACKAGE_REPUTATION_LOOKUPS = 25
PACKAGE_LOOKUP_CACHE: dict[tuple[str, str], bool | None] = {}
PACKAGE_LOOKUP_LOCK = threading.Lock()

SUSPICIOUS_PACKAGE_TYPOS = {
    "requets": "requests", "requestes": "requests", "python-dateutils": "python-dateutil",
    "beautifulsop4": "beautifulsoup4", "djanga": "django", "flaskk": "flask",
    "numppy": "numpy", "pands": "pandas", "tensorfow": "tensorflow",
    "expresss": "express", "lodahs": "lodash", "loadsh": "lodash",
    "axois": "axios", "react-domm": "react-dom", "chalkk": "chalk",
}

DEPENDENCY_SEVERITY_POINTS = {
    "CRITICAL": 16,
    "HIGH": 12,
    "MEDIUM": 7,
    "MODERATE": 7,
    "LOW": 3,
    "UNKNOWN": 5,
}

TRUSTED_INTERNAL_NETWORK_FUNCTION_NAMES = {
    "download_repo_zip",
    "fetch_json",
    "query_osv_batch",
    "fetch_osv_vulnerability",
}

TRUSTED_INTERNAL_NETWORK_HINTS = (
    "osv",
    "api.osv.dev",
    "codeload.github.com",
    "github.com",
    "certifi.where",
)


BADGE_CACHE_TTL_SECONDS = 600
BADGE_CACHE: dict[str, dict] = {}


def badge_color_from_risk(risk: str, trust_score: int) -> str:
    if risk == "green" or trust_score >= 75:
        return "#22c55e"
    if risk == "yellow" or trust_score >= 60:
        return "#d4aa21"
    return "#ef4444"


def generate_readme_badge(base_url: str, owner: str, repo: str, trust_score: int, risk: str) -> dict:
    base = str(base_url or "").rstrip("/")
    badge_image_url = f"{base}/badge/github/{quote(owner)}/{quote(repo)}.svg" if base else f"/badge/github/{quote(owner)}/{quote(repo)}.svg"
    report_url = f"{base}/?repo_url={quote(f'https://github.com/{owner}/{repo}', safe='')}" if base else "/"
    badge_markdown = f"[![AI Code Audit]({badge_image_url})]({report_url})"
    badge_html = f"<a href='{report_url}'><img src='{badge_image_url}' alt='AI Code Audit badge' /></a>"
    return {
        "badge_image_url": badge_image_url,
        "badge_markdown": badge_markdown,
        "badge_html": badge_html,
    }


def build_badge_svg(label: str, value: str, value_color: str) -> str:
    label = str(label)
    value = str(value)
    left_width = max(150, 22 + len(label) * 13)
    right_width = max(92, 20 + len(value) * 15)
    total_width = left_width + right_width

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="48" role="img" aria-label="{html_escape(label)}: {html_escape(value)}">
  <defs>
    <linearGradient id="badgeLeft" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#ffffff"/>
      <stop offset="100%" stop-color="#faf8ff"/>
    </linearGradient>
    <filter id="shadow" x="-10%" y="-20%" width="120%" height="160%">
      <feDropShadow dx="0" dy="3" stdDeviation="4" flood-color="#111827" flood-opacity="0.12"/>
    </filter>
  </defs>
  <g filter="url(#shadow)">
    <rect x="0.5" y="0.5" rx="10" ry="10" width="{total_width-1}" height="47" fill="url(#badgeLeft)" stroke="rgba(98,76,188,0.12)"/>
    <rect x="{left_width}" y="0.5" rx="10" ry="10" width="{right_width-0.5}" height="47" fill="{html_escape(value_color)}"/>
    <text x="16" y="31" fill="#6d28d9" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif" font-size="17" font-weight="800">◉ {html_escape(label)}</text>
    <text x="{left_width + right_width/2}" y="31" text-anchor="middle" fill="#ffffff" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif" font-size="16" font-weight="800">{html_escape(value)}</text>
  </g>
</svg>"""


def get_plan_limits(plan: str) -> dict:
    normalized = str(plan or "free").lower()

    if normalized == "admin":
        return {
            "line_limit": None,
            "repo_file_limit": None,
            "repo_size_limit_bytes": None,
            "daily_scan_limit": None,
        }

    if normalized == "pro":
        return {
            "line_limit": PRO_LINE_LIMIT,
            "repo_file_limit": PRO_REPO_FILE_LIMIT,
            "repo_size_limit_bytes": PRO_REPO_SIZE_LIMIT_BYTES,
            "daily_scan_limit": PRO_DAILY_SCAN_LIMIT,
        }

    return {
        "line_limit": FREE_LINE_LIMIT,
        "repo_file_limit": FREE_REPO_FILE_LIMIT,
        "repo_size_limit_bytes": FREE_REPO_SIZE_LIMIT_BYTES,
        "daily_scan_limit": FREE_DAILY_SCAN_LIMIT,
    }


def get_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "").strip()

    if not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    return token or None


def normalize_possible_access_token(value) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    if not token:
        return None
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    return token or None


async def extract_request_access_token(request: Request) -> str | None:
    direct_token = normalize_possible_access_token(get_bearer_token(request))
    if direct_token:
        return direct_token

    custom_header_token = normalize_possible_access_token(request.headers.get("x-access-token"))
    if custom_header_token:
        return custom_header_token

    try:
        payload = await request.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        body_token = normalize_possible_access_token(
            payload.get("access_token")
            or payload.get("accessToken")
            or payload.get("token")
        )
        if body_token:
            return body_token

    return None


def fetch_supabase_user(access_token: str) -> tuple[dict | None, bool]:
    if not access_token:
        return None, False

    if SUPABASE_URL and SUPABASE_SECRET_KEY:
        auth_request = urllib.request.Request(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "apikey": SUPABASE_SECRET_KEY,
            },
        )

        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with urllib.request.urlopen(auth_request, timeout=10, context=context) as response:
                return json.loads(response.read().decode("utf-8")), True
        except Exception:
            pass

    return None, False


def get_request_access_context(request: Request, access_token: str | None = None) -> dict:
    access = {
        "authenticated": False,
        "user_id": None,
        "email": None,
        "role": "user",
        "plan": "free",
        "limits": get_plan_limits("free"),
        "debug": {
            "has_supabase_url": bool(SUPABASE_URL),
            "has_supabase_secret_key": bool(SUPABASE_SECRET_KEY),
            "has_bearer_token": False,
            "user_fetch_succeeded": False,
        },
    }

    if not access_token:
        access_token = get_bearer_token(request)
    access_token = normalize_possible_access_token(access_token)
    access["debug"]["has_bearer_token"] = bool(access_token)

    user, verified_with_supabase = fetch_supabase_user(access_token)

    if not user:
        return access

    access["debug"]["user_fetch_succeeded"] = bool(verified_with_supabase)
    app_metadata = user.get("app_metadata") or {}
    role = str(app_metadata.get("role") or "user").lower()
    plan = str(app_metadata.get("plan") or ("admin" if role == "admin" else "free")).lower()

    access.update({
        "authenticated": True,
        "user_id": user.get("id"),
        "email": user.get("email"),
        "role": role,
        "plan": plan,
        "limits": get_plan_limits(plan),
        "app_metadata": app_metadata,
    })

    return enrich_access_with_admin_metadata(access)


def supabase_rest_request(method: str, path: str, payload: dict | list | None = None, query: str = "", prefer: str | None = None) -> dict | list:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return {}

    url = f"{SUPABASE_URL}/rest/v1/{path}"
    if query:
        url = f"{url}?{query}"

    data = None
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if prefer:
        headers["Prefer"] = prefer

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            raw = response.read().decode("utf-8", errors="ignore")
            return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def build_actor_key(request: Request, access: dict) -> str:
    if access.get("user_id"):
        return f"user:{access['user_id']}"

    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    client_host = forwarded_for or (request.client.host if request.client else "unknown")
    fingerprint = client_host
    digest = hashlib.sha256(fingerprint.encode("utf-8", errors="ignore")).hexdigest()
    return f"anon:{digest}"


def persistent_rate_limit_key(bucket_key: str) -> str:
    """Keep raw user IDs and network fingerprints out of the limiter table."""
    digest = hashlib.sha256(f"ai-code-audit-rate-v1\0{bucket_key}".encode("utf-8")).hexdigest()
    return f"v1:{digest}"


def consume_persistent_rate_limit(bucket_key: str, limit: int) -> dict | None:
    """Atomically consume a shared Supabase limit, or return None when unavailable."""
    if not PERSISTENT_RATE_LIMITS_ENABLED or not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return None
    result = supabase_rest_request(
        "POST",
        "rpc/consume_rate_limit",
        payload={
            "p_bucket_key": persistent_rate_limit_key(bucket_key),
            "p_limit": int(limit),
            "p_window_seconds": int(RATE_LIMIT_WINDOW_SECONDS),
        },
    )
    row = result[0] if isinstance(result, list) and result else result if isinstance(result, dict) else None
    if not isinstance(row, dict) or "allowed" not in row:
        return None
    return {
        "allowed": bool(row.get("allowed")),
        "retry_after": max(1, int(row.get("retry_after") or 1)),
        "remaining": max(0, int(row.get("remaining") or 0)),
    }


def raise_rate_limit(retry_after: int) -> None:
    raise HTTPException(
        status_code=429,
        detail="Too many requests. Wait briefly and try again.",
        headers={"Retry-After": str(max(1, int(retry_after)))},
    )


def enforce_rate_limit(request: Request, access: dict, scope: str):
    limits = RATE_LIMITS_PER_MINUTE.get(scope) or RATE_LIMITS_PER_MINUTE["scan"]
    identity_type = "authenticated" if access.get("authenticated") else "anonymous"
    limit = int(limits[identity_type])
    actor_key = build_actor_key(request, access)
    bucket_key = f"{scope}:{actor_key}"
    persistent = consume_persistent_rate_limit(bucket_key, limit)
    if persistent is not None:
        if not persistent["allowed"]:
            raise_rate_limit(persistent["retry_after"])
        request.state.rate_limit_backend = "supabase"
        request.state.rate_limit_remaining = persistent["remaining"]
        return

    request.state.rate_limit_backend = "local-fallback"
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with RATE_LIMIT_LOCK:
        if len(RATE_LIMIT_STATE) > 10_000:
            stale_keys = [
                key for key, timestamps in RATE_LIMIT_STATE.items()
                if not timestamps or timestamps[-1] <= cutoff
            ]
            for key in stale_keys[:5_000]:
                RATE_LIMIT_STATE.pop(key, None)
        recent = [timestamp for timestamp in RATE_LIMIT_STATE.get(bucket_key, []) if timestamp > cutoff]
        if len(recent) >= limit:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - recent[0])))
            RATE_LIMIT_STATE[bucket_key] = recent
            raise_rate_limit(retry_after)
        recent.append(now)
        RATE_LIMIT_STATE[bucket_key] = recent


def private_json(payload: dict | list, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


def require_admin_access(request: Request, scope: str = "feedback") -> dict:
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, scope)
    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Sign in before opening the admin review queue.")
    if str(access.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return access


def sanitize_feedback_text(value: str, limit: int = 500) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(
        r"(?i)\b(?:sk|pk|ghp|github_pat|xox[baprs]|AIza)[-_A-Za-z0-9]{12,}\b",
        "[redacted credential-like value]",
        text,
    )
    return text[:limit]


def get_daily_usage(actor_key: str, usage_day: str) -> dict | None:
    query = urlencode({
        "select": "actor_key,usage_date,scan_count",
        "actor_key": f"eq.{actor_key}",
        "usage_date": f"eq.{usage_day}",
        "limit": "1",
    })
    rows = supabase_rest_request("GET", "scan_usage_daily", query=query)
    if isinstance(rows, list) and rows:
        return rows[0]
    return None


def increment_daily_usage(actor_key: str, usage_day: str, plan: str) -> int | None:
    current = get_daily_usage(actor_key, usage_day) or {}
    current_count = int(current.get("scan_count") or 0)
    new_count = current_count + 1

    payload = [{
        "actor_key": actor_key,
        "usage_date": usage_day,
        "plan": str(plan or "free").lower(),
        "scan_count": new_count,
    }]

    rows = supabase_rest_request(
        "POST",
        "scan_usage_daily",
        payload=payload,
        prefer="resolution=merge-duplicates,return=representation",
    )

    if isinstance(rows, list) and rows:
        return int(rows[0].get("scan_count") or new_count)

    return new_count


def build_limit_result(title: str, summary: str, plan: str, limits: dict) -> dict:
    normalized_plan = str(plan or "free").lower()
    return {
        "risk": "limit",
        "error_type": "limit",
        "limit_title": title,
        "touches": [],
        "flags": [],
        "intent_mismatches": [],
        "behavior_summary": [],
        "summary": summary,
        "trust_score": 0,
        "trust_badge": build_trust_badge(0, "red"),
        "risk_points": 100,
        "score_explanation": {
            "high_risk_findings": 0,
            "review_findings": 0,
            "dependency_vulnerabilities": 0,
            "behavior_categories": 0,
            "intent_mismatches": 0,
        },
        "score_explanation_lines": ["Usage limits affected this result before a full scan could run."],
        "scan_confidence": {"level": "Limited", "lines": ["Usage limits prevented a full scan from completing."]},
        "focused_code_blocks": [],
        "plan_applied": normalized_plan,
        "limits_applied": limits,
    }


def check_and_record_daily_limit(request: Request, access: dict) -> dict | None:
    daily_limit = access.get("limits", {}).get("daily_scan_limit")

    if daily_limit is None:
        return None

    actor_key = build_actor_key(request, access)
    usage_day = date.today().isoformat()
    current = get_daily_usage(actor_key, usage_day) or {}
    current_count = int(current.get("scan_count") or 0)

    if current_count >= daily_limit:
        plan_name = str(access.get("plan") or "free").lower()
        label = "Free" if plan_name == "free" else "Pro"
        return build_limit_result(
            f"{label} daily scan limit reached",
            f"{label} allows up to {daily_limit} scans per day. Try again tomorrow or upgrade for higher limits.",
            access.get("plan", "free"),
            access.get("limits", {}),
        )

    increment_daily_usage(actor_key, usage_day, access.get("plan", "free"))
    return None


def strip_string_literals(text: str) -> str:
    text = re.sub(r"'''[\s\S]*?'''", "", text)
    text = re.sub(r'"""[\s\S]*?"""', "", text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', "", text)
    return text


def strip_comments_and_strings(text: str, *, mask_strings: bool = True) -> str:
    """Mask comments and string literals while preserving line numbers."""
    output = list(text)
    index = 0
    state = "code"
    quote = ""

    def mask(position: int):
        if output[position] not in {"\n", "\r"}:
            output[position] = " "

    while index < len(text):
        char = text[index]
        next_two = text[index:index + 2]
        next_three = text[index:index + 3]

        if state == "line_comment":
            if char in {"\n", "\r"}:
                state = "code"
            else:
                mask(index)
            index += 1
            continue

        if state == "block_comment":
            mask(index)
            if next_two == "*/":
                if index + 1 < len(text):
                    mask(index + 1)
                index += 2
                state = "code"
            else:
                index += 1
            continue

        if state == "string":
            if mask_strings:
                mask(index)
            if char == "\\":
                if mask_strings and index + 1 < len(text):
                    mask(index + 1)
                index += 2
                continue
            if char == quote:
                state = "code"
            index += 1
            continue

        if state == "triple_string":
            if mask_strings:
                mask(index)
            if next_three == quote * 3:
                if mask_strings:
                    for offset in (1, 2):
                        if index + offset < len(text):
                            mask(index + offset)
                index += 3
                state = "code"
            else:
                index += 1
            continue

        # Treat // as a comment delimiter, except when it is the URL separator
        # in values such as https://example.com. Masking the rest of a URL here
        # caused shell download-and-execute pipelines to disappear from analysis.
        if next_two == "//" and (index == 0 or text[index - 1] != ":"):
            mask(index)
            mask(index + 1)
            index += 2
            state = "line_comment"
            continue
        if char == "#":
            mask(index)
            index += 1
            state = "line_comment"
            continue
        if next_two == "/*":
            mask(index)
            mask(index + 1)
            index += 2
            state = "block_comment"
            continue
        if next_three in {"'''", '\"\"\"'}:
            quote = char
            if mask_strings:
                for offset in (0, 1, 2):
                    mask(index + offset)
            index += 3
            state = "triple_string"
            continue
        if char in {"'", '\"', "`"}:
            quote = char
            if mask_strings:
                mask(index)
            index += 1
            state = "string"
            continue

        index += 1

    return "".join(output)


def strip_comments(text: str) -> str:
    return strip_comments_and_strings(text, mask_strings=False)


def mask_non_executable_markup(text: str) -> str:
    """Mask display-only HTML blocks while preserving every line break."""
    pattern = re.compile(
        r"(<(?P<tag>textarea|pre|code)\b[^>]*>)(?P<body>[\s\S]*?)(</(?P=tag)\s*>)",
        re.IGNORECASE,
    )

    def replace(match: re.Match) -> str:
        body = match.group("body")
        masked_body = "".join(char if char in {"\n", "\r"} else " " for char in body)
        return f"{match.group(1)}{masked_body}{match.group(4)}"

    return pattern.sub(replace, text)


def calculate_trust_score_from_points(points: float) -> int:
    score = int(round(100 - points))
    return max(0, min(100, score))


def build_trust_badge(trust_score: int, risk: str) -> dict:
    if risk == "red" or trust_score <= 40:
        return {
            "label": "High Risk",
            "emoji": "🔴",
            "color": "red",
            "message": "This code needs careful review before running."
        }
    elif risk == "yellow" or trust_score <= 70:
        return {
            "label": "Review Carefully",
            "emoji": "🟡",
            "color": "goldenrod",
            "message": "Some caution is warranted before trusting this code."
        }
    return {
        "label": "No Major Risks Found",
        "emoji": "🟢",
        "color": "green",
        "message": "No major risk signals were found in this static scan. This is not a guarantee that the code is safe."
    }


LANGUAGE_LABELS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    ".cpp": "C++", ".c": "C", ".rs": "Rust", ".sh": "Shell",
    ".swift": "Swift", ".kt": "Kotlin", ".sql": "SQL",
    ".html": "HTML", ".css": "CSS", ".json": "JSON",
    ".yaml": "YAML", ".yml": "YAML", ".xml": "XML",
}


def language_from_filename(filename: str) -> str:
    return LANGUAGE_LABELS.get(Path(str(filename or "")).suffix.lower(), "Unknown")


def build_action_verdict(risk: str, trust_score: int, insufficient: bool = False) -> dict:
    """Give users a next action without claiming a static scan proved safety."""
    if insufficient or risk in {"limit", "limited"}:
        return {
            "id": "not_rated",
            "label": "Not enough was scanned",
            "action": "Provide supported code or reduce the scan size, then run the audit again.",
            "tone": "neutral",
        }
    if risk == "red" or trust_score <= 40:
        return {
            "id": "do_not_run",
            "label": "Do not run this yet",
            "action": "Fix the high-risk findings first, then scan the revised code again.",
            "tone": "danger",
        }
    if risk == "yellow" or trust_score <= 70:
        return {
            "id": "review_first",
            "label": "Review before running",
            "action": "Confirm each flagged behavior is expected and apply the relevant fixes.",
            "tone": "warning",
        }
    return {
        "id": "continue_with_review",
        "label": "No major supported risks found",
        "action": "You can continue testing, but still review business logic, permissions, and runtime behavior.",
        "tone": "clear",
    }


def build_code_coverage(code: str, filename: str, semgrep_status: str) -> dict:
    language = language_from_filename(filename)
    if language == "Python":
        depth = "Deep"
        evidence = "Python receives syntax-tree, data-flow, behavior-rule, and local Semgrep analysis."
    elif language in {"JavaScript", "TypeScript"}:
        depth = "Standard"
        evidence = f"{language} receives behavior-rule and local Semgrep analysis; cross-file flows are not followed."
    else:
        depth = "Basic"
        evidence = f"{language} receives supported static pattern checks; language-specific depth may be limited."
    limitations = [
        "Static review only: the submitted code was not executed.",
        "A clean result means no supported signal was found, not that the code was proven safe.",
        "Pasted-code scans do not resolve project dependencies or follow behavior across other files.",
    ]
    if semgrep_status != "complete":
        limitations.append(f"The local Semgrep engine was {semgrep_status}; results rely on the behavior engine.")
    return {
        "scope": "pasted_code",
        "language": language,
        "analysis_depth": depth,
        "summary": evidence,
        "lines_analyzed": len(code.splitlines()),
        "limitations": limitations,
    }


def build_repo_coverage(file_names: list[str], files_available: int, dependency_summary: dict) -> dict:
    languages = sorted({language_from_filename(name) for name in file_names if language_from_filename(name) != "Unknown"})
    manifests = int(dependency_summary.get("manifests_scanned", 0) or 0)
    return {
        "scope": "public_repository",
        "languages": languages,
        "files_analyzed": len(file_names),
        "supported_files_found": int(files_available or 0),
        "dependency_manifests_analyzed": manifests,
        "dependency_ecosystems": ["PyPI", "npm", "Go", "crates.io", "Packagist", "RubyGems"],
        "limitations": [
            "Static review only: repository code was not executed.",
            "Files are analyzed individually; cross-file data flows and runtime configuration are not followed.",
            "Dependency lookup covers common direct manifests and lockfiles, but generated, private-registry, and platform-specific resolution can still differ from production.",
            "A clean result means no supported signal was found, not that the repository was proven safe.",
        ],
    }


def summarize_score_explanation(
    flags: list[dict],
    dependency_findings: list[dict] | None = None,
    behavior_categories: list[str] | None = None,
    intent_mismatches: list[str] | None = None,
) -> dict:
    dependency_findings = dependency_findings or []
    behavior_categories = behavior_categories or []
    intent_mismatches = intent_mismatches or []

    high_risk_count = 0
    review_count = 0

    for flag in flags:
        severity = float(flag.get("severity", 0) or 0)
        if severity >= 18:
            high_risk_count += 1
        elif severity >= 8:
            review_count += 1

    return {
        "high_risk_findings": int(high_risk_count),
        "review_findings": int(review_count),
        "dependency_vulnerabilities": int(len(dependency_findings)),
        "behavior_categories": int(len(behavior_categories)),
        "intent_mismatches": int(len(intent_mismatches)),
    }


def build_score_explanation_lines(
    score_explanation: dict,
    scope_label: str = "repo",
) -> list[str]:
    scope_word = "repo" if str(scope_label or "").lower() == "repo" else "code"

    lines: list[str] = []
    high_risk_findings = int(score_explanation.get("high_risk_findings", 0) or 0)
    review_findings = int(score_explanation.get("review_findings", 0) or 0)
    dependency_vulnerabilities = int(score_explanation.get("dependency_vulnerabilities", 0) or 0)
    behavior_categories = int(score_explanation.get("behavior_categories", 0) or 0)
    intent_mismatches = int(score_explanation.get("intent_mismatches", 0) or 0)

    if high_risk_findings:
        noun = "finding" if high_risk_findings == 1 else "findings"
        lines.append(f"{high_risk_findings} high-risk {noun} influenced this {scope_word} score.")
    if review_findings:
        noun = "finding" if review_findings == 1 else "findings"
        lines.append(f"{review_findings} moderate-risk {noun} also contributed to the score.")
    if dependency_vulnerabilities:
        noun = "dependency vulnerability" if dependency_vulnerabilities == 1 else "dependency vulnerabilities"
        lines.append(f"{dependency_vulnerabilities} {noun} were detected.")
    if behavior_categories:
        noun = "behavior category" if behavior_categories == 1 else "behavior categories"
        lines.append(f"{behavior_categories} {noun} were triggered during analysis.")
    if intent_mismatches:
        noun = "intent mismatch" if intent_mismatches == 1 else "intent mismatches"
        lines.append(f"{intent_mismatches} {noun} affected the final result.")

    if not lines:
        lines.append(f"No major risk signals were detected in this {scope_word} scan.")

    return lines


def build_scan_confidence(
    scope_label: str,
    *,
    files_scanned_count: int = 0,
    files_total: int = 0,
    code_line_count: int = 0,
    line_limit_applied: int | None = None,
    dependency_summary: dict | None = None,
    scan_error: str | None = None,
    was_limited: bool = False,
) -> dict:
    dependency_summary = dependency_summary or {}
    normalized_scope = str(scope_label or "repo").lower()

    level = "High"
    lines: list[str] = []

    if normalized_scope == "repo":
        files_scanned_count = int(files_scanned_count or 0)
        files_total = int(files_total or files_scanned_count or 0)
        dependencies_queried = int(dependency_summary.get("dependencies_queried", 0) or 0)
        dependencies_skipped_count = int(dependency_summary.get("dependencies_skipped_count", 0) or 0)

        if files_total and files_scanned_count and files_total != files_scanned_count:
            lines.append(f"{files_scanned_count} of {files_total} files were analyzed.")
        else:
            noun = "file" if files_scanned_count == 1 else "files"
            lines.append(f"{files_scanned_count} {noun} were analyzed.")

        if scan_error or dependency_summary.get("scan_error"):
            lines.append("Dependency scan was only partially completed.")
        elif dependencies_queried > 0:
            lines.append("Dependency scan completed.")
        else:
            lines.append("No dependency manifests with resolvable versions were analyzed.")

        if dependencies_skipped_count > 0:
            noun = "entry was" if dependencies_skipped_count == 1 else "entries were"
            lines.append(f"{dependencies_skipped_count} dependency {noun} skipped.")

        if was_limited or files_scanned_count == 0:
            level = "Limited"
        elif files_total > files_scanned_count:
            level = "Medium"
            lines.append("Only part of the repo could be analyzed.")
        elif scan_error or dependency_summary.get("scan_error") or dependencies_skipped_count > 0:
            level = "Medium"
            lines.append("Some dependency analysis was incomplete, so confidence is moderate.")
        else:
            level = "High"
            lines.append("All supported files were analyzed.")
    else:
        code_line_count = int(code_line_count or 0)
        noun = "line" if code_line_count == 1 else "lines"
        lines.append(f"{code_line_count} {noun} of code were analyzed.")

        if line_limit_applied is not None and code_line_count >= int(line_limit_applied):
            lines.append(f"This scan used the current line limit of {line_limit_applied} lines.")

        if was_limited or code_line_count == 0:
            level = "Limited"
        elif line_limit_applied is not None and code_line_count >= int(line_limit_applied):
            level = "Medium"
            lines.append("The scan likely covered only part of the full file.")
        elif code_line_count >= 50:
            level = "High"
            lines.append("The scan covered enough code for a high-confidence result.")
        elif code_line_count >= 15:
            level = "Medium"
            lines.append("The scan covered a moderate amount of code.")
        else:
            level = "Limited"
            lines.append("The scan covered only a small amount of code.")

    return {
        "level": level,
        "lines": lines,
    }


def risk_from_points(points: float) -> str:
    if points >= 35:
        return "red"
    if points >= 10:
        return "yellow"
    return "green"


def aggregate_flag_risk_points(flags: list[dict]) -> float:
    """Avoid treating repeated instances of one behavior as unrelated risks."""
    severities_by_pattern: dict[str, list[float]] = {}
    for flag in flags:
        pattern = str(flag.get("pattern") or flag.get("type") or "finding")
        severities_by_pattern.setdefault(pattern, []).append(
            max(0.0, float(flag.get("severity", 0) or 0))
        )

    total = 0.0
    for severities in severities_by_pattern.values():
        ordered = sorted(severities, reverse=True)
        if not ordered:
            continue
        total += ordered[0]
        total += sum(ordered[1:4]) * 0.25
    return round(total, 2)


def file_weight_for_repo(file_name: str) -> float:
    lower = file_name.lower()

    if "/tests/" in lower or lower.endswith("_test.py") or "/test/" in lower:
        return 0.35
    if "/examples/" in lower or "/example/" in lower:
        return 0.45
    if "/templates/" in lower:
        return 0.5
    if "/docs/" in lower or lower.startswith("docs/"):
        return 0.4
    if "/.github/workflows/" in lower or "/workflows/" in lower:
        return 0.3
    if lower.endswith(".yml") or lower.endswith(".yaml"):
        return 0.4
    if lower.endswith(".html"):
        return 0.5
    return 1.0


def weighted_repository_file_points(file_name: str, risk_points: float) -> float:
    """Down-rank non-production examples without allowing them to look harmless."""
    weight = file_weight_for_repo(file_name)
    weighted = max(0.0, float(risk_points or 0)) * weight
    if weight <= 0.35:
        return round(min(25.0, weighted), 2)
    if weight < 1.0:
        return round(min(30.0, weighted), 2)
    return round(weighted, 2)


def dependency_file_weight(file_name: str) -> float:
    lower = file_name.lower()

    if "/tests/" in lower or "/test/" in lower:
        return 0.35
    if "/examples/" in lower or "/example/" in lower:
        return 0.4
    if "/demo/" in lower or "/demos/" in lower:
        return 0.4
    if "/sample/" in lower or "/samples/" in lower:
        return 0.45
    if "/fixture/" in lower or "/fixtures/" in lower:
        return 0.35
    if "/docs/" in lower:
        return 0.3
    if "/data/exploits/" in lower or "/exploit/" in lower or "/exploits/" in lower:
        return 0.25
    return 1.0


def calculate_repository_risk_points(
    weighted_file_points: list[float],
    dependency_risk_points: float = 0.0,
) -> float:
    normalized_points = [max(0.0, float(value)) for value in weighted_file_points]
    dependency_points = max(0.0, float(dependency_risk_points or 0))
    if not normalized_points:
        return round(min(100.0, dependency_points), 2)

    average_file_points = sum(normalized_points) / len(normalized_points)
    strongest_file_signal = max(normalized_points)
    return round(min(100.0, max(average_file_points, strongest_file_signal) + dependency_points), 2)


def parse_github_repo(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    parts = [p for p in parsed.path.split("/") if p]

    if parsed.netloc not in {"github.com", "www.github.com"} or len(parts) < 2:
        raise ValueError("Please provide a valid public GitHub repository URL.")

    owner = parts[0]
    repo = parts[1].replace(".git", "")
    return owner, repo


def read_bounded_response(response, max_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError):
            declared_length = 0
        if declared_length > max_bytes:
            raise ValueError("Repository archive exceeds the server download limit.")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("Repository archive exceeds the server download limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def download_repo_zip(owner: str, repo: str) -> bytes:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    candidate_branches: list[str] = []

    try:
        metadata_request = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "AI-Code-Audit/1.0",
            },
        )
        with urllib.request.urlopen(metadata_request, timeout=15, context=ssl_context) as response:
            metadata = json.loads(response.read().decode("utf-8", errors="ignore"))
            default_branch = str(metadata.get("default_branch") or "").strip()
            if default_branch:
                candidate_branches.append(default_branch)
    except Exception:
        pass

    for fallback in ("main", "master"):
        if fallback not in candidate_branches:
            candidate_branches.append(fallback)

    last_error = None
    for branch in candidate_branches:
        url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{quote(branch, safe='')}"
        try:
            zip_request = urllib.request.Request(url, headers={"User-Agent": "AI-Code-Audit/1.0"})
            with urllib.request.urlopen(zip_request, timeout=30, context=ssl_context) as response:
                return read_bounded_response(response, MAX_REPOSITORY_ARCHIVE_BYTES)
        except Exception as exc:
            last_error = exc

    raise ValueError(f"Could not download repository zip. {last_error}")


def is_supported_code_file(filename: str) -> bool:
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in SUPPORTED_CODE_EXTENSIONS)


def is_dependency_manifest(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(name) for name in DEPENDENCY_MANIFEST_FILES)


def explain_flag(pattern: str, flag_type: str) -> str:
    explanations = {
        "eval(": "This uses eval(), which executes dynamically constructed code. If untrusted input reaches it, that can allow arbitrary code execution.",
        "exec(": "This uses exec(), which can run dynamically generated code. That is risky unless the input is strictly controlled and trusted.",
        "os.system": "This runs shell commands on the host machine. If user input is passed into the command, it can lead to command injection.",
        "subprocess": "This launches system processes. That can be legitimate, but it should be reviewed carefully to make sure inputs are sanitized.",
        "child_process": "This starts system-level processes in JavaScript environments. Review whether any user-controlled values can reach the command.",
        "requests.post": "This sends outbound HTTP POST requests. Make sure the destination and transmitted data are expected.",
        "requests.get": "This fetches data over HTTP. That can be normal, but confirm the destination is expected and the download is safe to trust.",
        "socket": "This opens low-level network communication. That can be normal, but unexpected socket usage deserves review.",
        "fetch(": "This makes a network request. Confirm the destination is expected and no sensitive data is being sent.",
        "open(": "This reads or writes local files. Confirm file access matches the stated purpose of the code.",
        "base64": "This uses Base64 encoding. That is not dangerous by itself, but it is sometimes used to obscure payloads or secrets.",
        "__import__": "This dynamically imports a module by name at runtime. That can be legitimate, but it can also hide what code will actually run.",
        "importlib.import_module": "This dynamically imports a module at runtime. Review where the module name comes from and whether it is fully trusted.",
        "pickle.loads": "This deserializes Python pickle data. Untrusted pickle data can execute arbitrary code during loading.",
        "pickle.load": "This loads Python pickle data from a file-like object. Untrusted pickle data can be dangerous because loading it may execute code.",
        "marshal.loads": "This loads serialized Python bytecode-like data. It is not safe to use with untrusted input and can be used to hide payloads.",
        "marshal.load": "This loads serialized Python bytecode-like data from a stream. It is not safe with untrusted input.",
        "yaml.load": "This loads YAML data. Unsafe YAML loading can sometimes instantiate unexpected objects, depending on configuration.",
        "dill.loads": "This deserializes dill data. Like pickle, loading untrusted serialized objects can be unsafe.",
        "shelve.open": "This opens a persistent object store backed by pickle-like serialization. Review whether untrusted data could be loaded from it.",
        "urllib.request.urlopen": "This opens a network resource. Confirm the destination is expected and the returned content is not blindly trusted.",
        "urllib.request.urlretrieve": "This downloads a remote file. That deserves review, especially if the file is later executed or loaded.",
        "urllib.request.Request": "This constructs an outbound HTTP request. Confirm the destination and headers are expected.",
        "download helper": "This references command-line download tooling like curl or wget. That can be normal, but it deserves scrutiny if paired with execution.",
        "bytes.fromhex": "This decodes hex-encoded data. That is sometimes used to hide payloads or scripts from casual review.",
        "obfuscated_execution": "This appears to combine encoded or hidden payloads with code execution. That is a strong sign the code may be trying to conceal behavior.",
        "download_execute_chain": "This appears to download remote content and then execute it. That is a strong risk signal because the downloaded content may not be trustworthy.",
        "high_entropy_blob": "This file contains a long encoded-looking string. That may be harmless data, but it is also a common way to hide payloads or secrets.",
        "chr_chain": "This builds text using repeated chr() calls. That can be used to obscure code or command strings.",
        r"AKIA[0-9A-Z]{16}": "This looks like an AWS access key. If real, it may allow unauthorized access to cloud resources.",
        r"-----BEGIN PRIVATE KEY-----": "This appears to contain a private key. Private keys should never be exposed in source code.",
        r"sk-[A-Za-z0-9]{20,}": "This looks like an API secret key. If committed publicly, it may already be compromised.",
        r"AIza[0-9A-Za-z\-_]{35}": "This looks like a Google API key. Review whether it is safe to expose and whether restrictions are in place.",
    }

    return explanations.get(
        pattern,
        "This item deserves review because it may introduce behavior or exposure that is not obvious from the stated intent."
    )


def build_finding_guidance(pattern: str) -> dict:
    if pattern in {"eval(", "exec(", "obfuscated_execution"}:
        return {
            "why_risky": "Executing generated or decoded code can let hidden behavior run immediately. If any part of that input is untrusted, this may become arbitrary code execution.",
            "what_to_check": "Trace where the executed string comes from. Check for user input, HTTP responses, decoded payloads, string concatenation, or environment-controlled values.",
            "when_legitimate": "This can be legitimate in tightly controlled internal tooling, code sandboxes, or metaprogramming systems with strong input controls.",
            "suggested_fix": "Avoid dynamic code execution when possible. Prefer explicit function dispatch, allowlisted commands, or parsing structured data instead of executing strings.",
        }

    if pattern in {"os.system", "subprocess", "child_process"}:
        return {
            "why_risky": "Running shell or system commands increases the chance of command injection, privilege abuse, or unexpected system changes.",
            "what_to_check": "Inspect how command arguments are built. Look for input(), request data, argv, string interpolation, .format(), concatenation, or environment variables reaching the command.",
            "when_legitimate": "This is often legitimate in deployment scripts, developer tooling, and internal automation where all inputs are fixed and tightly controlled.",
            "suggested_fix": "Prefer library APIs over shell calls. If commands are required, pass explicit argument lists, validate inputs strictly, and avoid shell=True-style execution patterns.",
        }

    if pattern in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "yaml.load", "dill.loads", "shelve.open"}:
        return {
            "why_risky": "Unsafe deserialization can load attacker-controlled objects or hidden instructions, especially when data comes from files, caches, or network responses.",
            "what_to_check": "Verify the data source. Determine whether the serialized content is local and trusted, or whether it could come from uploads, downloads, caches, or third-party systems.",
            "when_legitimate": "This can be acceptable for trusted local data generated by the same application in a controlled environment.",
            "suggested_fix": "Use safer formats when possible, such as JSON or explicit schemas. If deserialization is required, only load from trusted sources and use safer loader options.",
        }

    if pattern in {"__import__", "importlib.import_module"}:
        return {
            "why_risky": "Dynamic imports can hide what code actually runs and can allow untrusted values to control which modules are loaded.",
            "what_to_check": "Look at where the module name comes from and whether it can be influenced by request data, config, plugins, or user input.",
            "when_legitimate": "This is common in plugin systems, extension frameworks, and modular applications that intentionally load known components dynamically.",
            "suggested_fix": "Restrict imports to a known allowlist of modules or plugin identifiers instead of passing arbitrary strings into runtime import functions.",
        }

    if pattern in {"requests.post", "requests.get", "fetch(", "socket", "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request", "download helper", "download_execute_chain"}:
        return {
            "why_risky": "Outbound requests or downloads can move data off the machine, retrieve untrusted content, or introduce behavior that was not obvious from the code’s stated purpose.",
            "what_to_check": "Review the destination, the data being sent, authentication headers, and whether downloaded content is later executed, parsed unsafely, or written to disk.",
            "when_legitimate": "This is normal for API clients, web apps, software updaters, and tools that intentionally communicate over the network.",
            "suggested_fix": "Document expected network destinations clearly, validate downloaded content, avoid executing remote content directly, and restrict data leaving the system.",
        }

    if pattern in {"open("}:
        return {
            "why_risky": "File access can expose local data, overwrite important files, or create behavior that the user did not expect.",
            "what_to_check": "Check which paths are opened, whether paths are user-controlled, whether the code reads secrets, and whether writes could modify sensitive files.",
            "when_legitimate": "Local file access is common in CLI tools, scripts, exports, and applications that intentionally read or save data.",
            "suggested_fix": "Validate file paths, constrain write locations, and make file operations explicit so the user understands what will be read or changed.",
        }

    if pattern in {"base64", "bytes.fromhex", "high_entropy_blob", "chr_chain"}:
        return {
            "why_risky": "Encoding and obfuscation can be used to conceal payloads, secrets, or behavior from casual review.",
            "what_to_check": "See whether the decoded value is later executed, imported, sent over the network, or written to a file. Also check whether it hides credentials or scripts.",
            "when_legitimate": "Encoding is normal for binary transport, embedded assets, and protocol handling where the decoded content is expected and documented.",
            "suggested_fix": "If the encoded content is legitimate, keep it well documented. Avoid decoding content and then executing it, and avoid hiding critical behavior inside encoded blobs.",
        }

    if pattern in {
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN PRIVATE KEY-----",
        r"sk-[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z\-_]{35}",
    }:
        return {
            "why_risky": "Secrets in source code can be copied, leaked, or abused by anyone who gains access to the file or repository.",
            "what_to_check": "Determine whether the secret is real, still active, already committed publicly, or duplicated elsewhere in the project history.",
            "when_legitimate": "Real secrets generally should not live in source files. The main exception is clearly fake demo data used for examples or tests.",
            "suggested_fix": "Rotate the secret if it may be real, remove it from source code, and load credentials from environment variables or a dedicated secrets manager.",
        }

    if pattern == "environment_secret_access":
        return {
            "why_risky": "Environment variables commonly contain live credentials. Reading one is sensitive even when the secret is not hard-coded.",
            "what_to_check": "Trace every use of the resulting variable and confirm it is only sent to the intended trusted service.",
            "when_legitimate": "Applications routinely read credentials from environment variables to authenticate with an expected provider.",
            "suggested_fix": "Keep the credential server-side, use the narrowest required scope, and never log or forward it to an unrelated destination.",
        }

    if pattern == "secret_exfiltration_chain":
        return {
            "why_risky": "A credential-derived value appears in an outbound request and could leave the trusted environment.",
            "what_to_check": "Verify the destination, request body, headers, redirects, and whether the credential is required by the stated task.",
            "when_legitimate": "This can be legitimate only when the credential is intentionally sent to its own trusted authentication service.",
            "suggested_fix": "Remove the credential from the outbound payload. If authentication is required, send it only to the approved provider using the expected authorization mechanism.",
        }

    if pattern == "credential_authentication":
        return {
            "why_risky": "Credentials should only be sent to the service they are intended to authenticate with.",
            "what_to_check": "Confirm the HTTPS destination belongs to the expected provider and that redirects cannot forward the authorization header elsewhere.",
            "when_legitimate": "Using a server-side environment credential in an HTTPS authorization header is normal for authenticated API clients.",
            "suggested_fix": "Keep the credential server-side, restrict it to the expected provider, and use the provider's documented authentication format.",
        }

    return {
        "why_risky": "This finding may introduce behavior or exposure that deserves manual review before the code is trusted.",
        "what_to_check": "Inspect the surrounding lines, the inputs reaching this behavior, and whether the behavior matches the stated purpose of the code.",
        "when_legitimate": "This may be acceptable when the code is intentionally designed for this behavior and the inputs are controlled.",
        "suggested_fix": "Reduce unnecessary complexity, document intentional risky behavior, and prefer safer alternatives where possible.",
    }


def make_flag(
    line: int,
    flag_type: str,
    pattern: str,
    message: str,
    severity: float,
    explanation: str,
) -> dict:
    guidance = build_finding_guidance(pattern)
    return {
        "line": line,
        "type": flag_type,
        "pattern": pattern,
        "message": message,
        "severity": round(max(0, float(severity)), 2),
        "explanation": explanation,
        "why_risky": guidance["why_risky"],
        "what_to_check": guidance["what_to_check"],
        "when_legitimate": guidance["when_legitimate"],
        "suggested_fix": guidance["suggested_fix"],
    }


def extract_scannable_lines(code: str) -> list[tuple[int, str]]:
    """
    Returns only the lines that should count toward scanning.
    This skips:
    - scanner pattern definition blocks
    - explanation dictionary blocks
    - demo/example JS functions in index.html
    - internal dependency scoring / config blocks
    """
    lines = code.splitlines()
    scannable_lines = []

    inside_suspicious_block = False
    inside_secret_block = False
    inside_explanations_block = False
    inside_guidance_block = False
    inside_dependency_points_block = False
    inside_manifest_files_block = False
    inside_js_example_function = False
    inside_scanner_explanation_function = False
    js_brace_depth = 0
    guidance_brace_depth = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if inside_scanner_explanation_function:
            if re.match(r"^(?:async\s+)?def\s+", line):
                inside_scanner_explanation_function = False
            else:
                continue

        if re.match(r"^def\s+(?:explain_flag|build_finding_guidance)\s*\(", line):
            inside_scanner_explanation_function = True
            continue

        if not inside_js_example_function:
            for function_name in JS_EXAMPLE_FUNCTIONS:
                if stripped.startswith(f"function {function_name}("):
                    inside_js_example_function = True
                    js_brace_depth = line.count("{") - line.count("}")
                    if js_brace_depth <= 0:
                        inside_js_example_function = False
                        js_brace_depth = 0
                    break
            if inside_js_example_function:
                continue

        if inside_js_example_function:
            js_brace_depth += line.count("{") - line.count("}")
            if js_brace_depth <= 0:
                inside_js_example_function = False
                js_brace_depth = 0
            continue

        if stripped.startswith("SUSPICIOUS_PATTERNS") and "[" in stripped:
            inside_suspicious_block = True
            continue

        if stripped.startswith("SECRET_PATTERNS") and "[" in stripped:
            inside_secret_block = True
            continue

        if stripped.startswith("DEPENDENCY_SEVERITY_POINTS") and "{" in stripped:
            inside_dependency_points_block = True
            continue

        if stripped.startswith("DEPENDENCY_MANIFEST_FILES") and "{" in stripped:
            inside_manifest_files_block = True
            continue

        if stripped.startswith("explanations = {"):
            inside_explanations_block = True
            continue

        if stripped.startswith("return {") and "why_risky" in stripped:
            inside_guidance_block = True
            guidance_brace_depth = line.count("{") - line.count("}")
            continue

        if inside_suspicious_block:
            if stripped == "]" or stripped == "],":
                inside_suspicious_block = False
            continue

        if inside_secret_block:
            if stripped == "]" or stripped == "],":
                inside_secret_block = False
            continue

        if inside_dependency_points_block:
            if stripped == "}":
                inside_dependency_points_block = False
            continue

        if inside_manifest_files_block:
            if stripped == "}":
                inside_manifest_files_block = False
            continue

        if inside_explanations_block:
            if stripped == "}":
                inside_explanations_block = False
            continue

        if inside_guidance_block:
            guidance_brace_depth += line.count("{") - line.count("}")
            if guidance_brace_depth <= 0:
                inside_guidance_block = False
                guidance_brace_depth = 0
            continue

        scannable_lines.append((line_number, line))

    return scannable_lines


def line_contains_source(line: str) -> bool:
    return any(re.search(pattern, line, re.IGNORECASE) for pattern in SOURCE_PATTERNS)


def extract_assigned_variable(line: str) -> str | None:
    match = re.match(
        r"\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)"
        r"(?:\s*:\s*[A-Za-z_$][A-Za-z0-9_$<>,.\[\]| &?]*)?\s*=",
        line,
    )
    if match:
        return match.group(1)
    return None


def contains_variable_reference(text: str, variable_name: str) -> bool:
    """Match Python, JavaScript, and PHP identifiers without partial matches."""
    return bool(re.search(
        rf"(?<![A-Za-z0-9_$]){re.escape(variable_name)}(?![A-Za-z0-9_$])",
        text,
        re.IGNORECASE,
    ))


def build_taint_map(scannable_lines: list[tuple[int, str]]) -> dict[str, str]:
    tainted: dict[str, str] = {}

    for _, line in scannable_lines:
        line_lower = line.lower()
        variable = extract_assigned_variable(line)

        if not variable:
            continue

        if line_contains_source(line_lower):
            tainted[variable.lower()] = "source"
            continue

        for known_var in list(tainted.keys()):
            if contains_variable_reference(line_lower, known_var):
                tainted[variable.lower()] = "propagated"
                break

    return tainted


def find_environment_secret_sources(
    scannable_lines: list[tuple[int, str]],
) -> tuple[dict[str, int], list[dict]]:
    secret_variables: dict[str, int] = {}
    secret_flags: list[dict] = []

    for line_number, line in scannable_lines:
        for pattern in ENV_SECRET_ASSIGNMENT_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            variable_name = match.group(1)
            env_name = next((group for group in match.groups()[1:] if group), "")
            if not SENSITIVE_ENV_NAME_PATTERN.search(env_name):
                continue

            secret_variables[variable_name] = line_number
            secret_flags.append(make_flag(
                line=line_number,
                flag_type="secret_source",
                pattern="environment_secret_access",
                message=f"Sensitive environment credential accessed: {env_name}",
                severity=25,
                explanation=(
                    "The code reads a credential from the environment. That can be legitimate, "
                    "but it becomes high risk when the value is transmitted, logged, written, or executed."
                ),
            ))
            break

    return secret_variables, secret_flags


def call_expression_is_complete(text: str, opening_index: int) -> bool:
    """Return True once the opening parenthesis has a matching close.

    This deliberately ignores parentheses inside common quoted string forms so
    multiline URLs and payload strings do not break the lightweight scanner.
    """
    depth = 0
    quote = ""
    escaped = False
    index = opening_index

    while index < len(text):
        if quote:
            if escaped:
                escaped = False
                index += 1
                continue
            if text[index] == "\\":
                escaped = True
                index += 1
                continue
            if text.startswith(quote, index):
                index += len(quote)
                quote = ""
                continue
            index += 1
            continue

        if text.startswith("'''", index) or text.startswith('\"\"\"', index):
            quote = text[index:index + 3]
            index += 3
            continue
        if text[index] in {"'", '\"', "`"}:
            quote = text[index]
            index += 1
            continue
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return True
        index += 1

    return False


def add_secret_flow_heuristics(
    scannable_lines: list[tuple[int, str]],
    secret_variables: dict[str, int],
    *,
    authentication_expected: bool = False,
) -> list[dict]:
    if not secret_variables:
        return []

    network_sink = re.compile(
        r"requests\.(?:post|put|patch|request)\s*\(|(?<![\w.])fetch\s*\(|"
        r"axios\.(?:post|put|patch|request)\s*\(|urllib\.request\.(?:urlopen|Request)\s*\(",
        re.IGNORECASE,
    )
    findings: list[dict] = []

    for line_index, (line_number, line) in enumerate(scannable_lines):
        sink_match = network_sink.search(line)
        if not sink_match:
            continue

        call_text = line
        opening_index = call_text.find("(", sink_match.start())
        next_index = line_index + 1
        while (
            opening_index >= 0
            and not call_expression_is_complete(call_text, opening_index)
            and next_index < len(scannable_lines)
            and next_index <= line_index + 24
        ):
            call_text += "\n" + scannable_lines[next_index][1]
            next_index += 1

        exposed = [
            name for name in secret_variables
            if re.search(rf"\b{re.escape(name)}\b", call_text)
        ]
        if not exposed:
            continue

        uses_https = bool(re.search(r"['\"]https://[^'\"]+['\"]", call_text, re.IGNORECASE))
        uses_auth_header = bool(re.search(r"\b(?:authorization|bearer|headers?)\b", call_text, re.IGNORECASE))
        if authentication_expected and uses_https and uses_auth_header:
            findings.append(make_flag(
                line=line_number,
                flag_type="credential_use",
                pattern="credential_authentication",
                message="Environment credential used for expected API authentication",
                severity=3,
                explanation=(
                    f"This HTTPS request uses environment-derived credential data ({', '.join(exposed)}) "
                    "in an authentication context that matches the stated intent. Verify the destination belongs to the intended provider."
                ),
            ))
            continue

        findings.append(make_flag(
            line=line_number,
            flag_type="secret_exfiltration",
            pattern="secret_exfiltration_chain",
            message="Sensitive credential may be sent to an external service",
            severity=25,
            explanation=(
                f"This network request includes environment-derived credential data ({', '.join(exposed)}). "
                "That behavior is high risk unless the destination and transmission are explicitly expected."
            ),
        ))

    return findings


def get_call_arguments(line: str, display_key: str) -> str:
    patterns = {
        "eval(": r"eval\s*\((.*)\)",
        "exec(": r"exec\s*\((.*)\)",
        "os.system": r"os\.system\s*\((.*)\)",
        "subprocess": r"subprocess(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*\((.*)\)",
        "child_process": r"child_process(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*\((.*)\)",
        "requests.post": r"requests\.post\s*\((.*)\)",
        "requests.get": r"requests\.get\s*\((.*)\)",
        "fetch(": r"fetch\s*\((.*)\)",
        "open(": r"open\s*\((.*)\)",
        "__import__": r"__import__\s*\((.*)\)",
        "importlib.import_module": r"importlib\.import_module\s*\((.*)\)",
        "pickle.loads": r"pickle\.loads\s*\((.*)\)",
        "pickle.load": r"pickle\.load\s*\((.*)\)",
        "marshal.loads": r"marshal\.loads\s*\((.*)\)",
        "marshal.load": r"marshal\.load\s*\((.*)\)",
        "yaml.load": r"yaml\.load\s*\((.*)\)",
        "dill.loads": r"dill\.loads\s*\((.*)\)",
        "urllib.request.urlopen": r"urllib\.request\.urlopen\s*\((.*)\)",
        "urllib.request.urlretrieve": r"urllib\.request\.urlretrieve\s*\((.*)\)",
        "urllib.request.Request": r"urllib\.request\.Request\s*\((.*)\)",
    }

    pattern = patterns.get(display_key)
    if not pattern:
        return ""

    match = re.search(pattern, line)
    if not match:
        return ""

    return match.group(1).strip()


def is_literal_argument_text(args: str) -> bool:
    return bool(args and re.fullmatch(r'\s*["\'].*["\']\s*', args))


def first_top_level_argument(args: str) -> str:
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(args):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            return args[:index].strip()
    return args.strip()


def line_is_trusted_internal_network_usage(line: str) -> bool:
    lowered = line.lower()
    return any(hint in lowered for hint in TRUSTED_INTERNAL_NETWORK_HINTS)


def assess_sink_context(
    display_key: str,
    line: str,
    tainted_vars: dict[str, str],
) -> tuple[float, str | None]:
    if display_key not in DANGEROUS_SINK_KEYS:
        return 0.0, None

    line_lower = line.lower()
    args = get_call_arguments(line, display_key)
    primary_arg = first_top_level_argument(args)
    args_lower = primary_arg.lower()

    context_notes: list[str] = []
    boost = 0.0

    dynamic_markers = [
        "f\"",
        "f'",
        ".format(",
        "%",
        "+",
        "[",
        "]",
        "{",
        "}",
    ]

    if primary_arg and not is_literal_argument_text(primary_arg):
        boost += 4
        context_notes.append("It appears to be called with a dynamic value instead of a fixed literal.")

    if any(marker in primary_arg for marker in dynamic_markers):
        boost += 4
        context_notes.append("The argument appears to be dynamically constructed.")

    # Only inputs reaching the sink argument should raise its severity. A
    # minified line may contain unrelated response handling or form reads after
    # a fixed, same-origin fetch call.
    if line_contains_source(args_lower):
        boost += 12
        context_notes.append("User-controlled or external input appears near this sink, which raises the risk significantly.")

    for variable_name in tainted_vars:
        if contains_variable_reference(args_lower, variable_name):
            boost += 12
            context_notes.append(f"The argument appears to use a variable derived from external input ({variable_name}).")
            break

    if primary_arg and is_literal_argument_text(primary_arg) and boost == 0:
        if display_key == "os.system":
            boost -= 8
        elif display_key in {"eval(", "exec("}:
            boost -= 2
        elif display_key in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads"}:
            boost -= 1
        else:
            boost -= 4
        context_notes.append("This appears to use a fixed literal value, which lowers the risk somewhat.")

    if not context_notes:
        return boost, None

    return boost, " ".join(context_notes)


def find_first_matching_line(scannable_lines: list[tuple[int, str]], pattern: str) -> int:
    compiled = re.compile(pattern, re.IGNORECASE)
    for line_number, line in scannable_lines:
        if compiled.search(line):
            return line_number
    return 1


def find_dataflow_chain_line(
    scannable_lines: list[tuple[int, str]],
    source_pattern: str,
    sink_pattern: str,
) -> int | None:
    source_regex = re.compile(source_pattern, re.IGNORECASE)
    sink_regex = re.compile(sink_pattern, re.IGNORECASE)
    source_variables: set[str] = set()

    for line_number, line in scannable_lines:
        cleaned_line = strip_comments_and_strings(line)
        has_source = bool(source_regex.search(cleaned_line))
        has_sink = bool(sink_regex.search(cleaned_line))

        if has_source and has_sink:
            return line_number

        assigned_variable = extract_assigned_variable(cleaned_line)
        references_source = any(
            contains_variable_reference(cleaned_line, variable_name)
            for variable_name in source_variables
        )
        if assigned_variable and (has_source or references_source):
            source_variables.add(assigned_variable)

        if has_sink and references_source:
            return line_number

    return None


def add_multi_signal_heuristics(
    scannable_lines: list[tuple[int, str]],
    python_tree: ast.AST | None = None,
) -> list[dict]:
    heuristic_flags: list[dict] = []
    joined_code = "\n".join(line for _, line in scannable_lines)
    cleaned_code = strip_comments_and_strings(joined_code).lower()

    obfuscated_execution_line = find_dataflow_chain_line(
        scannable_lines,
        r"base64\.(?:b64decode|standard_b64decode|urlsafe_b64decode)\s*\(|bytes\.fromhex\s*\(|\batob\s*\(|\bBuffer\.from\s*\(",
        r"(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(|\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(",
    )
    download_execute_line = find_dataflow_chain_line(
        scannable_lines,
        r"requests\.(?:get|post)\s*\(|urllib\.request\.(?:urlopen|urlretrieve|Request)\s*\(|(?<![\w.])fetch\s*\(",
        r"\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|\bchild_process\.(?:exec|execFile|spawn|fork)\s*\(|(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(",
    )
    direct_download_pipeline = False
    if download_execute_line is None:
        for line_number, line in scannable_lines:
            cleaned_line = strip_comments_and_strings(line)
            if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh|python|node)\b", cleaned_line, re.IGNORECASE):
                download_execute_line = line_number
                direct_download_pipeline = True
                break

    has_long_base64_blob = bool(re.search(r"[A-Za-z0-9+/]{180,}={0,2}", joined_code))
    has_chr_chain = len(re.findall(r"\bchr\s*\(", cleaned_code)) >= 4

    guarded_literal_execution = False
    if python_tree is not None:
        for node in ast.walk(python_tree):
            if not isinstance(node, ast.If) or not node.body or not isinstance(node.body[-1], (ast.Return, ast.Raise)):
                continue
            checked_methods = {
                child.func.attr
                for child in ast.walk(node.test)
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
            }
            rejects_inner_quote = any(
                isinstance(child, ast.Compare)
                and len(child.ops) == 1
                and isinstance(child.ops[0], ast.In)
                and isinstance(child.left, ast.Constant)
                and str(child.left.value) in {"'", '"'}
                and isinstance(child.comparators[0], ast.Subscript)
                for child in ast.walk(node.test)
            )
            if {"startswith", "endswith"}.issubset(checked_methods) and rejects_inner_quote:
                guarded_literal_execution = True
                break

    if obfuscated_execution_line is not None and not guarded_literal_execution:
        heuristic_flags.append(make_flag(
            line=obfuscated_execution_line,
            flag_type="heuristic",
            pattern="obfuscated_execution",
            message="Suspicious behavior detected: encoded data appears to be executed",
            severity=18,
            explanation=explain_flag("obfuscated_execution", "heuristic"),
        ))

    if download_execute_line is not None:
        heuristic_flags.append(make_flag(
            line=download_execute_line,
            flag_type="heuristic",
            pattern="download_execute_chain",
            message="Suspicious behavior detected: remote content may be downloaded and then executed",
            severity=35 if direct_download_pipeline else 14,
            explanation=explain_flag("download_execute_chain", "heuristic"),
        ))

    if has_long_base64_blob:
        line_number = find_first_matching_line(scannable_lines, r"[A-Za-z0-9+/]{180,}={0,2}")
        heuristic_flags.append(make_flag(
            line=line_number,
            flag_type="heuristic",
            pattern="high_entropy_blob",
            message="Suspicious behavior detected: long encoded-looking string found",
            severity=6,
            explanation=explain_flag("high_entropy_blob", "heuristic"),
        ))

    if has_chr_chain:
        line_number = find_first_matching_line(scannable_lines, r"\bchr\s*\(")
        heuristic_flags.append(make_flag(
            line=line_number,
            flag_type="heuristic",
            pattern="chr_chain",
            message="Suspicious behavior detected: repeated chr() calls may be hiding a string",
            severity=7,
            explanation=explain_flag("chr_chain", "heuristic"),
        ))

    return heuristic_flags


def analyze_python_ast(code: str, intent: str = "") -> list[dict]:
    ast_flags: list[dict] = []
    intent_lower = str(intent or "").lower()
    # These sinks are explicit enough to analyze without relying on the user
    # naming the vulnerability category in their intent description.
    cmd_context = True
    code_context = True
    deserialization_context = True

    try:
        tree = ast.parse(code)
    except Exception:
        return ast_flags

    tainted_vars: set[str] = set()
    fixed_literal_vars: set[str] = set()
    dynamic_sql_vars: set[str] = set()
    insecure_xml_parsers: set[str] = set()
    external_input_vars: set[str] = set()
    weak_random_vars: set[str] = set()
    current_function_stack: list[str] = []

    def attribute_root_name(node: ast.AST) -> str:
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return current.id if isinstance(current, ast.Name) else ""

    def is_request_derived(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in external_input_vars
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and attribute_root_name(node.func) == "request":
                return True
            return any(is_request_derived(argument) for argument in node.args)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return attribute_root_name(node) == "request" or is_request_derived(node.value)
        return False

    def is_tainted_value(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted_vars

        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(value, ast.FormattedValue) and is_tainted_value(value.value)
                for value in node.values
            )

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return is_tainted_value(node.left) or is_tainted_value(node.right)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(is_tainted_value(element) for element in node.elts)

        if isinstance(node, ast.Dict):
            return any(is_tainted_value(value) for value in node.values)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"input", "__import__"}:
                return True
            if isinstance(node.func, ast.Name) and node.func.id in {"getenv"}:
                return True
            if isinstance(node.func, ast.Attribute):
                attr_base = getattr(node.func.value, "id", "")
                if attr_base in {"requests", "request"}:
                    return True
                if attr_base == "os" and node.func.attr == "getenv":
                    return True
            return any(is_tainted_value(argument) for argument in node.args)

        if isinstance(node, ast.Attribute):
            attr_base = getattr(node.value, "id", "")
            if (attr_base, node.attr) in {
                ("request", "args"),
                ("request", "form"),
                ("request", "json"),
                ("request", "data"),
                ("sys", "argv"),
                ("os", "environ"),
            }:
                return True
            return is_tainted_value(node.value)

        if isinstance(node, ast.Subscript):
            return is_tainted_value(node.value)

        return False

    def is_fixed_literal_collection(node: ast.AST) -> bool:
        if not isinstance(node, (ast.List, ast.Tuple)):
            return False
        return bool(node.elts) and all(
            isinstance(element, ast.Constant)
            and isinstance(element.value, (str, int, float, bool, type(None)))
            for element in node.elts
        )

    def is_weak_random_value(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in weak_random_vars
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return attribute_root_name(node.func) == "random" and node.func.attr != "SystemRandom"
        return any(is_weak_random_value(child) for child in ast.iter_child_nodes(node))

    def current_function_name() -> str:
        if not current_function_stack:
            return ""
        return current_function_stack[-1]

    def build_context_note(base_explanation: str, node: ast.Call, pattern_key: str) -> tuple[float, str]:
        if not node.args:
            return 0.0, base_explanation

        first_arg = node.args[0]
        boost = 0.0
        notes: list[str] = []

        if is_tainted_value(first_arg):
            boost += 12
            notes.append("The argument appears to be derived from external or user-controlled input.")

        if isinstance(first_arg, ast.Name):
            if first_arg.id in fixed_literal_vars:
                if pattern_key == "os.system":
                    boost -= 8
                elif pattern_key in {"eval(", "exec("}:
                    boost -= 2
                elif pattern_key in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads"}:
                    boost -= 1
                elif pattern_key == "subprocess":
                    boost -= 10
                else:
                    boost -= 4
                notes.append("The variable is assigned from a fixed literal value, which lowers the risk.")
            else:
                boost += 4
                notes.append("It appears to be called with a variable instead of a fixed literal.")
        elif isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
            boost += 4
            notes.append("The value appears to be dynamically constructed.")
        elif is_fixed_literal_collection(first_arg):
            boost -= 10 if pattern_key == "subprocess" else 4
            notes.append("The call uses a fixed argument list, which lowers injection risk.")
        elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            if pattern_key == "os.system":
                boost -= 8
            elif pattern_key in {"eval(", "exec("}:
                boost -= 2
            elif pattern_key in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads"}:
                boost -= 1
            elif pattern_key == "subprocess":
                boost -= 10
            else:
                boost -= 4
            notes.append("This appears to use a fixed literal value, which lowers the risk somewhat.")

        if pattern_key == "subprocess" and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            boost += 12
            notes.append("shell=True enables shell parsing and increases command-injection risk.")

        fn_name = current_function_name()
        if pattern_key in {"urllib.request.urlopen", "urllib.request.Request"} and fn_name in TRUSTED_INTERNAL_NETWORK_FUNCTION_NAMES:
            boost -= 2
            notes.append("This appears inside a known internal scanner/network helper, which lowers the risk somewhat.")

        if notes:
            return boost, f"{base_explanation} {' '.join(notes)}"

        return boost, base_explanation

    class SecurityVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef):
            current_function_stack.append(node.name)
            self.generic_visit(node)
            current_function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            current_function_stack.append(node.name)
            self.generic_visit(node)
            current_function_stack.pop()

        def visit_Assign(self, node: ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if is_weak_random_value(node.value):
                        weak_random_vars.add(target.id)
                    else:
                        weak_random_vars.discard(target.id)
                    if is_request_derived(node.value):
                        external_input_vars.add(target.id)
                    else:
                        external_input_vars.discard(target.id)
                    dynamic_sql = (
                        isinstance(node.value, ast.JoinedStr)
                        and any(isinstance(value, ast.FormattedValue) for value in node.value.values)
                    ) or (
                        isinstance(node.value, ast.BinOp)
                        and isinstance(node.value.op, (ast.Add, ast.Mod))
                        and not (
                            isinstance(node.value.left, ast.Constant)
                            and isinstance(node.value.right, ast.Constant)
                        )
                    )
                    if dynamic_sql:
                        dynamic_sql_vars.add(target.id)
                    else:
                        dynamic_sql_vars.discard(target.id)
                    if is_tainted_value(node.value):
                        tainted_vars.add(target.id)
                        fixed_literal_vars.discard(target.id)
                    elif (
                        isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, (str, int, float, bool, type(None)))
                    ) or is_fixed_literal_collection(node.value):
                        fixed_literal_vars.add(target.id)
                        tainted_vars.discard(target.id)
                    else:
                        fixed_literal_vars.discard(target.id)
                elif (
                    isinstance(target, ast.Subscript)
                    and is_weak_random_value(node.value)
                    and any(
                        marker in ast.unparse(target.value).lower()
                        for marker in ("session", "cookie", "token", "auth")
                    )
                ):
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="weak_randomness",
                        pattern="weak_random_security_value",
                        message="Non-cryptographic randomness is stored as security-sensitive state",
                        severity=14,
                        explanation=(
                            "Values from Python's random module are predictable and should not be used for session, "
                            "cookie, token, or authentication state. Use the secrets module instead."
                        ),
                    ))
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign):
            if node.value and isinstance(node.target, ast.Name):
                if is_tainted_value(node.value):
                    tainted_vars.add(node.target.id)
                    fixed_literal_vars.discard(node.target.id)
                elif (
                    isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, (str, int, float, bool, type(None)))
                ) or is_fixed_literal_collection(node.value):
                    fixed_literal_vars.add(node.target.id)
                    tainted_vars.discard(node.target.id)
                else:
                    fixed_literal_vars.discard(node.target.id)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Attribute):
                owner = getattr(node.func.value, "id", "")
                algorithm = ""
                if owner == "hashlib" and node.func.attr in {"md5", "sha1"}:
                    algorithm = node.func.attr
                elif owner == "hashlib" and node.func.attr == "new" and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        candidate = first.value.lower().replace("-", "")
                        if candidate in {"md5", "sha1"}:
                            algorithm = candidate
                explicitly_nonsecurity = any(
                    keyword.arg == "usedforsecurity"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                )
                if algorithm:
                    security_context = intent_mentions_any(
                        intent_lower,
                        ["password", "credential", "authentication", "security", "signature", "token"],
                    ) and not intent_mentions_any(intent_lower, ["non-security", "nonsecurity", "checksum", "etag"])
                    severity = 4 if explicitly_nonsecurity else 14 if security_context else 7
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="weak_cryptography",
                        pattern="weak_hash",
                        message=f"Weak cryptographic hash algorithm used: {algorithm.upper()}",
                        severity=severity,
                        explanation=(
                            f"{algorithm.upper()} is collision-prone and should not protect passwords, signatures, tokens, or other security-sensitive values. "
                            "Use a purpose-built password hash or a modern digest such as SHA-256 when cryptographic integrity is required."
                        ),
                    ))

                if owner == "random" and node.func.attr != "SystemRandom":
                    security_context = intent_mentions_any(
                        intent_lower,
                        ["weakrand", "password", "credential", "authentication", "security", "session", "nonce", "token", "secret"],
                    ) and not intent_mentions_any(intent_lower, ["game", "simulation", "shuffle", "dice"])
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="weak_randomness",
                        pattern="weak_random_security_value",
                        message="Non-cryptographic randomness may protect a security-sensitive value",
                        severity=14 if security_context else 4,
                        explanation=(
                            "Python's random module is predictable and is not suitable for tokens, passwords, nonces, or session identifiers. "
                            "Use secrets or random.SystemRandom for security-sensitive randomness."
                        ),
                    ))

                if node.func.attr == "set_cookie":
                    secure_keyword = next((keyword for keyword in node.keywords if keyword.arg == "secure"), None)
                    if (
                        secure_keyword is not None
                        and isinstance(secure_keyword.value, ast.Constant)
                        and secure_keyword.value.value is False
                    ):
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="insecure_default",
                            pattern="insecure_cookie_transport",
                            message="Cookie is explicitly allowed over unencrypted connections",
                            severity=16,
                            explanation=(
                                "secure=False permits the browser to send this cookie over plain HTTP. "
                                "Use secure=True in production and keep HttpOnly and an appropriate SameSite policy enabled."
                            ),
                        ))
                    if any(is_weak_random_value(argument) for argument in node.args[1:]):
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="weak_randomness",
                            pattern="weak_random_security_value",
                            message="A predictable random value is written to a cookie",
                            severity=14,
                            explanation=(
                                "Cookie values used for identity or state should be generated with the secrets module, "
                                "not Python's predictable random module."
                            ),
                        ))

                if (
                    node.func.attr == "setFeature"
                    and isinstance(node.func.value, ast.Name)
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value is True
                    and "external" in ast.unparse(node.args[0]).lower()
                ):
                    insecure_xml_parsers.add(node.func.value.id)

                if (
                    node.func.attr == "parseString"
                    and node.args
                    and (is_tainted_value(node.args[0]) or is_request_derived(node.args[0]))
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Name)
                    and node.args[1].id in insecure_xml_parsers
                ):
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="xml_external_entity",
                        pattern="xxe_external_entities",
                        message="Externally supplied XML is parsed with external entities enabled",
                        severity=24,
                        explanation=(
                            "External entity resolution can read local files or make server-side network requests. "
                            "Keep external entities disabled and use a hardened XML parser for untrusted input."
                        ),
                    ))

                if node.func.attr == "execute" and len(node.args) == 1:
                    statement = node.args[0]
                    dynamic_statement = (
                        isinstance(statement, ast.JoinedStr)
                        and any(isinstance(value, ast.FormattedValue) for value in statement.values)
                    ) or (
                        isinstance(statement, ast.Name) and statement.id in dynamic_sql_vars
                    ) or (
                        isinstance(statement, ast.BinOp) and isinstance(statement.op, (ast.Add, ast.Mod))
                    )
                    if dynamic_statement:
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="sql_injection",
                            pattern="dynamic_sql_execute",
                            message="Dynamically constructed SQL is executed without parameters",
                            severity=22,
                            explanation=(
                                "Values interpolated into SQL can change the query structure. "
                                "Use the database driver's parameter placeholders and pass values separately."
                            ),
                        ))

            if isinstance(node.func, ast.Name):
                if node.func.id == "eval" and not code_context:
                    explanation = explain_flag("eval(", "suspicious_behavior")
                    boost, explanation = build_context_note(explanation, node, "eval(")
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="suspicious_behavior",
                        pattern="eval(",
                        message="Suspicious usage detected: eval(",
                        severity=25 + boost,
                        explanation=explanation,
                    ))

                elif node.func.id == "exec" and not code_context:
                    explanation = explain_flag("exec(", "suspicious_behavior")
                    boost, explanation = build_context_note(explanation, node, "exec(")
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="suspicious_behavior",
                        pattern="exec(",
                        message="Suspicious usage detected: exec(",
                        severity=25 + boost,
                        explanation=explanation,
                    ))

                elif node.func.id == "open":
                    explanation = explain_flag("open(", "suspicious_behavior")
                    boost, explanation = build_context_note(explanation, node, "open(")
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="suspicious_behavior",
                        pattern="open(",
                        message="Suspicious usage detected: open(",
                        severity=0.5 + boost,
                        explanation=explanation,
                    ))

                elif node.func.id == "__import__":
                    explanation = explain_flag("__import__", "suspicious_behavior")
                    boost, explanation = build_context_note(explanation, node, "__import__")
                    ast_flags.append(make_flag(
                        line=node.lineno,
                        flag_type="suspicious_behavior",
                        pattern="__import__",
                        message="Suspicious usage detected: __import__",
                        severity=8 + boost,
                        explanation=explanation,
                    ))

            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "os" and node.func.attr == "system" and not cmd_context:
                        explanation = explain_flag("os.system", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "os.system")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="os.system",
                            message="Suspicious usage detected: os.system",
                            severity=30 + boost,
                            explanation=explanation,
                        ))

                    elif (
                        node.func.value.id == "subprocess"
                        and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                        and not cmd_context
                    ):
                        explanation = explain_flag("subprocess", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "subprocess")
                        subprocess_severity = 15 + boost
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="review_note" if subprocess_severity <= 5 else "suspicious_behavior",
                            pattern="subprocess",
                            message=(
                                "Process execution detected with fixed arguments"
                                if subprocess_severity <= 5
                                else "Suspicious usage detected: subprocess"
                            ),
                            severity=subprocess_severity,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "importlib" and node.func.attr == "import_module":
                        explanation = explain_flag("importlib.import_module", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "importlib.import_module")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="importlib.import_module",
                            message="Suspicious usage detected: importlib.import_module",
                            severity=6 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "pickle" and node.func.attr == "loads" and not deserialization_context:
                        explanation = explain_flag("pickle.loads", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "pickle.loads")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="pickle.loads",
                            message="Suspicious usage detected: pickle.loads",
                            severity=20 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "pickle" and node.func.attr == "load" and not deserialization_context:
                        explanation = explain_flag("pickle.load", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "pickle.load")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="pickle.load",
                            message="Suspicious usage detected: pickle.load",
                            severity=20 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "marshal" and node.func.attr == "loads" and not deserialization_context:
                        explanation = explain_flag("marshal.loads", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "marshal.loads")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="marshal.loads",
                            message="Suspicious usage detected: marshal.loads",
                            severity=18 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "marshal" and node.func.attr == "load" and not deserialization_context:
                        explanation = explain_flag("marshal.load", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "marshal.load")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="marshal.load",
                            message="Suspicious usage detected: marshal.load",
                            severity=18 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "yaml" and node.func.attr == "load" and not deserialization_context:
                        loader_names = {
                            getattr(keyword.value, "id", "")
                            or getattr(keyword.value, "attr", "")
                            for keyword in node.keywords
                            if str(keyword.arg or "").lower() == "loader"
                        }
                        if not loader_names.intersection({"SafeLoader", "CSafeLoader"}):
                            explanation = explain_flag("yaml.load", "suspicious_behavior")
                            boost, explanation = build_context_note(explanation, node, "yaml.load")
                            ast_flags.append(make_flag(
                                line=node.lineno,
                                flag_type="suspicious_behavior",
                                pattern="yaml.load",
                                message="Suspicious usage detected: yaml.load",
                                severity=14 + boost,
                                explanation=explanation,
                            ))

                    elif node.func.value.id == "dill" and node.func.attr == "loads" and not deserialization_context:
                        explanation = explain_flag("dill.loads", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "dill.loads")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="dill.loads",
                            message="Suspicious usage detected: dill.loads",
                            severity=18 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "requests" and node.func.attr == "get":
                        explanation = explain_flag("requests.get", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "requests.get")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="requests.get",
                            message="Suspicious usage detected: requests.get",
                            severity=2 + boost,
                            explanation=explanation,
                        ))

                    elif node.func.value.id == "requests" and node.func.attr == "post":
                        explanation = explain_flag("requests.post", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "requests.post")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="requests.post",
                            message="Suspicious usage detected: requests.post",
                            severity=4 + boost,
                            explanation=explanation,
                        ))

                elif isinstance(node.func.value, ast.Attribute):
                    if (
                        isinstance(node.func.value.value, ast.Name)
                        and node.func.value.value.id == "urllib"
                        and node.func.value.attr == "request"
                    ):
                        if node.func.attr == "urlopen":
                            explanation = explain_flag("urllib.request.urlopen", "suspicious_behavior")
                            boost, explanation = build_context_note(explanation, node, "urllib.request.urlopen")
                            ast_flags.append(make_flag(
                                line=node.lineno,
                                flag_type="suspicious_behavior",
                                pattern="urllib.request.urlopen",
                                message="Suspicious usage detected: urllib.request.urlopen",
                                severity=3 + boost,
                                explanation=explanation,
                            ))
                        elif node.func.attr == "urlretrieve":
                            explanation = explain_flag("urllib.request.urlretrieve", "suspicious_behavior")
                            boost, explanation = build_context_note(explanation, node, "urllib.request.urlretrieve")
                            ast_flags.append(make_flag(
                                line=node.lineno,
                                flag_type="suspicious_behavior",
                                pattern="urllib.request.urlretrieve",
                                message="Suspicious usage detected: urllib.request.urlretrieve",
                                severity=5 + boost,
                                explanation=explanation,
                            ))
                        elif node.func.attr == "Request":
                            explanation = explain_flag("urllib.request.Request", "suspicious_behavior")
                            boost, explanation = build_context_note(explanation, node, "urllib.request.Request")
                            ast_flags.append(make_flag(
                                line=node.lineno,
                                flag_type="suspicious_behavior",
                                pattern="urllib.request.Request",
                                message="Suspicious usage detected: urllib.request.Request",
                                severity=2 + boost,
                                explanation=explanation,
                            ))

            self.generic_visit(node)

    SecurityVisitor().visit(tree)
    ast_flags.extend(analyze_python_web_dataflow(tree, intent_lower))
    return ast_flags


def analyze_python_web_dataflow(tree: ast.AST, intent_lower: str) -> list[dict]:
    """Track request-derived values through supported security-sensitive sinks."""
    findings: list[dict] = []
    web_context = intent_mentions_any(
        intent_lower,
        ["xss", "html", "web", "browser", "page", "template", "render", "display", "response"],
    )
    path_context = True
    ldap_context = True
    xpath_context = True
    redirect_context = True
    trust_context = True
    cmd_context = True
    code_context = True
    deserialization_context = True
    web_sanitizer_names = {
        "escape",
        "escape_for_html",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "quoteattr",
    }
    ldap_sanitizer_names = {"escape_filter_chars"}
    path_sanitizer_names = {"basename", "secure_filename", "os.path.basename"}
    unknown = object()
    assigned_names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    assigned_names.update(
        node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)
    )
    insecure_xml_parsers: set[str] = set()

    def dotted_name(node: ast.AST) -> str:
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def root_name(node: ast.AST) -> str:
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        if isinstance(current, ast.Call):
            return root_name(current.func)
        return current.id if isinstance(current, ast.Name) else ""

    def const_value(node: ast.AST, constants: dict[str, object]):
        try:
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, ast.Name):
                return constants.get(node.id, unknown)
            if isinstance(node, (ast.List, ast.Tuple)):
                values = [const_value(item, constants) for item in node.elts]
                if any(value is unknown for value in values):
                    return unknown
                return values if isinstance(node, ast.List) else tuple(values)
            if isinstance(node, ast.Dict):
                keys = [const_value(item, constants) for item in node.keys]
                values = [const_value(item, constants) for item in node.values]
                if any(value is unknown for value in keys + values):
                    return unknown
                return dict(zip(keys, values))
            if isinstance(node, ast.Subscript):
                value = const_value(node.value, constants)
                index = const_value(node.slice, constants)
                return unknown if value is unknown or index is unknown else value[index]
            if isinstance(node, ast.UnaryOp):
                value = const_value(node.operand, constants)
                if value is unknown:
                    return unknown
                if isinstance(node.op, ast.Not):
                    return not value
                if isinstance(node.op, ast.USub):
                    return -value
                if isinstance(node.op, ast.UAdd):
                    return +value
            if isinstance(node, ast.BinOp):
                left, right = const_value(node.left, constants), const_value(node.right, constants)
                if left is unknown or right is unknown:
                    return unknown
                operations = {
                    ast.Add: lambda: left + right,
                    ast.Sub: lambda: left - right,
                    ast.Mult: lambda: left * right,
                    ast.Div: lambda: left / right,
                    ast.FloorDiv: lambda: left // right,
                    ast.Mod: lambda: left % right,
                }
                operation = operations.get(type(node.op))
                return operation() if operation else unknown
            if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
                left = const_value(node.left, constants)
                right = const_value(node.comparators[0], constants)
                if left is unknown or right is unknown:
                    return unknown
                operation = node.ops[0]
                if isinstance(operation, ast.Eq):
                    return left == right
                if isinstance(operation, ast.NotEq):
                    return left != right
                if isinstance(operation, ast.Gt):
                    return left > right
                if isinstance(operation, ast.GtE):
                    return left >= right
                if isinstance(operation, ast.Lt):
                    return left < right
                if isinstance(operation, ast.LtE):
                    return left <= right
                if isinstance(operation, ast.In):
                    return left in right
                if isinstance(operation, ast.NotIn):
                    return left not in right
            if isinstance(node, ast.IfExp):
                condition = const_value(node.test, constants)
                if condition is unknown:
                    return unknown
                return const_value(node.body if condition else node.orelse, constants)
        except (KeyError, IndexError, TypeError, ValueError, ZeroDivisionError):
            return unknown
        return unknown

    def expr_tainted(node: ast.AST, tainted: set[str], containers: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return (
                node.id in tainted
                or node.id in containers
                or any(isinstance(item, tuple) and item[0] == node.id for item in containers)
            )
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Call):
            call_name = dotted_name(node.func)
            short_name = call_name.rsplit(".", 1)[-1]
            if short_name == "input":
                return True
            if call_name in {
                "requests.get", "requests.post", "urllib.request.urlopen", "urllib.request.urlretrieve"
            }:
                return True
            if (
                (web_context and (call_name in web_sanitizer_names or short_name in web_sanitizer_names))
                or (ldap_context and (call_name in ldap_sanitizer_names or short_name in ldap_sanitizer_names))
                or (path_context and (call_name in path_sanitizer_names or short_name in path_sanitizer_names))
            ):
                return False
            if (
                isinstance(node.func, ast.Attribute)
                and short_name in {"getvalue", "read", "readline", "readlines"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in containers
            ):
                return True
            if call_name == "request.path" or call_name.startswith("request.path."):
                return False
            if (
                xpath_context
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "replace"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[1], ast.Constant)
                and (str(node.args[0].value), str(node.args[1].value))
                in {("'", "&apos;"), ('"', "&quot;")}
            ):
                return False
            if call_name.rsplit(".", 1)[-1] in {"get_form_parameter", "get_query_parameter"}:
                return True
            if root_name(node.func) == "request":
                return True
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.args
                and all(isinstance(argument, ast.Constant) for argument in node.args[:2])
            ):
                key_values = tuple(argument.value for argument in node.args[:2])
                key = key_values[0] if len(key_values) == 1 else key_values
                return (
                    node.func.value.id in containers
                    or (node.func.value.id, key) in containers
                )
            return (
                expr_tainted(node.func.value, tainted, containers)
                if isinstance(node.func, ast.Attribute)
                else False
            ) or any(expr_tainted(arg, tainted, containers) for arg in node.args) or any(
                expr_tainted(keyword.value, tainted, containers) for keyword in node.keywords
            )
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(value, ast.FormattedValue) and expr_tainted(value.value, tainted, containers)
                for value in node.values
            )
        if isinstance(node, ast.FormattedValue):
            return expr_tainted(node.value, tainted, containers)
        if isinstance(node, ast.BinOp):
            return expr_tainted(node.left, tainted, containers) or expr_tainted(node.right, tainted, containers)
        if isinstance(node, ast.BoolOp):
            return any(expr_tainted(value, tainted, containers) for value in node.values)
        if isinstance(node, ast.IfExp):
            return expr_tainted(node.body, tainted, containers) or expr_tainted(node.orelse, tainted, containers)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(expr_tainted(value, tainted, containers) for value in node.elts)
        if isinstance(node, ast.Dict):
            return any(expr_tainted(value, tainted, containers) for value in node.values)
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant):
                return (
                    node.value.id in tainted
                    or
                    node.value.id in containers
                    or (node.value.id, node.slice.value) in containers
                )
            return root_name(node) == "request" or expr_tainted(node.value, tainted, containers)
        if isinstance(node, ast.Attribute):
            if dotted_name(node) == "request.path":
                return False
            return root_name(node) == "request" or expr_tainted(node.value, tainted, containers)
        return False

    def tainted_names(node: ast.AST, tainted: set[str], containers: set[str]) -> set[str]:
        names = {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and (child.id in tainted or child.id in containers)
        }
        return names

    def traversal_guard_name(node: ast.AST) -> str:
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In):
            if isinstance(node.left, ast.Constant) and str(node.left.value) in {"..", "../", "..\\"}:
                right_names = [child.id for child in ast.walk(node.comparators[0]) if isinstance(child, ast.Name)]
                return right_names[0] if right_names else ""
        return ""

    def rejected_character_guard_name(node: ast.AST) -> str:
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In):
            if isinstance(node.left, ast.Constant) and str(node.left.value) in {"'", '"'}:
                names = [child.id for child in ast.walk(node.comparators[0]) if isinstance(child, ast.Name)]
                return names[0] if names else ""
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                guarded = rejected_character_guard_name(value)
                if guarded:
                    return guarded
        return ""

    def containment_guard_name(node: ast.AST) -> str:
        candidate = node.operand if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) else node
        if not isinstance(candidate, ast.Call) or not isinstance(candidate.func, ast.Attribute):
            return ""
        if candidate.func.attr not in {"startswith", "is_relative_to"}:
            return ""
        receiver = candidate.func.value
        if isinstance(receiver, ast.Name):
            return receiver.id
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "str"
            and receiver.args
            and isinstance(receiver.args[0], ast.Name)
        ):
            return receiver.args[0].id
        return ""

    def definitely_stops(statements: list[ast.stmt]) -> bool:
        return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))

    def merge_states(states):
        continuing = [state for state in states if state[4]]
        if not continuing:
            return set(), set(), {}, set(), False
        tainted = set().union(*(state[0] for state in continuing))
        containers = set().union(*(state[1] for state in continuing))
        sanitized = set.intersection(*(state[3] for state in continuing)) if len(continuing) > 1 else set(continuing[0][3])
        shared_constants = dict(continuing[0][2])
        for state in continuing[1:]:
            shared_constants = {
                key: value for key, value in shared_constants.items()
                if key in state[2] and state[2][key] == value
            }
        return tainted, containers, shared_constants, sanitized, True

    def assign_target(
        target,
        value_tainted,
        value_constant,
        tainted,
        containers,
        constants,
        sanitized,
        value_path_safe=False,
    ):
        if isinstance(target, ast.Name):
            if value_tainted:
                tainted.add(target.id)
            else:
                tainted.discard(target.id)
            containers.discard(target.id)
            containers.difference_update({
                item for item in containers if isinstance(item, tuple) and item[0] == target.id
            })
            if value_path_safe:
                sanitized.add(target.id)
            else:
                sanitized.discard(target.id)
            if value_constant is unknown:
                constants.pop(target.id, None)
            else:
                constants[target.id] = value_constant
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            if isinstance(target.slice, ast.Constant):
                item = (target.value.id, target.slice.value)
                if value_tainted:
                    containers.add(item)
                else:
                    containers.discard(item)
            elif value_tainted:
                containers.add(target.value.id)

    def record_path_sink(call: ast.Call, tainted: set[str], containers: set[str], sanitized: set[str]) -> None:
        call_name = dotted_name(call.func)
        short_name = call_name.rsplit(".", 1)[-1]
        path_methods = {
            "exists", "is_file", "is_dir", "read_text", "read_bytes", "write_text", "write_bytes",
            "unlink", "rmdir", "mkdir", "rename", "chmod", "touch", "stat",
        }
        argument = None
        if call_name == "open" or call_name.endswith(".open"):
            argument = call.args[0] if call.args else getattr(call.func, "value", None)
        elif call_name.startswith("os.path.") and call.args:
            argument = call.args[0]
        elif short_name in path_methods and isinstance(call.func, ast.Attribute):
            argument = call.func.value
        if not path_context or argument is None:
            return
        if not expr_tainted(argument, tainted, containers):
            return
        names = tainted_names(argument, tainted, containers)
        if names and names.issubset(sanitized):
            return
        findings.append(make_flag(
            line=call.lineno,
            flag_type="path_traversal",
            pattern="untrusted_file_path",
            message="Request-controlled data is used to choose a filesystem path",
            severity=22,
            explanation=(
                "An attacker may use path segments such as ../ to access files outside the intended directory. "
                "Resolve the candidate path, enforce that it remains under an allowed base directory, and reject traversal segments."
            ),
        ))

    def record_security_sink(call: ast.Call, tainted: set[str], containers: set[str], sanitized: set[str]) -> None:
        call_name = dotted_name(call.func)
        short_name = call_name.rsplit(".", 1)[-1]
        if short_name == "setFeature" and isinstance(call.func, ast.Attribute) and len(call.args) >= 2:
            parser_name = call.func.value.id if isinstance(call.func.value, ast.Name) else ""
            feature_name = ast.unparse(call.args[0]).lower()
            enabled = call.args[1]
            if parser_name and "external" in feature_name and isinstance(enabled, ast.Constant):
                if enabled.value is True:
                    insecure_xml_parsers.add(parser_name)
                elif enabled.value is False:
                    insecure_xml_parsers.discard(parser_name)
        argument = call.args[0] if call.args else None
        argument_names = tainted_names(argument, tainted, containers) if argument is not None else set()
        unknown_direct_argument = bool(
            isinstance(argument, ast.Name)
            and argument.id not in assigned_names
            and argument.id not in sanitized
        )
        unsafe_argument = bool(
            argument is not None
            and (
                unknown_direct_argument
                or (
                    expr_tainted(argument, tainted, containers)
                    and (not argument_names or not argument_names.issubset(sanitized))
                )
            )
        )
        if (
            short_name in {"parseString", "parse"}
            and unsafe_argument
            and len(call.args) >= 2
            and isinstance(call.args[1], ast.Name)
            and call.args[1].id in insecure_xml_parsers
        ):
            findings.append(make_flag(
                line=call.lineno,
                flag_type="xml_external_entity",
                pattern="xxe_external_entities",
                message="Externally supplied XML is parsed with external entities enabled",
                severity=24,
                explanation=(
                    "External entity resolution can read local files or make server-side network requests. "
                    "Keep external entities disabled and use a hardened XML parser for untrusted input."
                ),
            ))
        if code_context and short_name in {"eval", "exec"} and unsafe_argument:
            pattern = f"{short_name}("
            findings.append(make_flag(
                line=call.lineno,
                flag_type="code_injection",
                pattern=pattern,
                message=f"Request-controlled data reaches {short_name}()",
                severity=38,
                explanation=(
                    f"{short_name}() executes Python source. Parse the expected data format instead, "
                    "or restrict the input to a rigorously validated non-executable representation."
                ),
            ))
        if (
            cmd_context
            and (call_name == "os.system" or call_name.startswith("subprocess."))
            and unsafe_argument
        ):
            findings.append(make_flag(
                line=call.lineno,
                flag_type="command_injection",
                pattern="subprocess" if call_name.startswith("subprocess.") else "os.system",
                message="Request-controlled data reaches a system command",
                severity=38,
                explanation=(
                    "Shell metacharacters in external input can change the command. Use a fixed executable and a list of "
                    "validated arguments, and avoid shell=True."
                ),
            ))
        deserialization_sinks = {
            "pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads", "yaml.load"
        }
        if deserialization_context and call_name in deserialization_sinks and unsafe_argument:
            findings.append(make_flag(
                line=call.lineno,
                flag_type="unsafe_deserialization",
                pattern=call_name,
                message="Request-controlled data reaches an unsafe deserializer",
                severity=38,
                explanation=(
                    "Some Python deserializers can construct attacker-controlled objects or execute code. "
                    "Use a non-executable data format and a safe loader for untrusted input."
                ),
            ))
        if ldap_context and short_name == "search" and len(call.args) >= 2:
            query = call.args[1]
            names = tainted_names(query, tainted, containers)
            if expr_tainted(query, tainted, containers) and (not names or not names.issubset(sanitized)):
                findings.append(make_flag(
                    line=call.lineno,
                    flag_type="ldap_injection",
                    pattern="dynamic_ldap_filter",
                    message="Request-controlled data is interpolated into an LDAP filter",
                    severity=22,
                    explanation=(
                        "LDAP metacharacters can change the filter and expose or modify unintended directory records. "
                        "Escape filter values with the LDAP library's filter-escaping helper before building the query."
                    ),
                ))

        xpath_argument = None
        if xpath_context and (call_name.endswith(".XPath") or short_name == "xpath") and call.args:
            xpath_argument = call.args[0]
        elif xpath_context and call_name.endswith("elementpath.select") and len(call.args) >= 2:
            xpath_argument = call.args[1]
        if xpath_argument is not None:
            names = tainted_names(xpath_argument, tainted, containers)
            if expr_tainted(xpath_argument, tainted, containers) and (not names or not names.issubset(sanitized)):
                findings.append(make_flag(
                    line=call.lineno,
                    flag_type="xpath_injection",
                    pattern="dynamic_xpath_query",
                    message="Request-controlled data is interpolated into an XPath query",
                    severity=22,
                    explanation=(
                        "XPath operators and quotes can change the query structure. "
                        "Use variable binding when supported, or strictly validate and escape values before interpolation."
                    ),
                ))
        if redirect_context and short_name == "redirect" and call.args:
            destination = call.args[0]
            names = tainted_names(destination, tainted, containers)
            if expr_tainted(destination, tainted, containers) and (not names or not names.issubset(sanitized)):
                findings.append(make_flag(
                    line=call.lineno,
                    flag_type="open_redirect",
                    pattern="unvalidated_redirect",
                    message="Request-controlled data determines a redirect destination",
                    severity=20,
                    explanation=(
                        "An attacker can send users to a malicious site when arbitrary redirect destinations are accepted. "
                        "Allowlist trusted hosts and schemes, or accept only application-relative paths."
                    ),
                ))

    def record_nested_security_sinks(node: ast.AST, tainted: set[str], containers: set[str], sanitized: set[str]) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                record_path_sink(child, tainted, containers, sanitized)
                record_security_sink(child, tainted, containers, sanitized)

    def process_block(statements, tainted=None, containers=None, constants=None, sanitized=None):
        tainted = set(tainted or ())
        containers = set(containers or ())
        constants = dict(constants or {})
        sanitized = set(sanitized or ())
        falls_through = True
        for statement in statements:
            if not falls_through:
                break
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameter_names = {
                    argument.arg
                    for argument in (
                        list(statement.args.posonlyargs)
                        + list(statement.args.args)
                        + list(statement.args.kwonlyargs)
                    )
                }
                if statement.args.vararg:
                    parameter_names.add(statement.args.vararg.arg)
                if statement.args.kwarg:
                    parameter_names.add(statement.args.kwarg.arg)
                process_block(statement.body, tainted=parameter_names)
                continue
            if isinstance(statement, ast.Assign):
                if isinstance(statement.value, ast.Call):
                    record_path_sink(statement.value, tainted, containers, sanitized)
                    record_nested_security_sinks(statement.value, tainted, containers, sanitized)
                value_constant = const_value(statement.value, constants)
                value_tainted = (
                    False
                    if value_constant is not unknown
                    else expr_tainted(statement.value, tainted, containers)
                )
                source_names = tainted_names(statement.value, tainted, containers)
                value_path_safe = bool(source_names) and source_names.issubset(sanitized)
                for target in statement.targets:
                    if (
                        trust_context
                        and isinstance(target, ast.Subscript)
                        and dotted_name(target.value).endswith("session")
                        and (
                            value_tainted
                            or expr_tainted(target.slice, tainted, containers)
                        )
                    ):
                        findings.append(make_flag(
                            line=statement.lineno,
                            flag_type="trust_boundary_violation",
                            pattern="untrusted_session_state",
                            message="Request-controlled data crosses into trusted session state",
                            severity=18,
                            explanation=(
                                "Session data is often trusted by later authorization and workflow code. "
                                "Validate and normalize request values before storing them, and keep session keys fixed."
                            ),
                        ))
                    assign_target(
                        target,
                        value_tainted,
                        value_constant,
                        tainted,
                        containers,
                        constants,
                        sanitized,
                        value_path_safe,
                    )
                    if (
                        isinstance(target, ast.Name)
                        and isinstance(statement.value, ast.Call)
                        and dotted_name(statement.value.func).endswith("urlparse")
                        and statement.value.args
                    ):
                        source_names = tainted_names(statement.value.args[0], tainted, containers)
                        if source_names:
                            constants[target.id] = ("__parsed_url__", tuple(sorted(source_names)))
                continue
            if isinstance(statement, ast.AnnAssign) and statement.value:
                assign_target(
                    statement.target,
                    expr_tainted(statement.value, tainted, containers),
                    const_value(statement.value, constants),
                    tainted,
                    containers,
                    constants,
                    sanitized,
                )
                continue
            if isinstance(statement, ast.AugAssign):
                record_nested_security_sinks(statement.value, tainted, containers, sanitized)
                value_tainted = expr_tainted(statement.value, tainted, containers)
                target_name = statement.target.id if isinstance(statement.target, ast.Name) else ""
                if web_context and value_tainted and target_name.lower() in {"response", "html", "body", "output"}:
                    findings.append(make_flag(
                        line=statement.lineno,
                        flag_type="cross_site_scripting",
                        pattern="unescaped_web_response",
                        message="Unescaped request data is included in a web response",
                        severity=22,
                        explanation=(
                            "Request-controlled text can become active browser content when it is returned without contextual escaping. "
                            "Escape or sanitize the value at the output boundary, or render it through an auto-escaping template."
                        ),
                    ))
                if target_name and value_tainted:
                    tainted.add(target_name)
                continue
            if isinstance(statement, ast.If):
                record_nested_security_sinks(statement.test, tainted, containers, sanitized)
                condition = const_value(statement.test, constants)
                if condition is not unknown:
                    chosen = statement.body if bool(condition) else statement.orelse
                    tainted, containers, constants, sanitized, falls_through = process_block(
                        chosen, tainted, containers, constants, sanitized
                    )
                else:
                    body_state = process_block(statement.body, tainted, containers, constants, sanitized)
                    else_state = process_block(statement.orelse, tainted, containers, constants, sanitized)
                    tainted, containers, constants, sanitized, falls_through = merge_states([body_state, else_state])
                    guarded_name = traversal_guard_name(statement.test)
                    if guarded_name and definitely_stops(statement.body) and falls_through:
                        sanitized.add(guarded_name)
                    rejected_name = rejected_character_guard_name(statement.test)
                    if rejected_name and definitely_stops(statement.body) and falls_through:
                        sanitized.add(rejected_name)
                    contained_name = containment_guard_name(statement.test)
                    if contained_name and definitely_stops(statement.body) and falls_through:
                        sanitized.add(contained_name)
                    if definitely_stops(statement.body) and falls_through:
                        tested_names = {child.id for child in ast.walk(statement.test) if isinstance(child, ast.Name)}
                        tested_attrs = {child.attr for child in ast.walk(statement.test) if isinstance(child, ast.Attribute)}
                        if {"netloc", "scheme"}.issubset(tested_attrs):
                            for tested_name in tested_names:
                                marker = constants.get(tested_name)
                                if isinstance(marker, tuple) and marker and marker[0] == "__parsed_url__":
                                    sanitized.update(marker[1])
                continue
            if isinstance(statement, ast.Match):
                record_nested_security_sinks(statement.subject, tainted, containers, sanitized)
                subject = const_value(statement.subject, constants)
                chosen_case = None
                if subject is not unknown:
                    for case in statement.cases:
                        pattern = case.pattern
                        if isinstance(pattern, ast.MatchValue) and const_value(pattern.value, constants) == subject:
                            chosen_case = case
                            break
                        if isinstance(pattern, ast.MatchOr) and any(
                            isinstance(item, ast.MatchValue) and const_value(item.value, constants) == subject
                            for item in pattern.patterns
                        ):
                            chosen_case = case
                            break
                        if isinstance(pattern, ast.MatchAs) and pattern.name is None:
                            chosen_case = case
                            break
                if chosen_case:
                    tainted, containers, constants, sanitized, falls_through = process_block(
                        chosen_case.body, tainted, containers, constants, sanitized
                    )
                else:
                    states = [process_block(case.body, tainted, containers, constants, sanitized) for case in statement.cases]
                    tainted, containers, constants, sanitized, falls_through = merge_states(states)
                continue
            if isinstance(statement, (ast.For, ast.While)):
                loop_expression = statement.iter if isinstance(statement, ast.For) else statement.test
                record_nested_security_sinks(loop_expression, tainted, containers, sanitized)
                loop_tainted = set(tainted)
                loop_containers = set(containers)
                loop_constants = dict(constants)
                loop_sanitized = set(sanitized)
                if isinstance(statement, ast.For):
                    assign_target(
                        statement.target,
                        expr_tainted(statement.iter, tainted, containers),
                        unknown,
                        loop_tainted,
                        loop_containers,
                        loop_constants,
                        loop_sanitized,
                    )
                loop_state = process_block(
                    statement.body,
                    loop_tainted,
                    loop_containers,
                    loop_constants,
                    loop_sanitized,
                )
                else_state = process_block(statement.orelse, tainted, containers, constants, sanitized)
                tainted, containers, constants, sanitized, falls_through = merge_states([
                    (tainted, containers, constants, sanitized, True), loop_state, else_state
                ])
                continue
            if isinstance(statement, ast.Try):
                states = [process_block(statement.body, tainted, containers, constants, sanitized)]
                states.extend(process_block(handler.body, tainted, containers, constants, sanitized) for handler in statement.handlers)
                if statement.orelse:
                    states.append(process_block(statement.orelse, tainted, containers, constants, sanitized))
                tainted, containers, constants, sanitized, falls_through = merge_states(states)
                if statement.finalbody:
                    tainted, containers, constants, sanitized, falls_through = process_block(
                        statement.finalbody, tainted, containers, constants, sanitized
                    )
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if isinstance(item.context_expr, ast.Call):
                        record_path_sink(item.context_expr, tainted, containers, sanitized)
                        record_nested_security_sinks(item.context_expr, tainted, containers, sanitized)
                tainted, containers, constants, sanitized, falls_through = process_block(
                    statement.body, tainted, containers, constants, sanitized
                )
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                record_path_sink(call, tainted, containers, sanitized)
                record_nested_security_sinks(call, tainted, containers, sanitized)
                call_name = dotted_name(call.func).rsplit(".", 1)[-1]
                if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                    container_name = call.func.value.id
                    if call_name == "append" and call.args:
                        value_tainted = expr_tainted(call.args[0], tainted, containers)
                        known_list = constants.get(container_name)
                        if isinstance(known_list, list):
                            index = len(known_list)
                            known_list.append(unknown if value_tainted else const_value(call.args[0], constants))
                            if value_tainted:
                                containers.add((container_name, index))
                            else:
                                containers.discard((container_name, index))
                        elif value_tainted:
                            containers.add(container_name)
                    elif call_name == "pop" and isinstance(constants.get(container_name), list):
                        known_list = constants[container_name]
                        raw_index = const_value(call.args[0], constants) if call.args else -1
                        if isinstance(raw_index, int) and known_list:
                            index = raw_index if raw_index >= 0 else len(known_list) + raw_index
                            if 0 <= index < len(known_list):
                                known_list.pop(index)
                                shifted = set()
                                for item in containers:
                                    if isinstance(item, tuple) and item[0] == container_name and isinstance(item[1], int):
                                        if item[1] == index:
                                            continue
                                        shifted.add((container_name, item[1] - 1 if item[1] > index else item[1]))
                                    else:
                                        shifted.add(item)
                                containers.clear()
                                containers.update(shifted)
                    elif call_name == "add" and call.args and expr_tainted(call.args[0], tainted, containers):
                        containers.add(container_name)
                    elif call_name == "extend" and call.args and expr_tainted(call.args[0], tainted, containers):
                        containers.add(container_name)
                    elif call_name == "write" and call.args and expr_tainted(call.args[0], tainted, containers):
                        containers.add(container_name)
                    elif call_name == "set" and call.args:
                        key_values = tuple(
                            argument.value for argument in call.args[:-1]
                            if isinstance(argument, ast.Constant)
                        )
                        key = key_values[0] if len(key_values) == 1 else key_values
                        if key_values and len(key_values) == len(call.args) - 1:
                            item = (container_name, key)
                            if expr_tainted(call.args[-1], tainted, containers):
                                containers.add(item)
                            else:
                                containers.discard(item)
                        elif expr_tainted(call.args[-1], tainted, containers):
                            containers.add(container_name)
                continue
            if isinstance(statement, ast.Return):
                if isinstance(statement.value, ast.Call):
                    record_nested_security_sinks(statement.value, tainted, containers, sanitized)
                if (
                    web_context
                    and statement.value
                    and not isinstance(statement.value, ast.Name)
                    and expr_tainted(statement.value, tainted, containers)
                ):
                    findings.append(make_flag(
                        line=statement.lineno,
                        flag_type="cross_site_scripting",
                        pattern="unescaped_web_response",
                        message="Unescaped request data is returned to a web client",
                        severity=22,
                        explanation=(
                            "Request-controlled text can become active browser content when returned without contextual escaping. "
                            "Escape or sanitize the value at the output boundary, or render it through an auto-escaping template."
                        ),
                    ))
                falls_through = False
                continue
            if isinstance(statement, ast.Raise):
                falls_through = False
        return tainted, containers, constants, sanitized, falls_through

    process_block(getattr(tree, "body", []))
    return findings


def dedupe_flags(flags: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple] = set()

    for flag in sorted(flags, key=lambda item: (item["line"], item["pattern"], -float(item["severity"]))):
        key = (flag["line"], flag["pattern"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(flag)

    return deduped


def has_meaningful_intent(intent: str) -> bool:
    normalized = intent.strip().lower()
    if normalized in GENERIC_INTENTS:
        return False
    if len(normalized) < 12:
        return False
    return True


def intent_mentions_any(intent_lower: str, terms: list[str]) -> bool:
    """Match whole intent terms so words like 'report' do not count as 'repo'."""
    return any(
        re.search(rf"(?<![a-z0-9_]){re.escape(term.lower())}(?![a-z0-9_])", intent_lower)
        for term in terms
    )


def normalize_manifest_version(raw_version: str) -> tuple[str | None, str]:
    if not raw_version:
        return None, "unresolved"

    version = str(raw_version).strip().strip("\"'")

    if not version:
        return None, "unresolved"

    lowered = version.lower()

    unsupported_prefixes = (
        "git+", "git://", "github:", "file:", "link:", "workspace:",
        "http://", "https://", "npm:", "path:", "*", "latest"
    )
    if lowered.startswith(unsupported_prefixes):
        return None, "unresolved"

    if "||" in version or " - " in version:
        return None, "unresolved"

    if any(token in version for token in ["<", ">", "*", "x", "X"]):
        return None, "unresolved"

    version = re.sub(r"^\s*[=v]+\s*", "", version)

    if version.startswith("^") or version.startswith("~"):
        normalized = version[1:].strip()
        if normalized:
            return normalized, "range-normalized"

    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.\-+_]*", version):
        return version, "exact"

    return None, "unresolved"


def normalize_python_package_name(name: str) -> str:
    cleaned = name.strip()
    cleaned = cleaned.split("[", 1)[0]
    return cleaned.strip()


def parse_requirements_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies: list[dict] = []
    skipped: list[dict] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "-e ", "--editable ")):
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Nested, editable, or indirect requirement not queried in this first version.",
            })
            continue

        line = line.split(" #", 1)[0].strip()
        line = line.split(";", 1)[0].strip()

        if not line:
            continue

        match = re.match(r"^\s*([A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,.\-]+\])?)\s*(==|~=|>=|<=|!=|>|<)?\s*([^\s]+)?", line)
        if not match:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Could not confidently parse this dependency line.",
            })
            continue

        package_name = normalize_python_package_name(match.group(1) or "")
        operator = match.group(2) or ""
        raw_version = match.group(3) or ""

        if not package_name:
            continue

        if not raw_version:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Unpinned dependency version could not be queried reliably.",
            })
            continue

        normalized_version, version_kind = normalize_manifest_version(f"{operator}{raw_version}")

        if not normalized_version:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Complex version specifier is not supported in this first version.",
            })
            continue

        dependencies.append({
            "file": file_name,
            "manifest_type": "requirements.txt",
            "line": line_number,
            "package": package_name,
            "ecosystem": "PyPI",
            "declared_version": f"{operator}{raw_version}".strip(),
            "version": normalized_version,
            "version_kind": version_kind,
        })

    return dependencies, skipped


def parse_package_json_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies: list[dict] = []
    skipped: list[dict] = []

    try:
        data = json.loads(content)
    except Exception:
        skipped.append({
            "file": file_name,
            "line": 1,
            "raw": "",
            "reason": "package.json could not be parsed as valid JSON.",
        })
        return dependencies, skipped

    sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]

    for section_name in sections:
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue

        for package_name, raw_version in section.items():
            normalized_version, version_kind = normalize_manifest_version(str(raw_version))

            if not normalized_version:
                skipped.append({
                    "file": file_name,
                    "line": 1,
                    "raw": f"{package_name}: {raw_version}",
                    "reason": f"{section_name} entry uses a complex or non-registry specifier.",
                })
                continue

            dependencies.append({
                "file": file_name,
                "manifest_type": "package.json",
                "line": 1,
                "package": str(package_name).strip(),
                "ecosystem": "npm",
                "declared_version": str(raw_version).strip(),
                "version": normalized_version,
                "version_kind": version_kind,
                "dependency_section": section_name,
            })

    return dependencies, skipped


def dependency_record(
    file_name: str,
    manifest_type: str,
    package: str,
    ecosystem: str,
    declared_version: str,
    line: int = 1,
    section: str = "",
) -> tuple[dict | None, dict | None]:
    normalized_version, version_kind = normalize_manifest_version(declared_version)
    if not package or not normalized_version:
        return None, {
            "file": file_name,
            "line": max(1, int(line or 1)),
            "raw": f"{package}: {declared_version}".strip(),
            "reason": "The dependency did not provide a resolvable registry version.",
        }
    return {
        "file": file_name,
        "manifest_type": manifest_type,
        "line": max(1, int(line or 1)),
        "package": package.strip(),
        "ecosystem": ecosystem,
        "declared_version": declared_version.strip(),
        "version": normalized_version,
        "version_kind": version_kind,
        "dependency_section": section,
    }, None


def parse_python_requirement_entry(
    file_name: str, manifest_type: str, raw: str, line: int = 1, section: str = ""
) -> tuple[dict | None, dict | None]:
    entry = str(raw or "").split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([~^=<>!]{0,2}\s*[^\s,]+)?", entry)
    if not match:
        return None, {"file": file_name, "line": line, "raw": entry, "reason": "Invalid Python dependency entry."}
    package = normalize_python_package_name(match.group(1) or "")
    version = str(match.group(2) or "").replace(" ", "")
    return dependency_record(file_name, manifest_type, package, "PyPI", version, line, section)


def parse_pyproject_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies: list[dict] = []
    skipped: list[dict] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return [], [{"file": file_name, "line": 1, "raw": "", "reason": "pyproject.toml is not valid TOML."}]

    project = data.get("project") if isinstance(data, dict) else {}
    entries: list[tuple[str, str]] = []
    if isinstance(project, dict):
        entries.extend(("project.dependencies", item) for item in project.get("dependencies", []) if isinstance(item, str))
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for group, values in optional.items():
                entries.extend((f"project.optional-dependencies.{group}", item) for item in values if isinstance(item, str))
    for section, raw in entries:
        record, skip = parse_python_requirement_entry(file_name, "pyproject.toml", raw, 1, section)
        (dependencies if record else skipped).append(record or skip)

    poetry = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}) if isinstance(data, dict) else {}
    if isinstance(poetry, dict):
        for package, spec in poetry.items():
            if str(package).lower() == "python":
                continue
            raw_version = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
            record, skip = dependency_record(
                file_name, "pyproject.toml", str(package), "PyPI", str(raw_version), 1, "tool.poetry.dependencies"
            )
            (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_python_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    try:
        data = tomllib.loads(content)
    except Exception:
        return [], [{"file": file_name, "line": 1, "raw": "", "reason": f"{Path(file_name).name} is not valid TOML."}]
    packages = data.get("package", []) if isinstance(data, dict) else []
    if isinstance(packages, dict):
        packages = [packages]
    dependencies, skipped = [], []
    for item in packages if isinstance(packages, list) else []:
        if not isinstance(item, dict):
            continue
        record, skip = dependency_record(
            file_name, Path(file_name).name.lower(), str(item.get("name") or ""), "PyPI", str(item.get("version") or "")
        )
        (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_npm_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    try:
        data = json.loads(content)
    except Exception:
        return [], [{"file": file_name, "line": 1, "raw": "", "reason": "npm lockfile is not valid JSON."}]
    dependencies, skipped = [], []
    packages = data.get("packages") or {}
    if isinstance(packages, dict):
        for path, item in packages.items():
            if not path or not isinstance(item, dict):
                continue
            package = str(item.get("name") or str(path).rsplit("node_modules/", 1)[-1]).strip()
            version = str(item.get("version") or "")
            record, skip = dependency_record(file_name, Path(file_name).name.lower(), package, "npm", version, 1, "packages")
            (dependencies if record else skipped).append(record or skip)
    elif isinstance(data.get("dependencies"), dict):
        for package, item in data["dependencies"].items():
            version = str(item.get("version") or "") if isinstance(item, dict) else str(item)
            record, skip = dependency_record(file_name, Path(file_name).name.lower(), str(package), "npm", version, 1, "dependencies")
            (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_yarn_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies, skipped = [], []
    current_names: list[str] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        if raw_line and not raw_line[0].isspace() and raw_line.rstrip().endswith(":"):
            header = raw_line.rstrip()[:-1]
            current_names = []
            for selector in re.split(r",\s*", header):
                selector = selector.strip().strip('"\'')
                match = re.match(r"^(@[^/]+/[^@]+|[^@]+)@", selector)
                if match:
                    current_names.append(match.group(1))
        version_match = re.match(r"^\s+version\s+[\"']?([^\"'\s]+)", raw_line)
        if version_match and current_names:
            for package in current_names:
                record, skip = dependency_record(file_name, "yarn.lock", package, "npm", version_match.group(1), line_number)
                (dependencies if record else skipped).append(record or skip)
            current_names = []
    return dependencies, skipped


def parse_pnpm_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies, skipped = [], []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        match = re.match(r"^\s{2,}['\"]?/?(@?[^@:'\"\s]+(?:/[^@:'\"\s]+)?)@([^:'\"\s()]+)(?:\([^)]*\))?['\"]?:\s*$", raw_line)
        if not match:
            continue
        record, skip = dependency_record(file_name, "pnpm-lock.yaml", match.group(1), "npm", match.group(2), line_number)
        (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_go_mod_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies, skipped = [], []
    in_require = False
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        record, skip = dependency_record(file_name, "go.mod", parts[0], "Go", parts[1], line_number)
        (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_cargo_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    try:
        data = tomllib.loads(content)
    except Exception:
        return [], [{"file": file_name, "line": 1, "raw": "", "reason": "Cargo.lock is not valid TOML."}]
    dependencies, skipped = [], []
    for item in data.get("package", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict) or str(item.get("source") or "").startswith("git+"):
            continue
        record, skip = dependency_record(file_name, "Cargo.lock", str(item.get("name") or ""), "crates.io", str(item.get("version") or ""))
        (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_composer_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    try:
        data = json.loads(content)
    except Exception:
        return [], [{"file": file_name, "line": 1, "raw": "", "reason": "composer.lock is not valid JSON."}]
    dependencies, skipped = [], []
    for section in ("packages", "packages-dev"):
        for item in data.get(section, []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            record, skip = dependency_record(file_name, "composer.lock", str(item.get("name") or ""), "Packagist", str(item.get("version") or ""), 1, section)
            (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def parse_gemfile_lock_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies, skipped = [], []
    in_specs = False
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        if raw_line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and raw_line and not raw_line.startswith("    "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", raw_line)
        if not match:
            continue
        record, skip = dependency_record(file_name, "Gemfile.lock", match.group(1), "RubyGems", match.group(2), line_number)
        (dependencies if record else skipped).append(record or skip)
    return dependencies, skipped


def dedupe_dependencies(dependencies: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple] = set()

    for dep in dependencies:
        key = (
            dep.get("file", ""),
            dep.get("package", "").lower(),
            dep.get("ecosystem", ""),
            dep.get("version", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dep)

    return deduped


def fetch_json(url: str, method: str = "GET", payload: dict | None = None) -> dict:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    data = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    with urllib.request.urlopen(request, context=ssl_context, timeout=20) as response:
        raw = response.read().decode("utf-8", errors="ignore")
        if not raw.strip():
            return {}
        return json.loads(raw)


def query_osv_batch(dependencies: list[dict]) -> list[dict]:
    if not dependencies:
        return []

    results: list[dict] = []

    for start in range(0, len(dependencies), OSV_BATCH_SIZE):
        chunk = dependencies[start:start + OSV_BATCH_SIZE]
        payload = {
            "queries": [
                {
                    "package": {
                        "name": dep["package"],
                        "ecosystem": dep["ecosystem"],
                    },
                    "version": dep["version"],
                }
                for dep in chunk
            ]
        }

        batch_response = fetch_json(OSV_API_BATCH_URL, method="POST", payload=payload)
        batch_results = batch_response.get("results", [])

        for dep, item in zip(chunk, batch_results):
            results.append({
                "dependency": dep,
                "vuln_refs": item.get("vulns", []) if isinstance(item, dict) else [],
            })

    return results


def fetch_osv_vulnerability(osv_id: str, cache: dict[str, dict]) -> dict | None:
    if osv_id in cache:
        return cache[osv_id]

    try:
        url = OSV_VULN_URL_TEMPLATE.format(osv_id=quote(osv_id, safe=""))
        vuln = fetch_json(url)
        cache[osv_id] = vuln
        return vuln
    except Exception:
        cache[osv_id] = {}
        return None


def extract_osv_severity_label(vuln: dict) -> str:
    for affected in vuln.get("affected", []) or []:
        ecosystem_specific = affected.get("ecosystem_specific", {}) or {}
        severity = ecosystem_specific.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity.strip().upper()

    database_specific = vuln.get("database_specific", {}) or {}
    db_severity = database_specific.get("severity")
    if isinstance(db_severity, str) and db_severity.strip():
        return db_severity.strip().upper()

    severity_items = vuln.get("severity", []) or []
    for item in severity_items:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score", "")).upper()
        if "CRITICAL" in score:
            return "CRITICAL"
        if "HIGH" in score:
            return "HIGH"
        if "MEDIUM" in score:
            return "MEDIUM"
        if "LOW" in score:
            return "LOW"

    return "UNKNOWN"


def extract_osv_fixed_versions(vuln: dict) -> list[str]:
    fixed_versions: list[str] = []

    for affected in vuln.get("affected", []) or []:
        for range_item in affected.get("ranges", []) or []:
            for event in range_item.get("events", []) or []:
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed.strip():
                    fixed_versions.append(fixed.strip())

    deduped: list[str] = []
    seen: set[str] = set()

    for version in fixed_versions:
        if version in seen:
            continue
        seen.add(version)
        deduped.append(version)

    return deduped[:5]


def build_dependency_guidance(severity_label: str, version_kind: str) -> dict:
    why_risky = "This dependency is associated with a published vulnerability record, which may expose the application even if your own code looks safe."
    what_to_check = "Confirm whether this exact package version is really installed in production, whether the vulnerable code path is reachable, and whether a fixed version is available."
    when_legitimate = "Occasionally a repo can contain an older declared version that is overridden in CI, pinned elsewhere, or not actually shipped."
    suggested_fix = "Upgrade to a fixed version if available, pin the dependency explicitly, and review release notes for breaking changes before deployment."

    if version_kind == "range-normalized":
        what_to_check += " This manifest used a version range that was normalized to its base version for scanning, so the actual installed version may differ."

    if severity_label == "CRITICAL":
        why_risky = "This dependency maps to a critical published vulnerability and deserves immediate manual review before trust or deployment."
    elif severity_label == "HIGH":
        why_risky = "This dependency maps to a high-severity published vulnerability and should be reviewed before trust or deployment."

    return {
        "why_risky": why_risky,
        "what_to_check": what_to_check,
        "when_legitimate": when_legitimate,
        "suggested_fix": suggested_fix,
    }


def build_dependency_finding(dep: dict, vuln: dict) -> dict:
    severity_label = extract_osv_severity_label(vuln)
    base_points = DEPENDENCY_SEVERITY_POINTS.get(severity_label, DEPENDENCY_SEVERITY_POINTS["UNKNOWN"])
    path_weight = dependency_file_weight(dep.get("file", ""))
    weighted_points = round(base_points * path_weight, 2)

    guidance = build_dependency_guidance(severity_label, dep.get("version_kind", "exact"))
    fixed_versions = extract_osv_fixed_versions(vuln)

    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or "").strip()
    explanation = summary or details or "Known vulnerability record returned for this dependency."

    aliases = []
    for alias in vuln.get("aliases", []) or []:
        if isinstance(alias, str) and alias.strip():
            aliases.append(alias.strip())

    if path_weight < 1.0:
        explanation = (
            f"{explanation} This manifest appears in a lower-priority path for repo scoring "
            f"(weight {path_weight}), so its repo-level impact was reduced."
        )

    return {
        "type": "dependency_vulnerability",
        "file": dep.get("file", ""),
        "manifest_type": dep.get("manifest_type", ""),
        "line": dep.get("line", 1),
        "package": dep.get("package", ""),
        "ecosystem": dep.get("ecosystem", ""),
        "declared_version": dep.get("declared_version", ""),
        "version": dep.get("version", ""),
        "version_kind": dep.get("version_kind", "exact"),
        "dependency_section": dep.get("dependency_section", ""),
        "id": vuln.get("id", ""),
        "aliases": aliases[:5],
        "message": f"Known vulnerable dependency detected: {dep.get('package', '')} ({dep.get('declared_version', dep.get('version', ''))})",
        "severity_label": severity_label,
        "severity": float(weighted_points),
        "base_severity": float(base_points),
        "path_weight": path_weight,
        "explanation": explanation[:700],
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
        "fixed_versions": fixed_versions,
        "why_risky": guidance["why_risky"],
        "what_to_check": guidance["what_to_check"],
        "when_legitimate": guidance["when_legitimate"],
        "suggested_fix": guidance["suggested_fix"],
    }


def registry_package_exists(dep: dict) -> bool | None:
    ecosystem = str(dep.get("ecosystem") or "")
    package = str(dep.get("package") or "").strip()
    cache_key = (ecosystem.lower(), package.lower())
    with PACKAGE_LOOKUP_LOCK:
        if cache_key in PACKAGE_LOOKUP_CACHE:
            return PACKAGE_LOOKUP_CACHE[cache_key]
    if not package or ecosystem not in {"PyPI", "npm"}:
        return None
    if ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{quote(package, safe='')}/json"
    else:
        url = f"https://registry.npmjs.org/{quote(package, safe='@/') }"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "AI-Code-Audit"})
    result: bool | None = None
    try:
        with urllib.request.urlopen(request, timeout=5, context=ssl.create_default_context(cafile=certifi.where())) as response:
            result = 200 <= int(response.status) < 300
    except urllib.error.HTTPError as exc:
        result = False if exc.code == 404 else None
    except Exception:
        result = None
    with PACKAGE_LOOKUP_LOCK:
        PACKAGE_LOOKUP_CACHE[cache_key] = result
    return result


def build_dependency_reputation_findings(dependencies: list[dict], skipped: list[dict]) -> list[dict]:
    findings = []
    lookup_candidates = dependencies[:MAX_PACKAGE_REPUTATION_LOOKUPS]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(lookup_candidates)))) as executor:
        existence = list(executor.map(registry_package_exists, lookup_candidates)) if lookup_candidates else []
    for dep, exists in zip(lookup_candidates, existence):
        normalized = str(dep.get("package") or "").lower().replace("_", "-")
        expected_name = SUSPICIOUS_PACKAGE_TYPOS.get(normalized)
        if expected_name:
            findings.append({
                "type": "dependency_typosquatting",
                "file": dep.get("file", ""), "line": dep.get("line", 1),
                "package": dep.get("package", ""), "ecosystem": dep.get("ecosystem", ""),
                "message": f"Possible dependency typo: {dep.get('package')} resembles {expected_name}",
                "severity": 18.0,
                "explanation": "A misspelled popular package name can install an unrelated or malicious package.",
                "suggested_fix": f"Verify the intended package. If appropriate, replace it with {expected_name} and review the lockfile diff.",
                "reputation_status": "possible_typosquat",
            })
        elif exists is False:
            findings.append({
                "type": "dependency_unverified",
                "file": dep.get("file", ""), "line": dep.get("line", 1),
                "package": dep.get("package", ""), "ecosystem": dep.get("ecosystem", ""),
                "message": f"Package was not found in the official {dep.get('ecosystem')} registry: {dep.get('package')}",
                "severity": 10.0,
                "explanation": "The dependency may be hallucinated, misspelled, private, removed, or sourced from a registry this scan cannot see.",
                "suggested_fix": "Confirm the exact package name and registry with the project owner before installing it.",
                "reputation_status": "not_found",
            })
    for item in skipped:
        raw = str(item.get("raw") or "")
        if re.search(r"(?:git\+|github:|https?://|file:|link:)", raw, re.IGNORECASE):
            findings.append({
                "type": "dependency_unpinned_source",
                "file": item.get("file", ""), "line": item.get("line", 1),
                "package": raw[:160], "ecosystem": "source",
                "message": "Dependency comes from a non-registry or local source",
                "severity": 8.0,
                "explanation": "Source dependencies can change outside normal registry controls and are harder to verify reproducibly.",
                "suggested_fix": "Pin an immutable commit and verify the repository owner, release signature, and reviewed source.",
                "reputation_status": "unverified_source",
            })
    return findings


def summarize_dependency_findings(findings: list[dict]) -> dict:
    unique_packages = {
        (item.get("package", "").lower(), item.get("version", ""))
        for item in findings
    }
    unique_manifests = {item.get("file", "") for item in findings if item.get("file")}
    unique_ids = {item.get("id", "") for item in findings if item.get("id")}

    return {
        "advisory_count": len(findings),
        "unique_package_versions": len(unique_packages),
        "unique_manifest_files": len(unique_manifests),
        "unique_vulnerability_ids": len(unique_ids),
    }


def analyze_dependency_manifests(zip_file: zipfile.ZipFile) -> dict:
    all_manifest_files = [
        name for name in zip_file.namelist()
        if not name.endswith("/") and is_dependency_manifest(name)
    ]
    all_manifest_files.sort(key=lambda name: (dependency_file_weight(name) * -1, name.lower()))
    manifest_files = all_manifest_files[:MAX_DEPENDENCY_MANIFESTS]

    all_dependencies: list[dict] = []
    skipped_dependencies: list[dict] = []
    manifest_scan_errors: list[str] = []

    if len(all_manifest_files) > len(manifest_files):
        manifest_scan_errors.append(
            f"Skipped {len(all_manifest_files) - len(manifest_files)} dependency manifests beyond the analysis limit."
        )

    for file_name in manifest_files:
        if zip_file.getinfo(file_name).file_size > MAX_DEPENDENCY_MANIFEST_BYTES:
            manifest_scan_errors.append(f"Skipped oversized dependency manifest: {file_name}")
            continue
        try:
            with zip_file.open(file_name) as file:
                content = file.read().decode("utf-8", errors="ignore")
        except Exception:
            manifest_scan_errors.append(f"Could not read dependency manifest: {file_name}")
            continue

        lower_name = file_name.lower()

        if lower_name.endswith("requirements.txt"):
            deps, skipped = parse_requirements_manifest(file_name, content)
        elif lower_name.endswith("package.json"):
            deps, skipped = parse_package_json_manifest(file_name, content)
        elif lower_name.endswith("pyproject.toml"):
            deps, skipped = parse_pyproject_manifest(file_name, content)
        elif lower_name.endswith(("poetry.lock", "uv.lock")):
            deps, skipped = parse_python_lock_manifest(file_name, content)
        elif lower_name.endswith(("package-lock.json", "npm-shrinkwrap.json")):
            deps, skipped = parse_npm_lock_manifest(file_name, content)
        elif lower_name.endswith("yarn.lock"):
            deps, skipped = parse_yarn_lock_manifest(file_name, content)
        elif lower_name.endswith(("pnpm-lock.yaml", "pnpm-lock.yml")):
            deps, skipped = parse_pnpm_lock_manifest(file_name, content)
        elif lower_name.endswith("go.mod"):
            deps, skipped = parse_go_mod_manifest(file_name, content)
        elif lower_name.endswith("cargo.lock"):
            deps, skipped = parse_cargo_lock_manifest(file_name, content)
        elif lower_name.endswith("composer.lock"):
            deps, skipped = parse_composer_lock_manifest(file_name, content)
        elif lower_name.endswith("gemfile.lock"):
            deps, skipped = parse_gemfile_lock_manifest(file_name, content)
        else:
            deps, skipped = [], []

        all_dependencies.extend(deps)
        skipped_dependencies.extend(skipped)

    deduped_dependencies = dedupe_dependencies(all_dependencies)
    reputation_findings = build_dependency_reputation_findings(deduped_dependencies, skipped_dependencies)

    try:
        osv_matches = query_osv_batch(deduped_dependencies)
    except Exception as exc:
        reputation_risk = round(min(25.0, sum(float(item["severity"]) for item in reputation_findings) * 0.75), 2)
        return {
            "manifests_scanned": len(manifest_files),
            "dependencies_parsed": len(deduped_dependencies),
            "dependencies_queried": 0,
            "dependencies_skipped": skipped_dependencies,
            "dependency_findings": reputation_findings,
            "dependency_reputation_findings": reputation_findings,
            "dependency_risk_points": reputation_risk,
            "dependency_summary_lines": [f"Dependency vulnerability lookup failed: {exc}"],
            "dependency_scan_error": "Dependency vulnerability lookup failed during the repo scan.",
            "dependency_rollup": {
                "advisory_count": 0,
                "unique_package_versions": len({item.get("package") for item in reputation_findings}),
                "unique_manifest_files": len({item.get("file") for item in reputation_findings}),
                "unique_vulnerability_ids": 0,
            },
        }

    vuln_cache: dict[str, dict] = {}
    dependency_findings: list[dict] = []

    for match in osv_matches:
        dep = match["dependency"]
        vuln_refs = match.get("vuln_refs", []) or []

        for vuln_ref in vuln_refs:
            osv_id = vuln_ref.get("id") if isinstance(vuln_ref, dict) else None
            if not osv_id:
                continue

            vuln = fetch_osv_vulnerability(osv_id, vuln_cache)
            if not vuln:
                continue

            dependency_findings.append(build_dependency_finding(dep, vuln))

    advisory_count = len(dependency_findings)
    dependency_findings.extend(reputation_findings)

    dependency_findings.sort(
        key=lambda item: (-float(item.get("severity", 0)), item.get("package", "").lower(), item.get("id", ""))
    )

    dependency_risk_points = round(min(35.0, sum(float(item["severity"]) for item in dependency_findings) * 0.75), 2)
    rollup = summarize_dependency_findings(dependency_findings)

    summary_lines = []
    if manifest_files:
        summary_lines.append(f"Scanned {len(manifest_files)} dependency manifest file(s).")
    if deduped_dependencies:
        summary_lines.append(f"Parsed {len(deduped_dependencies)} dependency entries with resolvable versions.")
    if skipped_dependencies:
        summary_lines.append(f"Skipped {len(skipped_dependencies)} dependency entries with complex or indirect version specs.")
    if advisory_count:
        summary_lines.append(
            f"Found {advisory_count} dependency advisory finding(s) across "
            f"{rollup['unique_package_versions']} package/version pair(s)."
        )
    elif manifest_files:
        summary_lines.append("No known dependency vulnerabilities were found in the queried manifest versions.")

    summary_lines.extend(manifest_scan_errors)
    if reputation_findings:
        summary_lines.append(f"Found {len(reputation_findings)} package reputation or source-integrity warning(s).")

    return {
        "manifests_scanned": len(manifest_files),
        "dependencies_parsed": len(deduped_dependencies),
        "dependencies_queried": len(deduped_dependencies),
        "dependencies_skipped": skipped_dependencies,
        "dependency_findings": dependency_findings,
        "dependency_reputation_findings": reputation_findings,
        "dependency_risk_points": dependency_risk_points,
        "dependency_summary_lines": summary_lines,
        "dependency_scan_error": None,
        "dependency_rollup": {**rollup, "advisory_count": advisory_count, "reputation_finding_count": len(reputation_findings)},
    }


def build_focused_code_blocks(code: str, flags: list[dict], context_lines: int = 2) -> list[dict]:
    if not code or not flags:
        return []

    code_lines = code.splitlines()
    flagged_lines = sorted({int(flag["line"]) for flag in flags if isinstance(flag.get("line"), int)})

    if not flagged_lines:
        return []

    windows: list[list[int]] = []
    current_start = max(1, flagged_lines[0] - context_lines)
    current_end = min(len(code_lines), flagged_lines[0] + context_lines)

    for line_number in flagged_lines[1:]:
        start = max(1, line_number - context_lines)
        end = min(len(code_lines), line_number + context_lines)

        if start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            windows.append([current_start, current_end])
            current_start, current_end = start, end

    windows.append([current_start, current_end])

    blocks = []
    flagged_set = set(flagged_lines)

    for start, end in windows:
        lines = []
        for line_no in range(start, end + 1):
            content = code_lines[line_no - 1] if 0 <= line_no - 1 < len(code_lines) else ""
            lines.append({
                "line": line_no,
                "content": content,
                "flagged": line_no in flagged_set,
            })

        blocks.append({
            "start_line": start,
            "end_line": end,
            "lines": lines,
        })

    return blocks


def infer_code_filename(code: str) -> str:
    lowered = code.lower()
    if re.search(r"<\?(?:php|=)", lowered):
        return "snippet.php"
    if re.search(r"\b(?:const|let|var)\s+\w+|=>|require\s*\(", code):
        return "snippet.js"
    if re.search(r"^\s*(?:select|insert|update|delete|create\s+table)\b", lowered, re.MULTILINE):
        return "snippet.sql"
    if re.search(r"^\s*(?:#!/bin/(?:ba)?sh|curl\s|wget\s)", lowered, re.MULTILINE):
        return "snippet.sh"
    if re.search(r"<\/?(?:html|main|script|div|body|head)\b", lowered):
        return "snippet.html"
    return "snippet.py"


def run_semgrep_scan(code: str, filename: str | None = None) -> dict:
    """Run the local, pinned Semgrep rules without sending code over the network."""
    started = time.monotonic()
    executable = shutil.which("semgrep")
    if not SEMGREP_ENABLED:
        return {"name": "semgrep", "status": "disabled", "findings": [], "duration_ms": 0}
    if not executable or not SEMGREP_CONFIG_PATH.exists():
        return {"name": "semgrep", "status": "unavailable", "findings": [], "duration_ms": 0}

    safe_name = Path(filename or infer_code_filename(code)).name
    attempts = []
    try:
        with tempfile.TemporaryDirectory(prefix="ai-code-audit-") as temp_dir:
            target = Path(temp_dir) / safe_name
            target.write_text(code, encoding="utf-8")
            command = [
                executable, "scan", "--json", "--metrics=off", "--quiet",
                "--jobs", "1", "--timeout", "5", "--max-memory", "512",
                "--config", str(SEMGREP_CONFIG_PATH), str(target),
            ]
            completed = None
            deadline = started + SEMGREP_BUDGET_SECONDS
            for attempt_number in (1, 2):
                remaining = max(0, deadline - time.monotonic())
                if remaining < 2:
                    break
                timeout_seconds = min(
                    SEMGREP_FIRST_ATTEMPT_SECONDS if attempt_number == 1 else remaining,
                    remaining,
                )
                attempt_started = time.monotonic()
                try:
                    completed = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        check=False,
                        env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
                    )
                    attempts.append({"attempt": attempt_number, "status": "complete", "duration_ms": round((time.monotonic() - attempt_started) * 1000)})
                    break
                except subprocess.TimeoutExpired:
                    attempts.append({"attempt": attempt_number, "status": "timeout", "duration_ms": round((time.monotonic() - attempt_started) * 1000)})
            if completed is None:
                return {
                    "name": "semgrep", "status": "timeout", "findings": [],
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "attempts": attempts, "fallback_used": True,
                    "message": "Semgrep exceeded its scan budget; the behavior engine still completed.",
                }
        if completed.returncode not in {0, 1}:
            raise RuntimeError("Semgrep returned a non-scan exit status")
        payload = json.loads(completed.stdout or "{}")
        findings = []
        for item in payload.get("results") or []:
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            raw_severity = str(extra.get("severity") or "WARNING").upper()
            severity = {"ERROR": 18, "WARNING": 10, "INFO": 4}.get(raw_severity, 10)
            findings.append({
                "engine": "semgrep",
                "rule_id": item.get("check_id") or "semgrep-rule",
                "type": "semgrep",
                "pattern": item.get("check_id") or "semgrep-rule",
                "line": ((item.get("start") or {}).get("line")),
                "message": extra.get("message") or "Semgrep detected code that needs review.",
                "explanation": metadata.get("explanation") or extra.get("message") or "A structural code rule matched this line.",
                "severity": severity,
                "confidence": str(metadata.get("confidence") or "medium").lower(),
            })
        return {
            "name": "semgrep",
            "status": "complete",
            "findings": findings,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "attempts": attempts,
            "fallback_used": bool(len(attempts) > 1),
        }
    except Exception as exc:
        log_server_issue("Semgrep scan could not complete", exc)
        return {
            "name": "semgrep",
            "status": "error",
            "findings": [],
            "duration_ms": round((time.monotonic() - started) * 1000),
            "attempts": attempts,
            "fallback_used": True,
            "message": "Semgrep could not complete; the behavior engine still completed.",
        }


def build_evidence_profile(
    flags: list[dict],
    touches: list[str],
    mismatches: list,
    semgrep_findings: list[dict] | None = None,
    dependency_points: float = 0,
    coverage_partial: bool = False,
) -> list[dict]:
    semgrep_findings = semgrep_findings or []
    combined = flags + semgrep_findings
    category_patterns = {
        "execution": {"eval(", "exec(", "os.system", "subprocess", "child_process", "download_execute_chain", "obfuscated_execution", "pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "yaml.load", "dill.loads"},
        "credentials": {"environment_secret_access", "secret_exfiltration_chain"},
        "network": {"requests.post", "requests.get", "fetch(", "socket", "urllib.request.urlopen", "urllib.request.urlretrieve", "download helper"},
    }

    def category_points(category: str) -> float:
        if category == "dependencies":
            return float(dependency_points or 0)
        if category == "intent":
            return min(20.0, len(mismatches) * 5.0)
        if category == "coverage":
            return 10.0 if coverage_partial else 0.0
        total = 0.0
        for flag in combined:
            pattern = str(flag.get("pattern") or flag.get("rule_id") or "")
            flag_type = str(flag.get("type") or "")
            if category == "credentials" and flag_type in {"secret", "secret_source", "secret_exfiltration"}:
                total += float(flag.get("severity", 0) or 0)
            elif pattern in category_patterns.get(category, set()) or any(token in pattern for token in category_patterns.get(category, set())):
                total += float(flag.get("severity", 0) or 0)
        return min(100.0, round(total, 1))

    labels = {
        "execution": "Code execution",
        "credentials": "Credentials",
        "network": "Network behavior",
        "dependencies": "Dependencies",
        "intent": "Intent match",
        "coverage": "Scan coverage",
    }
    summaries = {
        "execution": "Dynamic execution, shell commands, and unsafe deserialization.",
        "credentials": "Secret access, hard-coded credentials, and credential flows.",
        "network": "Outbound requests, downloads, and externally controlled destinations.",
        "dependencies": "Known advisories found in declared packages.",
        "intent": "Whether observed behavior matches the stated purpose.",
        "coverage": "How much of the supplied code was actually analyzed.",
    }
    profile = []
    for category in labels:
        points = category_points(category)
        status = "high" if points >= 18 else "review" if points > 0 else "clear"
        signals = [
            str(flag.get("message") or flag.get("pattern") or flag.get("rule_id"))
            for flag in combined
            if category == "execution" and str(flag.get("pattern") or flag.get("rule_id") or "") in category_patterns["execution"]
        ][:3]
        if category == "intent":
            signals = [str(value) for value in mismatches[:3]]
        profile.append({
            "id": category,
            "label": labels[category],
            "status": status,
            "risk_points": points,
            "summary": summaries[category],
            "confidence": "high" if category != "intent" else "medium",
            "signals": signals,
        })
    return profile


def build_fix_previews(code: str, flags: list[dict]) -> list[dict]:
    patterns = {str(flag.get("pattern") or "") for flag in flags}
    previews = []

    def add_preview(title: str, confidence: str, pattern: str, patched: str) -> None:
        if patched == code or any(item["patched_code"] == patched for item in previews):
            return
        diff = "\n".join(difflib.unified_diff(
            code.splitlines(), patched.splitlines(), fromfile="original", tofile="safer", lineterm=""
        ))
        previews.append({
            "title": title,
            "confidence": confidence,
            "finding_pattern": pattern,
            "diff": diff,
            "patched_code": patched,
            "applies_automatically": False,
        })

    if "yaml.load" in patterns and "yaml.load" in code:
        add_preview("Use PyYAML safe loading", "high", "yaml.load", re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", code))
    if "tls_verify_disabled" in patterns:
        add_preview("Restore TLS certificate verification", "high", "tls_verify_disabled", re.sub(r"\bverify\s*=\s*False\b", "verify=True", code))
    if "debug_mode_enabled" in patterns:
        add_preview("Disable production debug mode", "high", "debug_mode_enabled", re.sub(r"\bdebug\s*=\s*True\b", "debug=False", code))
    if any(pattern in patterns for pattern in {"eval(", "exec("}) and re.search(r"\beval\s*\(", code):
        patched = re.sub(r"\beval\s*\(", "ast.literal_eval(", code)
        if not re.search(r"^\s*(?:import\s+ast|from\s+ast\s+import)", patched, re.MULTILINE):
            patched = "import ast\n" + patched
        add_preview("Parse data instead of executing it", "medium", "eval(", patched)
    return previews[:4]


def analyze_code(intent: str, code: str, plan: str = "free") -> dict:
    intent_lower = intent.lower()
    original_lines = code.splitlines()
    analysis_code = mask_non_executable_markup(code)

    line_limit = get_plan_limits(plan).get("line_limit")

    if line_limit is not None and len(original_lines) > line_limit:
        plan_name = str(plan or "free").lower()
        if plan_name == "pro":
            limit_message = f"Pro scans are limited to {line_limit} lines right now."
        else:
            limit_message = f"Free scans are limited to {line_limit} lines. Pro unlocks larger file scanning."

        return {
            "risk": "limit",
            "touches": [],
            "flags": [],
            "intent_mismatches": [],
            "behavior_summary": [],
            "summary": limit_message,
            "code": code,
            "trust_score": 0,
            "trust_badge": build_trust_badge(0, "red"),
            "risk_points": 100,
            "scan_confidence": {
                "label": "Limited",
                "lines": [
                    f"Only the first {line_limit} lines can be analyzed on this plan.",
                    "Upgrade to scan larger code files without truncation.",
                ],
            },
            "focused_code_blocks": [],
            "plan_applied": plan_name,
            "line_limit_applied": line_limit,
        }

    scannable_lines = extract_scannable_lines(analysis_code)
    code_without_comments = strip_comments(analysis_code).splitlines()
    executable_code_lines = strip_comments_and_strings(analysis_code).splitlines()
    comment_clean_scannable_lines = [
        (line_number, code_without_comments[line_number - 1] if line_number <= len(code_without_comments) else "")
        for line_number, _ in scannable_lines
    ]
    executable_scannable_lines = [
        (line_number, executable_code_lines[line_number - 1] if line_number <= len(executable_code_lines) else "")
        for line_number, _ in scannable_lines
    ]
    tainted_vars = build_taint_map(executable_scannable_lines)
    secret_variables, secret_source_flags = find_environment_secret_sources(comment_clean_scannable_lines)
    python_tree = None
    try:
        python_tree = ast.parse(analysis_code)
        python_source_parses = True
    except Exception:
        python_source_parses = False

    secret_access_expected = intent_mentions_any(
        intent_lower,
        ["credential", "credentials", "secret", "api key", "token", "password", "authenticate", "authentication", "authorization"],
    )

    regex_flags: list[dict] = []
    ast_flags: list[dict] = []
    heuristic_flags: list[dict] = []
    touches = []

    current_function_name = ""

    for line_number, line in scannable_lines:
        stripped = line.strip()

        function_match = re.match(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if function_match:
            current_function_name = function_match.group(1)

        line_without_strings = (
            executable_code_lines[line_number - 1].lower()
            if line_number <= len(executable_code_lines)
            else ""
        )

        for display_key, regex_pattern, label, base_severity in SUSPICIOUS_PATTERNS:
            if python_source_parses and display_key in PYTHON_AST_PATTERN_KEYS:
                continue
            if re.search(regex_pattern, line_without_strings):
                adjusted_severity = float(base_severity)
                extra_boost, context_note = assess_sink_context(display_key, line, tainted_vars)
                adjusted_severity += extra_boost

                explanation = explain_flag(display_key, "suspicious_behavior")

                if display_key in {"urllib.request.urlopen", "urllib.request.Request"}:
                    if current_function_name in TRUSTED_INTERNAL_NETWORK_FUNCTION_NAMES or line_is_trusted_internal_network_usage(line):
                        adjusted_severity = max(0.25, adjusted_severity - 2.0)
                        trusted_note = "This appears inside trusted internal scanner plumbing, so the severity was reduced."
                        explanation = f"{explanation} {trusted_note}"

                if context_note:
                    explanation = f"{explanation} {context_note}"

                regex_flags.append(make_flag(
                    line=line_number,
                    flag_type="suspicious_behavior",
                    pattern=display_key,
                    message=label,
                    severity=adjusted_severity,
                    explanation=explanation,
                ))

        for regex_pattern, label, severity in SECRET_PATTERNS:
            if re.search(regex_pattern, line):
                regex_flags.append(make_flag(
                    line=line_number,
                    flag_type="secret",
                    pattern=regex_pattern,
                    message=label,
                    severity=severity,
                    explanation=explain_flag(regex_pattern, "secret"),
                ))

        if re.search(r"\b(?:pip|pip3|npm|pnpm|yarn)\s+(?:install|add)\b.*(?:git\+|https?://|github:)", stripped, re.IGNORECASE):
            regex_flags.append(make_flag(
                line=line_number,
                flag_type="supply_chain",
                pattern="unverified_package_source",
                message="Package is installed directly from an external source",
                severity=9,
                explanation="Direct source installs can bypass normal registry integrity and version controls. Verify the owner and pin an immutable commit.",
            ))
        if re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|access-control-allow-origin\s*[:=]\s*['\"]?\*", stripped, re.IGNORECASE):
            regex_flags.append(make_flag(
                line=line_number,
                flag_type="insecure_default",
                pattern="wildcard_cors",
                message="CORS allows every origin",
                severity=10,
                explanation="A wildcard cross-origin policy can expose authenticated data to untrusted websites.",
            ))
        if re.search(r"\b(?:token|secret|session|nonce|password)\w*\s*=.*\brandom\.", stripped, re.IGNORECASE):
            regex_flags.append(make_flag(
                line=line_number,
                flag_type="insecure_default",
                pattern="weak_random_secret",
                message="Security-sensitive value may use non-cryptographic randomness",
                severity=14,
                explanation="Python's random module is predictable and should not generate tokens, secrets, nonces, or passwords.",
            ))

    try:
        ast_flags = analyze_python_ast(analysis_code, intent)
    except Exception:
        ast_flags = []

    try:
        heuristic_flags = add_multi_signal_heuristics(scannable_lines, python_tree)
    except Exception:
        heuristic_flags = []

    try:
        secret_flow_flags = add_secret_flow_heuristics(
            comment_clean_scannable_lines,
            secret_variables,
            authentication_expected=secret_access_expected,
        )
    except Exception:
        secret_flow_flags = []

    flags = [
        flag
        for flag in dedupe_flags(regex_flags + ast_flags + heuristic_flags + secret_source_flags + secret_flow_flags)
        if float(flag.get("severity", 0) or 0) > 0
    ]

    has_secret_exfiltration = any(
        flag.get("pattern") == "secret_exfiltration_chain" for flag in flags
    )
    for flag in flags:
        if flag.get("pattern") == "environment_secret_access":
            if has_secret_exfiltration:
                flag["severity"] = 5.0
                flag["explanation"] += (
                    " The credential source is part of the separately scored transmission chain, "
                    "so it is not counted as a second major risk."
                )
            elif secret_access_expected:
                flag["severity"] = 5.0
                flag["explanation"] += " The stated intent appears to expect credential access, so this finding was reduced."
            else:
                flag["severity"] = 15.0
                flag["explanation"] += (
                    " Credential access was not stated in the intent, so it still requires review."
                )
        elif flag.get("pattern") == "secret_exfiltration_chain":
            flag["severity"] = max(32.0, float(flag.get("severity", 0) or 0))
    risk_points = aggregate_flag_risk_points(flags)

    cleaned_code = "\n".join(line for _, line in executable_scannable_lines)
    cleaned_code_lower = cleaned_code.lower()

    if re.search(
        r"(?<![\w.])fetch\s*\(|\brequests\.(get|post|put|delete|patch|request)\s*\(|\burllib\.request\.(urlopen|request|urlretrieve)\b|\bsocket\.(?:socket|create_connection)\s*\(|\b(?:curl|wget)\s+",
        cleaned_code_lower,
    ):
        touches.append("network")

    if re.search(
        r"(?<![\w.])open\s*\(|\.write\s*\(|read_text\s*\(|write_text\s*\(|read_bytes\s*\(|write_bytes\s*\(",
        cleaned_code_lower,
    ):
        touches.append("files")

    if re.search(
        r"(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(|\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|\bchild_process\.(?:exec|execFile|spawn|fork)\s*\(",
        cleaned_code_lower,
    ):
        touches.append("system execution")

    if re.search(
        r"\b__import__\s*\(|\bimportlib\.import_module\s*\(",
        cleaned_code_lower,
    ):
        touches.append("dynamic imports")

    if re.search(
        r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\bdill\.loads?\s*\(|\byaml\.load\s*\(|\bshelve\.open\s*\(",
        cleaned_code_lower,
    ):
        touches.append("deserialization")

    if re.search(
        r"\bbase64\b|\bbytes\.fromhex\s*\(|\bchr\s*\(",
        cleaned_code_lower,
    ):
        touches.append("encoding")

    if re.search(r"\b(?:sentry_sdk\.init|posthog\.capture|analytics\.track|mixpanel\.track)\s*\(", cleaned_code_lower):
        touches.append("telemetry")

    if re.search(r"\bwinreg\.(?:setvalue|setvalueex|createkey)\s*\(|\b(?:crontab|schtasks|launchctl)\b", cleaned_code_lower):
        touches.append("persistence")

    if any(flag["type"] in {"secret", "secret_source", "secret_exfiltration"} for flag in flags):
        touches.append("secrets")

    touches = list(dict.fromkeys(touches))

    mismatch_flags = []
    meaningful_intent = has_meaningful_intent(intent)

    if meaningful_intent and "network" in touches and not intent_mentions_any(
        intent_lower, ["api", "fetch", "request", "http", "network", "online", "web", "repo", "github", "download"]
    ):
        mismatch_flags.append("Code uses network behavior not clearly mentioned in the intent.")
        risk_points += 3.0

    if meaningful_intent and "files" in touches and not intent_mentions_any(
        intent_lower, ["file", "save", "write", "export", "download", "upload", "repo", "github", "read", "load", "config"]
    ):
        mismatch_flags.append("Code reads or writes files not clearly mentioned in the intent.")
        risk_points += 1.0

    if meaningful_intent and "system execution" in touches and not intent_mentions_any(
        intent_lower, ["terminal", "shell", "command", "system", "script", "execute", "cli"]
    ):
        mismatch_flags.append("Code runs system-level commands not clearly mentioned in the intent.")
        risk_points += 2.5

    if meaningful_intent and "dynamic imports" in touches and not intent_mentions_any(
        intent_lower, ["plugin", "module", "import", "extension", "dynamic"]
    ):
        mismatch_flags.append("Code dynamically loads modules in a way that is not clearly mentioned in the intent.")
        risk_points += 2.0

    if meaningful_intent and "deserialization" in touches and not intent_mentions_any(
        intent_lower, ["pickle", "yaml", "deserialize", "serialization", "load saved model", "cache"]
    ):
        mismatch_flags.append("Code deserializes data in a way that is not clearly mentioned in the intent.")
        risk_points += 2.0

    if meaningful_intent and "telemetry" in touches and not intent_mentions_any(
        intent_lower, ["telemetry", "analytics", "monitoring", "metrics", "logging", "sentry", "tracking"]
    ):
        mismatch_flags.append("Code sends telemetry or analytics that was not clearly mentioned in the intent.")
        risk_points += 6.0

    if meaningful_intent and "persistence" in touches and not intent_mentions_any(
        intent_lower, ["startup", "scheduled", "scheduler", "service", "persist", "registry", "cron"]
    ):
        mismatch_flags.append("Code may create persistence that was not requested.")
        risk_points += 12.0

    has_literal_or_exfiltrated_secret = any(
        flag.get("type") in {"secret", "secret_exfiltration"} for flag in flags
    )
    if "secrets" in touches and (has_literal_or_exfiltrated_secret or not secret_access_expected):
        mismatch_flags.append("Code appears to contain secrets or credentials, which may be unsafe.")
        if not has_secret_exfiltration:
            risk_points += 8

    behavior_summary = []

    if "network" in touches:
        behavior_summary.append("Makes outbound network requests or downloads remote content.")

    if "files" in touches:
        behavior_summary.append("Reads or writes local files.")

    if "system execution" in touches:
        behavior_summary.append("Executes system-level commands.")

    if "dynamic imports" in touches:
        behavior_summary.append("Dynamically loads code or modules at runtime.")

    if "deserialization" in touches:
        behavior_summary.append("Loads serialized data that may be unsafe if the source is untrusted.")

    if "encoding" in touches:
        behavior_summary.append("Uses encoded data; this is not dangerous by itself unless the decoded value is executed or otherwise trusted blindly.")

    if "telemetry" in touches:
        behavior_summary.append("Initializes or sends telemetry or analytics events.")

    if "persistence" in touches:
        behavior_summary.append("May configure the code to persist or run again later.")

    if "secrets" in touches:
        behavior_summary.append("Contains possible credentials or secret values.")

    if any(flag["pattern"] == "download_execute_chain" for flag in flags):
        behavior_summary.append("May download remote content and then execute it.")

    if any(flag["pattern"] == "obfuscated_execution" for flag in flags):
        behavior_summary.append("May decode hidden content and then execute it.")

    if mismatch_flags:
        behavior_summary.append("Includes behavior that may not match the stated request.")

    if not behavior_summary:
        behavior_summary.append("No obvious risky behavior was detected in this scan.")

    risk_points = round(risk_points, 2)
    risk = risk_from_points(risk_points)
    trust_score = calculate_trust_score_from_points(risk_points)
    trust_badge = build_trust_badge(trust_score, risk)
    focused_code_blocks = build_focused_code_blocks(code, flags, context_lines=2)

    return {
        "risk": risk,
        "touches": touches,
        "flags": flags,
        "intent_mismatches": mismatch_flags,
        "behavior_summary": behavior_summary,
        "summary": f"{len(flags)} review findings detected and {len(mismatch_flags)} intent mismatch warnings",
        "code": code,
        "trust_score": trust_score,
        "trust_badge": trust_badge,
        "risk_points": risk_points,
        "focused_code_blocks": focused_code_blocks,
    }


def analyze_code_product(intent: str, code: str, plan: str = "free", filename: str | None = None) -> dict:
    result = analyze_code(intent, code, plan=plan)
    scan_id = hashlib.sha256(f"{intent}\0{code}".encode("utf-8", errors="ignore")).hexdigest()[:24]
    result["scan_id"] = scan_id
    for finding in result.get("flags") or []:
        finding["finding_id"] = hashlib.sha256(
            f"behavior\0{finding.get('pattern')}\0{finding.get('line')}\0{finding.get('message')}".encode("utf-8")
        ).hexdigest()[:20]
    semgrep = run_semgrep_scan(code, filename=filename)
    semgrep_findings = semgrep.get("findings") or []
    for finding in semgrep_findings:
        finding["finding_id"] = hashlib.sha256(
            f"semgrep\0{finding.get('rule_id')}\0{finding.get('line')}\0{finding.get('message')}".encode("utf-8")
        ).hexdigest()[:20]
    result["engine_findings"] = semgrep_findings
    result["analysis_engines"] = [
        {"name": "behavior", "status": "complete", "findings": len(result.get("flags") or [])},
        {"name": "semgrep", "status": semgrep.get("status"), "findings": len(semgrep_findings), "duration_ms": semgrep.get("duration_ms", 0), "attempts": semgrep.get("attempts", []), "fallback_used": bool(semgrep.get("fallback_used")), "message": semgrep.get("message", "")},
    ]
    effective_filename = filename or infer_code_filename(code)
    result["scanner_version"] = SCANNER_VERSION
    result["verdict"] = build_action_verdict(
        str(result.get("risk") or "limited"),
        int(result.get("trust_score", 0) or 0),
        insufficient=result.get("risk") in {"limit", "limited"},
    )
    result["coverage"] = build_code_coverage(code, effective_filename, str(semgrep.get("status") or "unavailable"))
    result["scan_confidence"] = build_scan_confidence(
        "code",
        code_line_count=len(code.splitlines()),
        line_limit_applied=get_plan_limits(plan).get("line_limit"),
        was_limited=result.get("risk") in {"limit", "limited"},
    )
    result["evidence"] = build_evidence_profile(
        result.get("flags") or [],
        result.get("touches") or [],
        result.get("intent_mismatches") or [],
        semgrep_findings=semgrep_findings,
    )
    result["fix_previews"] = build_fix_previews(code, result.get("flags") or [])
    result["dynamic_sandbox"] = {
        "status": "not_enabled",
        "reason": "Untrusted code is never executed inside the web service.",
    }
    return result


def result_to_sarif(result: dict, filename: str = "snippet.py") -> dict:
    all_findings = list(result.get("flags") or []) + list(result.get("engine_findings") or [])
    rules = {}
    sarif_results = []
    for finding in all_findings:
        rule_id = str(finding.get("rule_id") or finding.get("pattern") or finding.get("type") or "audit-finding")
        rule_id = re.sub(r"[^A-Za-z0-9._-]", "-", rule_id)[:120]
        message = str(finding.get("message") or "Code behavior requires review.")
        severity = float(finding.get("severity", 0) or 0)
        level = "error" if severity >= 18 else "warning" if severity >= 8 else "note"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": message[:200]},
            "help": {"text": str(finding.get("explanation") or message)[:1000]},
        })
        line = max(1, int(finding.get("line") or 1))
        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                    "region": {"startLine": line},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AI Code Audit", "version": str(SCANNER_VERSION), "rules": list(rules.values())}},
            "results": sarif_results,
        }],
    }


def get_app_base_url(request: Request | None = None) -> str:
    configured = str(APP_BASE_URL or "").strip().rstrip("/")
    if configured:
        return configured
    if request is None:
        return "http://127.0.0.1:8000"
    return str(request.base_url).rstrip("/")


def stripe_is_configured() -> bool:
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)


def stripe_object_value(value, key: str, default=None):
    """Read a field from either a Stripe SDK object or a plain dictionary."""
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get(key, default)
    try:
        return getattr(value, key)
    except (AttributeError, TypeError):
        try:
            return value[key]
        except (KeyError, IndexError, TypeError, AttributeError):
            return default


def stripe_reference_id(value) -> str:
    if value is None:
        return ""
    reference_id = stripe_object_value(value, "id", value)
    return str(reference_id or "").strip()


def stripe_invoice_subscription_id(invoice) -> str:
    direct = stripe_reference_id(stripe_object_value(invoice, "subscription"))
    if direct:
        return direct
    parent = stripe_object_value(invoice, "parent")
    subscription_details = stripe_object_value(parent, "subscription_details")
    return stripe_reference_id(stripe_object_value(subscription_details, "subscription"))


def supabase_admin_is_valid() -> bool:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return False

    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/admin/users?page=1&per_page=1",
        headers={
            "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
            "apikey": SUPABASE_SECRET_KEY,
        },
    )
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            return 200 <= int(response.status) < 300
    except Exception as exc:
        log_server_issue("Supabase admin credential validation failed", exc)
        return False


def supabase_auth_admin_request(method: str, path: str, payload: dict | None = None) -> dict:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return {}

    url = f"{SUPABASE_URL}/auth/v1/admin/{path.lstrip('/')}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "apikey": SUPABASE_SECRET_KEY,
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with urllib.request.urlopen(req, timeout=20, context=context) as response:
            raw = response.read().decode("utf-8", errors="ignore")
            return json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        log_server_issue(f"Supabase admin request failed ({method.upper()} {path})", exc)
        return {}


def get_supabase_admin_user(user_id: str) -> dict | None:
    if not user_id:
        return None
    response = supabase_auth_admin_request("GET", f"users/{user_id}")
    if isinstance(response, dict) and response.get("id"):
        return response
    user = response.get("user") if isinstance(response, dict) else None
    return user if isinstance(user, dict) and user.get("id") else None


def update_supabase_user_app_metadata(user_id: str, metadata_updates: dict) -> bool:
    if not user_id:
        return False

    current_user = get_supabase_admin_user(user_id)
    if not current_user:
        return False

    existing_app_metadata = current_user.get("app_metadata") or {}
    merged_app_metadata = dict(existing_app_metadata)
    merged_app_metadata.update(metadata_updates)

    payload = {
        "app_metadata": merged_app_metadata,
        "user_metadata": current_user.get("user_metadata") or {},
    }
    updated = supabase_auth_admin_request("PUT", f"users/{user_id}", payload=payload)
    if isinstance(updated, dict) and (updated.get("id") == user_id or (updated.get("user") or {}).get("id") == user_id):
        return True
    log_server_issue(f"Failed to update Supabase app metadata for user {user_id}")
    return False


def unix_to_iso8601(unix_ts) -> str | None:
    try:
        if unix_ts in (None, "", 0, "0"):
            return None
        return datetime.fromtimestamp(int(unix_ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def should_keep_pro_access(
    status: str,
    *,
    cancel_at_period_end: bool = False,
    current_period_end = None,
) -> bool:
    normalized = str(status or "").lower().strip()

    if normalized in {"active", "trialing", "past_due"}:
        return True

    if cancel_at_period_end and current_period_end not in (None, "", 0, "0"):
        try:
            return int(current_period_end) > int(time.time())
        except Exception:
            return False

    return False


def plan_from_subscription_status(
    status: str,
    *,
    cancel_at_period_end: bool = False,
    current_period_end = None,
) -> str:
    if should_keep_pro_access(
        status,
        cancel_at_period_end=cancel_at_period_end,
        current_period_end=current_period_end,
    ):
        return "pro"
    return "free"


def get_supabase_admin_user_by_metadata_field(field_name: str, field_value: str) -> dict | None:
    if not field_name or not field_value:
        return None

    response = supabase_auth_admin_request("GET", "users")
    users = []
    if isinstance(response, dict):
        if isinstance(response.get("users"), list):
            users = response.get("users") or []
        elif isinstance(response.get("data"), list):
            users = response.get("data") or []
    elif isinstance(response, list):
        users = response

    lookup_value = str(field_value)
    for user in users:
        if not isinstance(user, dict):
            continue
        app_metadata = user.get("app_metadata") or {}
        if str(app_metadata.get(field_name) or "") == lookup_value and user.get("id"):
            return user
    return None


def resolve_supabase_user_id_for_stripe_event(
    *,
    explicit_user_id: str | None = None,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> str | None:
    if explicit_user_id:
        return str(explicit_user_id)

    if stripe_subscription_id:
        user = get_supabase_admin_user_by_metadata_field("stripe_subscription_id", str(stripe_subscription_id))
        if user and user.get("id"):
            return str(user["id"])

    if stripe_customer_id:
        user = get_supabase_admin_user_by_metadata_field("stripe_customer_id", str(stripe_customer_id))
        if user and user.get("id"):
            return str(user["id"])

    return None


def sync_user_plan_from_subscription(
    user_id: str,
    *,
    plan: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
    subscription_status: str | None = None,
    cancel_at_period_end: bool | None = None,
    current_period_end = None,
) -> bool:
    metadata_updates = {"plan": str(plan or "free").lower()}
    if stripe_customer_id is not None:
        metadata_updates["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        metadata_updates["stripe_subscription_id"] = stripe_subscription_id
    if subscription_status is not None:
        metadata_updates["stripe_subscription_status"] = subscription_status
    if cancel_at_period_end is not None:
        metadata_updates["stripe_cancel_at_period_end"] = bool(cancel_at_period_end)
    if current_period_end is not None:
        metadata_updates["stripe_current_period_end"] = int(current_period_end) if str(current_period_end).strip() else None
        metadata_updates["stripe_current_period_end_iso"] = unix_to_iso8601(current_period_end)
    return update_supabase_user_app_metadata(user_id, metadata_updates)


def build_authenticated_access_payload_for_user(user_id: str, request: Request | None = None) -> dict | None:
    current_user = get_supabase_admin_user(str(user_id))
    if not current_user:
        return None

    app_metadata = current_user.get("app_metadata") or {}
    role = str(app_metadata.get("role") or "user").lower()
    plan = str(app_metadata.get("plan") or ("admin" if role == "admin" else "free")).lower()
    effective_plan = "admin" if role == "admin" else plan

    access = {
        "authenticated": True,
        "user_id": str(current_user.get("id") or user_id),
        "email": current_user.get("email"),
        "role": role,
        "plan": effective_plan,
        "limits": get_plan_limits(effective_plan),
        "app_metadata": app_metadata,
        "debug": {
            "has_supabase_url": bool(SUPABASE_URL),
            "has_supabase_secret_key": bool(SUPABASE_SECRET_KEY),
            "has_bearer_token": bool(request is not None),
            "user_fetch_succeeded": True,
            "resolved_via": "supabase_admin",
        },
    }
    return build_access_payload(access)


@app.get("/auth/access")
async def auth_access(request: Request):
    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)
    return JSONResponse(build_access_payload(access), headers={"Cache-Control": "no-store"})


@app.post("/stripe/create-billing-portal-session")
async def create_billing_portal_session(request: Request):
    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "billing")

    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Log in before managing your subscription.")

    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe billing is not configured on the server yet.")

    current_user = get_supabase_admin_user(str(access["user_id"])) or {}
    app_metadata = current_user.get("app_metadata") or {}
    stripe_customer_id = str(app_metadata.get("stripe_customer_id") or "").strip() or None
    stripe_subscription_id = str(app_metadata.get("stripe_subscription_id") or "").strip() or None

    if not stripe_customer_id and stripe_subscription_id:
        try:
            subscription = stripe.Subscription.retrieve(stripe_subscription_id)
            stripe_customer_id = stripe_reference_id(stripe_object_value(subscription, "customer")) or None
        except Exception as exc:
            log_server_issue("Failed to resolve Stripe customer from subscription for billing portal", exc)

    if not stripe_customer_id:
        raise HTTPException(status_code=400, detail="No active Stripe customer record was found for this account yet.")

    try:
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{get_app_base_url(request)}/",
        )
    except Exception as exc:
        log_server_issue("Could not start Stripe billing portal", exc)
        raise HTTPException(status_code=500, detail="Could not open billing management right now.") from exc

    return {"url": session.url}


@app.post("/stripe/create-checkout-session")
async def create_stripe_checkout_session(request: Request):
    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "billing")

    if not access.get("authenticated") or not access.get("user_id") or not access.get("email"):
        raise HTTPException(status_code=401, detail="Log in before upgrading to Pro. Your session may need to be refreshed.")

    current_plan = str(access.get("plan") or "free").lower()
    current_role = str(access.get("role") or "user").lower()
    if current_role == "admin":
        raise HTTPException(status_code=400, detail="Admin accounts already have elevated access.")
    if current_plan == "pro":
        raise HTTPException(status_code=400, detail="Your account is already on Pro.")

    if not stripe_is_configured():
        raise HTTPException(status_code=503, detail="Stripe is not fully configured on the server yet.")

    current_user = get_supabase_admin_user(str(access["user_id"])) or {}
    existing_app_metadata = current_user.get("app_metadata") or {}
    existing_customer_id = str(existing_app_metadata.get("stripe_customer_id") or "").strip() or None

    checkout_kwargs = {
        "mode": "subscription",
        "line_items": [{"price": STRIPE_PRICE_ID, "quantity": 1}],
        "success_url": f"{get_app_base_url(request)}/?checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{get_app_base_url(request)}/?checkout=cancel",
        "client_reference_id": str(access["user_id"]),
        "metadata": {
            "user_id": str(access["user_id"]),
            "user_email": str(access["email"]),
        },
        "subscription_data": {
            "metadata": {
                "user_id": str(access["user_id"]),
                "user_email": str(access["email"]),
            }
        },
        "allow_promotion_codes": False,
    }

    if existing_customer_id:
        checkout_kwargs["customer"] = existing_customer_id
    else:
        checkout_kwargs["customer_email"] = str(access["email"])

    try:
        session = stripe.checkout.Session.create(**checkout_kwargs)
    except stripe.error.AuthenticationError as exc:
        log_server_issue("Stripe rejected the configured secret key", exc)
        raise HTTPException(
            status_code=500,
            detail="Stripe rejected the configured secret key. Replace STRIPE_SECRET_KEY in Render with the current key from the same live Stripe account.",
        ) from exc
    except stripe.error.InvalidRequestError as exc:
        log_server_issue("Stripe rejected the checkout configuration", exc)
        raise HTTPException(
            status_code=500,
            detail="Stripe rejected the configured Price ID. Confirm STRIPE_PRICE_ID is a recurring live price from the same Stripe account as STRIPE_SECRET_KEY.",
        ) from exc
    except Exception as exc:
        log_server_issue("Could not start Stripe checkout", exc)
        raise HTTPException(status_code=500, detail="Could not start Stripe checkout.") from exc

    return {
        "url": session.url,
        "session_id": session.id,
    }


@app.get("/stripe/checkout-session-status")
async def stripe_checkout_session_status(request: Request, session_id: str):
    if not stripe_is_configured():
        raise HTTPException(status_code=503, detail="Stripe is not fully configured on the server yet.")

    if not session_id or not str(session_id).strip():
        raise HTTPException(status_code=400, detail="A checkout session ID is required.")

    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "billing")

    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Log in before verifying checkout status.")

    try:
        session = stripe.checkout.Session.retrieve(str(session_id).strip())
    except Exception as exc:
        log_server_issue("Could not retrieve Stripe checkout session status", exc)
        raise HTTPException(status_code=500, detail="Could not verify checkout status right now.") from exc

    session_status = str(stripe_object_value(session, "status") or "").lower()
    payment_status = str(stripe_object_value(session, "payment_status") or "").lower()
    subscription_id = stripe_reference_id(stripe_object_value(session, "subscription")) or None
    customer_id = stripe_reference_id(stripe_object_value(session, "customer")) or None
    metadata = stripe_object_value(session, "metadata", {}) or {}

    user_id = resolve_supabase_user_id_for_stripe_event(
        explicit_user_id=stripe_object_value(metadata, "user_id") or stripe_object_value(session, "client_reference_id"),
        stripe_customer_id=str(customer_id) if customer_id else None,
        stripe_subscription_id=str(subscription_id) if subscription_id else None,
    )

    if not user_id or str(user_id) != str(access.get("user_id")):
        raise HTTPException(status_code=403, detail="This checkout session does not belong to the current account.")

    synced = False
    plan = str(access.get("plan") or "free").lower()
    subscription_status = None
    cancel_at_period_end = False
    current_period_end = None
    checkout_completed = session_status == "complete"
    payment_completed = payment_status in {"paid", "no_payment_required"}

    if subscription_id and checkout_completed and payment_completed:
        provisional_plan = "pro"
        subscription_status = "checkout_completed"
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            subscription_status = str(stripe_object_value(subscription, "status", "active") or "active")
            cancel_at_period_end = bool(stripe_object_value(subscription, "cancel_at_period_end", False) or False)
            current_period_end = stripe_object_value(subscription, "current_period_end")
            plan = plan_from_subscription_status(
                subscription_status,
                cancel_at_period_end=cancel_at_period_end,
                current_period_end=current_period_end,
            )
            if plan != "pro":
                plan = provisional_plan
        except Exception as exc:
            log_server_issue("Could not retrieve subscription during checkout verification; applying provisional Pro access", exc)
            plan = provisional_plan

        synced = sync_user_plan_from_subscription(
            user_id,
            plan=plan,
            stripe_customer_id=str(customer_id) if customer_id else None,
            stripe_subscription_id=str(subscription_id) if subscription_id else None,
            subscription_status=subscription_status,
            cancel_at_period_end=cancel_at_period_end,
            current_period_end=current_period_end,
        )
    elif subscription_id:
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            subscription_status = str(stripe_object_value(subscription, "status") or "")
            cancel_at_period_end = bool(stripe_object_value(subscription, "cancel_at_period_end", False) or False)
            current_period_end = stripe_object_value(subscription, "current_period_end")
            plan = plan_from_subscription_status(
                subscription_status,
                cancel_at_period_end=cancel_at_period_end,
                current_period_end=current_period_end,
            )
        except Exception as exc:
            log_server_issue("Could not retrieve subscription while reporting checkout status", exc)

    refreshed_access = build_authenticated_access_payload_for_user(str(user_id), request=request)
    response_payload = {
        "session_id": str(stripe_object_value(session, "id") or session_id),
        "session_status": session_status,
        "payment_status": payment_status,
        "subscription_id": str(subscription_id) if subscription_id else None,
        "customer_id": str(customer_id) if customer_id else None,
        "user_id": str(user_id),
        "synced": bool(synced),
        "plan": (refreshed_access or {}).get("plan") or plan,
        "subscription_status": subscription_status,
        "cancel_at_period_end": cancel_at_period_end,
        "current_period_end": current_period_end,
        "access": refreshed_access,
    }
    return JSONResponse(response_payload, headers={"Cache-Control": "no-store"})


@app.post("/stripe/reconcile-subscription")
async def reconcile_stripe_subscription(request: Request):
    request.state.operation_stage = "checking billing configuration"
    if not stripe_is_configured():
        raise HTTPException(status_code=503, detail="Stripe is not fully configured on the server yet.")

    request.state.operation_stage = "verifying the signed-in account"
    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "billing")

    if not access.get("authenticated") or not access.get("user_id") or not access.get("email"):
        raise HTTPException(status_code=401, detail="Log in before restoring a paid subscription.")
    if not (access.get("debug") or {}).get("user_fetch_succeeded"):
        raise HTTPException(
            status_code=503,
            detail="Your payment is safe, but the server cannot securely update your account. Replace SUPABASE_SECRET_KEY in Render with the current Supabase secret key, redeploy, then select Restore paid subscription.",
        )

    request.state.operation_stage = "listing completed Stripe checkouts"
    try:
        checkout_sessions = stripe.checkout.Session.list(limit=100)
        session_records = list(stripe_object_value(checkout_sessions, "data", []) or [])
    except Exception as exc:
        log_server_issue("Could not list Stripe Checkout Sessions while restoring subscription", exc)
        raise HTTPException(status_code=502, detail="Stripe could not be reached to restore the subscription right now.") from exc

    request.state.operation_stage = "matching the paid checkout to the account"
    paid_session = None
    expected_user_id = str(access["user_id"])
    expected_email = str(access["email"]).strip().lower()
    for session in session_records:
        metadata = stripe_object_value(session, "metadata", {}) or {}
        session_user_id = str(
            stripe_object_value(metadata, "user_id")
            or stripe_object_value(session, "client_reference_id")
            or ""
        )
        customer_details = stripe_object_value(session, "customer_details", {}) or {}
        session_email = str(
            stripe_object_value(metadata, "user_email")
            or stripe_object_value(customer_details, "email")
            or stripe_object_value(session, "customer_email")
            or ""
        ).strip().lower()
        belongs_to_user = session_user_id == expected_user_id or (
            not session_user_id and session_email == expected_email
        )
        if (
            belongs_to_user
            and str(stripe_object_value(session, "status") or "").lower() == "complete"
            and str(stripe_object_value(session, "payment_status") or "").lower()
            in {"paid", "no_payment_required"}
            and stripe_object_value(session, "subscription")
        ):
            paid_session = session
            break

    if not paid_session:
        raise HTTPException(
            status_code=404,
            detail="No completed paid checkout was found for this account. Confirm you are signed in with the same email used at checkout.",
        )

    request.state.operation_stage = "reading the paid checkout identifiers"
    raw_subscription = stripe_object_value(paid_session, "subscription")
    raw_customer = stripe_object_value(paid_session, "customer")
    subscription_id = stripe_reference_id(raw_subscription)
    customer_id = stripe_reference_id(raw_customer)
    if not subscription_id:
        raise HTTPException(
            status_code=409,
            detail="Stripe confirmed the payment, but no subscription was attached to the checkout.",
        )
    status = "active"
    cancel_at_period_end = False
    current_period_end = None
    request.state.operation_stage = "reading the Stripe subscription"
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        status = str(stripe_object_value(subscription, "status", "active") or "active").lower()
        cancel_at_period_end = bool(
            stripe_object_value(subscription, "cancel_at_period_end", False) or False
        )
        current_period_end = stripe_object_value(subscription, "current_period_end")
    except Exception as exc:
        log_server_issue("Could not retrieve subscription during paid Checkout Session recovery; applying paid access", exc)

    restored_plan = plan_from_subscription_status(
        status,
        cancel_at_period_end=cancel_at_period_end,
        current_period_end=current_period_end,
    )
    if restored_plan != "pro":
        raise HTTPException(
            status_code=409,
            detail="The checkout was paid, but the associated subscription is no longer active.",
        )

    request.state.operation_stage = "updating the Supabase account to Pro"
    synced = sync_user_plan_from_subscription(
        str(access["user_id"]),
        plan=restored_plan,
        stripe_customer_id=customer_id or None,
        stripe_subscription_id=subscription_id,
        subscription_status=status,
        cancel_at_period_end=cancel_at_period_end,
        current_period_end=current_period_end,
    )
    if not synced:
        raise HTTPException(
            status_code=503,
            detail="Stripe confirmed the paid subscription, but Supabase could not update the account. Replace SUPABASE_SECRET_KEY in Render, redeploy, then try Restore paid subscription again.",
        )

    request.state.operation_stage = "building the refreshed Pro account"
    refreshed_access = build_authenticated_access_payload_for_user(str(access["user_id"]), request=request)
    return JSONResponse(
        {
            "restored": True,
            "plan": "pro",
            "subscription_status": status,
            "access": refreshed_access,
        },
        headers={"Cache-Control": "no-store"},
    )


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        return JSONResponse({"received": False, "error": "Stripe webhook is not configured yet."}, status_code=503)

    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=signature, secret=STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        return JSONResponse({"received": False, "error": "Invalid webhook signature."}, status_code=400)
    except Exception:
        return JSONResponse({"received": False, "error": "Invalid webhook payload."}, status_code=400)

    event_type = str(stripe_object_value(event, "type") or "")
    event_data = stripe_object_value(event, "data", {}) or {}
    event_object = stripe_object_value(event_data, "object", {}) or {}

    if event_type == "checkout.session.completed":
        metadata = stripe_object_value(event_object, "metadata", {}) or {}
        subscription_id = stripe_reference_id(stripe_object_value(event_object, "subscription")) or None
        customer_id = stripe_reference_id(stripe_object_value(event_object, "customer")) or None
        user_id = resolve_supabase_user_id_for_stripe_event(
            explicit_user_id=(
                stripe_object_value(metadata, "user_id")
                or stripe_object_value(event_object, "client_reference_id")
            ),
            stripe_customer_id=str(customer_id) if customer_id else None,
            stripe_subscription_id=str(subscription_id) if subscription_id else None,
        )
        if user_id:
            subscription_status = "active"
            cancel_at_period_end = False
            current_period_end = None
            try:
                if subscription_id:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    subscription_status = str(stripe_object_value(subscription, "status", "active") or "active")
                    cancel_at_period_end = bool(stripe_object_value(subscription, "cancel_at_period_end", False) or False)
                    current_period_end = stripe_object_value(subscription, "current_period_end")
            except Exception as exc:
                log_server_issue("Failed to retrieve subscription after checkout.session.completed", exc)

            sync_user_plan_from_subscription(
                user_id,
                plan=plan_from_subscription_status(
                    subscription_status,
                    cancel_at_period_end=cancel_at_period_end,
                    current_period_end=current_period_end,
                ),
                stripe_customer_id=str(customer_id) if customer_id else None,
                stripe_subscription_id=str(subscription_id) if subscription_id else None,
                subscription_status=subscription_status,
                cancel_at_period_end=cancel_at_period_end,
                current_period_end=current_period_end,
            )

    elif event_type in {"customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"}:
        metadata = stripe_object_value(event_object, "metadata", {}) or {}
        customer_id = stripe_reference_id(stripe_object_value(event_object, "customer")) or None
        subscription_id = stripe_reference_id(stripe_object_value(event_object, "id")) or None
        user_id = resolve_supabase_user_id_for_stripe_event(
            explicit_user_id=stripe_object_value(metadata, "user_id"),
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        if user_id:
            status = str(stripe_object_value(event_object, "status") or "")
            cancel_at_period_end = bool(stripe_object_value(event_object, "cancel_at_period_end", False) or False)
            current_period_end = stripe_object_value(event_object, "current_period_end")
            sync_user_plan_from_subscription(
                user_id,
                plan=plan_from_subscription_status(
                    status,
                    cancel_at_period_end=cancel_at_period_end,
                    current_period_end=current_period_end,
                ),
                stripe_customer_id=customer_id,
                stripe_subscription_id=subscription_id,
                subscription_status=status,
                cancel_at_period_end=cancel_at_period_end,
                current_period_end=current_period_end,
            )

    elif event_type in {"invoice.payment_failed", "invoice.paid", "invoice.payment_succeeded"}:
        customer_id = stripe_reference_id(stripe_object_value(event_object, "customer")) or None
        subscription_id = stripe_invoice_subscription_id(event_object) or None
        user_id = resolve_supabase_user_id_for_stripe_event(
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        if user_id and subscription_id:
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
                status = str(stripe_object_value(subscription, "status") or "")
                cancel_at_period_end = bool(stripe_object_value(subscription, "cancel_at_period_end", False) or False)
                current_period_end = stripe_object_value(subscription, "current_period_end")
                sync_user_plan_from_subscription(
                    user_id,
                    plan=plan_from_subscription_status(
                        status,
                        cancel_at_period_end=cancel_at_period_end,
                        current_period_end=current_period_end,
                    ),
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=subscription_id,
                    subscription_status=status,
                    cancel_at_period_end=cancel_at_period_end,
                    current_period_end=current_period_end,
                )
            except Exception as exc:
                log_server_issue("Failed to sync invoice event subscription state", exc)

    return {"received": True}


def verify_github_webhook_signature(payload: bytes, signature: str) -> bool:
    if not GITHUB_WEBHOOK_SECRET or not signature.startswith("sha256="):
        return False
    expected = hmac.new(GITHUB_WEBHOOK_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature[7:], expected)


def github_app_jwt() -> str:
    now = int(time.time())
    return jwt.encode(
        {"iat": now - 30, "exp": now + 540, "iss": GITHUB_APP_ID},
        GITHUB_PRIVATE_KEY,
        algorithm="RS256",
    )


def github_api_request(method: str, url: str, token: str, body: dict | None = None) -> dict | list:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AI-Code-Audit",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context(cafile=certifi.where())) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def github_installation_token(installation_id: int) -> str:
    payload = github_api_request(
        "POST",
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        github_app_jwt(),
        {},
    )
    return str(payload.get("token") or "") if isinstance(payload, dict) else ""


def parse_github_pull_request_event(body: dict) -> tuple[int, str, int, str]:
    try:
        installation_id = int(((body.get("installation") or {}).get("id") or 0))
        pull_request_number = int(body.get("number") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Incomplete pull request event.") from exc
    full_name = str(((body.get("repository") or {}).get("full_name") or "")).strip()
    sha = str(((((body.get("pull_request") or {}).get("head") or {}).get("sha")) or "")).strip()
    if (
        installation_id <= 0
        or pull_request_number <= 0
        or not GITHUB_REPOSITORY_PATTERN.fullmatch(full_name)
        or not GITHUB_SHA_PATTERN.fullmatch(sha)
    ):
        raise ValueError("Incomplete pull request event.")
    return installation_id, full_name, pull_request_number, sha


def parse_github_check_rerequest_event(body: dict) -> tuple[int, str, int, str]:
    check_run = body.get("check_run") or {}
    pull_requests = check_run.get("pull_requests") or []
    try:
        installation_id = int(((body.get("installation") or {}).get("id") or 0))
        pull_request_number = int(((pull_requests[0] if pull_requests else {}).get("number") or 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("Incomplete check rerun event.") from exc
    full_name = str(((body.get("repository") or {}).get("full_name") or "")).strip()
    sha = str(check_run.get("head_sha") or "").strip()
    check_name = str(check_run.get("name") or "").strip()
    if (
        installation_id <= 0
        or pull_request_number <= 0
        or check_name != GITHUB_CHECK_NAME
        or not GITHUB_REPOSITORY_PATTERN.fullmatch(full_name)
        or not GITHUB_SHA_PATTERN.fullmatch(sha)
    ):
        raise ValueError("Incomplete check rerun event.")
    return installation_id, full_name, pull_request_number, sha


def github_installation_entitlement(installation_id: int) -> dict:
    """Resolve a claimed GitHub installation to a currently entitled account."""
    if not GITHUB_ENFORCE_PRO:
        return {"allowed": True, "reason": "enforcement_disabled"}
    rows = supabase_rest_request(
        "GET",
        "github_installations",
        query=f"installation_id=eq.{int(installation_id)}&status=eq.active&select=user_id&limit=1",
    )
    if not isinstance(rows, list) or not rows:
        return {"allowed": False, "reason": "installation_not_linked"}
    user_id = str(rows[0].get("user_id") or "")
    user = get_supabase_admin_user(user_id) or {}
    metadata = user.get("app_metadata") or {}
    role = str(metadata.get("role") or "user").lower()
    plan = str(metadata.get("plan") or ("admin" if role == "admin" else "free")).lower()
    return {
        "allowed": role == "admin" or plan == "pro",
        "reason": "active_pro" if role == "admin" or plan == "pro" else "pro_required",
        "user_id": user_id,
    }


def create_github_install_state(
    user_id: str,
    ttl_seconds: int = 900,
    purpose: str = "installation",
) -> str:
    if not GITHUB_LINK_STATE_SECRET:
        raise RuntimeError("GitHub installation linking is not configured")
    payload = {
        "user_id": str(user_id),
        "exp": int(time.time()) + max(60, min(int(ttl_seconds), 1800)),
        "nonce": secrets.token_urlsafe(10),
        "purpose": str(purpose),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(GITHUB_LINK_STATE_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def read_github_install_state(state: str, expected_purpose: str = "installation") -> dict:
    if not GITHUB_LINK_STATE_SECRET or not state or len(state) > 1000:
        return {}
    try:
        encoded, supplied_signature = state.rsplit(".", 1)
        expected_signature = hmac.new(
            GITHUB_LINK_STATE_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return {}
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if int(payload.get("exp") or 0) < int(time.time()):
            return {}
        if str(payload.get("purpose") or "installation") != str(expected_purpose):
            return {}
        return payload
    except Exception:
        return {}


def verify_github_install_state(
    state: str,
    expected_user_id: str,
    expected_purpose: str = "installation",
) -> bool:
    payload = read_github_install_state(state, expected_purpose)
    return str(payload.get("user_id") or "") == str(expected_user_id)


def github_oauth_callback_url() -> str:
    return f"{APP_BASE_URL}/github/oauth/callback"


def github_oauth_authorize_url(user_id: str) -> str:
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or not GITHUB_LINK_STATE_SECRET:
        raise RuntimeError("GitHub user authorization is not configured")
    state = create_github_install_state(user_id, purpose="oauth")
    return "https://github.com/login/oauth/authorize?" + urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": github_oauth_callback_url(),
        "state": state,
    })


def github_oauth_exchange(code: str) -> str:
    if not code or len(code) > 500:
        raise ValueError("GitHub returned an invalid authorization code")
    data = json.dumps({
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": github_oauth_callback_url(),
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://github.com/login/oauth/access_token",
        data=data,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AI-Code-Audit",
        },
    )
    with urllib.request.urlopen(
        request,
        timeout=20,
        context=ssl.create_default_context(cafile=certifi.where()),
    ) as response:
        payload = json.loads(response.read().decode("utf-8") or "{}")
    token = str(payload.get("access_token") or "") if isinstance(payload, dict) else ""
    if not token:
        raise RuntimeError("GitHub did not issue a user access token")
    return token


def list_github_user_installations(token: str) -> tuple[dict, list[dict]]:
    user = github_api_request("GET", "https://api.github.com/user", token)
    if not isinstance(user, dict) or not user.get("login"):
        raise RuntimeError("GitHub did not return the authorized user")
    installations: list[dict] = []
    for page in range(1, 11):
        result = github_api_request(
            "GET",
            f"https://api.github.com/user/installations?per_page=100&page={page}",
            token,
        )
        page_items = result.get("installations") if isinstance(result, dict) else []
        if not isinstance(page_items, list):
            raise RuntimeError("GitHub returned an invalid installation list")
        installations.extend(
            item for item in page_items
            if isinstance(item, dict) and str(item.get("app_id") or "") == str(GITHUB_APP_ID)
        )
        if len(page_items) < 100:
            break
    return user, installations


def github_user_has_pro(user_id: str) -> bool:
    user = get_supabase_admin_user(str(user_id)) or {}
    metadata = user.get("app_metadata") or {}
    role = str(metadata.get("role") or "user").lower()
    plan = str(metadata.get("plan") or ("admin" if role == "admin" else "free")).lower()
    return role == "admin" or plan == "pro"


def save_github_installation_link(user_id: str, installation: dict) -> dict:
    installation_id = int(installation.get("id") or 0)
    if installation_id <= 0:
        return {}
    account = installation.get("account") or {}
    payload = {
        "installation_id": installation_id,
        "user_id": str(user_id),
        "account_login": str(account.get("login") or "")[:255],
        "account_type": str(account.get("type") or "")[:80],
        "status": "active",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = supabase_rest_request(
        "POST",
        "github_installations",
        payload=payload,
        prefer="resolution=merge-duplicates,return=representation",
    )
    return payload if saved else {}


def list_github_pull_request_files(full_name: str, pull_request_number: int, token: str) -> list[dict]:
    changed_files: list[dict] = []
    page = 1
    while len(changed_files) < PRO_REPO_FILE_LIMIT and page <= 30:
        payload = github_api_request(
            "GET",
            (
                f"https://api.github.com/repos/{quote(full_name, safe='/')}"
                f"/pulls/{pull_request_number}/files?per_page=100&page={page}"
            ),
            token,
        )
        if not isinstance(payload, list):
            raise RuntimeError("GitHub returned an unreadable pull request file list")
        for item in payload:
            if not isinstance(item, dict):
                continue
            filename = str(item.get("filename") or "").strip()
            if item.get("status") == "removed" or not filename or not is_supported_code_file(filename):
                continue
            changed_files.append(item)
            if len(changed_files) >= PRO_REPO_FILE_LIMIT:
                break
        if len(payload) < 100:
            break
        page += 1
    return changed_files


def scan_github_changed_files(archive: bytes, changed_files: list[dict]) -> tuple[list[tuple[str, dict]], int, int]:
    findings: list[tuple[str, dict]] = []
    files_scanned = 0
    files_skipped = 0
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        archive_paths = {
            ("/".join(name.split("/")[1:]) or name): name
            for name in zf.namelist()
            if not name.endswith("/")
        }
        candidates = sorted(
            (str(item.get("filename") or "") for item in changed_files),
            key=lambda name: (-file_weight_for_repo(name), name.lower()),
        )
        for relative_path in candidates:
            archive_path = archive_paths.get(relative_path)
            if not archive_path or zf.getinfo(archive_path).file_size > MAX_PASTED_CODE_BYTES_PRO:
                files_skipped += 1
                continue
            code = zf.read(archive_path).decode("utf-8", errors="ignore")
            result = analyze_code("Review this pull request for security risks.", code, plan="pro")
            files_scanned += 1
            for finding in result.get("flags") or []:
                findings.append((relative_path, finding))
    return findings, files_scanned, files_skipped


def github_check_external_id(full_name: str, pull_request_number: int, sha: str) -> str:
    return f"ai-code-audit:{full_name}:{pull_request_number}:{sha}"


def upsert_github_check(
    full_name: str,
    pull_request_number: int,
    sha: str,
    token: str,
    check_payload: dict,
) -> dict | list:
    external_id = github_check_external_id(full_name, pull_request_number, sha)
    checks = github_api_request(
        "GET",
        (
            f"https://api.github.com/repos/{quote(full_name, safe='/')}/commits/{quote(sha, safe='')}"
            f"/check-runs?check_name={quote(GITHUB_CHECK_NAME, safe='')}"
        ),
        token,
    )
    existing_id = None
    existing_annotations = 0
    if isinstance(checks, dict):
        for check in checks.get("check_runs") or []:
            if isinstance(check, dict) and check.get("external_id") == external_id:
                existing_id = check.get("id")
                output = check.get("output") if isinstance(check.get("output"), dict) else {}
                existing_annotations = max(0, int(output.get("annotations_count") or 0))
                break
    if existing_id:
        update_payload = dict(check_payload)
        if existing_annotations and isinstance(update_payload.get("output"), dict):
            update_payload["output"] = dict(update_payload["output"])
            update_payload["output"].pop("annotations", None)
        update_payload["external_id"] = external_id
        return github_api_request(
            "PATCH",
            f"https://api.github.com/repos/{quote(full_name, safe='/')}/check-runs/{int(existing_id)}",
            token,
            update_payload,
        )
    create_payload = {
        "name": GITHUB_CHECK_NAME,
        "head_sha": sha,
        "external_id": external_id,
        **check_payload,
    }
    return github_api_request(
        "POST",
        f"https://api.github.com/repos/{quote(full_name, safe='/')}/check-runs",
        token,
        create_payload,
    )


def download_github_archive(full_name: str, sha: str, token: str) -> bytes:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{quote(full_name, safe='/')}/zipball/{quote(sha, safe='')}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AI-Code-Audit",
        },
    )
    with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context(cafile=certifi.where())) as response:
        data = response.read(MAX_REPOSITORY_ARCHIVE_BYTES + 1)
    if len(data) > MAX_REPOSITORY_ARCHIVE_BYTES:
        raise ValueError("Repository archive exceeds the 25 MB safety limit.")
    return data


def github_finding_severity(severity: float) -> str:
    if severity >= 18:
        return "High"
    if severity >= 8:
        return "Medium"
    return "Notice"


def github_scan_history_id(installation_id: int, full_name: str, pull_request_number: int, sha: str) -> str:
    return hashlib.sha256(
        f"{int(installation_id)}\0{full_name}\0{int(pull_request_number)}\0{sha}".encode("utf-8")
    ).hexdigest()[:24]


def serialize_github_findings(findings: list[tuple[str, dict]]) -> list[dict]:
    serialized = []
    for path, finding in findings[:100]:
        line = max(1, int(finding.get("line") or 1))
        message = str(finding.get("message") or "Code behavior requires review.")[:300]
        category = str(finding.get("pattern") or finding.get("type") or "review")[:80]
        finding_id = str(finding.get("finding_id") or "")
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", finding_id):
            finding_id = hashlib.sha256(
                f"github\0{path}\0{line}\0{category}\0{message}".encode("utf-8", errors="ignore")
            ).hexdigest()[:20]
        severity_points = float(finding.get("severity", 0) or 0)
        serialized.append({
            "finding_id": finding_id,
            "path": str(path)[:500],
            "line": line,
            "severity": github_finding_severity(severity_points).lower(),
            "category": category,
            "message": message,
            "why_risky": str(finding.get("why_risky") or "")[:1000],
            "suggested_fix": str(finding.get("suggested_fix") or "")[:1000],
        })
    return serialized


def default_repository_policy(repository: str) -> dict:
    return {"repository": repository, "enforcement_mode": "monitor", "block_at": "high"}


def get_repository_policy(user_id: str, repository: str) -> dict:
    rows = supabase_rest_request(
        "GET", "repository_security_policies",
        query=urlencode({
            "user_id": f"eq.{user_id}", "repository": f"eq.{repository}",
            "select": "repository,enforcement_mode,block_at,updated_at", "limit": "1",
        }),
    )
    return rows[0] if isinstance(rows, list) and rows else default_repository_policy(repository)


def get_active_suppressions(user_id: str, repository: str) -> dict[str, dict]:
    now = datetime.now(timezone.utc).isoformat()
    rows = supabase_rest_request(
        "GET", "finding_suppressions",
        query=urlencode({
            "user_id": f"eq.{user_id}", "repository": f"eq.{repository}",
            "select": "finding_id,disposition,reason,expires_at,created_at,updated_at",
            "or": f"(expires_at.is.null,expires_at.gt.{now})", "limit": "500",
        }),
    )
    return {str(row.get("finding_id")): row for row in rows} if isinstance(rows, list) else {}


def annotate_suppressions(serialized: list[dict], suppressions: dict[str, dict]) -> list[dict]:
    for finding in serialized:
        suppression = suppressions.get(str(finding.get("finding_id") or ""))
        finding["suppressed"] = bool(suppression)
        if suppression:
            finding["suppression"] = {
                "disposition": suppression.get("disposition"),
                "reason": suppression.get("reason"),
                "expires_at": suppression.get("expires_at"),
            }
    return serialized


def policy_blocks(policy: dict, serialized_findings: list[dict]) -> bool:
    if str(policy.get("enforcement_mode") or "monitor") != "block":
        return False
    ranks = {"notice": 1, "medium": 2, "high": 3}
    threshold = ranks.get(str(policy.get("block_at") or "high"), 3)
    return any(
        not finding.get("suppressed") and ranks.get(str(finding.get("severity") or "notice"), 1) >= threshold
        for finding in serialized_findings
    )


def add_scan_comparisons(scans: list[dict]) -> list[dict]:
    previous_by_key: dict[tuple[str, int], set[str]] = {}
    for scan in reversed(scans):
        key = (str(scan.get("repository") or ""), int(scan.get("pull_request_number") or 0))
        current = {str(item.get("finding_id")) for item in (scan.get("findings") or []) if item.get("finding_id") and not item.get("suppressed")}
        previous = previous_by_key.get(key)
        scan["comparison"] = {
            "new": len(current - previous) if previous is not None else len(current),
            "fixed": len(previous - current) if previous is not None else 0,
            "unchanged": len(current & previous) if previous is not None else 0,
            "has_previous": previous is not None,
        }
        previous_by_key[key] = current
    return scans


def save_github_scan_history(
    user_id: str,
    installation_id: int,
    full_name: str,
    pull_request_number: int,
    sha: str,
    status: str,
    *,
    conclusion: str = "",
    findings: list[tuple[str, dict]] | None = None,
    files_scanned: int = 0,
    files_skipped: int = 0,
    error_message: str = "",
) -> dict:
    if not user_id:
        return {}
    serialized = annotate_suppressions(
        serialize_github_findings(findings or []),
        get_active_suppressions(str(user_id), str(full_name)),
    )
    counts = {"high": 0, "medium": 0, "notice": 0}
    for finding in serialized:
        if finding.get("suppressed"):
            continue
        severity = str(finding.get("severity") or "notice")
        counts[severity if severity in counts else "notice"] += 1
    payload = {
        "scan_id": github_scan_history_id(installation_id, full_name, pull_request_number, sha),
        "user_id": str(user_id),
        "installation_id": int(installation_id),
        "repository": str(full_name)[:300],
        "pull_request_number": int(pull_request_number),
        "commit_sha": str(sha)[:40],
        "status": status if status in {"in_progress", "completed", "failed"} else "failed",
        "conclusion": str(conclusion)[:40],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "notice_count": counts["notice"],
        "files_scanned": max(0, int(files_scanned)),
        "files_skipped": max(0, int(files_skipped)),
        "findings": serialized,
        "details_url": f"https://github.com/{full_name}/pull/{int(pull_request_number)}/files",
        "error_message": str(error_message)[:300],
        "scanner_version": SCANNER_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = supabase_rest_request(
        "POST",
        "github_scan_runs",
        payload=payload,
        query="on_conflict=scan_id",
        prefer="resolution=merge-duplicates,return=representation",
    )
    return payload if saved else {}


def list_github_installation_repositories(installation_id: int, limit: int = 100) -> list[dict]:
    token = github_installation_token(installation_id)
    payload = github_api_request(
        "GET",
        f"https://api.github.com/installation/repositories?per_page={max(1, min(int(limit), 100))}",
        token,
    )
    repositories = payload.get("repositories") if isinstance(payload, dict) else []
    if not isinstance(repositories, list):
        return []
    safe_repositories = []
    for item in repositories[:limit]:
        full_name = str(item.get("full_name") or "") if isinstance(item, dict) else ""
        if not GITHUB_REPOSITORY_PATTERN.fullmatch(full_name):
            continue
        safe_repositories.append({
            "full_name": full_name,
            "private": bool(item.get("private")),
            "html_url": f"https://github.com/{quote(full_name, safe='/')}",
        })
    return safe_repositories


def github_annotation_message(finding: dict) -> str:
    parts = [str(finding.get("message") or "Code behavior requires review.")]
    why_risky = str(finding.get("why_risky") or "").strip()
    suggested_fix = str(finding.get("suggested_fix") or "").strip()
    if why_risky:
        parts.append(f"Why it matters: {why_risky}")
    if suggested_fix:
        parts.append(f"Suggested fix: {suggested_fix}")
    return "\n\n".join(parts)[:1000]


def build_github_check_output(
    findings: list[tuple[str, dict]],
    files_scanned: int,
    files_skipped: int,
    policy: dict | None = None,
    suppressed_count: int = 0,
) -> dict:
    counts = {"High": 0, "Medium": 0, "Notice": 0}
    review_lines = []
    for path, finding in findings:
        severity = github_finding_severity(float(finding.get("severity", 0) or 0))
        counts[severity] += 1
        if len(review_lines) < 50:
            line = max(1, int(finding.get("line") or 1))
            message = str(finding.get("message") or "Code behavior requires review.")
            review_lines.append(f"- **{severity.upper()}** `{path}:{line}` — {message}")

    policy = policy or default_repository_policy("")
    enforced = str(policy.get("enforcement_mode") or "monitor") == "block"
    summary = (
        f"**{counts['High']} high · {counts['Medium']} medium · {counts['Notice']} notice**\n\n"
        + (f"Policy enforcement: findings at {policy.get('block_at', 'high')} severity or above block merging. " if enforced else "Monitor-only: this check does not block merging. ")
        + "No code was executed. "
        f"Scanned {files_scanned} changed supported file(s); skipped {files_skipped}."
    )
    if suppressed_count:
        summary += f" {suppressed_count} reviewed finding(s) were suppressed and remain in the audit history."
    if len(findings) > 50:
        summary += f" GitHub displays the first 50 of {len(findings)} findings; review the changed files for the remainder."
    output = {
        "title": f"{len(findings)} finding(s) across {files_scanned} file(s)",
        "summary": summary,
    }
    if review_lines:
        output["text"] = "## Review these findings\n\n" + "\n".join(review_lines)
    return output


def process_github_pull_request(installation_id: int, full_name: str, pull_request_number: int, sha: str) -> None:
    token = ""
    history_user_id = ""
    try:
        token = github_installation_token(installation_id)
        if not token:
            raise RuntimeError("GitHub did not issue an installation token")
        details_url = (
            f"https://github.com/{quote(full_name, safe='/')}/pull/{pull_request_number}/files"
        )
        entitlement = github_installation_entitlement(installation_id)
        if not entitlement.get("allowed"):
            upsert_github_check(
                full_name,
                pull_request_number,
                sha,
                token,
                {
                    "status": "completed",
                    "conclusion": "neutral",
                    "details_url": f"{APP_BASE_URL}/?github=link&installation_id={installation_id}",
                    "output": {
                        "title": "Connect this installation to Pro",
                        "summary": (
                            "This monitor-only scan was not run because the GitHub installation is not linked "
                            "to an active AI Code Audit Pro account. Open the details link while signed in to connect it."
                        ),
                    },
                },
            )
            return
        history_user_id = str(entitlement.get("user_id") or "")
        save_github_scan_history(
            history_user_id,
            installation_id,
            full_name,
            pull_request_number,
            sha,
            "in_progress",
        )
        upsert_github_check(
            full_name,
            pull_request_number,
            sha,
            token,
            {
                "status": "in_progress",
                "details_url": details_url,
                "output": {
                    "title": "Scanning changed files",
                    "summary": "Monitor-only scan in progress. This check does not block merging.",
                },
            },
        )
        changed_files = list_github_pull_request_files(full_name, pull_request_number, token)
        archive = download_github_archive(full_name, sha, token)
        findings, files_scanned, files_skipped = scan_github_changed_files(archive, changed_files)
        policy = get_repository_policy(history_user_id, full_name)
        suppressions = get_active_suppressions(history_user_id, full_name)
        serialized_findings = annotate_suppressions(serialize_github_findings(findings), suppressions)
        active_findings = [item for item, serialized in zip(findings, serialized_findings) if not serialized.get("suppressed")]
        suppressed_count = len(findings) - len(active_findings)
        conclusion = "failure" if policy_blocks(policy, serialized_findings) else "neutral" if active_findings else "success"
        annotations = []
        for path, finding in active_findings[:50]:
            line = max(1, int(finding.get("line") or 1))
            severity = float(finding.get("severity", 0) or 0)
            annotations.append({
                "path": path,
                "start_line": line,
                "end_line": line,
                "annotation_level": "warning" if severity >= 8 else "notice",
                "message": github_annotation_message(finding),
                "title": f"AI Code Audit • {github_finding_severity(severity)} severity",
            })
        check_output = build_github_check_output(active_findings, files_scanned, files_skipped, policy, suppressed_count)
        check_output["annotations"] = annotations
        upsert_github_check(
            full_name,
            pull_request_number,
            sha,
            token,
            {
                "status": "completed",
                "conclusion": conclusion,
                "details_url": details_url,
                "output": check_output,
            },
        )
        save_github_scan_history(
            history_user_id,
            installation_id,
            full_name,
            pull_request_number,
            sha,
            "completed",
            conclusion=conclusion,
            findings=findings,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
        )
    except Exception as exc:
        log_server_issue("GitHub pull request scan failed", exc)
        save_github_scan_history(
            history_user_id,
            installation_id,
            full_name,
            pull_request_number,
            sha,
            "failed",
            conclusion="neutral",
            error_message="The scan could not complete. Retry the GitHub check.",
        )
        if token:
            try:
                upsert_github_check(
                    full_name,
                    pull_request_number,
                    sha,
                    token,
                    {
                        "status": "completed",
                        "conclusion": "neutral",
                        "output": {
                            "title": "Scan could not complete",
                            "summary": (
                                "AI Code Audit could not complete this monitor-only scan. "
                                "This result does not block merging; retry the check or review the service logs."
                            ),
                        },
                    },
                )
            except Exception as reporting_exc:
                log_server_issue("GitHub pull request failure check could not be published", reporting_exc)


@app.get("/github/status")
def github_status():
    valid_slug = GITHUB_APP_SLUG if GITHUB_APP_SLUG_PATTERN.fullmatch(GITHUB_APP_SLUG) else ""
    return private_json({
        "configured": bool(GITHUB_APP_ID and GITHUB_PRIVATE_KEY and GITHUB_WEBHOOK_SECRET),
        "has_app_id": bool(GITHUB_APP_ID),
        "has_private_key": bool(GITHUB_PRIVATE_KEY),
        "has_webhook_secret": bool(GITHUB_WEBHOOK_SECRET),
        "has_app_slug": bool(valid_slug),
        "install_url": f"https://github.com/apps/{valid_slug}/installations/new" if valid_slug else "",
        "pull_request_checks": True,
        "monitor_only": True,
        "scans_changed_files_only": True,
        "dynamic_sandbox": "not_enabled",
        "pro_enforcement": GITHUB_ENFORCE_PRO,
        "secure_linking": bool(GITHUB_LINK_STATE_SECRET),
        "existing_install_linking": bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET and GITHUB_LINK_STATE_SECRET),
        "connection_revision": 2,
        "scanner_version": SCANNER_VERSION,
    })


@app.get("/github/connect-url")
def github_connect_url(request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        return private_json({"detail": "Sign in before connecting GitHub."}, status_code=401)
    if access.get("plan") not in {"pro", "admin"} and access.get("role") != "admin":
        return private_json({"detail": "An active Pro account is required for automatic pull-request checks."}, status_code=403)
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or not GITHUB_LINK_STATE_SECRET:
        return private_json({"detail": "Connecting an existing GitHub installation is not configured yet."}, status_code=503)
    return private_json({
        "url": github_oauth_authorize_url(str(access["user_id"])),
        "expires_in": 900,
    })


@app.get("/github/install-url")
def github_install_url(request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        return private_json({"detail": "Sign in before installing the GitHub App."}, status_code=401)
    if access.get("plan") not in {"pro", "admin"} and access.get("role") != "admin":
        return private_json({"detail": "An active Pro account is required for automatic pull-request checks."}, status_code=403)
    valid_slug = GITHUB_APP_SLUG if GITHUB_APP_SLUG_PATTERN.fullmatch(GITHUB_APP_SLUG) else ""
    if not valid_slug or not GITHUB_LINK_STATE_SECRET:
        return private_json({"detail": "Secure GitHub installation linking is not configured."}, status_code=503)
    state = create_github_install_state(str(access["user_id"]))
    return private_json({
        "url": f"https://github.com/apps/{valid_slug}/installations/new?{urlencode({'state': state})}",
        "expires_in": 900,
    })


@app.get("/github/oauth/callback")
def github_oauth_callback(code: str = "", state: str = "", error: str = ""):
    def home_redirect(result: str, **extra: str | int) -> RedirectResponse:
        query = {"github": result, **extra}
        return RedirectResponse(
            f"{APP_BASE_URL}/?{urlencode(query)}",
            status_code=303,
            headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
        )

    if error:
        return home_redirect("cancelled")
    payload = read_github_install_state(state, "oauth")
    user_id = str(payload.get("user_id") or "")
    if not user_id or not github_user_has_pro(user_id):
        return home_redirect("error")
    try:
        token = github_oauth_exchange(code)
        github_user, installations = list_github_user_installations(token)
        if not installations:
            valid_slug = GITHUB_APP_SLUG if GITHUB_APP_SLUG_PATTERN.fullmatch(GITHUB_APP_SLUG) else ""
            if not valid_slug:
                return home_redirect("error")
            install_state = create_github_install_state(user_id, purpose="installation")
            install_url = f"https://github.com/apps/{valid_slug}/installations/new?" + urlencode({
                "state": install_state,
            })
            return RedirectResponse(
                install_url,
                status_code=303,
                headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
            )
        saved = [save_github_installation_link(user_id, item) for item in installations]
        if not all(saved):
            raise RuntimeError("One or more GitHub installation links could not be saved")
        return home_redirect(
            "connected",
            github_account=str(github_user.get("login") or "")[:255],
            github_installations=len(saved),
        )
    except Exception as exc:
        log_server_issue("GitHub user authorization failed", exc)
        return home_redirect("error")


@app.get("/github/account-status")
def github_account_status(request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        return private_json({"detail": "Sign in to view connected GitHub installations."}, status_code=401)
    rows = supabase_rest_request(
        "GET",
        "github_installations",
        query=urlencode({
            "user_id": f"eq.{access['user_id']}",
            "status": "eq.active",
            "select": "installation_id,account_login,account_type,status,updated_at",
            "order": "updated_at.desc",
        }),
    )
    installations = rows if isinstance(rows, list) else []
    return private_json({
        "connected": bool(installations),
        "installations": installations,
        "count": len(installations),
    })


@app.get("/github/dashboard")
def github_dashboard(request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        return private_json({"detail": "Sign in to view your GitHub dashboard."}, status_code=401)

    user_id = str(access["user_id"])
    installation_rows = supabase_rest_request(
        "GET",
        "github_installations",
        query=urlencode({
            "user_id": f"eq.{user_id}",
            "status": "eq.active",
            "select": "installation_id,account_login,account_type,status,updated_at",
            "order": "updated_at.desc",
            "limit": "10",
        }),
    )
    installations = installation_rows if isinstance(installation_rows, list) else []

    repositories_by_name = {}
    for installation in installations:
        try:
            installation_id = int(installation.get("installation_id") or 0)
            for repository in list_github_installation_repositories(installation_id):
                repositories_by_name[repository["full_name"]] = repository
        except Exception as exc:
            log_server_issue("GitHub dashboard repository listing failed", exc)

    scan_rows = supabase_rest_request(
        "GET",
        "github_scan_runs",
        query=urlencode({
            "user_id": f"eq.{user_id}",
            "select": (
                "scan_id,repository,pull_request_number,commit_sha,status,conclusion,"
                "high_count,medium_count,notice_count,files_scanned,files_skipped,"
                "findings,details_url,error_message,scanner_version,created_at,updated_at"
            ),
            "order": "updated_at.desc",
            "limit": "25",
        }),
    )
    scans = scan_rows if isinstance(scan_rows, list) else []
    policy_rows = supabase_rest_request(
        "GET", "repository_security_policies",
        query=urlencode({
            "user_id": f"eq.{user_id}",
            "select": "repository,enforcement_mode,block_at,updated_at",
            "limit": "200",
        }),
    )
    policies = {str(row.get("repository")): row for row in policy_rows} if isinstance(policy_rows, list) else {}
    suppression_rows = supabase_rest_request(
        "GET", "finding_suppressions",
        query=urlencode({
            "user_id": f"eq.{user_id}",
            "select": "repository,finding_id,disposition,reason,expires_at,created_at,updated_at",
            "limit": "500",
        }),
    )
    suppressions_by_repo: dict[str, dict[str, dict]] = {}
    if isinstance(suppression_rows, list):
        now = datetime.now(timezone.utc)
        for row in suppression_rows:
            expires_at = str(row.get("expires_at") or "")
            if expires_at:
                try:
                    if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= now:
                        continue
                except ValueError:
                    continue
            suppressions_by_repo.setdefault(str(row.get("repository") or ""), {})[str(row.get("finding_id") or "")] = row
    for repository in repositories_by_name.values():
        repository["policy"] = policies.get(repository["full_name"], default_repository_policy(repository["full_name"]))
    for scan in scans:
        findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
        annotate_suppressions(findings, suppressions_by_repo.get(str(scan.get("repository") or ""), {}))
        scan["accepted_count"] = sum(1 for item in findings if item.get("suppressed"))
    add_scan_comparisons(scans)
    return private_json({
        "connected": bool(installations),
        "plan": str(access.get("plan") or "free"),
        "installations": installations,
        "repositories": sorted(repositories_by_name.values(), key=lambda item: item["full_name"].lower()),
        "scans": scans,
        "history_storage_ready": isinstance(scan_rows, list),
        "policy_storage_ready": isinstance(policy_rows, list) and isinstance(suppression_rows, list),
        "stored_code": False,
        "scanner_version": SCANNER_VERSION,
    })


def require_github_repository_access(request: Request, repository: str) -> tuple[dict, str]:
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Sign in to manage repository security settings.")
    if not GITHUB_REPOSITORY_PATTERN.fullmatch(repository):
        raise HTTPException(status_code=400, detail="The repository name is invalid.")
    user_id = str(access["user_id"])
    rows = supabase_rest_request(
        "GET", "github_installations",
        query=urlencode({"user_id": f"eq.{user_id}", "status": "eq.active", "select": "installation_id", "limit": "20"}),
    )
    for row in rows if isinstance(rows, list) else []:
        try:
            if any(item["full_name"].lower() == repository.lower() for item in list_github_installation_repositories(int(row.get("installation_id") or 0))):
                return access, user_id
        except Exception as exc:
            log_server_issue("Repository access verification failed", exc)
    raise HTTPException(status_code=403, detail="That repository is not connected to this account.")


@app.post("/github/repositories/{owner}/{repo}/policy")
def save_repository_policy(owner: str, repo: str, req: RepositoryPolicyRequest, request: Request):
    repository = f"{owner}/{repo}"
    access, user_id = require_github_repository_access(request, repository)
    mode = str(req.enforcement_mode or "monitor").lower()
    block_at = str(req.block_at or "high").lower()
    if mode not in {"monitor", "block"} or block_at not in {"high", "medium", "notice"}:
        raise HTTPException(status_code=400, detail="Choose monitor or block, with a valid severity threshold.")
    if mode == "block" and access.get("plan") not in {"pro", "admin"} and access.get("role") != "admin":
        raise HTTPException(status_code=403, detail="An active Pro account is required to enforce blocking policies.")
    payload = {
        "user_id": user_id, "repository": repository, "enforcement_mode": mode,
        "block_at": block_at, "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = supabase_rest_request(
        "POST", "repository_security_policies", payload=payload,
        query="on_conflict=user_id,repository", prefer="resolution=merge-duplicates,return=representation",
    )
    if not saved:
        return private_json({"detail": "Repository policy storage still needs its one-time database setup."}, status_code=503)
    return private_json({"saved": True, "policy": payload})


@app.post("/github/suppressions")
def save_finding_suppression(req: FindingSuppressionRequest, request: Request):
    _access, user_id = require_github_repository_access(request, req.repository)
    disposition = str(req.disposition or "").lower()
    reason = str(req.reason or "").strip()
    if disposition not in {"accepted_risk", "false_positive", "temporary"}:
        raise HTTPException(status_code=400, detail="Choose accepted risk, false positive, or temporary suppression.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(req.finding_id or "")) or len(reason) < 5:
        raise HTTPException(status_code=400, detail="A valid finding and a short audit reason are required.")
    expires_at = None
    if disposition == "temporary":
        days = max(1, min(int(req.expires_in_days or 30), 365))
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    payload = {
        "user_id": user_id, "repository": req.repository, "finding_id": req.finding_id,
        "disposition": disposition, "reason": reason[:500], "expires_at": expires_at,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = supabase_rest_request(
        "POST", "finding_suppressions", payload=payload,
        query="on_conflict=user_id,repository,finding_id", prefer="resolution=merge-duplicates,return=representation",
    )
    if not saved:
        return private_json({"detail": "Suppression storage still needs its one-time database setup."}, status_code=503)
    return private_json({"saved": True, "suppression": payload})


@app.post("/github/link-installation")
def link_github_installation(req: GitHubInstallationLinkRequest, request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "github")
    if not access.get("authenticated") or not access.get("user_id"):
        return private_json({"detail": "Sign in before connecting a GitHub installation."}, status_code=401)
    if access.get("plan") not in {"pro", "admin"} and access.get("role") != "admin":
        return private_json({"detail": "An active Pro account is required for automatic pull-request checks."}, status_code=403)
    if req.installation_id <= 0:
        return private_json({"detail": "The GitHub installation ID is invalid."}, status_code=400)
    if not verify_github_install_state(req.state, str(access["user_id"])):
        return private_json({"detail": "The GitHub installation link expired or did not match this account. Start the connection again."}, status_code=400)
    try:
        installation = github_api_request(
            "GET",
            f"https://api.github.com/app/installations/{int(req.installation_id)}",
            github_app_jwt(),
        )
    except Exception:
        return private_json({"detail": "GitHub could not verify that installation for this App."}, status_code=400)
    if not isinstance(installation, dict) or int(installation.get("id") or 0) != req.installation_id:
        return private_json({"detail": "GitHub returned an invalid installation record."}, status_code=400)
    payload = save_github_installation_link(str(access["user_id"]), installation)
    if not payload:
        return private_json({"detail": "GitHub linking storage is not configured yet."}, status_code=503)
    return private_json({
        "linked": True,
        "installation_id": req.installation_id,
        "account_login": payload["account_login"],
        "pro_enforcement": GITHUB_ENFORCE_PRO,
    })


@app.post("/github/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not verify_github_webhook_signature(payload, signature):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")
    event = request.headers.get("x-github-event", "")
    try:
        body = json.loads(payload.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed GitHub webhook payload.") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Malformed GitHub webhook payload.")
    if event == "ping":
        return private_json({"received": True, "event": "ping"})
    try:
        if event == "pull_request" and body.get("action") in {"opened", "reopened", "synchronize"}:
            installation_id, full_name, pull_request_number, sha = parse_github_pull_request_event(body)
        elif event == "check_run" and body.get("action") == "rerequested":
            installation_id, full_name, pull_request_number, sha = parse_github_check_rerequest_event(body)
        else:
            return private_json({"received": True, "ignored": True})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(
        process_github_pull_request,
        installation_id,
        full_name,
        pull_request_number,
        sha,
    )
    return private_json({"received": True, "queued": True})


@app.get("/stripe/status")
def stripe_status():
    return {
        "configured": stripe_is_configured(),
        "has_publishable_key": bool(STRIPE_PUBLISHABLE_KEY),
        "has_price_id": bool(STRIPE_PRICE_ID),
        "has_webhook_secret": bool(STRIPE_WEBHOOK_SECRET),
        "supabase_admin_valid": supabase_admin_is_valid(),
        "app_base_url": APP_BASE_URL,
        "recovery_version": 4,
        "scanner_version": SCANNER_VERSION,
        "security_version": 1,
        "benchmark_cases": 1115,
        "benchmark_independent_cases": 300,
        "benchmark_internal_cases": 65,
        "benchmark_category_assisted_cases": 750,
        "benchmark_no_hint_holdout_cases": 300,
        "benchmark_regression_variants": 325,
    }


@app.get("/favicon.ico")
def favicon_ico():
    return FileResponse("static/favicon.png")


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return FileResponse("static/favicon.png")


@app.get("/apple-touch-icon-precomposed.png")
def apple_touch_icon_precomposed():
    return FileResponse("static/favicon.png")


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/accuracy/status")
def accuracy_status():
    try:
        report = json.loads(Path(__file__).with_name("accuracy-report.json").read_text(encoding="utf-8"))
    except Exception:
        return private_json({"available": False, "detail": "The published accuracy report is unavailable."}, status_code=503)
    return private_json({"available": True, **report})


@app.post("/scan")
def scan(req: ScanRequest, request: Request):
    access = get_request_access_context(request)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "scan")

    plan = str(access.get("plan") or "free").lower()
    max_code_bytes = MAX_PASTED_CODE_BYTES_PRO if plan in {"pro", "admin"} else MAX_PASTED_CODE_BYTES_FREE
    code_size_bytes = len(req.code.encode("utf-8", errors="ignore"))
    if code_size_bytes > max_code_bytes:
        return private_json(
            {"detail": f"Pasted code exceeds the {max_code_bytes // 1_000_000} MB request limit."},
            status_code=413,
        )
    if len(req.intent) > 2000:
        return private_json({"detail": "The intent description is too long."}, status_code=413)

    is_example_scan = bool(req.is_example)

    result = analyze_code_product(req.intent, req.code, plan=access["plan"])
    result["access"] = access
    result["is_example"] = is_example_scan
    result["privacy"] = {
        "stored_by_scanner": False,
        "response_cache_disabled": True,
    }
    return private_json(result)


@app.post("/scan/sarif")
def scan_sarif(req: ScanRequest, request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "scan")
    max_code_bytes = MAX_PASTED_CODE_BYTES_PRO if access.get("plan") in {"pro", "admin"} else MAX_PASTED_CODE_BYTES_FREE
    if len(req.code.encode("utf-8", errors="ignore")) > max_code_bytes:
        return private_json({"detail": "Pasted code exceeds this plan's request limit."}, status_code=413)
    result = analyze_code_product(req.intent, req.code, plan=access.get("plan") or "free")
    return private_json(result_to_sarif(result, infer_code_filename(req.code)))


@app.post("/fix-preview")
def fix_preview(req: FixPreviewRequest, request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "scan")
    result = analyze_code(req.intent, req.code, plan=access.get("plan") or "free")
    return private_json({
        "fix_previews": build_fix_previews(req.code, result.get("flags") or []),
        "applied": False,
    })


@app.post("/feedback")
def submit_feedback(req: FeedbackRequest, request: Request):
    access = enrich_access_with_admin_metadata(get_request_access_context(request))
    enforce_rate_limit(request, access, "feedback")
    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Sign in before submitting scanner feedback.")
    verdict = req.verdict.strip().lower()
    if verdict not in {"correct", "false_positive", "missed_risk"}:
        raise HTTPException(status_code=400, detail="Choose correct, false positive, or missed risk.")
    if not re.fullmatch(r"[a-f0-9]{8,32}", req.scan_id) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", req.finding_id):
        raise HTTPException(status_code=400, detail="The feedback reference is invalid.")
    payload = {
        "user_id": str(access["user_id"]),
        "scan_id": req.scan_id,
        "finding_id": req.finding_id,
        "verdict": verdict,
        "category": req.category.strip()[:80],
        "note": sanitize_feedback_text(req.note, 500),
        "scanner_version": SCANNER_VERSION,
        "review_status": "pending",
        "review_note": "",
        "reviewed_at": None,
        "reviewed_by": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    inserted = supabase_rest_request(
        "POST",
        "scan_feedback",
        payload=payload,
        query="on_conflict=user_id,scan_id,finding_id,verdict",
        prefer="resolution=merge-duplicates,return=representation",
    )
    if not inserted:
        return private_json({"detail": "Feedback storage is not configured yet."}, status_code=503)
    return private_json({"received": True, "stored_code": False})


@app.get("/admin/feedback")
def admin_feedback_queue(request: Request, status: str = "pending"):
    require_admin_access(request)
    review_status = str(status or "pending").strip().lower()
    if review_status not in {"pending", "accepted", "dismissed", "all"}:
        raise HTTPException(status_code=400, detail="Choose pending, accepted, dismissed, or all.")
    filters = {
        "select": (
            "id,created_at,updated_at,user_id,scan_id,finding_id,verdict,category,note,"
            "scanner_version,review_status,review_note,reviewed_at,reviewed_by"
        ),
        "order": "created_at.desc",
        "limit": "200",
    }
    if review_status != "all":
        filters["review_status"] = f"eq.{review_status}"
    rows = supabase_rest_request("GET", "scan_feedback", query=urlencode(filters))
    feedback = rows if isinstance(rows, list) else []
    return private_json({
        "feedback": feedback,
        "status": review_status,
        "count": len(feedback),
        "stored_code": False,
        "scanner_version": SCANNER_VERSION,
    })


@app.post("/admin/feedback/{feedback_id}/review")
def review_admin_feedback(feedback_id: int, req: FeedbackReviewRequest, request: Request):
    access = require_admin_access(request)
    if feedback_id <= 0:
        raise HTTPException(status_code=400, detail="The feedback record is invalid.")
    decision = str(req.decision or "").strip().lower()
    if decision not in {"accepted", "dismissed"}:
        raise HTTPException(status_code=400, detail="Choose accepted or dismissed.")
    payload = {
        "review_status": decision,
        "review_note": sanitize_feedback_text(req.review_note, 500),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_by": str(access["user_id"]),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    updated = supabase_rest_request(
        "PATCH",
        "scan_feedback",
        payload=payload,
        query=urlencode({"id": f"eq.{int(feedback_id)}"}),
        prefer="return=representation",
    )
    if not isinstance(updated, list) or not updated:
        return private_json({"detail": "The feedback record could not be updated."}, status_code=404)
    return private_json({"reviewed": True, "feedback": updated[0], "stored_code": False})


@app.get("/admin/feedback/export")
def export_admin_feedback(request: Request, status: str = "accepted"):
    require_admin_access(request)
    review_status = str(status or "accepted").strip().lower()
    if review_status not in {"accepted", "pending", "dismissed", "all"}:
        raise HTTPException(status_code=400, detail="Choose pending, accepted, dismissed, or all.")
    filters = {
        "select": (
            "id,created_at,scan_id,finding_id,verdict,category,note,scanner_version,"
            "review_status,review_note,reviewed_at"
        ),
        "order": "created_at.asc",
        "limit": "1000",
    }
    if review_status != "all":
        filters["review_status"] = f"eq.{review_status}"
    rows = supabase_rest_request("GET", "scan_feedback", query=urlencode(filters))
    feedback = rows if isinstance(rows, list) else []
    candidates = [{
        "feedback_id": int(item.get("id") or 0),
        "verdict": str(item.get("verdict") or ""),
        "category": str(item.get("category") or "")[:80],
        "scanner_version": int(item.get("scanner_version") or 0),
        "review_status": str(item.get("review_status") or "pending"),
        "review_note": sanitize_feedback_text(item.get("review_note") or "", 500),
        "user_note": sanitize_feedback_text(item.get("note") or "", 500),
        "scan_fingerprint": str(item.get("scan_id") or "")[:32],
        "finding_fingerprint": str(item.get("finding_id") or "")[:40],
        "test_case_ready": False,
        "missing": ["minimal reproducing code", "independently verified expected result"],
    } for item in feedback]
    export = {
        "schema_version": 1,
        "scanner_version": SCANNER_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contains_source_code": False,
        "warning": "Candidates must be independently reviewed and supplied with a minimal reproducer before becoming regression tests.",
        "candidates": candidates,
    }
    return Response(
        content=json.dumps(export, indent=2) + "\n",
        media_type="application/json",
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Content-Disposition": 'attachment; filename="ai-code-audit-feedback-candidates.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )



@app.post("/scan-repo")
def scan_repo(req: RepoScanRequest, request: Request):
    access = get_request_access_context(request)
    access = enrich_access_with_admin_metadata(access)
    enforce_rate_limit(request, access, "repo")

    if len(req.intent) > 2000 or len(req.repo_url) > 500:
        return private_json({"error": "The repository request is too long."}, status_code=413)

    try:
        owner, repo = parse_github_repo(req.repo_url)
        zip_bytes = download_repo_zip(owner, repo)
    except ValueError as exc:
        return private_json({"error": str(exc)}, status_code=400)
    except Exception:
        return private_json({"error": "Something went wrong while scanning this repository."}, status_code=502)

    repo_file_limit = access["limits"].get("repo_file_limit")
    repo_size_limit_bytes = access["limits"].get("repo_size_limit_bytes")

    files_scanned = []
    repo_weighted_points: list[float] = []
    all_touches = set()
    all_behavior_summary = []
    highest_file_risk = "green"

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        dependency_scan = analyze_dependency_manifests(zf)
        dependency_findings = dependency_scan["dependency_findings"]
        dependency_risk_points = float(dependency_scan["dependency_risk_points"])
        dependency_rollup = dependency_scan.get("dependency_rollup", {
            "advisory_count": 0,
            "unique_package_versions": 0,
            "unique_manifest_files": 0,
            "unique_vulnerability_ids": 0,
        })

        all_code_files = [
            name for name in zf.namelist()
            if not name.endswith("/") and is_supported_code_file(name)
        ]
        all_code_files.sort(key=lambda name: (-file_weight_for_repo(name), name.lower()))
        code_files = all_code_files[:repo_file_limit] if repo_file_limit is not None else list(all_code_files)

        if repo_size_limit_bytes is not None:
            size_limited_files = []
            selected_size = 0
            for name in code_files:
                file_size = zf.getinfo(name).file_size
                if selected_size + file_size > repo_size_limit_bytes:
                    continue
                size_limited_files.append(name)
                selected_size += file_size
            code_files = size_limited_files

        repo_code_size_bytes = sum(zf.getinfo(name).file_size for name in all_code_files)

        for file_name in code_files:
            try:
                with zf.open(file_name) as file:
                    raw = file.read()
                    code_text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            result = analyze_code(req.intent, code_text, plan=access["plan"])
            weight = file_weight_for_repo(file_name)
            weighted_file_points = weighted_repository_file_points(file_name, result["risk_points"])
            repo_weighted_points.append(weighted_file_points)

            files_scanned.append({
                "file": file_name,
                "risk": result["risk"],
                "trust_score": result["trust_score"],
                "summary": result["summary"],
                "touches": result["touches"],
                "flags": result["flags"],
                "intent_mismatches": result["intent_mismatches"],
                "behavior_summary": result["behavior_summary"],
                "file_weight": weight,
                "weighted_risk_points": round(weighted_file_points, 2),
                "focused_code_blocks": result["focused_code_blocks"],
            })

            all_touches.update(result["touches"])

            for item in result["behavior_summary"]:
                if item not in all_behavior_summary:
                    all_behavior_summary.append(item)

            if result["risk"] == "red":
                highest_file_risk = "red"
            elif result["risk"] == "yellow" and highest_file_risk != "red":
                highest_file_risk = "yellow"

    files_available_count = len(all_code_files)
    coverage_partial = len(code_files) < files_available_count

    if not files_scanned and not dependency_findings:
        return private_json({
            "scanner_version": SCANNER_VERSION,
            "repo_url": req.repo_url,
            "repo_name": f"{owner}/{repo}",
            "risk": "limited",
            "trust_score": 0,
            "trust_badge": {
                "label": "No scannable code",
                "emoji": "⚪",
                "color": "gray",
                "message": "No supported source files or dependency findings were available, so this repository was not rated safe.",
            },
            "readme_badge": None,
            "files_scanned_count": 0,
            "files_available_count": files_available_count,
            "files_scanned_limit": repo_file_limit if repo_file_limit is not None else "Unlimited",
            "coverage_partial": coverage_partial,
            "touches": [],
            "behavior_summary": ["No supported source files were available for analysis."],
            "summary": "Repository downloaded successfully, but no scannable code was found.",
            "risk_points": 0,
            "highest_file_risk": "unknown",
            "files": [],
            "dependency_summary": {
                "manifests_scanned": dependency_scan["manifests_scanned"],
                "dependencies_parsed": dependency_scan["dependencies_parsed"],
                "dependencies_queried": dependency_scan["dependencies_queried"],
                "dependencies_skipped_count": len(dependency_scan["dependencies_skipped"]),
                "vulnerabilities_found": 0,
                "risk_points": 0,
                "summary_lines": dependency_scan.get("dependency_summary_lines", []),
                "scan_error": dependency_scan.get("dependency_scan_error"),
            },
            "dependency_findings": [],
            "dependency_skipped": dependency_scan["dependencies_skipped"][:25],
            "scan_confidence": {
                "level": "Insufficient",
                "lines": ["No supported source files were found. A safety rating was not produced."],
            },
            "verdict": build_action_verdict("limited", 0, insufficient=True),
            "coverage": build_repo_coverage([], files_available_count, dependency_scan),
            "access": access,
            "privacy": {"stored_by_scanner": False, "response_cache_disabled": True},
        })

    if dependency_findings:
        all_touches.add("dependencies")
        dep_summary_line = (
            f"Contains {dependency_rollup['advisory_count']} dependency advisory finding(s) across "
            f"{dependency_rollup['unique_package_versions']} package/version pair(s)."
        )
        if dep_summary_line not in all_behavior_summary:
            all_behavior_summary.append(dep_summary_line)

    if files_scanned and not dependency_findings:
        if "No major code-behavior risks were detected in the scanned files." not in all_behavior_summary:
            all_behavior_summary.append("No major code-behavior risks were detected in the scanned files.")

    if dependency_findings:
        line = "Dependency vulnerability findings were also detected in manifest files."
        if line not in all_behavior_summary:
            all_behavior_summary.append(line)

    for extra_line in dependency_scan.get("dependency_summary_lines", []):
        if extra_line not in all_behavior_summary:
            all_behavior_summary.append(extra_line)

    normalized_repo_points = calculate_repository_risk_points(
        repo_weighted_points,
        dependency_risk_points,
    )

    overall_risk = risk_from_points(normalized_repo_points)
    trust_score = calculate_trust_score_from_points(normalized_repo_points)
    trust_badge = build_trust_badge(trust_score, overall_risk)
    flattened_repo_flags = [flag for file_result in files_scanned for flag in file_result.get("flags", [])]
    repo_behavior_categories = sorted(list(all_touches))
    repo_intent_mismatches = [
        mismatch
        for file_result in files_scanned
        for mismatch in file_result.get("intent_mismatches", [])
    ]
    score_explanation = summarize_score_explanation(
        flattened_repo_flags,
        dependency_findings,
        repo_behavior_categories,
        repo_intent_mismatches,
    )
    score_explanation_lines = build_score_explanation_lines(score_explanation, "repo")
    scan_confidence = build_scan_confidence(
        "repo",
        files_scanned_count=len(files_scanned),
        files_total=files_available_count,
        dependency_summary={
            "dependencies_queried": dependency_scan["dependencies_queried"],
            "dependencies_skipped_count": len(dependency_scan["dependencies_skipped"]),
            "scan_error": dependency_scan.get("dependency_scan_error"),
        },
        scan_error=dependency_scan.get("dependency_scan_error"),
    )
    evidence = build_evidence_profile(
        flattened_repo_flags,
        repo_behavior_categories,
        repo_intent_mismatches,
        dependency_points=dependency_risk_points,
        coverage_partial=coverage_partial,
    )

    return private_json({
        "scanner_version": SCANNER_VERSION,
        "repo_url": req.repo_url,
        "repo_name": f"{owner}/{repo}",
        "risk": overall_risk,
        "trust_score": trust_score,
        "trust_badge": trust_badge,
        "readme_badge": generate_readme_badge(str(request.base_url), owner, repo, trust_score, overall_risk),
        "files_scanned_count": len(files_scanned),
        "files_available_count": files_available_count,
        "files_scanned_limit": repo_file_limit if repo_file_limit is not None else "Unlimited",
        "coverage_partial": coverage_partial,
        "repo_size_bytes": repo_code_size_bytes,
        "repo_size_limit_bytes": repo_size_limit_bytes,
        "touches": sorted(list(all_touches)),
        "score_explanation": score_explanation,
        "score_explanation_lines": score_explanation_lines,
        "scan_confidence": scan_confidence,
        "verdict": build_action_verdict(overall_risk, trust_score),
        "coverage": build_repo_coverage(
            [str(item.get("file") or "") for item in files_scanned],
            files_available_count,
            dependency_scan,
        ),
        "evidence": evidence,
        "analysis_engines": [
            {"name": "behavior", "status": "complete", "findings": len(flattened_repo_flags)},
            {"name": "dependency-advisories", "status": "complete" if not dependency_scan.get("dependency_scan_error") else "partial", "findings": len(dependency_findings)},
        ],
        "dynamic_sandbox": {"status": "not_enabled", "reason": "Repository code is inspected but never executed."},
        "behavior_summary": all_behavior_summary or ["No obvious risky behavior was detected in this repo scan."],
        "summary": f"Weighted repo scan completed across {len(files_scanned)} files.",
        "risk_points": round(normalized_repo_points, 2),
        "highest_file_risk": highest_file_risk,
        "files": files_scanned,
        "dependency_summary": {
            "manifests_scanned": dependency_scan["manifests_scanned"],
            "dependencies_parsed": dependency_scan["dependencies_parsed"],
            "dependencies_queried": dependency_scan["dependencies_queried"],
            "dependencies_skipped_count": len(dependency_scan["dependencies_skipped"]),
            "vulnerabilities_found": len(dependency_findings),
            "risk_points": dependency_risk_points,
            "summary_lines": dependency_scan.get("dependency_summary_lines", []),
            "scan_error": dependency_scan.get("dependency_scan_error"),
            "advisory_count": dependency_rollup["advisory_count"],
            "unique_package_versions": dependency_rollup["unique_package_versions"],
            "unique_manifest_files": dependency_rollup["unique_manifest_files"],
            "unique_vulnerability_ids": dependency_rollup["unique_vulnerability_ids"],
        },
        "dependency_findings": dependency_findings,
        "dependency_skipped": dependency_scan["dependencies_skipped"][:25],
        "access": access,
        "privacy": {"stored_by_scanner": False, "response_cache_disabled": True},
    })


@app.get("/badge/github/{owner}/{repo}.svg")
def github_repo_badge_svg(owner: str, repo: str):
    cache_key = f"{owner}/{repo}".lower()
    now = time.time()
    cached = BADGE_CACHE.get(cache_key)

    if cached and now - cached.get("timestamp", 0) < BADGE_CACHE_TTL_SECONDS:
        trust_score = cached["trust_score"]
        risk = cached["risk"]
    else:
        try:
            repo_url = f"https://github.com/{owner}/{repo}"
            zip_bytes = download_repo_zip(owner, repo)
            badge_weighted_points: list[float] = []

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                dependency_scan = analyze_dependency_manifests(zf)
                dependency_risk_points = float(dependency_scan["dependency_risk_points"])

                code_files = [
                    name for name in zf.namelist()
                    if not name.endswith("/") and is_supported_code_file(name)
                ][:FREE_REPO_FILE_LIMIT]

                if not code_files and not dependency_scan.get("dependency_findings"):
                    svg = build_badge_svg("AI Code Audit", "not rated", "#6b7280")
                    return Response(
                        content=svg,
                        media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=120"},
                    )

                for file_name in code_files:
                    try:
                        with zf.open(file_name) as file:
                            raw = file.read()
                            code_text = raw.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    result = analyze_code("Scan this public GitHub repo", code_text, plan="free")
                    badge_weighted_points.append(
                        weighted_repository_file_points(file_name, result["risk_points"])
                    )

            normalized_repo_points = calculate_repository_risk_points(
                badge_weighted_points,
                dependency_risk_points,
            )

            risk = risk_from_points(normalized_repo_points)
            trust_score = calculate_trust_score_from_points(normalized_repo_points)

            BADGE_CACHE[cache_key] = {
                "timestamp": now,
                "trust_score": trust_score,
                "risk": risk,
            }
        except Exception:
            svg = build_badge_svg("AI Code Audit", "scan failed", "#ef4444")
            return Response(
                content=svg,
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=120"},
            )

    svg = build_badge_svg("AI Code Audit", f"{trust_score}/100", badge_color_from_risk(risk, trust_score))
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": f"public, max-age={BADGE_CACHE_TTL_SECONDS}"},
    )
