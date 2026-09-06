from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import os
import io
import base64
import ast
import json
import zipfile
import urllib.request
import ssl
import certifi
import hashlib
import time
from html import escape as html_escape
from dotenv import load_dotenv
from datetime import date, datetime, timezone
from urllib.parse import urlparse, quote, urlencode
import stripe

load_dotenv()

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    intent: str
    code: str
    is_example: bool = False


class RepoScanRequest(BaseModel):
    intent: str
    repo_url: str


# display_key, regex, label, base severity points
SUSPICIOUS_PATTERNS = [
    ("eval(", r"(?<![\w.])eval\s*\(", "Suspicious usage detected: eval(", 25),
    ("exec(", r"(?<![\w.])exec\s*\(", "Suspicious usage detected: exec(", 25),
    ("os.system", r"\bos\.system\s*\(", "Suspicious usage detected: os.system", 30),
    ("subprocess", r"\bsubprocess\b", "Suspicious usage detected: subprocess", 15),
    ("child_process", r"\bchild_process\b", "Suspicious usage detected: child_process", 15),
    ("requests.post", r"\brequests\.post\s*\(", "Suspicious usage detected: requests.post", 4),
    ("requests.get", r"\brequests\.get\s*\(", "Suspicious usage detected: requests.get", 2),
    ("socket", r"\bsocket\b", "Suspicious usage detected: socket", 8),
    ("fetch(", r"(?<![\w.])fetch\s*\(", "Suspicious usage detected: fetch(", 0.5),
    ("open(", r"(?<![\w.])open\s*\(", "Suspicious usage detected: open(", 0.5),
    ("base64", r"\bbase64\b", "Suspicious usage detected: base64", 0.25),
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
    ("download helper", r"\b(curl|wget)\b", "Suspicious usage detected: download helper", 8),
    ("bytes.fromhex", r"\bbytes\.fromhex\s*\(", "Suspicious usage detected: bytes.fromhex", 4),
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

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "price_1TBryAEKmNfjd7YM13LoKYvs").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

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
}

OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{osv_id}"
OSV_BATCH_SIZE = 100

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


def decode_supabase_access_token(access_token: str) -> dict | None:
    if not access_token or access_token.count(".") < 2:
        return None

    try:
        payload_segment = access_token.split(".")[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
        payload = json.loads(decoded.decode("utf-8"))
    except Exception:
        return None

    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id or not email:
        return None

    app_metadata = payload.get("app_metadata") or {}
    role = str(app_metadata.get("role") or "user").lower()
    plan = str(app_metadata.get("plan") or ("admin" if role == "admin" else "free")).lower()

    return {
        "id": user_id,
        "email": email,
        "app_metadata": app_metadata,
        "role": role,
        "plan": plan,
    }


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

    decoded_user = decode_supabase_access_token(access_token)
    if decoded_user:
        return decoded_user, False

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
    access["debug"]["user_token_decoded_fallback"] = bool(user and not verified_with_supabase)
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
    user_agent = request.headers.get("user-agent", "")
    fingerprint = f"{client_host}|{user_agent}"
    digest = hashlib.sha256(fingerprint.encode("utf-8", errors="ignore")).hexdigest()
    return f"anon:{digest}"


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
        "label": "Safe",
        "emoji": "🟢",
        "color": "green",
        "message": "Looks relatively safe based on this scan."
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


def parse_github_repo(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    parts = [p for p in parsed.path.split("/") if p]

    if parsed.netloc not in {"github.com", "www.github.com"} or len(parts) < 2:
        raise ValueError("Please provide a valid public GitHub repository URL.")

    owner = parts[0]
    repo = parts[1].replace(".git", "")
    return owner, repo


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
                return response.read()
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
    js_brace_depth = 0
    guidance_brace_depth = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

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
    return any(re.search(pattern, line) for pattern in SOURCE_PATTERNS)


def extract_assigned_variable(line: str) -> str | None:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
    if match:
        return match.group(1)
    return None


def build_taint_map(scannable_lines: list[tuple[int, str]]) -> dict[str, str]:
    tainted: dict[str, str] = {}

    for _, line in scannable_lines:
        line_lower = line.lower()
        variable = extract_assigned_variable(line)

        if not variable:
            continue

        if line_contains_source(line_lower):
            tainted[variable] = "source"
            continue

        for known_var in list(tainted.keys()):
            if re.search(rf"\b{re.escape(known_var)}\b", line_lower):
                tainted[variable] = "propagated"
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


def add_secret_flow_heuristics(
    scannable_lines: list[tuple[int, str]],
    secret_variables: dict[str, int],
) -> list[dict]:
    if not secret_variables:
        return []

    network_sink = re.compile(
        r"requests\.(?:post|put|patch|request)\s*\(|(?<![\w.])fetch\s*\(|"
        r"axios\.(?:post|put|patch|request)\s*\(|urllib\.request\.(?:urlopen|Request)\s*\(",
        re.IGNORECASE,
    )
    findings: list[dict] = []

    for line_number, line in scannable_lines:
        if not network_sink.search(line):
            continue
        exposed = [name for name in secret_variables if re.search(rf"\b{re.escape(name)}\b", line)]
        if not exposed:
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
    args_lower = args.lower()

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

    if args and not is_literal_argument_text(args):
        boost += 4
        context_notes.append("It appears to be called with a dynamic value instead of a fixed literal.")

    if any(marker in args for marker in dynamic_markers):
        boost += 4
        context_notes.append("The argument appears to be dynamically constructed.")

    if line_contains_source(line_lower) or line_contains_source(args_lower):
        boost += 12
        context_notes.append("User-controlled or external input appears near this sink, which raises the risk significantly.")

    for variable_name in tainted_vars:
        if re.search(rf"\b{re.escape(variable_name.lower())}\b", args_lower):
            boost += 12
            context_notes.append(f"The argument appears to use a variable derived from external input ({variable_name}).")
            break

    if args and is_literal_argument_text(args) and boost == 0:
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


def add_multi_signal_heuristics(scannable_lines: list[tuple[int, str]]) -> list[dict]:
    heuristic_flags: list[dict] = []
    joined_code = "\n".join(line for _, line in scannable_lines)
    cleaned_code = strip_string_literals(joined_code).lower()

    has_exec = bool(re.search(r"(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(", cleaned_code))
    has_base64_decode = bool(re.search(r"base64\.(b64decode|standard_b64decode|urlsafe_b64decode)\s*\(", cleaned_code))
    has_hex_decode = bool(re.search(r"bytes\.fromhex\s*\(", cleaned_code))
    has_download = bool(re.search(
        r"requests\.(get|post)\s*\(|urllib\.request\.(urlopen|urlretrieve|request)\s*\(|(?<![\w.])fetch\s*\(|\b(curl|wget)\b",
        cleaned_code,
    ))
    has_system_exec = bool(re.search(
        r"\bos\.system\s*\(|\bsubprocess\b|\bchild_process\b|(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(",
        cleaned_code,
    ))
    has_long_base64_blob = bool(re.search(r"[A-Za-z0-9+/]{180,}={0,2}", joined_code))
    has_chr_chain = len(re.findall(r"\bchr\s*\(", cleaned_code)) >= 4

    if has_exec and (has_base64_decode or has_hex_decode):
        line_number = find_first_matching_line(
            scannable_lines,
            r"base64\.(b64decode|standard_b64decode|urlsafe_b64decode)\s*\(|bytes\.fromhex\s*\(",
        )
        heuristic_flags.append(make_flag(
            line=line_number,
            flag_type="heuristic",
            pattern="obfuscated_execution",
            message="Suspicious behavior detected: encoded data appears to be executed",
            severity=18,
            explanation=explain_flag("obfuscated_execution", "heuristic"),
        ))

    if has_download and has_system_exec:
        line_number = find_first_matching_line(
            scannable_lines,
            r"os\.system\s*\(|subprocess|child_process|(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(",
        )
        heuristic_flags.append(make_flag(
            line=line_number,
            flag_type="heuristic",
            pattern="download_execute_chain",
            message="Suspicious behavior detected: remote content may be downloaded and then executed",
            severity=14,
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


def analyze_python_ast(code: str) -> list[dict]:
    ast_flags: list[dict] = []

    try:
        tree = ast.parse(code)
    except Exception:
        return ast_flags

    tainted_vars: set[str] = set()
    current_function_stack: list[str] = []

    def is_tainted_value(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted_vars

        if isinstance(node, ast.JoinedStr):
            return True

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"input", "__import__"}:
                return True
            if isinstance(node.func, ast.Name) and node.func.id in {"getenv"}:
                return True
            if isinstance(node.func, ast.Attribute):
                attr_base = getattr(node.func.value, "id", "")
                if attr_base in {"os", "request", "sys", "importlib"}:
                    return True

        if isinstance(node, ast.Attribute):
            attr_base = getattr(node.value, "id", "")
            if attr_base in {"request", "sys", "os"}:
                return True

        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                attr_base = getattr(node.value.value, "id", "")
                if attr_base in {"request", "os"}:
                    return True
            if isinstance(node.value, ast.Name) and node.value.id in {"argv", "environ"}:
                return True

        return False

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
            boost += 4
            notes.append("It appears to be called with a variable instead of a fixed literal.")
        elif isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
            boost += 4
            notes.append("The value appears to be dynamically constructed.")
        elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            if pattern_key == "os.system":
                boost -= 8
            elif pattern_key in {"eval(", "exec("}:
                boost -= 2
            elif pattern_key in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads"}:
                boost -= 1
            else:
                boost -= 4
            notes.append("This appears to use a fixed literal value, which lowers the risk somewhat.")

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
            if is_tainted_value(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted_vars.add(target.id)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign):
            if node.value and isinstance(node.target, ast.Name) and is_tainted_value(node.value):
                tainted_vars.add(node.target.id)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id == "eval":
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

                elif node.func.id == "exec":
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
                    if node.func.value.id == "os" and node.func.attr == "system":
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

                    elif node.func.value.id == "subprocess":
                        explanation = explain_flag("subprocess", "suspicious_behavior")
                        boost, explanation = build_context_note(explanation, node, "subprocess")
                        ast_flags.append(make_flag(
                            line=node.lineno,
                            flag_type="suspicious_behavior",
                            pattern="subprocess",
                            message="Suspicious usage detected: subprocess",
                            severity=15 + boost,
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

                    elif node.func.value.id == "pickle" and node.func.attr == "loads":
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

                    elif node.func.value.id == "pickle" and node.func.attr == "load":
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

                    elif node.func.value.id == "marshal" and node.func.attr == "loads":
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

                    elif node.func.value.id == "marshal" and node.func.attr == "load":
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

                    elif node.func.value.id == "yaml" and node.func.attr == "load":
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

                    elif node.func.value.id == "dill" and node.func.attr == "loads":
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
    return ast_flags


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
    manifest_files = [
        name for name in zip_file.namelist()
        if not name.endswith("/") and is_dependency_manifest(name)
    ]

    all_dependencies: list[dict] = []
    skipped_dependencies: list[dict] = []
    manifest_scan_errors: list[str] = []

    for file_name in manifest_files:
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
        else:
            deps, skipped = [], []

        all_dependencies.extend(deps)
        skipped_dependencies.extend(skipped)

    deduped_dependencies = dedupe_dependencies(all_dependencies)

    try:
        osv_matches = query_osv_batch(deduped_dependencies)
    except Exception as exc:
        return {
            "manifests_scanned": len(manifest_files),
            "dependencies_parsed": len(deduped_dependencies),
            "dependencies_queried": 0,
            "dependencies_skipped": skipped_dependencies,
            "dependency_findings": [],
            "dependency_risk_points": 0.0,
            "dependency_summary_lines": [f"Dependency vulnerability lookup failed: {exc}"],
            "dependency_scan_error": "Dependency vulnerability lookup failed during the repo scan.",
            "dependency_rollup": {
                "advisory_count": 0,
                "unique_package_versions": 0,
                "unique_manifest_files": 0,
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
    if dependency_findings:
        summary_lines.append(
            f"Found {rollup['advisory_count']} dependency advisory finding(s) across "
            f"{rollup['unique_package_versions']} package/version pair(s)."
        )
    elif manifest_files:
        summary_lines.append("No known dependency vulnerabilities were found in the queried manifest versions.")

    summary_lines.extend(manifest_scan_errors)

    return {
        "manifests_scanned": len(manifest_files),
        "dependencies_parsed": len(deduped_dependencies),
        "dependencies_queried": len(deduped_dependencies),
        "dependencies_skipped": skipped_dependencies,
        "dependency_findings": dependency_findings,
        "dependency_risk_points": dependency_risk_points,
        "dependency_summary_lines": summary_lines,
        "dependency_scan_error": None,
        "dependency_rollup": rollup,
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


def analyze_code(intent: str, code: str, plan: str = "free") -> dict:
    intent_lower = intent.lower()
    original_lines = code.splitlines()

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

    scannable_lines = extract_scannable_lines(code)
    tainted_vars = build_taint_map(scannable_lines)
    secret_variables, secret_source_flags = find_environment_secret_sources(scannable_lines)

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

        line_lower = line.lower()
        line_without_strings = strip_string_literals(line_lower)

        for display_key, regex_pattern, label, base_severity in SUSPICIOUS_PATTERNS:
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

    try:
        ast_flags = analyze_python_ast(code)
    except Exception:
        ast_flags = []

    try:
        heuristic_flags = add_multi_signal_heuristics(scannable_lines)
    except Exception:
        heuristic_flags = []

    try:
        secret_flow_flags = add_secret_flow_heuristics(scannable_lines, secret_variables)
    except Exception:
        secret_flow_flags = []

    flags = dedupe_flags(regex_flags + ast_flags + heuristic_flags + secret_source_flags + secret_flow_flags)
    secret_access_expected = intent_mentions_any(
        intent_lower,
        ["credential", "credentials", "secret", "api key", "token", "password", "authenticate", "authentication", "authorization"],
    )
    if secret_access_expected:
        for flag in flags:
            if flag.get("pattern") == "environment_secret_access":
                flag["severity"] = 5.0
                flag["explanation"] += " The stated intent appears to expect credential access, so this finding was reduced."
    risk_points = round(sum(float(flag["severity"]) for flag in flags), 2)

    cleaned_code = "\n".join(line for _, line in scannable_lines)
    cleaned_code_lower = strip_string_literals(cleaned_code).lower()

    if re.search(
        r"https?://|(?<![\w.])fetch\s*\(|\brequests\.(get|post|put|delete|patch|request)\s*\(|\burllib\.request\.(urlopen|request|urlretrieve)\b|\bsocket\b|\b(curl|wget)\b",
        cleaned_code_lower,
    ):
        touches.append("network")

    if re.search(
        r"(?<![\w.])open\s*\(|\.write\s*\(|read_text\s*\(|write_text\s*\(|read_bytes\s*\(|write_bytes\s*\(",
        cleaned_code_lower,
    ):
        touches.append("files")

    if re.search(
        r"(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(|\bos\.system\s*\(|\bsubprocess\b|\bchild_process\b",
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
        touches.append("obfuscation")

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
        intent_lower, ["file", "save", "write", "export", "download", "upload", "repo", "github", "read"]
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

    has_literal_or_exfiltrated_secret = any(
        flag.get("type") in {"secret", "secret_exfiltration"} for flag in flags
    )
    if "secrets" in touches and (has_literal_or_exfiltrated_secret or not secret_access_expected):
        mismatch_flags.append("Code appears to contain secrets or credentials, which may be unsafe.")
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

    if "obfuscation" in touches:
        behavior_summary.append("Contains encoding or obfuscation signals that may hide behavior.")

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
        "summary": f"{len(flags)} suspicious patterns detected and {len(mismatch_flags)} intent mismatch warnings",
        "code": code,
        "trust_score": trust_score,
        "trust_badge": trust_badge,
        "risk_points": risk_points,
        "focused_code_blocks": focused_code_blocks,
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
            stripe_customer_id = str(subscription.get("customer") or "").strip() or None
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

    if not access.get("authenticated") or not access.get("user_id"):
        raise HTTPException(status_code=401, detail="Log in before verifying checkout status.")

    try:
        session = stripe.checkout.Session.retrieve(str(session_id).strip())
    except Exception as exc:
        log_server_issue("Could not retrieve Stripe checkout session status", exc)
        raise HTTPException(status_code=500, detail="Could not verify checkout status right now.") from exc

    session_status = str(session.get("status") or "").lower()
    payment_status = str(session.get("payment_status") or "").lower()
    subscription_id = session.get("subscription")
    customer_id = session.get("customer")
    metadata = session.get("metadata") or {}

    user_id = resolve_supabase_user_id_for_stripe_event(
        explicit_user_id=metadata.get("user_id") or session.get("client_reference_id"),
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
            subscription_status = str(subscription.get("status") or "active")
            cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or False)
            current_period_end = subscription.get("current_period_end")
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
            subscription_status = str(subscription.get("status") or "")
            cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or False)
            current_period_end = subscription.get("current_period_end")
            plan = plan_from_subscription_status(
                subscription_status,
                cancel_at_period_end=cancel_at_period_end,
                current_period_end=current_period_end,
            )
        except Exception as exc:
            log_server_issue("Could not retrieve subscription while reporting checkout status", exc)

    refreshed_access = build_authenticated_access_payload_for_user(str(user_id), request=request)
    response_payload = {
        "session_id": str(session.get("id") or session_id),
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
    if not stripe_is_configured():
        raise HTTPException(status_code=503, detail="Stripe is not fully configured on the server yet.")

    access_token = await extract_request_access_token(request)
    access = get_request_access_context(request, access_token=access_token)
    access = enrich_access_with_admin_metadata(access)

    if not access.get("authenticated") or not access.get("user_id") or not access.get("email"):
        raise HTTPException(status_code=401, detail="Log in before restoring a paid subscription.")
    if not (access.get("debug") or {}).get("user_fetch_succeeded"):
        raise HTTPException(
            status_code=503,
            detail="Your payment is safe, but the server cannot securely update your account. Replace SUPABASE_SECRET_KEY in Render with the current Supabase secret key, redeploy, then select Restore paid subscription.",
        )

    try:
        checkout_sessions = stripe.checkout.Session.list(limit=100)
        session_records = list(getattr(checkout_sessions, "data", None) or checkout_sessions.get("data") or [])
    except Exception as exc:
        log_server_issue("Could not list Stripe Checkout Sessions while restoring subscription", exc)
        raise HTTPException(status_code=502, detail="Stripe could not be reached to restore the subscription right now.") from exc

    paid_session = None
    expected_user_id = str(access["user_id"])
    expected_email = str(access["email"]).strip().lower()
    for session in session_records:
        metadata = session.get("metadata") or {}
        session_user_id = str(metadata.get("user_id") or session.get("client_reference_id") or "")
        customer_details = session.get("customer_details") or {}
        session_email = str(
            metadata.get("user_email")
            or customer_details.get("email")
            or session.get("customer_email")
            or ""
        ).strip().lower()
        belongs_to_user = session_user_id == expected_user_id or (
            not session_user_id and session_email == expected_email
        )
        if (
            belongs_to_user
            and str(session.get("status") or "").lower() == "complete"
            and str(session.get("payment_status") or "").lower() in {"paid", "no_payment_required"}
            and session.get("subscription")
        ):
            paid_session = session
            break

    if not paid_session:
        raise HTTPException(
            status_code=404,
            detail="No completed paid checkout was found for this account. Confirm you are signed in with the same email used at checkout.",
        )

    raw_subscription = paid_session.get("subscription")
    raw_customer = paid_session.get("customer")
    subscription_id = str(
        raw_subscription.get("id") if hasattr(raw_subscription, "get") else raw_subscription
    ).strip()
    customer_id = str(raw_customer.get("id") if hasattr(raw_customer, "get") else raw_customer).strip()
    status = "active"
    cancel_at_period_end = False
    current_period_end = None
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        status = str(subscription.get("status") or "active").lower()
        cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or False)
        current_period_end = subscription.get("current_period_end")
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

    event_type = str(event.get("type") or "")
    event_object = (event.get("data") or {}).get("object") or {}

    if event_type == "checkout.session.completed":
        metadata = event_object.get("metadata") or {}
        subscription_id = event_object.get("subscription")
        customer_id = event_object.get("customer")
        user_id = resolve_supabase_user_id_for_stripe_event(
            explicit_user_id=metadata.get("user_id") or event_object.get("client_reference_id"),
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
                    subscription_status = str(subscription.get("status") or "active")
                    cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or False)
                    current_period_end = subscription.get("current_period_end")
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
        metadata = event_object.get("metadata") or {}
        customer_id = str(event_object.get("customer") or "") or None
        subscription_id = str(event_object.get("id") or "") or None
        user_id = resolve_supabase_user_id_for_stripe_event(
            explicit_user_id=metadata.get("user_id"),
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        if user_id:
            status = str(event_object.get("status") or "")
            cancel_at_period_end = bool(event_object.get("cancel_at_period_end") or False)
            current_period_end = event_object.get("current_period_end")
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

    elif event_type in {"invoice.payment_failed", "invoice.paid"}:
        customer_id = str(event_object.get("customer") or "") or None
        subscription_id = str(event_object.get("subscription") or "") or None
        user_id = resolve_supabase_user_id_for_stripe_event(
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
        )
        if user_id and subscription_id:
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
                status = str(subscription.get("status") or "")
                cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or False)
                current_period_end = subscription.get("current_period_end")
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


@app.get("/stripe/status")
def stripe_status():
    return {
        "configured": stripe_is_configured(),
        "has_publishable_key": bool(STRIPE_PUBLISHABLE_KEY),
        "has_price_id": bool(STRIPE_PRICE_ID),
        "has_webhook_secret": bool(STRIPE_WEBHOOK_SECRET),
        "supabase_admin_valid": supabase_admin_is_valid(),
        "app_base_url": APP_BASE_URL,
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


@app.post("/scan")
def scan(req: ScanRequest, request: Request):
    access = get_request_access_context(request)
    access = enrich_access_with_admin_metadata(access)

    is_example_scan = bool(req.is_example)

    result = analyze_code(req.intent, req.code, plan=access["plan"])
    result["access"] = access
    result["is_example"] = is_example_scan
    return result



@app.post("/scan-repo")
def scan_repo(req: RepoScanRequest, request: Request):
    access = get_request_access_context(request)
    access = enrich_access_with_admin_metadata(access)

    try:
        owner, repo = parse_github_repo(req.repo_url)
        zip_bytes = download_repo_zip(owner, repo)
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception:
        return {"error": "Something went wrong while scanning this repository."}

    repo_file_limit = access["limits"].get("repo_file_limit")
    repo_size_limit_bytes = access["limits"].get("repo_size_limit_bytes")

    files_scanned = []
    weighted_points_total = 0.0
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
            weighted_file_points = result["risk_points"] * weight
            weighted_points_total += weighted_file_points

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
        return {
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
            "access": access,
        }

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

    file_count = max(1, len(files_scanned))
    normalized_repo_points = weighted_points_total / file_count
    normalized_repo_points += dependency_risk_points

    if normalized_repo_points >= 35:
        normalized_repo_points *= 0.85
    elif normalized_repo_points >= 15:
        normalized_repo_points *= 0.9

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

    return {
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
    }


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
            weighted_points_total = 0.0

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
                    weighted_points_total += result["risk_points"] * file_weight_for_repo(file_name)

            file_count = max(1, len(code_files))
            normalized_repo_points = (weighted_points_total / file_count) + dependency_risk_points

            if normalized_repo_points >= 35:
                normalized_repo_points *= 0.85
            elif normalized_repo_points >= 15:
                normalized_repo_points *= 0.9

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
