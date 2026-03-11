from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import io
import zipfile
import urllib.request
import ssl
import certifi
from urllib.parse import urlparse

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    intent: str
    code: str


class RepoScanRequest(BaseModel):
    intent: str
    repo_url: str


SUSPICIOUS_PATTERNS = [
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "requests.post",
    "fetch(",
    "child_process",
    "base64",
    "socket",
    "open(",
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Possible AWS access key"),
    (r"-----BEGIN PRIVATE KEY-----", "Possible private key"),
    (r"sk-[A-Za-z0-9]{20,}", "Possible API secret key"),
    (r"AIza[0-9A-Za-z\\-_]{35}", "Possible Google API key"),
]

SUPPORTED_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb",
    ".php", ".cs", ".cpp", ".c", ".rs", ".sh", ".swift", ".kt",
    ".sql", ".html", ".css", ".json", ".yaml", ".yml", ".xml"
}

FREE_LINE_LIMIT = 10000
FREE_REPO_FILE_LIMIT = 50


def strip_string_literals(text: str) -> str:
    text = re.sub(r"'''[\s\S]*?'''", "", text)
    text = re.sub(r'"""[\s\S]*?"""', "", text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', "", text)
    return text


def calculate_trust_score(flag_count: int, mismatch_count: int, risk: str) -> int:
    trust_score = 100
    trust_score -= flag_count * 12
    trust_score -= mismatch_count * 10

    if risk == "yellow":
        trust_score -= 8
    elif risk == "red":
        trust_score -= 18

    return max(0, min(100, trust_score))


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
    else:
        return {
            "label": "Safe",
            "emoji": "🟢",
            "color": "green",
            "message": "Looks relatively safe based on this scan."
        }


def analyze_code(intent: str, code: str) -> dict:
    intent_lower = intent.lower()
    lines = code.splitlines()

    if len(lines) > FREE_LINE_LIMIT:
        return {
            "risk": "limit",
            "touches": [],
            "flags": [],
            "intent_mismatches": [],
            "behavior_summary": [],
            "summary": f"Free scans are limited to {FREE_LINE_LIMIT} lines. Pro unlocks larger file scanning.",
            "code": code,
            "trust_score": 0,
            "trust_badge": build_trust_badge(0, "red"),
        }

    flags = []
    touches = []

    inside_suspicious_block = False
    inside_secret_block = False

    for line_number, line in enumerate(lines, start=1):
        line_lower = line.lower()
        stripped = line.strip()

        if stripped.startswith("SUSPICIOUS_PATTERNS") and "[" in stripped:
            inside_suspicious_block = True

        if stripped.startswith("SECRET_PATTERNS") and "[" in stripped:
            inside_secret_block = True

        if inside_suspicious_block or inside_secret_block:
            if stripped == "]" or stripped == "],":
                inside_suspicious_block = False
                inside_secret_block = False
            continue

        line_without_strings = strip_string_literals(line_lower)

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in line_without_strings:
                flags.append({
                    "line": line_number,
                    "type": "suspicious_behavior",
                    "pattern": pattern,
                    "message": f"Suspicious usage detected: {pattern}"
                })

        for regex_pattern, label in SECRET_PATTERNS:
            if re.search(regex_pattern, line):
                flags.append({
                    "line": line_number,
                    "type": "secret",
                    "pattern": regex_pattern,
                    "message": label
                })

    cleaned_lines = []
    inside_suspicious_block = False
    inside_secret_block = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("SUSPICIOUS_PATTERNS") and "[" in stripped:
            inside_suspicious_block = True

        if stripped.startswith("SECRET_PATTERNS") and "[" in stripped:
            inside_secret_block = True

        if inside_suspicious_block or inside_secret_block:
            if stripped == "]" or stripped == "],":
                inside_suspicious_block = False
                inside_secret_block = False
            continue

        cleaned_lines.append(line)

    cleaned_code = "\n".join(cleaned_lines)
    cleaned_code_without_strings = strip_string_literals(cleaned_code)
    cleaned_code_lower = cleaned_code_without_strings.lower()

    if "http" in cleaned_code_lower or "fetch" in cleaned_code_lower or "requests" in cleaned_code_lower:
        touches.append("network")

    if "open(" in cleaned_code_lower or "write(" in cleaned_code_lower:
        touches.append("files")

    if (
        "exec" in cleaned_code_lower
        or "eval" in cleaned_code_lower
        or "subprocess" in cleaned_code_lower
        or "os.system" in cleaned_code_lower
        or "child_process" in cleaned_code_lower
    ):
        touches.append("system execution")

    if any(flag["type"] == "secret" for flag in flags):
        touches.append("secrets")

    touches = list(dict.fromkeys(touches))

    mismatch_flags = []

    if "network" in touches and not any(
        word in intent_lower for word in ["api", "fetch", "request", "http", "network", "online", "web"]
    ):
        mismatch_flags.append("Code uses network behavior not clearly mentioned in the intent.")

    if "files" in touches and not any(
        word in intent_lower for word in ["file", "save", "write", "export", "download", "upload"]
    ):
        mismatch_flags.append("Code reads or writes files not clearly mentioned in the intent.")

    if "system execution" in touches and not any(
        word in intent_lower for word in ["terminal", "shell", "command", "system", "script", "execute"]
    ):
        mismatch_flags.append("Code runs system-level commands not clearly mentioned in the intent.")

    if "secrets" in touches:
        mismatch_flags.append("Code appears to contain secrets or credentials, which may be unsafe.")

    behavior_summary = []

    if "network" in touches:
        behavior_summary.append("Makes outbound network requests.")

    if "files" in touches:
        behavior_summary.append("Reads or writes local files.")

    if "system execution" in touches:
        behavior_summary.append("Executes system-level commands.")

    if "secrets" in touches:
        behavior_summary.append("Contains possible credentials or secret values.")

    if mismatch_flags:
        behavior_summary.append("Includes behavior that may not match the stated request.")

    if not behavior_summary:
        behavior_summary.append("No obvious risky behavior was detected in this scan.")

    risk = "green"
    if len(flags) > 0 or len(mismatch_flags) > 0:
        risk = "yellow"
    if len(flags) + len(mismatch_flags) > 3:
        risk = "red"

    trust_score = calculate_trust_score(len(flags), len(mismatch_flags), risk)
    trust_badge = build_trust_badge(trust_score, risk)

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
    }


def parse_github_repo(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    parts = [p for p in parsed.path.split("/") if p]

    if parsed.netloc not in {"github.com", "www.github.com"} or len(parts) < 2:
        raise ValueError("Please provide a valid public GitHub repository URL.")

    owner = parts[0]
    repo = parts[1].replace(".git", "")
    return owner, repo


def download_repo_zip(owner: str, repo: str) -> bytes:
    urls = [
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/main",
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master",
    ]

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    last_error = None

    for url in urls:
        try:
            with urllib.request.urlopen(url, context=ssl_context) as response:
                return response.read()
        except Exception as exc:
            last_error = exc

    raise ValueError(f"Could not download repository zip. {last_error}")


def is_supported_code_file(filename: str) -> bool:
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in SUPPORTED_CODE_EXTENSIONS)


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan")
def scan(req: ScanRequest):
    return analyze_code(req.intent, req.code)


@app.post("/scan-repo")
def scan_repo(req: RepoScanRequest):
    owner, repo = parse_github_repo(req.repo_url)
    zip_bytes = download_repo_zip(owner, repo)

    files_scanned = []
    total_flags = 0
    total_mismatches = 0
    all_touches = set()
    all_behavior_summary = []
    overall_risk = "green"

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        code_files = [
            name for name in zf.namelist()
            if not name.endswith("/") and is_supported_code_file(name)
        ]

        code_files = code_files[:FREE_REPO_FILE_LIMIT]

        for file_name in code_files:
            try:
                with zf.open(file_name) as file:
                    raw = file.read()
                    code_text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            result = analyze_code(req.intent, code_text)

            files_scanned.append({
                "file": file_name,
                "risk": result["risk"],
                "trust_score": result["trust_score"],
                "summary": result["summary"],
                "touches": result["touches"],
                "flags": result["flags"],
                "intent_mismatches": result["intent_mismatches"],
                "behavior_summary": result["behavior_summary"],
            })

            total_flags += len(result["flags"])
            total_mismatches += len(result["intent_mismatches"])
            all_touches.update(result["touches"])

            for item in result["behavior_summary"]:
                if item not in all_behavior_summary:
                    all_behavior_summary.append(item)

            if result["risk"] == "red":
                overall_risk = "red"
            elif result["risk"] == "yellow" and overall_risk != "red":
                overall_risk = "yellow"

    trust_score = calculate_trust_score(total_flags, total_mismatches, overall_risk)
    trust_badge = build_trust_badge(trust_score, overall_risk)

    return {
        "repo_url": req.repo_url,
        "repo_name": f"{owner}/{repo}",
        "risk": overall_risk,
        "trust_score": trust_score,
        "trust_badge": trust_badge,
        "files_scanned_count": len(files_scanned),
        "files_scanned_limit": FREE_REPO_FILE_LIMIT,
        "touches": sorted(list(all_touches)),
        "behavior_summary": all_behavior_summary or ["No obvious risky behavior was detected in this repo scan."],
        "summary": f"{total_flags} suspicious patterns detected and {total_mismatches} intent mismatch warnings across {len(files_scanned)} files.",
        "files": files_scanned,
    }