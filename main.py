from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re
import io
import ast
import json
import zipfile
import urllib.request
import ssl
import certifi
from urllib.parse import urlparse, quote

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    intent: str
    code: str


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

SUPPORTED_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb",
    ".php", ".cs", ".cpp", ".c", ".rs", ".sh", ".swift", ".kt",
    ".sql", ".html", ".css", ".json", ".yaml", ".yml", ".xml"
}

FREE_LINE_LIMIT = 10000
FREE_REPO_FILE_LIMIT = 50

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
    "cargo.toml": "crates.io",
    "go.mod": "Go",
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


def parse_cargo_toml_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies: list[dict] = []
    skipped: list[dict] = []
    current_section = ""

    supported_sections = {
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "target",
        "workspace.dependencies",
    }

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        section_match = re.match(r"^\[([^\]]+)\]$", stripped)
        if section_match:
            current_section = section_match.group(1).strip()
            continue

        if not current_section:
            continue

        if not any(
            current_section == section
            or current_section.startswith(f"target.")
            or current_section.endswith(".dependencies")
            for section in supported_sections
        ):
            continue

        if "=" not in stripped:
            continue

        package_name, raw_value = [part.strip() for part in stripped.split("=", 1)]
        package_name = package_name.strip("\"'")

        if not package_name:
            continue

        inline_table_match = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", raw_value)
        if inline_table_match:
            declared_version = inline_table_match.group(1).strip()
        elif raw_value.startswith('"') or raw_value.startswith("'"):
            declared_version = raw_value.strip().strip(',').strip("\"'")
        else:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Cargo dependency entry does not expose a simple version string.",
            })
            continue

        normalized_version, version_kind = normalize_manifest_version(str(declared_version))

        if not normalized_version:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "Cargo dependency entry uses a complex or unsupported version specifier.",
            })
            continue

        dependencies.append({
            "file": file_name,
            "manifest_type": "Cargo.toml",
            "line": line_number,
            "package": package_name,
            "ecosystem": "crates.io",
            "declared_version": str(declared_version).strip(),
            "version": normalized_version,
            "version_kind": version_kind,
            "dependency_section": current_section,
        })

    return dependencies, skipped


def parse_go_mod_manifest(file_name: str, content: str) -> tuple[list[dict], list[dict]]:
    dependencies: list[dict] = []
    skipped: list[dict] = []
    inside_require_block = False

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("//"):
            continue

        if stripped == "require (":
            inside_require_block = True
            continue

        if inside_require_block and stripped == ")":
            inside_require_block = False
            continue

        if inside_require_block:
            entry = stripped.split("//", 1)[0].strip()
            parts = entry.split()
            if len(parts) < 2:
                skipped.append({
                    "file": file_name,
                    "line": line_number,
                    "raw": raw_line.strip(),
                    "reason": "Could not confidently parse this go.mod requirement entry.",
                })
                continue

            package_name = parts[0].strip()
            declared_version = parts[1].strip()
        elif stripped.startswith("require "):
            entry = stripped[len("require "):].split("//", 1)[0].strip()
            parts = entry.split()
            if len(parts) < 2:
                skipped.append({
                    "file": file_name,
                    "line": line_number,
                    "raw": raw_line.strip(),
                    "reason": "Could not confidently parse this go.mod requirement entry.",
                })
                continue

            package_name = parts[0].strip()
            declared_version = parts[1].strip()
        else:
            continue

        normalized_version, version_kind = normalize_manifest_version(str(declared_version))

        if not normalized_version:
            skipped.append({
                "file": file_name,
                "line": line_number,
                "raw": raw_line.strip(),
                "reason": "go.mod entry uses a complex or unsupported version specifier.",
            })
            continue

        dependencies.append({
            "file": file_name,
            "manifest_type": "go.mod",
            "line": line_number,
            "package": package_name,
            "ecosystem": "Go",
            "declared_version": str(declared_version).strip(),
            "version": normalized_version,
            "version_kind": version_kind,
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
        elif lower_name.endswith("cargo.toml"):
            deps, skipped = parse_cargo_toml_manifest(file_name, content)
        elif lower_name.endswith("go.mod"):
            deps, skipped = parse_go_mod_manifest(file_name, content)
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


def analyze_code(intent: str, code: str) -> dict:
    intent_lower = intent.lower()
    original_lines = code.splitlines()

    if len(original_lines) > FREE_LINE_LIMIT:
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
            "risk_points": 100,
            "focused_code_blocks": [],
        }

    scannable_lines = extract_scannable_lines(code)
    tainted_vars = build_taint_map(scannable_lines)

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

    flags = dedupe_flags(regex_flags + ast_flags + heuristic_flags)
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

    if any(flag["type"] == "secret" for flag in flags):
        touches.append("secrets")

    touches = list(dict.fromkeys(touches))

    mismatch_flags = []
    meaningful_intent = has_meaningful_intent(intent)

    if meaningful_intent and "network" in touches and not any(
        word in intent_lower for word in ["api", "fetch", "request", "http", "network", "online", "web", "repo", "github", "download"]
    ):
        mismatch_flags.append("Code uses network behavior not clearly mentioned in the intent.")
        risk_points += 1.0

    if meaningful_intent and "files" in touches and not any(
        word in intent_lower for word in ["file", "save", "write", "export", "download", "upload", "repo", "github", "read"]
    ):
        mismatch_flags.append("Code reads or writes files not clearly mentioned in the intent.")
        risk_points += 1.0

    if meaningful_intent and "system execution" in touches and not any(
        word in intent_lower for word in ["terminal", "shell", "command", "system", "script", "execute", "cli"]
    ):
        mismatch_flags.append("Code runs system-level commands not clearly mentioned in the intent.")
        risk_points += 2.5

    if meaningful_intent and "dynamic imports" in touches and not any(
        word in intent_lower for word in ["plugin", "module", "import", "extension", "dynamic"]
    ):
        mismatch_flags.append("Code dynamically loads modules in a way that is not clearly mentioned in the intent.")
        risk_points += 2.0

    if meaningful_intent and "deserialization" in touches and not any(
        word in intent_lower for word in ["pickle", "yaml", "deserialize", "serialization", "load saved model", "cache"]
    ):
        mismatch_flags.append("Code deserializes data in a way that is not clearly mentioned in the intent.")
        risk_points += 2.0

    if "secrets" in touches:
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


def build_repo_badge_payload(repo_name: str, trust_badge: dict, trust_score: int, repo_url: str) -> dict:
    label_text = trust_badge.get("label", "Review")
    badge_label = f"AI Code Audit • {label_text} • {trust_score}/100"
    alt_text = f"{repo_name} AI Code Audit snapshot: {label_text} ({trust_score}/100)"
    color = trust_badge.get("color", "goldenrod")
    badge_message = f"{label_text} {trust_score}/100"
    badge_url = (
        "https://img.shields.io/badge/"
        f"{quote('AI Code Audit')}"
        f"-{quote(badge_message)}"
        f"-{quote(color)}?style=for-the-badge"
    )

    return {
        "label": badge_label,
        "alt_text": alt_text,
        "badge_url": badge_url,
        "markdown": f"[![{alt_text}]({badge_url})]({repo_url})",
        "html": f'<a href="{repo_url}" target="_blank" rel="noopener noreferrer"><img src="{badge_url}" alt="{alt_text}" /></a>',
        "image_markdown": f"![{alt_text}]({badge_url})",
        "snapshot_note": "This badge is a snapshot from this scan, not a continuously updating badge.",
    }

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
    try:
        owner, repo = parse_github_repo(req.repo_url)
        zip_bytes = download_repo_zip(owner, repo)
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception:
        return {"error": "Something went wrong while scanning this repository."}

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
    }