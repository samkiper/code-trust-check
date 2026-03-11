from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import re

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    intent: str
    code: str


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

FREE_LINE_LIMIT = 200


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan")
def scan(req: ScanRequest):
    code_lower = req.code.lower()
    intent_lower = req.intent.lower()
    lines = req.code.splitlines()

    if len(lines) > FREE_LINE_LIMIT:
        return {
            "risk": "limit",
            "touches": [],
            "flags": [],
            "intent_mismatches": [],
            "behavior_summary": [],
            "summary": f"Free scans are limited to {FREE_LINE_LIMIT} lines. Pro unlocks larger file scanning.",
            "code": req.code,
        }

    flags = []
    touches = []

    for line_number, line in enumerate(lines, start=1):
        line_lower = line.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in line_lower:
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

    if "http" in code_lower or "fetch" in code_lower or "requests" in code_lower:
        touches.append("network")

    if "open(" in code_lower or "write(" in code_lower:
        touches.append("files")

    if (
        "exec" in code_lower
        or "eval" in code_lower
        or "subprocess" in code_lower
        or "os.system" in code_lower
        or "child_process" in code_lower
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

    return {
        "risk": risk,
        "touches": touches,
        "flags": flags,
        "intent_mismatches": mismatch_flags,
        "behavior_summary": behavior_summary,
        "summary": f"{len(flags)} suspicious patterns detected and {len(mismatch_flags)} intent mismatch warnings",
        "code": req.code,
    }