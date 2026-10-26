"""Wall-clock bound for trusted static analysis, isolated from the web worker.

Source travels over stdin, never command arguments or disk. This executes only
our scanner, never submitted code. Metering and queue ownership stay in parent.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from fastapi import HTTPException

AUDIT_TIMEOUT_SECONDS = 120
TIMEOUT_MESSAGE = 'The audit exceeded its maximum runtime and was stopped. No scan allowance was used. Try a smaller snippet or repository.'


def validation_stall_enabled(payload):
    digest=os.getenv('AUDIT_DEADLINE_VALIDATION_SHA256','')
    try:
        remaining=float(os.getenv('AUDIT_DEADLINE_VALIDATION_EXPIRES','0'))-time.time()
    except ValueError:
        return False
    code=payload.get('code')
    return (isinstance(code,str) and 0 < remaining <= 900 and len(digest)==64
            and hmac.compare_digest(digest,hashlib.sha256(code.encode()).hexdigest()))


def scanner_environment():
    # Only runtime and scanner configuration belong in parsing workers. Payment,
    # Auth, GitHub and AI secrets remain in the web process.
    allowed = {
        'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'TZ',
        'VIRTUAL_ENV', 'PYTHONPATH', 'PYTHONHOME', 'LD_LIBRARY_PATH',
        'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
        'SEMGREP_ENABLED', 'SEMGREP_BUDGET_SECONDS',
        'SEMGREP_FIRST_ATTEMPT_SECONDS', 'SEMGREP_NATIVE_CLI',
        'SCAN_TIMEOUT_VALIDATION_SHA256', 'SCAN_TIMEOUT_VALIDATION_EXPIRES',
        'AUDIT_DEADLINE_VALIDATION_SHA256', 'AUDIT_DEADLINE_VALIDATION_EXPIRES',
    }
    return {**{key: value for key, value in os.environ.items() if key in allowed},
            'AUDIT_ISOLATED_WORKER': '1', 'SEMGREP_SEND_METRICS': 'off'}


def run_process(command, payload, timeout):
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,start_new_session=True,
                             env=scanner_environment())
    try:
        output,_=process.communicate(json.dumps(payload).encode(),timeout=timeout)
        if process.returncode:
            raise HTTPException(502,'The scanner could not complete this audit. No scan allowance was used.')
        return output
    except subprocess.TimeoutExpired:
        raise HTTPException(504,TIMEOUT_MESSAGE) from None
    finally:
        # All nested scanner processes inherit this group. Even successful work
        # is reaped before the caller releases the shared capacity permit.
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait()
        for stream in (process.stdin,process.stdout):
            if stream:stream.close()


def run_audit_process(kind, payload, access, base_url='http://localhost/'):
    timeout=1 if validation_stall_enabled(payload) else AUDIT_TIMEOUT_SECONDS
    output=run_process([sys.executable,str(Path(__file__).with_name('audit_worker.py'))],
                       {'kind':kind,'payload':payload,'access':{key: access[key] for key in ('plan','limits') if key in access},'base_url':base_url},timeout)
    try:
        result=json.loads(output)
        status=result['status_code'];body=result['body']
        if not isinstance(status,int) or not 100<=status<=599 or not isinstance(body,dict):raise ValueError()
    except (ValueError,KeyError,TypeError):
        raise HTTPException(502,'The scanner returned an invalid result. No scan allowance was used.') from None
    from fastapi.responses import JSONResponse
    return JSONResponse(body,status_code=status,headers={'Cache-Control':'no-store'})
