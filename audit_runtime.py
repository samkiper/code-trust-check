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
import threading
import sys
import time
from fastapi import HTTPException

AUDIT_TIMEOUT_SECONDS = 120
# A single customer's scanner and descendants must leave room for the web process.
# RSS sums shared pages more than once: conservative by design.
AUDIT_MEMORY_LIMIT_KIB = 1_450_000
AUDIT_MEMORY_MESSAGE = 'The audit exceeded its safe memory limit and was stopped. No scan allowance was used. Try a smaller or less complex input.'
AUDIT_MONITOR_MESSAGE = 'The scanner could not verify its safe memory limit and stopped. No scan allowance was used. Please retry later.'
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


def _process_tree_rss_kib(child_pid):
    """Sum scanner descendants' resident memory, handling nested PID namespaces."""
    parent_pid = int(os.readlink('/proc/self'))
    entries = {}
    for folder in Path('/proc').iterdir():
        if not folder.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (folder / 'status').read_text().splitlines() if ':' in line)
            namespace_ids = fields.get('NSpid', str(folder.name)).split()
            entries[int(folder.name)] = (int(fields['PPid']), int(fields.get('VmRSS', '0 kB').split()[0]), int(namespace_ids[-1]))
        except (OSError, KeyError, ValueError, IndexError):
            continue  # Processes may exit while /proc is being read.
    roots = {pid for pid, (parent, _, local) in entries.items() if parent == parent_pid and local == child_pid}
    if not roots:
        return None
    family = roots.copy()
    while True:
        extra = {pid for pid, (parent, _, _) in entries.items() if parent in family} - family
        if not extra:
            break
        family.update(extra)
    return sum(entries[pid][1] for pid in family)


def run_process(command, payload, timeout):
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,start_new_session=True,
                             env=scanner_environment())
    stop = threading.Event()
    memory_exceeded = threading.Event()
    monitor_unavailable = threading.Event()
    def watch_memory():
        missing = 0
        while not stop.wait(.1):
            if process.poll() is not None:
                return
            try:
                rss = _process_tree_rss_kib(process.pid)
            except (OSError, ValueError):
                rss = None
            if rss is None:
                # A /proc entry can vanish as the worker exits. If it is
                # still running across several samples, fail closed instead
                # of treating an unobservable worker as zero memory.
                if process.poll() is not None:
                    return
                missing += 1
                if missing < 3:
                    continue
                monitor_unavailable.set()
            elif rss <= AUDIT_MEMORY_LIMIT_KIB:
                missing = 0
                continue
            else:
                memory_exceeded.set()
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            return
    watcher = threading.Thread(target=watch_memory, daemon=True)
    watcher.start()
    try:
        output,_=process.communicate(json.dumps(payload).encode(),timeout=timeout)
        if monitor_unavailable.is_set():
            raise HTTPException(503, AUDIT_MONITOR_MESSAGE)
        if memory_exceeded.is_set():
            raise HTTPException(503, AUDIT_MEMORY_MESSAGE)
        if process.returncode:
            raise HTTPException(502,'The scanner could not complete this audit. No scan allowance was used.')
        return output
    except subprocess.TimeoutExpired:
        raise HTTPException(504,TIMEOUT_MESSAGE) from None
    finally:
        stop.set()
        watcher.join(timeout=1)
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
