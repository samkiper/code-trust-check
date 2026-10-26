"""Trusted one-shot static scanner entrypoint. Never executes customer source."""
import contextlib
import base64
import json
import sys
import time


def execute(message):
    import main
    from audit_runtime import validation_stall_enabled
    from starlette.requests import Request
    from urllib.parse import urlsplit
    # Scoped operator-only fault injection: simulate a stuck scanner stage.
    if validation_stall_enabled(message['payload']):time.sleep(10)
    access=message['access']
    if message['kind']=='code':
        return main.scan_code_work(main.ScanRequest(**message['payload']),access)
    if message['kind']=='repo':
        base=urlsplit(message['base_url'])
        request=Request({'type':'http','method':'POST','path':'/scan-repo','root_path':'',
                         'headers':[],'scheme':base.scheme,'server':(base.hostname,base.port or (443 if base.scheme=='https' else 80))})
        return main.scan_repo_work(main.RepoScanRequest(**message['payload']),access,request)
    if message['kind']=='github_pr':
        # Archive bytes arrive over stdin; the worker has no GitHub or billing secrets.
        from fastapi.responses import JSONResponse
        archive=base64.b64decode(message['payload']['archive'],validate=True)
        findings,scanned,skipped=main.scan_github_changed_files(archive,message['payload']['changed_files'])
        return JSONResponse({'findings':findings,'files_scanned':scanned,'files_skipped':skipped})
    raise ValueError('Invalid audit kind')


if __name__=='__main__':
    from fastapi import HTTPException
    try:
        message=json.load(sys.stdin)
        with contextlib.redirect_stdout(sys.stderr):
            response=execute(message)
        result={'status_code':response.status_code,'body':json.loads(response.body)}
    except HTTPException as exc:
        result={'status_code':exc.status_code,'body':{'detail':exc.detail}}
    except Exception:
        result={'status_code':502,'body':{'detail':'The scanner could not complete this audit. No scan allowance was used.'}}
    sys.stdout.write(json.dumps(result))
