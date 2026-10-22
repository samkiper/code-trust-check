"""Compare identical local rules/targets with fresh version-check caches. No code executes."""
import json, os, subprocess, tempfile, time
from pathlib import Path

with tempfile.TemporaryDirectory() as folder:
    target=Path(folder)/'snippet.py';target.write_text('def add(a,b):\n    return a+b\n')
    common=['semgrep','scan','--json','--metrics=off','--quiet','--jobs','1','--timeout','5','--max-memory','512','--config',str(Path('semgrep.yml').resolve()),str(target)]
    for i in range(3):
        for variant in ['before','after']:
            env={**os.environ,'SEMGREP_VERSION_CACHE_PATH':str(Path(folder)/f'{variant}-{i}.cache')}
            command=common+(['--disable-version-check','--oss-only'] if variant=='after' else [])
            start=time.monotonic()
            try:
                run=subprocess.run(command,env=env,capture_output=True,text=True,timeout=40)
                payload=json.loads(run.stdout or '{}');status='complete' if run.returncode in (0,1) and not payload.get('errors') and payload.get('paths',{}).get('scanned') else 'partial'
                print(json.dumps({'variant':variant,'run':i+1,'seconds':round(time.monotonic()-start,3),'status':status,'findings':len(payload.get('results',[]))}),flush=True)
            except subprocess.TimeoutExpired:
                print(json.dumps({'variant':variant,'run':i+1,'seconds':round(time.monotonic()-start,3),'status':'timeout'}),flush=True)
