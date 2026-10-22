"""Gate the pinned native CLI against the default CLI with identical local rules."""
import json, os, subprocess, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_scanner_benchmark import SAFE_CASES,DANGEROUS_CASES
EXT={'python':'.py','javascript':'.js','typescript':'.ts','shell':'.sh','sql':'.sql','html':'.html','css':'.css','java':'.java','go':'.go','rust':'.rs','php':'.php'}

def signature(p):
 return {
  'findings':sorted((r['check_id'],Path(r['path']).name,r['start']['line'],r['start']['col'],r['end']['line'],r['end']['col'],r['extra']['severity'],r['extra']['message'],json.dumps(r['extra'].get('metadata',{}),sort_keys=True)) for r in p['results']),
  'scanned':sorted(Path(f).name for f in p['paths']['scanned']),
  'errors':sorted((str(e.get('type')),Path(e.get('path','')).name,str(e.get('level'))) for e in p.get('errors',[])),
 }
with tempfile.TemporaryDirectory() as folder:
 cases=list(SAFE_CASES)+list(DANGEROUS_CASES)+[
 ('malformed','python','','def broken(:\n eval(input())'),
 ('comments_only','python','','# eval exec password shell=True'),
 ('empty','python','',''),
 ('environment','python','','import os\nkey=os.environ.get("API_KEY")'),
 ('fixed_no_shell','python','','import subprocess\nsubprocess.run(["git","status"],shell=False)'),
 ('many_findings','python','','\n'.join('eval(input())' for _ in range(12))),
 ('unsupported','unknown','','unrecognized input'),
 ]
 for case in cases:Path(folder,case[0]+EXT.get(case[1],'.unknown')).write_text(case[3])
 outputs={};timings={}
 base=['semgrep','scan','--json','--metrics=off','--quiet','--disable-version-check','--oss-only','--jobs','1','--timeout','5','--max-memory','512','--config',str(ROOT/'semgrep.yml'),folder]
 for mode,flags in [('default',[]),('native',['--experimental'])]:
  t=time.monotonic();r=subprocess.run(base+flags,capture_output=True,text=True,timeout=120)
  if r.returncode not in (0,1):raise RuntimeError(f'{mode} failed: {r.returncode}')
  outputs[mode]=signature(json.loads(r.stdout));timings[mode]=round(time.monotonic()-t,3)
 if outputs['default']!=outputs['native']:
  print(json.dumps({'parity':False,'default':outputs['default'],'native':outputs['native']},indent=2));sys.exit(1)
 print(json.dumps({'parity':True,'cases':len(cases),'findings':len(outputs['native']['findings']),'targets':len(outputs['native']['scanned']),'errors':outputs['native']['errors'],'seconds':timings}))
