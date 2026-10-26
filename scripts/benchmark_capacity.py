"""Offline real-engine capacity probe. Does not call AI or execute submitted source."""
import json,sys,time,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import main
from scan_jobs import ScanJobs

def code_for(lines):
    block=lambda i: f'''def summarize_{i}(rows, limit=100):
    totals = {{}}
    for row in rows[:limit]:
        key = str(row.get("category", "other"))
        value = float(row.get("amount", 0))
        if value >= 0:
            totals[key] = totals.get(key, 0) + value
    return sorted(totals.items())

'''
    code=''.join(block(i) for i in range((lines-4)//9))
    code+='\nvalue = input()\neval(value)\n'
    return code

def compact_code_for(lines):
    """Branching 50k-line fixture that fits the public 1 MB snippet bound."""
    block=lambda i: f'def f{i}(r):\n t={{}}\n for a in r:\n  v=a["v"]\n  if v>0:\n   k=a["k"]\n   t[k]=t.get(k,0)+v\n return t\n\n'
    count=max(0,(lines-2)//9)
    code=''.join(block(i) for i in range(count))+'value=input()\neval(value)\n'
    return code+'x=1\n'*max(0,lines-len(code.splitlines()))

def run(lines,compact=False):
    code=compact_code_for(lines) if compact else code_for(lines)
    main.validate_scan_request(main.ScanRequest(intent='Summarize local category amounts. Do not execute dynamic input.',code=code,language='Python'),{'authenticated':True,'plan':'serious','limits':main.get_plan_limits('serious')})
    t=time.monotonic()
    result=main.analyze_code_product('Summarize local category amounts. Do not execute dynamic input.',code,plan='serious',filename='summary.py',language='Python')
    record={'requested_lines':lines,'actual_lines':len(code.splitlines()),'bytes':len(code.encode()),'seconds':round(time.monotonic()-t,3),'state':result.get('scan_status'),'engines':result.get('analysis_engines'),'flags':len(result.get('flags',[])),'engine_findings':len(result.get('engine_findings',[]))}
    print(json.dumps(record),flush=True)
    assert result['scan_status']=='complete',record
    assert result.get('flags') or result.get('engine_findings'),record
    return record

if __name__=='__main__':
    if '--serious' in sys.argv:
        run(50000,compact=True)
        sys.exit(0)
    for n in (2000,10000,20000):run(n)
    q=ScanJobs();start=time.monotonic();ids=[]
    for i in range(3):ids.append((f'benchmark-{i}',q.submit(f'benchmark-{i}',lambda:run(2000))['id']))
    while True:
        states=[q.get(owner,key) for owner,key in ids]
        if all(s['status'] not in ('queued','running') for s in states):break
        if time.monotonic()-start>120:raise TimeoutError('Local queue exceeded test budget')
        time.sleep(.05)
    print(json.dumps({'queue_seconds':round(time.monotonic()-start,3),'statuses':[s['status'] for s in states]}),flush=True)
    assert all(s['status']=='completed' for s in states)
