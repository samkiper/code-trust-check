"""Bounded FIFO for a single Render process. Ephemeral source/results, never disk.

One queued/active job per account; at most 5 waiting jobs. Completed responses
expire after 10 minutes. Restart loses jobs, never restores/replays source.
"""
import threading
import time
import uuid
from collections import deque
from fastapi import HTTPException

class ScanJobs:
    def __init__(self, capacity=5, ttl=600):
        self.capacity=capacity; self.ttl=ttl
        self.lock=threading.RLock(); self.jobs={}; self.waiting=deque(); self.active=None
        self.worker=threading.Thread(target=self._work,daemon=True); self.wake=threading.Event(); self.worker.start()

    def _prune(self):
        now=time.monotonic()
        for key,job in list(self.jobs.items()):
            if job['status'] not in ('queued','running') and now-job['updated']>self.ttl:
                del self.jobs[key]
        finished=[k for k,j in self.jobs.items() if j['status'] not in ('queued','running')]
        for key in sorted(finished,key=lambda k:self.jobs[k]['updated'])[:-24]:
            del self.jobs[key]

    def submit(self,owner,work):
        with self.lock:
            self._prune()
            if any(j['owner']==owner and j['status'] in ('queued','running') for j in self.jobs.values()):
                raise HTTPException(409,'You already have an audit queued or running. Wait for it to finish before submitting another.')
            if len(self.waiting)>=self.capacity:
                raise HTTPException(429,'The audit queue is full. Your scan has not started and no allowance was used.',headers={'Retry-After':'10','X-Scan-Rejection':'capacity'})
            key=str(uuid.uuid4())
            self.jobs[key]={'id':key,'owner':owner,'work':work,'status':'queued','updated':time.monotonic()}
            self.waiting.append(key); self.wake.set()
            return self.get(owner,key)

    def get(self,owner,key):
        with self.lock:
            self._prune();j=self.jobs.get(key)
            if not j or j['owner']!=owner: raise HTTPException(404,'Audit not found or expired. A server restart can interrupt an audit; retry if needed.')
            return {k:j[k] for k in ('id','status','result','error','http_status','cancel_requested') if k in j}|{'position':list(self.waiting).index(key)+1 if key in self.waiting else 0}

    def cancel(self,owner,key):
        with self.lock:
            self.get(owner,key);j=self.jobs[key]
            if j['status']=='queued':
                self.waiting.remove(key);j.pop('work',None);j.update(status='cancelled',updated=time.monotonic())
            elif j['status']=='running':j['cancel_requested']=True
            return self.get(owner,key)

    def _work(self):
        while True:
            self.wake.wait(30)
            with self.lock:
                self._prune()
                if not self.waiting:self.wake.clear();continue
                key=self.waiting.popleft();j=self.jobs[key];j['status']='running';self.active=key;work=j.pop('work')
            try:
                result=work()
                with self.lock:
                    if j.get('cancel_requested'):j['status']='cancelled'
                    else:j.update(status='completed',result=result)
            except HTTPException as exc:
                with self.lock:j.update(status='failed',error=str(exc.detail),http_status=exc.status_code)
            except Exception:
                with self.lock:j.update(status='failed',error='The scanner could not complete this audit. No completed scan was charged.',http_status=502)
            finally:
                work=None;result=None
                with self.lock:j['updated']=time.monotonic();self.active=None
