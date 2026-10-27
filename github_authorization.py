"""Short-lived GitHub App user authorization held only in this server process.

The user token is never returned to the browser, written to disk, or logged.
An app restart or expiry requires the user to authorize again.
"""
import threading
import time


class AuthorizationCache:
    def __init__(self, limit=1024, ttl=7*60*60):
        self.limit=limit
        self.ttl=ttl
        self.lock=threading.Lock()
        self.entries={}
        self.timer=None
        self.generation=0

    def _schedule_expiry_locked(self):
        self.generation+=1
        if self.timer:
            self.timer.cancel()
            self.timer=None
        if not self.entries:return
        delay=max(0, min(entry['expires'] for entry in self.entries.values())-time.monotonic())
        self.timer=threading.Timer(delay,self._expire,args=(self.generation,))
        self.timer.daemon=True
        self.timer.start()

    def _expire(self,generation):
        with self.lock:
            if generation!=self.generation:return
            now=time.monotonic()
            self.entries={k:v for k,v in self.entries.items() if v['expires']>now}
            self.timer=None
            self._schedule_expiry_locked()

    def put(self,user_id,github_id,token):
        if not isinstance(user_id,str) or not user_id or not isinstance(github_id,int) or isinstance(github_id,bool) or github_id<=0 or not isinstance(token,str) or not token:
            raise ValueError('Invalid GitHub user authorization')
        now=time.monotonic()
        with self.lock:
            self.entries={k:v for k,v in self.entries.items() if v['expires']>now}
            if user_id not in self.entries and len(self.entries)>=self.limit:
                raise RuntimeError('GitHub authorization capacity is temporarily full')
            self.entries[user_id]={'github_id':github_id,'token':token,'expires':now+self.ttl}
            self._schedule_expiry_locked()

    def get(self,user_id):
        with self.lock:
            entry=self.entries.get(user_id)
            if not entry:return None
            if entry['expires']<=time.monotonic():
                del self.entries[user_id]
                return None
            return dict(entry)

    def revoke_github_user(self,github_id):
        with self.lock:
            users=[user_id for user_id,entry in self.entries.items() if entry['github_id']==github_id]
            for user_id in users:del self.entries[user_id]
            self._schedule_expiry_locked()
            return len(users)

    def remove(self,user_id):
        with self.lock:
            self.entries.pop(user_id,None)
            self._schedule_expiry_locked()
