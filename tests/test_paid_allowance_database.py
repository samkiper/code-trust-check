"""Exercise billing and quota transactions using a disposable native PostgreSQL."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi.testclient import TestClient
import main

ROOT = Path(__file__).resolve().parents[1]


class PaidAllowanceDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = sorted(Path('/usr/lib/postgresql').glob('*/bin/postgres'))
        binary = shutil.which('postgres') or (candidates[-1] if candidates else None)
        if not binary or os.geteuid() == 0:
            if os.getenv('GITHUB_ACTIONS'):
                raise RuntimeError('The billing integration suite requires native PostgreSQL and a non-root runner')
            raise unittest.SkipTest('Native PostgreSQL requires installed server binaries and a non-root test user')
        cls.bin = Path(binary).parent
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.directory = Path(tmp.name)
        data = cls.directory / 'data'
        subprocess.run([cls.bin/'initdb', '-D', data, '-A', 'trust', '-U', 'postgres', '--no-locale'],
                       check=True, stdout=subprocess.DEVNULL)
        subprocess.run([cls.bin/'pg_ctl','-D',data,'-l',cls.directory/'postgres.log','-o',
                        f"-k {cls.directory} -c listen_addresses='' -p 55433",'start'], check=True,
                       stdout=subprocess.DEVNULL)
        cls.addClassCleanup(subprocess.run, [cls.bin/'pg_ctl','-D',data,'-m','immediate','stop'],
                            check=True, stdout=subprocess.DEVNULL)
        cls.sql("""create role anon; create role authenticated; create role service_role bypassrls;
            create schema auth; create table auth.users (id uuid primary key,email text,email_confirmed_at timestamptz,
            created_at timestamptz,deleted_at timestamptz,raw_app_meta_data jsonb);""")
        for name in ('monthly_usage','saved_workspace','ai_review_usage'):
            cls.sql((ROOT/'supabase'/f'{name}.sql').read_text())
        cls.sql(next((ROOT/'supabase/migrations').glob('*_paid_allowance_cycles.sql')).read_text())

    @classmethod
    def sql(cls, command):
        return subprocess.run([cls.bin/'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-h',cls.directory,
                               '-p','55433','-U','postgres'],input=command,text=True,
                              stdout=subprocess.PIPE,check=True).stdout.strip()

    def account(self):
        user = str(uuid.uuid4())
        self.sql(f"insert into auth.users values ('{user}','cycle@example.invalid', now(),now()-interval '3 months',null,'{{}}')")
        return user

    def test_sql_transitions_and_calendar(self):
        for name in ('monthly_anniversary','paid_allowance_cycles'):
            self.sql((ROOT/'tests/sql'/f'{name}.sql').read_text())

    def test_competing_reservations_and_delivery_versions(self):
        u = self.account()
        def reserve(_):
            return self.sql(f"select public.audit_monthly_usage('{u}','reserve',gen_random_uuid(),'code',5,1)->>'allowed'")
        def upgrade(_):
            return self.sql(f"select public.aca_sync_subscription('{u}',0,'sub_A','cus_A',100,100,'pro','active',false,null)->>'ok'")
        with ThreadPoolExecutor(max_workers=10) as pool:
            self.assertEqual(list(pool.map(reserve, range(16))).count('true'),5)
            self.assertEqual(list(pool.map(upgrade, range(8))).count('true'),1)
            def review(_):
                return self.sql(f"select public.aca_ai_usage_control('{u}','reserve',gen_random_uuid())->>'ok'")
            self.assertEqual(list(pool.map(review, range(8))).count('true'),1)
        self.assertEqual(self.sql(f"select public.audit_monthly_usage('{u}','status')->>'total_used'"),'0')

    def test_signed_webhook_to_database(self):
        u = self.account()
        started = int(time.time()) - 3600
        signing_secret = 'whsec_ephemeral_integration_fixture'
        subscription = {'id':'sub_fixture','customer':'cus_fixture','start_date':started,'created':started,
                        'status':'active','items':{'data':[{'price':{'id':'price_fixture'}}]}}
        # Only services external to the test instance are adapted. The real webhook
        # signature, reconciliation code, SQL function and allowance RPCs run.
        def account(_):
            metadata = self.sql(f"select raw_app_meta_data from auth.users where id='{u}'")
            return {'id':u,'app_metadata':json.loads(metadata)}
        def rpc(method,path,payload):
            self.assertEqual((method,path),('POST','rpc/aca_sync_subscription'))
            # json_populate_record is unnecessary here: fixture values are bound
            # through a generated dollar quote which is absent from the payload.
            delim='$fixture$'
            encoded=json.dumps(payload)
            self.assertNotIn(delim,encoded)
            result=self.sql(f"""with x as (select * from json_to_record({delim}{encoded}{delim}::json)
              as r(p_user uuid,p_revision bigint,p_subscription text,p_customer text,p_created bigint,p_start bigint,
              p_plan text,p_status text,p_scheduled boolean,p_end bigint,p_prior_ended bigint))
              select public.aca_sync_subscription(p_user,p_revision,p_subscription,p_customer,p_created,p_start,p_plan,
              p_status,p_scheduled,p_end,p_prior_ended) from x""")
            return json.loads(result)
        evt={'id':'evt_fixture','object':'event','type':'customer.subscription.updated','data':{'object':{
            'id':'sub_fixture','customer':'cus_fixture','metadata':{'user_id':u},'status':'canceled'}}}
        body=json.dumps(evt)
        ts=str(int(time.time()))
        sig=hmac.new(signing_secret.encode(),f'{ts}.{body}'.encode(),hashlib.sha256).hexdigest()
        with patch.object(main,'get_supabase_admin_user',side_effect=account), \
             patch.object(main,'supabase_rest_request',side_effect=rpc), \
             patch.object(main.stripe.Subscription,'retrieve',return_value=subscription), \
             patch.object(main,'STRIPE_SECRET_KEY','fixture'),patch.object(main,'STRIPE_PRICE_ID','price_fixture'), \
             patch.object(main,'STRIPE_WEBHOOK_SECRET',signing_secret):
            client=TestClient(main.app)
            for _ in range(2):
                response=client.post('/stripe/webhook',content=body,headers={'stripe-signature':f't={ts},v1={sig}'})
                self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(account(u)['app_metadata']['paid_allowance_anchor'], started)
            self.assertEqual(self.sql(f"select public.audit_monthly_usage('{u}','status')->>'total_limit'"),'75')
            self.assertEqual(self.sql(f"select public.aca_ai_usage_control('{u}','status')->>'limit'"),'25')
