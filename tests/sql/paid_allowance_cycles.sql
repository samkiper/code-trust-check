-- Synthetic accounts only. Suitable for a local database or a rollback smoke test.
begin;
insert into auth.users(id,email,email_confirmed_at,created_at,raw_app_meta_data) values
('00000000-0000-4000-8000-000000002301','allowance-cycle@example.invalid',now(),now()-interval '85 days','{}'),
('00000000-0000-4000-8000-000000002302','allowance-legacy@example.invalid',now(),now()-interval '85 days','{"plan":"pro","stripe_subscription_id":"sub_legacy"}');
set local role service_role;
do $$
declare
 u constant uuid:='00000000-0000-4000-8000-000000002301';
 legacy constant uuid:='00000000-0000-4000-8000-000000002302';
 started bigint:=extract(epoch from now()-interval '2 days')::bigint;
 expired bigint:=extract(epoch from now()-interval '1 second')::bigint;
 final_date bigint:=extract(epoch from now()+interval '1 year')::bigint;
 a jsonb; s jsonb; result jsonb; old_receipt uuid:=gen_random_uuid(); paid_receipt uuid:=gen_random_uuid();
 reset_at timestamptz; i integer;
begin
 assert not has_function_privilege('anon','public.aca_sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint)','execute');
 assert not has_function_privilege('authenticated','audit_private.sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint)','execute');
 s:=public.audit_monthly_usage(u,'reserve',old_receipt,'code',5,1);
 assert s->>'cycle_basis'='account_created_at' and (s->>'total_used')::int=1;
 result:=public.aca_sync_subscription(u,0,'sub_A','cus_A',started,started,'pro','active',false,final_date);
 assert (result->>'ok')::boolean;
 s:=public.audit_monthly_usage(u,'status');
 a:=public.aca_ai_usage_control(u,'status');
 assert s->>'cycle_basis'='paid_subscription_start' and (s->>'total_used')::int=0;
 assert (s->>'total_limit')::int=75 and (a->>'limit')::int=25;
 reset_at:=(s->>'resets_at')::timestamptz;
 assert (a->>'resets_at')::timestamptz=reset_at and reset_at=(to_timestamp(started) at time zone 'UTC'+interval '1 month') at time zone 'UTC';
 perform public.audit_monthly_usage(u,'settle',old_receipt,'code',5,1,true);
 perform public.audit_monthly_usage(u,'reserve',paid_receipt,'repo',75,10);
 perform public.aca_ai_usage_control(u,'reserve',paid_receipt);
 perform public.aca_ai_usage_control(u,'settle',paid_receipt,1200,true);
 -- Duplicate/current snapshot and a stale version of a different tier.
 perform public.aca_sync_subscription(u,1,'sub_A','cus_A',started,started,'pro','active',false,final_date);
 result:=public.aca_sync_subscription(u,1,'sub_A','cus_A',started,started,'free','canceled',false,final_date);
 assert not (result->>'ok')::boolean;
 perform public.aca_sync_subscription(u,2,'sub_A','cus_A',started,started,'serious','active',true,final_date);
 s:=public.audit_monthly_usage(u,'status'); a:=public.aca_ai_usage_control(u,'status');
 assert (s->>'total_used')::int=1 and (s->>'repo_limit')::int=40 and (s->>'total_limit')::int=300;
 assert (s->>'resets_at')::timestamptz=reset_at and (a->>'resets_at')::timestamptz=reset_at and (a->>'used')::int=1 and (a->>'limit')::int=100;
 -- Paid-through expiry wins even if terminal delivery is delayed.
 perform public.aca_sync_subscription(u,3,'sub_A','cus_A',started,started,'serious','active',true,expired);
 assert (public.aca_ai_usage_control(u,'status')->>'limit')::int=0;
 assert (public.audit_monthly_usage(u,'status')->>'total_limit')::int=5;
 perform public.aca_sync_subscription(u,4,'sub_A','cus_A',started,started,'free','canceled',false,expired);
 perform public.aca_sync_subscription(u,5,'sub_B','cus_A',expired,expired,'pro','active',false,final_date);
 result:=public.aca_sync_subscription(u,6,'sub_A','cus_A',started,started,'free','canceled',false,expired);
 assert (result->>'ignored')::boolean;
 result:=public.aca_sync_subscription(u,6,'sub_A','cus_A',started,started,'serious','active',false,final_date);
 assert (result->>'ignored')::boolean;
 s:=public.audit_monthly_usage(u,'status');
 assert (s->>'period_starts_at')::timestamptz=to_timestamp(expired) and (s->>'total_used')::int=0;
 assert (public.aca_ai_usage_control(u,'status')->>'used')::int=0;
 -- Legacy paid usage follows the verified paid start without a second allowance.
 perform public.audit_monthly_usage(legacy,'reserve',gen_random_uuid(),'code',75,10);
 perform public.aca_ai_usage_control(legacy,'reserve',gen_random_uuid());
 perform public.aca_sync_subscription(legacy,0,'sub_legacy','cus_B',started,started,'pro','active',false,final_date);
 assert (public.audit_monthly_usage(legacy,'status')->>'total_used')::int=1;
 assert (public.aca_ai_usage_control(legacy,'status')->>'used')::int=1;
end $$;
rollback;
