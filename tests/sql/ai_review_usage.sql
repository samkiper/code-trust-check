begin;
insert into auth.users(id,email,email_confirmed_at,created_at,raw_app_meta_data) values
('00000000-0000-4000-8000-000000000201','ai-admin@example.invalid',now(),now()-interval '2 months','{"role":"admin"}'),
('00000000-0000-4000-8000-000000000202','ai-free@example.invalid',now(),now()-interval '2 months','{}');
set local role service_role;
do $$ declare u uuid:='00000000-0000-4000-8000-000000000201'; other_id uuid:='00000000-0000-4000-8000-000000000202'; rid uuid:=gen_random_uuid();r jsonb; i int;
begin
 r:=public.aca_ai_usage_control(u,'status');assert (r->>'available')::boolean;assert (r->>'limit')::int=400;
 r:=public.aca_ai_usage_control(other_id,'status');assert not (r->>'available')::boolean;assert (r->>'limit')::int=5;
 assert not (public.aca_ai_usage_control(other_id,'reserve',gen_random_uuid())->>'ok')::boolean;
 assert (public.aca_ai_usage_control(u,'reserve',rid)->>'ok')::boolean;
 assert not (public.aca_ai_usage_control(u,'reserve',rid)->>'ok')::boolean;
 assert not (public.aca_ai_usage_control(u,'reserve',gen_random_uuid())->>'ok')::boolean;
 perform public.aca_ai_usage_control(other_id,'settle',rid,0,true);
 assert (select state='reserved' from public.aca_ai_usage where receipt=rid);
 perform public.aca_ai_usage_control(u,'settle',rid,525,true,100,100);
 assert (select cost_micro_usd=525 and state='complete' from public.aca_ai_usage where receipt=rid);
 perform public.aca_ai_usage_control(u,'settle',rid,0,false);
 assert (select cost_micro_usd=525 and state='complete' from public.aca_ai_usage where receipt=rid);
 for i in 1..249 loop
  rid:=gen_random_uuid();assert (public.aca_ai_usage_control(u,'reserve',rid)->>'ok')::boolean;
  perform public.aca_ai_usage_control(u,'settle',rid,null,false);
  if i=200 then assert public.aca_ai_usage_control(u,'status')->>'budget_warning'='80_percent'; end if;
  if i=225 then assert public.aca_ai_usage_control(u,'status')->>'budget_warning'='90_percent'; end if;
 end loop;
 assert not (public.aca_ai_usage_control(u,'reserve',gen_random_uuid())->>'ok')::boolean;
 assert (public.aca_ai_usage_control(u,'status')->>'used')::int=1;
 assert public.aca_ai_usage_control(u,'status')->>'budget_warning'='exhausted';
 assert (public.aca_ai_usage_control(u,'status')->>'monthly_budget_usd')::int=25;
 -- Simulate previous-month receipts: new month regains capacity without deleting history.
 update public.aca_ai_usage set created_at=date_trunc('month',now() at time zone 'UTC') at time zone 'UTC'-interval '1 day' where user_id=u;
 assert (public.aca_ai_usage_control(u,'status')->>'available')::boolean;
 assert (select count(*) from public.aca_ai_usage where user_id=u)=250;
 assert (public.aca_ai_usage_control(u,'reserve',gen_random_uuid())->>'ok')::boolean;
end $$;
reset role;
set local role authenticated;
do $$ begin
 begin perform public.aca_ai_usage_control('00000000-0000-4000-8000-000000000201','status');raise exception 'RPC exposed';exception when insufficient_privilege then null;end;
 begin perform * from public.aca_ai_usage;raise exception 'Ledger exposed';exception when insufficient_privilege then null;end;
end $$;
rollback;
select 'AI budget, duplicate, in-flight, ownership, quotas and privilege tests passed; fixtures rolled back' as result;
