-- Synthetic data, rolled back. Run on the real schema after the cleanup migration.
begin;
do $$
declare u uuid:=gen_random_uuid(); other_user uuid:=gen_random_uuid();
 r uuid:=gen_random_uuid(); other_report uuid:=gen_random_uuid();
 email text:='deletion-'||u::text||'@example.invalid';
begin
 insert into auth.users(id,email,raw_app_meta_data) values(u,email,'{}'),(other_user,other_user||'@example.invalid','{}');
 insert into public.aca_reports(id,user_id,title,kind,payload,expires_at) values
 (r,u,'Deletion fixture','audit','{}',now()+interval '1 day'),
 (other_report,other_user,'Keep fixture','audit','{}',now()+interval '1 day');
 insert into public.aca_report_grants(report_id,recipient_email) values(other_report,upper(email));
 insert into public.scan_usage_monthly(receipt,user_id,period,kind,state) values(gen_random_uuid(),u,current_date,'code','charged');
 insert into public.aca_ai_usage(receipt,user_id,state,cost_micro_usd) values(gen_random_uuid(),u,'complete',1000);
 insert into public.repository_security_policies(user_id,repository,enforcement_mode,block_at) values(u,'fixture/repo','monitor','high');
 insert into public.finding_suppressions(user_id,repository,finding_id,disposition,reason) values(u,'fixture/repo','fixture','false_positive','Fixture reason');
 insert into public.scan_usage_daily(actor_key,usage_date,scan_count,plan) values('user:'||u,current_date,1,'free');
 insert into public.rate_limit_buckets(bucket_key,request_count) values('v1:'||encode(sha256(convert_to('ai-code-audit-rate-v1','UTF8')||decode('00','hex')||convert_to('billing:user:'||u,'UTF8')),'hex'),1);
 delete from auth.users where id=u;
 assert not exists(select 1 from public.scan_usage_monthly where user_id=u);
 assert not exists(select 1 from public.aca_ai_usage where user_id=u);
 assert not exists(select 1 from public.repository_security_policies where user_id=u);
 assert not exists(select 1 from public.finding_suppressions where user_id=u);
 assert not exists(select 1 from public.aca_reports where id=r);
 assert not exists(select 1 from public.aca_report_grants where lower(recipient_email)=email);
 assert not exists(select 1 from public.scan_usage_daily where actor_key='user:'||u);
 assert not exists(select 1 from public.rate_limit_buckets where bucket_key='v1:'||encode(sha256(convert_to('ai-code-audit-rate-v1','UTF8')||decode('00','hex')||convert_to('billing:user:'||u,'UTF8')),'hex'));
 assert exists(select 1 from auth.users where id=other_user);
 assert exists(select 1 from public.aca_reports where id=other_report);
 assert not has_function_privilege('anon','audit_private.clean_deleted_account()','execute');
 assert not has_function_privilege('authenticated','audit_private.clean_deleted_account()','execute');
end $$;
rollback;
