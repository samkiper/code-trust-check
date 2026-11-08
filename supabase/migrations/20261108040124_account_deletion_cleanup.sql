-- An Auth admin deletion must also remove application rows without user FKs.
-- This private trigger cannot be called as a public RPC. Existing cascades
-- remove profiles, reports, projects, GitHub links/history and owned grants.
create or replace function audit_private.clean_deleted_account()
returns trigger language plpgsql security definer set search_path = '' as $$
declare scope text;
begin
  delete from public.scan_usage_monthly where user_id=old.id;
  delete from public.aca_ai_usage where user_id=old.id;
  delete from public.repository_security_policies where user_id=old.id;
  delete from public.finding_suppressions where user_id=old.id;
  delete from public.aca_report_grants where lower(recipient_email)=lower(old.email);
  delete from public.scan_usage_daily where actor_key='user:'||old.id::text;
  foreach scope in array array['scan','repo','billing','github','feedback'] loop
    delete from public.rate_limit_buckets where bucket_key='v1:'||
      encode(sha256(convert_to('ai-code-audit-rate-v1','UTF8')||decode('00','hex')||
        convert_to(scope||':user:'||old.id::text,'UTF8')),'hex');
  end loop;
  return old;
end $$;
revoke all on function audit_private.clean_deleted_account() from public, anon, authenticated, service_role;
create trigger aca_clean_deleted_account before delete on auth.users
  for each row execute function audit_private.clean_deleted_account();
