-- Service-only usage metadata. No submitted code, intent, or findings are stored.
create table if not exists public.scan_usage_monthly (
  receipt uuid primary key,
  user_id uuid not null,
  period date not null,
  kind text not null check (kind in ('code','repo')),
  state text not null check (state in ('reserved','charged','refunded')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '15 minutes'
);
create index if not exists scan_usage_monthly_user_period on public.scan_usage_monthly(user_id,period);
alter table public.scan_usage_monthly enable row level security;
revoke all on public.scan_usage_monthly from public,anon,authenticated;
grant select,insert,update,delete on public.scan_usage_monthly to service_role;
create or replace function public.audit_monthly_usage(p_user uuid,p_action text,p_receipt uuid default null,p_kind text default 'code',p_total integer default 20,p_repos integer default 2,p_charge boolean default false)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  month_start date := date_trunc('month',now() at time zone 'UTC')::date;
  total_used integer; repo_used integer; pending integer; allowed boolean := true;
begin
  if p_user is null or p_action not in ('status','reserve','settle') or p_kind not in ('code','repo') or p_total < 0 or p_repos < 0 then raise exception 'Invalid usage operation'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text,0));
  delete from public.scan_usage_monthly where user_id=p_user and created_at < now()-interval '90 days';
  if p_action='settle' then
    update public.scan_usage_monthly set state=case when p_charge then 'charged' else 'refunded' end
      where receipt=p_receipt and user_id=p_user and state='reserved';
  end if;
  select count(*),count(*) filter(where kind='repo'),count(*) filter(where state='reserved') into total_used,repo_used,pending
    from public.scan_usage_monthly where user_id=p_user and period=month_start and (state='charged' or (state='reserved' and expires_at>now()));
  if p_action='reserve' then
    if p_receipt is null then raise exception 'Missing receipt'; end if;
    if exists(select 1 from public.scan_usage_monthly where receipt=p_receipt) then raise exception 'Receipt already used'; end if;
    allowed := total_used < p_total and (p_kind <> 'repo' or repo_used < p_repos);
    if allowed then
      insert into public.scan_usage_monthly(receipt,user_id,period,kind,state) values(p_receipt,p_user,month_start,p_kind,'reserved');
      total_used:=total_used+1; pending:=pending+1;
      if p_kind='repo' then repo_used:=repo_used+1; end if;
    end if;
  end if;
  return jsonb_build_object('allowed',allowed,'total_used',total_used,'repo_used',repo_used,'pending',pending,'total_limit',p_total,'repo_limit',p_repos,'total_remaining',greatest(0,p_total-total_used),'repo_remaining',greatest(0,p_repos-repo_used),'resets_at',to_char(month_start+interval '1 month','YYYY-MM-DD')||'T00:00:00Z');
end; $$;
revoke all on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) from public,anon,authenticated;
grant execute on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) to service_role;
