-- Anniversary boundaries are computed from the original UTC signup timestamp,
-- never from the prior clamped boundary (Jan 31 -> Feb 28 -> Mar 31).
create schema if not exists audit_private;
revoke all on schema audit_private from public,anon,authenticated;
grant usage on schema audit_private to service_role;
create or replace function audit_private.monthly_window(p_anchor timestamptz,p_now timestamptz)
returns table(starts_at timestamptz,ends_at timestamptz)
language plpgsql immutable strict security invoker set search_path = '' as $$
declare
 a timestamp := p_anchor at time zone 'UTC';
 n timestamp := p_now at time zone 'UTC';
 m integer;
begin
 if p_now < p_anchor then raise exception 'Account creation is in the future'; end if;
 m := (extract(year from n)::integer-extract(year from a)::integer)*12
      +extract(month from n)::integer-extract(month from a)::integer;
 if a+make_interval(months=>m)>n then m:=m-1; end if;
 return query select (a+make_interval(months=>m)) at time zone 'UTC',
                     (a+make_interval(months=>m+1)) at time zone 'UTC';
end; $$;
revoke all on function audit_private.monthly_window(timestamptz,timestamptz) from public,anon,authenticated;
grant execute on function audit_private.monthly_window(timestamptz,timestamptz) to service_role;
-- Narrow privileged lookup: service_role cannot SELECT auth.users directly.
-- This private helper exposes only the immutable signup timestamp to the server.
create or replace function audit_private.account_created_at(p_user uuid)
returns timestamptz language sql stable security definer set search_path = '' as $$
 select created_at from auth.users where id=p_user;
$$;
revoke all on function audit_private.account_created_at(uuid) from public,anon,authenticated;
grant execute on function audit_private.account_created_at(uuid) to service_role;
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
create index if not exists scan_usage_monthly_user_created on public.scan_usage_monthly(user_id,created_at);
create index if not exists scan_usage_monthly_user_period on public.scan_usage_monthly(user_id,period);
alter table public.scan_usage_monthly enable row level security;
revoke all on public.scan_usage_monthly from public,anon,authenticated;
grant select,insert,update,delete on public.scan_usage_monthly to service_role;
create or replace function public.audit_monthly_usage(p_user uuid,p_action text,p_receipt uuid default null,p_kind text default 'code',p_total integer default 20,p_repos integer default 2,p_charge boolean default false)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  cycle_start timestamptz; cycle_end timestamptz; anchor timestamptz;
  total_used integer; repo_used integer; pending integer; allowed boolean := true;
begin
  if p_user is null or p_action not in ('status','reserve','settle') or p_kind not in ('code','repo') or p_total < 0 or p_repos < 0 then raise exception 'Invalid usage operation'; end if;
  anchor:=audit_private.account_created_at(p_user);
  if anchor is null then raise exception 'Unknown usage account'; end if;
  select starts_at,ends_at into cycle_start,cycle_end from audit_private.monthly_window(anchor,now());
  perform pg_advisory_xact_lock(hashtextextended(p_user::text,0));
  delete from public.scan_usage_monthly where user_id=p_user and created_at < now()-interval '90 days';
  if p_action='settle' then
    update public.scan_usage_monthly set state=case when p_charge then 'charged' else 'refunded' end
      where receipt=p_receipt and user_id=p_user and state='reserved';
  end if;
  select count(*),count(*) filter(where kind='repo'),count(*) filter(where state='reserved') into total_used,repo_used,pending
    from public.scan_usage_monthly where user_id=p_user and created_at>=cycle_start and created_at<cycle_end and (state='charged' or (state='reserved' and expires_at>now()));
  if p_action='reserve' then
    if p_receipt is null then raise exception 'Missing receipt'; end if;
    if exists(select 1 from public.scan_usage_monthly where receipt=p_receipt) then raise exception 'Receipt already used'; end if;
    allowed := total_used < p_total and (p_kind <> 'repo' or repo_used < p_repos);
    if allowed then
      insert into public.scan_usage_monthly(receipt,user_id,period,kind,state) values(p_receipt,p_user,(cycle_start at time zone 'UTC')::date,p_kind,'reserved');
      total_used:=total_used+1; pending:=pending+1;
      if p_kind='repo' then repo_used:=repo_used+1; end if;
    end if;
  end if;
  return jsonb_build_object('allowed',allowed,'total_used',total_used,'repo_used',repo_used,'pending',pending,'total_limit',p_total,'repo_limit',p_repos,'total_remaining',greatest(0,p_total-total_used),'repo_remaining',greatest(0,p_repos-repo_used),'period_starts_at',cycle_start,'resets_at',cycle_end,'cycle_basis','account_created_at');
end; $$;
revoke all on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) from public,anon,authenticated;
grant execute on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) to service_role;
