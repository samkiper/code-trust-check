-- Metadata only: no code, prompts, reports or provider responses are persisted here.
create table if not exists public.aca_ai_usage (
 receipt uuid primary key, user_id uuid not null, created_at timestamptz not null default now(),
 state text not null default 'reserved' check(state in ('reserved','complete','failed')),
 cost_micro_usd bigint not null default 100000 check(cost_micro_usd between 0 and 100000),
 input_tokens integer, output_tokens integer
);
create index if not exists aca_ai_usage_owner_date on public.aca_ai_usage(user_id,created_at);
alter table public.aca_ai_usage enable row level security;
revoke all on public.aca_ai_usage from public,anon,authenticated;
grant select,insert,update on public.aca_ai_usage to service_role;
create or replace function public.aca_ai_usage_control(p_user uuid,p_action text,p_receipt uuid default null,p_cost bigint default null,p_success boolean default false,p_input integer default null,p_output integer default null)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare ident jsonb; tier text; starts timestamptz; ends timestamptz; cap int; used int; spent bigint; allowed boolean; budget_start timestamptz; budget_end timestamptz;
begin
 if p_action not in ('status','reserve','settle') or p_user is null then raise exception 'Invalid AI usage operation'; end if;
 ident:=audit_private.workspace_identity(p_user);tier:=ident->>'plan';
 if ident is null or ident->>'email' is null then return jsonb_build_object('ok',false,'error','Sign in with a verified email.'); end if;
 select starts_at,ends_at into starts,ends from audit_private.monthly_window(audit_private.account_created_at(p_user),now());
 cap:=case when tier='admin' then 400 when tier='serious' then 100 when tier='pro' then 25 else 0 end;
 -- Single transaction lock protects both global dollars and per-account allowances.
 perform pg_advisory_xact_lock(60129102);
 -- Interrupted calls free the customer allowance, but retain full reserved dollars.
 update public.aca_ai_usage set state='failed' where state='reserved' and created_at<now()-interval '3 minutes';
 if p_action='settle' then
  if p_cost is not null and (p_cost<0 or p_cost>100000) then raise exception 'Invalid AI cost'; end if;
  update public.aca_ai_usage set state=case when p_success then 'complete' else 'failed' end,
    cost_micro_usd=coalesce(p_cost,cost_micro_usd),input_tokens=p_input,output_tokens=p_output
    where receipt=p_receipt and user_id=p_user and state='reserved';
 end if;
 -- Cost reporting uses UTC calendar months; customer quotas keep signup anniversaries.
 -- No shared dollar cutoff: paid accounts retain access within their own allowances.
 budget_start:=date_trunc('month',now() at time zone 'UTC') at time zone 'UTC';
 budget_end:=(date_trunc('month',now() at time zone 'UTC')+interval '1 month') at time zone 'UTC';
 select coalesce(sum(cost_micro_usd),0) into spent from public.aca_ai_usage where created_at>=budget_start and created_at<budget_end;
 select count(*) into used from public.aca_ai_usage where user_id=p_user and created_at>=starts and created_at<ends and state in ('reserved','complete');
 allowed:=tier in ('admin','pro','serious') and used<cap;
 if p_action='reserve' then
  if p_receipt is null then raise exception 'Missing request ID'; end if;
  if exists(select 1 from public.aca_ai_usage where receipt=p_receipt) then return jsonb_build_object('ok',false,'error','This request was already submitted. It will not be charged again.'); end if;
  if exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved') then return jsonb_build_object('ok',false,'error','An AI review is already running. Wait before starting another.'); end if;
  if not allowed then return jsonb_build_object('ok',false,'error',case when cap=0 then 'AI change reviews require Pro or Serious. Basic comparison remains free.' when used>=cap then 'Your AI comparison allowance is used. Basic comparison remains available.' else 'AI review is temporarily unavailable. Basic comparison remains available.' end); end if;
  insert into public.aca_ai_usage(receipt,user_id) values(p_receipt,p_user); used:=used+1;spent:=spent+100000;
 end if;
 allowed:=tier in ('admin','pro','serious') and used<cap and not exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved');
 return jsonb_build_object('ok',true,'available',allowed,'reason',case when cap=0 then 'plan' when used>=cap then 'allowance' when exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved') then 'running' else null end,'private_validation',false,'limit',cap,'used',used,'resets_at',ends,'budget_reserved_or_spent_usd',case when tier='admin' then spent/1000000.0 else null end,'monthly_budget_usd',null,'budget_resets_at',budget_end,'budget_warning',null);
end; $$;
revoke all on function public.aca_ai_usage_control(uuid,text,uuid,bigint,boolean,integer,integer) from public,anon,authenticated;
grant execute on function public.aca_ai_usage_control(uuid,text,uuid,bigint,boolean,integer,integer) to service_role;
