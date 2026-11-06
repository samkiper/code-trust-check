-- Both ledgers and billing changes take the same account lock before reading
-- entitlements. A receipt belongs to the entitlement in effect at reservation.
alter table public.scan_usage_monthly add column paid_cycle text;
alter table public.aca_ai_usage add column paid_cycle text;

create function audit_private.effective_tier(meta jsonb, as_of timestamptz)
returns text language sql immutable set search_path='' as $$
 select case when meta->>'role'='admin' then 'admin'
   when (meta->>'stripe_cancel_at_period_end')::boolean and
        (meta->>'stripe_current_period_end')::bigint <= extract(epoch from as_of) then 'free'
   else coalesce(meta->>'plan','free') end
$$;

create or replace function audit_private.workspace_identity(p_user uuid)
returns jsonb language sql stable security definer set search_path='' as $$
 select jsonb_build_object('plan',audit_private.effective_tier(raw_app_meta_data,statement_timestamp()),
  'email',case when email_confirmed_at is not null then lower(email) end)
 from auth.users where id=p_user and deleted_at is null
$$;

create function audit_private.allowance_identity(p_user uuid, as_of timestamptz)
returns table(tier text, anchor timestamptz, paid_cycle text)
language sql stable security definer set search_path='' as $$
 select t.plan, coalesce(to_timestamp(c.epoch),u.created_at),
        case when c.epoch is not null then u.raw_app_meta_data->>'paid_allowance_generation' end
 from auth.users u
 cross join lateral (select audit_private.effective_tier(u.raw_app_meta_data,as_of) as plan) t
 cross join lateral (select case when t.plan in ('pro','serious') then
     (u.raw_app_meta_data->>'paid_allowance_anchor')::bigint end as epoch) c
 where u.id=p_user and u.deleted_at is null
$$;

-- Stripe creation timestamps have one-second precision. Remember displaced
-- subscription IDs so an old contract cannot take over in a same-second tie.
create table audit_private.retired_subscriptions(
 user_id uuid not null references auth.users(id) on delete cascade,
 subscription_id text not null,
 primary key(user_id,subscription_id)
);
revoke all on audit_private.retired_subscriptions from public,anon,authenticated,service_role;

-- Only this narrow internal function can merge server-owned billing fields
-- into auth.users. It never accepts a caller-provided metadata object.
create function audit_private.sync_subscription(p_user uuid,p_revision bigint,p_subscription text,
 p_customer text,p_created bigint,p_start bigint,p_plan text,p_status text,p_scheduled boolean,p_end bigint,p_prior_ended bigint default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
 meta jsonb; prior text; prior_created bigint; anchor bigint; generation text; revision bigint;
begin
 if p_user is null or coalesce(p_subscription,'')='' or coalesce(p_customer,'')=''
    or p_created is null or p_start is null or p_created<=0 or p_start<=0
    or p_start>extract(epoch from clock_timestamp())
    or p_plan is null or p_plan not in ('free','pro','serious') or coalesce(p_status,'')=''
    or p_scheduled is null or (p_scheduled and p_end is null)
    or (p_plan<>'free' and p_status not in ('active','trialing','past_due')) then
    raise exception 'Invalid subscription snapshot';
 end if;
 perform pg_advisory_xact_lock(hashtextextended(p_user::text,0));
 select coalesce(raw_app_meta_data,'{}') into strict meta from auth.users
 where id=p_user and deleted_at is null for update;
 revision:=coalesce((meta->>'billing_revision')::bigint,0);
 if p_revision is distinct from revision then return jsonb_build_object('ok',false,'reason','retry'); end if;
 prior:=meta->>'stripe_subscription_id';
 prior_created:=(meta->>'stripe_subscription_created')::bigint;
 if exists(select 1 from audit_private.retired_subscriptions where user_id=p_user and subscription_id=p_subscription) then
   return jsonb_build_object('ok',true,'ignored',true);
 end if;
 if prior is not null and prior<>p_subscription then
   -- First reconcile the recorded legacy subscription to establish ordering.
   if prior_created is null then return jsonb_build_object('ok',false,'reason','legacy'); end if;
   if p_created<prior_created or p_plan='free' then return jsonb_build_object('ok',true,'ignored',true); end if;
   if p_created=prior_created and p_prior_ended is null and meta->>'stripe_subscription_status'<>'canceled' then
     return jsonb_build_object('ok',false,'reason','ambiguous_subscription');
   end if;
   insert into audit_private.retired_subscriptions values(p_user,prior);
 end if;
 if prior=p_subscription and meta->>'stripe_subscription_status' in ('canceled','incomplete_expired')
    and p_status not in ('canceled','incomplete_expired') then return jsonb_build_object('ok',true,'ignored',true); end if;
 if p_plan in ('pro','serious') then
   anchor:=p_start;
   generation:=p_subscription;
   -- A replacement contract that overlaps paid access is a continuous switch.
   -- A distinct contract after expiry or cancellation starts fresh.
   if prior is distinct from p_subscription and meta->>'plan' in ('pro','serious')
      and meta->>'paid_allowance_anchor' is not null and (p_prior_ended is null or p_prior_ended>p_start)
      and audit_private.effective_tier(meta,to_timestamp(p_start)) in ('pro','serious') then
     anchor:=(meta->>'paid_allowance_anchor')::bigint;
     generation:=meta->>'paid_allowance_generation';
   end if;
   if prior=p_subscription and meta->>'plan' in ('pro','serious') then
     anchor:=coalesce((meta->>'paid_allowance_anchor')::bigint,p_start);
     generation:=coalesce(meta->>'paid_allowance_generation',p_subscription);
     if revision=0 and not (meta ? 'paid_allowance_anchor') then
       -- Existing paid account: preserve usage since its verified Stripe start.
       update public.scan_usage_monthly set paid_cycle=generation where user_id=p_user and paid_cycle is null and created_at>=to_timestamp(anchor);
       update public.aca_ai_usage set paid_cycle=generation where user_id=p_user and paid_cycle is null and created_at>=to_timestamp(anchor);
     end if;
   end if;
 end if;
 update auth.users set raw_app_meta_data=meta || jsonb_build_object(
   'plan',p_plan,'stripe_customer_id',p_customer,'stripe_subscription_id',p_subscription,
   'stripe_subscription_created',p_created,'stripe_subscription_status',p_status,
   'stripe_cancel_at_period_end',p_scheduled,'stripe_current_period_end',p_end,
   'stripe_current_period_end_iso',to_timestamp(p_end),'paid_allowance_anchor',anchor,
   'paid_allowance_generation',generation,'billing_revision',revision+1)
 where id=p_user;
 return jsonb_build_object('ok',true);
end $$;
revoke all on function audit_private.effective_tier(jsonb,timestamptz),
 audit_private.allowance_identity(uuid,timestamptz),
 audit_private.sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint)
 from public,anon,authenticated;
grant execute on function audit_private.allowance_identity(uuid,timestamptz),
 audit_private.sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint) to service_role;

create function public.aca_sync_subscription(p_user uuid,p_revision bigint,p_subscription text,p_customer text,
 p_created bigint,p_start bigint,p_plan text,p_status text,p_scheduled boolean,p_end bigint,p_prior_ended bigint default null)
returns jsonb language sql security invoker set search_path='' as $$
 select audit_private.sync_subscription(p_user,p_revision,p_subscription,p_customer,p_created,p_start,p_plan,p_status,p_scheduled,p_end,p_prior_ended)
$$;
revoke all on function public.aca_sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint) from public,anon,authenticated;
grant execute on function public.aca_sync_subscription(uuid,bigint,text,text,bigint,bigint,text,text,boolean,bigint,bigint) to service_role;

create or replace function public.audit_monthly_usage(p_user uuid,p_action text,p_receipt uuid default null,p_kind text default 'code',p_total integer default 20,p_repos integer default 2,p_charge boolean default false)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  cycle_start timestamptz; cycle_end timestamptz; ident record; as_of timestamptz;
  total_used integer; repo_used integer; pending integer; allowed boolean := true;
begin
  if p_user is null or p_action not in ('status','reserve','settle') or p_kind not in ('code','repo') or p_total < 0 or p_repos < 0 then raise exception 'Invalid usage operation'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text,0));
  as_of:=clock_timestamp();
  select * into strict ident from audit_private.allowance_identity(p_user,as_of);
  select starts_at,ends_at into cycle_start,cycle_end from audit_private.monthly_window(ident.anchor,as_of);
  -- Legacy clients supply limits. The committed tier owns the actual limits.
  if p_action='reserve' and (p_total,p_repos) is distinct from
     (case ident.tier when 'serious' then 300 when 'pro' then 75 else 5 end,
      case ident.tier when 'serious' then 40 when 'pro' then 10 else 1 end) then
    raise exception 'Plan changed during reservation; retry';
  end if;
  p_total:=case ident.tier when 'serious' then 300 when 'pro' then 75 else 5 end;
  p_repos:=case ident.tier when 'serious' then 40 when 'pro' then 10 else 1 end;
  delete from public.scan_usage_monthly where user_id=p_user and created_at < now()-interval '90 days';
  if p_action='settle' then
    update public.scan_usage_monthly set state=case when p_charge and expires_at>as_of then 'charged' else 'refunded' end
      where receipt=p_receipt and user_id=p_user and state='reserved';
  end if;
  select count(*),count(*) filter(where kind='repo'),count(*) filter(where state='reserved') into total_used,repo_used,pending
    from public.scan_usage_monthly where user_id=p_user and paid_cycle is not distinct from ident.paid_cycle and created_at>=cycle_start and created_at<cycle_end and (state='charged' or (state='reserved' and expires_at>as_of));
  if p_action='reserve' then
    if p_receipt is null then raise exception 'Missing receipt'; end if;
    if exists(select 1 from public.scan_usage_monthly where receipt=p_receipt) then raise exception 'Receipt already used'; end if;
    allowed := total_used < p_total and (p_kind <> 'repo' or repo_used < p_repos);
    if allowed then
      insert into public.scan_usage_monthly(receipt,user_id,period,kind,state,paid_cycle,created_at,expires_at) values(p_receipt,p_user,(cycle_start at time zone 'UTC')::date,p_kind,'reserved',ident.paid_cycle,as_of,as_of+interval '15 minutes');
      total_used:=total_used+1; pending:=pending+1;
      if p_kind='repo' then repo_used:=repo_used+1; end if;
    end if;
  end if;
  return jsonb_build_object('allowed',allowed,'total_used',total_used,'repo_used',repo_used,'pending',pending,'total_limit',p_total,'repo_limit',p_repos,'total_remaining',greatest(0,p_total-total_used),'repo_remaining',greatest(0,p_repos-repo_used),'period_starts_at',cycle_start,'resets_at',cycle_end,'cycle_basis',case when ident.paid_cycle is null then 'account_created_at' else 'paid_subscription_start' end);
end; $$;
revoke all on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) from public,anon,authenticated;
grant execute on function public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean) to service_role;

create or replace function public.aca_ai_usage_control(p_user uuid,p_action text,p_receipt uuid default null,p_cost bigint default null,p_success boolean default false,p_input integer default null,p_output integer default null)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare entitlement record; as_of timestamptz; ident jsonb; tier text; starts timestamptz; ends timestamptz; cap int; used int; spent bigint; allowed boolean; budget_start timestamptz; budget_end timestamptz;
begin
 if p_action not in ('status','reserve','settle') or p_user is null then raise exception 'Invalid AI usage operation'; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_user::text,0));
 perform pg_advisory_xact_lock(60129102);
 as_of:=clock_timestamp();
 select * into strict entitlement from audit_private.allowance_identity(p_user,as_of);
 ident:=audit_private.workspace_identity(p_user);
 tier:=entitlement.tier;
 if ident is null or ident->>'email' is null then return jsonb_build_object('ok',false,'error','Sign in with a verified email.'); end if;
 select starts_at,ends_at into starts,ends from audit_private.monthly_window(entitlement.anchor,as_of);
 cap:=case when tier='admin' then 400 when tier='serious' then 100 when tier='pro' then 25 else 0 end;
 -- Interrupted calls free the customer allowance, but retain full reserved dollars.
 update public.aca_ai_usage set state='failed' where state='reserved' and created_at<now()-interval '3 minutes';
 if p_action='settle' then
  if p_cost is not null and (p_cost<0 or p_cost>100000) then raise exception 'Invalid AI cost'; end if;
  update public.aca_ai_usage set state=case when p_success then 'complete' else 'failed' end,
    cost_micro_usd=coalesce(p_cost,cost_micro_usd),input_tokens=p_input,output_tokens=p_output
    where receipt=p_receipt and user_id=p_user and state='reserved';
 end if;
 -- Cost reporting uses UTC calendar months; customer quotas use the account entitlement.
 -- No shared dollar cutoff: paid accounts retain access within their own allowances.
 budget_start:=date_trunc('month',now() at time zone 'UTC') at time zone 'UTC';
 budget_end:=(date_trunc('month',now() at time zone 'UTC')+interval '1 month') at time zone 'UTC';
 select coalesce(sum(cost_micro_usd),0) into spent from public.aca_ai_usage where created_at>=budget_start and created_at<budget_end;
 select count(*) into used from public.aca_ai_usage where user_id=p_user and paid_cycle is not distinct from entitlement.paid_cycle and created_at>=starts and created_at<ends and state in ('reserved','complete');
 allowed:=tier in ('admin','pro','serious') and used<cap;
 if p_action='reserve' then
  if p_receipt is null then raise exception 'Missing request ID'; end if;
  if exists(select 1 from public.aca_ai_usage where receipt=p_receipt) then return jsonb_build_object('ok',false,'error','This request was already submitted. It will not be charged again.'); end if;
  if exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved') then return jsonb_build_object('ok',false,'error','An AI review is already running. Wait before starting another.'); end if;
  if not allowed then return jsonb_build_object('ok',false,'error',case when cap=0 then 'AI change reviews require Pro or Serious. Basic comparison remains free.' when used>=cap then 'Your AI comparison allowance is used. Basic comparison remains available.' else 'AI review is temporarily unavailable. Basic comparison remains available.' end); end if;
  insert into public.aca_ai_usage(receipt,user_id,created_at,paid_cycle) values(p_receipt,p_user,as_of,entitlement.paid_cycle); used:=used+1;spent:=spent+100000;
 end if;
 allowed:=tier in ('admin','pro','serious') and used<cap and not exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved');
 return jsonb_build_object('ok',true,'available',allowed,'reason',case when cap=0 then 'plan' when used>=cap then 'allowance' when exists(select 1 from public.aca_ai_usage where user_id=p_user and state='reserved') then 'running' else null end,'private_validation',false,'limit',cap,'used',used,'resets_at',ends,'budget_reserved_or_spent_usd',case when tier='admin' then spent/1000000.0 else null end,'monthly_budget_usd',null,'budget_resets_at',budget_end,'budget_warning',null);
end; $$;
revoke all on function public.aca_ai_usage_control(uuid,text,uuid,bigint,boolean,integer,integer) from public,anon,authenticated;
grant execute on function public.aca_ai_usage_control(uuid,text,uuid,bigint,boolean,integer,integer) to service_role;
