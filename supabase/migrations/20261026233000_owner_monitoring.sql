-- Aggregated service-only monitoring. No source, customer identifiers or caps.
create index if not exists aca_ai_usage_created_at_idx on public.aca_ai_usage(created_at);
create index if not exists scan_usage_monthly_created_at_idx on public.scan_usage_monthly(created_at);

create or replace function public.aca_owner_monitoring_summary()
returns jsonb language sql stable security invoker set search_path = '' as $$
  with bounds as (
    select (date_trunc('month', now() at time zone 'UTC') at time zone 'UTC') as month_start,
           now() - interval '24 hours' as day_start
  ), ai as (
    select count(*) filter (where u.state='complete') as completed,
           count(*) filter (where u.state='failed') as failed,
           count(*) filter (where u.state='reserved') as reserved,
           count(*) filter (where u.input_tokens is null or u.output_tokens is null) as unresolved_count,
           coalesce(sum(u.cost_micro_usd) filter (where u.input_tokens is not null and u.output_tokens is not null),0) as recorded_micro_usd,
           coalesce(sum(u.cost_micro_usd) filter (where u.input_tokens is null or u.output_tokens is null),0) as unresolved_reserved_micro_usd
      from public.aca_ai_usage u cross join bounds b where u.created_at>=b.month_start
  ), scans as (
    select count(*) filter (where s.state='charged') as charged,
           count(*) filter (where s.state='refunded') as refunded,
           count(*) filter (where s.state='reserved' and s.expires_at>now()) as reserved,
           count(*) filter (where s.state='reserved' and s.expires_at<=now()) as expired_reservations
      from public.scan_usage_monthly s cross join bounds b where s.created_at>=b.day_start
  )
  select jsonb_build_object('period_start_utc', b.month_start,
    'ai', to_jsonb(ai), 'scans_last_24_hours', to_jsonb(scans))
    from bounds b cross join ai cross join scans;
$$;
revoke all on function public.aca_owner_monitoring_summary() from public, anon, authenticated;
grant execute on function public.aca_owner_monitoring_summary() to service_role;
