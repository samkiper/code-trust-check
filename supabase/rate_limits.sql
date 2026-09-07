create table if not exists public.rate_limit_buckets (
  bucket_key text primary key check (char_length(bucket_key) between 16 and 96),
  window_started_at timestamptz not null default clock_timestamp(),
  request_count integer not null default 0 check (request_count >= 0),
  updated_at timestamptz not null default clock_timestamp()
);

alter table public.rate_limit_buckets enable row level security;
revoke all on public.rate_limit_buckets from anon, authenticated;

create index if not exists rate_limit_buckets_updated_idx
  on public.rate_limit_buckets (updated_at);

create or replace function public.consume_rate_limit(
  p_bucket_key text,
  p_limit integer,
  p_window_seconds integer
)
returns table (allowed boolean, retry_after integer, remaining integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_row public.rate_limit_buckets%rowtype;
  v_window interval;
begin
  if p_bucket_key is null or char_length(p_bucket_key) not between 16 and 96 then
    raise exception 'invalid rate-limit bucket';
  end if;
  if p_limit < 1 or p_limit > 10000 or p_window_seconds < 1 or p_window_seconds > 86400 then
    raise exception 'invalid rate-limit configuration';
  end if;

  v_window := make_interval(secs => p_window_seconds);

  insert into public.rate_limit_buckets as bucket (
    bucket_key, window_started_at, request_count, updated_at
  ) values (
    p_bucket_key, v_now, 1, v_now
  )
  on conflict (bucket_key) do update set
    window_started_at = case
      when bucket.window_started_at + v_window <= v_now then v_now
      else bucket.window_started_at
    end,
    request_count = case
      when bucket.window_started_at + v_window <= v_now then 1
      else bucket.request_count + 1
    end,
    updated_at = v_now
  returning * into v_row;

  return query select
    v_row.request_count <= p_limit,
    case
      when v_row.request_count <= p_limit then 0
      else greatest(1, ceil(extract(epoch from ((v_row.window_started_at + v_window) - v_now)))::integer)
    end,
    greatest(0, p_limit - v_row.request_count);
end;
$$;

revoke all on function public.consume_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_rate_limit(text, integer, integer) to service_role;

-- Old buckets are operational metadata only. Run periodically if the table grows.
delete from public.rate_limit_buckets where updated_at < clock_timestamp() - interval '2 days';
