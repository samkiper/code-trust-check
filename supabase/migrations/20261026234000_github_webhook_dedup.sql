-- Delivery metadata only. Submitted code and GitHub tokens are never stored here.
create table if not exists public.aca_github_deliveries (
  delivery_id uuid primary key,
  lease_id uuid not null,
  state text not null check (state in ('reserved','done')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists aca_github_deliveries_expiry_idx on public.aca_github_deliveries(expires_at);
alter table public.aca_github_deliveries enable row level security;
revoke all on public.aca_github_deliveries from public, anon, authenticated;
grant select,insert,update,delete on public.aca_github_deliveries to service_role;

create or replace function public.aca_github_delivery_control(p_delivery uuid,p_lease uuid,p_action text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare accepted boolean := false;
begin
  if p_delivery is null or p_lease is null or p_action not in ('reserve','complete','release') then raise exception 'Invalid delivery operation'; end if;
  if p_action='reserve' then
    delete from public.aca_github_deliveries where delivery_id in
      (select delivery_id from public.aca_github_deliveries where expires_at<=now() order by expires_at limit 100);
    insert into public.aca_github_deliveries(delivery_id,lease_id,state,expires_at)
      values(p_delivery,p_lease,'reserved',now()+interval '2 hours') on conflict do nothing;
    accepted := found;
  elsif p_action='complete' then
    update public.aca_github_deliveries set state='done',expires_at=now()+interval '7 days'
      where delivery_id=p_delivery and lease_id=p_lease and state='reserved';
    accepted := found;
  else
    delete from public.aca_github_deliveries where delivery_id=p_delivery and lease_id=p_lease and state='reserved';
    accepted := found;
  end if;
  return jsonb_build_object('ok',true,'accepted',accepted);
end; $$;
revoke all on function public.aca_github_delivery_control(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.aca_github_delivery_control(uuid,uuid,text) to service_role;
