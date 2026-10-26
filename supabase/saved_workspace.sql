-- Service-only API. Identity is supplied by the backend after live Auth verification.
create table if not exists public.aca_projects (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 name text not null check(length(name) between 1 and 100), created_at timestamptz not null default now(), unique(user_id,name)
);
create table if not exists public.aca_reports (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 project_id uuid references public.aca_projects(id) on delete set null, title text not null check(length(title) between 1 and 120),
 kind text not null check(kind in ('audit','compare')), payload jsonb not null check(jsonb_typeof(payload)='object'),
 created_at timestamptz not null default now(), expires_at timestamptz not null, deleted_at timestamptz,
 check(octet_length(payload::text)<=262144)
);
create table if not exists public.aca_report_grants (
 report_id uuid not null references public.aca_reports(id) on delete cascade, recipient_email text not null,
 created_at timestamptz not null default now(), primary key(report_id,recipient_email)
);
create index if not exists aca_projects_owner on public.aca_projects(user_id);
create index if not exists aca_reports_owner on public.aca_reports(user_id,created_at desc);
create index if not exists aca_reports_expiry on public.aca_reports(expires_at);
create index if not exists aca_reports_project on public.aca_reports(project_id);
alter table public.aca_projects enable row level security;
alter table public.aca_reports enable row level security;
alter table public.aca_report_grants enable row level security;
revoke all on public.aca_projects,public.aca_reports,public.aca_report_grants from public,anon,authenticated;
grant select,insert,update,delete on public.aca_projects,public.aca_reports,public.aca_report_grants to service_role;
create or replace function audit_private.workspace_identity(p_user uuid)
returns jsonb language sql stable security definer set search_path='' as $$
 select jsonb_build_object('plan',case when raw_app_meta_data->>'role'='admin' then 'admin' else coalesce(raw_app_meta_data->>'plan','free') end,
 'email',case when email_confirmed_at is not null then lower(email) else null end) from auth.users where id=p_user and deleted_at is null;
$$;
revoke all on function audit_private.workspace_identity(uuid) from public,anon,authenticated;
grant execute on function audit_private.workspace_identity(uuid) to service_role;
create or replace function public.aca_workspace(p_user uuid,p_action text,p_body jsonb default '{}')
returns jsonb language plpgsql security invoker set search_path='' as $$
declare ident jsonb; tier text; rid uuid; pid uuid; item public.aca_reports; mail text; days int; cap int; payload jsonb;
begin
 ident:=audit_private.workspace_identity(p_user); tier:=ident->>'plan';
 if ident is null then return jsonb_build_object('ok',false,'error','Sign in to view saved work.'); end if;
 if jsonb_typeof(p_body)!='object' then return jsonb_build_object('ok',false,'error','Invalid workspace request.'); end if;
 days:=case when tier in ('serious','admin') then 365 when tier='pro' then 30 else 0 end;
 cap:=case when tier in ('serious','admin') then 200 else 50 end;
 -- A global transaction lock prevents concurrent saves from racing storage limits.
 perform pg_advisory_xact_lock(60129101);
 -- Expired data is inaccessible immediately and purged on the next workspace operation.
 delete from public.aca_reports where expires_at<=now() or deleted_at<=now()-interval '7 days';
 if p_action='list' then
  return jsonb_build_object('ok',true,'plan',tier,'history_days',days,'report_limit',cap,'project_limit',case when tier='pro' then 3 when days=0 then 0 else null end,
    'projects',coalesce((select jsonb_agg(to_jsonb(p) order by p.name) from public.aca_projects p where user_id=p_user),'[]'::jsonb),
    'reports',coalesce((select jsonb_agg(to_jsonb(r) order by r.created_at desc) from (select id,project_id,title,kind,created_at,expires_at,deleted_at from public.aca_reports where user_id=p_user) r),'[]'::jsonb));
 end if;
 if p_action='get' then
  rid:=(p_body->>'id')::uuid;
  select * into item from public.aca_reports where id=rid and deleted_at is null and expires_at>now();
  if not found then return jsonb_build_object('ok',false,'error','Report unavailable or access not granted.'); end if;
  if item.user_id!=p_user and not coalesce((
    audit_private.workspace_identity(item.user_id)->>'plan' in ('serious','admin')
    and exists(select 1 from public.aca_report_grants where report_id=rid and recipient_email=ident->>'email')
  ),false) then return jsonb_build_object('ok',false,'error','Report unavailable or access not granted.'); end if;
  return jsonb_build_object('ok',true,'report',to_jsonb(item),'owned',item.user_id=p_user,'can_share',item.user_id=p_user and tier in ('serious','admin'),
    'recipients',case when item.user_id=p_user then coalesce((select jsonb_agg(recipient_email order by recipient_email) from public.aca_report_grants where report_id=rid),'[]'::jsonb) else '[]'::jsonb end);
 end if;
 if p_action in ('trash','restore') then
  update public.aca_reports set deleted_at=case when p_action='trash' then now() else null end where id=(p_body->>'id')::uuid and user_id=p_user and expires_at>now();
  return jsonb_build_object('ok',found);
 end if;
 if p_action='revoke' then
  delete from public.aca_report_grants g using public.aca_reports r where r.id=g.report_id and r.user_id=p_user and r.id=(p_body->>'id')::uuid and g.recipient_email=lower(trim(p_body->>'email'));
  return jsonb_build_object('ok',true);
 end if;
 if days=0 then return jsonb_build_object('ok',false,'error','Saving new work requires Pro or Serious. Existing saved reports remain accessible until their expiry.'); end if;
 if p_action='project_create' then
  if tier='pro' and (select count(*) from public.aca_projects where user_id=p_user)>=3 then return jsonb_build_object('ok',false,'error','Pro includes 3 projects.'); end if;
  if length(trim(coalesce(p_body->>'name',''))) not between 1 and 100 then return jsonb_build_object('ok',false,'error','Use a project name from 1 to 100 characters.'); end if;
  insert into public.aca_projects(user_id,name) values(p_user,trim(p_body->>'name')) returning id into pid;
  return jsonb_build_object('ok',true,'id',pid);
 end if;
 if p_action='project_rename' then
  update public.aca_projects set name=trim(p_body->>'name') where id=(p_body->>'id')::uuid and user_id=p_user;
  return jsonb_build_object('ok',found);
 end if;
 if p_action='save' then
  payload:=p_body->'payload'; pid:=nullif(p_body->>'project_id','')::uuid;
  if jsonb_typeof(payload) is distinct from 'object' or octet_length(payload::text)>262144 then return jsonb_build_object('ok',false,'error','Report must be an object smaller than 256 KB. Download larger reports instead.'); end if;
  if pid is not null and not exists(select 1 from public.aca_projects where id=pid and user_id=p_user) then return jsonb_build_object('ok',false,'error','Project unavailable.'); end if;
  if (select count(*) from public.aca_reports where user_id=p_user)>=cap then return jsonb_build_object('ok',false,'error','Saved report capacity reached. Download reports or wait for expired/trash reports to be removed.'); end if;
  if (select coalesce(sum(octet_length(stored.payload::text)),0) from public.aca_reports stored)+octet_length(payload::text)>100000000 then return jsonb_build_object('ok',false,'error','Saved history storage is temporarily full. Download this report to keep a copy.'); end if;
  insert into public.aca_reports(user_id,project_id,title,kind,payload,expires_at) values(p_user,pid,trim(p_body->>'title'),p_body->>'kind',payload,now()+make_interval(days=>days)) returning id into rid;
  return jsonb_build_object('ok',true,'id',rid);
 end if;
 if p_action='move' then
  pid:=nullif(p_body->>'project_id','')::uuid;
  if pid is not null and not exists(select 1 from public.aca_projects where id=pid and user_id=p_user) then return jsonb_build_object('ok',false,'error','Project unavailable.'); end if;
  update public.aca_reports set project_id=pid where id=(p_body->>'id')::uuid and user_id=p_user;
  return jsonb_build_object('ok',found);
 end if;
 if p_action='share' then
  if tier not in ('serious','admin') then return jsonb_build_object('ok',false,'error','Private sharing requires Serious.'); end if;
  rid:=(p_body->>'id')::uuid; mail:=lower(trim(p_body->>'email'));
  if mail is null or length(mail)>254 or mail!~'^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then return jsonb_build_object('ok',false,'error','Enter the recipient email address.'); end if;
  if not exists(select 1 from public.aca_reports where id=rid and user_id=p_user and deleted_at is null and expires_at>now()) then return jsonb_build_object('ok',false,'error','Report unavailable.'); end if;
  if (select count(*) from public.aca_report_grants where report_id=rid)>=20 then return jsonb_build_object('ok',false,'error','Each report supports up to 20 recipients. Revoke an existing recipient first.'); end if;
  insert into public.aca_report_grants(report_id,recipient_email) values(rid,mail) on conflict do nothing;
  return jsonb_build_object('ok',true);
 end if;
 return jsonb_build_object('ok',false,'error','Unknown workspace action.');
exception when invalid_text_representation or check_violation or not_null_violation or unique_violation then
 return jsonb_build_object('ok',false,'error','Check the request fields. Project names must be unique.');
end; $$;
revoke all on function public.aca_workspace(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.aca_workspace(uuid,text,jsonb) to service_role;
