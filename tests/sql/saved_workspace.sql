begin;
insert into auth.users(id,email,email_confirmed_at,raw_app_meta_data) values
('00000000-0000-4000-8000-000000000101','workspace-owner@example.invalid',now(),'{"plan":"pro"}'),
('00000000-0000-4000-8000-000000000102','workspace-recipient@example.invalid',now(),'{}'),
('00000000-0000-4000-8000-000000000103','workspace-other@example.invalid',now(),'{}');
set local role service_role;
do $$ declare owner_id uuid:='00000000-0000-4000-8000-000000000101'; recipient uuid:='00000000-0000-4000-8000-000000000102'; r jsonb; rid uuid; pid uuid; i int;
begin
 r:=public.aca_workspace(owner_id,'project_create','{"name":"Test project"}'); assert (r->>'ok')::boolean; pid:=(r->>'id')::uuid;
 perform public.aca_workspace(owner_id,'project_create','{"name":"Second"}');perform public.aca_workspace(owner_id,'project_create','{"name":"Third"}');
 for i in 4..10 loop assert (public.aca_workspace(owner_id,'project_create',jsonb_build_object('name','Project '||i))->>'ok')::boolean; end loop;
 assert not (public.aca_workspace(owner_id,'project_create','{"name":"Eleventh"}')->>'ok')::boolean;
 r:=public.aca_workspace(owner_id,'save',jsonb_build_object('title','Fixture','kind','compare','project_id',pid,'payload',jsonb_build_object('before','safe','after','safe'))); assert (r->>'ok')::boolean;rid:=(r->>'id')::uuid;
 assert (public.aca_workspace(owner_id,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
 assert not (public.aca_workspace(recipient,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
 assert not (public.aca_workspace(recipient,'save','{"title":"No","kind":"audit","payload":{}}')->>'ok')::boolean;
 assert not (public.aca_workspace(owner_id,'share',jsonb_build_object('id',rid,'email','workspace-recipient@example.invalid'))->>'ok')::boolean;
 assert not (public.aca_workspace(owner_id,'save',jsonb_build_object('title','Too big','kind','audit','payload',jsonb_build_object('text',repeat('a',262145))))->>'ok')::boolean;
 assert (select expires_at<=now()+interval '30 days' from public.aca_reports where id=rid);
 perform public.aca_workspace(owner_id,'trash',jsonb_build_object('id',rid)); assert not (public.aca_workspace(owner_id,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
 perform public.aca_workspace(owner_id,'restore',jsonb_build_object('id',rid)); assert (public.aca_workspace(owner_id,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
end $$;
reset role;
update auth.users set raw_app_meta_data='{"plan":"serious"}' where id='00000000-0000-4000-8000-000000000101';
set local role service_role;
do $$ declare owner_id uuid:='00000000-0000-4000-8000-000000000101'; recipient uuid:='00000000-0000-4000-8000-000000000102'; rid uuid; r jsonb; i int;
begin
 select id into rid from public.aca_reports where user_id=owner_id limit 1;
 for i in 11..50 loop assert (public.aca_workspace(owner_id,'project_create',jsonb_build_object('name','Project '||i))->>'ok')::boolean; end loop;
 assert not (public.aca_workspace(owner_id,'project_create','{"name":"Fifty first"}')->>'ok')::boolean;
 assert (public.aca_workspace(owner_id,'share',jsonb_build_object('id',rid,'email','WORKSPACE-RECIPIENT@example.invalid'))->>'ok')::boolean;
 assert (public.aca_workspace(recipient,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
 assert not (public.aca_workspace('00000000-0000-4000-8000-000000000103','get',jsonb_build_object('id',rid))->>'ok')::boolean;
 assert not (public.aca_workspace(recipient,'trash',jsonb_build_object('id',rid))->>'ok')::boolean;
 perform public.aca_workspace(owner_id,'revoke',jsonb_build_object('id',rid,'email','workspace-recipient@example.invalid'));
 assert not (public.aca_workspace(recipient,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
 r:=public.aca_workspace(owner_id,'save','{"title":"Serious expiry","kind":"audit","payload":{}}'); assert (r->>'ok')::boolean;
 assert (select expires_at=now()+interval '365 days' from public.aca_reports where id=(r->>'id')::uuid);
 update public.aca_reports set expires_at=now()-interval '1 second' where id=rid;
 assert not (public.aca_workspace(owner_id,'get',jsonb_build_object('id',rid))->>'ok')::boolean;
end $$;
reset role;
set local role authenticated;
do $$ begin
 begin perform public.aca_workspace('00000000-0000-4000-8000-000000000101','list','{}'); raise exception 'Unexpected RPC access'; exception when insufficient_privilege then null; end;
 begin perform 1 from public.aca_reports; raise exception 'Unexpected table access'; exception when insufficient_privilege then null; end;
end $$;
reset role;
rollback;
select 'Workspace authorization, quotas, sharing, trash and expiry tests passed; fixtures rolled back' as result;
