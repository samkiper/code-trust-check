-- Run after supabase/monthly_usage.sql; read-only calendar assertions.
do $$
declare r record; w record;
begin
 for r in select * from (values
 ('2025-01-31 12:34:56+00','2025-02-28 12:34:55+00','2025-01-31 12:34:56+00','2025-02-28 12:34:56+00'),
 ('2025-01-31 12:34:56+00','2025-02-28 12:34:56+00','2025-02-28 12:34:56+00','2025-03-31 12:34:56+00'),
 ('2024-01-31 12:34:56+00','2024-02-29 12:34:56+00','2024-02-29 12:34:56+00','2024-03-31 12:34:56+00'),
 ('2024-02-29 08:15:00+00','2025-02-28 08:15:00+00','2025-02-28 08:15:00+00','2025-03-29 08:15:00+00'),
 ('2025-01-30 08:15:00+00','2025-03-30 08:15:00+00','2025-03-30 08:15:00+00','2025-04-30 08:15:00+00'),
 ('2025-01-31 08:15:00+00','2025-04-30 08:15:00+00','2025-04-30 08:15:00+00','2025-05-31 08:15:00+00'),
 ('2025-12-15 08:15:00+00','2026-01-15 08:15:00+00','2026-01-15 08:15:00+00','2026-02-15 08:15:00+00'),
 ('2026-10-26 00:35:27.965126+00','2026-11-01 00:00:00+00','2026-10-26 00:35:27.965126+00','2026-11-26 00:35:27.965126+00')
 ) as cases(anchor,instant,expected_start,expected_end) loop
 select * into w from audit_private.monthly_window(r.anchor::timestamptz,r.instant::timestamptz);
 if w.starts_at<>r.expected_start::timestamptz or w.ends_at<>r.expected_end::timestamptz then raise exception 'Incorrect window: %',r; end if;
 end loop;
 -- Session timezone cannot change the calendar calculations.
 perform set_config('TimeZone','America/Chicago',true);
 select * into w from audit_private.monthly_window('2025-01-31 12:34:56+00','2025-02-28 12:34:56+00');
 if w.ends_at<>'2025-03-31 12:34:56+00'::timestamptz then raise exception 'Timezone drift'; end if;
 if has_function_privilege('authenticated','audit_private.account_created_at(uuid)','EXECUTE')
 or has_function_privilege('anon','public.audit_monthly_usage(uuid,text,uuid,text,integer,integer,boolean)','EXECUTE') then raise exception 'Usage function exposed'; end if;
end $$;
