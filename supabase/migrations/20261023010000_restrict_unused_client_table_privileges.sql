-- Preserve authenticated own-profile RLS and backend service-role access.
REVOKE ALL ON TABLE public.scan_usage_daily FROM anon, authenticated;
REVOKE ALL ON TABLE public.profiles FROM anon;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.profiles FROM authenticated;
