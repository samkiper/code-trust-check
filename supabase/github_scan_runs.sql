create table if not exists public.github_scan_runs (
  scan_id text primary key check (char_length(scan_id) between 8 and 32),
  user_id uuid not null references auth.users(id) on delete cascade,
  installation_id bigint not null references public.github_installations(installation_id) on delete cascade,
  repository text not null,
  pull_request_number integer not null check (pull_request_number > 0),
  commit_sha text not null check (char_length(commit_sha) = 40),
  status text not null check (status in ('in_progress', 'completed', 'failed')),
  conclusion text not null default '',
  high_count integer not null default 0 check (high_count >= 0),
  medium_count integer not null default 0 check (medium_count >= 0),
  notice_count integer not null default 0 check (notice_count >= 0),
  files_scanned integer not null default 0 check (files_scanned >= 0),
  files_skipped integer not null default 0 check (files_skipped >= 0),
  findings jsonb not null default '[]'::jsonb,
  details_url text not null default '',
  error_message text not null default '',
  scanner_version integer not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.github_scan_runs enable row level security;

create index if not exists github_scan_runs_user_updated_idx
  on public.github_scan_runs (user_id, updated_at desc);

create index if not exists github_scan_runs_repository_updated_idx
  on public.github_scan_runs (repository, updated_at desc);

revoke all on public.github_scan_runs from anon, authenticated;
