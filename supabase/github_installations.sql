create table if not exists public.github_installations (
  installation_id bigint primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  account_login text not null default '',
  account_type text not null default '',
  status text not null default 'active' check (status in ('active', 'suspended', 'deleted')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.github_installations enable row level security;

create index if not exists github_installations_user_id_idx
  on public.github_installations (user_id, status, updated_at desc);

revoke all on public.github_installations from anon, authenticated;
