create extension if not exists "pgcrypto";

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  display_name text,
  created_at timestamptz not null default now()
);

create table if not exists public.scan_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  url text not null,
  classification text not null,
  trust_score double precision,
  ml_score double precision,
  rule_score double precision,
  sandbox_score double precision,
  l1l2_risk text,
  l3_risk text,
  timestamp timestamptz not null default now()
);

create table if not exists public.scan_analysis_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  url text not null,
  raw_result_json jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists public.user_settings (
  user_id uuid primary key references auth.users (id) on delete cascade,
  auto_block_enabled boolean not null default true,
  risk_threshold integer not null default 60,
  scan_mode text not null default 'fast',
  security_mode text not null default 'balanced',
  updated_at timestamptz not null default now()
);

create table if not exists public.allowlist (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  domain text not null,
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);

create table if not exists public.blocklist (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  domain text not null,
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);

create table if not exists public.weekly_summaries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  week_start date not null,
  safe_count integer not null default 0,
  suspicious_count integer not null default 0,
  phishing_count integer not null default 0,
  top_risky_domains_json jsonb not null default '[]'::jsonb,
  unique (user_id, week_start)
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name, created_at)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'display_name', new.raw_user_meta_data->>'full_name'),
    now()
  )
  on conflict (id) do update
  set email = excluded.email,
      display_name = coalesce(excluded.display_name, public.profiles.display_name);

  insert into public.user_settings (user_id, updated_at)
  values (new.id, now())
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.scan_history enable row level security;
alter table public.scan_analysis_logs enable row level security;
alter table public.user_settings enable row level security;
alter table public.allowlist enable row level security;
alter table public.blocklist enable row level security;
alter table public.weekly_summaries enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles for select using (auth.uid() = id);
drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own" on public.profiles for insert with check (auth.uid() = id);
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles for update using (auth.uid() = id);

drop policy if exists "scan_history_select_own" on public.scan_history;
create policy "scan_history_select_own" on public.scan_history for select using (auth.uid() = user_id);
drop policy if exists "scan_history_insert_own" on public.scan_history;
create policy "scan_history_insert_own" on public.scan_history for insert with check (auth.uid() = user_id);
drop policy if exists "scan_history_update_own" on public.scan_history;
create policy "scan_history_update_own" on public.scan_history for update using (auth.uid() = user_id);
drop policy if exists "scan_history_delete_own" on public.scan_history;
create policy "scan_history_delete_own" on public.scan_history for delete using (auth.uid() = user_id);

drop policy if exists "scan_logs_select_own" on public.scan_analysis_logs;
create policy "scan_logs_select_own" on public.scan_analysis_logs for select using (auth.uid() = user_id);
drop policy if exists "scan_logs_insert_own" on public.scan_analysis_logs;
create policy "scan_logs_insert_own" on public.scan_analysis_logs for insert with check (auth.uid() = user_id);
drop policy if exists "scan_logs_delete_own" on public.scan_analysis_logs;
create policy "scan_logs_delete_own" on public.scan_analysis_logs for delete using (auth.uid() = user_id);

drop policy if exists "user_settings_select_own" on public.user_settings;
create policy "user_settings_select_own" on public.user_settings for select using (auth.uid() = user_id);
drop policy if exists "user_settings_insert_own" on public.user_settings;
create policy "user_settings_insert_own" on public.user_settings for insert with check (auth.uid() = user_id);
drop policy if exists "user_settings_update_own" on public.user_settings;
create policy "user_settings_update_own" on public.user_settings for update using (auth.uid() = user_id);

drop policy if exists "allowlist_select_own" on public.allowlist;
create policy "allowlist_select_own" on public.allowlist for select using (auth.uid() = user_id);
drop policy if exists "allowlist_insert_own" on public.allowlist;
create policy "allowlist_insert_own" on public.allowlist for insert with check (auth.uid() = user_id);
drop policy if exists "allowlist_delete_own" on public.allowlist;
create policy "allowlist_delete_own" on public.allowlist for delete using (auth.uid() = user_id);

drop policy if exists "blocklist_select_own" on public.blocklist;
create policy "blocklist_select_own" on public.blocklist for select using (auth.uid() = user_id);
drop policy if exists "blocklist_insert_own" on public.blocklist;
create policy "blocklist_insert_own" on public.blocklist for insert with check (auth.uid() = user_id);
drop policy if exists "blocklist_delete_own" on public.blocklist;
create policy "blocklist_delete_own" on public.blocklist for delete using (auth.uid() = user_id);

drop policy if exists "weekly_summaries_select_own" on public.weekly_summaries;
create policy "weekly_summaries_select_own" on public.weekly_summaries for select using (auth.uid() = user_id);
drop policy if exists "weekly_summaries_insert_own" on public.weekly_summaries;
create policy "weekly_summaries_insert_own" on public.weekly_summaries for insert with check (auth.uid() = user_id);
drop policy if exists "weekly_summaries_update_own" on public.weekly_summaries;
create policy "weekly_summaries_update_own" on public.weekly_summaries for update using (auth.uid() = user_id);

insert into public.profiles (id, email, display_name, created_at)
select
  users.id,
  users.email,
  coalesce(users.raw_user_meta_data->>'display_name', users.raw_user_meta_data->>'full_name'),
  coalesce(users.created_at, now())
from auth.users as users
on conflict (id) do update
set email = excluded.email,
    display_name = coalesce(excluded.display_name, public.profiles.display_name);

insert into public.user_settings (user_id, updated_at)
select users.id, now()
from auth.users as users
on conflict (user_id) do nothing;

notify pgrst, 'reload schema';
