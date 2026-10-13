-- Stage 8: ADDITIVE-only schema for server-managed instructor notices.
-- Does not touch existing public.notes, users, policies or stored note data.
-- Run manually in the existing Supabase SQL editor only after review.
begin;

create table if not exists public.instructor_grants (
  user_id uuid primary key references auth.users(id) on delete cascade,
  can_edit_notices boolean not null default false
);
create table if not exists public.instructor_notices (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(title) between 1 and 120),
  content text not null check (length(content) <= 10000)
);
alter table public.instructor_grants enable row level security;
alter table public.instructor_notices enable row level security;

-- Server-only: no anon/authenticated/public Data API reads or writes.
revoke all on public.instructor_grants from public, anon, authenticated;
revoke all on public.instructor_notices from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.instructor_grants to service_role;
grant select, insert, update, delete on public.instructor_notices to service_role;

commit;

-- Do not seed an instructor account or fabricate a grant.
-- A trusted administrator must separately grant an existing verified
-- auth.users(id) after confirming the instructor's identity.
