-- Synthetic isolated PostgreSQL fixture: not the user's Supabase.
create role anon;
create role authenticated;
create role service_role bypassrls;
create table public.notes (
  id uuid primary key,
  owner_id uuid not null,
  title text not null,
  content text not null
);
grant select, insert, update, delete on public.notes to service_role;
