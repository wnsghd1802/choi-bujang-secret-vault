-- Run once in the SAME Supabase project as stage 2.
-- Preserves note content and owner_id. Existing numeric IDs become UUIDs.
begin;
do $$
declare current_type text;
begin
  select data_type into current_type from information_schema.columns
    where table_schema = 'public' and table_name = 'notes' and column_name = 'id';
  if current_type = 'bigint' then
    alter table public.notes alter column id type uuid using gen_random_uuid();
  elsif current_type is distinct from 'uuid' then
    raise exception 'Unexpected notes.id type. No migration applied.';
  end if;
end $$;
alter table public.notes alter column id set default gen_random_uuid();
alter table public.notes enable row level security;
revoke all on table public.notes from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on table public.notes to service_role;
commit;
select
  (select count(*) from public.notes) as note_count,
  (select data_type from information_schema.columns where table_schema='public' and table_name='notes' and column_name='id') as id_type,
  (select relrowsecurity from pg_class where oid='public.notes'::regclass) as rls_enabled,
  has_table_privilege('anon','public.notes','SELECT') as anon_can_read,
  has_table_privilege('authenticated','public.notes','SELECT') as authenticated_can_read,
  (has_table_privilege('service_role','public.notes','SELECT') and
   has_table_privilege('service_role','public.notes','INSERT') and
   has_table_privilege('service_role','public.notes','UPDATE') and
   has_table_privilege('service_role','public.notes','DELETE')) as server_crud_ready;
