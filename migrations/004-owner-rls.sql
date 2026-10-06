-- Only public.notes is changed. Other tables, users and note contents are preserved.
-- Before: inspect effective privileges and explicit grants.
select 'before' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='notes' and grantee in ('PUBLIC','anon','authenticated')
order by grantee,privilege_type;
select 'before' as phase, role_name,
  has_table_privilege(role_name,'public.notes','SELECT') as can_select,
  has_table_privilege(role_name,'public.notes','INSERT') as can_insert,
  has_table_privilege(role_name,'public.notes','UPDATE') as can_update,
  has_table_privilege(role_name,'public.notes','DELETE') as can_delete
from (values ('anon'),('authenticated')) as roles(role_name);

begin;
alter table public.notes enable row level security;
revoke all on table public.notes from public, anon, authenticated;
revoke all privileges (id,owner_id,title,content) on public.notes from public, anon, authenticated;
-- Replace policies only on this exercise table, so older permissive policies cannot bypass these rules.
do $$
declare existing record;
begin
  for existing in select policyname from pg_policies where schemaname='public' and tablename='notes'
  loop
    execute format('drop policy %I on public.notes',existing.policyname);
  end loop;
end $$;
create policy notes_select_own on public.notes for select to authenticated
  using ((select auth.uid()) = owner_id);
create policy notes_insert_own on public.notes for insert to authenticated
  with check ((select auth.uid()) = owner_id);
create policy notes_update_own on public.notes for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy notes_delete_own on public.notes for delete to authenticated
  using ((select auth.uid()) = owner_id);
grant select,insert,update,delete on public.notes to authenticated;
commit;

select 'after' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='notes' and grantee in ('PUBLIC','anon','authenticated')
order by grantee,privilege_type;
select policyname,cmd,roles,qual,with_check from pg_policies
where schemaname='public' and tablename='notes' order by policyname;
-- Expected: anon false for all four privileges; authenticated true for all four.
-- true grants operation capability; the policies still restrict each row to its owner.
select 'after' as phase, role_name,
  has_table_privilege(role_name,'public.notes','SELECT') as can_select,
  has_table_privilege(role_name,'public.notes','INSERT') as can_insert,
  has_table_privilege(role_name,'public.notes','UPDATE') as can_update,
  has_table_privilege(role_name,'public.notes','DELETE') as can_delete,
  (select relrowsecurity from pg_class where oid='public.notes'::regclass) as rls_enabled,
  (select count(*) from pg_policies where schemaname='public' and tablename='notes') as policy_count
from (values ('anon'),('authenticated')) as roles(role_name);
