-- Stage 5: close direct client access to this exercise table only.
select 'before' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='notes' and grantee in ('PUBLIC','anon','authenticated','service_role')
order by grantee,privilege_type;
select 'before' as phase, role_name,
  has_table_privilege(role_name,'public.notes','SELECT') as can_select,
  has_table_privilege(role_name,'public.notes','INSERT') as can_insert,
  has_table_privilege(role_name,'public.notes','UPDATE') as can_update,
  has_table_privilege(role_name,'public.notes','DELETE') as can_delete
from (values ('anon'),('authenticated'),('service_role')) as roles(role_name);

begin;
revoke all on table public.notes from public, anon, authenticated;
revoke all privileges (id,owner_id,title,content) on public.notes from public, anon, authenticated;
-- Keep RLS, owner policies and existing server grants. Do not change other tables.
alter table public.notes enable row level security;
commit;

select 'after' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='notes' and grantee in ('PUBLIC','anon','authenticated','service_role')
order by grantee,privilege_type;
select 'after' as phase, role_name,
  has_table_privilege(role_name,'public.notes','SELECT') as can_select,
  has_table_privilege(role_name,'public.notes','INSERT') as can_insert,
  has_table_privilege(role_name,'public.notes','UPDATE') as can_update,
  has_table_privilege(role_name,'public.notes','DELETE') as can_delete,
  (select relrowsecurity from pg_class where oid='public.notes'::regclass) as rls_enabled
from (values ('anon'),('authenticated'),('service_role')) as roles(role_name);
