-- Stage 10: additive, test-account-B-only recovery storage.
-- This script MUST be reviewed and applied manually to the SAME Supabase
-- project before testing the /api/restore endpoint.
-- It never deletes/modifies existing notes, service policies or audit logs.
begin;

create table if not exists public.test_note_backups (
  id uuid primary key,
  owner_id uuid not null,
  run_id uuid not null,
  identity text not null default 'b' check (identity = 'b'),
  title text not null check (length(title) between 1 and 120),
  content text not null check (length(content) <= 10000),
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at timestamptz not null default now()
);
alter table public.test_note_backups enable row level security;
revoke all on public.test_note_backups from public, anon, authenticated;
grant select, insert on public.test_note_backups to service_role;
-- No update/delete privilege is needed: good copies cannot be overwritten
-- from the application, even after malicious edits/deletes to original notes.

-- Append-only recovery evidence (no memo title/body/token).
create table if not exists public.test_recovery_audit (
  event_id bigint generated always as identity primary key,
  note_id uuid not null,
  owner_id uuid not null,
  run_id uuid not null,
  restored_sha256 text not null,
  restored_at timestamptz not null default now()
);
alter table public.test_recovery_audit enable row level security;
revoke all on public.test_recovery_audit from public, anon, authenticated;
grant insert on public.test_recovery_audit to service_role;

create or replace function public.create_test_note_with_backup(
  p_id uuid, p_owner_id uuid, p_run_id uuid,
  p_title text, p_content text, p_hash text
) returns table (id uuid, title text, content text)
language plpgsql security invoker set search_path = public, pg_temp as $func$
begin
  if p_id is null or p_owner_id is null or p_run_id is null
      or p_title is null or length(p_title) not between 1 and 120
      or p_content is null or length(p_content) > 10000
      or p_hash is null or p_hash !~ '^[0-9a-f]{64}$'
      or p_hash is distinct from encode(sha256(convert_to(p_content, 'UTF8')), 'hex') then
    raise exception 'unverified_test_note';
  end if;

  -- Both inserts are part of one database transaction. Failed backups
  -- cannot leave a newly created unprotected test note behind.
  insert into public.notes (id, owner_id, title, content)
    values (p_id, p_owner_id, p_title, p_content);
  insert into public.test_note_backups
    (id, owner_id, run_id, identity, title, content, content_sha256)
    values (p_id, p_owner_id, p_run_id, 'b', p_title, p_content, p_hash);
  return query select n.id, n.title, n.content from public.notes n
    where n.id = p_id and n.owner_id = p_owner_id;
end;
$func$;

create or replace function public.restore_test_note_from_backup(
  p_id uuid, p_owner_id uuid, p_run_id uuid, p_hash text
) returns table (id uuid, owner_id uuid, title text, content text)
language plpgsql security invoker set search_path = public, pg_temp as $func$
declare
  safe_copy public.test_note_backups%rowtype;
  checked_copy public.test_note_backups%rowtype;
begin
  -- Fetch and verify the exact stored backup BEFORE any notes mutation.
  select b.* into safe_copy from public.test_note_backups b
    where b.id = p_id and b.owner_id = p_owner_id
      and b.run_id = p_run_id and b.identity = 'b'
      and b.content_sha256 = p_hash;
  if not found then raise exception 'backup_missing_or_unverified'; end if;
  if safe_copy.title is null or length(safe_copy.title) not between 1 and 120
      or safe_copy.content is null or length(safe_copy.content) > 10000
      or safe_copy.content_sha256 is null
      or safe_copy.content_sha256 is distinct from
        encode(sha256(convert_to(safe_copy.content, 'UTF8')), 'hex') then
    raise exception 'backup_digest_mismatch';
  end if;

  -- Restore only the selected B note; never overwrite another owner.
  insert into public.notes as n (id, owner_id, title, content)
    values (safe_copy.id, safe_copy.owner_id, safe_copy.title, safe_copy.content)
  on conflict on constraint notes_pkey do update
    set title = excluded.title, content = excluded.content
    where n.owner_id = excluded.owner_id;

  -- Re-read the exact private backup after the write and compare ALL
  -- restored values. Any failed check raises inside the SAME transaction
  -- so even a prior INSERT/UPDATE is rolled back.
  select b.* into checked_copy from public.test_note_backups b
    where b.id = p_id and b.owner_id = p_owner_id
      and b.run_id = p_run_id and b.identity = 'b';
  if not found
      or checked_copy.title is distinct from safe_copy.title
      or checked_copy.content is distinct from safe_copy.content
      or checked_copy.content_sha256 is distinct from safe_copy.content_sha256
      or checked_copy.content_sha256 is distinct from
        encode(sha256(convert_to(checked_copy.content, 'UTF8')), 'hex') then
    raise exception 'backup_reread_failed';
  end if;

  perform 1 from public.notes n
    where n.id = safe_copy.id and n.owner_id = safe_copy.owner_id
      and n.title = safe_copy.title and n.content = safe_copy.content
      and encode(sha256(convert_to(n.content, 'UTF8')), 'hex') = safe_copy.content_sha256;
  if not found then raise exception 'restored_note_verification_failed'; end if;

  -- Add, never replace, the recovery evidence only after both checks pass.
  insert into public.test_recovery_audit
    (note_id, owner_id, run_id, restored_sha256)
    values (p_id, p_owner_id, p_run_id, p_hash);

  return query select n.id, n.owner_id, n.title, n.content from public.notes n
    where n.id = safe_copy.id and n.owner_id = safe_copy.owner_id;
end;
$func$;

-- Functions are callable only with the server's service-role credential.
revoke all on function public.create_test_note_with_backup(
  uuid,uuid,uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.restore_test_note_from_backup(
  uuid,uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_test_note_with_backup(
  uuid,uuid,uuid,text,text,text) to service_role;
grant execute on function public.restore_test_note_from_backup(
  uuid,uuid,uuid,text) to service_role;
commit;

-- CHECK MANUALLY (read-only). Never print backup content or tokens.
select has_table_privilege('anon','public.test_note_backups','SELECT') as anon_read,
  has_table_privilege('authenticated','public.test_note_backups','SELECT') as student_direct_read,
  has_table_privilege('service_role','public.test_note_backups','SELECT') as server_read,
  has_table_privilege('service_role','public.test_note_backups','INSERT') as server_snapshot;
-- Expected: false, false, true, true.
