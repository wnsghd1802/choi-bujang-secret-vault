-- Stage 10: require durable proof of exactly the requested recovery audit event.
-- This replaces ONLY the test-B restore RPC function; no existing notes, backup
-- rows, audit entries, or prior-stage policies are modified by the migration.
-- Prerequisite: 010 backup re-verification, 011/012 audit immutability.
-- The caller applies this migration transactionally; any failure rolls back.

create or replace function public.restore_test_note_from_backup(
  p_id uuid, p_owner_id uuid, p_run_id uuid, p_hash text
) returns table (id uuid, owner_id uuid, title text, content text)
language plpgsql security invoker set search_path = public, pg_temp as $func$
declare
  safe_copy public.test_note_backups%rowtype;
  checked_copy public.test_note_backups%rowtype;
  audit_event_id bigint;
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
    values (p_id, p_owner_id, p_run_id, p_hash)
    returning event_id into audit_event_id;

  -- A BEFORE INSERT trigger may suppress an insert without raising an error.
  -- Do not leave restored data committed without a persisted audit receipt.
  if audit_event_id is null then
    raise exception 'recovery_audit_persistence_failed';
  end if;
  perform 1 from public.test_recovery_audit a
    where a.event_id = audit_event_id
      and a.note_id = p_id and a.owner_id = p_owner_id
      and a.run_id = p_run_id and a.restored_sha256 = p_hash;
  if not found then
    raise exception 'recovery_audit_reverification_failed';
  end if;

  return query select n.id, n.owner_id, n.title, n.content from public.notes n
    where n.id = safe_copy.id and n.owner_id = safe_copy.owner_id;
end;
$func$;

-- The caller must be able to read the receipt again in the SAME transaction.
-- A fresh isolated DB does not inherit Supabase-managed service_role grants.
-- Other roles keep their direct audit table access denied.
grant select on public.test_recovery_audit to service_role;

-- Verify privilege scope remains server-only.
revoke all on function public.restore_test_note_from_backup(
  uuid,uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.restore_test_note_from_backup(
  uuid,uuid,uuid,text) to service_role;
