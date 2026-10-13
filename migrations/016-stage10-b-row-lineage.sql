-- Stage 10: trusted row identity lineage for genuine B note id/owner tampering.
-- Purpose: reclaim the SAME backed-up B row, not an arbitrary foreign owner's
-- note. An attacker cannot supply lineage via HTTP. Old RPC remains unchanged.
-- No existing notes, backups, audit rows, earlier policies are changed here.
begin;

create table if not exists public.test_b_mutation_lineage (
  original_id uuid primary key,
  current_id uuid not null unique,
  owner_id uuid not null,
  run_id uuid not null
);
alter table public.test_b_mutation_lineage enable row level security;
revoke all on public.test_b_mutation_lineage from public,anon,authenticated;
grant select,insert,update,delete on public.test_b_mutation_lineage to service_role;

create or replace function public.trace_test_b_identity_change()
returns trigger language plpgsql security definer
set search_path = pg_catalog, pg_temp as $trigger$
declare
  v_backup record;
begin
  if TG_OP = 'DELETE' then
    -- A deleted/missing tuple may NEVER authorize rewriting a new note whose
    -- UUID was subsequently reused. Ordinary deleted B recovery still works.
    delete from public.test_b_mutation_lineage l where l.current_id=OLD.id;
    return OLD;
  end if;
  if OLD.id is not distinct from NEW.id
     and OLD.owner_id is not distinct from NEW.owner_id then
    return NEW;
  end if;
  -- Follow already-tracked moves without resetting their original identity.
  update public.test_b_mutation_lineage l set current_id=NEW.id
    where l.current_id=OLD.id;
  if found then return NEW; end if;
  -- Start tracking only a row that DID belong to the immutable B snapshot.
  select b.id,b.owner_id,b.run_id into v_backup
    from public.test_note_backups b
    where b.id=OLD.id and b.owner_id=OLD.owner_id
      and b.identity='b';
  if found then
    insert into public.test_b_mutation_lineage
      (original_id,current_id,owner_id,run_id)
      values(v_backup.id,NEW.id,v_backup.owner_id,v_backup.run_id)
    on conflict(original_id) do update set current_id=excluded.current_id
      where test_b_mutation_lineage.current_id=OLD.id
        and test_b_mutation_lineage.owner_id=excluded.owner_id
        and test_b_mutation_lineage.run_id=excluded.run_id;
    if not found then raise exception 'trusted_b_lineage_conflict'; end if;
  end if;
  return NEW;
end;
$trigger$;
revoke all on function public.trace_test_b_identity_change() from public,anon,authenticated;
-- Its trusted database trigger, not an untrusted direct API, invokes it.
drop trigger if exists trace_test_b_identity_change on public.notes;
create trigger trace_test_b_identity_change
after update of id,owner_id or delete on public.notes
for each row execute function public.trace_test_b_identity_change();

create or replace function public.restore_test_note_with_lineage(
  p_id uuid, p_owner_id uuid, p_run_id uuid, p_hash text
) returns table (id uuid, owner_id uuid, title text, content text, audit_event_id bigint)
language plpgsql security invoker set search_path = public, pg_temp as $func$
declare
  safe_copy public.test_note_backups%rowtype;
  checked_copy public.test_note_backups%rowtype;
  v_audit_event_id bigint;
  v_linked_id uuid;
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

  -- A protected lineage event proves this SAME original B record was moved
  -- by an UPDATE of id/owner_id after its immutable backup existed. Never
  -- infer a move from attacker-supplied values or from similar note text.
  select l.current_id into v_linked_id
    from public.test_b_mutation_lineage l
    where l.original_id = safe_copy.id
      and l.owner_id = safe_copy.owner_id and l.run_id = safe_copy.run_id
    for update;
  if found then
    -- Update exactly the tracked tuple (which may have a modified primary key).
    -- A collision with another owner's original ID fails and rolls back.
    update public.notes n
      set id = safe_copy.id, owner_id = safe_copy.owner_id,
          title = safe_copy.title, content = safe_copy.content
      where n.id = v_linked_id;
    if not found then raise exception 'tracked_test_note_missing'; end if;
  else
    -- No verified mutation lineage: keep the original owner protection.
    -- This also continues to support a genuinely deleted B note.
    insert into public.notes as n (id, owner_id, title, content)
      values (safe_copy.id, safe_copy.owner_id, safe_copy.title, safe_copy.content)
    on conflict on constraint notes_pkey do update
      set title = excluded.title, content = excluded.content
      where n.owner_id = excluded.owner_id;
  end if;

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
    returning event_id into v_audit_event_id;

  -- A BEFORE INSERT trigger may suppress an insert without raising an error.
  -- Do not leave restored data committed without a persisted audit receipt.
  if v_audit_event_id is null then
    raise exception 'recovery_audit_persistence_failed';
  end if;
  perform 1 from public.test_recovery_audit a
    where a.event_id = v_audit_event_id
      and a.note_id = p_id and a.owner_id = p_owner_id
      and a.run_id = p_run_id and a.restored_sha256 = p_hash;
  if not found then
    raise exception 'recovery_audit_reverification_failed';
  end if;

  return query select n.id, n.owner_id, n.title, n.content, v_audit_event_id from public.notes n
    where n.id = safe_copy.id and n.owner_id = safe_copy.owner_id;
end;
$func$;


revoke all on function public.restore_test_note_with_lineage(
 uuid,uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.restore_test_note_with_lineage(
 uuid,uuid,uuid,text) to service_role;
commit;
