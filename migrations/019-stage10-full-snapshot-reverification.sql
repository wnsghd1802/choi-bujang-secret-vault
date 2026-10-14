-- Stage10: full backup snapshot integrity gate, before any note restoration.
-- A content hash alone does not bind the original note ID, owner and title.
-- This seals each NEW append-only snapshot at its initial insertion.
-- Existing snapshot rows are never retroactively declared authentic.
BEGIN;

-- Refuse to silently backfill or endorse previously created evidence.
DO $check$
BEGIN
  IF EXISTS(SELECT 1 FROM public.test_note_backups LIMIT 1)
    OR EXISTS(SELECT 1 FROM public.test_note_prechange_copies LIMIT 1) THEN
    RAISE EXCEPTION 'existing_snapshots_require_manual_provenance_review';
  END IF;
END $check$;

CREATE OR REPLACE FUNCTION public.stage10_full_snapshot_digest(
  p_id uuid, p_owner uuid, p_run uuid, p_identity text,
  p_title text, p_content text
) RETURNS text LANGUAGE sql IMMUTABLE STRICT
SET search_path=pg_catalog AS $digest$
  SELECT encode(sha256(convert_to(
    concat_ws('|','aleph.stage10.snapshot.v1',p_id::text,p_owner::text,
      p_run::text,p_identity,
      encode(convert_to(p_title,'UTF8'),'hex'),
      encode(convert_to(p_content,'UTF8'),'hex')), 'UTF8')), 'hex');
$digest$;
REVOKE ALL ON FUNCTION public.stage10_full_snapshot_digest(
  uuid,uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_full_snapshot_digest(
  uuid,uuid,uuid,text,text,text) TO service_role;

ALTER TABLE public.test_note_backups
  ADD COLUMN snapshot_sha256 text;
ALTER TABLE public.test_note_prechange_copies
  ADD COLUMN snapshot_sha256 text;
ALTER TABLE public.test_note_backups
  ALTER COLUMN snapshot_sha256 SET NOT NULL;
ALTER TABLE public.test_note_prechange_copies
  ALTER COLUMN snapshot_sha256 SET NOT NULL;
ALTER TABLE public.test_note_backups ADD CONSTRAINT stage10_backup_full_hash_valid
  CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE public.test_note_prechange_copies ADD CONSTRAINT stage10_prechange_full_hash_valid
  CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$');

CREATE OR REPLACE FUNCTION public.stage10_seal_new_snapshot()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $seal$
DECLARE
  zero_run constant uuid:='00000000-0000-0000-0000-000000000000'::uuid;
BEGIN
  IF TG_TABLE_NAME='test_note_backups' THEN
    NEW.snapshot_sha256 := public.stage10_full_snapshot_digest(
      NEW.id,NEW.owner_id,NEW.run_id,NEW.identity,NEW.title,NEW.content);
  ELSIF TG_TABLE_NAME='test_note_prechange_copies' THEN
    NEW.snapshot_sha256 := public.stage10_full_snapshot_digest(
      NEW.id,NEW.owner_id,zero_run,'prechange',NEW.title,NEW.content);
  ELSE
    RAISE EXCEPTION 'unknown_snapshot_source';
  END IF;
  RETURN NEW;
END $seal$;
REVOKE ALL ON FUNCTION public.stage10_seal_new_snapshot()
  FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER stage10_seal_backup_before_insert
 BEFORE INSERT ON public.test_note_backups
 FOR EACH ROW EXECUTE FUNCTION public.stage10_seal_new_snapshot();
CREATE TRIGGER stage10_seal_prechange_before_insert
 BEFORE INSERT ON public.test_note_prechange_copies
 FOR EACH ROW EXECUTE FUNCTION public.stage10_seal_new_snapshot();

-- Keep the exact prior restore paths, adding fail-closed complete seals both
-- BEFORE restoration and AFTER the snapshot reread inside their transactions.
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

  -- Verify an immutable seal over the ENTIRE snapshot before any note write.
  -- The existing content-only SHA256 cannot detect changed titles/owners.
  if safe_copy.snapshot_sha256 is null
     or safe_copy.snapshot_sha256 is distinct from public.stage10_full_snapshot_digest(
          safe_copy.id,safe_copy.owner_id,safe_copy.run_id,safe_copy.identity,
          safe_copy.title,safe_copy.content)
     or safe_copy.backed_up_at > statement_timestamp()
    then raise exception 'backup_full_snapshot_unverified'; end if;

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

  if checked_copy.snapshot_sha256 is distinct from safe_copy.snapshot_sha256
     or checked_copy.snapshot_sha256 is distinct from public.stage10_full_snapshot_digest(
          checked_copy.id,checked_copy.owner_id,checked_copy.run_id,checked_copy.identity,
          checked_copy.title,checked_copy.content)
    then raise exception 'backup_full_snapshot_reread_failed'; end if;

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

CREATE OR REPLACE FUNCTION public.restore_test_note_from_prechange(
  p_id uuid,p_owner_id uuid,p_run_id uuid,p_hash text
) RETURNS TABLE(id uuid,owner_id uuid,title text,content text,audit_event_id bigint)
LANGUAGE plpgsql SECURITY INVOKER SET search_path=public,pg_temp AS $fn$
DECLARE
  safe public.test_note_prechange_copies%rowtype;
  reread public.test_note_prechange_copies%rowtype;
  moving uuid;
  event bigint;
  unbound constant uuid:='00000000-0000-0000-0000-000000000000'::uuid;
BEGIN
  IF p_id IS NULL OR p_owner_id IS NULL OR p_run_id IS NULL
    OR p_run_id=unbound OR substring(p_owner_id::text from 15 for 1)<>'5'
    OR p_hash !~ '^[0-9a-f]{64}$'
    THEN RAISE EXCEPTION 'prechange_invalid_restore_scope'; END IF;
  SELECT p.* INTO safe FROM public.test_note_prechange_copies p
    WHERE p.id=p_id AND p.owner_id=p_owner_id AND p.content_sha256=p_hash;
  IF NOT FOUND THEN RAISE EXCEPTION 'prechange_copy_not_found'; END IF;
  IF safe.content_sha256 IS DISTINCT FROM
    encode(sha256(convert_to(safe.content,'UTF8')),'hex')
    THEN RAISE EXCEPTION 'prechange_digest_mismatch'; END IF;
  -- A first-change OLD capture is sealed at insert. Compare the complete
  -- original ID, owner, title and content BEFORE restoring any row.
  IF safe.snapshot_sha256 IS NULL
     OR safe.snapshot_sha256 IS DISTINCT FROM public.stage10_full_snapshot_digest(
       safe.id,safe.owner_id,unbound,'prechange',safe.title,safe.content)
     OR safe.captured_at > statement_timestamp()
    THEN RAISE EXCEPTION 'prechange_full_snapshot_unverified'; END IF;

  SELECT l.current_id INTO moving FROM public.test_b_mutation_lineage l
    WHERE l.original_id=safe.id AND l.owner_id=safe.owner_id
      AND l.run_id=unbound FOR UPDATE;
  IF FOUND THEN
    UPDATE public.notes n SET id=safe.id,owner_id=safe.owner_id,
      title=safe.title,content=safe.content WHERE n.id=moving;
    IF NOT FOUND THEN RAISE EXCEPTION 'prechange_tracked_row_missing'; END IF;
  ELSE
    INSERT INTO public.notes AS n(id,owner_id,title,content)
      VALUES(safe.id,safe.owner_id,safe.title,safe.content)
    ON CONFLICT ON CONSTRAINT notes_pkey DO UPDATE
      SET title=excluded.title,content=excluded.content
      WHERE n.owner_id=excluded.owner_id;
  END IF;
  SELECT p.* INTO reread FROM public.test_note_prechange_copies p
    WHERE p.id=safe.id AND p.owner_id=safe.owner_id;
  IF NOT FOUND OR reread.title IS DISTINCT FROM safe.title
    OR reread.content IS DISTINCT FROM safe.content
    OR reread.content_sha256 IS DISTINCT FROM safe.content_sha256
    OR reread.content_sha256 IS DISTINCT FROM
      encode(sha256(convert_to(reread.content,'UTF8')),'hex')
    THEN RAISE EXCEPTION 'prechange_snapshot_changed'; END IF;
  IF reread.snapshot_sha256 IS DISTINCT FROM safe.snapshot_sha256
     OR reread.snapshot_sha256 IS DISTINCT FROM public.stage10_full_snapshot_digest(
       reread.id,reread.owner_id,unbound,'prechange',reread.title,reread.content)
    THEN RAISE EXCEPTION 'prechange_full_snapshot_reread_failed'; END IF;

  PERFORM 1 FROM public.notes n WHERE n.id=safe.id AND n.owner_id=safe.owner_id
    AND n.title=safe.title AND n.content=safe.content
    AND encode(sha256(convert_to(n.content,'UTF8')),'hex')=safe.content_sha256;
  IF NOT FOUND THEN RAISE EXCEPTION 'prechange_restored_note_mismatch'; END IF;
  INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
    VALUES(safe.id,safe.owner_id,p_run_id,safe.content_sha256)
    RETURNING event_id INTO event;
  IF event IS NULL THEN RAISE EXCEPTION 'prechange_audit_missing'; END IF;
  PERFORM 1 FROM public.test_recovery_audit a
    WHERE a.event_id=event AND a.note_id=safe.id AND a.owner_id=safe.owner_id
      AND a.run_id=p_run_id AND a.restored_sha256=safe.content_sha256;
  IF NOT FOUND THEN RAISE EXCEPTION 'prechange_audit_reread_failed'; END IF;
  RETURN QUERY SELECT n.id,n.owner_id,n.title,n.content,event FROM public.notes n
    WHERE n.id=safe.id AND n.owner_id=safe.owner_id;
END
$fn$;
COMMIT;
