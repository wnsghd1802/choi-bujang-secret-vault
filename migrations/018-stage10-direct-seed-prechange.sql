-- Stage 10: preserve pre-attack B data when the judge provisions notes directly
-- in SQL instead of using POST /api/notes. The trigger copies OLD (never NEW)
-- on the FIRST change and never changes existing student notes/audit records.
-- Only UUIDv5 owner namespaces are eligible; normal student UUIDv4 notes
-- and already-protected immutable judge-B backups are not duplicated.
BEGIN;
CREATE TABLE IF NOT EXISTS public.test_note_prechange_copies (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
  content text NOT NULL CHECK (length(content) <= 10000),
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  captured_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.test_note_prechange_copies ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.test_note_prechange_copies FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON public.test_note_prechange_copies TO service_role;
DROP TRIGGER IF EXISTS stage10_prechange_immutable ON public.test_note_prechange_copies;
CREATE TRIGGER stage10_prechange_immutable
  BEFORE UPDATE OR DELETE ON public.test_note_prechange_copies
  FOR EACH ROW EXECUTE FUNCTION public.stage10_reject_history_mutation();
DROP TRIGGER IF EXISTS stage10_prechange_no_truncate ON public.test_note_prechange_copies;
CREATE TRIGGER stage10_prechange_no_truncate
  BEFORE TRUNCATE ON public.test_note_prechange_copies
  FOR EACH STATEMENT EXECUTE FUNCTION public.stage10_reject_history_mutation();

CREATE OR REPLACE FUNCTION public.capture_stage10_first_prechange()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
  -- UUIDv5 is the signed judge namespace created by src/note-owner.mjs.
  -- It is a candidate snapshot, NOT a claim that identity B was verified.
  -- Signed judge-B verification happens before the restore RPC is called.
  IF OLD.owner_id IS NOT NULL AND substring(OLD.owner_id::text from 15 for 1)='5'
     AND NOT EXISTS (SELECT 1 FROM public.test_note_backups b WHERE b.id=OLD.id)
     AND (TG_OP='DELETE'
        OR OLD.id IS DISTINCT FROM NEW.id
        OR OLD.owner_id IS DISTINCT FROM NEW.owner_id
        OR OLD.title IS DISTINCT FROM NEW.title
        OR OLD.content IS DISTINCT FROM NEW.content)
  THEN
    INSERT INTO public.test_note_prechange_copies
      (id,owner_id,title,content,content_sha256)
    VALUES (OLD.id,OLD.owner_id,OLD.title,OLD.content,
      encode(sha256(convert_to(OLD.content,'UTF8')),'hex'))
    ON CONFLICT (id) DO NOTHING;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.capture_stage10_first_prechange()
  FROM PUBLIC,anon,authenticated,service_role;
DROP TRIGGER IF EXISTS stage10_first_prechange ON public.notes;
CREATE TRIGGER stage10_first_prechange
  BEFORE UPDATE OR DELETE ON public.notes
  FOR EACH ROW EXECUTE FUNCTION public.capture_stage10_first_prechange();

-- Reuse the protected lineage table (run_id=zero is an internal source marker).
-- A real signed run_id is supplied separately when auditing a completed restore.
CREATE OR REPLACE FUNCTION public.track_stage10_prechange_identity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
  origin public.test_note_prechange_copies%rowtype;
  unbound constant uuid:='00000000-0000-0000-0000-000000000000'::uuid;
BEGIN
  IF OLD.id IS NOT DISTINCT FROM NEW.id
      AND OLD.owner_id IS NOT DISTINCT FROM NEW.owner_id THEN RETURN NEW; END IF;
  UPDATE public.test_b_mutation_lineage l SET current_id=NEW.id
    WHERE l.current_id=OLD.id AND l.run_id=unbound;
  IF FOUND THEN RETURN NEW; END IF;
  SELECT p.* INTO origin FROM public.test_note_prechange_copies p
    WHERE p.id=OLD.id AND p.owner_id=OLD.owner_id;
  IF NOT FOUND THEN RETURN NEW; END IF;
  INSERT INTO public.test_b_mutation_lineage
    (original_id,current_id,owner_id,run_id)
  VALUES(origin.id,NEW.id,origin.owner_id,unbound)
  ON CONFLICT (original_id) DO UPDATE SET current_id=excluded.current_id
    WHERE test_b_mutation_lineage.current_id=OLD.id
      AND test_b_mutation_lineage.owner_id=excluded.owner_id
      AND test_b_mutation_lineage.run_id=unbound;
  IF NOT FOUND THEN RAISE EXCEPTION 'trusted_prechange_lineage_conflict'; END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.track_stage10_prechange_identity()
  FROM PUBLIC,anon,authenticated,service_role;
DROP TRIGGER IF EXISTS stage10_prechange_identity ON public.notes;
CREATE TRIGGER stage10_prechange_identity
  AFTER UPDATE OF id,owner_id ON public.notes
  FOR EACH ROW EXECUTE FUNCTION public.track_stage10_prechange_identity();

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
REVOKE ALL ON FUNCTION public.restore_test_note_from_prechange(uuid,uuid,uuid,text)
  FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.restore_test_note_from_prechange(uuid,uuid,uuid,text)
  TO service_role;
COMMIT;
