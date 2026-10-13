-- Synthetic direct-SQL B provisioning and attack, isolated in one rollback.
BEGIN;
SET LOCAL ROLE service_role;
DO $test$
DECLARE
  b uuid:=gen_random_uuid();
  a uuid:=gen_random_uuid();
  student_note uuid:=gen_random_uuid();
  moved uuid:=gen_random_uuid();
  v_run uuid:=gen_random_uuid();
  owner_b uuid:='5a47746c-e927-50bb-9a28-f7db4feaa201';
  owner_a uuid:='8057c773-cad0-5a72-a575-9b2c35b3e91e';
  owner_student uuid:=gen_random_uuid();
  safe_hash text:=encode(sha256(convert_to('untampered initial B','UTF8')),'hex');
  old_event bigint;
  restored record;
BEGIN
  INSERT INTO public.notes(id,owner_id,title,content) VALUES
    (a,owner_a,'Original A','preserve A'),
    (student_note,owner_student,'Student normal','preserve student'),
    (b,owner_b,'Directly seeded B','untampered initial B');
  INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
    VALUES(a,owner_a,v_run,repeat('e',64)) RETURNING event_id INTO old_event;

  -- Attack direct SQL note, bypassing the student's create endpoint.
  UPDATE public.notes SET id=moved,owner_id=owner_student,content='attacker B'
    WHERE id=b;
  IF NOT EXISTS(SELECT 1 FROM public.test_note_prechange_copies c
    WHERE c.id=b AND c.owner_id=owner_b AND c.content_sha256=safe_hash)
    THEN RAISE EXCEPTION 'DIRECT_B_PRECHANGE_MISSING'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.test_b_mutation_lineage l
    WHERE l.original_id=b AND l.current_id=moved
      AND l.run_id='00000000-0000-0000-0000-000000000000'::uuid)
    THEN RAISE EXCEPTION 'DIRECT_B_LINEAGE_MISSING'; END IF;
  SELECT * INTO restored FROM public.restore_test_note_from_prechange(
    b,owner_b,v_run,safe_hash);
  IF NOT FOUND OR restored.audit_event_id IS NULL
    OR restored.content<>'untampered initial B'
    OR EXISTS(SELECT 1 FROM public.notes WHERE id=moved)
    OR (SELECT content FROM public.notes WHERE id=a)<>'preserve A'
    OR (SELECT content FROM public.notes WHERE id=student_note)<>'preserve student'
    OR (SELECT count(*) FROM public.test_recovery_audit
      WHERE event_id=old_event AND note_id=a AND restored_sha256=repeat('e',64))<>1
    OR (SELECT count(*) FROM public.test_recovery_audit
      WHERE note_id=b AND run_id=v_run AND restored_sha256=safe_hash)<>1
    THEN RAISE EXCEPTION 'DIRECT_B_AUDIT_OR_SCOPE_FAILED'; END IF;
  -- Ordinary student edits must not be silently copied as stage-10 B notes.
  UPDATE public.notes SET content='student routine edit' WHERE id=student_note;
  IF EXISTS(SELECT 1 FROM public.test_note_prechange_copies c
    WHERE c.id=student_note)
    THEN RAISE EXCEPTION 'STUDENT_NOTE_COPIED'; END IF;
  -- A direct SQL deletion is also captured BEFORE the affected row vanishes.
  DELETE FROM public.notes WHERE id=a;
  IF NOT EXISTS(SELECT 1 FROM public.test_note_prechange_copies c
    WHERE c.id=a AND c.content='preserve A')
    THEN RAISE EXCEPTION 'V5_PREDELETE_NOT_CAPTURED'; END IF;
END $test$;
ROLLBACK;
SELECT 'PASS direct B prechange snapshot + audit + student isolation' AS result;
