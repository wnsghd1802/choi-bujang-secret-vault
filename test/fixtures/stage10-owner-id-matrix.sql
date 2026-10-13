-- Independent PostgreSQL 16; all rows synthetic and transaction rolled back.
BEGIN;
SET LOCAL ROLE service_role;
DO $matrix$
DECLARE
  v_a uuid:=gen_random_uuid();
  v_owner_a uuid:=gen_random_uuid();
  v_owner_b uuid:=gen_random_uuid();
  v_intruder uuid:=gen_random_uuid();
  v_run uuid:=gen_random_uuid();
  v_prior_run uuid:=gen_random_uuid();
  v_b uuid:=gen_random_uuid();
  v_b2 uuid:=gen_random_uuid();
  v_b3 uuid:=gen_random_uuid();
  v_b4 uuid:=gen_random_uuid();
  v_b5 uuid:=gen_random_uuid();
  v_b6 uuid:=gen_random_uuid();
  v_other_b uuid:=gen_random_uuid();
  v_moved uuid:=gen_random_uuid();
  v_moved2 uuid:=gen_random_uuid();
  v_moved3 uuid:=gen_random_uuid();
  v_original text:='verified pre-attack B content';
  v_hash text:=encode(sha256(convert_to('verified pre-attack B content','UTF8')),'hex');
  v_result record;
  v_audit_before int;
  v_failed bool;
BEGIN
 INSERT INTO public.notes(id,owner_id,title,content) VALUES
  (v_a,v_owner_a,'Original A','A untouched'),
  (v_other_b,v_owner_b,'Other B','Other B untouched');
 INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
  VALUES(v_a,v_owner_a,v_prior_run,repeat('a',64));

 -- 1. Correct trusted B tuple loses its owner and content, then is reclaimed.
 PERFORM * FROM public.create_test_note_with_backup(v_b,v_owner_b,v_run,'Safe B',v_original,v_hash);
 UPDATE public.notes SET owner_id=v_intruder,content='intruder body' WHERE id=v_b;
 IF (SELECT count(*) FROM public.test_b_mutation_lineage WHERE original_id=v_b AND current_id=v_b)<>1
 THEN RAISE EXCEPTION 'OWNER_ATTACK_NOT_TRACED'; END IF;
 SELECT * INTO v_result FROM public.restore_test_note_with_lineage(v_b,v_owner_b,v_run,v_hash);
 IF NOT FOUND OR v_result.audit_event_id IS NULL
 OR (SELECT n.owner_id FROM public.notes n WHERE n.id=v_b)<>v_owner_b
 OR (SELECT n.content FROM public.notes n WHERE n.id=v_b)<>v_original
 THEN RAISE EXCEPTION 'OWNER_RESTORE_FAILED';END IF;
 RAISE NOTICE 'PASS owner-change attack restores exact verified B row';

 -- 2. Correct trusted B tuple has its primary key moved. Do NOT INSERT
 -- a second note and leave a corrupted orphan.
 PERFORM * FROM public.create_test_note_with_backup(v_b2,v_owner_b,v_run,'Safe B2',v_original,v_hash);
 UPDATE public.notes SET id=v_moved,content='wrong moved body' WHERE id=v_b2;
 SELECT * INTO v_result FROM public.restore_test_note_with_lineage(v_b2,v_owner_b,v_run,v_hash);
 IF NOT FOUND OR v_result.audit_event_id IS NULL OR
   (SELECT count(*) FROM public.notes WHERE id IN (v_b2,v_moved))<>1 OR
   EXISTS (SELECT 1 FROM public.notes WHERE id=v_moved) OR
   (SELECT content FROM public.notes WHERE id=v_b2)<>v_original
 THEN RAISE EXCEPTION 'ID_RESTORE_LEFT_OTHER_ROW';END IF;
 RAISE NOTICE 'PASS primary-key change restores same tuple without orphan';

 -- 3. Chained move followed by owner change, still one row and audit.
 PERFORM * FROM public.create_test_note_with_backup(v_b3,v_owner_b,v_run,'Safe B3',v_original,v_hash);
 UPDATE public.notes SET id=v_moved2 WHERE id=v_b3;
 UPDATE public.notes SET owner_id=v_intruder,content='corrupt' WHERE id=v_moved2;
 SELECT * INTO v_result FROM public.restore_test_note_with_lineage(v_b3,v_owner_b,v_run,v_hash);
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.notes WHERE id=v_moved2)
  OR (SELECT owner_id FROM public.notes WHERE id=v_b3)<>v_owner_b
 THEN RAISE EXCEPTION 'CHAINED_MUTATION_NOT_RECOVERED';END IF;
 RAISE NOTICE 'PASS chained id and owner mutation restores exact B';

 -- 4. A foreign note replacing deleted B at same UUID has no mutation
 -- lineage and must NOT be overwritten.
 PERFORM * FROM public.create_test_note_with_backup(v_b4,v_owner_b,v_run,'Safe B4',v_original,v_hash);
 DELETE FROM public.notes WHERE id=v_b4;
 INSERT INTO public.notes(id,owner_id,title,content)
   VALUES(v_b4,v_owner_a,'Foreign owner','foreign private data');
 v_audit_before:=(SELECT count(*) FROM public.test_recovery_audit);
 v_failed:=false;
 BEGIN
   PERFORM * FROM public.restore_test_note_with_lineage(v_b4,v_owner_b,v_run,v_hash);
 EXCEPTION WHEN OTHERS THEN v_failed:=true; END;
 IF NOT v_failed OR (SELECT owner_id FROM public.notes WHERE id=v_b4)<>v_owner_a
 OR (SELECT content FROM public.notes WHERE id=v_b4)<>'foreign private data'
 OR (SELECT count(*) FROM public.test_recovery_audit)<>v_audit_before
 THEN RAISE EXCEPTION 'FOREIGN_NOTE_WAS_OVERWRITTEN';END IF;
 RAISE NOTICE 'PASS replacing foreign note refused without lineage';

 -- 5. ID mutation followed by collision at old ID must fail, leaving both
 -- exact existing rows and historical audit unchanged.
 PERFORM * FROM public.create_test_note_with_backup(v_b5,v_owner_b,v_run,'Safe B5',v_original,v_hash);
 UPDATE public.notes SET id=v_moved3 WHERE id=v_b5;
 INSERT INTO public.notes(id,owner_id,title,content)
   VALUES(v_b5,v_owner_a,'Foreign collision','foreign safe content');
 v_audit_before:=(SELECT count(*) FROM public.test_recovery_audit);
 v_failed:=false;
 BEGIN
   PERFORM * FROM public.restore_test_note_with_lineage(v_b5,v_owner_b,v_run,v_hash);
 EXCEPTION WHEN OTHERS THEN v_failed:=true; END;
 IF NOT v_failed OR (SELECT owner_id FROM public.notes WHERE id=v_b5)<>v_owner_a
 OR (SELECT content FROM public.notes WHERE id=v_b5)<>'foreign safe content'
 OR (SELECT count(*) FROM public.notes WHERE id=v_moved3)<>1
 OR (SELECT count(*) FROM public.test_recovery_audit)<>v_audit_before
 THEN RAISE EXCEPTION 'COLLISION_NOT_ROLLED_BACK';END IF;
 RAISE NOTICE 'PASS malicious ID collision rolled back, unrelated foreign row intact';

 -- 6. Normal content-only B changes and genuinely deleted note still restore.
 PERFORM * FROM public.create_test_note_with_backup(v_b6,v_owner_b,v_run,'Safe B6',v_original,v_hash);
 UPDATE public.notes SET content='damaged' WHERE id=v_b6;
 SELECT * INTO v_result FROM public.restore_test_note_with_lineage(v_b6,v_owner_b,v_run,v_hash);
 IF NOT FOUND OR v_result.content<>v_original THEN
 RAISE EXCEPTION 'ORDINARY_RESTORE_REGRESSION'; END IF;
 DELETE FROM public.notes WHERE id=v_b6;
 SELECT * INTO v_result FROM public.restore_test_note_with_lineage(v_b6,v_owner_b,v_run,v_hash);
 IF NOT FOUND OR v_result.content<>v_original THEN
 RAISE EXCEPTION 'DELETED_RESTORE_REGRESSION';END IF;

 IF (SELECT content FROM public.notes WHERE id=v_a)<>'A untouched'
 OR (SELECT content FROM public.notes WHERE id=v_other_b)<>'Other B untouched'
 OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id=v_a
         AND restored_sha256=repeat('a',64))<>1
 OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id IN (v_b,v_b2,v_b3,v_b6))<>5
 THEN RAISE EXCEPTION 'OTHER_NOTES_OR_EXISTING_AUDIT_CHANGED'; END IF;
 RAISE NOTICE 'PASS normal/deletion regression and existing audit/A/other B unchanged';
END $matrix$;
ROLLBACK;
SELECT 'PASS isolated owner/id lineage test and rollback' result;
