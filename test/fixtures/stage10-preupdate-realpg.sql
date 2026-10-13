-- Postgres 16: all data synthetic. Never run against production.
BEGIN;
SET LOCAL ROLE service_role;
DO $test$
DECLARE
 a uuid:='33333333-3333-4333-8333-333333333333';
 b uuid:='44444444-4444-4444-8444-444444444444';
 b2 uuid:='55555555-5555-4555-8555-555555555555';
 bowner uuid:='11111111-1111-4111-8111-111111111111';
 aowner uuid:='99999999-9999-4999-8999-999999999999';
 run uuid:='22222222-2222-4222-8222-222222222222';
 olderun uuid:='88888888-8888-4888-8888-888888888888';
 restored record;
 original text:='Trusted before first PUT';
 original_hash text:=encode(sha256(convert_to('Trusted before first PUT','UTF8')),'hex');
BEGIN
 INSERT INTO public.notes(id,owner_id,title,content) VALUES
  (a,aowner,'A safe','Keep A content'),
  (b,bowner,'B safe','Trusted before first PUT'),
  (b2,bowner,'Other B','Keep other B content');
 INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
  VALUES(a,aowner,olderun,repeat('a',64));
 PERFORM * FROM public.update_test_note_with_backup(b,bowner,run,'B attacked','first PUT corruption');
 IF (SELECT content FROM public.notes WHERE id=b)<>'first PUT corruption'
 OR (SELECT content FROM public.test_note_backups WHERE id=b)<>original
 OR (SELECT content_sha256 FROM public.test_note_backups WHERE id=b)<>original_hash
 OR (SELECT count(*) FROM public.test_recovery_audit)<>1
 THEN RAISE EXCEPTION 'FIRST_PUT_SNAPSHOT_FAILED';END IF;
 PERFORM * FROM public.update_test_note_with_backup(b,bowner,run,'B attacked again','second PUT corruption');
 IF (SELECT content FROM public.notes WHERE id=b)<>'second PUT corruption'
 OR (SELECT content FROM public.test_note_backups WHERE id=b)<>original
 THEN RAISE EXCEPTION 'SAFE_BACKUP_OVERWRITTEN';END IF;
 BEGIN
  PERFORM * FROM public.update_test_note_with_backup(b,bowner,olderun,'B overwrite','forbidden');
  RAISE EXCEPTION 'RUN_MISMATCH_NOT_REJECTED';
 EXCEPTION WHEN OTHERS THEN
  IF SQLERRM<>'existing_test_backup_mismatch' THEN RAISE;END IF;
 END;
 IF (SELECT content FROM public.notes WHERE id=b)<>'second PUT corruption'
  THEN RAISE EXCEPTION 'RUN_MISMATCH_CHANGED_NOTE';END IF;
 SELECT * INTO restored FROM public.restore_test_note_from_backup(b,bowner,run,original_hash);
 IF NOT FOUND OR restored.content<>original OR restored.title<>'B safe' THEN
  RAISE EXCEPTION 'RESTORE_ORIGINAL_FAILED';END IF;
 IF (SELECT content FROM public.notes WHERE id=a)<>'Keep A content'
 OR (SELECT content FROM public.notes WHERE id=b2)<>'Keep other B content'
 OR (SELECT count(*) FROM public.test_recovery_audit)<>2
 OR (SELECT count(*) FROM public.test_recovery_audit
     WHERE note_id=a AND restored_sha256=repeat('a',64))<>1
 OR (SELECT count(*) FROM public.test_recovery_audit
     WHERE note_id=b AND restored_sha256=original_hash)<>1
 THEN RAISE EXCEPTION 'OTHER_RECORDS_OR_AUDIT_CHANGED';END IF;
 RAISE NOTICE 'PASS: initial B PUT snapshots old value; repeat PUT keeps original; only B restored; prior audit/A/B2 unchanged';
END $test$;
ROLLBACK;
