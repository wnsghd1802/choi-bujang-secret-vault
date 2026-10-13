-- Stage10 lineage authorization regression. All records synthetic;
-- test writes and audit insert are rolled back after checking.
BEGIN;
SET LOCAL ROLE service_role;
DO $verify$
DECLARE
  b uuid:=gen_random_uuid();
  a uuid:=gen_random_uuid();
  moved uuid:=gen_random_uuid();
  moved2 uuid:=gen_random_uuid();
  owner_b uuid:=gen_random_uuid();
  owner_a uuid:=gen_random_uuid();
  intruder uuid:=gen_random_uuid();
  v_run uuid:=gen_random_uuid();
  digest text:=encode(sha256(convert_to('verified original','UTF8')),'hex');
  old_audit bigint;
  restored record;
  denied bool;
BEGIN
  INSERT INTO public.notes(id,owner_id,title,content)
    VALUES(a,owner_a,'synthetic A','unchanged A');
  INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
    VALUES(a,owner_a,v_run,repeat('f',64)) RETURNING event_id INTO old_audit;
  PERFORM * FROM public.create_test_note_with_backup(
    b,owner_b,v_run,'synthetic B','verified original',digest
  );

  denied:=false;
  BEGIN
    INSERT INTO public.test_b_mutation_lineage(original_id,current_id,owner_id,run_id)
      VALUES(b,a,owner_b,v_run);
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'S10_FORGED_LINEAGE_INSERT_ALLOWED'; END IF;

  UPDATE public.notes SET id=moved,owner_id=intruder,content='attacked' WHERE id=b;
  IF NOT EXISTS(SELECT 1 FROM public.test_b_mutation_lineage
                WHERE original_id=b AND current_id=moved)
  THEN RAISE EXCEPTION 'S10_TRUSTED_LINEAGE_TRIGGER_FAILED'; END IF;

  denied:=false;
  BEGIN
    UPDATE public.test_b_mutation_lineage SET current_id=a WHERE original_id=b;
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'S10_FORGED_LINEAGE_UPDATE_ALLOWED'; END IF;
  denied:=false;
  BEGIN
    DELETE FROM public.test_b_mutation_lineage WHERE original_id=b;
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'S10_FORGED_LINEAGE_DELETE_ALLOWED'; END IF;
  denied:=false;
  BEGIN
    EXECUTE 'TRUNCATE public.test_b_mutation_lineage';
  EXCEPTION WHEN insufficient_privilege THEN denied:=true;
  END;
  IF NOT denied THEN RAISE EXCEPTION 'S10_LINEAGE_TRUNCATE_ALLOWED'; END IF;

  -- Legitimate chained moves still work even when service_role cannot
  -- directly modify lineage. SELECT FOR UPDATE remains possible.
  UPDATE public.notes SET id=moved2 WHERE id=moved;
  IF NOT EXISTS(SELECT 1 FROM public.test_b_mutation_lineage
                WHERE original_id=b AND current_id=moved2)
  THEN RAISE EXCEPTION 'S10_TRUSTED_CHAINED_MOVE_FAILED'; END IF;
  SELECT * INTO restored
    FROM public.restore_test_note_with_lineage(b,owner_b,v_run,digest);
  IF NOT FOUND OR restored.audit_event_id IS NULL
    OR restored.content<>'verified original'
    OR EXISTS(SELECT 1 FROM public.notes WHERE id=moved2)
    OR (SELECT content FROM public.notes WHERE id=a)<>'unchanged A'
    OR (SELECT count(*) FROM public.test_recovery_audit
        WHERE event_id=old_audit AND note_id=a
          AND restored_sha256=repeat('f',64))<>1
    OR (SELECT count(*) FROM public.test_recovery_audit
        WHERE note_id=b AND run_id=v_run AND restored_sha256=digest)<>1
  THEN RAISE EXCEPTION 'S10_AUTHORIZATION_OR_AUDIT_REGRESSION'; END IF;
END $verify$;
ROLLBACK;
SELECT 'PASS Stage10 immutable lineage permissions + trusted trigger + audit' AS result;
