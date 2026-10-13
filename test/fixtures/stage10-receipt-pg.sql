-- Independent PostgreSQL 16 fixture, all synthetic. Entire test rolled back.
BEGIN;
CREATE OR REPLACE FUNCTION public.suppress_stage10_receipt() RETURNS trigger
LANGUAGE plpgsql AS $trigger$
BEGIN
 IF NEW.run_id='22222222-2222-4222-8222-222222222222'::uuid THEN RETURN NULL; END IF;
 RETURN NEW;
END $trigger$;
CREATE TRIGGER suppress_stage10_receipt BEFORE INSERT ON public.test_recovery_audit
 FOR EACH ROW EXECUTE FUNCTION public.suppress_stage10_receipt();
SET LOCAL ROLE service_role;
DO $test$
DECLARE
 a uuid:='33333333-3333-4333-8333-333333333333';
 b uuid:='44444444-4444-4444-8444-444444444444';
 b2 uuid:='55555555-5555-4555-8555-555555555555';
 owner_b uuid:='11111111-1111-4111-8111-111111111111';
 owner_a uuid:='99999999-9999-4999-8999-999999999999';
 run_b uuid:='22222222-2222-4222-8222-222222222222';
 run_a uuid:='88888888-8888-4888-8888-888888888888';
 hash_b text:=encode(sha256(convert_to('verified original B','UTF8')),'hex');
 failed boolean:=false;
BEGIN
 INSERT INTO public.notes (id,owner_id,title,content) VALUES
 (a,owner_a,'A preserved','A content unchanged'),
 (b2,owner_b,'other B preserved','other B content unchanged');
 INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
 VALUES(a,owner_a,run_a,repeat('a',64));
 PERFORM * FROM public.create_test_note_with_backup(b,owner_b,run_b,'B original','verified original B',hash_b);
 UPDATE public.notes SET title='hacked',content='tampered' WHERE id=b;
 BEGIN
  PERFORM * FROM public.restore_test_note_with_receipt(b,owner_b,run_b,hash_b);
 EXCEPTION WHEN OTHERS THEN
  IF SQLERRM='recovery_audit_persistence_failed' THEN failed:=true; ELSE RAISE; END IF;
 END;
 IF NOT failed THEN RAISE EXCEPTION 'Missing audit was accepted'; END IF;
 IF (SELECT content FROM public.notes WHERE id=b) <> 'tampered'
 OR (SELECT count(*) FROM public.test_recovery_audit)<>1
 OR (SELECT content FROM public.notes WHERE id=a)<>'A content unchanged'
 OR (SELECT content FROM public.notes WHERE id=b2)<>'other B content unchanged'
 THEN RAISE EXCEPTION 'Failed receipt changed data or old history'; END IF;
 RAISE NOTICE 'PASS missing audit receipt forced rollback with A, other B, history preserved';
END $test$;
RESET ROLE;
DROP TRIGGER suppress_stage10_receipt ON public.test_recovery_audit;
SET LOCAL ROLE service_role;
DO $test$
DECLARE
 a uuid:='33333333-3333-4333-8333-333333333333';
 b uuid:='44444444-4444-4444-8444-444444444444';
 b2 uuid:='55555555-5555-4555-8555-555555555555';
 owner_b uuid:='11111111-1111-4111-8111-111111111111';
 run_b uuid:='22222222-2222-4222-8222-222222222222';
 hash_b text:=encode(sha256(convert_to('verified original B','UTF8')),'hex');
 record_b record;
BEGIN
 SELECT * INTO record_b FROM public.restore_test_note_with_receipt(b,owner_b,run_b,hash_b);
 IF NOT FOUND OR record_b.audit_event_id IS NULL OR record_b.audit_event_id<1
  OR record_b.content<>'verified original B'
  OR (SELECT count(*) FROM public.test_recovery_audit WHERE event_id=record_b.audit_event_id
    AND note_id=b AND owner_id=owner_b AND run_id=run_b AND restored_sha256=hash_b)<>1
  OR (SELECT count(*) FROM public.test_recovery_audit)<>2
  OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id=a AND restored_sha256=repeat('a',64))<>1
  OR (SELECT content FROM public.notes WHERE id=a)<>'A content unchanged'
  OR (SELECT content FROM public.notes WHERE id=b2)<>'other B content unchanged'
 THEN RAISE EXCEPTION 'Atomic returned receipt or preservation mismatch'; END IF;
 RAISE NOTICE 'PASS returned receipt matches persisted audit; only B restored; old data intact';
END $test$;
ROLLBACK;
SELECT 'PASS standalone audit receipt proof, all test data rolled back' result;
