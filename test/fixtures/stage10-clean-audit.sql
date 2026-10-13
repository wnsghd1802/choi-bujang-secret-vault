BEGIN;
CREATE OR REPLACE FUNCTION public.suppress_stage10_audit() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.run_id='22222222-2222-4222-8222-222222222222'::uuid THEN RETURN NULL;END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER suppress_audit BEFORE INSERT ON public.test_recovery_audit
 FOR EACH ROW EXECUTE FUNCTION public.suppress_stage10_audit();

SET LOCAL ROLE service_role;
DO $fail$
DECLARE
 target uuid := '44444444-4444-4444-8444-444444444444';
 a uuid := '33333333-3333-4333-8333-333333333333';
 b2 uuid := '55555555-5555-4555-8555-555555555555';
 ownerb uuid := '11111111-1111-4111-8111-111111111111';
 ownera uuid := '99999999-9999-4999-8999-999999999999';
 runb uuid := '22222222-2222-4222-8222-222222222222';
 other_run uuid := '88888888-8888-4888-8888-888888888888';
 original text := 'clean standalone tested original';
 digest text := encode(sha256(convert_to('clean standalone tested original','UTF8')),'hex');
 blocked boolean:=false;
BEGIN
 INSERT INTO public.notes(id,owner_id,title,content) VALUES
   (a,ownera,'Synthetic A','A remains unchanged'),
   (b2,ownerb,'Unrelated B','Other B unchanged');
 INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
   VALUES(a,ownera,other_run,repeat('a',64));
 PERFORM * FROM public.create_test_note_with_backup(target,ownerb,runb,'Trusted B',original,digest);
 UPDATE public.notes SET content='attacked and corrupted' WHERE id=target;
 BEGIN
    PERFORM * FROM public.restore_test_note_from_backup(target,ownerb,runb,digest);
 EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='recovery_audit_persistence_failed' THEN blocked:=true;
    ELSE RAISE; END IF;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'missing audit erroneously committed'; END IF;
 IF (SELECT content FROM public.notes WHERE id=target)<>'attacked and corrupted'
  OR (SELECT content FROM public.notes WHERE id=a)<>'A remains unchanged'
  OR (SELECT content FROM public.notes WHERE id=b2)<>'Other B unchanged'
  OR (SELECT count(*) FROM public.test_recovery_audit)<>1
  OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id=a AND restored_sha256=repeat('a',64))<>1
 THEN RAISE EXCEPTION 'audit failure did not rollback or changed other records'; END IF;
 RAISE NOTICE 'PASS audit insertion suppressed: B restore rolled back; A, other B and audit preserved';
END $fail$;
RESET ROLE;
DROP TRIGGER suppress_audit ON public.test_recovery_audit;
SET LOCAL ROLE service_role;
DO $good$
DECLARE
 target uuid := '44444444-4444-4444-8444-444444444444';
 a uuid := '33333333-3333-4333-8333-333333333333';
 b2 uuid := '55555555-5555-4555-8555-555555555555';
 ownerb uuid := '11111111-1111-4111-8111-111111111111';
 runb uuid := '22222222-2222-4222-8222-222222222222';
 digest text := encode(sha256(convert_to('clean standalone tested original','UTF8')),'hex');
 restored record;
BEGIN
 SELECT * INTO restored FROM public.restore_test_note_from_backup(target,ownerb,runb,digest);
 IF NOT FOUND OR restored.content<>'clean standalone tested original'
  OR (SELECT content FROM public.notes WHERE id=a)<>'A remains unchanged'
  OR (SELECT content FROM public.notes WHERE id=b2)<>'Other B unchanged'
  OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id=a AND restored_sha256=repeat('a',64))<>1
  OR (SELECT count(*) FROM public.test_recovery_audit WHERE note_id=target AND restored_sha256=digest)<>1
  OR (SELECT count(*) FROM public.test_recovery_audit)<>2 THEN
    RAISE EXCEPTION 'normal restore affected other note or audit';END IF;
 RAISE NOTICE 'PASS one B restored; A + other B untouched; one new audit; old audit preserved';
END $good$;
ROLLBACK;
SELECT 'PASS: independent SQL transaction verified' AS outcome;
