-- Run in a standalone PostgreSQL 16 service, NEVER against user data.
BEGIN;
-- Fixture creates an intentionally bad audit trigger that silently suppresses
-- insertion for a chosen B recovery run, simulating audit loss.
CREATE FUNCTION public.isolated_suppress_audit()
RETURNS trigger LANGUAGE plpgsql AS $impl$
BEGIN
  IF NEW.run_id = '22222222-2222-4222-8222-222222222222'::uuid THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END $impl$;
CREATE TRIGGER isolated_suppress_audit
  BEFORE INSERT ON public.test_recovery_audit
  FOR EACH ROW EXECUTE FUNCTION public.isolated_suppress_audit();

-- Proven after migrations: server can retrieve its own audit receipt, but
-- users cannot browse the private audit. No artificial grants in this fixture.
DO $grant_test$
BEGIN
  IF NOT has_table_privilege('service_role','public.test_recovery_audit','SELECT')
      OR has_table_privilege('anon','public.test_recovery_audit','SELECT')
      OR has_table_privilege('authenticated','public.test_recovery_audit','SELECT')
  THEN RAISE EXCEPTION 'audit_grant_mismatch'; END IF;
END $grant_test$;
SET LOCAL ROLE service_role;
DO $test$
DECLARE
  bid uuid := '44444444-4444-4444-8444-444444444444';
  aid uuid := '33333333-3333-4333-8333-333333333333';
  ownerb uuid := '11111111-1111-4111-8111-111111111111';
  ownera uuid := '99999999-9999-4999-8999-999999999999';
  runb uuid := '22222222-2222-4222-8222-222222222222';
  runa uuid := '88888888-8888-4888-8888-888888888888';
  original text := 'isolated real PostgreSQL safe B before attack';
  bodyhash text := encode(sha256(convert_to('isolated real PostgreSQL safe B before attack','UTF8')),'hex');
  raised boolean := false;
  restored record;
BEGIN
  INSERT INTO public.notes(id,owner_id,title,content)
    VALUES(aid,ownera,'A synthetic','A untouched');
  INSERT INTO public.test_recovery_audit(note_id,owner_id,run_id,restored_sha256)
    VALUES(aid,ownera,runa,repeat('a',64));
  PERFORM * FROM public.create_test_note_with_backup(bid,ownerb,runb,'B safe',original,bodyhash);
  UPDATE public.notes SET content='ATTACKER_CONTENT',title='attacker' WHERE id=bid;
  BEGIN
    PERFORM * FROM public.restore_test_note_from_backup(bid,ownerb,runb,bodyhash);
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='recovery_audit_persistence_failed' THEN raised:=true;
    ELSE RAISE; END IF;
  END;
  IF NOT raised THEN RAISE EXCEPTION 'AUDIT_SUPPRESSION_NOT_REJECTED'; END IF;
  IF (SELECT content FROM public.notes WHERE id=bid)<>'ATTACKER_CONTENT'
    THEN RAISE EXCEPTION 'RESTORE_NOT_ROLLED_BACK_AFTER_AUDIT_FAILURE'; END IF;
  IF (SELECT count(*) FROM public.test_recovery_audit)<>1 THEN
    RAISE EXCEPTION 'AUDIT_HISTORY_MUTATED_AFTER_FAILURE'; END IF;
  IF (SELECT content FROM public.notes WHERE id=aid)<>'A untouched'
    THEN RAISE EXCEPTION 'A_NOTE_MUTATED_AFTER_FAILURE'; END IF;
  RAISE NOTICE 'PASS: suppressed audit rejected and the B restore rolled back atomically';
END $test$;
RESET ROLE;
DROP TRIGGER isolated_suppress_audit ON public.test_recovery_audit;

SET LOCAL ROLE service_role;
DO $success$
DECLARE
  bid uuid := '44444444-4444-4444-8444-444444444444';
  aid uuid := '33333333-3333-4333-8333-333333333333';
  ownerb uuid := '11111111-1111-4111-8111-111111111111';
  runb uuid := '22222222-2222-4222-8222-222222222222';
  h text := encode(sha256(convert_to('isolated real PostgreSQL safe B before attack','UTF8')),'hex');
  restored record;
BEGIN
  SELECT * INTO restored FROM public.restore_test_note_from_backup(bid,ownerb,runb,h);
  IF NOT FOUND OR restored.content <> 'isolated real PostgreSQL safe B before attack'
    THEN RAISE EXCEPTION 'NORMAL_RESTORE_FAILED'; END IF;
  IF (SELECT count(*) FROM public.test_recovery_audit)<>2 THEN
    RAISE EXCEPTION 'NORMAL_RESTORE_AUDIT_MISSING';END IF;
  IF (SELECT content FROM public.notes WHERE id=aid)<>'A untouched' THEN
    RAISE EXCEPTION 'OTHER_NOTE_CHANGED';END IF;
  RAISE NOTICE 'PASS: normal B restore commits one audit while preserving A and historical audit';
END $success$;
ROLLBACK;
SELECT 'PASS isolated SQL audit rollback and success checks' AS outcome;
