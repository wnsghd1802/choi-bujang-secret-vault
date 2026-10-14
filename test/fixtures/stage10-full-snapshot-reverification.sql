-- Regression: creation-time complete seal, successful B restore and audit.
-- Synthetic IDs and data only; all rows are rolled back.
BEGIN;
SET LOCAL ROLE service_role;
DO $good$
DECLARE
  v_b uuid:=gen_random_uuid(); v_owner uuid:=gen_random_uuid();
  v_run uuid:=gen_random_uuid();
  v_hash text:=encode(sha256(convert_to('stable body','UTF8')),'hex');
  v_done record;
BEGIN
  PERFORM * FROM public.create_test_note_with_backup(
    v_b,v_owner,v_run,'Original title','stable body',v_hash);
  IF NOT EXISTS (SELECT 1 FROM public.test_note_backups b
    WHERE b.id=v_b AND b.snapshot_sha256=public.stage10_full_snapshot_digest(
      b.id,b.owner_id,b.run_id,b.identity,b.title,b.content))
    THEN RAISE EXCEPTION 'FULL_BACKUP_SEAL_ABSENT'; END IF;
  UPDATE public.notes SET title='attacked title',content='tampered' WHERE id=v_b;
  SELECT * INTO v_done FROM public.restore_test_note_with_lineage(
     v_b,v_owner,v_run,v_hash);
  IF NOT FOUND OR v_done.title<>'Original title' OR v_done.audit_event_id IS NULL
     THEN RAISE EXCEPTION 'NORMAL_SEALED_RESTORE_FAILED'; END IF;
END $good$;
ROLLBACK;
SELECT 'PASS full-snapshot verified restore and audit' AS result;

-- Reproduce an adversary changing ONLY the saved title, not the content hash.
-- A test superuser temporarily bypasses the append-only trigger, simulating
-- corruption. The new immutable original seal remains unchanged.
BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO public.notes(id,owner_id,title,content)
 VALUES ('93b94209-d102-4484-a08f-158f17129b81'::uuid,
         '7fc8f281-7557-4d54-bf03-3454e1393e81'::uuid,'B title','safe body');
INSERT INTO public.test_note_backups
 (id,owner_id,run_id,identity,title,content,content_sha256)
 VALUES('93b94209-d102-4484-a08f-158f17129b81'::uuid,
        '7fc8f281-7557-4d54-bf03-3454e1393e81'::uuid,
        '8b131956-36fd-4f20-8a94-6df00e93b416'::uuid,
        'b','B title','safe body',
        encode(sha256(convert_to('safe body','UTF8')),'hex'));
RESET ROLE;
ALTER TABLE public.test_note_backups DISABLE TRIGGER stage10_private_backup_immutable;
UPDATE public.test_note_backups SET title='FORGED title'
 WHERE id='93b94209-d102-4484-a08f-158f17129b81'::uuid;
ALTER TABLE public.test_note_backups ENABLE TRIGGER stage10_private_backup_immutable;
SET LOCAL ROLE service_role;
DO $bad$
DECLARE
  v_id uuid:='93b94209-d102-4484-a08f-158f17129b81'::uuid;
  v_owner uuid:='7fc8f281-7557-4d54-bf03-3454e1393e81'::uuid;
  v_run uuid:='8b131956-36fd-4f20-8a94-6df00e93b416'::uuid;
  v_failed boolean:=false;
  v_prior integer:=(SELECT count(*) FROM public.test_recovery_audit);
BEGIN
  BEGIN
    PERFORM * FROM public.restore_test_note_with_lineage(
      v_id,v_owner,v_run,encode(sha256(convert_to('safe body','UTF8')),'hex'));
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='backup_full_snapshot_unverified' THEN v_failed:=true;
    ELSE RAISE; END IF;
  END;
  IF NOT v_failed OR (SELECT title FROM public.notes WHERE id=v_id)<>'B title'
    OR (SELECT count(*) FROM public.test_recovery_audit)<>v_prior
    THEN RAISE EXCEPTION 'FORGED_TITLE_RESTORED_OR_AUDITED'; END IF;
END $bad$;
ROLLBACK;
SELECT 'PASS forged snapshot title blocked before any note or audit write' AS result;
