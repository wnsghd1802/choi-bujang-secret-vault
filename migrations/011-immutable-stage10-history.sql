-- Stage 10: preserve verified private backups and recovery audit evidence.
-- Additive for existing stage-10 databases. Does not touch notes.
BEGIN;
CREATE OR REPLACE FUNCTION public.stage10_reject_history_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = public, pg_temp AS $body$
BEGIN
  RAISE EXCEPTION 'stage10_immutable_history' USING ERRCODE = '55000';
END;
$body$;
REVOKE ALL ON FUNCTION public.stage10_reject_history_mutation() FROM PUBLIC, anon, authenticated;
DROP TRIGGER IF EXISTS stage10_private_backup_immutable ON public.test_note_backups;
CREATE TRIGGER stage10_private_backup_immutable BEFORE UPDATE OR DELETE ON public.test_note_backups
FOR EACH ROW EXECUTE FUNCTION public.stage10_reject_history_mutation();
DROP TRIGGER IF EXISTS stage10_recovery_audit_immutable ON public.test_recovery_audit;
CREATE TRIGGER stage10_recovery_audit_immutable BEFORE UPDATE OR DELETE ON public.test_recovery_audit
FOR EACH ROW EXECUTE FUNCTION public.stage10_reject_history_mutation();
COMMIT;
SELECT c.relname AS table_name,t.tgname AS trigger_name,t.tgenabled AS enabled
FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname IN ('test_note_backups','test_recovery_audit')
AND t.tgname IN ('stage10_private_backup_immutable','stage10_recovery_audit_immutable')
ORDER BY c.relname;
