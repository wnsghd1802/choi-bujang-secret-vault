-- Stage10: do not let the app service role forge trusted B-row lineage.
-- The authorized notes trigger (SECURITY DEFINER, table-owner context) may
-- record real id/owner moves. Recovery RPC still needs SELECT ... FOR UPDATE,
-- which requires UPDATE privilege, so reject direct DML in a BEFORE trigger.
-- Does not edit any notes, backups, audit events, or prior service policies.
BEGIN;
REVOKE INSERT, DELETE, TRUNCATE ON public.test_b_mutation_lineage
  FROM service_role, anon, authenticated, PUBLIC;
GRANT SELECT, UPDATE ON public.test_b_mutation_lineage TO service_role;

CREATE OR REPLACE FUNCTION public.stage10_lineage_update_gate()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $guard$
BEGIN
  -- A trigger firing within the trusted SECURITY DEFINER lineage writer runs
  -- as the table owner. Client-issued service_role UPDATE does not.
  IF current_user <> pg_get_userbyid(
    (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID)
  ) THEN
    RAISE EXCEPTION 'stage10_lineage_direct_update_denied'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$guard$;
REVOKE ALL ON FUNCTION public.stage10_lineage_update_gate()
  FROM PUBLIC, anon, authenticated, service_role;

DROP TRIGGER IF EXISTS stage10_lineage_update_gate ON public.test_b_mutation_lineage;
CREATE TRIGGER stage10_lineage_update_gate
  BEFORE UPDATE ON public.test_b_mutation_lineage
  FOR EACH ROW EXECUTE FUNCTION public.stage10_lineage_update_gate();
COMMIT;
