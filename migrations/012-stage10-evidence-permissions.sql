-- Stage 10 follow-up: close the remaining mutation privileges on test-only
-- pre-attack snapshots and append-only recovery audit evidence.
-- Apply AFTER migrations/011-immutable-stage10-history.sql.
-- No DML (INSERT/UPDATE/DELETE) is run on notes or any existing data.
-- Supabase applies migrations transactionally; safe to retry.

-- Previously service_role inherited default UPDATE/DELETE/TRUNCATE grants.
-- Creation and restoration need only SELECT/INSERT on these two tables.
revoke update, delete, truncate on
  public.test_note_backups, public.test_recovery_audit
from service_role, anon, authenticated, public;

-- The 011 row triggers deny UPDATE/DELETE. Add statement triggers
-- to deny TRUNCATE even for privileged callers with elevated table grants.
drop trigger if exists stage10_private_backup_no_truncate on public.test_note_backups;
create trigger stage10_private_backup_no_truncate
  before truncate on public.test_note_backups
  for each statement execute function public.stage10_reject_history_mutation();

drop trigger if exists stage10_recovery_audit_no_truncate on public.test_recovery_audit;
create trigger stage10_recovery_audit_no_truncate
  before truncate on public.test_recovery_audit
  for each statement execute function public.stage10_reject_history_mutation();
