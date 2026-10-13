-- Stage10: protect an already-existing synthetic judge-B note on its FIRST
-- verified, owner-scoped, API-mediated PUT. This is NOT a replacement for a
-- genuinely verified backup taken before any unrelated/direct DB attack.
-- No existing student notes or recovery audits are mutated by this migration.
begin;
create or replace function public.update_test_note_with_backup(
  p_id uuid,p_owner_id uuid,p_run_id uuid,p_title text,p_content text
) returns table(id uuid,title text,content text)
language plpgsql security invoker set search_path=public,pg_temp as $body$
declare
 old_note public.notes%rowtype;
 safe_copy public.test_note_backups%rowtype;
 v_updated public.notes%rowtype;
begin
 if p_id is null or p_owner_id is null or p_run_id is null
    or p_title is null or length(p_title) not between 1 and 120
    or p_content is null or length(p_content)>10000
 then raise exception 'invalid_test_note_update';end if;

 -- Exact one note, exact verified owner, locked before any state mutation.
 select n.* into old_note from public.notes n
   where n.id=p_id and n.owner_id=p_owner_id for update;
 if not found then return; end if;

 select b.* into safe_copy from public.test_note_backups b where b.id=p_id;
 if found then
   -- Never rebind a known safe copy to a different run, owner or note.
   if safe_copy.owner_id is distinct from p_owner_id
      or safe_copy.run_id is distinct from p_run_id
      or safe_copy.identity is distinct from 'b'
      or safe_copy.content_sha256 is distinct from
         encode(sha256(convert_to(safe_copy.content,'UTF8')),'hex')
   then raise exception 'existing_test_backup_mismatch';end if;
 else
   -- The old value is captured before the first API-mediated mutation.
   -- It must NOT be rewritten on subsequent PUTs or DELETEs.
   insert into public.test_note_backups
      (id,owner_id,run_id,identity,title,content,content_sha256)
   values(old_note.id,old_note.owner_id,p_run_id,'b',old_note.title,
          old_note.content,encode(sha256(convert_to(old_note.content,'UTF8')),'hex'));
 end if;

 update public.notes n set title=p_title,content=p_content
  where n.id=p_id and n.owner_id=p_owner_id
  returning n.* into v_updated;
 if not found then raise exception 'test_note_update_not_found';end if;
 return query select v_updated.id,v_updated.title,v_updated.content;
end;
$body$;
revoke all on function public.update_test_note_with_backup(
 uuid,uuid,uuid,text,text) from public,anon,authenticated;
grant execute on function public.update_test_note_with_backup(
 uuid,uuid,uuid,text,text) to service_role;
commit;
