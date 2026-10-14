-- Stage 11 WebAuthn credential enrollment. Additive: never delete notes, audits,
-- existing registrations, or prior migrations. Only service-role can access.
alter table public.device_registrations
  add column if not exists credential_id text,
  add column if not exists sign_count bigint not null default 0;
create unique index if not exists device_registrations_credential_id_unique
  on public.device_registrations (credential_id) where credential_id is not null;
create table if not exists public.device_challenges (
  challenge text primary key,
  user_id uuid not null,
  token_digest text not null check (token_digest ~ '^[a-f0-9]{64}$'),
  purpose text not null check (purpose in ('register','assert')),
  request_method text not null default '',
  request_path text not null default '',
  body_digest text not null default '',
  issued_at timestamptz not null default now()
);
alter table public.device_challenges enable row level security;
revoke all on public.device_challenges from public, anon, authenticated;
grant select, insert, delete on public.device_challenges to service_role;
create index if not exists device_challenges_issued_idx on public.device_challenges(issued_at);
