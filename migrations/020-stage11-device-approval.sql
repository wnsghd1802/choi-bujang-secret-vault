-- Stage 11 device enrollment: no changes to existing notes or audit data.
create table if not exists public.device_registrations (
  user_id uuid not null,
  device_id varchar(16) not null check (device_id ~ '^[a-f0-9]{16}$'),
  public_key jsonb not null check (jsonb_typeof(public_key) = 'object'),
  state text not null default 'pending' check (state in ('pending','approved','revoked')),
  requested_at timestamptz not null default now(),
  approved_at timestamptz,
  primary key (user_id, device_id)
);
alter table public.device_registrations enable row level security;
revoke all on public.device_registrations from anon, authenticated, public;
grant select, insert, update on public.device_registrations to service_role;

create table if not exists public.device_proof_nonces (
  user_id uuid not null,
  device_id varchar(16) not null,
  nonce varchar(32) not null check (nonce ~ '^[a-f0-9]{32}$'),
  used_at timestamptz not null default now(),
  primary key (user_id, device_id, nonce),
  foreign key (user_id, device_id) references public.device_registrations(user_id, device_id)
    on delete cascade
);
create index if not exists device_proof_nonces_used_at_idx on public.device_proof_nonces(used_at);
alter table public.device_proof_nonces enable row level security;
revoke all on public.device_proof_nonces from anon, authenticated, public;
grant insert on public.device_proof_nonces to service_role;

-- Pending requests may only be approved out of band by a trusted operator.
-- No public SQL/RPC route may update the registration state.
