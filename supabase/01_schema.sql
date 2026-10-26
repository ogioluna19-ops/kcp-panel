-- =====================================================================
--  KCP TV · Panel de activación de dispositivos  ·  Esquema Supabase
--  Pégalo completo en  SQL Editor ▸ New query ▸ Run  (se puede repetir sin problema)
-- =====================================================================

-- ---------- Tablas ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text,
  role        text not null default 'reseller' check (role in ('admin','reseller')),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.accounts (          -- cuentas Xtream
  id          uuid primary key default gen_random_uuid(),
  owner       uuid not null default auth.uid() references public.profiles(id),
  name        text not null,
  url         text not null,
  username    text not null,
  password    text not null,
  max_devices int  not null default 1 check (max_devices >= 1),
  notes       text,
  created_at  timestamptz not null default now()
);

create table if not exists public.devices (           -- dispositivos activados
  id              uuid primary key default gen_random_uuid(),
  owner           uuid not null default auth.uid() references public.profiles(id),
  device_code     text not null unique
                  check (device_code = upper(device_code) and device_code ~ '^[A-Z0-9-]{6,40}$'),
  mac             text,
  label           text,
  account_id      uuid references public.accounts(id) on delete set null,
  status          text not null default 'pending' check (status in ('pending','active','blocked')),
  expires_at      timestamptz,
  device_key_hash text,            -- hash de la llave secreta que se entrega al dispositivo al activarse
  claimed_at      timestamptz,
  last_seen       timestamptz,
  app_version     text,
  created_at      timestamptz not null default now()
);
create index if not exists devices_owner_idx   on public.devices(owner);
create index if not exists devices_account_idx on public.devices(account_id);
create index if not exists accounts_owner_idx  on public.accounts(owner);

create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default now(),
  actor      uuid,
  action     text not null,
  device_id  uuid,
  detail     jsonb
);

-- ---------- Funciones auxiliares ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and active)
$$;

create or replace function public.is_active_user() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active)
$$;

-- Alta automática del perfil cuando creas un usuario en Authentication
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email) on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Límite de dispositivos activos por cuenta Xtream
create or replace function public.devices_limit() returns trigger
language plpgsql security definer set search_path = public as $$
declare mx int; cnt int;
begin
  if tg_op = 'UPDATE' and old.status = new.status and old.account_id is not distinct from new.account_id then
    return new;
  end if;
  if new.status = 'active' and new.account_id is not null then
    select max_devices into mx from public.accounts where id = new.account_id;
    select count(*) into cnt from public.devices
      where account_id = new.account_id and status = 'active' and id <> new.id;
    if mx is not null and cnt >= mx then
      raise exception 'Esa cuenta ya alcanzó su límite de % dispositivo(s) activos', mx;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists devices_limit_trg on public.devices;
create trigger devices_limit_trg before insert or update on public.devices
  for each row execute function public.devices_limit();

-- Bitácora de cambios importantes (ignora las simples actualizaciones de "última conexión")
create or replace function public.devices_audit() returns trigger
language plpgsql security definer set search_path = public as $$
declare act text;
begin
  if tg_op = 'INSERT' then
    insert into public.audit_log(actor, action, device_id, detail)
      values (auth.uid(), 'crear', new.id, jsonb_build_object('code', new.device_code, 'status', new.status));
    return new;
  elsif tg_op = 'DELETE' then
    insert into public.audit_log(actor, action, device_id, detail)
      values (auth.uid(), 'eliminar', old.id, jsonb_build_object('code', old.device_code));
    return old;
  end if;
  if old.status is not distinct from new.status
     and old.account_id is not distinct from new.account_id
     and old.expires_at is not distinct from new.expires_at
     and old.device_key_hash is not distinct from new.device_key_hash then
    return new;
  end if;
  act := case
    when old.status <> new.status then 'estado: ' || new.status
    when old.device_key_hash is not null and new.device_key_hash is null then 'reiniciar clave'
    when old.device_key_hash is null and new.device_key_hash is not null then 'dispositivo reclamado'
    else 'editar' end;
  insert into public.audit_log(actor, action, device_id, detail)
    values (auth.uid(), act, new.id, jsonb_build_object('code', new.device_code, 'status', new.status));
  return new;
end $$;
drop trigger if exists devices_audit_trg on public.devices;
create trigger devices_audit_trg after insert or update or delete on public.devices
  for each row execute function public.devices_audit();

-- ---------- Seguridad por filas (RLS) ----------
alter table public.profiles  enable row level security;
alter table public.accounts  enable row level security;
alter table public.devices   enable row level security;
alter table public.audit_log enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists accounts_all on public.accounts;
create policy accounts_all on public.accounts for all to authenticated
  using      (public.is_admin() or (owner = auth.uid() and public.is_active_user()))
  with check (public.is_admin() or (owner = auth.uid() and public.is_active_user()));

-- Un dispositivo solo puede usar cuentas que el usuario puede ver (las suyas; el admin, todas)
drop policy if exists devices_all on public.devices;
create policy devices_all on public.devices for all to authenticated
  using (public.is_admin() or (owner = auth.uid() and public.is_active_user()))
  with check (
    (public.is_admin() or (owner = auth.uid() and public.is_active_user()))
    and (account_id is null or exists (select 1 from public.accounts a where a.id = account_id))
  );

drop policy if exists audit_select on public.audit_log;
create policy audit_select on public.audit_log for select to authenticated
  using (public.is_admin() or actor = auth.uid());

-- Permisos: el usuario anónimo (la app) NO toca tablas; solo llama a device_check()
revoke all on public.profiles, public.accounts, public.devices, public.audit_log from anon;
revoke all on public.profiles, public.accounts, public.devices, public.audit_log from authenticated;
grant select, update                 on public.profiles  to authenticated;
grant select, insert, update, delete on public.accounts  to authenticated;
grant select, insert, update, delete on public.devices   to authenticated;
grant select                         on public.audit_log to authenticated;

-- ---------- Lo que usa la app ----------
-- device_check: la app envía su código (y su llave, una vez activada). Responde estado y, si procede, la cuenta.
create or replace function public.device_check(
  p_device_code text, p_device_key text default null, p_app_version text default null
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare d public.devices%rowtype; a public.accounts%rowtype; new_key text;
begin
  select * into d from public.devices where device_code = upper(trim(p_device_code));
  if not found then return jsonb_build_object('status', 'unknown'); end if;

  update public.devices set last_seen = now(), app_version = coalesce(p_app_version, app_version) where id = d.id;

  if d.status = 'blocked' then return jsonb_build_object('status', 'blocked'); end if;
  if d.status <> 'active' or d.account_id is null then return jsonb_build_object('status', 'pending'); end if;
  if d.expires_at is not null and d.expires_at < now() then return jsonb_build_object('status', 'expired'); end if;

  select * into a from public.accounts where id = d.account_id;
  if not found then return jsonb_build_object('status', 'pending'); end if;

  if d.device_key_hash is null then
    -- Primera vez: se genera la llave única del dispositivo (solo se entrega en esta respuesta)
    new_key := encode(extensions.gen_random_bytes(24), 'hex');
    update public.devices
       set device_key_hash = encode(extensions.digest(new_key, 'sha256'), 'hex'), claimed_at = now()
     where id = d.id;
    return jsonb_build_object('status', 'active', 'device_key', new_key,
      'url', a.url, 'username', a.username, 'password', a.password, 'expires_at', d.expires_at);
  end if;

  if p_device_key is null or encode(extensions.digest(p_device_key, 'sha256'), 'hex') <> d.device_key_hash then
    return jsonb_build_object('status', 'invalid_key');
  end if;

  return jsonb_build_object('status', 'active',
    'url', a.url, 'username', a.username, 'password', a.password, 'expires_at', d.expires_at);
end $$;

revoke all on function public.device_check(text, text, text) from public;
grant execute on function public.device_check(text, text, text) to anon, authenticated;

-- ping: lo usa la tarea programada de GitHub para que el proyecto gratuito no se pause
create or replace function public.ping() returns timestamptz
language sql stable as $$ select now() $$;
grant execute on function public.ping() to anon, authenticated;
