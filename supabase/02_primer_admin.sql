-- Ejecuta esto DESPUÉS de crear tu usuario en  Authentication ▸ Users ▸ Add user.
-- Cambia el correo por el tuyo:
insert into public.profiles (id, email, role, active)
select id, email, 'admin', true from auth.users where email = 'TU_CORREO@EJEMPLO.COM'
on conflict (id) do update set role = 'admin', active = true;
