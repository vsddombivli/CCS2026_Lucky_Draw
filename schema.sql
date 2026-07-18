-- ============================================================
-- Vardhman Sanskar Dham - Choviyar Lucky Draw - Supabase Schema
-- Run this whole file once in Supabase SQL Editor.
--
-- WIN MECHANISM: live per-claim probability, not pre-generated
-- timestamps. Each location has a prize target (lucky_draw_count)
-- and an admin-set expected total claims (expected_total_claims).
-- On every claim, the odds of winning are recomputed from
-- (prizes still available) / (claims still expected), so:
--   - slow/fast footfall self-corrects the odds in real time
--   - admin can bump lucky_draw_count or expected_total_claims
--     at any time, mid-event, with a plain column update — no
--     regeneration step, no clustering risk
--   - it is mathematically impossible to award more prizes than
--     lucky_draw_count at any location
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- LOCATIONS ----------
create table if not exists locations (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  lucky_draw_count int not null default 0,       -- prize target (admin can edit any time)
  expected_total_claims int not null default 0,  -- admin's best estimate of total attempts
  prizes_awarded int not null default 0,         -- running count, maintained by claim_lucky_draw
  claims_so_far int not null default 0,          -- running count, maintained by claim_lucky_draw
  start_time timestamptz,
  end_time timestamptz,
  created_at timestamptz not null default now()
);

-- ---------- PROFILES (role + location mapping) ----------
-- One row per Supabase Auth user you create manually from the
-- Supabase dashboard (Authentication > Users > Add user).
-- After creating the auth user, insert a matching row here.
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','volunteer')),
  location_id uuid references locations(id),
  display_name text
);

-- ---------- PARTICIPATIONS ----------
-- do_number as primary key = one attempt ever, globally, enforced
-- at the database level (not just app logic).
create table if not exists participations (
  do_number text primary key,
  location_id uuid not null references locations(id),
  attempted_at timestamptz not null default now(),
  result text not null check (result in ('win','lose'))
);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================

alter table locations enable row level security;
alter table profiles enable row level security;
alter table participations enable row level security;

-- profiles: everyone can read only their own row
create policy "read own profile" on profiles
  for select using (auth.uid() = id);

-- locations: any logged-in user can read (needed for volunteer
-- countdown timer + admin dashboard); only admins can write.
-- Admin bumping lucky_draw_count / expected_total_claims mid-event
-- is just a normal update through this policy — no RPC needed.
create policy "read locations" on locations
  for select using (auth.role() = 'authenticated');

create policy "admin write locations" on locations
  for all using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.role = 'admin')
  );

-- participations: any logged-in user can read (needed for the
-- "already availed elsewhere" check) but never write directly.
create policy "read participations" on participations
  for select using (auth.role() = 'authenticated');

create policy "no direct write participations" on participations
  for insert with check (false);

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- ---- check_do_status: read-only, safe to retry on network drop.
-- Called on DO-number submit, BEFORE the gift box is shown.
-- Does not lock anything, does not touch odds. ----
create or replace function check_do_status(p_do_number text)
returns table(status text, message text)
language plpgsql
security definer
as $$
declare
  v_existing record;
  v_loc_name text;
begin
  select * into v_existing from participations where do_number = p_do_number;

  if found then
    select name into v_loc_name from locations where id = v_existing.location_id;
    return query select 'blocked', 'Lucky draw already availed at ' || coalesce(v_loc_name, 'another location');
    return;
  end if;

  return query select 'ok', 'eligible';
end;
$$;

-- ---- claim_lucky_draw: the ONLY function that writes to
-- participations, and the ONLY place win/lose is decided.
-- Called when the child clicks the gift box, never before.
--
-- Atomicity: "select ... for update" locks the location's row for
-- the duration of this call, so two simultaneous claims at the
-- same location are processed one after another, never both
-- reading the same prizes_awarded value. This is what prevents
-- over-awarding when two volunteers' phones claim at the same
-- instant.
--
-- Odds formula:
--   remaining_prizes   = lucky_draw_count - prizes_awarded
--   remaining_expected = greatest(expected_total_claims - claims_so_far, remaining_prizes)
--   p = remaining_prizes / remaining_expected   (capped at 1, floored at 0)
--
-- The greatest(...) guard is what makes this self-correcting:
-- if actual claims run ahead of the admin's expected_total_claims
-- late in the window, remaining_expected collapses toward
-- remaining_prizes and p rises toward 1, instead of quietly
-- staying low and risking unclaimed prizes with claims still
-- coming in.
-- ----
create or replace function claim_lucky_draw(p_do_number text)
returns table(result text, message text)
language plpgsql
security definer
as $$
declare
  v_profile record;
  v_loc record;
  v_existing record;
  v_remaining_prizes int;
  v_remaining_expected int;
  v_p float;
  v_win boolean;
begin
  select * into v_profile from profiles where id = auth.uid();
  if v_profile.role is distinct from 'volunteer' or v_profile.location_id is null then
    raise exception 'Not authorized as a volunteer with an assigned location';
  end if;

  -- lock this location's row for the rest of the transaction
  select * into v_loc from locations where id = v_profile.location_id for update;

  -- server-side safety net alongside the client-side countdown
  if v_loc.start_time is null or v_loc.end_time is null
     or now() < v_loc.start_time or now() > v_loc.end_time then
    raise exception 'Lucky draw window is closed for this location';
  end if;

  -- re-check: someone else may have claimed this DO number between
  -- the check_do_status call and this click
  select * into v_existing from participations where do_number = p_do_number;
  if found then
    return query select 'blocked',
      'Lucky draw already availed at ' ||
      (select name from locations where id = v_existing.location_id);
    return;
  end if;

  v_remaining_prizes := v_loc.lucky_draw_count - v_loc.prizes_awarded;
  v_remaining_expected := greatest(v_loc.expected_total_claims - v_loc.claims_so_far, v_remaining_prizes);

  if v_remaining_prizes <= 0 then
    v_p := 0;
  else
    v_p := least(v_remaining_prizes::float / v_remaining_expected::float, 1.0);
  end if;

  v_win := v_remaining_prizes > 0 and random() < v_p;

  update locations
    set claims_so_far = claims_so_far + 1,
        prizes_awarded = prizes_awarded + (case when v_win then 1 else 0 end)
    where id = v_loc.id;

  insert into participations (do_number, location_id, result)
    values (p_do_number, v_loc.id, case when v_win then 'win' else 'lose' end);

  if v_win then
    return query select 'win', 'jackpot';
  else
    return query select 'lose', 'better luck next time';
  end if;
end;
$$;

-- ============================================================
-- REALTIME
-- ============================================================
-- Required so the admin panel can subscribe to live claims_so_far /
-- prizes_awarded updates instead of polling or manual refresh.
-- If you already ran an earlier version of this schema against
-- an existing project, run just this block again on its own —
-- adding a table twice to the same publication errors out.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and tablename = 'locations'
  ) then
    alter publication supabase_realtime add table locations;
  end if;
end $$;

-- ============================================================
-- SETUP NOTES
-- ============================================================
-- 1. Create auth users from Supabase Dashboard > Authentication > Users
--    (1 admin + 5 volunteers, email + password).
-- 2. Insert locations, e.g.:
--    insert into locations (name) values ('SMPT'), ('Rakhi'), ('Suvidhinath'), ('Navneet'), ('Munisurat');
-- 3. Insert profiles mapping each auth user to a role/location, e.g.:
--    insert into profiles (id, role, location_id, display_name)
--    values ('<auth-user-uuid>', 'volunteer', '<location-uuid>', 'SMPT Volunteer');
--    insert into profiles (id, role, display_name)
--    values ('<admin-auth-user-uuid>', 'admin', 'Admin');
-- 4. Admin logs into admin.html, sets:
--      - lucky_draw_count      (how many prizes this location has)
--      - expected_total_claims (best estimate of total DO numbers
--                                that will come through)
--      - start_time / end_time
--    and clicks "Save Settings". No separate generation step.
-- 5. Mid-event: if actual pace runs ahead of the estimate, admin
--    just edits lucky_draw_count and/or expected_total_claims for
--    that location and saves again — odds recalculate on the very
--    next claim automatically.
-- ============================================================
