-- supabase/tests/shim.sql
--
-- A LOCAL-ONLY stand-in for the pieces of a real Supabase project that our
-- migrations assume exist, but that a plain `initdb`'d Postgres 16 cluster
-- does not provide (build plan §10 P3: "no Docker and no Supabase CLI", so
-- there is no `supabase start` to get these for free).
--
-- This file is NEVER run against a real Supabase project (`gr-staging` /
-- `gr-prod` already have all of this). It exists only so
-- `tools/db/test.sh` can apply the real `supabase/migrations/*.sql` files
-- unmodified against a throwaway local cluster and run the pgTAP
-- authorization matrix against something that behaves like Supabase.
--
-- Every assumption below about how Supabase actually wires this up is
-- marked [unverified — training knowledge of Supabase internals]. Where an
-- assumption turned out to matter for a specific migration or test, the
-- exact reasoning is inlined next to it.

-- ============================================================================
-- 1. Roles
-- ============================================================================
-- [unverified — training knowledge of Supabase internals] Supabase's default
-- Postgres role layout: `anon` and `authenticated` are login-less roles that
-- PostgREST assumes via `SET ROLE` after verifying the JWT; `service_role`
-- bypasses RLS; `authenticator` is the actual login role PostgREST connects
-- as and is granted the other three so it can `SET ROLE` into them. We
-- recreate exactly this shape so `GRANT ... TO anon/authenticated/service_role`
-- in the migrations resolves against real roles.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticator') THEN
    CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'shim_only_not_for_prod';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_admin') THEN
    CREATE ROLE supabase_admin NOINHERIT LOGIN SUPERUSER PASSWORD 'shim_only_not_for_prod';
  END IF;
END
$$;

GRANT anon TO authenticator;
GRANT authenticated TO authenticator;
GRANT service_role TO authenticator;

-- ----------------------------------------------------------------------------
-- 1a. The MIGRATION-OWNER role this shim provisions (S1, gate round 3) —
-- separate from the four PostgREST-facing roles above.
-- ----------------------------------------------------------------------------
-- [unverified — training knowledge of Supabase internals] On a real hosted
-- Supabase project, migrations run as the project's `postgres` role, which
-- is widely documented/believed NOT to be a true Postgres superuser —
-- Supabase reserves actual cluster superuser for its own control plane and
-- grants the project's `postgres` role a large but bounded privilege set
-- instead. `tools/db/test.sh`'s default mode does NOT reproduce this: it
-- connects as the cluster bootstrap role, which IS a true superuser
-- (BYPASSRLS-equivalent for every table, always, regardless of FORCE ROW
-- LEVEL SECURITY) — a strictly more permissive stand-in than the real
-- thing. Its `restricted` mode (`HARNESS_MODE=restricted`) migrates and
-- runs the pgTAP matrix as `migration_owner`, created below: LOGIN,
-- CREATEDB, CREATEROLE, and explicitly NOSUPERUSER NOBYPASSRLS. It is
-- made the OWNER of the test database itself (so it can CREATE SCHEMA/
-- TABLE/POLICY without further grants) and CREATEROLE lets it run
-- 0016_private_definer.sql's `CREATE ROLE private_definer ...` — the one
-- piece of DDL a plain schema owner cannot do on its own.
--
-- ⛔ PRIOR GAP, RESOLVED THIS ROUND (2026, gate round 3): an earlier
-- version of this note recorded a hard blocker — PostgreSQL forbids
-- changing the `role` GUC from inside a SECURITY DEFINER function body (no
-- `SET LOCAL ROLE`, no function-level `SET role = ...`), so a
-- SECURITY DEFINER function owned by a plain NOSUPERUSER NOBYPASSRLS
-- migration-owner could never reach a FORCE-ROW-LEVEL-SECURITY table with
-- no policy for its own owner. The coordinator's directive was explicit:
-- do not remove FORCE ROW LEVEL SECURITY anywhere. The actual fix
-- (0016_private_definer.sql) sidesteps the blocker instead of working
-- around it: every `private.*` SECURITY DEFINER function is owned by a
-- DEDICATED role, `private_definer` (NOLOGIN NOSUPERUSER NOBYPASSRLS, NOT
-- the table owner of anything), reaching each table it touches only
-- through narrow, explicit RLS policies `TO private_definer` — the same
-- mechanism anon/authenticated/service_role already use, not an
-- ownership/FORCE exemption. `migration_owner` (this section) never owns
-- those functions and is unaffected by any of this — it only needs
-- CREATEROLE to create the `private_definer` role once, in 0016.
--
-- migration_owner's OWN interaction with FORCE ROW LEVEL SECURITY: once a
-- migration file `ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY`s a
-- table migration_owner just created (owner + FORCE + NOBYPASSRLS = RLS
-- applies to the owner too, from that point on), migration_owner can no
-- longer see/write that table's rows with a plain, unscoped statement —
-- exactly the property S1 wants proven, not worked around. Two places in
-- the pipeline need real data access to a FORCE'd table on migration_owner's
-- own connection, so each gets a narrow, explicit, commented grant here
-- (bootstrap-as-superuser provisioning, the same tier this file's other
-- role setup already lives in) rather than a BYPASSRLS-shaped exemption:
--   (i) 0012_storage.sql's two `INSERT INTO storage.buckets ... ON
--       CONFLICT DO NOTHING` seed rows — storage.buckets is created and
--       FORCE'd by THIS file (owned by the bootstrap role, not
--       migration_owner), holds bucket CONFIG, not user data, and the
--       insert is unconditional (every row, not a caller-scoped subset)
--       — see the GRANT + POLICY below.
--   (ii) supabase/tests/helpers.sql's fixture-seeding INSERTs into
--       app.*/private.* tables migration_owner itself now owns — these
--       are wide, cross-actor test fixtures with no natural per-row
--       scope, so tools/db/test.sh runs helpers.sql (in EITHER harness
--       mode) via `SET ROLE service_role` first: service_role already has
--       full DML + BYPASSRLS (this file, below) for exactly this "server-
--       side/administrative write" shape, matching how these same rows
--       would really be written (Edge Functions running as service_role,
--       0009's own comment). No new grant needed for this one.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migration_owner') THEN
    CREATE ROLE migration_owner
      LOGIN NOSUPERUSER NOBYPASSRLS CREATEDB CREATEROLE
      PASSWORD 'shim_only_not_for_prod';
  END IF;
END
$$;
DO $$
BEGIN
  EXECUTE format('ALTER DATABASE %I OWNER TO migration_owner', current_database());
END
$$;

-- [unverified — training knowledge of Supabase internals] Supabase's default
-- grants: usage on `public` is broad, but we do NOT replicate that here,
-- because build plan §4.4/§4.7 puts nothing client-relevant in `public` —
-- everything client-facing lives in `api`. The migrations grant USAGE on
-- `app`/`api`/`private` explicitly per §4.7, so no blanket grant belongs in
-- the shim.

-- ============================================================================
-- 2. `auth` schema: `auth.users`, `auth.uid()`, `auth.jwt()`, `auth.role()`
-- ============================================================================
-- [unverified — training knowledge of Supabase internals] Supabase's real
-- `auth.users` has ~30 columns (encrypted_password, confirmation tokens,
-- identities, MFA factors, etc.) that our RLS policies and functions never
-- reference. We shim only the columns build plan §3.6/§4.4 actually touch:
-- `id`, `email` (for partner_invite's verified-email check, A2-21), and
-- `raw_user_meta_data` (so the "role never comes from user_metadata" must-fail
-- cell, §4.7 item 4, has something real to attempt writing to).
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE,
  email_confirmed_at timestamptz,
  raw_user_meta_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- [unverified — training knowledge of Supabase internals] `auth.uid()` and
-- `auth.role()` read the `sub` / `role` claims out of the current session's
-- JWT, which PostgREST makes available as the Postgres GUC
-- `request.jwt.claims` (a JSON string) before running the request. We
-- reproduce that exact GUC contract so migrations that call `auth.uid()`
-- behave the same against the shim as against real Supabase; the pgTAP
-- harness sets the GUC with `set_config('request.jwt.claims', ..., true)`
-- to impersonate each test actor (see supabase/tests/helpers.sql).
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb
LANGUAGE sql STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$;

CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
LANGUAGE sql STABLE
AS $$
  SELECT NULLIF(auth.jwt() ->> 'sub', '')::uuid;
$$;

CREATE OR REPLACE FUNCTION auth.role() RETURNS text
LANGUAGE sql STABLE
AS $$
  SELECT COALESCE(auth.jwt() ->> 'role', 'anon');
$$;

CREATE OR REPLACE FUNCTION auth.email() RETURNS text
LANGUAGE sql STABLE
AS $$
  SELECT auth.jwt() ->> 'email';
$$;

GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role, migration_owner;
GRANT SELECT, INSERT ON auth.users TO service_role;
-- INSERT (not UPDATE/DELETE — helpers.sql never does either): fixture
-- account seeding in supabase/tests/helpers.sql now runs `SET ROLE
-- service_role` first (tools/db/test.sh, S1 gate round 3), matching how a
-- real account would really be created (Supabase's admin/auth API, not a
-- direct client write) — auth.users itself carries no RLS in this shim
-- (matching a real Supabase project, which does not expose it to
-- PostgREST at all), so the table-level grant is the only gate.
-- migration_owner (S1, gate round 3) needs REFERENCES on auth.users
-- because several migrations' own tables declare
-- `... REFERENCES auth.users (id)` FK constraints — creating an FK
-- requires REFERENCES on the TARGET table for whichever role runs the
-- CREATE/ALTER TABLE, regardless of RLS (FK enforcement is independent of
-- RLS and always reads with the referenced table owner's rights, not the
-- FK-creating role's — REFERENCES is a one-time, DDL-time check).
GRANT REFERENCES ON auth.users TO migration_owner;
-- No SELECT for anon/authenticated on auth.users — real Supabase does not
-- expose it to PostgREST either [unverified — training knowledge].
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.jwt() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.role() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.email() TO anon, authenticated, service_role;

-- ============================================================================
-- 3. `storage` schema (minimal): `storage.buckets`, `storage.objects`
-- ============================================================================
-- [unverified — training knowledge of Supabase internals] Real Supabase
-- Storage's `storage.objects` has more columns (version, owner_id, path_tokens
-- generated column, etc.). We shim only what build plan §4.4's Storage
-- section and the §4.7.7 matrix's storage.objects row need: enough to
-- create the `receipts` / `exports` buckets, enable+force RLS on
-- `storage.objects`, and write must-fail policy tests against it (no client
-- role may select/insert/update/delete any row, §4.4).
CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE IF NOT EXISTS storage.buckets (
  id text PRIMARY KEY,
  name text NOT NULL,
  public boolean NOT NULL DEFAULT false,
  file_size_limit bigint,
  allowed_mime_types text[],
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS storage.objects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id text NOT NULL REFERENCES storage.buckets (id),
  name text NOT NULL,
  owner uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb
);

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.buckets FORCE ROW LEVEL SECURITY;
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.objects FORCE ROW LEVEL SECURITY;
-- No CLIENT-facing policies created here — the migrations (0012_storage.sql)
-- create the buckets and, per build plan §4.4, deliberately add NO
-- storage.objects policy for anon or authenticated on either bucket. RLS
-- enabled + forced + zero policies for those roles is exactly "denied (no
-- policy)" (§4.7.7).
--
-- migration_owner IS granted a narrow INSERT-only policy here (S1, gate
-- round 3, 1a(i) above): 0012_storage.sql's own INSERT INTO storage.buckets
-- runs as migration_owner in restricted mode, and storage.buckets is owned
-- by the bootstrap role (created in this file), not migration_owner, so
-- FORCE ROW LEVEL SECURITY applies to it the same as to anon/authenticated
-- — no exemption, just an explicit grant for the one legitimate write this
-- role's migration actually makes. Bucket config only, never storage.objects
-- (no policy for migration_owner there at all).
GRANT INSERT ON storage.buckets TO migration_owner;
CREATE POLICY migration_owner_seed_buckets ON storage.buckets
  FOR INSERT TO migration_owner WITH CHECK (true);

GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role, migration_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.buckets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO service_role;
-- anon/authenticated get table-level SELECT/INSERT grants (matching real
-- Supabase, which authorizes Storage access through RLS policies, not
-- table grants [unverified — training knowledge]) so that "no policy exists"
-- is what blocks them, not a missing GRANT — otherwise the must-fail test
-- would be trivially true for the wrong reason (E1 in the plan's cause
-- taxonomy: the read would look blocked without the RLS policy actually
-- being what did the blocking).
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO anon, authenticated;
GRANT SELECT ON storage.buckets TO anon, authenticated;

-- ============================================================================
-- 4. Realtime shim (minimal, for the §4.7 item 6 "Realtime disabled" check)
-- ============================================================================
-- [unverified — training knowledge of Supabase internals; build plan §4.7
-- item 6 / A67 says this is confirmed by the P3 week-1 spike against a real
-- project] Supabase wires Realtime through a logical-replication publication
-- named `supabase_realtime`. We create an empty one so the migrations'
-- assertion ("the publication exists and is empty") has something real to
-- check locally, instead of the check silently passing because the object
-- doesn't exist at all.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END
$$;

-- ============================================================================
-- 5. Test-actor helper (test-only; never shipped in a real migration)
-- ============================================================================
-- Sets the session's simulated JWT claims and switches into the client role
-- PostgREST would have used, so a pgTAP test can run a query "as" a given
-- actor. Lives in the tests/ tree (not migrations/) on purpose: it is test
-- scaffolding, not product schema.
CREATE SCHEMA IF NOT EXISTS tests;
GRANT USAGE ON SCHEMA tests TO PUBLIC;

CREATE OR REPLACE FUNCTION tests.authenticate_as(p_role text, p_claims jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config('request.jwt.claims', p_claims::text, false);
  EXECUTE format('SET LOCAL ROLE %I', p_role);
END;
$$;

CREATE OR REPLACE FUNCTION tests.clear_actor()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config('request.jwt.claims', '', false);
  RESET ROLE;
END;
$$;
