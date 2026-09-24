-- 0001_schemas.sql
-- build plan §4.4 (docs/golf-trails/02-build-plan.md:811-817): the three
-- schemas the player plane uses.
--
--   app     base tables. Not exposed through PostgREST; clients reach them
--           only via views under their own RLS.
--   api     the only schema exposed. security_invoker views + allow-listed
--           RPCs.
--   private SECURITY DEFINER helpers. Not exposed.
--
-- This migration assumes the `anon` / `authenticated` / `service_role` /
-- `authenticator` roles already exist (real Supabase creates them; our local
-- test harness recreates them in supabase/tests/shim.sql before applying
-- migrations — see tools/db/test.sh).

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS postgis;    -- geometry columns + GiST (§4.2 polygon matching)

CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS api;
CREATE SCHEMA IF NOT EXISTS private;

-- `app` is NOT granted USAGE to anon (build plan §4.4: "not exposed through
-- PostgREST; clients reach them only via views" — anon reaches only the
-- static site and api.* reference views, never app.* by name).
--
-- ⛔ FIX (S2, gate round 2): `authenticated` DOES need USAGE here, and its
-- absence was a real functional bug, not extra safety — confirmed this
-- session: `api.my_progress`/`api.my_offers` (SECURITY INVOKER, per §4.7
-- item 5's explicit "no SECURITY DEFINER in an exposed schema" CI rule,
-- line 1305) reference `app.*` tables in their body, and a SECURITY
-- INVOKER **function** (unlike a security_invoker **view** — verified
-- empirically that `api.my_device` etc. work with zero schema grant at
-- all) genuinely re-checks the caller's schema USAGE at call time. Without
-- this grant every allow-listed RPC failed outright with "permission
-- denied for schema app" for every authenticated caller — the entire
-- RPC allowlist was dead code. USAGE only permits referencing `app.*`
-- objects BY NAME; it grants no table access by itself — every table
-- `authenticated` can actually read still depends on 0008's RLS policies
-- and 0009's per-table SELECT grants, both unchanged by this line (an
-- `anon` role, or an authenticated role probing a table with no SELECT
-- grant, is unaffected: confirmed this session that `anon` still gets
-- "permission denied for schema app" on a direct `app.*` query).
GRANT USAGE ON SCHEMA app TO authenticated, service_role;
GRANT USAGE ON SCHEMA api TO anon, authenticated, service_role;
-- `private` is usable (not selectable-from-PostgREST) by authenticated so
-- that RLS policies and api views can call its SECURITY DEFINER helpers
-- (build plan §4.7 item 3: "executable by authenticated so that views and
-- policies can call them. They are not reachable through PostgREST, because
-- private is not exposed.").
GRANT USAGE ON SCHEMA private TO authenticated, service_role;

-- No `api` schema is exposed via PostgREST to `anon` beyond what explicit
-- grants below allow; PostgREST's own schema-exposure config
-- (`db-schemas`) is a project setting outside this migration
-- [unverified — training knowledge; not a DB-level object].

-- Revoke the default PUBLIC execute grant on every function, everywhere,
-- from the start (build plan §4.7 item 5). Anything created after this
-- point in a later migration must be explicitly GRANTed.
--
-- ⛔ SECURITY FIX (B1, gate round 2): the three `IN SCHEMA <x>` variants
-- this migration originally shipped are a confirmed-empirically-broken
-- no-op — `ALTER DEFAULT PRIVILEGES IN SCHEMA <x> REVOKE EXECUTE ON
-- FUNCTIONS FROM PUBLIC` produces ZERO rows in `pg_default_acl` on
-- PostgreSQL 16 (reproduced this session: `SELECT * FROM pg_default_acl`
-- stayed empty after the statement, and a function created afterward in
-- that schema still had `has_function_privilege('public', ..., 'EXECUTE')
-- = true`). Dropping the `IN SCHEMA` clause and issuing ONE role-scoped
-- (not schema-scoped) statement DOES register a `pg_default_acl` row and
-- DOES block PUBLIC on every function the migration-running role creates
-- afterward, in any schema — reproduced and verified this session. This is
-- therefore now a single global statement, not three schema-scoped ones;
-- since every function this migration set creates lives in app/api/private
-- anyway, "global for this role" and "these three schemas" are the same
-- set in practice. `private.hit_rate_limit` (and every other `private.*`
-- helper) is unreachable by `anon`/`authenticated` from this point on
-- unless a later migration explicitly GRANTs it — none does; only
-- `service_role` is granted `private.*` execute (0007).
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- Backstop for any function an extension might install directly into one
-- of these three schemas (defence in depth; a no-op today since nothing
-- has been created in them yet at this point in the migration order).
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;

-- Same discipline for tables: nothing in `app` is selectable by default:
-- every grant is explicit in 0009_grants_revokes.sql, driven by the §4.4
-- "client read" column.
ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM PUBLIC, anon, authenticated;
