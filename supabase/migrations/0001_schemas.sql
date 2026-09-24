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

-- `app` is deliberately NOT granted USAGE to anon/authenticated (build plan
-- §4.4: "not exposed through PostgREST; clients reach them only via views").
GRANT USAGE ON SCHEMA app TO service_role;
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
ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA api REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;

-- Same discipline for tables: nothing in `app` is selectable by default:
-- every grant is explicit in 0009_grants_revokes.sql, driven by the §4.4
-- "client read" column.
ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM PUBLIC, anon, authenticated;
