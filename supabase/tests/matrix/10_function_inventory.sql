-- 10_function_inventory.sql
-- build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1206-1215): "The
-- function inventory is derived, not maintained ... The same job derives
-- the RPC column list from pg_proc for the exposed schema. No hand list is
-- authoritative." This file is the pg_proc half (the RPC column list); the
-- supabase/functions/*/ directory half (Edge Functions vs. the matrix's
-- columns, and vs. the deployed list) is a separate, non-SQL check —
-- tools/db/verify-function-inventory.mjs — because directory listings and
-- a staging/prod deploy comparison are not things a SQL migration/test can
-- see.
--
-- "CI fails if a function in the inventory has no matrix cells" (task
-- instruction): the inventory here is exactly api.my_progress and
-- api.my_offers (the v3 RPC allowlist, line 1302); both are exercised by
-- 03_views_and_rpc.sql's EXECUTE-privilege assertions, which stand in for
-- "matrix cells" for a 0-argument-shaped authorization surface (there is
-- no id-scoped variant to test per actor — neither function takes a
-- caller-supplied foreign id whose ownership must be checked; my_progress
-- takes a trail_id, which is public catalog reference data, not another
-- user's private id).

BEGIN;
SELECT plan(2);

-- Every function in the exposed `api` schema, executable by ANY client
-- role (anon or authenticated), must be one of the two allow-listed names.
-- A new api.* function added later without also widening this list fails
-- here immediately — that failure is the point (it means the matrix in
-- 03_views_and_rpc.sql / 05_own_row_matrix.sql needs a new entry too).
SELECT is(
  (
    SELECT array_agg(DISTINCT p.proname::text ORDER BY p.proname::text)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'api'
      AND p.prokind = 'f'
      AND (
        has_function_privilege('anon', p.oid, 'EXECUTE')
        OR has_function_privilege('authenticated', p.oid, 'EXECUTE')
      )
  ),
  ARRAY['my_offers', 'my_progress'],
  'every EXECUTE-able api.* function is exactly the v3 RPC allowlist (my_offers, my_progress) — a new one added without updating this test fails CI'
);

-- Reverse direction: neither allowlisted function is missing (belt and
-- suspenders alongside 03_views_and_rpc.sql's per-function EXECUTE checks).
SELECT is(
  (
    SELECT count(*)::int FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'api' AND p.proname IN ('my_progress', 'my_offers')
  ),
  2,
  'both allow-listed api.* functions exist'
);

SELECT * FROM finish();
ROLLBACK;
