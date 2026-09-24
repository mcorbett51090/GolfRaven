-- 03_views_and_rpc.sql
-- build plan §4.7 item 3 (docs/golf-trails/02-build-plan.md:1243-1245):
-- "Every api. view is created WITH (security_invoker = true) ... CI query:
-- fail if any view in api/public lacks security_invoker=true."
-- Item 5 (line 1298-1306): RPC allowlist — no SECURITY DEFINER function in
-- an exposed schema, no exposed function executable by anon that is not on
-- the allowlist, and api.request_checkin_token() must not exist (v2 →
-- removed, line 1303-1304, must-fail cell line 1363).

BEGIN;
SELECT plan(6);

-- Extension-owned views (postgis' geometry_columns/geography_columns,
-- pgtap's tap_funky, etc.) are excluded: they live in `public` as a side
-- effect of CREATE EXTENSION, are not product code, and would fail this
-- check on any real Supabase project with the same extensions enabled —
-- the check is about views THIS migration set creates, not the schema's
-- entire contents.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ('api', 'public') AND c.relkind = 'v'
      AND NOT (c.reloptions IS NOT NULL AND 'security_invoker=true' = ANY (c.reloptions))
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')
  ),
  0,
  'every non-extension view in api/public has security_invoker=true in pg_class.reloptions'
);

-- No SECURITY DEFINER function in an exposed schema (api). `private` is
-- explicitly exempt: it holds the SECURITY DEFINER helpers by design
-- (§4.7 item 3, line 1284-1285) and is never exposed to PostgREST.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'api' AND p.prosecdef
  ),
  0,
  'no SECURITY DEFINER function exists in the exposed api schema'
);

-- Every function in `api` executable by anon must be on the allowlist —
-- which, per the plan, is empty (line 1302-1304: authenticated only).
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'api'
      AND has_function_privilege('anon', p.oid, 'EXECUTE')
  ),
  0,
  'no api.* function is executable by anon'
);

-- The allowlist itself: exactly api.my_progress(text) and api.my_offers(),
-- executable by authenticated.
SELECT ok(
  has_function_privilege('authenticated', 'api.my_progress(text)', 'EXECUTE'),
  'authenticated may EXECUTE api.my_progress(trail_id)'
);
SELECT ok(
  has_function_privilege('authenticated', 'api.my_offers()', 'EXECUTE'),
  'authenticated may EXECUTE api.my_offers()'
);

-- v2's api.request_checkin_token() is removed (line 1303-1304, 1363).
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'api' AND p.proname = 'request_checkin_token'
  ),
  0,
  'api.request_checkin_token() does not exist (removed v2 -> v3)'
);

SELECT * FROM finish();
ROLLBACK;
