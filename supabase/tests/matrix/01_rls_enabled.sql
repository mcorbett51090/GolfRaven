-- 01_rls_enabled.sql
-- build plan §4.7 item 2 (docs/golf-trails/02-build-plan.md:1239): "RLS
-- enabled and forced on every app. table." Table-agnostic: iterates
-- pg_class so a new table added later without RLS fails this test without
-- anyone having to remember to add a row for it here.

BEGIN;
SELECT plan(2);

SELECT is(
  (
    SELECT count(*)::int FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'app' AND c.relkind = 'r' AND NOT c.relrowsecurity
  ),
  0,
  'every app. table has ROW LEVEL SECURITY enabled'
);

SELECT is(
  (
    SELECT count(*)::int FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'app' AND c.relkind = 'r' AND NOT c.relforcerowsecurity
  ),
  0,
  'every app. table has ROW LEVEL SECURITY forced (applies to the table owner too)'
);

SELECT * FROM finish();
ROLLBACK;
