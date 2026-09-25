-- 02_grants_trust.sql
-- build plan §4.7 item 1 (docs/golf-trails/02-build-plan.md:1167-1181):
-- "A CI query fails on any app. table that grants a write to a client
-- role." Table-agnostic over information_schema, so it covers "every
-- table" without an enumerated list.

BEGIN;
SELECT plan(4);

-- No INSERT/UPDATE/DELETE grant to anon on ANY app. table, ever.
SELECT is(
  (
    SELECT count(*)::int
    FROM information_schema.role_table_grants
    WHERE table_schema = 'app'
      AND grantee = 'anon'
      AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE')
  ),
  0,
  'anon has no INSERT/UPDATE/DELETE grant on any app. table'
);

-- authenticated may only ever hold profile's column-scoped UPDATE — no
-- table-wide INSERT/UPDATE/DELETE grant, and no INSERT/DELETE at all.
SELECT is(
  (
    SELECT count(*)::int
    FROM information_schema.role_table_grants
    WHERE table_schema = 'app'
      AND grantee = 'authenticated'
      AND privilege_type IN ('INSERT', 'DELETE')
  ),
  0,
  'authenticated has no INSERT/DELETE grant on any app. table'
);

SELECT is(
  (
    SELECT count(*)::int
    FROM information_schema.role_table_grants
    WHERE table_schema = 'app'
      AND grantee = 'authenticated'
      AND privilege_type = 'UPDATE'
      AND table_name <> 'profile'
  ),
  0,
  'authenticated has no UPDATE grant on any app. table except the profile column-level grant'
);

-- profile's UPDATE grant is column-scoped to exactly the four columns the
-- plan names (line 824), never a whole-row UPDATE.
SELECT is(
  (
    SELECT array_agg(column_name::text ORDER BY column_name::text)
    FROM information_schema.column_privileges
    WHERE table_schema = 'app' AND table_name = 'profile'
      AND grantee = 'authenticated' AND privilege_type = 'UPDATE'
  ),
  ARRAY['handle', 'home_region', 'leaderboard_opt_in', 'locale'],
  'profile UPDATE is column-scoped to exactly handle/locale/home_region/leaderboard_opt_in'
);

SELECT * FROM finish();
ROLLBACK;
