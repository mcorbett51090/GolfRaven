-- 04_storage.sql
-- build plan §4.4 Storage section (docs/golf-trails/02-build-plan.md:862-885)
-- and the §4.7.7 must-fail cells:
--   "Player A lists or reads receipts/<B>/…, or writes any object in
--   receipts directly | denied (no policy)" (line 1344)
--   "operator@T ... reads/lists any exports object | 403 / denied (no
--   policy)" (line 1355)

BEGIN;
SELECT plan(6);

SELECT ok(
  (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class c
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'storage' AND c.relname = 'objects'),
  'storage.objects has RLS enabled and forced'
);

SELECT is(
  (
    SELECT count(*)::int FROM pg_policies
    WHERE schemaname = 'storage' AND tablename = 'objects'
      AND (roles::text[] && ARRAY['anon', 'authenticated']::text[] OR roles::text[] = ARRAY['public'])
  ),
  0,
  'storage.objects has no RLS policy naming anon or authenticated (default deny)'
);

SELECT is(
  (SELECT public FROM storage.buckets WHERE id = 'receipts'), false,
  'the receipts bucket is not public'
);
SELECT is(
  (SELECT public FROM storage.buckets WHERE id = 'exports'), false,
  'the exports bucket is not public'
);

-- Seed one object in each bucket so a real SELECT has a row to (fail to)
-- return, as service_role (bypasses RLS to set up the fixture).
-- S1 restricted-mode fix: the comment above always claimed this ran "as
-- service_role", but no role switch actually preceded these two INSERTs —
-- they silently relied on the connecting bootstrap role's own superuser
-- bypass instead. Made real here with an explicit authenticate_as/
-- clear_actor pair, matching what the comment always said this was.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO storage.objects (bucket_id, name, owner)
VALUES ('receipts', 'receipts/00000000-0000-0000-0000-00000000000b/r1.jpg',
        '00000000-0000-0000-0000-00000000000b');
INSERT INTO storage.objects (bucket_id, name)
VALUES ('exports', 'exports/settlement-2026-09.csv');
SELECT tests.clear_actor();

-- Player A (authenticated) lists receipts/<B's> object -> denied (no
-- policy) -> the RLS-forced table simply returns 0 rows to a role with no
-- SELECT policy, which is what "denied (no policy)" means at the SQL
-- level (PostgREST would surface this as an empty list / 403 depending on
-- route; the DB-level contract under test here is "returns nothing").
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'));
SELECT is(
  (SELECT count(*)::int FROM storage.objects WHERE bucket_id = 'receipts'),
  0,
  'player A reading storage.objects in the receipts bucket sees 0 rows (no policy for authenticated)'
);
SELECT tests.clear_actor();

-- Player uploads directly to the receipts bucket ("writes any object in
-- receipts directly | denied (no policy)", line 1344): INSERT is blocked
-- the same way — no policy for authenticated on storage.objects at all.
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('receipts', 'receipts/00000000-0000-0000-0000-00000000000a/x.jpg')$$,
  '42501',
  NULL,
  'player A cannot INSERT into storage.objects directly (no policy for authenticated)'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
