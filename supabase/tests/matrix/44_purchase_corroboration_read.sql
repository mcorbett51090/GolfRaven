-- 44_purchase_corroboration_read.sql
-- 0066_purchase_corroboration_read.sql: scorePlay purchase corroboration definer (no edge_actor table SELECT).

\set QUIET 1
BEGIN;
SELECT plan(10);

GRANT edge_actor TO CURRENT_USER WITH SET TRUE;
GRANT edge_system TO CURRENT_USER WITH SET TRUE;
GRANT edge_partner TO CURRENT_USER WITH SET TRUE;

-- ----------------------------------------------------------------------------
-- 1. EXECUTE matrix + closed table grant
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('edge_actor'), ('edge_partner'), ('edge_system'), ('service_role')) r(n)
   WHERE has_function_privilege(r.n, 'private.list_valid_purchases_around_for_actor(text, date)', 'EXECUTE')),
  ARRAY['edge_actor'],
  'only edge_actor may EXECUTE list_valid_purchases_around_for_actor (among edge roles)'
);

SELECT is(
  has_table_privilege('edge_actor', 'app.purchase_evidence', 'SELECT'),
  false,
  'edge_actor still has no SELECT on app.purchase_evidence (reads go through the definer)'
);

SAVEPOINT s44_root;

-- ----------------------------------------------------------------------------
-- 2. Happy path: helpers seed player A with a valid purchase at fac_x / current_date
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s44_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT count(*)::int FROM private.list_valid_purchases_around_for_actor('fac_x', current_date)),
  1,
  'player A: seeded valid purchase at fac_x is visible within the ±7d window'
);
SELECT is(
  (SELECT o_facility_id FROM private.list_valid_purchases_around_for_actor('fac_x', current_date) LIMIT 1),
  'fac_x',
  'o_facility_id is the purchase facility'
);
SELECT is(
  (SELECT count(*)::int FROM private.list_valid_purchases_around_for_actor('fac_x', current_date - 30)),
  0,
  'a date 30 days away returns nothing (outside CORROBORATION_WINDOW_DAYS)'
);

-- ----------------------------------------------------------------------------
-- 3. Other user: player B does not see A's purchase
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s44_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  (SELECT count(*)::int FROM private.list_valid_purchases_around_for_actor('fac_x', current_date)),
  0,
  'player B: no rows for A''s purchase (actor_uid conjunct)'
);

-- ----------------------------------------------------------------------------
-- 4. Unbound refuses
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s44_root;
SET LOCAL ROLE edge_actor;
SELECT throws_ok(
  $$SELECT * FROM private.list_valid_purchases_around_for_actor('fac_x', current_date)$$,
  '42501',
  NULL,
  'unbound edge_actor cannot list purchases'
);

-- ----------------------------------------------------------------------------
-- 5. Bad args
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s44_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT throws_ok(
  $$SELECT * FROM private.list_valid_purchases_around_for_actor('', current_date)$$,
  '22023',
  NULL,
  'empty facility_id is refused'
);

-- ----------------------------------------------------------------------------
-- 6. Inventory row
-- ----------------------------------------------------------------------------
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_edge_actor FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'list_valid_purchases_around_for_actor'
     AND identity_args = 'p_facility_id text, p_around_local_date date'),
  true,
  'function_inventory expects edge_actor EXECUTE'
);
SELECT is(
  (SELECT expected_edge_system FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'list_valid_purchases_around_for_actor'
     AND identity_args = 'p_facility_id text, p_around_local_date date'),
  false,
  'function_inventory does not expect edge_system EXECUTE'
);

SELECT * FROM finish();
ROLLBACK;
