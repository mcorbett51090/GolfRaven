-- 54_course_qr_static_pin_cap.sql
-- 0076_course_qr_static_pin_cap_alert.sql (P5 §62 / plan §8.3): facility-wide
-- count of credited static_pin course_qr marker_credits (signal, not block).
-- Restricted harness: auth.users / app seeds go through service_role (FORCE RLS;
-- migration_owner has no INSERT on auth.users — same pattern as matrices 10 / 20 / 49).

\set QUIET 1
BEGIN;
SELECT plan(15);

GRANT edge_actor TO CURRENT_USER WITH SET TRUE;
GRANT edge_system TO CURRENT_USER WITH SET TRUE;
GRANT edge_partner TO CURRENT_USER WITH SET TRUE;
-- service_role SET is already granted to migration_owner in shim.sql (no re-GRANT).

-- ----------------------------------------------------------------------------
-- 1. Structure / EXECUTE / closed table grants
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'course_qr_static_pin_credit_count_for_actor'
     AND p.prosecdef AND p.proowner = 'private_definer'::regrole
     AND p.proconfig = ARRAY['search_path=""']),
  1,
  'structure: SECURITY DEFINER / private_definer / search_path='''''
);

SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('edge_actor'), ('edge_partner'), ('edge_system'), ('service_role')) r(n)
   WHERE has_function_privilege(r.n, 'private.course_qr_static_pin_credit_count_for_actor(text, date)', 'EXECUTE')),
  ARRAY['edge_actor'],
  'only edge_actor may EXECUTE course_qr_static_pin_credit_count_for_actor (among edge roles)'
);

SELECT is(
  has_table_privilege('edge_actor', 'app.marker_credit', 'SELECT')
    OR has_table_privilege('edge_actor', 'app.purchase_evidence', 'SELECT'),
  false,
  'edge_actor still has no SELECT on marker_credit / purchase_evidence (count goes through the definer)'
);

SELECT is(
  (SELECT count(*)::int FROM pg_policy pol WHERE pol.polname IN ('pd_course_qr_cap_credit_select', 'pd_course_qr_cap_purchase_select')),
  2,
  'structure: two pd_course_qr_cap_* SELECT policies exist'
);

SELECT is(
  (SELECT count(*)::int FROM pg_indexes
   WHERE schemaname = 'app' AND indexname = 'fraud_signal_course_qr_static_pin_cap_open_idx'),
  1,
  'structure: open-signal unique index exists'
);

SELECT ok(
  (SELECT pg_get_function_identity_arguments(p.oid) !~* '(^|, )p_(user|uid|actor)'
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'course_qr_static_pin_credit_count_for_actor'),
  'no user-id argument: a wrong uid cannot even be expressed'
);

-- ----------------------------------------------------------------------------
-- 2. Inventory
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_edge_actor FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'course_qr_static_pin_credit_count_for_actor'
     AND identity_args = 'p_facility_id text, p_local_date date'),
  true,
  'function_inventory expects edge_actor EXECUTE'
);
SELECT is(
  (SELECT expected_edge_system OR expected_edge_partner FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'course_qr_static_pin_credit_count_for_actor'
     AND identity_args = 'p_facility_id text, p_local_date date'),
  false,
  'function_inventory does not expect edge_system / edge_partner EXECUTE'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 3. Count correctness
--    unique credited index is (user_id, trail_id, facility_id) → one user per credit
--    Plant helper is created BEFORE the savepoint so ROLLBACK TO keeps it.
--    Plants as service_role (BYPASSRLS + auth.users INSERT).
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.plant_static_pin_credits(
  p_n int,
  p_facility text DEFAULT 'fac_x',
  p_local date DEFAULT current_date,
  p_base int DEFAULT 1
) RETURNS void
LANGUAGE plpgsql AS $f$
DECLARE
  i int;
  uid uuid;
  pe uuid;
BEGIN
  SET LOCAL ROLE service_role;
  FOR i IN p_base..(p_base + p_n - 1) LOOP
    uid := ('ee540000-0000-0000-0000-' || lpad(to_hex(i), 12, '0'))::uuid;
    pe := ('ee54ce00-0000-0000-0000-' || lpad(to_hex(i), 12, '0'))::uuid;
    INSERT INTO auth.users (id, email) VALUES (uid, 's54-' || i || '@cap.test') ON CONFLICT (id) DO NOTHING;
    INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES (pe, uid, p_facility, 'trl_t', 'course_qr', 'static_pin', p_local, 'valid');
    INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status)
    VALUES (gen_random_uuid(), uid, 'trl_t', p_facility, pe, 'credited');
  END LOOP;
  RESET ROLE;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.plant_static_pin_credits(int, text, date, int) TO PUBLIC;

SAVEPOINT s54_root;

-- helpers seed has one rotating credited credit at fac_x — must not count
ROLLBACK TO SAVEPOINT s54_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date),
  0,
  'helpers rotating credited credit does not count (static_pin only)'
);

-- plant 3 → count 3 (visible to any bound actor, not only the credit owner)
ROLLBACK TO SAVEPOINT s54_root;
SELECT pg_temp.plant_static_pin_credits(3);
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date),
  3,
  'facility-wide: player B sees the three static_pin credits of other users'
);

-- pending does not count
ROLLBACK TO SAVEPOINT s54_root;
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email) VALUES ('ee540000-0000-0000-0000-0000000000aa', 's54-pend@cap.test') ON CONFLICT (id) DO NOTHING;
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
VALUES ('ee54ce00-0000-0000-0000-0000000000aa', 'ee540000-0000-0000-0000-0000000000aa', 'fac_x', 'trl_t', 'course_qr', 'static_pin', current_date, 'pending');
INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
VALUES ('ee540000-0000-0000-0000-0000000000aa', 'trl_t', 'fac_x', 'ee54ce00-0000-0000-0000-0000000000aa', 'pending');
RESET ROLE;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date),
  0,
  'pending static_pin credit does not count'
);

-- other facility / other date do not count
ROLLBACK TO SAVEPOINT s54_root;
SELECT pg_temp.plant_static_pin_credits(2, 'fac_x', current_date, 1);
SELECT pg_temp.plant_static_pin_credits(2, 'fac_y', current_date, 11);
SELECT pg_temp.plant_static_pin_credits(2, 'fac_x', current_date - 1, 21);
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date),
  2,
  'other facility and other local_date are excluded'
);

-- 25 → cap threshold the Edge fires on (>= 25; unique index dedupes later)
ROLLBACK TO SAVEPOINT s54_root;
SELECT pg_temp.plant_static_pin_credits(25);
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date),
  25,
  '25 credited static_pin credits (Edge alert threshold floor)'
);

-- unbound / bad args
ROLLBACK TO SAVEPOINT s54_root;
SET LOCAL ROLE edge_actor;
SELECT throws_ok(
  $$SELECT private.course_qr_static_pin_credit_count_for_actor('fac_x', current_date)$$,
  '42501',
  NULL,
  'unbound edge_actor cannot count'
);

ROLLBACK TO SAVEPOINT s54_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT throws_ok(
  $$SELECT private.course_qr_static_pin_credit_count_for_actor('', current_date)$$,
  '22023',
  NULL,
  'empty facility_id is refused'
);

SELECT * FROM finish();
ROLLBACK;
