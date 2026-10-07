-- 29a_review_window.sql
-- 0051, the App Store review account: the SUBMISSION WINDOW table and predicate, the posture of everything 0051 adds, and the cells that pin the restrictions the
-- review account already had (no partner scope; no path to an offer or a special marker on the only lane it can bind). The gate / binder cells are the edge files
-- (29b-29f): `SET ROLE edge_system` is judged by the SESSION user, so they run as a real `edge_gateway` login, and pgTAP numbers per session, so every session that asserts
-- is its own file (the 23_*_edge / _rows pattern). This file also seeds, COMMITTED, what 29b-29f read:
--   R = 29510000-...-a0  the review account (demo row)       N = 29510000-...-b0  an ordinary account
--   two windows that are NOT now: one ended 2 days ago, one starting in 2 days (the gate must refuse with windows on the table).
-- 29f removes everything this file seeds. Re-runnable on one cluster.

\set QUIET 1
SELECT plan(46);

SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('29510000-0000-0000-0000-0000000000a0'),
  ('29510000-0000-0000-0000-0000000000b0')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('29510000-0000-0000-0000-0000000000a0', 'rev29_r'),
  ('29510000-0000-0000-0000-0000000000b0', 'rev29_n');
DELETE FROM app.app_review_demo_account; -- the harness's seeded review account is put back in 29f (at most ONE exists: 0051)
INSERT INTO app.app_review_demo_account (user_id) VALUES ('29510000-0000-0000-0000-0000000000a0');
INSERT INTO app.app_review_window (id, starts_at, ends_at, note) VALUES
  ('29510000-0000-0000-0000-00000000f001', now() - interval '3 days', now() - interval '2 days', 'matrix 29 past'),
  ('29510000-0000-0000-0000-00000000f002', now() + interval '2 days', now() + interval '3 days', 'matrix 29 future');
COMMIT;

-- ============================================================================
-- 1. The predicate: boundary instants (fixed instants in 2031, in a transaction that rolls back; the seeded past / future windows are nowhere near)
-- ============================================================================
BEGIN;
INSERT INTO app.app_review_window (id, starts_at, ends_at) VALUES
  ('29510000-0000-0000-0000-00000000f101', '2031-03-01 10:00:00+00', '2031-03-01 12:00:00+00'),
  ('29510000-0000-0000-0000-00000000f102', '2031-03-01 14:00:00+00', '2031-03-01 16:00:00+00');
SELECT is(private.review_window_open_at('2031-03-01 10:00:00+00'), true, 'boundary: the START instant is inside the window (closed at the start)');
SELECT is(private.review_window_open_at('2031-03-01 09:59:59.999999+00'), false, 'boundary: one microsecond before the start is outside');
SELECT is(private.review_window_open_at('2031-03-01 11:59:59.999999+00'), true, 'boundary: one microsecond before the end is still inside');
SELECT is(private.review_window_open_at('2031-03-01 12:00:00+00'), false, 'boundary: the END instant is outside (open at the end)');
SELECT is(private.review_window_open_at('2031-03-01 13:00:00+00'), false, 'between two windows: outside EVERY window means disabled');
SELECT is(private.review_window_open_at('2031-03-01 14:30:00+00'), true, 'the second window opens it again');
SELECT is(private.review_window_open_at('2031-02-28 00:00:00+00'), false, 'long before any window: disabled');
SELECT is(private.review_window_open_at('2031-03-02 00:00:00+00'), false, 'long after every window: disabled');
INSERT INTO app.app_review_window (id, starts_at, ends_at) VALUES ('29510000-0000-0000-0000-00000000f103', '2031-03-01 11:00:00+00', '2031-03-01 13:00:00+00');
SELECT is(private.review_window_open_at('2031-03-01 12:00:00+00'), true, 'overlapping windows are a UNION: the first one ended at 12:00, the second one still holds it open');
SELECT is(private.review_window_open_at('2031-03-01 13:00:00+00'), false, 'and the union ends where the last overlapping window ends');
ROLLBACK;
SELECT is(private.review_window_open_at(now()), false, 'with only a past and a future window on the table, NOW is outside every window (the default is closed)');
SELECT is(private.review_window_open_at((SELECT ends_at FROM app.app_review_window WHERE id = '29510000-0000-0000-0000-00000000f001')), false, 'the past window is half-open: its own END instant is outside');
SELECT is(private.review_window_open_at((SELECT ends_at - interval '1 microsecond' FROM app.app_review_window WHERE id = '29510000-0000-0000-0000-00000000f001')), true, 'and the instant before it is inside (the seeded window really is a window)');

-- ============================================================================
-- 2. Constraints: a window opened by mistake cannot be empty, inverted or open for months
-- ============================================================================
BEGIN;
SELECT throws_ok($$INSERT INTO app.app_review_window (starts_at, ends_at) VALUES ('2031-03-01 10:00:00+00', '2031-03-01 10:00:00+00')$$, '23514', NULL, 'an empty window (ends_at = starts_at) is refused');
SELECT throws_ok($$INSERT INTO app.app_review_window (starts_at, ends_at) VALUES ('2031-03-01 10:00:00+00', '2031-03-01 09:00:00+00')$$, '23514', NULL, 'an inverted window is refused');
SELECT throws_ok($$INSERT INTO app.app_review_window (starts_at, ends_at) VALUES ('2031-03-01 10:00:00+00', '2031-05-01 10:00:00+00')$$, '23514', NULL, 'a window longer than 60 days is refused');
SELECT lives_ok($$INSERT INTO app.app_review_window (starts_at, ends_at) VALUES ('2031-03-01 10:00:00+00', '2031-04-30 10:00:00+00')$$, 'a window of exactly 60 days is accepted');
SELECT throws_ok($$INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES ('2031-03-01 10:00:00+00', '2031-03-02 10:00:00+00', repeat('x', 201))$$, '23514', NULL, 'a note longer than 200 characters is refused');
ROLLBACK;
RESET ROLE;

-- ============================================================================
-- 3. Posture of what 0051 adds
-- ============================================================================
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.app_review_window'::regclass), true, 'app_review_window: RLS enabled AND forced');
SELECT is((SELECT count(*)::int FROM pg_policy WHERE polrelid = 'app.app_review_window'::regclass AND polname <> 'pd_read_review_window'), 0, 'app_review_window carries no policy but the definer-owner read policy (default deny for every client)');
SELECT is((SELECT array_agg(polroles::regrole[]::text ORDER BY polname) FROM pg_policy WHERE polrelid = 'app.app_review_window'::regclass), ARRAY['{private_definer}'], 'and that one policy applies to private_definer only');
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['anon', 'authenticated', 'edge_actor', 'edge_system', 'edge_gateway']) r, unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p WHERE has_table_privilege(r, 'app.app_review_window', p)), 0, 'no client role and no edge role holds ANY privilege on app_review_window');
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p WHERE has_table_privilege('service_role', 'app.app_review_window', p)), 4, 'service_role administers the windows (full DML, the posture of app.admin_user and app.app_review_demo_account)');
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['anon', 'authenticated', 'edge_actor', 'service_role']) r WHERE has_function_privilege(r, 'private.review_account_gate(uuid, text)', 'EXECUTE')), 0, 'the gate is executable by none of anon / authenticated / edge_actor / service_role');
SELECT is(has_function_privilege('edge_system', 'private.review_account_gate(uuid, text)', 'EXECUTE'), true, 'the gate is executable by edge_system (the lane getActorFromRequest runs it on)');
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['anon', 'authenticated', 'edge_actor', 'edge_system']) r WHERE has_function_privilege(r, 'private.review_window_open_at(timestamptz)', 'EXECUTE')), 0, 'review_window_open_at is executable by no client and no edge role');
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND pg_get_userbyid(p.proowner) = 'private_definer' FROM pg_proc p WHERE p.oid = 'private.review_account_gate(uuid, text)'::regprocedure), true, 'the gate is SECURITY DEFINER, search_path empty, owned by private_definer');
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND pg_get_userbyid(p.proowner) = 'private_definer' FROM pg_proc p WHERE p.oid = 'private.review_window_open_at(timestamptz)'::regprocedure), true, 'the predicate is SECURITY DEFINER, search_path empty, owned by private_definer');
SELECT is((SELECT pg_get_userbyid(p.proowner) FROM pg_proc p WHERE p.oid = 'private.bind_actor_internal(uuid, text)'::regprocedure), 'private_definer', 'the redefined binder keeps its owner');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.bind_actor_internal(uuid, text)'::regprocedure AND p.prosrc LIKE '%review_window_open_at%'), 1, 'the binder carries the window backstop');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.bind_actor_internal(uuid, text)'::regprocedure AND p.prosrc LIKE '%p_kind = ''user'' AND private.is_demo_account(p_uid) AND NOT private.review_window_open_at%'), 1, 'the backstop applies to the user kind only (a system delegate is the system acting on one queued row, not a sign-in)');
SELECT is((SELECT indisunique AND indpred IS NOT NULL FROM pg_index WHERE indexrelid = 'app.audit_log_review_session_once'::regclass), true, 'one audit row per (account, session, outcome) is a partial unique index (a database fact)');

-- ============================================================================
-- 3b. ONE review account (plan line 1871: "One app-review account"), as a database fact
-- ============================================================================
SELECT is((SELECT i.indisunique AND pg_get_expr(i.indexprs, i.indrelid) = 'true' FROM pg_index i WHERE i.indexrelid = 'app.app_review_demo_account_single'::regclass), true, 'a unique index on a constant allows at most one review-account row');
SET ROLE service_role;
BEGIN;
SELECT throws_ok($$INSERT INTO app.app_review_demo_account (user_id) VALUES ('29510000-0000-0000-0000-0000000000b0')$$, '23505', NULL, 'a SECOND review account is refused (23505)');
SELECT lives_ok($$DELETE FROM app.app_review_demo_account; INSERT INTO app.app_review_demo_account (user_id) VALUES ('29510000-0000-0000-0000-0000000000b0')$$, 'replacing the review account is delete-then-insert (the documented way)');
ROLLBACK;
RESET ROLE;

-- ============================================================================
-- 4. The restrictions the review account already had, pinned (service_role asks the predicates; nothing here widens anything)
-- ============================================================================
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name = 'pd_read_review_window' AND using_expr = 'true' AND role_name = 'private_definer'), 1, 'the one new private_definer policy is registered (and the checked-in fixture compares it)');
SELECT is(private.is_demo_account('29510000-0000-0000-0000-0000000000a0'), true, 'R is a review account');
SELECT is(private.is_demo_account('29510000-0000-0000-0000-0000000000b0'), false, 'N is not');
-- "It has no partner scope": the demo account holds no partner membership, and the two scope predicates are false for it at ANY facility / trail
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = '29510000-0000-0000-0000-0000000000a0'), 0, 'R holds no partner_member row (no partner scope)');
SELECT is(private.has_facility_scope('29510000-0000-0000-0000-0000000000a0', 'fac_x'), false, 'R has no facility scope (fac_x)');
SELECT is(private.has_facility_scope('29510000-0000-0000-0000-0000000000a0', 'fac_y'), false, 'R has no facility scope (fac_y)');
SELECT is(private.has_trail_scope('29510000-0000-0000-0000-0000000000a0', 'trl_t'), false, 'R has no trail scope');
SELECT is(private.is_admin('29510000-0000-0000-0000-0000000000a0'), false, 'R is not an admin');
RESET ROLE;
-- "can receive no offer or special marker": the only lane R can bind is edge_actor, and edge_actor holds no INSERT on any offer / marker / entitlement table. (The offer and
-- marker REQUEST routes are P6; until then the absence of any write path IS the restriction, and these cells fail the day someone grants one.)
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['app.offer', 'app.offer_code', 'app.entitlement', 'app.special_marker_stock', 'app.special_marker_stock_movement', 'app.marker_credit']) t WHERE has_table_privilege('edge_actor', t, 'INSERT') OR has_table_privilege('authenticated', t, 'INSERT')), 0, 'neither edge_actor nor authenticated can INSERT into an offer, an offer code, an entitlement, a special marker or a marker credit');
SELECT is((SELECT count(*)::int FROM unnest(ARRAY['app.offer', 'app.offer_code', 'app.entitlement', 'app.special_marker_stock', 'app.special_marker_stock_movement', 'app.marker_credit']) t WHERE has_table_privilege('edge_actor', t, 'DELETE') OR has_table_privilege('authenticated', t, 'DELETE')), 0, 'nor DELETE from them');
SELECT is((SELECT count(*)::int FROM app.offer_code WHERE user_id = '29510000-0000-0000-0000-0000000000a0') + (SELECT count(*)::int FROM app.entitlement WHERE user_id = '29510000-0000-0000-0000-0000000000a0'), 0, 'R holds no offer code and no entitlement (the matrix 16 / 25 cells prove the refusals through the lanes; the reward 403 is rewards-activate.deno.test.ts)');
