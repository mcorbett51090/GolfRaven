-- 15_rewards_activation.sql
-- P3f (0027_rewards_activation.sql): the §7.5 activation state machine and the
-- `held_review` semantics on offer_code / entitlement, exercised against the
-- real SQL functions app.activate_offer_code, app.activate_entitlement,
-- app.resolve_held_offer_code and app.resolve_held_entitlement; plus the
-- schema additions and the must-fail cells (who may NOT call them, which
-- transitions are refused).
--
-- Runs as service_role for the function calls (that is the only role with
-- EXECUTE, by design), and switches to authenticated / anon only for the
-- must-fail privilege cells. The DECISION (which §7.5 row matched) is made in
-- TypeScript and covered by supabase/tests/unit/decision-table.test.ts and the
-- Deno integration suite; what this file proves is what the DATABASE enforces
-- independently of its caller.
--
-- Fixture ids reused from supabase/tests/helpers.sql: player A =
-- ...00000a, player B = ...00000b, admin = ...4000000000d0, device (A) =
-- 20000000-...-000000000001, trails trl_t / trl_u / trl_v, facility fac_x.

BEGIN;
SELECT plan(121);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------
-- A second device for A (a "second device" / "reinstall") and two for B.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('20000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-00000000000a', 'ios'),
  ('20000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000b', 'ios');

-- Offers (all live, face value 10): enough that every (user, offer) pair below
-- is unique. budget_cap 25 leaves room for two reservations, not three.
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
SELECT ('61000000-0000-0000-0000-0000000000' || lpad(n::text, 2, '0'))::uuid, 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 25, 10, current_date, current_date + 30, 'live'
FROM generate_series(1, 14) AS n;

-- ============================================================================
-- 1. Schema additions
-- ============================================================================
SELECT has_column('app', 'device', 'attest_public_key', 'device.attest_public_key exists');
SELECT has_column('app', 'offer', 'face_value', 'offer.face_value exists');
SELECT has_column('app', 'offer_code', 'reserved_amount', 'offer_code.reserved_amount exists');
SELECT has_column('app', 'offer_code', 'rests_on_unattestable', 'offer_code.rests_on_unattestable exists');
SELECT has_column('app', 'entitlement', 'rests_on_unattestable', 'entitlement.rests_on_unattestable exists');
SELECT is(
  (SELECT bool_and(NOT rests_on_unattestable) FROM app.offer_code) AND (SELECT bool_and(NOT rests_on_unattestable) FROM app.entitlement),
  true,
  'rests_on_unattestable defaults to false for every existing reward (nothing is retroactively held)'
);
SELECT throws_ok(
  $$UPDATE app.device SET attest_public_key = '\x0102030405'::bytea WHERE id = '20000000-0000-0000-0000-0000000000a2'$$,
  '23514', NULL, 'device.attest_public_key must be exactly 65 bytes (an uncompressed P-256 point) or NULL'
);
SELECT lives_ok(
  $$UPDATE app.device SET attest_public_key = decode('04' || repeat('ab', 64), 'hex') WHERE id = '20000000-0000-0000-0000-0000000000a2'$$,
  'a 65-byte key is accepted'
);
SELECT throws_ok(
  $$UPDATE app.offer SET face_value = -1 WHERE id = '61000000-0000-0000-0000-000000000001'$$,
  '23514', NULL, 'offer.face_value cannot be negative'
);
SELECT throws_ok(
  $$UPDATE app.offer_code SET reserved_amount = -1 WHERE id = '70000000-0000-0000-0000-000000000001'$$,
  '23514', NULL, 'offer_code.reserved_amount cannot be negative'
);
SELECT is(
  (SELECT count(*)::int FROM pg_constraint WHERE conrelid = 'app.device_reward_ledger'::regclass AND contype = 'u'
     AND conname = 'device_reward_ledger_device_reward_key'),
  1,
  'device_reward_ledger has UNIQUE (device_id, reward_kind, reward_id)'
);
SELECT is(
  (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.device_reward_ledger'::regclass),
  true,
  'device_reward_ledger keeps ENABLE + FORCE ROW LEVEL SECURITY'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND tablename = 'device_reward_ledger' AND roles && ARRAY['anon', 'authenticated']::name[]),
  0,
  'device_reward_ledger has no policy for any client role'
);

-- ============================================================================
-- 2. Function privileges (must-fail cells)
-- ============================================================================
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('activate_offer_code', 'activate_entitlement', 'resolve_held_offer_code', 'resolve_held_entitlement', 'release_account_reservations')),
  5, 'the five P3f functions exist'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('activate_offer_code', 'activate_entitlement', 'resolve_held_offer_code', 'resolve_held_entitlement', 'release_account_reservations')
     AND (p.prosecdef OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'))),
  0, 'none is SECURITY DEFINER and every one pins search_path'
);
SELECT is(
  (SELECT bool_and(has_function_privilege('service_role', p.oid, 'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('activate_offer_code', 'activate_entitlement', 'resolve_held_offer_code', 'resolve_held_entitlement', 'release_account_reservations')),
  true, 'service_role may EXECUTE all five'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('activate_offer_code', 'activate_entitlement', 'resolve_held_offer_code', 'resolve_held_entitlement', 'release_account_reservations')
     AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))),
  0, 'neither anon nor authenticated may EXECUTE any of them'
);

SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '42501', NULL, 'must-fail: a signed-in player cannot call app.activate_offer_code themselves (not even for their own code)'
);
SELECT throws_ok(
  $$SELECT app.activate_entitlement('50000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '42501', NULL, 'must-fail: a signed-in player cannot call app.activate_entitlement'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('70000000-0000-0000-0000-000000000001', true, '00000000-0000-0000-0000-00000000000a')$$,
  '42501', NULL, 'must-fail: a signed-in player cannot approve a held offer code (not even by naming themselves)'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_entitlement('50000000-0000-0000-0000-000000000001', true, '00000000-0000-0000-0000-00000000000a')$$,
  '42501', NULL, 'must-fail: a signed-in player cannot approve a held entitlement'
);
SELECT throws_ok(
  $$SELECT app.release_account_reservations('00000000-0000-0000-0000-00000000000a')$$,
  '42501', NULL, 'must-fail: a signed-in player cannot call app.release_account_reservations (not even for themselves)'
);
SELECT throws_ok(
  $$UPDATE app.offer_code SET state = 'issued' WHERE id = '70000000-0000-0000-0000-000000000001'$$,
  '42501', NULL, 'must-fail: a player cannot write offer_code.state directly (no grant)'
);
SELECT throws_ok(
  $$UPDATE app.offer_code SET reserved_amount = 0, rests_on_unattestable = false WHERE id = '70000000-0000-0000-0000-000000000001'$$,
  '42501', NULL, 'must-fail: a player cannot write the budget reservation or the unattestable flag'
);
SELECT throws_ok(
  $$UPDATE app.entitlement SET state = 'redeemable', rests_on_unattestable = false WHERE id = '50000000-0000-0000-0000-000000000001'$$,
  '42501', NULL, 'must-fail: a player cannot write entitlement.state or its unattestable flag'
);
SELECT throws_ok(
  $$SELECT count(*) FROM app.device_reward_ledger$$,
  '42501', NULL, 'must-fail: a player cannot read device_reward_ledger (no grant at all)'
);
SELECT throws_ok(
  $$INSERT INTO app.device_reward_ledger (device_id, user_id, reward_kind, reward_id) VALUES ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'offer', gen_random_uuid())$$,
  '42501', NULL, 'must-fail: a player cannot write device_reward_ledger'
);
SELECT throws_ok(
  $$UPDATE app.device SET attest_public_key = decode('04' || repeat('cd', 64), 'hex'), attest_counter = 99 WHERE id = '20000000-0000-0000-0000-000000000001'$$,
  '42501', NULL, 'must-fail: a player cannot register their own App Attest key or advance their own counter'
);
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '42501', NULL, 'must-fail: anon cannot call app.activate_offer_code'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- 3. app.activate_offer_code
-- ============================================================================
-- Fixture codes for player A. earned_at/expires_at give a 30-day validity.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('71000000-0000-0000-0000-000000000001', '61000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '10 days', now() + interval '20 days'),
  ('71000000-0000-0000-0000-000000000002', '61000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '10 days', now() + interval '20 days'),
  ('71000000-0000-0000-0000-000000000003', '61000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '10 days', now() + interval '20 days'),
  ('71000000-0000-0000-0000-000000000004', '61000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '10 days', now() + interval '20 days');

-- 3a. activate: earned -> issued, binds the device and the token hash, writes the ledger.
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'tokhash-1', 'activate'),
  'issued'::app.offer_code_state, 'activate: an earned code becomes issued'
);
SELECT results_eq(
  $$SELECT activated_device_id, devicecheck_token_hash, activated_at IS NOT NULL FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('20000000-0000-0000-0000-000000000001'::uuid, 'tokhash-1'::text, true)$$,
  'activate: records activated_device_id, devicecheck_token_hash and activated_at'
);
SELECT results_eq(
  $$SELECT device_id, user_id, reward_kind::text, devicecheck_token_hash FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('20000000-0000-0000-0000-000000000001'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, 'offer'::text, 'tokhash-1'::text)$$,
  'activate: writes exactly one device_reward_ledger row (device, account, reward kind, token hash)'
);
SELECT is(
  (SELECT reserved_amount FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000001'),
  0::numeric, 'activate: an issued code reserves no budget (only a held code does)'
);

-- 3b. A SECOND device re-runs the table: state stays issued, the ledger gains the device, provenance is kept.
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000a2', 'tokhash-2', 'activate'),
  'issued'::app.offer_code_state, 'second device, decision activate: stays issued'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000001'),
  2, 'second device: the ledger now has a row per device'
);
SELECT results_eq(
  $$SELECT activated_device_id, devicecheck_token_hash FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('20000000-0000-0000-0000-000000000001'::uuid, 'tokhash-1'::text)$$,
  'second device: the FIRST activation''s device and token hash are kept (provenance is not overwritten)'
);
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000a2', 'tokhash-2', 'activate'),
  'issued'::app.offer_code_state, 'repeating the same activation is idempotent'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000001'),
  2, '...and does not duplicate the ledger row'
);

-- 3c. hold: earned -> held_review reserves the budget and pauses the expiry clock.
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'tokhash-3', 'held_review'),
  'held_review'::app.offer_code_state, 'held_review: an earned code is held'
);
SELECT results_eq(
  $$SELECT state::text, reserved_amount, expiry_paused_at IS NOT NULL, activated_device_id, devicecheck_token_hash
    FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000002'$$,
  $$VALUES ('held_review'::text, 10::numeric, true, '20000000-0000-0000-0000-000000000001'::uuid, 'tokhash-3'::text)$$,
  'held_review: reserves its face value (10), pauses the expiry clock, and still records the device and token hash'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000002'),
  10::numeric, 'held_review: offer.budget_reserved counts the held code (A2-08)'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000002'),
  0, 'held_review: nothing was ISSUED, so there is no ledger row yet'
);
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'tokhash-3', 'held_review'),
  'held_review'::app.offer_code_state, 'holding again is idempotent'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000002'),
  10::numeric, '...and does not reserve twice'
);
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000a2', 'tokhash-x', 'activate'),
  'held_review'::app.offer_code_state, 'a held code is NOT released by a later activate (even from a clean second device): a human decides'
);
SELECT results_eq(
  $$SELECT state::text, activated_device_id FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000002'$$,
  $$VALUES ('held_review'::text, '20000000-0000-0000-0000-000000000001'::uuid)$$,
  '...and nothing about it changed'
);

-- 3d. an ISSUED code can be sent back to held_review (a second device is flagged).
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000a2', 'tokhash-2', 'held_review'),
  'held_review'::app.offer_code_state, 'an issued code re-run with decision held_review becomes held'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000001'),
  10::numeric, '...and takes its reservation then'
);

-- 3e. budget cannot cover the reservation: still held (never refused), unreserved, and a human is told.
UPDATE app.offer SET budget_used = 20 WHERE id = '61000000-0000-0000-0000-000000000003'; -- 20 + 10 > 25
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review'),
  'held_review'::app.offer_code_state, 'no budget left: the code is STILL held, never refused'
);
SELECT results_eq(
  $$SELECT reserved_amount, (SELECT budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000003') FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000003'$$,
  $$VALUES (0::numeric, 0::numeric)$$,
  '...with nothing reserved (offer_budget_within_cap is never violated)'
);
SELECT is(
  (SELECT count(*)::int FROM app.review_item WHERE kind = 'held_offer_budget_unreserved' AND subject_id = '71000000-0000-0000-0000-000000000003'),
  1, '...and a review_item records the unreserved hold'
);

-- 3f. the offer is NOT required to still be live when a code is held (earned while it was).
UPDATE app.offer SET status = 'ended', valid_to = current_date - 1 WHERE id = '61000000-0000-0000-0000-000000000004';
SELECT is(
  app.activate_offer_code('71000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review'),
  'held_review'::app.offer_code_state, 'a code earned under an offer that has since ended can still be held'
);
SELECT is(
  (SELECT reserved_amount FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000004'),
  10::numeric, '...and still reserves its budget'
);

-- 3g. must-fail cells.
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  'P0002', NULL, 'must-fail: player B cannot activate player A''s offer code (the function finds no such code for B)'
);
SELECT is(
  (SELECT state::text FROM app.offer_code WHERE id = '70000000-0000-0000-0000-000000000001'), 'earned',
  '...and A''s code is untouched'
);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  '42501', NULL, 'must-fail: a device owned by ANOTHER account cannot activate a reward'
);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', gen_random_uuid(), NULL, 'activate')$$,
  '42501', NULL, 'must-fail: a nonexistent device cannot activate a reward'
);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'refuse')$$,
  '22023', NULL, 'must-fail: there is no "refuse" decision'
);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, NULL)$$,
  '22023', NULL, 'must-fail: a NULL decision is refused'
);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '55000', NULL, 'must-fail: a redeemed code cannot be activated'
);
UPDATE app.offer_code SET state = 'void' WHERE id = '70000000-0000-0000-0000-000000000001';
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review')$$,
  '55000', NULL, 'must-fail: a void code cannot be activated or held'
);
UPDATE app.offer_code SET state = 'expired' WHERE id = '70000000-0000-0000-0000-000000000001';
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '55000', NULL, 'must-fail: an expired code cannot be activated'
);
UPDATE app.offer_code SET state = 'earned', expires_at = now() - interval '1 hour' WHERE id = '70000000-0000-0000-0000-000000000001';
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '55000', NULL, 'must-fail: an earned code past expires_at (clock running) cannot be activated'
);
UPDATE app.offer_code SET expires_at = NULL WHERE id = '70000000-0000-0000-0000-000000000001';

-- 3h. the database-side backstops for table rows 2 and 3.
UPDATE app.offer_code SET rests_on_unattestable = true WHERE id = '70000000-0000-0000-0000-000000000001';
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'row 3 backstop: a code resting on an unattestable co-signal can NEVER be activated, whatever the caller decided'
);
SELECT is(
  app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review'),
  'held_review'::app.offer_code_state, '...but it can be held (precedence: an unattestable reward on a clean device is held)'
);
UPDATE app.offer_code SET state = 'earned', rests_on_unattestable = false, reserved_amount = 0, expiry_paused_at = NULL WHERE id = '70000000-0000-0000-0000-000000000001';
UPDATE app.offer SET budget_reserved = 0 WHERE id = '60000000-0000-0000-0000-000000000001';

INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, held_review)
VALUES ('42000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-00000000000a', 'crs_x1', 'fac_x', current_date - 40, 'v1', 'confirmed', true);
UPDATE app.offer_code SET play_id = '42000000-0000-0000-0000-0000000000f1' WHERE id = '70000000-0000-0000-0000-000000000001';
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'row 3 backstop: a code backed by a held_review play cannot be activated'
);
UPDATE app.offer_code SET play_id = NULL WHERE id = '70000000-0000-0000-0000-000000000001';

INSERT INTO app.fraud_signal (id, user_id, kind, detail) VALUES
  ('f2000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'attestation_failed', '{}'::jsonb);
SELECT throws_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'row 2 backstop: an open attestation_failed fraud_signal holds the account''s activations at the database too'
);
SELECT lives_ok(
  $$SELECT app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review')$$,
  '...while holding is still allowed'
);
UPDATE app.offer_code SET state = 'earned', reserved_amount = 0, expiry_paused_at = NULL WHERE id = '70000000-0000-0000-0000-000000000001';
UPDATE app.offer SET budget_reserved = 0 WHERE id = '60000000-0000-0000-0000-000000000001';
UPDATE app.fraud_signal SET cleared_at = now() WHERE id = 'f2000000-0000-0000-0000-000000000001';
SELECT is(
  app.activate_offer_code('70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'once the signal is cleared the account can activate again'
);
SELECT lives_ok(
  $$SET CONSTRAINTS ALL IMMEDIATE$$,
  'the play-guard constraint triggers (0017) are satisfied by an activation that follows the table'
);
SET CONSTRAINTS ALL DEFERRED;

-- ============================================================================
-- 4. app.resolve_held_offer_code
-- ============================================================================
-- 71..0002 is held (reserved 10 against offer 61..02), earned 10 days ago with a 30-day validity.
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('71000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-00000000000b')$$,
  '42501', NULL, 'must-fail: a non-admin cannot resolve a held code'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('71000000-0000-0000-0000-000000000002', true, NULL)$$,
  '42501', NULL, 'must-fail: resolving with no resolver is refused'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('71000000-0000-0000-0000-000000000002', NULL, '00000000-0000-0000-0000-4000000000d0')$$,
  '22023', NULL, 'must-fail: a NULL decision is refused'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code(gen_random_uuid(), true, '00000000-0000-0000-0000-4000000000d0')$$,
  'P0002', NULL, 'must-fail: an unknown code'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('70000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '55000', NULL, 'must-fail: only a held code can be resolved (a redeemed one cannot)'
);

-- The offer ENDS while the code is in review; an approved code is still honoured.
UPDATE app.offer SET status = 'ended', valid_to = current_date - 1 WHERE id = '61000000-0000-0000-0000-000000000002';
SELECT is(
  app.resolve_held_offer_code('71000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0'),
  'issued'::app.offer_code_state, 'approve: a held code whose offer ended during review is honoured -> issued'
);
SELECT results_eq(
  $$SELECT state::text, expiry_paused_at IS NULL, expires_at = now() + interval '30 days', reserved_amount
    FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000002'$$,
  $$VALUES ('issued'::text, true, true, 10::numeric)$$,
  'approve: the expiry clock resumes with the FULL 30-day validity counted from the approval date, and the reservation is kept'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000002'),
  10::numeric, 'approve: offer.budget_reserved still holds the code''s 10 — the reservation pays for it, though the offer has ended'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000002' AND device_id = '20000000-0000-0000-0000-000000000001'),
  1, 'approve: the ledger now records the activation (the code is issued)'
);
SELECT results_eq(
  $$SELECT actor_user_id, action, subject_table, subject_id FROM app.audit_log WHERE subject_id = '71000000-0000-0000-0000-000000000002'$$,
  $$VALUES ('00000000-0000-0000-0000-4000000000d0'::uuid, 'held_reward_approved'::text, 'offer_code'::text, '71000000-0000-0000-0000-000000000002'::text)$$,
  'approve: audit_log records who approved it'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('71000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '55000', NULL, 'must-fail: a code that was already resolved cannot be approved again'
);
-- the honoured code can still be consumed: the reservation turns into spend.
SELECT lives_ok(
  $$SELECT app.consume_offer_budget('61000000-0000-0000-0000-000000000002', 10)$$,
  'the reserved budget can be consumed at redemption even though the offer has ended'
);
SELECT results_eq(
  $$SELECT budget_used, budget_reserved FROM app.offer WHERE id = '61000000-0000-0000-0000-000000000002'$$,
  $$VALUES (10::numeric, 0::numeric)$$,
  '...moving 10 from reserved to used'
);

-- reject: the reservation is released.
SELECT is(
  app.resolve_held_offer_code('71000000-0000-0000-0000-000000000004', false, '00000000-0000-0000-0000-4000000000d0'),
  'void'::app.offer_code_state, 'reject: a held code becomes void'
);
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '71000000-0000-0000-0000-000000000004'$$,
  $$VALUES (0::numeric, 0::numeric)$$,
  'reject: the reservation is released (code and offer both back to 0)'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000004'),
  0, 'reject: nothing was issued, so no ledger row'
);

-- a held code with no recorded device approves without a ledger row (device was detached).
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, activated_device_id) VALUES
  ('71000000-0000-0000-0000-000000000005', '61000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now(), NULL, NULL);
SELECT is(
  app.resolve_held_offer_code('71000000-0000-0000-0000-000000000005', true, '00000000-0000-0000-0000-4000000000d0'),
  'issued'::app.offer_code_state, 'approve: a code with no expiry stays without one, and a detached device writes no ledger row'
);
SELECT results_eq(
  $$SELECT expires_at IS NULL, (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '71000000-0000-0000-0000-000000000005') FROM app.offer_code WHERE id = '71000000-0000-0000-0000-000000000005'$$,
  $$VALUES (true, 0)$$, '...as asserted'
);

-- ============================================================================
-- 5. app.activate_entitlement / app.resolve_held_entitlement  (player B)
-- ============================================================================
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state) VALUES
  ('51000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'special_marker', 'trl_t', 'earned'),
  ('51000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', 'special_marker', 'trl_u', 'earned'),
  ('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', 'special_marker', 'trl_v', 'earned');

SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', 'etok-1', 'activate'),
  'redeemable'::app.entitlement_state, 'activate: an earned entitlement becomes redeemable'
);
SELECT results_eq(
  $$SELECT activated_device_id, devicecheck_token_hash, activated_at IS NOT NULL FROM app.entitlement WHERE id = '51000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('20000000-0000-0000-0000-0000000000b1'::uuid, 'etok-1'::text, true)$$,
  'activate: records activated_device_id, devicecheck_token_hash and activated_at'
);
SELECT results_eq(
  $$SELECT reward_kind::text, user_id FROM app.device_reward_ledger WHERE reward_id = '51000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('special_marker'::text, '00000000-0000-0000-0000-00000000000b'::uuid)$$,
  'activate: one ledger row of kind special_marker'
);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', 'etok-1', 'activate'),
  'redeemable'::app.entitlement_state, 'idempotent for the same device'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '51000000-0000-0000-0000-000000000001'),
  1, '...with no duplicate ledger row'
);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'held_review'),
  'held_review'::app.entitlement_state, 'held_review: an earned entitlement is held (reserves no unit anywhere)'
);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate'),
  'held_review'::app.entitlement_state, 'a held entitlement is not released by a later activate'
);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'held_review'),
  'held_review'::app.entitlement_state, 'a redeemable entitlement re-run on a flagged device goes back to held_review'
);

SELECT throws_ok(
  $$SELECT app.activate_entitlement('50000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  'P0002', NULL, 'must-fail: player B cannot activate player A''s entitlement'
);
SELECT throws_ok(
  $$SELECT app.activate_entitlement('50000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  '42501', NULL, 'must-fail: B''s device cannot activate A''s entitlement either'
);
SELECT throws_ok(
  $$SELECT app.activate_entitlement('50000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '55000', NULL, 'must-fail: a redeemed entitlement cannot be activated'
);
UPDATE app.entitlement SET state = 'vouchered' WHERE id = '51000000-0000-0000-0000-000000000003';
SELECT throws_ok(
  $$SELECT app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  '55000', NULL, 'must-fail: a vouchered entitlement is already past activation'
);
UPDATE app.entitlement SET state = 'void' WHERE id = '51000000-0000-0000-0000-000000000003';
SELECT throws_ok(
  $$SELECT app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'held_review')$$,
  '55000', NULL, 'must-fail: a void entitlement cannot be held'
);
SELECT throws_ok(
  $$SELECT app.activate_entitlement('51000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'refuse')$$,
  '22023', NULL, 'must-fail: no "refuse" decision for an entitlement either'
);

-- backstops for entitlements
UPDATE app.entitlement SET state = 'earned', rests_on_unattestable = true WHERE id = '51000000-0000-0000-0000-000000000003';
SELECT throws_ok(
  $$SELECT app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  '23514', NULL, 'row 3 backstop: an entitlement resting on an unattestable co-signal can never be activated'
);
UPDATE app.entitlement SET rests_on_unattestable = false WHERE id = '51000000-0000-0000-0000-000000000003';
INSERT INTO app.fraud_signal (id, user_id, kind, detail) VALUES
  ('f2000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', 'attestation_failed', '{}'::jsonb);
SELECT throws_ok(
  $$SELECT app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate')$$,
  '23514', NULL, 'row 2 backstop: an open attestation_failed signal holds the account''s entitlement activations'
);
UPDATE app.fraud_signal SET cleared_at = now() WHERE id = 'f2000000-0000-0000-0000-000000000002';
-- (another account's open signal does not affect B)
INSERT INTO app.fraud_signal (id, user_id, kind, detail) VALUES
  ('f2000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', 'attestation_failed', '{}'::jsonb);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate'),
  'redeemable'::app.entitlement_state, 'another account''s open signal does not hold B (row 2 is per account)'
);

-- resolve
SELECT throws_ok(
  $$SELECT app.resolve_held_entitlement('51000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-00000000000b')$$,
  '42501', NULL, 'must-fail: a non-admin cannot resolve a held entitlement'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_entitlement('51000000-0000-0000-0000-000000000003', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '55000', NULL, 'must-fail: only a held entitlement can be resolved'
);
SELECT is(
  app.resolve_held_entitlement('51000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0'),
  'redeemable'::app.entitlement_state, 'approve: a held entitlement becomes redeemable'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '51000000-0000-0000-0000-000000000002'),
  1, 'approve: the ledger records the activation'
);
SELECT is(
  app.resolve_held_entitlement('51000000-0000-0000-0000-000000000001', false, '00000000-0000-0000-0000-4000000000d0'),
  'void'::app.entitlement_state, 'reject: a held entitlement becomes void'
);
SELECT is(
  (SELECT count(*)::int FROM app.audit_log WHERE subject_table = 'entitlement' AND action IN ('held_reward_approved', 'held_reward_rejected')),
  2, 'both decisions are audited'
);

-- ============================================================================
-- 5b. app.release_account_reservations (account deletion hands budget back)
-- ============================================================================
-- Player B: one held code (reserved 10), one approved-unredeemed code (issued, reserved 5),
-- one redeemed code whose reservation was consumed (reserved 0), one void code with a stale
-- reserved_amount that must NOT be touched. Player A has an unrelated held code (reserved 10).
UPDATE app.offer SET budget_reserved = 30, budget_cap = 100 WHERE id = '61000000-0000-0000-0000-000000000006';
UPDATE app.offer SET budget_reserved = 5 WHERE id = '61000000-0000-0000-0000-000000000007';
UPDATE app.offer SET budget_reserved = 7, budget_cap = 100 WHERE id = '61000000-0000-0000-0000-000000000008';
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount) VALUES
  ('71000000-0000-0000-0000-0000000000b1', '61000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'held_review', 10),
  ('71000000-0000-0000-0000-0000000000b2', '61000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'issued', 5),
  ('71000000-0000-0000-0000-0000000000b3', '61000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'redeemed', 0),
  ('71000000-0000-0000-0000-0000000000b4', '61000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'void', 7),
  ('71000000-0000-0000-0000-0000000000a9', '61000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', 10);
SELECT is(
  app.release_account_reservations('00000000-0000-0000-0000-00000000000b'),
  15::numeric, 'release_account_reservations: returns the total handed back (10 held + 5 approved-unredeemed)'
);
SELECT results_eq(
  $$SELECT id::text, reserved_amount FROM app.offer_code WHERE user_id = '00000000-0000-0000-0000-00000000000b' AND id::text LIKE '71000000-0000-0000-0000-0000000000b%' ORDER BY id$$,
  $$VALUES ('71000000-0000-0000-0000-0000000000b1'::text, 0::numeric), ('71000000-0000-0000-0000-0000000000b2', 0), ('71000000-0000-0000-0000-0000000000b3', 0), ('71000000-0000-0000-0000-0000000000b4', 7)$$,
  '...zeroing the held and issued codes, leaving a redeemed code (0) and a void code (7, stale: not outstanding) alone'
);
SELECT results_eq(
  $$SELECT id::text, budget_reserved FROM app.offer WHERE id IN ('61000000-0000-0000-0000-000000000006', '61000000-0000-0000-0000-000000000007', '61000000-0000-0000-0000-000000000008') ORDER BY id$$,
  $$VALUES ('61000000-0000-0000-0000-000000000006'::text, 20::numeric), ('61000000-0000-0000-0000-000000000007', 0), ('61000000-0000-0000-0000-000000000008', 7)$$,
  '...and the offers'' budget_reserved went down by exactly what was released (30 -> 20 for the shared offer: player A''s 10 is untouched)'
);
SELECT is(
  app.release_account_reservations('00000000-0000-0000-0000-00000000000b'),
  0::numeric, 'idempotent: a second call (a retried deletion) releases nothing'
);
SELECT is(
  (SELECT reserved_amount FROM app.offer_code WHERE id = '71000000-0000-0000-0000-0000000000a9'),
  10::numeric, 'another account''s reservation is never touched'
);
SELECT throws_ok(
  $$SELECT app.release_account_reservations(NULL)$$,
  '22023', NULL, 'must-fail: a NULL user is refused'
);
SELECT is(
  app.release_account_reservations(gen_random_uuid()),
  0::numeric, 'an unknown user releases nothing'
);

-- ============================================================================
-- 6. Ledger idempotency / uniqueness
-- ============================================================================
SELECT throws_ok(
  $$INSERT INTO app.device_reward_ledger (device_id, user_id, reward_kind, reward_id)
    VALUES ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'offer', '71000000-0000-0000-0000-000000000001')$$,
  '23505', NULL, 'the ledger cannot hold the same (device, kind, reward) twice'
);

-- ============================================================================
-- 7. Unchanged invariants this migration must not weaken
-- ============================================================================
SELECT is(
  (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relkind = 'r' AND NOT (c.relrowsecurity AND c.relforcerowsecurity)),
  0, 'every app table still has ENABLE + FORCE ROW LEVEL SECURITY'
);
SELECT is(
  (SELECT count(*)::int FROM information_schema.role_table_grants
   WHERE table_schema = 'app' AND table_name IN ('offer_code', 'entitlement', 'device_reward_ledger', 'device', 'offer', 'fraud_signal')
     AND grantee IN ('anon', 'authenticated') AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE')),
  0, 'no client role holds INSERT/UPDATE/DELETE on any table this feature writes'
);

SELECT * FROM finish();
ROLLBACK;
