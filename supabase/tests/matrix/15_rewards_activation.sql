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
SELECT plan(224);

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

-- Offers for the gate-round sections below (budget_cap 100: room for several reservations each).
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
SELECT ('62000000-0000-0000-0000-0000000000' || lpad(n::text, 2, '0'))::uuid, 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'
FROM generate_series(1, 20) AS n;

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
  $$UPDATE app.device SET attest_public_key = '\x0102030405'::bytea, attest_key_id = encode(sha256('\x0102030405'::bytea), 'base64') WHERE id = '20000000-0000-0000-0000-0000000000a2'$$,
  '23514', NULL, 'device.attest_public_key must be exactly 65 bytes (an uncompressed P-256 point) or NULL'
);
SELECT lives_ok(
  $$UPDATE app.device SET attest_public_key = decode('04' || repeat('ab', 64), 'hex'), attest_key_id = encode(sha256(decode('04' || repeat('ab', 64), 'hex')), 'base64') WHERE id = '20000000-0000-0000-0000-0000000000a2'$$,
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
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '71000000-0000-0000-0000-000000000001'$$,
  $$VALUES (10::numeric, 10::numeric)$$,
  'activate: an earned code that holds no reservation takes one (its face value) as it is issued (the earn path reserves nothing today — 0027 header)'
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
  'earned'::app.offer_code_state, 'approve (H2): a held code NO DEVICE ever ran the table on returns to earned, not issued — it keeps no expiry and writes no ledger row'
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
-- 8. THE RESERVATION TRIGGER (gate H3 / F13): held_review by ANY path reserves
--    and pauses; void / expired / DELETE release; explicit + trigger paths are
--    idempotent against each other.
-- ============================================================================
-- (player A's open attestation_failed signal from section 5 would hold every activation below)
UPDATE app.fraud_signal SET cleared_at = now() WHERE id = 'f2000000-0000-0000-0000-000000000003';
SELECT has_trigger('app', 'offer_code', 'offer_code_reservation_sync_trg', 'the reservation trigger exists on offer_code');

INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, held_review) VALUES
  ('42000000-0000-0000-0000-0000000000f2', '00000000-0000-0000-0000-00000000000a', 'crs_x1', 'fac_x', current_date - 50, 'v1', 'confirmed', false);
-- 72..01: earned, no reservation.  72..02: issued WITH an earn-time reservation (10) and 20 days of validity left.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, play_id, state, earned_at, expires_at, activated_device_id, reserved_amount) VALUES
  ('72000000-0000-0000-0000-000000000001', '62000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'fac_x', '42000000-0000-0000-0000-0000000000f2', 'earned', now() - interval '10 days', now() + interval '20 days', NULL, 0),
  ('72000000-0000-0000-0000-000000000002', '62000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', 'fac_x', '42000000-0000-0000-0000-0000000000f2', 'issued', now() - interval '10 days', now() + interval '20 days', '20000000-0000-0000-0000-000000000001', 10);
UPDATE app.offer SET budget_reserved = 10 WHERE id = '62000000-0000-0000-0000-000000000002';

-- The 0017 play-hold cascade writes ONLY `state`. It used to reserve nothing and pause nothing.
UPDATE app.play SET held_review = true WHERE id = '42000000-0000-0000-0000-0000000000f2';
SELECT results_eq(
  $$SELECT state::text, reserved_amount, expiry_paused_at IS NOT NULL, issued_before_hold FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('held_review'::text, 10::numeric, true, false)$$,
  'H3: a play-hold cascade moves an earned code to held_review AND reserves its face value AND pauses its expiry clock'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000001'), 10::numeric,
  'H3: ...and offer.budget_reserved counts it'
);
SELECT results_eq(
  $$SELECT state::text, reserved_amount, issued_before_hold, expiry_paused_at IS NOT NULL, expiry_remaining = interval '20 days' FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000002'$$,
  $$VALUES ('held_review'::text, 10::numeric, true, true, true)$$,
  'H3: an ISSUED code the cascade holds keeps its earn-time reservation (no double reservation), remembers it was issued, and records the validity it had left'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000002'), 10::numeric,
  'H3: ...idempotent against the earn-time reservation: offer.budget_reserved is still 10, not 20'
);
SELECT lives_ok($$SET CONSTRAINTS ALL IMMEDIATE$$, 'the play-guard constraint triggers (0017) accept the cascade-held codes');
SET CONSTRAINTS ALL DEFERRED;

-- Approval keeps the reservation. The reviewer clears the play first (the 0017 guard refuses a non-held code over a held play).
UPDATE app.play SET held_review = false WHERE id = '42000000-0000-0000-0000-0000000000f2';
SELECT is(
  app.resolve_held_offer_code('72000000-0000-0000-0000-000000000001', true, '00000000-0000-0000-0000-4000000000d0'),
  'earned'::app.offer_code_state, 'H2/H3: approving the cascade-held code (no device ever ran the table) returns it to earned'
);
SELECT results_eq(
  $$SELECT reserved_amount, review_cleared_at IS NOT NULL, expiry_paused_at IS NULL, activated_device_id IS NULL FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000001'$$,
  $$VALUES (10::numeric, true, true, true)$$,
  'H3: approval KEEPS the reservation, sets review_cleared_at, resumes the clock, and does not invent a device'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000001'), 10::numeric,
  'H3: ...offer.budget_reserved unchanged by an approval'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '72000000-0000-0000-0000-000000000001'), 0,
  'H2: no ledger row — nothing was issued'
);

-- Re-hold: an ISSUED code that was held and approved gets its REMAINING validity back, not a fresh 30 days.
SELECT is(
  app.resolve_held_offer_code('72000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0'),
  'issued'::app.offer_code_state, 'approving a held code that DID run on a device -> issued'
);
SELECT results_eq(
  $$SELECT expires_at = now() + interval '20 days', issued_before_hold, expiry_remaining IS NULL, reserved_amount FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000002'$$,
  $$VALUES (true, false, true, 10::numeric)$$,
  'LOW re-hold: a code issued before it was held gets its REMAINING 20 days (a self-induced re-hold is not a free renewal to a fresh 30), the reservation kept'
);

-- Reject (via the resolver) and every other route to void / expired release EXACTLY once.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('72000000-0000-0000-0000-000000000003', '62000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now(), now() + interval '30 days');
SELECT app.activate_offer_code('72000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review');
SELECT is((SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000003'), 10::numeric, 'a held activation reserved 10 (via the trigger)');
SELECT is(
  app.resolve_held_offer_code('72000000-0000-0000-0000-000000000003', false, '00000000-0000-0000-0000-4000000000d0'),
  'void'::app.offer_code_state, 'reject -> void'
);
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '72000000-0000-0000-0000-000000000003'$$,
  $$VALUES (0::numeric, 0::numeric)$$,
  'H3: reject releases the reservation (code and offer back to 0), once'
);

-- a code INSERTED as held_review (any writer) reserves and pauses; then a plain void releases.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at) VALUES
  ('72000000-0000-0000-0000-000000000004', '62000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now());
SELECT results_eq(
  $$SELECT reserved_amount, expiry_paused_at IS NOT NULL FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000004'$$,
  $$VALUES (10::numeric, true)$$,
  'H3: a code INSERTED as held_review reserves and pauses (the earn path holding a code outright)'
);
UPDATE app.offer_code SET state = 'void' WHERE id = '72000000-0000-0000-0000-000000000004';
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '72000000-0000-0000-0000-000000000004'$$,
  $$VALUES (0::numeric, 0::numeric)$$,
  'H3: a bare UPDATE ... SET state = void releases (the 0017 "resolved by review" terminal) — whoever writes it'
);
UPDATE app.offer_code SET state = 'void' WHERE id = '72000000-0000-0000-0000-000000000004';
SELECT is((SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000004'), 0::numeric, 'idempotent: voiding again releases nothing more');

-- expired releases too.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, reserved_amount) VALUES
  ('72000000-0000-0000-0000-000000000005', '62000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'issued', now(), now() + interval '1 day', 10);
UPDATE app.offer SET budget_reserved = 10 WHERE id = '62000000-0000-0000-0000-000000000005';
UPDATE app.offer_code SET state = 'expired' WHERE id = '72000000-0000-0000-0000-000000000005';
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '72000000-0000-0000-0000-000000000005'$$,
  $$VALUES (0::numeric, 0::numeric)$$,
  'H3: expiry releases the reservation'
);

-- DELETE releases (when the deleting role can update the offer) — and a void code's stale amount is NOT released.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at) VALUES
  ('72000000-0000-0000-0000-000000000006', '62000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now());
SELECT is((SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000006'), 10::numeric, 'a held code holds 10');
DELETE FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000006';
SELECT is((SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000006'), 0::numeric, 'H3/M1: DELETE of a code that holds a reservation releases it');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, reserved_amount) VALUES
  ('72000000-0000-0000-0000-000000000007', '62000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'void', now(), 7);
UPDATE app.offer SET budget_reserved = 7 WHERE id = '62000000-0000-0000-0000-000000000007';
DELETE FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000007';
SELECT is((SELECT budget_reserved FROM app.offer WHERE id = '62000000-0000-0000-0000-000000000007'), 7::numeric, 'DELETE of a void code does not release its stale reserved_amount (not outstanding)');

-- the cap cannot cover it: held anyway, unreserved, a review_item says so.
UPDATE app.offer SET budget_cap = 5 WHERE id = '62000000-0000-0000-0000-000000000008';
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at) VALUES
  ('72000000-0000-0000-0000-000000000008', '62000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now());
SELECT results_eq(
  $$SELECT reserved_amount, (SELECT count(*)::int FROM app.review_item WHERE kind = 'held_offer_budget_unreserved' AND subject_id = '72000000-0000-0000-0000-000000000008') FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000008'$$,
  $$VALUES (0::numeric, 1)$$,
  'H3: a hold the cap cannot cover is never refused: held, unreserved, and a review_item says so'
);

-- ============================================================================
-- 9. REVIEW-CLEARED (gate H2) and the budget model (gate M3)
-- ============================================================================
-- 73..01: a held code NO device ever ran the table on, resting on an unattestable co-signal.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, rests_on_unattestable) VALUES
  ('73000000-0000-0000-0000-000000000001', '62000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now(), true),
  ('73000000-0000-0000-0000-000000000002', '62000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now(), true),
  ('73000000-0000-0000-0000-000000000003', '62000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', now(), true);
SELECT is(
  app.resolve_held_offer_code('73000000-0000-0000-0000-000000000001', true, '00000000-0000-0000-0000-4000000000d0'),
  'earned'::app.offer_code_state, 'H2 probe: approving a held code with activated_device_id NULL returns it to earned (NOT issued)'
);
SELECT results_eq(
  $$SELECT state::text, review_cleared_at IS NOT NULL, rests_on_unattestable FROM app.offer_code WHERE id = '73000000-0000-0000-0000-000000000001'$$,
  $$VALUES ('earned'::text, true, true)$$,
  'H2: review_cleared_at is the marker; the flag itself is left as the earning path wrote it'
);
SELECT is(
  app.activate_offer_code('73000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'H2: the cleared code can now be activated on a real device (the row 3 backstop treats the unattestable basis as cleared)'
);
SELECT is(
  (SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '73000000-0000-0000-0000-000000000001'), 1,
  'H2: ...and only THEN does the ledger record it'
);

-- N3: a review of ONE reward never waives an ACCOUNT-level signal. An open
-- attestation_failed signal holds the cleared code whether it was raised before or
-- after the review; only the signal being CLEARED (cleared_at) releases it.
SELECT app.resolve_held_offer_code('73000000-0000-0000-0000-000000000002', true, '00000000-0000-0000-0000-4000000000d0');
INSERT INTO app.fraud_signal (id, user_id, kind, detail, created_at) VALUES
  ('f2000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-00000000000a', 'attestation_failed', '{}'::jsonb, now() - interval '1 hour');
SELECT throws_ok(
  $$SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'N3 probe E: an approved (review-cleared) code is STILL refused while the account has an open attestation_failed signal raised BEFORE the review'
);
SELECT app.resolve_held_offer_code('73000000-0000-0000-0000-000000000003', true, '00000000-0000-0000-0000-4000000000d0');
INSERT INTO app.fraud_signal (id, user_id, kind, detail, created_at) VALUES
  ('f2000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-00000000000a', 'attestation_failed', '{}'::jsonb, now() + interval '1 hour');
SELECT throws_ok(
  $$SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'N3: ...and its sibling, with a signal raised AFTER the review, is refused too'
);
UPDATE app.fraud_signal SET cleared_at = now() WHERE id IN ('f2000000-0000-0000-0000-000000000011', 'f2000000-0000-0000-0000-000000000012');
SELECT is(
  app.activate_offer_code('73000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'N3: once the signal is CLEARED, the approved code activates'
);
SELECT is(
  app.activate_offer_code('73000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'N3: ...and so does its sibling'
);
DELETE FROM app.fraud_signal WHERE id IN ('f2000000-0000-0000-0000-000000000011', 'f2000000-0000-0000-0000-000000000012');

-- a held PLAY is not cleared by a review of the code.
INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, held_review) VALUES
  ('42000000-0000-0000-0000-0000000000f3', '00000000-0000-0000-0000-00000000000a', 'crs_x1', 'fac_x', current_date - 60, 'v1', 'confirmed', true);
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, play_id, state, earned_at, review_cleared_at) VALUES
  ('73000000-0000-0000-0000-000000000004', '62000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-00000000000a', 'fac_x', '42000000-0000-0000-0000-0000000000f3', 'earned', now(), now());
SELECT throws_ok(
  $$SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate')$$,
  '23514', NULL, 'H2: a review-cleared code whose backing play is STILL held_review cannot be activated'
);
UPDATE app.offer_code SET play_id = NULL WHERE id = '73000000-0000-0000-0000-000000000004';
DELETE FROM app.play WHERE id = '42000000-0000-0000-0000-0000000000f3';

-- M3: an earn-time reservation makes both activation paths idempotent; an ended offer does not block activation.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, reserved_amount) VALUES
  ('73000000-0000-0000-0000-000000000005', '62000000-0000-0000-0000-000000000013', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now(), now() + interval '30 days', 10),
  ('73000000-0000-0000-0000-000000000006', '62000000-0000-0000-0000-000000000014', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now(), now() + interval '30 days', 10);
UPDATE app.offer SET budget_reserved = 10 WHERE id IN ('62000000-0000-0000-0000-000000000013', '62000000-0000-0000-0000-000000000014');
SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate');
SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review');
SELECT results_eq(
  $$SELECT budget_reserved FROM app.offer WHERE id IN ('62000000-0000-0000-0000-000000000013', '62000000-0000-0000-0000-000000000014') ORDER BY id$$,
  $$VALUES (10::numeric), (10::numeric)$$,
  'M3: activating (issue OR hold) a code that already holds an earn-time reservation does not reserve again'
);
UPDATE app.offer SET status = 'ended', valid_to = current_date - 1 WHERE id = '62000000-0000-0000-0000-000000000015';
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('73000000-0000-0000-0000-000000000007', '62000000-0000-0000-0000-000000000015', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '5 days', now() + interval '25 days');
SELECT is(
  app.activate_offer_code('73000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'M3 decision: an ENDED offer does not block a clean activation of a code earned while it was live (the code''s own expiry bounds it)'
);
SELECT is((SELECT reserved_amount FROM app.offer_code WHERE id = '73000000-0000-0000-0000-000000000007'), 10::numeric, '...and the reservation is taken, since the offer''s cap still bounds the spend');
UPDATE app.offer SET budget_cap = 5 WHERE id = '62000000-0000-0000-0000-000000000016';
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at) VALUES
  ('73000000-0000-0000-0000-000000000008', '62000000-0000-0000-0000-000000000016', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now());
SELECT is(
  app.activate_offer_code('73000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'held_review'::app.offer_code_state, 'N1: a CLEAN activation the cap cannot reserve for is HELD, never issued unreserved (and never refused)'
);
SELECT results_eq(
  $$SELECT reserved_amount, hold_detail ->> 'heldFor', (SELECT count(*)::int FROM app.review_item WHERE kind = 'held_offer_budget_unreserved' AND subject_id = '73000000-0000-0000-0000-000000000008') FROM app.offer_code WHERE id = '73000000-0000-0000-0000-000000000008'$$,
  $$VALUES (0::numeric, 'offer_budget'::text, 1)$$, '...unreserved, hold_detail says why, and exactly ONE review_item (the trigger''s second attempt does not duplicate it)'
);

-- hold_detail: written on a hold, only what the reviewer needs.
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at) VALUES
  ('73000000-0000-0000-0000-000000000009', '62000000-0000-0000-0000-000000000017', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now());
SELECT app.activate_offer_code('73000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'held_review',
  '{"matchedRows":[3,4],"primaryRow":3,"bits":{"bit0":true,"bit1":false},"deviceCheckLastUpdateMonth":"2026-02"}'::jsonb);
SELECT is(
  (SELECT hold_detail -> 'matchedRows' FROM app.offer_code WHERE id = '73000000-0000-0000-0000-000000000009'),
  '[3, 4]'::jsonb, 'M2: the hold records every matched row (and the bits, and the DeviceCheck month) for the reviewer'
);

-- entitlements follow the same H2 rule.
-- (reuse B's 51..03: put it back into a held state no device ran the table on)
UPDATE app.entitlement SET state = 'held_review', rests_on_unattestable = true, activated_device_id = NULL, review_cleared_at = NULL
WHERE id = '51000000-0000-0000-0000-000000000003';
SELECT is(
  app.resolve_held_entitlement('51000000-0000-0000-0000-000000000003', true, '00000000-0000-0000-0000-4000000000d0'),
  'earned'::app.entitlement_state, 'H2: an entitlement no device ran the table on is approved back to earned too'
);
SELECT is(
  app.activate_entitlement('51000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate'),
  'redeemable'::app.entitlement_state, 'H2: ...and is activatable on a device once the unattestable basis was cleared'
);

-- ============================================================================
-- 10. The Android A20 substitute (gate M4)
-- ============================================================================
SELECT has_column('app', 'device', 'install_link_hash', 'device.install_link_hash exists');
SELECT has_column('app', 'device', 'fraud_voided_at', 'device.fraud_voided_at exists');
SELECT throws_ok(
  $$UPDATE app.device SET install_link_hash = 'not-a-hash' WHERE id = '20000000-0000-0000-0000-0000000000a2'$$,
  '23514', NULL, 'install_link_hash must be 64 lowercase hex characters'
);
INSERT INTO app.device (id, user_id, platform, install_link_hash) VALUES
  ('20000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-1000000000a1', 'android', repeat('a', 64)),
  ('20000000-0000-0000-0000-0000000000c2', '00000000-0000-0000-0000-2000000000b1', 'android', repeat('a', 64)),
  ('20000000-0000-0000-0000-0000000000c3', '00000000-0000-0000-0000-3000000000c1', 'android', repeat('b', 64));
UPDATE app.device SET install_link_hash = repeat('a', 64) WHERE id = '20000000-0000-0000-0000-0000000000a2';
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000a2')$$,
  $$VALUES (3, false)$$, 'device_link_signals: three accounts share an install link -> "> 2 accounts" is derivable'
);
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000c3')$$,
  $$VALUES (1, false)$$, 'device_link_signals: a lone install is one account'
);
SELECT results_eq(
  $$SELECT accounts_on_install FROM app.device_link_signals('20000000-0000-0000-0000-000000000001')$$,
  $$VALUES (1)$$, 'device_link_signals: a device with no link keys counts only itself'
);
-- (0038: a key is written whole and bound -- the key id is the base64 SHA-256 of the public key -- so two devices sharing a key share both.)
UPDATE app.device SET attest_public_key = decode('04' || repeat('5a', 64), 'hex'),
  attest_key_id = encode(sha256(decode('04' || repeat('5a', 64), 'hex')), 'base64') WHERE id IN ('20000000-0000-0000-0000-0000000000b1', '20000000-0000-0000-0000-0000000000c3');
SELECT results_eq(
  $$SELECT accounts_on_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000c3')$$,
  $$VALUES (2)$$, 'device_link_signals: rows also link by an equal attest key id'
);
SELECT throws_ok(
  $$SELECT app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-1000000000a1', '00000000-0000-0000-0000-00000000000b')$$,
  '42501', NULL, 'must-fail: a non-admin cannot mark an account''s devices fraud-voided'
);
SELECT throws_ok(
  $$SELECT app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-1000000000a1', NULL)$$,
  '42501', NULL, 'must-fail: no resolver, no marking'
);
SELECT is(
  app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-1000000000a1', '00000000-0000-0000-0000-4000000000d0'),
  1, 'an admin marks every device of the voided account (1)'
);
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000a2')$$,
  $$VALUES (3, true)$$, 'device_link_signals: "an account voided for fraud used this install" (the bit1 substitute) — seen from ANOTHER account''s device on the same install'
);
SELECT is(
  (SELECT count(*)::int FROM app.audit_log WHERE action = 'account_devices_fraud_voided' AND subject_id = '00000000-0000-0000-0000-1000000000a1'),
  1, 'the marking is audited'
);

-- ============================================================================
-- 8b. N1 probe G — the cap covers ONE code; two accounts activate cleanly.
-- ============================================================================
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status) VALUES
  ('63000000-0000-0000-0000-000000000001', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('74000000-0000-0000-0000-00000000000a', '63000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now(), now() + interval '30 days'),
  ('74000000-0000-0000-0000-00000000000b', '63000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'earned', now(), now() + interval '30 days');
SELECT is(
  app.activate_offer_code('74000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', NULL, 'activate'),
  'issued'::app.offer_code_state, 'N1 probe G: the first code on a cap that covers one is issued and reserved'
);
SELECT is(
  app.activate_offer_code('74000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-0000000000b1', NULL, 'activate'),
  'held_review'::app.offer_code_state, 'N1 probe G: the second is HELD (it used to be issued with reserved_amount 0)'
);
SELECT results_eq(
  $$SELECT (SELECT reserved_amount FROM app.offer_code WHERE id = '74000000-0000-0000-0000-00000000000a'),
           (SELECT reserved_amount FROM app.offer_code WHERE id = '74000000-0000-0000-0000-00000000000b'),
           (SELECT budget_reserved FROM app.offer WHERE id = '63000000-0000-0000-0000-000000000001')$$,
  $$VALUES (10::numeric, 0::numeric, 10::numeric)$$, 'N1: the books reconcile: only the issued code holds the reservation'
);
SELECT lives_ok(
  $$SELECT app.consume_offer_budget('63000000-0000-0000-0000-000000000001', 10)$$,
  'N1: the till pays the issued code'
);
SELECT results_eq(
  $$SELECT budget_used, budget_reserved FROM app.offer WHERE id = '63000000-0000-0000-0000-000000000001'$$,
  $$VALUES (10::numeric, 0::numeric)$$, '...and the cap is exactly spent: nothing is owed to the held code'
);
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code('74000000-0000-0000-0000-00000000000b', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '23514', NULL, 'N1: approving the held code is REFUSED while the cap still cannot cover it (raise the cap or reject)'
);
UPDATE app.offer SET budget_cap = 20 WHERE id = '63000000-0000-0000-0000-000000000001';
SELECT is(
  app.resolve_held_offer_code('74000000-0000-0000-0000-00000000000b', true, '00000000-0000-0000-0000-4000000000d0'),
  'issued'::app.offer_code_state, 'N1: once the cap is raised, approval issues it...'
);
SELECT results_eq(
  $$SELECT c.reserved_amount, o.budget_reserved FROM app.offer_code c JOIN app.offer o ON o.id = c.offer_id WHERE c.id = '74000000-0000-0000-0000-00000000000b'$$,
  $$VALUES (10::numeric, 10::numeric)$$, '...WITH its reservation taken at approval, so it can be paid at the till'
);

-- ============================================================================
-- 8c. N5 — the cascade's lock order is code(id) -> offer(id) -> entitlement(id).
-- (The two-session race is in rewards-activate.deno.test.ts; here: the function is the
-- redefined one, and pinned.)
-- ============================================================================
SELECT is(
  (SELECT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'app' AND p.proname = 'play_held_review_cascade'),
  true, 'N5: app.play_held_review_cascade now pins search_path'
);
-- (0032 moved the cascade's BODY, unchanged, into app.hold_play_rewards so the edge role's definer runs the same code;
-- the trigger function calls it. The lock order now lives there.)
SELECT ok(
  (SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'app' AND p.proname = 'hold_play_rewards') ~ 'ORDER BY id FOR UPDATE',
  'N5: the cascade (app.hold_play_rewards, 0032) locks the play''s rows ORDER BY id before it updates them'
);

-- ============================================================================
-- 10b. N4 — the install-link tombstone survives account deletion.
-- ============================================================================
SELECT has_table('app', 'install_link_account', 'app.install_link_account exists');
SELECT is(
  (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.install_link_account'::regclass),
  true, 'install_link_account has ENABLE + FORCE ROW LEVEL SECURITY'
);
SELECT is(
  (SELECT count(*)::int FROM information_schema.role_table_grants WHERE table_schema = 'app' AND table_name = 'install_link_account' AND grantee IN ('anon', 'authenticated', 'PUBLIC')),
  0, 'no client role holds any grant on install_link_account'
);
SELECT is(
  (SELECT count(*)::int FROM pg_constraint WHERE conrelid = 'app.install_link_account'::regclass AND contype = 'f' AND confrelid = 'auth.users'::regclass)
  + (SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'install_link_account' AND column_name IN ('user_id', 'device_id', 'email')),
  0, 'the tombstone has NO column or FK that names a user: it is not a personal row, so private.pii_retention_policy (derived from FKs to auth.users) has nothing to classify — and a future user column fails this cell'
);
SELECT is(
  (SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name = 'install_link_account'),
  0, 'install_link_account is deliberately absent from the retention policy (a documented retention exception)'
);
SELECT is(
  (SELECT count(*)::int FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a')), 2,
  'account_pseudonyms: one pseudonym per active vault key'
);
SELECT is(
  (SELECT count(*)::int FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a') WHERE preferred), 1,
  '...exactly one of them preferred (the newest key)'
);
SELECT is(
  (SELECT pseudonym FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a') WHERE preferred),
  (SELECT pseudonym FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a') WHERE preferred),
  'account_pseudonyms is deterministic'
);
SELECT isnt(
  (SELECT pseudonym FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a') WHERE preferred),
  (SELECT pseudonym FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000b') WHERE preferred),
  '...and differs per account'
);
SELECT throws_ok($$SELECT * FROM private.account_pseudonyms(NULL)$$, '22023', NULL, 'account_pseudonyms refuses NULL');
-- P1 (0029): domain separation. (account_pseudonyms is EXECUTE-able by service_role only and the vault
-- by nobody but its owner, so each check snapshots the function's output into a temp table as service_role
-- and compares it, as the owner, against the vault.)
CREATE TEMP TABLE p1_snap_1 AS SELECT * FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a');
GRANT SELECT ON p1_snap_1 TO PUBLIC;
RESET ROLE;
SELECT is(
  (SELECT count(*)::int FROM p1_snap_1 a
   WHERE a.pseudonym IN (
     SELECT encode(public.hmac('00000000-0000-0000-0000-00000000000a', v.decrypted_secret, 'sha256'), 'hex')
     FROM vault.decrypted_secrets v WHERE v.name LIKE 'pseudonym_hmac%')),
  0, 'P1: account_pseudonyms(A) never equals hmac(A, key) — the value app.attestation.player_pseudonym stores — under ANY active key'
);
SELECT is(
  (SELECT count(*)::int FROM p1_snap_1 a JOIN app.attestation t ON t.player_pseudonym = a.pseudonym),
  0, 'P1: no tombstone pseudonym joins to a retained attestation row'
);
SELECT is(
  (SELECT pseudonym FROM p1_snap_1 WHERE preferred),
  (SELECT encode(public.hmac('install_link_account:00000000-0000-0000-0000-00000000000a', v.decrypted_secret, 'sha256'), 'hex')
   FROM vault.decrypted_secrets v WHERE v.name = 'pseudonym_hmac_v2'),
  'P1: the pseudonym is hmac(''install_link_account:'' || user_id, key) with the newest key preferred'
);
-- "preferred" follows the vault's creation order, NOT lexicographic name order.
INSERT INTO vault.secrets (name, secret) VALUES
  ('pseudonym_hmac_v9',  'shim-test-only-pseudonym-hmac-nine-32bytes-minimum-zzzzzzzzzzzzzzzzzzzzz'),
  ('pseudonym_hmac_v10', 'shim-test-only-pseudonym-hmac-ten-32bytes-minimum-wwwwwwwwwwwwwwwwwwwwwwww');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
CREATE TEMP TABLE p1_snap_2 AS SELECT * FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a');
GRANT SELECT ON p1_snap_2 TO PUBLIC;
RESET ROLE;
SELECT is((SELECT count(*)::int FROM p1_snap_2 WHERE preferred), 1, 'P1: still exactly one preferred key with four keys in the vault');
SELECT is(
  (SELECT v.name FROM p1_snap_2 a JOIN vault.decrypted_secrets v ON v.id = a.key_id WHERE a.preferred),
  'pseudonym_hmac_v10',
  'P1: of two keys created together, the higher NUMERIC version wins (_v10, not the lexicographic max _v9)'
);
INSERT INTO vault.secrets (name, secret, created_at) VALUES
  ('pseudonym_hmac_v11', 'shim-test-only-pseudonym-hmac-eleven-32bytes-minimum-vvvvvvvvvvvvvvvvvvv', now() - interval '30 days');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
CREATE TEMP TABLE p1_snap_3 AS SELECT * FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a');
GRANT SELECT ON p1_snap_3 TO PUBLIC;
RESET ROLE;
SELECT is(
  (SELECT v.name FROM p1_snap_3 a JOIN vault.decrypted_secrets v ON v.id = a.key_id WHERE a.preferred),
  'pseudonym_hmac_v10',
  'P1: a key with a higher name but an OLDER vault creation time is not preferred: creation order decides'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Four accounts use one install; two of them delete themselves.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('20000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-1000000000a2', 'android'),
  ('20000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-2000000000b2', 'android'),
  ('20000000-0000-0000-0000-0000000000d3', '00000000-0000-0000-0000-3000000000c2', 'android'),
  ('20000000-0000-0000-0000-0000000000d4', '00000000-0000-0000-0000-1000000000a3', 'android');
SELECT app.record_install_link('00000000-0000-0000-0000-1000000000a2', '20000000-0000-0000-0000-0000000000d1', repeat('c', 64));
SELECT app.record_install_link('00000000-0000-0000-0000-1000000000a2', '20000000-0000-0000-0000-0000000000d1', repeat('c', 64));
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('c', 64)), 1,
  'record_install_link is idempotent per (install, account)');
SELECT is((SELECT install_link_hash FROM app.device WHERE id = '20000000-0000-0000-0000-0000000000d1'), repeat('c', 64),
  '...and stamps the link on the device row');
SELECT app.record_install_link('00000000-0000-0000-0000-2000000000b2', '20000000-0000-0000-0000-0000000000d2', repeat('c', 64));
SELECT app.record_install_link('00000000-0000-0000-0000-3000000000c2', '20000000-0000-0000-0000-0000000000d3', repeat('c', 64));
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000d3')$$,
  $$VALUES (3, false)$$, 'three accounts on the install'
);
-- two of the three delete themselves (devices go; the tombstone rows must stay)
DELETE FROM app.device WHERE id IN ('20000000-0000-0000-0000-0000000000d1', '20000000-0000-0000-0000-0000000000d2');
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000d3')$$,
  $$VALUES (3, false)$$, 'N4: the ">2 accounts" count HOLDS after two of the accounts deleted their device rows'
);
SELECT app.record_install_link('00000000-0000-0000-0000-1000000000a3', '20000000-0000-0000-0000-0000000000d4', repeat('c', 64));
SELECT results_eq(
  $$SELECT accounts_on_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000d4')$$,
  $$VALUES (4)$$, 'N4: a 4th account on the install sees 4, not 2'
);
-- the fraud decision is recorded, then the voided account deletes its device
SELECT app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-3000000000c2', '00000000-0000-0000-0000-4000000000d0');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('c', 64) AND fraud_voided_at IS NOT NULL), 1,
  'N4: the fraud mark is written on the voided account''s tombstone row');
DELETE FROM app.device WHERE id = '20000000-0000-0000-0000-0000000000d3';
SELECT results_eq(
  $$SELECT accounts_on_install, voided_account_used_install FROM app.device_link_signals('20000000-0000-0000-0000-0000000000d4')$$,
  $$VALUES (4, true)$$, 'N4: a fraud-voided account that DELETED itself still taints the install for the next account'
);
-- marking an account whose devices are already gone still works (it needs only the id)
SELECT is(
  app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-2000000000b2', '00000000-0000-0000-0000-4000000000d0'), 0,
  'marking an already-deleted account''s devices touches no device (0) ...'
);
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('c', 64) AND fraud_voided_at IS NOT NULL), 2,
  '...but still marks its tombstone');
-- the REAL deletion path leaves the tombstone (a retention exception), and removes the device
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('c', 64)), 4, 'four tombstone rows before the deletion');
SELECT lives_ok($$SELECT private.delete_my_data('00000000-0000-0000-0000-1000000000a3')$$, 'private.delete_my_data runs for an account that has a tombstone row');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = '00000000-0000-0000-0000-1000000000a3'), 0, 'N4: delete_my_data removed the account''s device rows...');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('c', 64)), 4, '...and left the install-link tombstone rows (documented retention exception)');
-- a row written under an OLDER key is still recognised after the preferred key moved on (rotation).
INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id)
SELECT repeat('d', 64), a.pseudonym, a.key_id FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a') a WHERE NOT a.preferred ORDER BY a.key_id LIMIT 1;
UPDATE app.device SET install_link_hash = NULL WHERE id = '20000000-0000-0000-0000-000000000001';
SELECT app.record_install_link('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', repeat('d', 64));
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('d', 64)), 1,
  'N4: an account already recorded under a non-preferred (older) key is not counted twice');
SELECT throws_ok(
  $$INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id) VALUES (repeat('e', 64), repeat('f', 64), gen_random_uuid())$$,
  '23514', NULL, 'the write-time trigger rejects a pseudonym key id that does not resolve in the vault'
);
SELECT throws_ok(
  $$SELECT app.record_install_link('00000000-0000-0000-0000-00000000000b', '20000000-0000-0000-0000-000000000001', repeat('a', 64))$$,
  '42501', NULL, 'record_install_link refuses a device that is not the account''s'
);
SELECT throws_ok(
  $$SELECT app.record_install_link('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'nope')$$,
  '22023', NULL, 'record_install_link refuses a malformed link hash'
);
SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok($$SELECT * FROM private.account_pseudonyms('00000000-0000-0000-0000-00000000000a')$$, '42501', NULL, 'must-fail: a player cannot compute pseudonyms');
SELECT throws_ok($$SELECT count(*) FROM app.install_link_account$$, '42501', NULL, 'must-fail: a player cannot read the tombstone');
SELECT throws_ok($$SELECT app.record_install_link('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', repeat('a', 64))$$, '42501', NULL, 'must-fail: a player cannot call record_install_link');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);


-- ============================================================================
-- 11. Privileges on the gate-round functions
-- ============================================================================
SELECT is(
  (SELECT bool_and(has_function_privilege('service_role', p.oid, 'EXECUTE') AND NOT has_function_privilege('anon', p.oid, 'EXECUTE') AND NOT has_function_privilege('authenticated', p.oid, 'EXECUTE'))
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('reserve_offer_for_code', 'device_link_signals', 'mark_account_devices_fraud_voided')),
  true, 'reserve_offer_for_code / device_link_signals / mark_account_devices_fraud_voided: service_role only'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app' AND p.proname IN ('reserve_offer_for_code', 'device_link_signals', 'mark_account_devices_fraud_voided', 'offer_code_reservation_sync')
     AND (p.prosecdef OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'))),
  0, 'none of them is SECURITY DEFINER and every one pins search_path'
);
SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok(
  $$SELECT app.reserve_offer_for_code('62000000-0000-0000-0000-000000000001', gen_random_uuid(), 'x')$$,
  '42501', NULL, 'must-fail: a player cannot reserve offer budget themselves'
);
SELECT throws_ok(
  $$SELECT * FROM app.device_link_signals('20000000-0000-0000-0000-000000000001')$$,
  '42501', NULL, 'must-fail: a player cannot read the install-link signals (they describe other accounts)'
);
SELECT throws_ok(
  $$SELECT app.mark_account_devices_fraud_voided('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000a')$$,
  '42501', NULL, 'must-fail: a player cannot mark another account''s devices'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);


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
