-- 36_partner_stock_handover.sql
-- P5.1a S5 (0058): HAND-OVER AND STOCK, from docs/security/partner-auth-design.md 12.1 "S5": AT(8) / AT(21) (race for the last unit and the voucher path); class A1 for hand-over and stock
-- movements, A0 for stock and collect-queue reads; staff_scan and hand_over_token redeem; offline_code refused; binding-keyed policies, no GUC.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 pattern). Authority refusals each sit in a SAVEPOINT that is rolled back (a second bind in one
-- transaction is itself refused). Happy-path helpers bind once as staff_x then only SET ROLE and call (no re-bind). Token hashes are precomputed with \gset.
-- Inventory / allow-list reads run as service_role.

\set QUIET 1
BEGIN;
SELECT plan(65);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, UPDATE ON app.special_marker_stock, app.special_marker_availability, app.entitlement TO CURRENT_USER;
GRANT SELECT ON app.special_marker_stock_movement, app.attestation, app.audit_log, app.partner_handover_token, app.profile TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz36_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz36_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz36_stock ON app.special_marker_stock FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz36_avail ON app.special_marker_availability FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz36_ent ON app.entitlement FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz36_mov ON app.special_marker_stock_movement FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz36_att ON app.attestation FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz36_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz36_ht ON app.partner_handover_token FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz36_pr ON app.profile FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s36:' || p_label) || md5('s36b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c36:' || p_label) || md5('c36b:' || p_label), 'hex'), decode(md5('k36:' || p_label) || md5('k36b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n36:' || p_label) || md5('n36b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;

-- helpers: bind already made; fresh PIN each A1 call
CREATE FUNCTION pg_temp.rd(p_label text, p_fac text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; n int := 0;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  FOR r IN SELECT * FROM private.partner_stock_read_for_partner(p_fac) LOOP n := n + 1; END LOOP;
  EXECUTE 'RESET ROLE';
  RETURN n::text;
END
$f$;
CREATE FUNCTION pg_temp.mv(p_label text, p_fac text, p_trail text, p_kind text, p_qty int, p_note text DEFAULT NULL) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_stock_move_for_partner(p_fac, p_trail, p_kind, p_qty, p_note);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_on_hand::text, '') || '|' || coalesce(r.o_availability, '');
END
$f$;
CREATE FUNCTION pg_temp.q(p_label text, p_fac text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.partner_entitlement_queue_for_partner(p_fac);
  EXECUTE 'RESET ROLE';
  RETURN n::text;
END
$f$;
CREATE FUNCTION pg_temp.mint(p_label text, p_fac text, p_ent uuid, p_hash text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_handover_mint_for_partner(p_fac, p_ent, p_hash);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_expires_at IS NOT NULL, false)::text;
END
$f$;
CREATE FUNCTION pg_temp.red(p_label text, p_fac text, p_ent uuid, p_method text, p_cred text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_entitlement_redeem_for_partner(p_fac, p_ent, p_method, p_cred);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_movement, '') || '|' || coalesce(r.o_availability, '');
END
$f$;
CREATE FUNCTION pg_temp.vouch(p_label text, p_fac text, p_ent uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_entitlement_voucher_for_partner(p_fac, p_ent);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_voucher_issued_at IS NOT NULL, false)::text;
END
$f$;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad, pg_temp.th('pa') AS th_pa \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_cred('pa', '00000000-0000-0000-0000-00000000000a') AS c_pa \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.mk_session('pa', '00000000-0000-0000-0000-00000000000a', :'c_pa') AS s_pa \gset

-- player_b redeemable entitlement (helpers already gave player_a 5000...0001 on trl_t); second unit for the race
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_device_id, activated_at)
VALUES ('51000000-0000-0000-0000-000000003601', '00000000-0000-0000-0000-00000000000b', 'special_marker', 'trl_t', 'redeemable',
        '20000000-0000-0000-0000-000000000001', now());

-- check-in tokens for staff_scan (player_a and player_b)
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform) VALUES
  ('36000000-0000-0000-0000-00000000d0b1', '00000000-0000-0000-0000-00000000000b', 'ios')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) VALUES
  ('36100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'n36-1', now() + interval '10 minutes', 'live'),
  ('36100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '36000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n36-2', now() + interval '10 minutes', 'live'),
  ('36100000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '36000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n36-3', now() + interval '10 minutes', 'live'),
  ('36100000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'n36-4', now() - interval '20 minutes', 'live');
INSERT INTO app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) VALUES
  ('36200000-0000-0000-0000-000000000001', '36100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('36200000-0000-0000-0000-000000000002', '36100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '36000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('36200000-0000-0000-0000-000000000003', '36100000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '36000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('36200000-0000-0000-0000-000000000004', '36100000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'attested', 'live', now() - interval '20 minutes', now() - interval '10 minutes');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Inventory and EXECUTE
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_stock_read_for_partner(text)'::regprocedure, 'EXECUTE'), 'stock read is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_stock_move_for_partner(text, text, text, integer, text)'::regprocedure, 'EXECUTE'), 'stock move is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_entitlement_queue_for_partner(text)'::regprocedure, 'EXECUTE'), 'queue is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_handover_mint_for_partner(text, uuid, text)'::regprocedure, 'EXECUTE'), 'mint is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_entitlement_redeem_for_partner(text, uuid, text, text)'::regprocedure, 'EXECUTE'), 'redeem is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_entitlement_voucher_for_partner(text, uuid)'::regprocedure, 'EXECUTE'), 'voucher is edge_partner');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.partner_stock_availability_refresh(text, text)'::regprocedure, 'EXECUTE'), 'projection writer is not edge_partner');
SELECT ok(NOT has_function_privilege('edge_actor', 'private.partner_entitlement_redeem_for_partner(text, uuid, text, text)'::regprocedure, 'EXECUTE'), 'edge_actor cannot redeem');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN (
  'partner_stock_read_for_partner', 'partner_stock_move_for_partner', 'partner_entitlement_queue_for_partner',
  'partner_handover_mint_for_partner', 'partner_entitlement_redeem_for_partner', 'partner_entitlement_voucher_for_partner') AND expected_edge_partner), 6,
  'six partner functions are in function_inventory as edge_partner');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_stock_%' OR pol.polname LIKE 'pd_partner_availability_%' OR pol.polname LIKE 'pd_partner_handover_%'), 17,
  'seventeen S5 private_definer policies exist');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE (pol.polname LIKE 'pd_partner_stock_%' OR pol.polname LIKE 'pd_partner_availability_%' OR pol.polname LIKE 'pd_partner_handover_%')
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'current_setting'), 0,
  'none of the S5 policies reads a setting: no GUC window');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd_partner_stock_%' OR policy_name LIKE 'pd_partner_availability_%' OR policy_name LIKE 'pd_partner_handover_%'), 17,
  'the seventeen policies are in definer_policy_allowlist');
RESET ROLE;
SELECT ok(NOT has_table_privilege('edge_partner', 'app.partner_handover_token', 'SELECT'), 'edge_partner has no privilege on partner_handover_token');
SELECT ok(NOT has_table_privilege('edge_actor', 'app.partner_handover_token', 'SELECT'), 'edge_actor has no privilege on partner_handover_token');

-- ----------------------------------------------------------------------------
-- 2. Authority: scope, role, class A1
-- ----------------------------------------------------------------------------
SAVEPOINT scope_y;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
SELECT throws_ok($$SELECT * FROM private.partner_stock_read_for_partner('fac_x')$$, '42501', 'partner_authorize: no scope', 'staff at Y cannot read stock at X');
SELECT throws_ok($$SELECT * FROM private.partner_stock_move_for_partner('fac_x', 'trl_t', 'delivered', 1, NULL)$$, '42501', 'partner_authorize: no scope', 'staff at Y cannot move stock at X');
SELECT throws_ok($$SELECT * FROM private.partner_entitlement_redeem_for_partner('fac_x', '50000000-0000-0000-0000-000000000001', 'staff_scan', '36200000-0000-0000-0000-000000000001')$$, '42501', 'partner_authorize: no scope', 'staff at Y cannot redeem at X');
RESET ROLE;
ROLLBACK TO SAVEPOINT scope_y;

SAVEPOINT no_pin;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_stock_move_for_partner('fac_x', 'trl_t', 'delivered', 1, NULL)$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'A1: no PIN grant, no stock move');
SELECT throws_ok($$SELECT * FROM private.partner_entitlement_redeem_for_partner('fac_x', '50000000-0000-0000-0000-000000000001', 'staff_scan', '36200000-0000-0000-0000-000000000001')$$, '42501', NULL, 'A1: no PIN grant, no redeem');
RESET ROLE;
ROLLBACK TO SAVEPOINT no_pin;

SAVEPOINT op_refuse;
SELECT pg_temp.seed_step('op', '{"pin_grant_s": 50, "mfa_s": 120}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_stock_read_for_partner('fac_x')$$, '42501', NULL, 'an operator cannot read stock (staff or manager)');
SELECT throws_ok($$SELECT * FROM private.partner_entitlement_queue_for_partner('fac_x')$$, '42501', NULL, 'an operator cannot read the collect queue');
RESET ROLE;
ROLLBACK TO SAVEPOINT op_refuse;

SAVEPOINT self_red;
SELECT pg_temp.seed_step('pa', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_pa');
-- helpers: player_a is staff at the org that covers fac_x and holds redeemable entitlement 5000...0001
SELECT throws_ok($$SELECT * FROM private.partner_entitlement_redeem_for_partner('fac_x', '50000000-0000-0000-0000-000000000001', 'staff_scan', '36200000-0000-0000-0000-000000000001')$$, '22023', 'self_redeem_refused: a staff member cannot redeem their own account', 'self-redeem is 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT self_red;

-- ----------------------------------------------------------------------------
-- 3. Happy path: bind staff_x once; stock read / move / queue / mint / redeem / voucher
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;

SELECT is(pg_temp.rd('sx', 'fac_x'), '1', 'A0: stock read returns the facility row (trl_t)');
SELECT is((SELECT o_on_hand::text || '|' || o_status FROM private.partner_stock_read_for_partner('fac_x') LIMIT 1), '5|in_stock', 'helpers seed: on_hand 5, in_stock');

SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_t', 'delivered', 2, 'delivery'), 'ok|7|in_stock', 'delivered +2');
SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_t', 'damaged', 1, NULL), 'ok|6|in_stock', 'damaged -1');
SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_t', 'transfer_out', 100, NULL), 'short|6|', 'short: would go below zero');
SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_t', 'count_adjustment', -3, 'count'), 'ok|3|low', 'count_adjustment to low threshold');
SELECT is((SELECT last_counted_at IS NOT NULL FROM app.special_marker_stock WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), true, 'count_adjustment stamps last_counted_at');
SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_missing', 'delivered', 1, NULL), 'no_stock_row||', 'no_stock_row for an unknown trail');
SELECT is((SELECT count(*)::int FROM app.special_marker_stock_movement WHERE facility_id = 'fac_x' AND kind = 'delivered' AND note = 'delivery'), 1, 'one delivered movement with the note');

SELECT ok((SELECT count(*)::int FROM private.partner_entitlement_queue_for_partner('fac_x')) >= 2, 'collect queue lists redeemable entitlements at the facility');
SELECT ok((SELECT bool_or(o_player_handle = 'player_a') FROM private.partner_entitlement_queue_for_partner('fac_x')), 'queue shows player handle, not an email');

-- mint + hand_over_token redeem of player_b entitlement
SELECT is(pg_temp.mint('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', repeat('ab', 32)), 'ok|true', 'mint a hand-over token hash');
SELECT is(pg_temp.mint('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', repeat('ab', 32)), 'token_exists|false', 'the same hash again is token_exists');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'hand_over_token', repeat('ab', 32)), 'ok|redeemed|low', 'AT(8): hand_over_token redeem');
SELECT is((SELECT state::text || '|' || redemption_method::text FROM app.entitlement WHERE id = '51000000-0000-0000-0000-000000003601'), 'redeemed|hand_over_token', 'entitlement redeemed by hand_over_token');
SELECT is((SELECT on_hand FROM app.special_marker_stock WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 2, 'on_hand decremented to 2');
SELECT is((SELECT count(*)::int FROM app.attestation WHERE kind = 'special_marker_handover' AND player_user_id = '00000000-0000-0000-0000-00000000000b'), 1, 'one special_marker_handover attestation');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'hand_over_token', repeat('ab', 32)), 'not_redeemable||', 'already redeemed is not_redeemable');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'hand_over_token', repeat('cd', 32)), 'not_redeemable||', 'unknown token on a redeemed entitlement is still not_redeemable');

-- staff_scan redeem of player_a helpers entitlement
SELECT is(pg_temp.red('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', 'staff_scan', '36200000-0000-0000-0000-000000000001'), 'ok|redeemed|low', 'AT(8): staff_scan redeem');
SELECT is((SELECT state::text || '|' || redemption_method::text FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000001'), 'redeemed|staff_scan', 'entitlement redeemed by staff_scan');
SELECT is(pg_temp.red('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', 'staff_scan', '36200000-0000-0000-0000-000000000001'), 'not_redeemable||', 'replay of the same entitlement is not_redeemable');
SELECT is((SELECT on_hand FROM app.special_marker_stock WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 1, 'on_hand is 1 after two redeems');

-- AT(8) race for the last unit: reset both players' trl_t entitlements to redeemable (UNIQUE per user+trail), on_hand is 1
UPDATE app.entitlement SET state = 'redeemable', redeemed_at = NULL, redeemed_facility_id = NULL, redeemed_by_staff = NULL,
  redemption_method = NULL, redemption_jti = NULL, activated_at = now()
WHERE id IN ('50000000-0000-0000-0000-000000000001', '51000000-0000-0000-0000-000000003601');

SELECT is(pg_temp.mint('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', repeat('ef', 32)), 'ok|true', 'mint for the race winner');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'hand_over_token', repeat('ef', 32)), 'ok|redeemed|out', 'AT(8): last unit redeemed -> availability out');
SELECT is((SELECT on_hand FROM app.special_marker_stock WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 0, 'on_hand is 0');
SELECT is(pg_temp.mint('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', repeat('aa', 32)), 'ok|true', 'mint for the race loser (token unused until redeem succeeds)');
SELECT is(pg_temp.red('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', 'hand_over_token', repeat('aa', 32)), 'out_of_stock||out', 'AT(8): race loser is out_of_stock; entitlement unchanged');
SELECT is((SELECT state::text FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000001'), 'redeemable', 'out_of_stock leaves the entitlement redeemable');
SELECT is((SELECT consumed_at IS NULL FROM app.partner_handover_token WHERE token_hash = repeat('aa', 32)), true,
  'out_of_stock does not consume the hand-over token');

-- AT(21) voucher path: voucher while out, deliver stock, redeem as voucher_redeemed
SELECT is(pg_temp.vouch('sx', 'fac_x', '50000000-0000-0000-0000-000000000001'), 'ok|true', 'AT(21): voucher while out of stock');
SELECT is((SELECT state::text || '|' || voucher_facility_id FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000001'), 'vouchered|fac_x', 'entitlement is vouchered at fac_x');
SELECT is(pg_temp.mv('sx', 'fac_x', 'trl_t', 'delivered', 2, 'restock'), 'ok|2|low', 'restock after voucher');
SELECT is(pg_temp.mint('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', repeat('11', 32)), 'ok|true', 'mint for a vouchered entitlement owed here');
SELECT is(pg_temp.red('sx', 'fac_x', '50000000-0000-0000-0000-000000000001', 'hand_over_token', repeat('11', 32)), 'ok|voucher_redeemed|low', 'AT(21): voucher_redeemed movement');
SELECT is((SELECT kind::text FROM app.special_marker_stock_movement WHERE entitlement_id = '50000000-0000-0000-0000-000000000001' ORDER BY at DESC LIMIT 1), 'voucher_redeemed', 'movement kind is voucher_redeemed');

-- statuses and refusals
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003699', 'staff_scan', '36200000-0000-0000-0000-000000000002'), 'not_found||', 'unknown entitlement is not_found');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'staff_scan', '36200000-0000-0000-0000-000000000002'), 'not_redeemable||', 'already-redeemed entitlement');
SELECT is(pg_temp.red('sx', 'fac_x', '51000000-0000-0000-0000-000000003601', 'hand_over_token', repeat('ff', 32)), 'not_redeemable||', 'unknown token hash on a redeemed entitlement is not_redeemable');

SAVEPOINT bad_args;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT * FROM private.partner_entitlement_redeem_for_partner('fac_x', '50000000-0000-0000-0000-000000000001', 'offline_code', '123456')$$, '22023', NULL, 'offline_code redemption is refused in this slice');
SELECT throws_ok($$SELECT * FROM private.partner_stock_move_for_partner('fac_x', 'trl_t', 'redeemed', 1, NULL)$$, '22023', NULL, 'redeemed is not a staff stock-move kind');
SELECT throws_ok($$SELECT * FROM private.partner_handover_mint_for_partner('fac_x', '51000000-0000-0000-0000-000000003601', 'not-a-hash')$$, '22023', NULL, 'a malformed token hash is 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT bad_args;

SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.stock_move' OR action LIKE 'partner.entitlement_%' OR action = 'partner.handover_mint') >= 5, true,
  'audit rows for stock move, mint, redeem and voucher');

SELECT * FROM finish();
ROLLBACK;
