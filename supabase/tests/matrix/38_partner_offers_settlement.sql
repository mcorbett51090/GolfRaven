-- 38_partner_offers_settlement.sql
-- P5.1b (0060): OFFERS-REDEEM AND SETTLEMENT EXPORT, from docs/security/partner-auth-design.md 12 / 32: AT(17) settlement export after role check;
-- AT(20) settlement lines with sponsorship attribution; AT(10) settlement reconcile half (export matches redemptions). Class A1 redeem, A0 queue, A3 settlement;
-- foreign facility 403; A1 without PIN; self-redeem 22023; A3 without TOTP refused; planted GUC; binding-keyed policies, no GUC.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 36 / 37 pattern). Authority refusals each sit in a SAVEPOINT that is rolled back.
-- Happy-path helpers bind once as staff_x then only SET ROLE and call (no re-bind). Settlement happy cells bind operator_t with MFA.
-- Inventory / allow-list reads run as service_role.

\set QUIET 1
BEGIN;
SELECT plan(32);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.offer, app.offer_code, app.sponsorship, app.partner_org TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.checkin_token, app.device TO CURRENT_USER;
GRANT SELECT ON app.attestation, app.audit_log, app.profile TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz38_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_of ON app.offer FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_oc ON app.offer_code FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_sp ON app.sponsorship FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_po ON app.partner_org FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_ct ON app.checkin_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_dv ON app.device FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz38_att ON app.attestation FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz38_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz38_pr ON app.profile FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s38:' || p_label) || md5('s38b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c38:' || p_label) || md5('c38b:' || p_label), 'hex'), decode(md5('k38:' || p_label) || md5('k38b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n38:' || p_label) || md5('n38b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
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

CREATE FUNCTION pg_temp.q(p_fac text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.partner_offers_queue_for_partner(p_fac);
  EXECUTE 'RESET ROLE';
  RETURN n::text;
END
$f$;
CREATE FUNCTION pg_temp.red(p_label text, p_fac text, p_code uuid, p_method text, p_cred text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offers_redeem_for_partner(p_fac, p_code, p_method, p_cred);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_attestation_id IS NOT NULL, false)::text;
END
$f$;
CREATE FUNCTION pg_temp.sett(p_label text, p_trail text, p_month date) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; n int := 0; s text;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  FOR r IN SELECT * FROM private.partner_settlement_export_for_partner(p_trail, p_month) LOOP
    n := n + 1;
    s := r.o_status;
  END LOOP;
  EXECUTE 'RESET ROLE';
  RETURN s || '|' || n::text;
END
$f$;

-- principals: staff_x, staff_y, operator_t, admin, player_a as staff for self-redeem
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_cred('pa', '00000000-0000-0000-0000-00000000000a') AS c_pa \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.mk_session('pa', '00000000-0000-0000-0000-00000000000a', :'c_pa') AS s_pa \gset

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad, pg_temp.th('pa') AS th_pa \gset

-- sponsor org + sponsorship for AT(20) settlement line
INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-000000000038', 'sponsor', 'Sponsor 38');
INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, starts_on, ends_on, status)
VALUES ('38000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000038', 'trl_t', 'other', 'offers', 'Sponsor 38', current_date, current_date + 90, 'live');

-- live offer with face_value and budget reservation headroom; sponsor funder
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, budget_used, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000001', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '38000000-0000-0000-0000-000000000001',
        500, 20, 10, 10, current_date, current_date + 30, 'live');
-- already-redeemed code (planted for settlement cells; bind order: settlement savepoints before the lasting staff bind)
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at, redeemed_at, redeemed_by_staff)
VALUES ('78000000-0000-0000-0000-000000000099', '68000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'redeemed', 0, now() + interval '7 days', now(), now(), '00000000-0000-0000-0000-1000000000a1');
-- issued code for player_b (staff_x redeems) — UNIQUE(user_id, offer_id) so player_b cannot also hold the planted redeemed row; use a second offer for redeem
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000002', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '38000000-0000-0000-0000-000000000001',
        500, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at)
VALUES ('78000000-0000-0000-0000-000000000001', '68000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'issued', 10, now() + interval '7 days', now());
-- issued code for player_a (self-redeem cell; helpers already made player_a staff at fac_x)
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at)
VALUES ('78000000-0000-0000-0000-000000000002', '68000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'issued', 0, now() + interval '7 days', now());
-- device + checkin tokens (36 pattern)
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform) VALUES
  ('38000000-0000-0000-0000-00000000d0b1', '00000000-0000-0000-0000-00000000000b', 'ios')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) VALUES
  ('38100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '38000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n38-1', now() + interval '10 minutes', 'live'),
  ('38100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'n38-2', now() + interval '10 minutes', 'live');
INSERT INTO app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) VALUES
  ('38200000-0000-0000-0000-000000000001', '38100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '38000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('38200000-0000-0000-0000-000000000002', '38100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Inventory and EXECUTE
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_offers_queue_for_partner(text)'::regprocedure, 'EXECUTE'), 'queue is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_offers_redeem_for_partner(text, uuid, text, text)'::regprocedure, 'EXECUTE'), 'redeem is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_settlement_export_for_partner(text, date)'::regprocedure, 'EXECUTE'), 'settlement is edge_partner');
SELECT ok(NOT has_function_privilege('edge_actor', 'private.partner_offers_redeem_for_partner(text, uuid, text, text)'::regprocedure, 'EXECUTE'), 'edge_actor cannot redeem');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.partner_offers_redeem_apply(uuid, text, uuid, uuid, uuid, text, numeric, text)'::regprocedure, 'EXECUTE'), 'apply helper is not edge_partner');
SELECT ok(has_function_privilege('private_definer', 'app.consume_offer_budget(uuid, numeric)'::regprocedure, 'EXECUTE'), 'private_definer may execute consume_offer_budget');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN (
  'partner_offers_queue_for_partner', 'partner_offers_redeem_for_partner', 'partner_settlement_export_for_partner') AND expected_edge_partner), 3,
  'three partner functions are in function_inventory as edge_partner');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_offers_%'), 9,
  'nine P5.1b private_definer policies exist');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_offers_%'
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'current_setting'), 0,
  'none of the P5.1b policies reads a setting: no GUC window');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd_partner_offers_%'), 9,
  'the nine policies are in definer_policy_allowlist');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. Authority: foreign facility, A1 without PIN, A3 without TOTP, self-redeem, planted GUC
-- ----------------------------------------------------------------------------
SAVEPOINT scope_y;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_for_partner('fac_x', '78000000-0000-0000-0000-000000000001', 'staff_scan', '38200000-0000-0000-0000-000000000001')$$, '42501', 'partner_authorize: no scope', 'staff at Y cannot redeem at X (foreign facility 403)');
SELECT throws_ok($$SELECT * FROM private.partner_offers_queue_for_partner('fac_x')$$, '42501', 'partner_authorize: no scope', 'staff at Y cannot read queue at X');
RESET ROLE;
ROLLBACK TO SAVEPOINT scope_y;

SAVEPOINT no_pin;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_for_partner('fac_x', '78000000-0000-0000-0000-000000000001', 'staff_scan', '38200000-0000-0000-0000-000000000001')$$, '42501', NULL, 'A1: no PIN grant, no redeem');
RESET ROLE;
ROLLBACK TO SAVEPOINT no_pin;

SAVEPOINT no_totp;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
-- operator session is aal 2 but mfa_until is null
SELECT throws_ok($$SELECT * FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date)$$, '42501', NULL, 'A3 settlement without TOTP refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT no_totp;

SAVEPOINT self_red;
SELECT pg_temp.seed_step('pa', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_pa');
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_for_partner('fac_x', '78000000-0000-0000-0000-000000000002', 'staff_scan', '38200000-0000-0000-0000-000000000002')$$, '22023', 'self_redeem_refused: a staff member cannot redeem their own account', 'self-redeem is 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT self_red;

SAVEPOINT planted_guc;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT set_config('app.guard.offer_code_id', '78000000-0000-0000-0000-000000000001', true);
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-00000000000a', true);
-- planted GUCs must not open a foreign facility or widen the redeem
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_for_partner('fac_y', '78000000-0000-0000-0000-000000000001', 'staff_scan', '38200000-0000-0000-0000-000000000001')$$, '42501', NULL, 'planted GUC does not open a foreign facility redeem');
RESET ROLE;
ROLLBACK TO SAVEPOINT planted_guc;

-- ----------------------------------------------------------------------------
-- 3. Settlement (bind operator in a savepoint; planted redeemed row; no lasting bind)
-- ----------------------------------------------------------------------------
SAVEPOINT sett_ok;
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT is((SELECT o_status || '|' || count(*) OVER () FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date) LIMIT 1),
  'ok|1', 'AT(17)/AT(10): settlement export returns ok with one line for the month');
SELECT is((SELECT o_sponsorship_id::text FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date) WHERE o_status = 'ok' LIMIT 1),
  '38000000-0000-0000-0000-000000000001', 'AT(20): settlement line includes sponsorship_id for sponsor funder');
SELECT is((SELECT o_redemptions::text || '|' || o_face_value_total::numeric::text FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date) WHERE o_status = 'ok' LIMIT 1),
  '1|10.00', 'AT(10): export redemptions and face_value_total match the planted redeem');
SELECT is((SELECT o_funder FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date) WHERE o_status = 'ok' LIMIT 1),
  'sponsor', 'settlement funder is sponsor');
SELECT is((SELECT o_status FROM private.partner_settlement_export_for_partner('trl_t', '2000-01-01'::date) LIMIT 1), 'empty', 'settlement for a month with no redemptions is empty');
RESET ROLE;
ROLLBACK TO SAVEPOINT sett_ok;

SAVEPOINT admin_sett;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is((SELECT o_status FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date) LIMIT 1), 'ok', 'admin can settlement-export via has_trail_scope');
RESET ROLE;
ROLLBACK TO SAVEPOINT admin_sett;

-- ----------------------------------------------------------------------------
-- 4. Happy redeem: bind staff_x once; queue + budget consume
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;

SELECT ok((SELECT count(*)::int FROM private.partner_offers_queue_for_partner('fac_x')) >= 2, 'A0: queue lists issued codes at the facility');
SELECT ok((SELECT bool_or(o_player_handle = 'player_b') FROM private.partner_offers_queue_for_partner('fac_x')), 'queue shows player handle');

SELECT is((SELECT budget_reserved::text || '|' || budget_used::text FROM app.offer WHERE id = '68000000-0000-0000-0000-000000000002'), '10.00|0.00', 'offer budget before redeem: reserved 10 used 0');
SELECT is(pg_temp.red('sx', 'fac_x', '78000000-0000-0000-0000-000000000001', 'staff_scan', '38200000-0000-0000-0000-000000000001'), 'ok|true', 'happy redeem consumes budget and writes attestation');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000001'), 'redeemed', 'offer_code is redeemed');
SELECT is((SELECT budget_reserved::text || '|' || budget_used::text FROM app.offer WHERE id = '68000000-0000-0000-0000-000000000002'), '0.00|10.00', 'budget: reserved 0 used 10 after consume of 10');
SELECT is((SELECT count(*)::int FROM app.attestation WHERE kind = 'offer_redemption' AND player_user_id = '00000000-0000-0000-0000-00000000000b'), 1, 'one offer_redemption attestation');
SELECT is(pg_temp.red('sx', 'fac_x', '78000000-0000-0000-0000-000000000001', 'staff_scan', '38200000-0000-0000-0000-000000000001'), 'not_issued|false', 'already redeemed is not_issued');

SAVEPOINT bad_args;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_for_partner('fac_x', '78000000-0000-0000-0000-000000000001', 'offline_code', '123456')$$, '22023', NULL, 'offline_code redemption is refused in this slice');
RESET ROLE;
ROLLBACK TO SAVEPOINT bad_args;

SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.offer_redeem') >= 1, true, 'audit row for offer redeem');

SELECT * FROM finish();
ROLLBACK;
