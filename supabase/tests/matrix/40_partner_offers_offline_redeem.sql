-- 40_partner_offers_offline_redeem.sql
-- P5.1b follow-up (0062): OFFLINE_CODE OFFER REDEEM, from docs/security/partner-auth-design.md 32.3 / 35 and money-doc A2-21:
-- PIN step-up + profile-card name check; redeem with redeemed_offline and offline_confirm_by; settlement unconfirmed_count + fraud_signal offer_offline_unconfirmed.
-- Class A1; foreign facility 403; A1 without PIN; name_unconfirmed; wrong code; happy path; replay; settlement overdue signal.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 38 pattern). Authority refusals each sit in a SAVEPOINT that is rolled back.

\set QUIET 1
BEGIN;
SELECT plan(23);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.offer, app.offer_code, app.sponsorship, app.partner_org, app.device TO CURRENT_USER;
GRANT SELECT ON app.attestation, app.audit_log, app.profile, app.offline_code_step, app.fraud_signal, private.rate_limit_bucket TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz40_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_of ON app.offer FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_oc ON app.offer_code FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_sp ON app.sponsorship FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_po ON app.partner_org FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_dv ON app.device FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz40_att ON app.attestation FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz40_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz40_pr ON app.profile FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz40_st ON app.offline_code_step FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz40_fs ON app.fraud_signal FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s40:' || p_label) || md5('s40b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c40:' || p_label) || md5('c40b:' || p_label), 'hex'), decode(md5('k40:' || p_label) || md5('k40b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n40:' || p_label) || md5('n40b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
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
CREATE FUNCTION pg_temp.red_off(p_label text, p_fac text, p_code uuid, p_handle text, p_digits text, p_name boolean) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offers_redeem_offline_for_partner(p_fac, p_code, p_handle, p_digits, p_name);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_attestation_id IS NOT NULL, false)::text;
END
$f$;
-- Independent offline code (same as matrix 34): seed = HMAC-SHA256(K, label || 0x00 || user || device || version), HOTP SHA-256 6 digits
CREATE FUNCTION pg_temp.ref_code(p_user uuid, p_dev uuid, p_ver int, p_step bigint) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  k text := (SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'offline_seed_key');
  seed bytea;
  h bytea;
  o int;
  b bigint;
BEGIN
  seed := public.hmac(convert_to('golfraven/offline-seed/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_user::text, '-', ''), 'hex') || decode(replace(p_dev::text, '-', ''), 'hex') || int4send(p_ver),
                      convert_to(k, 'UTF8'), 'sha256');
  h := public.hmac(int8send(p_step), seed, 'sha256');
  o := get_byte(h, 31) & 15;
  b := ((get_byte(h, o)::bigint & 127) << 24) | (get_byte(h, o + 1)::bigint << 16) | (get_byte(h, o + 2)::bigint << 8) | get_byte(h, o + 3)::bigint;
  RETURN lpad((b % 1000000)::text, 6, '0');
END
$f$;
CREATE FUNCTION pg_temp.now_step() RETURNS bigint LANGUAGE sql AS $f$ SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint $f$;

SET LOCAL ROLE service_role;
UPDATE app.partner_member SET created_at = now() - interval '60 days';
RESET ROLE;

SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('op') AS th_op \gset

INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-000000000040', 'sponsor', 'Sponsor 40');
INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, starts_on, ends_on, status)
VALUES ('40000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000040', 'trl_t', 'other', 'offers', 'Sponsor 40', current_date, current_date + 90, 'live');
-- issued code for happy-path offline redeem (player_b)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000040', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '40000000-0000-0000-0000-000000000001',
        500, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at)
VALUES ('78000000-0000-0000-0000-000000000040', '68000000-0000-0000-0000-000000000040',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'issued', 10, now() + interval '7 days', now());
-- planted already-offline-redeemed overdue code for settlement cells (separate offer: UNIQUE(user_id, offer_id); bind order: settlement before lasting staff bind)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, budget_used, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000041', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '40000000-0000-0000-0000-000000000001',
        500, 0, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at, redeemed_at, redeemed_by_staff, redeemed_offline, offline_confirm_by)
VALUES ('78000000-0000-0000-0000-000000000041', '68000000-0000-0000-0000-000000000041',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'redeemed', 0, now() + interval '7 days', now(), now(),
        '00000000-0000-0000-0000-1000000000a1', true, now() - interval '1 minute');

SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, last_seen) VALUES
  ('40000000-0000-0000-0000-00000000d0b1', '00000000-0000-0000-0000-00000000000b', 'ios', now())
ON CONFLICT (id) DO UPDATE SET last_seen = now();
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Inventory and EXECUTE
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean)'::regprocedure, 'EXECUTE'),
  'offline redeem is edge_partner');
SELECT ok(NOT has_function_privilege('edge_actor', 'private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean)'::regprocedure, 'EXECUTE'),
  'edge_actor cannot offline-redeem');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric, bigint)'::regprocedure, 'EXECUTE'),
  'apply_offline helper is not edge_partner');
SELECT ok(EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'offer_code' AND column_name = 'offline_confirm_by'),
  'offer_code.offline_confirm_by exists');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name = 'partner_offers_redeem_offline_for_partner' AND expected_edge_partner), 1,
  'offline redeem is in function_inventory as edge_partner');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. Authority and refusals
-- ----------------------------------------------------------------------------
SAVEPOINT scope_y;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_offline_for_partner('fac_x', '78000000-0000-0000-0000-000000000040', 'player_b', '123456', true)$$,
  '42501', 'partner_authorize: no scope', 'staff at Y cannot offline-redeem at X');
RESET ROLE;
ROLLBACK TO SAVEPOINT scope_y;

SAVEPOINT no_pin;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_offers_redeem_offline_for_partner('fac_x', '78000000-0000-0000-0000-000000000040', 'player_b', '123456', true)$$,
  '42501', NULL, 'A1: no PIN grant, no offline redeem');
RESET ROLE;
ROLLBACK TO SAVEPOINT no_pin;

-- ----------------------------------------------------------------------------
-- 3. Settlement first (bind operator in a savepoint; planted overdue offline redeem; before lasting staff bind)
-- ----------------------------------------------------------------------------
SAVEPOINT sett_unc;
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT is((SELECT o_status || '|' || o_offline_count::text || '|' || o_unconfirmed_count::text
           FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date)
           WHERE o_status = 'ok' LIMIT 1),
  'ok|1|1', 'settlement: offline_count and unconfirmed_count are 1 when confirm deadline passed');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.fraud_signal f WHERE f.kind = 'offer_offline_unconfirmed'
             AND f.user_id = '00000000-0000-0000-0000-00000000000b'
             AND f.detail ->> 'offer_code_id' = '78000000-0000-0000-0000-000000000041'), 1,
  'settlement inserts fraud_signal offer_offline_unconfirmed once');
SET LOCAL ROLE edge_partner;
SELECT is((SELECT o_unconfirmed_count::text FROM private.partner_settlement_export_for_partner('trl_t', date_trunc('month', now())::date)
           WHERE o_status = 'ok' LIMIT 1), '1', 'second settlement export still reports unconfirmed_count 1');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.fraud_signal f WHERE f.kind = 'offer_offline_unconfirmed'
             AND f.detail ->> 'offer_code_id' = '78000000-0000-0000-0000-000000000041'), 1,
  'fraud_signal is not duplicated on a second export');
ROLLBACK TO SAVEPOINT sett_unc;

-- ----------------------------------------------------------------------------
-- 4. Happy offline redeem: bind staff_x once (lasting)
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;

SELECT is(pg_temp.red_off('sx', 'fac_x', '78000000-0000-0000-0000-000000000040', 'player_b', '123456', false),
  'name_unconfirmed|false', 'nameConfirmed false is name_unconfirmed (status, commits)');
SELECT is(pg_temp.red_off('sx', 'fac_x', '78000000-0000-0000-0000-000000000040', 'player_b', '000000', true),
  'verification_failed|false', 'wrong offline code is verification_failed');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000040'), 'issued', 'failed attempts leave the code issued');

SELECT is(pg_temp.red_off('sx', 'fac_x', '78000000-0000-0000-0000-000000000040', 'player_b',
  pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '40000000-0000-0000-0000-00000000d0b1', 1, pg_temp.now_step()), true),
  'ok|true', 'happy offline redeem with current-step code and nameConfirmed');
SELECT is((SELECT state::text || '|' || redeemed_offline::text FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000040'),
  'redeemed|true', 'offer_code is redeemed_offline');
SELECT ok((SELECT offline_confirm_by IS NOT NULL AND offline_confirm_by > now() + interval '23 hours'
             AND offline_confirm_by < now() + interval '25 hours' FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000040'),
  'offline_confirm_by is about 24 h ahead');
SELECT is((SELECT offline_step FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000040'),
  pg_temp.now_step(), 'offline redeem records offline_step for the confirm clear');
SELECT is((SELECT budget_reserved::text || '|' || budget_used::text FROM app.offer WHERE id = '68000000-0000-0000-0000-000000000040'),
  '0.00|10.00', 'budget consumed on offline redeem');
SELECT is((SELECT count(*)::int FROM app.attestation WHERE kind = 'offer_redemption' AND player_user_id = '00000000-0000-0000-0000-00000000000b'
             AND token_jti LIKE 'ofr-off:%'), 1, 'one offer_redemption attestation keyed ofr-off');
SELECT is((SELECT count(*)::int FROM app.offline_code_step s WHERE s.user_id = '00000000-0000-0000-0000-00000000000b'
             AND s.device_id = '40000000-0000-0000-0000-00000000d0b1' AND s.step = pg_temp.now_step()), 1, 'offline_code_step recorded');
SELECT is(pg_temp.red_off('sx', 'fac_x', '78000000-0000-0000-0000-000000000040', 'player_b',
  pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '40000000-0000-0000-0000-00000000d0b1', 1, pg_temp.now_step()), true),
  'replayed|false', 'same step again is replayed');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.offer_redeem_offline') >= 1, true, 'audit row for offline offer redeem');

SELECT * FROM finish();
ROLLBACK;
