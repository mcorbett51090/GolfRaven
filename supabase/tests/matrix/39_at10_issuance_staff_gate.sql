-- 39_at10_issuance_staff_gate.sql
-- P5.1b / 0061: AT(10) ISSUANCE STAFF GATE. A facility with no active staff/manager cannot
-- first-issue an earned offer_code (held_review / heldFor=no_active_staff). Happy path on fac_x
-- still issues. Already-issued re-activate is not gated. Approve that would issue is refused
-- (app.resolve_held_offer_code 23514; partner apply status no_active_staff).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end. Activate / direct resolve cells
-- run as service_role. The partner apply status cell binds admin with A3 (the 35 pattern).

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz39_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz39_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s39:' || p_label) || md5('s39b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c39:' || p_label) || md5('c39b:' || p_label), 'hex'),
          decode(md5('k39:' || p_label) || md5('k39b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind,
                                   mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, 2, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n39:' || p_label) || md5('n39b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.res_oc(p_label text, p_id uuid, p_approve boolean) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_resolve_held_offer_code_for_partner(p_id, p_approve);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_state, '');
END
$f$;

-- ----------------------------------------------------------------------------
-- 0. Setup: facility with no active staff (org + scope, only a revoked member)
-- ----------------------------------------------------------------------------
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version)
VALUES ('fac_z', 'facility', 'verified', 1);
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version)
VALUES ('fac_z', 'facility-z', 'Facility Z', 'US-TN', 'America/Chicago', 1);
INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-0000000000f1', 'facility', 'Facility Z Pro Shop');
INSERT INTO app.partner_scope (org_id, facility_id)
VALUES ('10000000-0000-0000-0000-0000000000f1', 'fac_z');
INSERT INTO app.partner_member (user_id, org_id, role, revoked_at)
VALUES ('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-0000000000f1', 'staff', now());

INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status) VALUES
  ('61000000-0000-0000-0000-0000000000f1', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000f2', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000f3', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000f4', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live');

INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('71000000-0000-0000-0000-0000000000f1', '61000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000f2', '61000000-0000-0000-0000-0000000000f2', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'earned', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000f3', '61000000-0000-0000-0000-0000000000f3', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'issued', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000f4', '61000000-0000-0000-0000-0000000000f4', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'held_review', now() - interval '1 day', now() + interval '20 days');

UPDATE app.offer_code SET
  activated_device_id = '20000000-0000-0000-0000-000000000001',
  devicecheck_token_hash = 'tok-f3',
  activated_at = now() - interval '1 hour',
  reserved_amount = 10
WHERE id = '71000000-0000-0000-0000-0000000000f3';
UPDATE app.offer SET budget_reserved = budget_reserved + 10 WHERE id = '61000000-0000-0000-0000-0000000000f3';

UPDATE app.offer_code SET
  activated_device_id = '20000000-0000-0000-0000-000000000001',
  devicecheck_token_hash = 'tok-f4',
  activated_at = now() - interval '1 hour',
  hold_detail = jsonb_build_object('heldFor', 'no_active_staff'),
  reserved_amount = 10,
  expiry_paused_at = now()
WHERE id = '71000000-0000-0000-0000-0000000000f4';
UPDATE app.offer SET budget_reserved = budget_reserved + 10 WHERE id = '61000000-0000-0000-0000-0000000000f4';

SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad') AS s_ad \gset
SELECT pg_temp.th('ad') AS th_ad \gset

-- ----------------------------------------------------------------------------
-- 1. Helper + grants
-- ----------------------------------------------------------------------------
SELECT ok(private.facility_has_active_staff('fac_x'), 'fac_x has active staff/manager');
SELECT ok(NOT private.facility_has_active_staff('fac_z'), 'fac_z has no active staff/manager (revoked only)');
SELECT ok(has_function_privilege('service_role', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'service_role EXECUTEs facility_has_active_staff');
SELECT ok(has_function_privilege('private_definer', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'private_definer EXECUTEs facility_has_active_staff');
SELECT ok(NOT has_function_privilege('edge_actor', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'edge_actor cannot EXECUTE facility_has_active_staff');
SELECT ok(
  (SELECT expected_service_role AND NOT expected_edge_actor AND NOT expected_edge_partner
   FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'facility_has_active_staff'),
  'inventory: facility_has_active_staff is service_role only (not edge)');

-- ----------------------------------------------------------------------------
-- 2. Activate path
-- ----------------------------------------------------------------------------
SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-f1', 'activate'),
  'issued'::app.offer_code_state,
  'AT(10) happy: earned at fac_x (active staff) issues');

SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000f2', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-f2', 'activate'),
  'held_review'::app.offer_code_state,
  'AT(10): earned at fac_z (no active staff) is held_review');

SELECT is(
  (SELECT hold_detail ->> 'heldFor' FROM app.offer_code WHERE id = '71000000-0000-0000-0000-0000000000f2'),
  'no_active_staff',
  'AT(10): hold_detail.heldFor = no_active_staff');

SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000f3', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-f3b', 'activate'),
  'issued'::app.offer_code_state,
  'AT(10): already-issued re-activate at fac_z is NOT gated (stays issued)');

-- ----------------------------------------------------------------------------
-- 3. Resolve path (approve would issue)
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code(
      '71000000-0000-0000-0000-0000000000f4', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '23514',
  'resolve_held_offer_code: facility fac_z has no active staff; cannot issue (AT(10) no_active_staff)',
  'AT(10): approve that would issue without active staff raises 23514');

SELECT is(
  (SELECT state::text FROM app.offer_code WHERE id = '71000000-0000-0000-0000-0000000000f4'),
  'held_review',
  'AT(10): refused approve leaves the code held');

-- Partner A3 path: bind admin once, then status-map via for_partner (apply needs binding-keyed RLS).
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;

SELECT is(
  pg_temp.res_oc('ad', '71000000-0000-0000-0000-0000000000f4', true),
  'no_active_staff|',
  'AT(10): partner apply maps the refusal to status no_active_staff');

SELECT * FROM finish();
ROLLBACK;
