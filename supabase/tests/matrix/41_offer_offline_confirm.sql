-- 41_offer_offline_confirm.sql
-- P5 follow-up (0063): PLAYER-LANE clear of app.offer_code.offline_confirm_by on a qualifying co-signal
-- (money doc A2-21 / design §37). Same proof as marker_cosignal_attach (marker_cosignal_check); clears the
-- bound player's own redeemed_offline codes at the facility whose offline_step window holds the fix.
-- Statuses: confirmed | none_awaiting | cosignal_invalid | cosignal_used | review_account.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 40 pattern).

\set QUIET 1
BEGIN;
SELECT plan(14);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.offer, app.offer_code, app.sponsorship, app.partner_org, app.device, app.evidence, app.purchase_evidence TO CURRENT_USER;
GRANT SELECT ON app.profile, app.catalog_facility, app.attestation, app.offline_code_step TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz41_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_of ON app.offer FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_oc ON app.offer_code FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_sp ON app.sponsorship FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_po ON app.partner_org FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_dv ON app.device FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_ev ON app.evidence FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_pe ON app.purchase_evidence FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz41_pr ON app.profile FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz41_cf ON app.catalog_facility FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s41:' || p_label) || md5('s41b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c41:' || p_label) || md5('c41b:' || p_label), 'hex'), decode(md5('k41:' || p_label) || md5('k41b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n41:' || p_label) || md5('n41b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
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
-- Qualifying co-signal evidence (twin of matrix 24's qfix / seed_ev).
CREATE FUNCTION pg_temp.qfix(p_fix text, p_fac text, p_grade text, p_at timestamptz, p_ld date) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $f$
  SELECT jsonb_build_object('fixId', p_fix, 'facilityId', p_fac, 'fromApp', true, 'simulated', false, 'foreground', true, 'challenge', 'live',
    'token', jsonb_build_object('present', true, 'grade', p_grade), 'verificationTier', 'play-verified', 'geometryKind', 'polygon',
    'insideBuffer', true, 'accuracyMeters', 10, 'capturedAt', (extract(epoch FROM p_at) * 1000)::bigint, 'localDate', p_ld::text)
$f$;
CREATE FUNCTION pg_temp.seed_ev(p_fix text, p_u uuid, p_fac text, p_grade text, p_cap timestamptz, p_ev uuid DEFAULT NULL)
RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE v_ld date; v_id uuid;
BEGIN
  v_ld := (p_cap AT TIME ZONE (SELECT f.tz FROM app.catalog_facility f WHERE f.id = p_fac))::date;
  v_id := coalesce(p_ev, md5('ev41-' || p_fix)::uuid);
  INSERT INTO app.evidence (id, user_id, source, source_ref, facility_id, summary, attestation_grade, local_date, input_hash, status)
  VALUES (v_id, p_u, 'foreground_checkin', 'fix:' || p_fix, p_fac,
          jsonb_build_object('localDate', v_ld::text, 'fix', pg_temp.qfix(p_fix, p_fac, p_grade, p_cap, v_ld)),
          p_grade::app.attestation_grade, v_ld, 'h41-' || p_fix, 'accepted');
  RETURN v_id;
END
$f$;
-- Caller must already be bound as the player (actor_binding is one per transaction; re-bind raises).
CREATE FUNCTION pg_temp.confirm(p_fac text, p_at timestamptz, p_grade text, p_fix text, p_ev uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_actor';
  SELECT * INTO r FROM private.offer_offline_confirm_for_actor(p_fac, p_at, p_grade, p_fix, p_ev);
  EXECUTE 'RESET ROLE';
  RETURN r.o_result || '|' || r.o_cleared::text;
END
$f$;

SET LOCAL ROLE service_role;
UPDATE app.partner_member SET created_at = now() - interval '60 days';
RESET ROLE;

SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.th('sx') AS th_sx \gset

INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-000000000041', 'sponsor', 'Sponsor 41');
INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, starts_on, ends_on, status)
VALUES ('41000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000041', 'trl_t', 'other', 'offers', 'Sponsor 41', current_date, current_date + 90, 'live');
-- Issued code for offline redeem → offline_step write path
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000050', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '41000000-0000-0000-0000-000000000001',
        500, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at)
VALUES ('78000000-0000-0000-0000-000000000050', '68000000-0000-0000-0000-000000000050',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'issued', 10, now() + interval '7 days', now());
-- Planted already-offline-redeemed code awaiting confirm (current step window)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, budget_used, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000051', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '41000000-0000-0000-0000-000000000001',
        500, 0, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at, redeemed_at, redeemed_by_staff, redeemed_offline, offline_confirm_by, offline_step)
VALUES ('78000000-0000-0000-0000-000000000051', '68000000-0000-0000-0000-000000000051',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'redeemed', 0, now() + interval '7 days', now(), now(),
        '00000000-0000-0000-0000-1000000000a1', true, now() + interval '23 hours', pg_temp.now_step());
-- Another player's awaiting code at fac_x (must never clear)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, budget_reserved, budget_used, face_value, valid_from, valid_to, status)
VALUES ('68000000-0000-0000-0000-000000000052', 'trl_t', 'fac_x', '{}'::jsonb, 'sponsor', '41000000-0000-0000-0000-000000000001',
        500, 0, 10, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, expires_at, activated_at, redeemed_at, redeemed_by_staff, redeemed_offline, offline_confirm_by, offline_step)
VALUES ('78000000-0000-0000-0000-000000000052', '68000000-0000-0000-0000-000000000052',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'redeemed', 0, now() + interval '7 days', now(), now(),
        '00000000-0000-0000-0000-1000000000a1', true, now() + interval '23 hours', pg_temp.now_step());

SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, last_seen) VALUES
  ('40000000-0000-0000-0000-00000000d0b1', '00000000-0000-0000-0000-00000000000b', 'ios', now())
ON CONFLICT (id) DO UPDATE SET last_seen = now();
RESET ROLE;

SELECT clock_timestamp() AS t0 \gset
SELECT pg_temp.seed_ev('fix41ok', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'attested', :'t0'::timestamptz, 'a1000000-0000-0000-0000-000000000041') AS ev_ok \gset
SELECT pg_temp.seed_ev('fix41bad', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'attested', :'t0'::timestamptz, 'a1000000-0000-0000-0000-000000000042') AS ev_bad \gset
SELECT pg_temp.seed_ev('fix41used', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'attested', :'t0'::timestamptz, 'a1000000-0000-0000-0000-000000000043') AS ev_used \gset
-- Break qualification on fix41bad (radius geometry is not a co-signal)
UPDATE app.evidence SET summary = jsonb_set(summary, '{fix,geometryKind}', '"radius"'::jsonb)
WHERE id = 'a1000000-0000-0000-0000-000000000042';
-- Mark fix41used as already backing a purchase
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status, created_at)
VALUES ('b1000000-0000-0000-0000-000000000041', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'course_qr', 'rotating', 'ref-41-used', false,
        jsonb_build_object('fixId', 'fix41used', 'grade', 'attested', 'evidenceId', 'a1000000-0000-0000-0000-000000000043'),
        (:'t0'::timestamptz AT TIME ZONE 'America/Chicago')::date, 'valid', now());

-- ----------------------------------------------------------------------------
-- 1. Inventory and EXECUTE
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_actor', 'private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid)'::regprocedure, 'EXECUTE'),
  'offer_offline_confirm is edge_actor');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid)'::regprocedure, 'EXECUTE'),
  'edge_partner cannot confirm offline offers');
SELECT ok(EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'offer_code' AND column_name = 'offline_step'),
  'offer_code.offline_step exists');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric, bigint)'::regprocedure, 'EXECUTE'),
  'apply_offline 8-arg helper is not edge_partner');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name = 'offer_offline_confirm_for_actor' AND expected_edge_actor AND NOT expected_edge_partner), 1,
  'confirm is in function_inventory as edge_actor only');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. Offline redeem records offline_step (partner bind; rolled back so section 3 can bind_actor)
-- ----------------------------------------------------------------------------
SAVEPOINT redeem_step;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.red_off('sx', 'fac_x', '78000000-0000-0000-0000-000000000050', 'player_b',
  pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '40000000-0000-0000-0000-00000000d0b1', 1, pg_temp.now_step()), true),
  'ok|true', 'offline redeem still succeeds under 0063 apply signature');
SELECT is((SELECT offline_step FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000050'),
  pg_temp.now_step(), 'offline redeem writes offline_step');
SELECT ok((SELECT offline_confirm_by IS NOT NULL AND offline_confirm_by > now() + interval '23 hours'
             FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000050'),
  'offline redeem still sets offline_confirm_by ~24 h ahead');
ROLLBACK TO SAVEPOINT redeem_step;

-- ----------------------------------------------------------------------------
-- 3. Happy confirm + refusals (actor bind; partner binding was rolled back above)
-- ----------------------------------------------------------------------------
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b');
RESET ROLE;

SELECT is(pg_temp.confirm('fac_x', :'t0'::timestamptz, 'attested', 'fix41ok', :'ev_ok'::uuid),
  'confirmed|1', 'qualifying fix clears the planted awaiting offline offer for the bound player');
SELECT ok((SELECT offline_confirm_by IS NULL FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000051'),
  'planted code offline_confirm_by is cleared');
SELECT ok((SELECT offline_confirm_by IS NOT NULL FROM app.offer_code WHERE id = '78000000-0000-0000-0000-000000000052'),
  'another player''s awaiting code at the same facility is untouched');

SELECT is(pg_temp.confirm('fac_x', :'t0'::timestamptz, 'attested', 'fix41ok', :'ev_ok'::uuid),
  'none_awaiting|0', 'second confirm with nothing left awaiting is none_awaiting');
SELECT is(pg_temp.confirm('fac_x', :'t0'::timestamptz, 'attested', 'fix41bad', :'ev_bad'::uuid),
  'cosignal_invalid|0', 'non-qualifying evidence is cosignal_invalid');
SELECT is(pg_temp.confirm('fac_x', :'t0'::timestamptz, 'attested', 'fix41used', :'ev_used'::uuid),
  'cosignal_used|0', 'evidence already used by a purchase is cosignal_used');

SELECT * FROM finish();
ROLLBACK;
