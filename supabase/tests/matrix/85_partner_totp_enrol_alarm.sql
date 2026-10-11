-- 85_partner_totp_enrol_alarm.sql
-- 0107_partner_totp_enrol_alarm.sql (P5 §113): kind totp_enrol on
-- partner_auth_alarm raised from partner_totp_enrol_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, enrol under otp_proof raises
-- one row per subject per minute, already_confirmed stays quiet,
-- ON CONFLICT quiet, detail shape (no seed), inventory.

\set QUIET 1
BEGIN;
SELECT plan(16);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_totp, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz85_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz85_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz85_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz85_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s85:' || p_label) || md5('s85b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c85:' || p_label) || md5('c85b:' || p_label), 'hex'),
          decode(md5('k85:' || p_label) || md5('k85b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n85:' || p_label) || md5('n85b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END,
    enrolment_until = CASE WHEN p_cols ? 'enrol_s' THEN clock_timestamp() + ((p_cols ->> 'enrol_s')::numeric * interval '1 second') ELSE s.enrolment_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.seed_totp(p_uid uuid, p_ver integer, p_confirmed boolean) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
  VALUES (p_uid, p_ver, clock_timestamp(), NULL,
          CASE WHEN p_confirmed THEN clock_timestamp() END, NULL, 0, NULL, NULL, clock_timestamp())
$f$;
CREATE FUNCTION pg_temp.enrol() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_enrol_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_seed_version::text, '');
END
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_uid uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'totp_enrol',
    NULL,
    p_uid::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('subject', p_uid::text, 'status', 'ok', 'seed_version', 1)
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_step(text, jsonb), pg_temp.seed_totp(uuid, integer, boolean), pg_temp.enrol(), pg_temp.force_alarm(uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_enrol', 'a5300000-0000-0000-0000-000000000085', '00000000-0000-0000-0000-3000000000c1', 1)$$,
  '23514', NULL,
  'totp_enrol refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_enrol', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'totp_enrol requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_enrol', NULL, '00000000-0000-0000-0000-3000000000ff', 9907)$$,
  'totp_enrol accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%totp_enrol%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes totp_enrol'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_totp_enrol_alarm_insert', 'pd_partner_totp_enrol_alarm_select')),
  2,
  'structure: partner-bound totp_enrol INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Enrol ok raises; re-enrol ON CONFLICT; already_confirmed quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('op1', '00000000-0000-0000-0000-3000000000c1') AS c_op1 \gset
SELECT pg_temp.mk_session('op1', '00000000-0000-0000-0000-3000000000c1', :'c_op1', 1) AS s_op1 \gset
SELECT pg_temp.th('op1') AS th_op1 \gset
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;

SELECT is(pg_temp.enrol(), 'ok|1',
  'first TOTP enrol under otp_proof → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'ok enrol raises one totp_enrol alarm keyed on subject uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  true,
  'totp_enrol leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  '00000000-0000-0000-0000-3000000000c1',
  'detail.subject is the enrollee uid'
);
SELECT is(
  (SELECT detail ->> 'seed_version' FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  '1',
  'detail.seed_version is 1'
);
SELECT ok(
  (SELECT detail ? 'seed' = false FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  'detail never carries the TOTP seed'
);

SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SELECT is(pg_temp.enrol(), 'ok|2',
  'unconfirmed re-enrol bumps seed_version and returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'second ok enrol in the same minute is ON CONFLICT DO NOTHING'
);

DELETE FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1';
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true);
SELECT pg_temp.seed_step('op1', '{"otp_s": 500, "aal": 2}'::jsonb);
SELECT is(pg_temp.enrol(), 'already_confirmed|',
  'enrol after confirmed → already_confirmed');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_enrol' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'already_confirmed does not raise another totp_enrol alarm'
);

SELECT lives_ok(
  $$SELECT pg_temp.force_alarm('00000000-0000-0000-0000-3000000000c1'::uuid)$$,
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§113%' OR note LIKE '%totp_enrol alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_totp_enrol_for_partner'),
  'function_inventory note mentions §113 / totp_enrol alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
