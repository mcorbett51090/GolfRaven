-- 82_partner_totp_locked_alarm.sql
-- 0104_partner_totp_locked_alarm.sql (P5 §110): kind totp_locked on
-- partner_auth_alarm raised from partner_totp_verify_for_partner and
-- partner_totp_confirm_for_partner when newly locked (retry_after = 900).
-- Proved here: kind/row CHECKs, policies, verify + confirm raise one row
-- per subject per minute, further locked attempts quiet, detail shape,
-- inventory.

\set QUIET 1
BEGIN;
SELECT plan(16);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_totp, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz82_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz82_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz82_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz82_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s82:' || p_label) || md5('s82b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c82:' || p_label) || md5('c82b:' || p_label), 'hex'),
          decode(md5('k82:' || p_label) || md5('k82b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n82:' || p_label) || md5('n82b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END,
    enrolment_until = CASE WHEN p_cols ? 'enrol_s' THEN clock_timestamp() + ((p_cols ->> 'enrol_s')::numeric * interval '1 second') ELSE s.enrolment_until END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.seed_totp(p_uid uuid, p_ver integer, p_confirmed boolean, p_failed smallint, p_sid uuid DEFAULT NULL) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
  VALUES (p_uid, p_ver, clock_timestamp(), p_sid,
          CASE WHEN p_confirmed THEN clock_timestamp() END, NULL, p_failed, NULL, NULL, clock_timestamp())
$f$;
CREATE FUNCTION pg_temp.verify(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_verify_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.confirm(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_confirm_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_step(text, jsonb), pg_temp.seed_totp(uuid, integer, boolean, smallint, uuid),
  pg_temp.verify(text), pg_temp.confirm(text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_locked', 'a5300000-0000-0000-0000-000000000082', '00000000-0000-0000-0000-3000000000c1', 1)$$,
  '23514', NULL,
  'totp_locked refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_locked', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'totp_locked requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_locked', NULL, '00000000-0000-0000-0000-3000000000ff', 9904)$$,
  'totp_locked accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%totp_locked%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes totp_locked'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_totp_locked_alarm_insert', 'pd_partner_totp_locked_alarm_select')),
  2,
  'structure: partner-bound totp_locked INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Verify path: 5th wrong code raises alarm; further locked attempts quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op') AS s_op \gset
SELECT pg_temp.th('op') AS th_op \gset
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, 4::smallint);

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;

SELECT is(pg_temp.verify('000000'), 'locked|900',
  'verify: 5th wrong code locks TOTP');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'verify lock raises one totp_locked alarm keyed on subject uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  true,
  'totp_locked leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  '00000000-0000-0000-0000-3000000000c1',
  'detail.subject is the locked operator'
);
SELECT is(
  (SELECT detail ->> 'stage' FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  'verify',
  'detail.stage is verify'
);
SELECT is(split_part(pg_temp.verify('000001'), '|', 1), 'locked',
  'a further attempt on a locked TOTP is still locked');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'further locked attempts do not raise another alarm'
);

-- ----------------------------------------------------------------------------
-- 3. Confirm path: 5th wrong code raises alarm with stage=confirm
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('op2', '00000000-0000-0000-0000-3000000000c1') AS c_op2 \gset
SELECT pg_temp.mk_session('op2', '00000000-0000-0000-0000-3000000000c1', :'c_op2') AS s_op2 \gset
SELECT pg_temp.th('op2') AS th_op2 \gset
DELETE FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1';
DELETE FROM app.partner_auth_alarm
WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1';
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, false, 4::smallint, :'s_op2'::uuid);
SELECT pg_temp.seed_step('op2', '{"otp_s": 500}'::jsonb);

SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op2');
RESET ROLE;

SELECT is(pg_temp.confirm('000000'), 'locked|900',
  'confirm: 5th wrong code locks TOTP');
SELECT is(
  (SELECT detail ->> 'stage' FROM app.partner_auth_alarm
   WHERE kind = 'totp_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  'confirm',
  'confirm lock raises totp_locked with detail.stage=confirm'
);

-- ----------------------------------------------------------------------------
-- 4. Inventory notes
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§110%' OR note LIKE '%totp_locked alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_totp_verify_for_partner'),
  'function_inventory note for verify mentions §110 / totp_locked'
);
SELECT ok(
  (SELECT note LIKE '%§110%' OR note LIKE '%totp_locked alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_totp_confirm_for_partner'),
  'function_inventory note for confirm mentions §110 / totp_locked'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
