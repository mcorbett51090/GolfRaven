-- 70_partner_totp_reset_alarm.sql
-- 0092_partner_totp_reset_alarm.sql (P5 §95): kind totp_reset on
-- partner_auth_alarm raised from partner_totp_reset_for_partner.
-- Proved here: kind/row CHECKs, policies, admin reset raises one row
-- per target per minute (ON CONFLICT quiet), detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_totp, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz70_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz70_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz70_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz70_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s70:' || p_label) || md5('s70b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c70:' || p_label) || md5('c70b:' || p_label), 'hex'),
          decode(md5('k70:' || p_label) || md5('k70b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 2) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n70:' || p_label) || md5('n70b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
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
CREATE FUNCTION pg_temp.seed_totp(p_uid uuid, p_ver integer DEFAULT 1) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
  VALUES (p_uid, p_ver, clock_timestamp(), NULL, clock_timestamp(), NULL, 0, NULL, NULL, clock_timestamp())
$f$;
CREATE FUNCTION pg_temp.reset_totp(p_uid uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_reset_for_partner(p_uid);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_step(text, jsonb), pg_temp.seed_totp(uuid, integer), pg_temp.reset_totp(uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_reset', 'a5300000-0000-0000-0000-000000000070', '00000000-0000-0000-0000-3000000000c1', 1)$$,
  '23514', NULL,
  'totp_reset refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_reset', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'totp_reset requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('totp_reset', NULL, '00000000-0000-0000-0000-3000000000ff', 8001)$$,
  'totp_reset accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%totp_reset%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes totp_reset'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_totp_reset_alarm_insert', 'pd_partner_totp_reset_alarm_select')),
  2,
  'structure: partner-bound totp_reset INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Admin reset raises alarm; second call in same minute is quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op') AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad') AS s_ad \gset
SELECT pg_temp.th('ad') AS th_ad \gset

SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 3);
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240}'::jsonb);

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;

SELECT is(pg_temp.reset_totp('00000000-0000-0000-0000-3000000000c1'), 'ok',
  'admin reset of operator TOTP → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_reset' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'reset raises one totp_reset alarm keyed on target uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'totp_reset' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  true,
  'totp_reset leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'target' FROM app.partner_auth_alarm
   WHERE kind = 'totp_reset' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  '00000000-0000-0000-0000-3000000000c1',
  'detail.target is the reset target'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'totp_reset' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  'ok',
  'detail.status mirrors the reset outcome'
);

-- Re-confirm so a second reset in the same minute still succeeds, then ON CONFLICT.
UPDATE app.partner_totp
SET seed_version = seed_version + 1, confirmed_at = clock_timestamp(), enrolled_at = clock_timestamp()
WHERE user_id = '00000000-0000-0000-0000-3000000000c1';
SELECT is(pg_temp.reset_totp('00000000-0000-0000-0000-3000000000c1'), 'ok',
  'second reset in the same minute still returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'totp_reset' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  1,
  'second reset in the same minute is ON CONFLICT DO NOTHING'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§95%' OR note LIKE '%totp_reset alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_totp_reset_for_partner'),
  'function_inventory note mentions §95 / totp_reset alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
