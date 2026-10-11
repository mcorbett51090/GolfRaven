-- 71_partner_pin_locked_alarm.sql
-- 0093_partner_pin_locked_alarm.sql (P5 §97): kind pin_locked on
-- partner_auth_alarm raised from partner_pin_verify_for_partner and
-- partner_pin_change_for_partner when o_newly_locked. Proved here:
-- kind/row CHECKs, policies, verify + change raise one row per subject
-- per minute, detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(15);

GRANT edge_partner, private_definer, partner_pin_verifier TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_pin, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz71_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz71_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz71_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz71_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s71:' || p_label) || md5('s71b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c71:' || p_label) || md5('c71b:' || p_label), 'hex'),
          decode(md5('k71:' || p_label) || md5('k71b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n71:' || p_label) || md5('n71b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.vf(p_uid uuid, p_derived bytea) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(convert_to('golfraven/partner-pin/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_uid::text, '-', ''), 'hex') || p_derived,
                     convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper'), 'UTF8'), 'sha256')
$f$;
CREATE FUNCTION pg_temp.seed_pin(p_uid uuid, p_derived bytea, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, failed_day, last_failed_at, next_attempt_at, locked_at, must_change)
  VALUES (p_uid, decode(repeat('0a', 16), 'hex'), 600000, pg_temp.vf(p_uid, p_derived),
          coalesce((p_opts ->> 'failed_count')::smallint, 0), coalesce((p_opts ->> 'failed_today')::smallint, 0), (p_opts ->> 'failed_day')::date, NULL,
          (p_opts ->> 'next_attempt_at')::timestamptz, (p_opts ->> 'locked_at')::timestamptz, coalesce((p_opts ->> 'must_change')::boolean, false))
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.pv(p_derived bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_verify_for_partner(p_derived);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.pchg(p_current bytea, p_derived bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_change_for_partner(p_current, p_derived, decode(repeat('0c', 16), 'hex'), 600000);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.vf(uuid, bytea), pg_temp.seed_pin(uuid, bytea, jsonb), pg_temp.seed_step(text, jsonb),
  pg_temp.pv(bytea), pg_temp.pchg(bytea, bytea) TO PUBLIC;

SELECT '\x' || repeat('11', 32) AS dk_ok \gset
SELECT '\x' || repeat('22', 32) AS dk_bad \gset
SELECT '\x' || repeat('33', 32) AS dk_new \gset

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_locked', 'a5300000-0000-0000-0000-000000000071', '00000000-0000-0000-0000-1000000000a1', 1)$$,
  '23514', NULL,
  'pin_locked refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_locked', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'pin_locked requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_locked', NULL, '00000000-0000-0000-0000-1000000000ff', 9001)$$,
  'pin_locked accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%pin_locked%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes pin_locked'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_pin_locked_alarm_insert', 'pd_partner_pin_locked_alarm_select')),
  2,
  'structure: partner-bound pin_locked INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Verify path: 5th wrong key raises alarm; further locked attempts do not
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.th('sx') AS th_sx \gset
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea,
  jsonb_build_object('failed_count', 4, 'next_attempt_at', clock_timestamp() - interval '1 second'));

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;

SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'locked|0',
  'verify: 5th wrong key locks the PIN');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'pin_locked' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'verify lock raises one pin_locked alarm keyed on subject uid'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'pin_locked' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  '00000000-0000-0000-0000-1000000000a1',
  'detail.subject is the locked member'
);
SELECT is(
  (SELECT detail ->> 'stage' FROM app.partner_auth_alarm
   WHERE kind = 'pin_locked' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  'verify',
  'detail.stage is verify'
);
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'locked|0',
  'a further attempt on a locked PIN is still locked');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'pin_locked' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'further locked attempts do not raise another alarm'
);

-- ----------------------------------------------------------------------------
-- 3. Change path: 5th wrong current key raises alarm with stage=change
-- (smudge xact like matrix 69 so a second bind in this transaction is allowed)
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.th('sy') AS th_sy \gset
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a3', :'dk_ok'::bytea,
  jsonb_build_object('failed_count', 4, 'next_attempt_at', clock_timestamp() - interval '1 second'));
SELECT pg_temp.seed_step('sy', '{"otp_s": 500}'::jsonb);

SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
RESET ROLE;

SELECT is(pg_temp.pchg(:'dk_bad'::bytea, :'dk_new'::bytea), 'locked|0',
  'change: 5th wrong current key locks the PIN');
SELECT is(
  (SELECT detail ->> 'stage' FROM app.partner_auth_alarm
   WHERE kind = 'pin_locked' AND bucket_key = '00000000-0000-0000-0000-1000000000a3'),
  'change',
  'change lock raises pin_locked with detail.stage=change'
);

-- ----------------------------------------------------------------------------
-- 4. Inventory notes
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§97%' OR note LIKE '%pin_locked alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_pin_verify_for_partner'),
  'function_inventory note for verify mentions §97 / pin_locked'
);
SELECT ok(
  (SELECT note LIKE '%§97%' OR note LIKE '%pin_locked alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_pin_change_for_partner'),
  'function_inventory note for change mentions §97 / pin_locked'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
