-- 73_partner_member_recover_alarm.sql
-- 0095_partner_member_recover_alarm.sql (P5 §100): kind member_recover on
-- partner_auth_alarm raised from partner_member_recover_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, manager recover raises one row
-- per target per minute (ON CONFLICT quiet), detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(13);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_pin, app.partner_enrolment_token, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz73_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz73_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz73_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz73_enr ON app.partner_enrolment_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz73_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s73:' || p_label) || md5('s73b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h73:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c73:' || p_label) || md5('c73b:' || p_label), 'hex'),
          decode(md5('k73:' || p_label) || md5('k73b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n73:' || p_label) || md5('n73b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_a2(p_label text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = clock_timestamp() + interval '55 seconds',
    reauth_until = clock_timestamp() + interval '240 seconds',
    mfa_until = clock_timestamp() + interval '240 seconds'
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.mk_pin(p_uid uuid) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, locked_at)
  VALUES (p_uid, decode(repeat('01', 16), 'hex'), 210000, decode(repeat('02', 32), 'hex'), 5, 5, now())
$f$;
CREATE FUNCTION pg_temp.recover(p_uid uuid, p_label text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2('mx');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_member_recover_for_partner(p_uid, pg_temp.hh(p_label));
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.hh(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a2(text), pg_temp.mk_pin(uuid), pg_temp.recover(uuid, text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_recover', 'a5300000-0000-0000-0000-000000000073', '00000000-0000-0000-0000-1000000000a1', 1)$$,
  '23514', NULL,
  'member_recover refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_recover', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'member_recover requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_recover', NULL, '00000000-0000-0000-0000-1000000000ff', 9201)$$,
  'member_recover accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%member_recover%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes member_recover'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_member_recover_alarm_insert', 'pd_partner_member_recover_alarm_select')),
  2,
  'structure: partner-bound member_recover INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Manager recover raises alarm; second call in same minute is quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.th('mx') AS th_mx \gset
SELECT pg_temp.mk_pin('00000000-0000-0000-0000-1000000000a1');

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;

SELECT is(pg_temp.recover('00000000-0000-0000-0000-1000000000a1', 'rec1'), 'ok',
  'manager recover of staff → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'member_recover' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'recover raises one member_recover alarm keyed on target uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'member_recover' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  true,
  'member_recover leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'member_recover' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  '00000000-0000-0000-0000-1000000000a1',
  'detail.subject is the recover target'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'member_recover' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  'ok',
  'detail.status is ok'
);

SELECT is(pg_temp.recover('00000000-0000-0000-0000-1000000000a1', 'rec2'), 'ok',
  'second recover in the same minute still returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'member_recover' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'second recover in the same minute is ON CONFLICT DO NOTHING'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§100%' OR note LIKE '%member_recover alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_member_recover_for_partner'),
  'function_inventory note mentions §100 / member_recover alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
