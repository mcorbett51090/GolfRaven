-- 84_partner_pin_set_alarm.sql
-- 0106_partner_pin_set_alarm.sql (P5 §112): kind pin_set on
-- partner_auth_alarm raised from partner_pin_set_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, first set under enrolment_until
-- raises one row per subject per minute, already_set stays quiet,
-- ON CONFLICT quiet, detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(15);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_pin, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz84_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz84_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz84_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz84_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s84:' || p_label) || md5('s84b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c84:' || p_label) || md5('c84b:' || p_label), 'hex'),
          decode(md5('k84:' || p_label) || md5('k84b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_mint_kind text DEFAULT 'sign_in', p_enrol interval DEFAULT NULL) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature, enrolment_until)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, 1, now() - interval '1 hour', now(), now() + interval '7 hours', p_mint_kind,
          decode(md5('n84:' || p_label) || md5('n84b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'),
          CASE WHEN p_mint_kind = 'sign_in' THEN decode(repeat('05', 70), 'hex') END,
          CASE WHEN p_enrol IS NOT NULL THEN now() + p_enrol END)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.pset(p_derived bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_set_for_partner(p_derived, decode(repeat('0b', 16), 'hex'), 600000);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_uid uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'pin_set',
    NULL,
    p_uid::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('subject', p_uid::text, 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid),
  pg_temp.mk_session(text, uuid, uuid, text, interval), pg_temp.pset(bytea), pg_temp.force_alarm(uuid) TO PUBLIC;

SELECT decode(repeat('11', 32), 'hex') AS dk_ok \gset

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_set', 'a5300000-0000-0000-0000-000000000084', '00000000-0000-0000-0000-1000000000a1', 1)$$,
  '23514', NULL,
  'pin_set refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_set', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'pin_set requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('pin_set', NULL, '00000000-0000-0000-0000-1000000000ff', 9906)$$,
  'pin_set accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%pin_set%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes pin_set'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_pin_set_alarm_insert', 'pd_partner_pin_set_alarm_select')),
  2,
  'structure: partner-bound pin_set INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. First set raises; already_set quiet; ON CONFLICT quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_session('sx_reg', '00000000-0000-0000-0000-1000000000a1', :'c_sx', 'register', interval '10 minutes') AS s_sx_reg \gset
SELECT pg_temp.th('sx_reg') AS th_sx_reg \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_reg');
RESET ROLE;

SELECT is(pg_temp.pset(:'dk_ok'::bytea), 'ok|0',
  'first PIN set under enrolment_until → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'ok set raises one pin_set alarm keyed on subject uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  true,
  'pin_set leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  '00000000-0000-0000-0000-1000000000a1',
  'detail.subject is the setter uid'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  'ok',
  'detail.status is ok'
);

-- Re-seed enrolment window (set spent otp_proof; enrolment_until still live on register mint).
SELECT is(pg_temp.pset(:'dk_ok'::bytea), 'already_set|0',
  'second set on a live PIN → already_set');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'already_set does not raise another pin_set alarm'
);

SELECT lives_ok(
  $$SELECT pg_temp.force_alarm('00000000-0000-0000-0000-1000000000a1'::uuid)$$,
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'pin_set' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'ON CONFLICT keeps a single pin_set row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§112%' OR note LIKE '%pin_set alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_pin_set_for_partner'),
  'function_inventory note mentions §112 / pin_set alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
