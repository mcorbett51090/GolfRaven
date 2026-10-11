-- 78_partner_enrolment_issue_alarm.sql
-- 0100_partner_enrolment_issue_alarm.sql (P5 §106): kind enrolment_issue on
-- partner_auth_alarm raised from partner_admin_enrolment_issue_for_partner
-- on ok. Proved here: kind/row CHECKs, policies, admin issue raises one
-- row per target uid per minute, second issue in the same minute is
-- ON CONFLICT quiet, detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(15);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.admin_user, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz78_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz78_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz78_adm ON app.admin_user FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz78_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s78:' || p_label) || md5('s78b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h78:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c78:' || p_label) || md5('c78b:' || p_label), 'hex'),
          decode(md5('k78:' || p_label) || md5('k78b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 2) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '50 minutes', 'sign_in',
          decode(md5('n78:' || p_label) || md5('n78b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_a3(p_label text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    mfa_until = clock_timestamp() + interval '240 seconds'
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.issue(p_target uuid, p_hash text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a3('ad');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_admin_enrolment_issue_for_partner(p_target, p_hash);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_target uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'enrolment_issue',
    NULL,
    p_target::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('subject', p_target::text, 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.hh(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a3(text), pg_temp.issue(uuid, text), pg_temp.force_alarm(uuid) TO PUBLIC;

-- second admin target (helpers only seeds d0)
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email, email_confirmed_at)
VALUES ('ee780000-0000-0000-0000-000000000002', 'admin2-78@example.test', now());
RESET ROLE;
INSERT INTO app.admin_user (user_id) VALUES ('ee780000-0000-0000-0000-000000000002');

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_issue', 'a5300000-0000-0000-0000-000000000078', 'a5300000-0000-0000-0000-000000000078', 1)$$,
  '23514', NULL,
  'enrolment_issue refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_issue', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'enrolment_issue requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_issue', NULL, 'ee780000-0000-0000-0000-0000000000ff', 9701)$$,
  'enrolment_issue accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%enrolment_issue%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes enrolment_issue'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_enrolment_issue_alarm_insert', 'pd_partner_enrolment_issue_alarm_select')),
  2,
  'structure: partner-bound enrolment_issue INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Admin issue raises alarm; second issue + ON CONFLICT stay at one row
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.th('ad') AS th_ad \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;

SELECT is(pg_temp.issue('ee780000-0000-0000-0000-000000000002', pg_temp.hh('t1')), 'ok',
  'admin issues enrolment token for a different admin → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  1,
  'issue raises one enrolment_issue alarm keyed on target uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  true,
  'enrolment_issue leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  'ee780000-0000-0000-0000-000000000002',
  'detail.subject is the target admin'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  'ok',
  'detail.status is ok'
);

SELECT is(pg_temp.issue('ee780000-0000-0000-0000-000000000002', pg_temp.hh('t2')), 'ok',
  'second issue for the same target in the same minute still returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  1,
  'second issue in the same minute is ON CONFLICT DO NOTHING'
);
SELECT lives_ok(
  $$SELECT pg_temp.force_alarm('ee780000-0000-0000-0000-000000000002'::uuid)$$,
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_issue' AND bucket_key = 'ee780000-0000-0000-0000-000000000002'),
  1,
  'ON CONFLICT keeps a single enrolment_issue row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§106%' OR note LIKE '%enrolment_issue alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_admin_enrolment_issue_for_partner'),
  'function_inventory note mentions §106 / enrolment_issue alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
