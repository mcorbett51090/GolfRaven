-- 79_partner_invite_create_alarm.sql
-- 0101_partner_invite_create_alarm.sql (P5 §107): kind invite_create on
-- partner_auth_alarm raised from partner_invite_create_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, manager create raises one row
-- per invite per minute, already_member stays quiet, ON CONFLICT quiet
-- on a forced re-insert, detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(17);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_invite, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz79_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz79_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz79_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz79_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s79:' || p_label) || md5('s79b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h79:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c79:' || p_label) || md5('c79b:' || p_label), 'hex'),
          decode(md5('k79:' || p_label) || md5('k79b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n79:' || p_label) || md5('n79b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
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
CREATE FUNCTION pg_temp.create_inv(p_email text, p_hash text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2('mx');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_invite_create_for_partner(
    '10000000-0000-0000-0000-000000000001'::uuid, 'staff', p_email, p_hash);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || ':' || coalesce(r.o_invite_id::text, '');
END
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_inv uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_create',
    NULL,
    p_inv::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('invite', p_inv::text, 'org', '10000000-0000-0000-0000-000000000001', 'role', 'staff', 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.hh(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a2(text), pg_temp.create_inv(text, text), pg_temp.force_alarm(uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_create', 'a5300000-0000-0000-0000-000000000079', 'a5300000-0000-0000-0000-000000000079', 1)$$,
  '23514', NULL,
  'invite_create refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_create', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'invite_create requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_create', NULL, 'a5300000-0000-0000-0000-0000000000ff', 9801)$$,
  'invite_create accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%invite_create%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes invite_create'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_invite_create_alarm_insert', 'pd_partner_invite_create_alarm_select')),
  2,
  'structure: partner-bound invite_create INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Manager create raises alarm; already_member quiet; ON CONFLICT quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.th('mx') AS th_mx \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;

SELECT pg_temp.create_inv('new-staff-79@example.test', pg_temp.hh('c1')) AS create_r \gset
SELECT is(split_part(:'create_r', ':', 1), 'ok',
  'manager create of facility staff invite → ok');
SELECT split_part(:'create_r', ':', 2) AS inv_id \gset
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  1,
  'create raises one invite_create alarm keyed on invite id'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  true,
  'invite_create leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'invite' FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  :'inv_id',
  'detail.invite is the invite id'
);
SELECT is(
  (SELECT detail ->> 'org' FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  '10000000-0000-0000-0000-000000000001',
  'detail.org is the invite org'
);
SELECT is(
  (SELECT detail ->> 'role' FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  'staff',
  'detail.role is the grant role'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  'ok',
  'detail.status is ok'
);

-- staff-x@example.test is already an active member at facility X (helpers)
SELECT is(split_part(pg_temp.create_inv('staff-x@example.test', pg_temp.hh('c2')), ':', 1), 'already_member',
  'already_member stays a status');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  1,
  'already_member does not add another alarm for the created invite'
);
SELECT lives_ok(
  format($$SELECT pg_temp.force_alarm(%L::uuid)$$, :'inv_id'),
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_create' AND bucket_key = :'inv_id'),
  1,
  'ON CONFLICT keeps a single invite_create row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§107%' OR note LIKE '%invite_create alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_invite_create_for_partner'),
  'function_inventory note mentions §107 / invite_create alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
