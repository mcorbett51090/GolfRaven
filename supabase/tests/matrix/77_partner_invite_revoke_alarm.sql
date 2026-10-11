-- 77_partner_invite_revoke_alarm.sql
-- 0099_partner_invite_revoke_alarm.sql (P5 §105): kind invite_revoke on
-- partner_auth_alarm raised from partner_invite_revoke_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, manager revoke raises one row
-- per invite per minute, already_revoked stays quiet, ON CONFLICT quiet
-- on a forced re-insert, detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(16);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_invite, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz77_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz77_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz77_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz77_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s77:' || p_label) || md5('s77b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c77:' || p_label) || md5('c77b:' || p_label), 'hex'),
          decode(md5('k77:' || p_label) || md5('k77b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n77:' || p_label) || md5('n77b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_inv(p_label text) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (
    '10000000-0000-0000-0000-000000000001',
    'staff',
    'fac_x',
    '00000000-0000-0000-0000-2000000000b1',
    p_label || '@example.test',
    encode(sha256(convert_to('h77:' || p_label, 'UTF8')), 'hex'),
    now() + interval '72 hours',
    now()
  )
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
CREATE FUNCTION pg_temp.revoke_inv(p_inv uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2('mx');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_invite_revoke_for_partner(p_inv);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
-- Invite revoke is final for the row; prove ON CONFLICT without un-revoking.
CREATE FUNCTION pg_temp.force_alarm(p_inv uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_revoke',
    NULL,
    p_inv::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('invite', p_inv::text, 'org', '10000000-0000-0000-0000-000000000001', 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.mk_inv(text), pg_temp.seed_a2(text), pg_temp.revoke_inv(uuid), pg_temp.force_alarm(uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_revoke', 'a5300000-0000-0000-0000-000000000077', 'a5300000-0000-0000-0000-000000000077', 1)$$,
  '23514', NULL,
  'invite_revoke refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_revoke', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'invite_revoke requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_revoke', NULL, 'a5300000-0000-0000-0000-0000000000ff', 9601)$$,
  'invite_revoke accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%invite_revoke%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes invite_revoke'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_invite_revoke_alarm_insert', 'pd_partner_invite_revoke_alarm_select')),
  2,
  'structure: partner-bound invite_revoke INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Manager revoke raises alarm; already_revoked + ON CONFLICT stay at one row
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_inv('mx1') AS inv_mx \gset
SELECT pg_temp.th('mx') AS th_mx \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;

SELECT is(pg_temp.revoke_inv(:'inv_mx'), 'ok',
  'manager revoke of facility invite → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  1,
  'revoke raises one invite_revoke alarm keyed on invite id'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  true,
  'invite_revoke leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'invite' FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  :'inv_mx',
  'detail.invite is the invite id'
);
SELECT is(
  (SELECT detail ->> 'org' FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  '10000000-0000-0000-0000-000000000001',
  'detail.org is the invite org'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  'ok',
  'detail.status is ok'
);

SELECT is(pg_temp.revoke_inv(:'inv_mx'), 'already_revoked',
  'second revoke is already_revoked');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  1,
  'already_revoked does not add another alarm'
);
SELECT lives_ok(
  format($$SELECT pg_temp.force_alarm(%L::uuid)$$, :'inv_mx'),
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_revoke' AND bucket_key = :'inv_mx'),
  1,
  'ON CONFLICT keeps a single invite_revoke row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§105%' OR note LIKE '%invite_revoke alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_invite_revoke_for_partner'),
  'function_inventory note mentions §105 / invite_revoke alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
