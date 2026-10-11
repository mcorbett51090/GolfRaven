-- 75_partner_member_revoke_alarm.sql
-- 0097_partner_member_revoke_alarm.sql (P5 §102): kind member_revoke on
-- partner_auth_alarm raised from partner_member_revoke_for_partner on ok.
-- Proved here: kind/row CHECKs, policies, manager revoke raises one row
-- per target per minute (ON CONFLICT quiet after restoring membership),
-- detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_member, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz75_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz75_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz75_mem ON app.partner_member FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz75_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s75:' || p_label) || md5('s75b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c75:' || p_label) || md5('c75b:' || p_label), 'hex'),
          decode(md5('k75:' || p_label) || md5('k75b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n75:' || p_label) || md5('n75b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
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
CREATE FUNCTION pg_temp.revoke_mem(p_uid uuid, p_org uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2('mx');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_member_revoke_for_partner(p_uid, p_org);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a2(text), pg_temp.revoke_mem(uuid, uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_revoke', 'a5300000-0000-0000-0000-000000000075', '00000000-0000-0000-0000-1000000000a1', 1)$$,
  '23514', NULL,
  'member_revoke refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_revoke', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'member_revoke requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('member_revoke', NULL, '00000000-0000-0000-0000-1000000000ff', 9401)$$,
  'member_revoke accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%member_revoke%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes member_revoke'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_member_revoke_alarm_insert', 'pd_partner_member_revoke_alarm_select')),
  2,
  'structure: partner-bound member_revoke INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Manager revoke raises alarm; restore membership and second call is quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.th('mx') AS th_mx \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;

SELECT is(pg_temp.revoke_mem('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001'), 'ok',
  'manager revoke of staff@X → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'revoke raises one member_revoke alarm keyed on target uid'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  true,
  'member_revoke leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  '00000000-0000-0000-0000-1000000000a1',
  'detail.subject is the revoke target'
);
SELECT is(
  (SELECT detail ->> 'org' FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  '10000000-0000-0000-0000-000000000001',
  'detail.org is the membership org'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  'ok',
  'detail.status is ok'
);

-- Restore active membership so a second revoke in the same minute can fire (flood).
UPDATE app.partner_member
SET revoked_at = NULL, revoked_by = NULL
WHERE user_id = '00000000-0000-0000-0000-1000000000a1'
  AND org_id = '10000000-0000-0000-0000-000000000001';
SELECT is(pg_temp.revoke_mem('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001'), 'ok',
  'second revoke in the same minute still returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'member_revoke' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'second revoke in the same minute is ON CONFLICT DO NOTHING'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§102%' OR note LIKE '%member_revoke alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_member_revoke_for_partner'),
  'function_inventory note mentions §102 / member_revoke alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
