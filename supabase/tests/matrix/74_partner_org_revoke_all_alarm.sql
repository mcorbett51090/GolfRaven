-- 74_partner_org_revoke_all_alarm.sql
-- 0096_partner_org_revoke_all_alarm.sql (P5 §101): kind org_revoke_all on
-- partner_auth_alarm raised from partner_org_sessions_revoke_for_partner
-- on ok. Proved here: kind/row CHECKs, policies, manager revoke-all raises
-- one row per org per minute (ON CONFLICT quiet; second call uses a fresh
-- session because panic_revoke_all revokes the actor's session too),
-- detail shape, inventory.

\set QUIET 1
BEGIN;
SELECT plan(13);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz74_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz74_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz74_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s74:' || p_label) || md5('s74b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c74:' || p_label) || md5('c74b:' || p_label), 'hex'),
          decode(md5('k74:' || p_label) || md5('k74b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n74:' || p_label) || md5('n74b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
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
CREATE FUNCTION pg_temp.revoke_all(p_org uuid, p_label text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2(p_label);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(pg_temp.th(p_label));
  SELECT * INTO r FROM private.partner_org_sessions_revoke_for_partner(p_org, NULL);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a2(text), pg_temp.revoke_all(uuid, text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('org_revoke_all', 'a5300000-0000-0000-0000-000000000074', '10000000-0000-0000-0000-000000000001', 1)$$,
  '23514', NULL,
  'org_revoke_all refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('org_revoke_all', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'org_revoke_all requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('org_revoke_all', NULL, '10000000-0000-0000-0000-0000000000ff', 9301)$$,
  'org_revoke_all accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%org_revoke_all%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes org_revoke_all'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_org_revoke_all_alarm_insert', 'pd_partner_org_revoke_all_alarm_select')),
  2,
  'structure: partner-bound org_revoke_all INSERT + SELECT policies'
);

-- ----------------------------------------------------------------------------
-- 2. Manager revoke-all raises alarm; second call (fresh session) is quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx1', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx1 \gset

SELECT is(pg_temp.revoke_all('10000000-0000-0000-0000-000000000001', 'mx1'), 'ok',
  'manager revoke-all at facility X → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'org_revoke_all' AND bucket_key = '10000000-0000-0000-0000-000000000001'),
  1,
  'revoke-all raises one org_revoke_all alarm keyed on org id'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'org_revoke_all' AND bucket_key = '10000000-0000-0000-0000-000000000001'),
  true,
  'org_revoke_all leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'org' FROM app.partner_auth_alarm
   WHERE kind = 'org_revoke_all' AND bucket_key = '10000000-0000-0000-0000-000000000001'),
  '10000000-0000-0000-0000-000000000001',
  'detail.org is the org'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'org_revoke_all' AND bucket_key = '10000000-0000-0000-0000-000000000001'),
  'ok',
  'detail.status is ok'
);

-- Panic revoked the actor session: mint a second manager session, then smudge
-- xact (PA-2 / matrix 69) so a second bind in this transaction is allowed.
SELECT pg_temp.mk_session('mx2', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx2 \gset
SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SELECT is(pg_temp.revoke_all('10000000-0000-0000-0000-000000000001', 'mx2'), 'ok',
  'second revoke-all in the same minute still returns ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'org_revoke_all' AND bucket_key = '10000000-0000-0000-0000-000000000001'),
  1,
  'second revoke-all in the same minute is ON CONFLICT DO NOTHING'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§101%' OR note LIKE '%org_revoke_all alarm%'
   FROM private.function_inventory
   WHERE function_name = 'partner_org_sessions_revoke_for_partner'),
  'function_inventory note mentions §101 / org_revoke_all alarm'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
