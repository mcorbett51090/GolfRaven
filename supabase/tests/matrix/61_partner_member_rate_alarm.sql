-- 61_partner_member_rate_alarm.sql
-- 0083_partner_member_rate_alarm.sql (P5 §70): member-keyed alert-only
-- rate_member bucket. Proved here: kind/row CHECKs, EXECUTE surface,
-- binding required, unbound refuse, ON CONFLICT quiet, audit on insert,
-- inventory. partner_rate_alarm_raise (minter-only) stays closed to
-- edge_partner.

\set QUIET 1
BEGIN;
SELECT plan(18);

GRANT edge_partner, edge_partner_minter, edge_actor, private_definer
  TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_alarm, app.audit_log TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz61_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz61_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz61_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz61_audit ON app.audit_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s61:' || p_label) || md5('s61b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c61:' || p_label) || md5('c61b:' || p_label), 'hex'),
          decode(md5('k61:' || p_label) || md5('k61b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n61:' || p_label) || md5('n61b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_member', 'a5300000-0000-0000-0000-000000000061', '00000000-0000-0000-0000-1000000000a1', 1)$$,
  '23514', NULL,
  'rate_member refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_member', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'rate_member requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_member', NULL, '00000000-0000-0000-0000-1000000000a1', 7001)$$,
  'rate_member accepts NULL credential_id + uuid bucket_key'
);

-- ----------------------------------------------------------------------------
-- 2. EXECUTE + structure
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n)
   FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'),
                ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
   WHERE has_function_privilege(r.n, 'private.partner_member_rate_alarm_raise(jsonb)'::regprocedure, 'EXECUTE')),
  ARRAY['edge_partner'],
  'EXECUTE: only edge_partner may run partner_member_rate_alarm_raise'
);
SELECT is(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole
   FROM pg_proc p WHERE p.oid = 'private.partner_member_rate_alarm_raise(jsonb)'::regprocedure),
  true,
  'partner_member_rate_alarm_raise is SECURITY DEFINER search_path='''' owned by private_definer'
);
SELECT ok(
  NOT has_function_privilege('edge_partner', 'private.partner_rate_alarm_raise(text, text, jsonb)'::regprocedure, 'EXECUTE'),
  'partner_rate_alarm_raise stays closed to edge_partner (minter-only)'
);

-- ----------------------------------------------------------------------------
-- 3. Binding required / unbound refuse / raise / ON CONFLICT / audit
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$SET LOCAL ROLE edge_partner; SELECT private.partner_member_rate_alarm_raise('{"stage":"t"}'::jsonb)$$,
  '42501', NULL,
  'partner_member_rate_alarm_raise refuses without a partner binding'
);
RESET ROLE;

-- Actor binding must also refuse (kind <> partner), before any partner bind.
SAVEPOINT sp_actor;
SELECT lives_ok($$SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$,
  'setup: bind a user so partner_binding_kind() is not partner');
RESET ROLE;
SELECT throws_ok(
  $$SET LOCAL ROLE edge_partner; SELECT private.partner_member_rate_alarm_raise('{"stage":"t"}'::jsonb)$$,
  '42501', NULL,
  'partner_member_rate_alarm_raise refuses inside a non-partner binding'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT sp_actor;

SELECT pg_temp.th('stf') AS th_stf \gset
SELECT pg_temp.mk_cred('stf', '00000000-0000-0000-0000-1000000000a1') AS c_stf \gset
SELECT pg_temp.mk_session('stf', '00000000-0000-0000-0000-1000000000a1', :'c_stf') AS s_stf \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_stf');
SELECT lives_ok(
  $$SELECT private.partner_member_rate_alarm_raise('{"stage":"partner-any-call"}'::jsonb)$$,
  'bound edge_partner can raise rate_member'
);
SELECT lives_ok(
  $$SELECT private.partner_member_rate_alarm_raise('{"stage":"partner-any-call"}'::jsonb)$$,
  'second raise in the same minute is ON CONFLICT DO NOTHING'
);
RESET ROLE;

SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'rate_member' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  1,
  'one rate_member row per (kind, binding uid, minute)'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'rate_member' AND bucket_key = '00000000-0000-0000-0000-1000000000a1'),
  true,
  'rate_member leaves credential_id NULL'
);
SELECT is(
  (SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.rate.rate_member'),
  1,
  'audit_log partner.rate.rate_member only when the alarm row is new'
);
SELECT is(
  (SELECT subject_id FROM app.audit_log WHERE action = 'partner.rate.rate_member' LIMIT 1),
  '00000000-0000-0000-0000-1000000000a1',
  'audit subject_id is the binding uid (bucket_key), never caller-chosen'
);

-- Caller cannot choose bucket_key: row CHECK + writer always uses binding uid.
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_member', NULL, repeat('ab', 32), 1)$$,
  '23514', NULL,
  'rate_member refuses a non-uuid bucket_key (no caller-chosen IP hash)'
);

-- ----------------------------------------------------------------------------
-- 4. Inventory
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_edge_partner AND NOT expected_edge_partner_minter AND NOT expected_edge_system
   FROM private.function_inventory WHERE function_name = 'partner_member_rate_alarm_raise'),
  true,
  'function_inventory: partner_member_rate_alarm_raise expected_edge_partner=true'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
