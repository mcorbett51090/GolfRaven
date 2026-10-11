-- 63_partner_session_lock_revoke.sql
-- 0085_partner_session_lock_revoke.sql (P5 §72): lock revokes with
-- revoke_reason = 'lock'. Proved:
--   1. structure / ACL / inventory (edge_partner; class SESSION; body);
--   2. lock → revoked_at set, revoke_reason = 'lock';
--   3. re-bind same token → 28000;
--   4. another live session of the same user is untouched.
-- Plants two live sessions for helpers.sql staff_x (a1).

\set QUIET 1
BEGIN;
SELECT plan(12);

GRANT edge_partner, edge_partner_minter, edge_actor, private_definer, partner_session_issuer, partner_reauth_verifier, partner_pin_verifier TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config TO CURRENT_USER;
CREATE POLICY zz63_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

INSERT INTO app.partner_rp_config (rp_id, origin)
VALUES ('partners.example.test', 'https://partners.example.test')
ON CONFLICT DO NOTHING;

CREATE TEMP TABLE creds (label text PRIMARY KEY, uid uuid, cred_id bytea, cred_row uuid);
GRANT ALL ON creds TO PUBLIC;

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('plant63:' || p_label, 'UTF8')), 'hex')
$f$;

CREATE FUNCTION pg_temp.newcred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  cid bytea; rid uuid;
BEGIN
  cid := public.gen_random_bytes(32);
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, sign_count)
  VALUES (p_uid, cid, decode(repeat('ab', 32), 'hex'), -7, 0)
  RETURNING id INTO rid;
  INSERT INTO creds VALUES (p_label, p_uid, cid, rid);
  RETURN rid;
END
$f$;

CREATE FUNCTION pg_temp.plant(p_label text, p_cred text) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  v_id uuid := gen_random_uuid();
  c record;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  SET CONSTRAINTS ALL IMMEDIATE;
  ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
  INSERT INTO app.partner_session (
    id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
    mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature
  ) VALUES (
    v_id,
    pg_temp.th(p_label),
    c.uid, c.cred_row, 1,
    now() - interval '1 hour', now(), now() + interval '8 hours',
    'sign_in',
    sha256(convert_to('plant63n:' || p_label, 'UTF8')),
    decode(repeat('04', 40), 'hex'),
    convert_to('{}', 'UTF8'),
    decode(repeat('05', 70), 'hex')
  );
  ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
  RETURN v_id;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure / ACL / inventory / class SESSION
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_session_lock_for_partner'
     AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer'
     AND 'search_path=""' = ANY (p.proconfig)
     AND p.prosrc ~ 'partner_authorize' AND p.prosrc ~ '''SESSION'''
     AND p.prosrc ~ 'revoke_reason' AND p.prosrc ~ '''lock'''
     AND p.prosrc !~ 'partner_pin_grant_consume'
     AND p.prosrc !~ 'partner_reauth_clear'
     AND p.prosrc !~ 'partner_totp_mfa_clear'),
  1,
  'structure: SECURITY DEFINER / private_definer / SESSION revoke with reason lock (no grant/mfa clears)'
);

SELECT is(
  (SELECT has_function_privilege('edge_partner', 'private.partner_session_lock_for_partner()', 'EXECUTE')
        AND NOT has_function_privilege('edge_actor', 'private.partner_session_lock_for_partner()', 'EXECUTE')
        AND NOT has_function_privilege('edge_system', 'private.partner_session_lock_for_partner()', 'EXECUTE')
        AND NOT has_function_privilege('anon', 'private.partner_session_lock_for_partner()', 'EXECUTE')),
  true,
  'privileges: edge_partner EXECUTE only among client/edge roles checked'
);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_edge_partner AND NOT expected_edge_partner_minter AND NOT expected_edge_system
          AND note LIKE '%revoke_reason = lock%'
   FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'partner_session_lock_for_partner'),
  true,
  'inventory: edge_partner; note records revoke_reason = lock'
);
SELECT tests.clear_actor();

SELECT is(
  (SELECT obj_description('private.partner_session_lock_for_partner()'::regprocedure)
          LIKE '%revoke_reason%lock%'),
  true,
  'COMMENT mentions revoke_reason lock'
);

SELECT is(
  (SELECT count(*)::int FROM unnest(ARRAY[
     'private.partner_whoami_for_partner()',
     'private.partner_session_revoke_for_partner()',
     'private.partner_session_lock_for_partner()'
   ]) AS t(ident)
   WHERE t.ident = 'private.partner_session_lock_for_partner()'),
  1,
  'class: lock remains listed with the SESSION/PEEK peers'
);

-- ----------------------------------------------------------------------------
-- 2. Behaviour: revoke bound session; other session untouched; re-bind 28000
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('a', '00000000-0000-0000-0000-1000000000a1') IS NOT NULL AS ok1 \gset
SELECT pg_temp.newcred('b', '00000000-0000-0000-0000-1000000000a1') IS NOT NULL AS ok2 \gset
SELECT pg_temp.plant('s_a', 'a') AS sid_a \gset
SELECT pg_temp.plant('s_b', 'b') AS sid_b \gset
SELECT pg_temp.th('s_a') AS th_a, pg_temp.th('s_b') AS th_b \gset

SELECT is(
  (SELECT count(*)::int FROM app.partner_session WHERE id IN (:'sid_a'::uuid, :'sid_b'::uuid) AND revoked_at IS NULL),
  2,
  'setup: two live planted sessions for staff_x'
);

SAVEPOINT lock1;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_a'), 'lock: bind session A');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'lock: runs');
RESET ROLE;
SELECT is(
  (SELECT revoke_reason FROM app.partner_session WHERE id = :'sid_a'::uuid),
  'lock',
  'lock: revoke_reason = lock'
);
SELECT ok(
  (SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'sid_a'::uuid),
  'lock: revoked_at is set'
);
SELECT is(
  (SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'sid_b'::uuid),
  true,
  'lock: another session of the same user is untouched'
);
ROLLBACK TO SAVEPOINT lock1;

SAVEPOINT lock2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_a');
SELECT private.partner_session_lock_for_partner();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  format($$SELECT private.bind_partner_session(%L)$$, :'th_a'),
  '28000',
  'partner_session_refused',
  'lock: re-bind of the same token is one uniform 28000'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT lock2;

SELECT * FROM finish();
ROLLBACK;
