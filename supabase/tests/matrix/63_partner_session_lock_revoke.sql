-- 63_partner_session_lock_revoke.sql
-- 0085_partner_session_lock_revoke.sql (P5 §72): lock revokes with
-- revoke_reason = 'lock'. Proved:
--   1. structure / ACL / inventory (edge_partner; class SESSION; body);
--   2. lock → revoked_at set, revoke_reason = 'lock';
--   3. re-bind same token → 28000;
--   4. another live session of the same user is untouched.
-- Uses helpers.sql staff_x (a1) + two credentials / two mint sessions.

\set QUIET 1
BEGIN;
SELECT plan(12);

GRANT edge_partner, edge_partner_minter, private_definer, partner_session_issuer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config TO CURRENT_USER;
CREATE POLICY zz63_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz63_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

INSERT INTO app.partner_rp_config (rp_id, origin)
VALUES ('partners.example.test', 'https://partners.example.test')
ON CONFLICT DO NOTHING;

SET LOCAL ROLE private_definer;
\i supabase/tests/partner-sign-helpers.sql
RESET ROLE;

CREATE TEMP TABLE creds (label text PRIMARY KEY, uid uuid, d numeric, qx numeric, qy numeric, cred_id bytea, cred_row uuid);
CREATE TEMP TABLE asr (label text PRIMARY KEY, token text, cred_id bytea, nonce bytea, exp bigint, mac bytea, ad bytea, cd bytea, sig bytea);
CREATE TEMP TABLE mres (label text, o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz);
GRANT ALL ON creds, asr, mres TO PUBLIC;

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex')
$f$;

CREATE FUNCTION pg_temp.newcred(p_label text, p_uid uuid DEFAULT NULL, p_stored bigint DEFAULT 0) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  d numeric; pub numeric[]; cid bytea; cose bytea; rid uuid;
BEGIN
  IF p_uid IS NULL THEN
    p_uid := gen_random_uuid();
    EXECUTE 'SET LOCAL ROLE service_role';
    INSERT INTO auth.users (id, email) VALUES (p_uid, 'lock63-' || p_label || '@example.test');
    EXECUTE 'RESET ROLE';
  END IF;
  EXECUTE 'SET LOCAL ROLE private_definer';
  d := private.partner_sig_os2ip(public.gen_random_bytes(32)) % (private.partner_sig_p256_n() - 1) + 1;
  pub := pg_temp.ps_pub(d);
  cose := pg_temp.ps_cose_es256(pub[1], pub[2]);
  EXECUTE 'RESET ROLE';
  cid := public.gen_random_bytes(32);
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, sign_count) VALUES (p_uid, cid, cose, -7, p_stored) RETURNING id INTO rid;
  INSERT INTO creds VALUES (p_label, p_uid, d, pub[1], pub[2], cid, rid);
  RETURN rid;
END
$f$;

CREATE FUNCTION pg_temp.signin(p_label text, p_cred text, p_counter bigint) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; a record; v_th text;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  v_th := pg_temp.th(p_label);
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter);
  EXECUTE 'RESET ROLE';
  INSERT INTO asr VALUES (p_label, v_th, c.cred_id, a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  INSERT INTO mres SELECT p_label, m.* FROM private.partner_session_mint(
    v_th, c.cred_id, a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig) m;
  EXECUTE 'RESET ROLE';
  RETURN (SELECT o_status FROM mres WHERE label = p_label ORDER BY ctid DESC LIMIT 1);
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
SELECT pg_temp.newcred('staff', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS ok1 \gset
SELECT pg_temp.newcred('staff2', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS ok2 \gset
SELECT is(pg_temp.signin('s_a', 'staff', 1), 'ok', 'setup: mint session A for staff_x');
SELECT is(pg_temp.signin('s_b', 'staff2', 1), 'ok', 'setup: mint session B (same user, other credential)');

SELECT pg_temp.th('s_a') AS th_a, pg_temp.th('s_b') AS th_b \gset
SELECT (SELECT o_session_id FROM mres WHERE label = 's_a') AS sid_a,
       (SELECT o_session_id FROM mres WHERE label = 's_b') AS sid_b \gset

SAVEPOINT lock1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_a');
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
-- same transaction: after revoke, a fresh bind of the dead token is refused
SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  format($$SELECT private.bind_partner_session(%L)$$, :'th_a'),
  '28000',
  'partner_session_refused',
  'lock: re-bind of the same token is one uniform 28000'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT lock1;

SELECT * FROM finish();
ROLLBACK;
