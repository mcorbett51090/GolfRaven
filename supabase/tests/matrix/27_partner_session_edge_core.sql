-- 27_partner_session_edge_core.sql
-- P5.1a S1.2 (0049): the DATABASE SIDE OF THE PARTNER EDGE CORE, from docs/security/partner-auth-design.md section 12.1 "S1.2": PA-13b (the lane's EXECUTE set), PA-27 (reauth with someone else's credential),
-- the failure cooldown of section 8 ("5 failed verifications per credential per hour, then a cooldown"), GET session through PEEK (it never moves last_seen_at), sign-out, lock, reauth (the issuer, the verifier-owned
-- writer of reauth_until, every refusal a STATUS), hit_partner_rate_limit, and the check-14 (a) behavioural cells of the seven new `_for_partner` definers. What a pgTAP file cannot show -- that the refusal's TRANSACTION COMMITS
-- (the alarm, the burned nonce, the failure counter) -- is the Deno integration suite (supabase/tests/integration/partner-session.deno.test.ts), which commits for real.
--
-- HOW IT RUNS. One transaction, rolled back at the end. Real ES256 signatures are generated at RUN TIME by supabase/tests/partner-sign-helpers.sql (no key is stored anywhere); the sessions are minted by the REAL
-- mint (0048) as edge_partner_minter and bound by the REAL binder as edge_partner, so every cell below runs through the same functions the Edge calls. Every scenario that needs a clean binding runs inside a SAVEPOINT
-- that is rolled back (a second bind in one transaction is itself refused).

\set QUIET 1
BEGIN;
SELECT plan(162);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_partner_minter, edge_actor, partner_session_issuer, partner_reauth_verifier, partner_pin_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config, app.partner_auth_alarm, app.partner_sign_in_failure TO CURRENT_USER;
CREATE POLICY zz27_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_fail ON app.partner_sign_in_failure FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz27_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');

SET LOCAL ROLE private_definer;
\i supabase/tests/partner-sign-helpers.sql
RESET ROLE;

CREATE TEMP TABLE creds (label text PRIMARY KEY, uid uuid, d numeric, qx numeric, qy numeric, cred_id bytea, cred_row uuid);
CREATE TEMP TABLE asr (label text PRIMARY KEY, token text, cred_id bytea, nonce bytea, exp bigint, mac bytea, ad bytea, cd bytea, sig bytea);
CREATE TEMP TABLE mres (label text, o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz);
CREATE TEMP TABLE rr (label text, o_status text, o_reauth_until timestamptz);
CREATE TEMP TABLE ro (label text PRIMARY KEY, nonce bytea, exp bigint, mac bytea, rp_id text, origin text);
CREATE TEMP TABLE ra (label text PRIMARY KEY, cred_id bytea, nonce bytea, exp bigint, mac bytea, ad bytea, cd bytea, sig bytea);
GRANT ALL ON creds, asr, mres, rr, ro, ra TO PUBLIC;

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex') $f$;

-- a credential for `uid` with a freshly generated key and the given stored counter; returns its row id
CREATE FUNCTION pg_temp.newcred(p_label text, p_uid uuid DEFAULT NULL, p_stored bigint DEFAULT 0) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  d numeric; pub numeric[]; cid bytea; cose bytea; rid uuid;
BEGIN
  IF p_uid IS NULL THEN
    p_uid := gen_random_uuid();
    EXECUTE 'SET LOCAL ROLE service_role';
    INSERT INTO auth.users (id, email) VALUES (p_uid, 'edge27-' || p_label || '@example.test');
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

-- a sign-in assertion bound to a database-issued challenge, presented to the REAL mint as edge_partner_minter; returns the status (the session's token is th(p_label))
CREATE FUNCTION pg_temp.signin(p_label text, p_cred text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; a record; v_th text;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  v_th := pg_temp.th(p_label);
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter, p_opts);
  EXECUTE 'RESET ROLE';
  INSERT INTO asr VALUES (p_label, v_th, c.cred_id, a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  INSERT INTO mres SELECT p_label, m.* FROM private.partner_session_mint(v_th, c.cred_id, a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig) m;
  EXECUTE 'RESET ROLE';
  RETURN (SELECT o_status FROM mres WHERE label = p_label ORDER BY ctid DESC LIMIT 1);
END
$f$;

-- THE reauth round trip, run INSIDE a transaction that already holds a partner binding (the caller binds): the options call (as edge_partner), an assertion over exactly that challenge (the SQL signer), and the
-- reauth call (as edge_partner). p_opts is merged over the challenge the database just issued; `mac_binding` / `mac_purpose` recompute the MAC for another session / purpose instead of presenting the issued one.
CREATE FUNCTION pg_temp.reauth(p_label text, p_cred text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; o record; a record; v_base jsonb;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO o FROM private.partner_session_reauth_options_for_partner();
  EXECUTE 'RESET ROLE';
  INSERT INTO ro VALUES (p_label, o.o_nonce, o.o_exp, o.o_mac, o.o_rp_id, o.o_origin);
  v_base := jsonb_build_object('nonce_hex', encode(o.o_nonce, 'hex'), 'exp_abs', o.o_exp);
  IF NOT (p_opts ? 'mac_binding' OR p_opts ? 'mac_purpose' OR p_opts ? 'mac_tamper') THEN v_base := v_base || jsonb_build_object('mac_hex', encode(o.o_mac, 'hex')); END IF;
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter, v_base || p_opts);
  EXECUTE 'RESET ROLE';
  INSERT INTO ra VALUES (p_label, coalesce(decode(p_opts ->> 'cred_id_hex', 'hex'), c.cred_id), a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  RETURN pg_temp.reauth_again(p_label, p_label);
END
$f$;
-- (re)present the stored assertion `p_src` to the reauth verification as label `p_label` (a replay, or the plain call), inside the caller's binding
CREATE FUNCTION pg_temp.reauth_again(p_label text, p_src text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  a record;
BEGIN
  SELECT * INTO a FROM ra WHERE label = p_src;
  EXECUTE 'SET LOCAL ROLE edge_partner';
  INSERT INTO rr SELECT p_label, r.o_status, r.o_reauth_until FROM private.partner_session_reauth_for_partner(a.cred_id, a.nonce, a.exp, a.mac, a.ad, a.cd, a.sig) r;
  EXECUTE 'RESET ROLE';
  RETURN (SELECT o_status FROM rr WHERE label = p_label ORDER BY ctid DESC LIMIT 1);
END
$f$;

-- principals (helpers.sql): staff_x (a1: staff at fac_x), operator_t (c1), admin (d0); fresh persons for the rest
SELECT pg_temp.newcred('staff', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS ok1 \gset
SELECT pg_temp.newcred('staff2', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS ok1b \gset
SELECT pg_temp.newcred('operator', '00000000-0000-0000-0000-3000000000c1', 0) IS NOT NULL AS ok2 \gset
SELECT pg_temp.newcred('admin', '00000000-0000-0000-0000-4000000000d0', 0) IS NOT NULL AS ok3 \gset
SELECT pg_temp.newcred('other', NULL, 0) IS NOT NULL AS ok4 \gset
SELECT pg_temp.newcred('staff3', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS ok4b \gset
SELECT '\x' || encode(public_key, 'hex') AS pk_staff FROM app.partner_credential WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff') \gset
-- sessions, minted by the REAL mint: two of the same staff member (two credentials), an operator and an admin (aal 1: a TOTP step-up does not exist yet)
SELECT pg_temp.signin('s_sx', 'staff', 1) AS m_sx \gset
SELECT pg_temp.signin('s_sx2', 'staff2', 1) AS m_sx2 \gset
SELECT pg_temp.signin('s_op', 'operator', 1) AS m_op \gset
SELECT pg_temp.signin('s_ad', 'admin', 1) AS m_ad \gset
SELECT pg_temp.signin('s_z', 'staff3', 0) AS m_z \gset
SELECT is(:'m_sx'::text || ',' || :'m_sx2' || ',' || :'m_op' || ',' || :'m_ad' || ',' || :'m_z', 'ok,ok,ok,ok,ok', 'setup: the five sessions are minted by the real mint (the fifth with counter 0 against a stored 0: a synced passkey)');
SELECT pg_temp.th('s_sx') AS th_sx, pg_temp.th('s_sx2') AS th_sx2, pg_temp.th('s_op') AS th_op, pg_temp.th('s_ad') AS th_ad, pg_temp.th('s_z') AS th_z \gset
SELECT (SELECT o_session_id FROM mres WHERE label = 's_sx') AS sid_sx, (SELECT o_session_id FROM mres WHERE label = 's_sx2') AS sid_sx2, (SELECT o_session_id FROM mres WHERE label = 's_op') AS sid_op \gset

-- ----------------------------------------------------------------------------
-- 1. Structure (PA-13b and the registry): who can execute what, and nothing else
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.partner_whoami_for_partner()'::regprocedure, 'private.partner_session_revoke_for_partner()'::regprocedure, 'private.partner_session_lock_for_partner()'::regprocedure,
  'private.partner_session_reauth_options_for_partner()'::regprocedure, 'private.partner_session_reauth_credential_for_partner(bytea)'::regprocedure,
  'private.partner_session_reauth_for_partner(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'private.hit_partner_rate_limit(text, interval, int)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole), 7,
  'PA-13b: the seven edge_partner functions of 0049 are SECURITY DEFINER with search_path = '''', owned by private_definer');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
           CROSS JOIN (VALUES ('private.partner_whoami_for_partner()'), ('private.partner_session_revoke_for_partner()'), ('private.partner_session_lock_for_partner()'),
                              ('private.partner_session_reauth_options_for_partner()'), ('private.partner_session_reauth_credential_for_partner(bytea)'),
                              ('private.partner_session_reauth_for_partner(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'), ('private.hit_partner_rate_limit(text, interval, int)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), ARRAY['edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner'],
  'PA-13b: of every client and edge role, ONLY edge_partner can execute any of the seven (not edge_actor, not the minter, not service_role)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner')) r(n)
           CROSS JOIN (VALUES ('private.partner_rp_config_read()'), ('private.partner_credential_lookup(bytea)'), ('private.partner_sign_in_failure_record(bytea)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[],
  'the three minter-lane definers: no client role and no other edge role (not edge_partner) can execute them');
SELECT is((SELECT array_agg(f.sig ORDER BY f.sig) FROM (VALUES ('private.partner_rp_config_read()'), ('private.partner_credential_lookup(bytea)'), ('private.partner_sign_in_failure_record(bytea)')) f(sig)
           WHERE has_function_privilege('edge_partner_minter', f.sig::regprocedure, 'EXECUTE')), ARRAY['private.partner_credential_lookup(bytea)', 'private.partner_rp_config_read()', 'private.partner_sign_in_failure_record(bytea)'],
  'the minter executes the three minter-lane definers');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.partner_rp_config_read()'::regprocedure, 'private.partner_credential_lookup(bytea)'::regprocedure, 'private.partner_sign_in_failure_record(bytea)'::regprocedure,
  'private.partner_reauth_credential_read(uuid, bytea)'::regprocedure, 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'partner_session_issuer'::regrole), 5,
  'the five issuer-owned functions are owned by partner_session_issuer (the role that already holds every privilege the checks need)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'private.partner_reauth_clear()'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'partner_reauth_verifier'::regrole), 2,
  'R5-L1: the writer of reauth_until and the clearer are owned by partner_reauth_verifier');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_pin_verifier'), ('partner_session_toucher')) r(n)
           CROSS JOIN (VALUES ('private.partner_reauth_credential_read(uuid, bytea)'), ('private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'),
                              ('private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'), ('private.partner_reauth_clear()')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[],
  'the four reauth helpers: no client role, no edge role and no other owner role can execute them');
SELECT is((SELECT array_agg(f.who ORDER BY f.who) FROM (VALUES
    ('private_definer:partner_reauth_credential_read', has_function_privilege('private_definer', 'private.partner_reauth_credential_read(uuid, bytea)'::regprocedure, 'EXECUTE')),
    ('private_definer:partner_reauth_apply', has_function_privilege('private_definer', 'private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE')),
    ('private_definer:partner_reauth_clear', has_function_privilege('private_definer', 'private.partner_reauth_clear()'::regprocedure, 'EXECUTE')),
    ('private_definer:partner_rp_config_read', has_function_privilege('private_definer', 'private.partner_rp_config_read()'::regprocedure, 'EXECUTE')),
    ('partner_reauth_verifier:partner_reauth_check', has_function_privilege('partner_reauth_verifier', 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE'))) f(who, ok) WHERE f.ok),
  ARRAY['partner_reauth_verifier:partner_reauth_check', 'private_definer:partner_reauth_apply', 'private_definer:partner_reauth_clear', 'private_definer:partner_reauth_credential_read', 'private_definer:partner_rp_config_read'],
  'the internal callers hold exactly the EXECUTE they need');
SELECT is(has_function_privilege('private_definer', 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE'), false,
  'R5-L1: private_definer CANNOT execute partner_reauth_check: a definer of its own cannot reach the verification except through the verifier-owned writer');
SELECT is(has_function_privilege('edge_partner', 'private.actor_uid()'::regprocedure, 'EXECUTE') OR has_function_privilege('edge_partner', 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE')
          OR EXISTS (SELECT 1 FROM pg_proc p WHERE p.proname = 'bind_actor' AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')), false,
  'PA-13b: edge_partner cannot execute actor_uid(), bind_actor or the authorization seam itself');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_pin_verifier'), ('partner_reauth_verifier'), ('private_definer')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.partner_sign_in_failure', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.partner_sign_in_failure', 'DELETE,TRUNCATE,TRIGGER')), 0,
  'the failure counter: no client role, no edge role and no other owner role (private_definer included) holds any privilege on it');
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.partner_sign_in_failure'::regclass), true, 'the failure counter has ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT array_agg(pol.polname::text || ':' || pol.polcmd::text ORDER BY pol.polname) FROM pg_policy pol WHERE pol.polrelid = 'app.partner_sign_in_failure'::regclass AND pol.polname NOT LIKE 'zz27%'),
  ARRAY['psi_insert_partner_sign_in_failure:a', 'psi_read_partner_sign_in_failure:r', 'psi_update_partner_sign_in_failure:w'],
  'the failure counter carries exactly the three issuer policies');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polrelid = 'app.partner_sign_in_failure'::regclass AND pol.polname NOT LIKE 'zz27%'
           AND (pol.polroles <> ARRAY['partner_session_issuer'::regrole::oid] OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') ~* 'current_setting|pg_settings' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') ~* 'current_setting|pg_settings')), 0,
  'the OR rule: every policy on the new table is TO partner_session_issuer alone and reads no settable GUC (nothing here can be planted)');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('partner_rp_config_read', 'partner_credential_lookup', 'partner_sign_in_failure_record', 'partner_reauth_credential_read', 'partner_reauth_check',
  'partner_reauth_apply', 'partner_reauth_clear', 'hit_partner_rate_limit', 'partner_whoami_for_partner', 'partner_session_revoke_for_partner', 'partner_session_lock_for_partner',
  'partner_session_reauth_options_for_partner', 'partner_session_reauth_credential_for_partner', 'partner_session_reauth_for_partner')), 14, 'registry: all 14 new functions have a function_inventory row');

-- ----------------------------------------------------------------------------
-- 2. Check 14 (a) behavioural cells: every `_for_partner` definer raises 42501 with no scope. No binding at all, and a USER binding (PA-3 (ii)), for each of the six; and, for the three class-A0 ones, an
-- operator session at aal 1 (the assurance gate: partner_authorize refuses an A0 call below the required level).
-- ----------------------------------------------------------------------------
SELECT throws_ok($$SELECT private.partner_whoami_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_whoami_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT private.partner_session_revoke_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_revoke_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT private.partner_session_lock_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_lock_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_reauth_options_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_credential_for_partner('\x00112233445566778899aabbccddeeff'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_reauth_credential_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_for_partner('\x00112233445566778899aabbccddeeff'::bytea, '\x00'::bytea, 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_reauth_for_partner with NO binding raises 42501');
SAVEPOINT user_bound;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
SELECT throws_ok($$SELECT private.partner_whoami_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_whoami_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT private.partner_session_revoke_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_session_revoke_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT private.partner_session_lock_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_session_lock_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): the reauth issuer refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_credential_for_partner('\x00112233445566778899aabbccddeeff'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): the reauth credential read refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_for_partner('\x00112233445566778899aabbccddeeff'::bytea, '\x00'::bytea, 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): the reauth verification refuses a USER binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT user_bound;
SAVEPOINT op_aal1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', '14 (a) / PA-20: the reauth issuer is class A0: an aal 1 OPERATOR session is refused');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_credential_for_partner('\x00112233445566778899aabbccddeeff'::bytea)$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', '14 (a): the reauth credential read is class A0: an aal 1 OPERATOR session is refused');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_for_partner('\x00112233445566778899aabbccddeeff'::bytea, '\x00'::bytea, 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', '14 (a): the reauth verification is class A0: an aal 1 OPERATOR session is refused');
SELECT is((SELECT private.partner_whoami_for_partner() ->> 'requiredAal'), '2', '4.1: ... while GET session (PEEK) still answers an aal 1 operator, and reports the assurance it needs');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, '4.1: ... and lock (SESSION) still works at aal 1');
SELECT lives_ok($$SELECT private.partner_session_revoke_for_partner()$$, '4.1: ... and sign-out (SESSION) still works at aal 1');
RESET ROLE;
ROLLBACK TO SAVEPOINT op_aal1;

-- ----------------------------------------------------------------------------
-- 3. GET session: class PEEK. It reports everything re-read, and it NEVER moves last_seen_at (4.2)
-- ----------------------------------------------------------------------------
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
UPDATE app.partner_session SET last_seen_at = now() - interval '5 minutes' WHERE id = :'sid_sx'::uuid;
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;
SELECT last_seen_at AS seen0 FROM app.partner_session WHERE id = :'sid_sx'::uuid \gset
SAVEPOINT who1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT private.partner_whoami_for_partner() ->> 'userId'), '00000000-0000-0000-0000-1000000000a1', 'GET session: the user is the session''s own');
SELECT is((SELECT private.partner_whoami_for_partner() ->> 'sessionId'), :'sid_sx', 'GET session: ... and the session id is the bound one');
SELECT is((SELECT (private.partner_whoami_for_partner() ->> 'aal')::int), 1, 'GET session: aal 1');
SELECT is((SELECT (private.partner_whoami_for_partner() ->> 'requiredAal')::int), 1, 'GET session: a staff member needs aal 1');
SELECT is((SELECT private.partner_whoami_for_partner() -> 'memberships' -> 0 ->> 'role'), 'staff', 'GET session: the membership role, re-read');
SELECT is((SELECT private.partner_whoami_for_partner() -> 'memberships' -> 0 -> 'facilityIds'), '["fac_x"]'::jsonb, 'GET session: the facility scope of the member''s org, re-read');
SELECT is((SELECT jsonb_array_length(private.partner_whoami_for_partner() -> 'memberships')), 1, 'GET session: exactly the one active, non-sponsor membership');
SELECT is((SELECT private.partner_whoami_for_partner() -> 'stepUp'), '{"mfaUntil": null, "reauthUntil": null, "otpProofUntil": null, "enrolmentUntil": null, "pinGrantActive": false}'::jsonb, 'GET session: no step-up state exists yet');
SELECT is((SELECT (private.partner_whoami_for_partner() ->> 'isAdmin')::boolean), false, 'GET session: not an admin');
SELECT ok((SELECT (private.partner_whoami_for_partner() ->> 'idleExpiresAt')::timestamptz > now() + interval '24 minutes' AND (private.partner_whoami_for_partner() ->> 'idleExpiresAt')::timestamptz < now() + interval '26 minutes'), 'GET session: the idle deadline is last_seen_at + 30 minutes (5 minutes ago + 30)');
RESET ROLE;
SELECT is((SELECT last_seen_at FROM app.partner_session WHERE id = :'sid_sx'::uuid), :'seen0'::timestamptz, 'PEEK: GET session did NOT move last_seen_at (six reads, the session is 5 minutes idle)');
ROLLBACK TO SAVEPOINT who1;
SAVEPOINT who2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'control: a SESSION-class call (lock) on the same 5 minute idle session');
RESET ROLE;
SELECT ok((SELECT last_seen_at > :'seen0'::timestamptz FROM app.partner_session WHERE id = :'sid_sx'::uuid), 'PEEK control: a SESSION-class call DOES advance last_seen_at (so the PEEK cell above is not vacuous)');
ROLLBACK TO SAVEPOINT who2;
SAVEPOINT who3;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is((SELECT (private.partner_whoami_for_partner() ->> 'isAdmin')::boolean), true, 'GET session: an admin session reports isAdmin');
SELECT is((SELECT private.partner_whoami_for_partner() -> 'memberships'), '[]'::jsonb, 'GET session: an admin who holds no membership reports none');
SELECT is((SELECT (private.partner_whoami_for_partner() ->> 'requiredAal')::int), 2, 'GET session: an admin needs aal 2');
RESET ROLE;
ROLLBACK TO SAVEPOINT who3;
UPDATE app.partner_session SET last_seen_at = now() WHERE id = :'sid_sx'::uuid;

-- ----------------------------------------------------------------------------
-- 4. Sign-out revokes the BOUND session only; lock clears every step-up grant and keeps the session live
-- ----------------------------------------------------------------------------
SAVEPOINT out1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT lives_ok($$SELECT private.partner_session_revoke_for_partner()$$, 'sign-out: runs');
RESET ROLE;
SELECT is((SELECT revoke_reason FROM app.partner_session WHERE id = :'sid_sx'::uuid), 'sign_out', 'sign-out: the bound session is revoked, with reason sign_out');
SELECT ok((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), 'sign-out: revoked_at is set');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'sid_sx2'::uuid), true, 'sign-out: ANOTHER session of the same member (another credential) is untouched');
ROLLBACK TO SAVEPOINT out1;
SAVEPOINT out2;
SET LOCAL ROLE private_definer;
SELECT private.partner_sessions_revoke('user', '00000000-0000-0000-0000-1000000000a1'::uuid, 'test') IS NOT NULL AS x \gset
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '28000', 'partner_session_refused', 'sign-out: a revoked session cannot bind again (one uniform 28000)');
RESET ROLE;
ROLLBACK TO SAVEPOINT out2;

-- lock: seed every step-up state a session can hold (the guard is switched off for the seeding: the verifiers' own definers do not exist yet), then lock
SAVEPOINT lock1;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
UPDATE app.partner_session SET pin_grant_until = now() + interval '30 seconds', reauth_until = now() + interval '4 minutes', otp_proof_until = now() + interval '9 minutes', mfa_until = now() + interval '3 minutes' WHERE id = :'sid_sx'::uuid;
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT private.partner_whoami_for_partner() -> 'stepUp' ->> 'pinGrantActive'), 'true', 'lock: before it, the PIN grant is active');
SELECT is((SELECT (private.partner_whoami_for_partner() -> 'stepUp' ->> 'reauthUntil') IS NOT NULL), true, 'lock: before it, the reauth window is open');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'lock: runs');
RESET ROLE;
SELECT is((SELECT (pin_grant_until IS NULL AND reauth_until IS NULL AND otp_proof_until IS NULL) FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'lock: the PIN grant, the reauth window and the OTP proof are cleared');
SELECT ok((SELECT mfa_until IS NOT NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), 'lock: mfa_until is NOT cleared here (S1.4 owns that column and adds its clearer: nothing sets it before S1.4); the seam is stated in 0049');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'lock: the session stays LIVE');
ROLLBACK TO SAVEPOINT lock1;
SAVEPOINT lock2;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), 'lock: after a lock the same session still binds (a locked till still reads)');
RESET ROLE;
ROLLBACK TO SAVEPOINT lock2;

-- the planted-GUC rerun of PA-4c (ii) for the two new session writers: with every GUC planted for ANOTHER member, sign-out and lock change only the bound session
SAVEPOINT guc1;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
UPDATE app.partner_session SET pin_grant_until = now() + interval '30 seconds', reauth_until = now() + interval '4 minutes' WHERE id = :'sid_op'::uuid;
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT bool_and(set_config(g, CASE WHEN g IN ('app.edge.purge_fix_coords', 'app.signin.proof_purge') THEN 'on' WHEN g LIKE '%email' THEN 'op@example.test' WHEN g IN ('app.delete_my_data.target_handle', 'app.delete_my_data.target_pseudonym', 'app.edge.link_attest_key', 'app.edge.link_hash') THEN 'x'
                                ELSE '00000000-0000-0000-0000-3000000000c1' END, true) IS NOT NULL) AS planted
FROM unnest(ARRAY['app.delete_my_data.target_user_id', 'app.delete_my_data.target_email', 'app.delete_my_data.target_handle', 'app.delete_my_data.target_pseudonym', 'app.edge.link_attest_key', 'app.edge.link_device_id', 'app.edge.link_hash',
                  'app.edge.purge_fix_coords', 'app.guard.entitlement_id', 'app.guard.offer_code_id', 'app.guard.play_id', 'app.offline_code.target_device_id', 'app.signin.proof_id', 'app.signin.proof_purge', 'app.signin.target_user_id']) g \gset
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'PA-4c (ii): lock under every planted GUC runs');
SELECT lives_ok($$SELECT private.partner_session_revoke_for_partner()$$, 'PA-4c (ii): sign-out under every planted GUC runs');
RESET ROLE;
SELECT is((SELECT (revoked_at IS NULL AND pin_grant_until IS NOT NULL AND reauth_until IS NOT NULL) FROM app.partner_session WHERE id = :'sid_op'::uuid), true,
  'PA-4c (ii): ANOTHER member''s session (the one the GUCs name) kept its grants and stayed live: 0 rows changed');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'PA-4c (ii): the bound session itself was signed out');
ROLLBACK TO SAVEPOINT guc1;

-- ----------------------------------------------------------------------------
-- 5. Reauth. The issuer, the credential read (PA-27), the verification and the verifier-owned writer of reauth_until
-- ----------------------------------------------------------------------------
SAVEPOINT re1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.reauth('re_ok', 'staff', 2) AS st_ok \gset
SELECT is(:'st_ok'::text, 'ok', 'reauth: a valid assertion by the session''s own credential over the issued challenge is `ok`');
SELECT ok((SELECT o_reauth_until > now() + interval '4 minutes 50 seconds' AND o_reauth_until <= now() + interval '5 minutes 1 second' FROM rr WHERE label = 're_ok'), 'reauth: reauth_until is now + 5 minutes');
SELECT is((SELECT (reauth_until = (SELECT o_reauth_until FROM rr WHERE label = 're_ok')) FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'reauth: the session row carries exactly the returned reauth_until');
SELECT is((SELECT sign_count::int FROM app.partner_credential WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff')), 2, 'reauth: the assertion advanced the credential''s counter (a later sign-in would otherwise see a counter already passed)');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge WHERE purpose = 'reauth' AND session_id = :'sid_sx'::uuid AND user_id = '00000000-0000-0000-0000-1000000000a1'), 1, 'reauth: the used nonce is recorded once, as purpose reauth, for this session');
SELECT is((SELECT length(nonce) FROM ro WHERE label = 're_ok'), 32, 'reauth: the issued challenge is 32 random bytes');
SELECT ok((SELECT exp BETWEEN extract(epoch FROM now())::bigint + 118 AND extract(epoch FROM now())::bigint + 122 FROM ro WHERE label = 're_ok'), 'reauth: the challenge expires 120 s ahead');
SELECT is((SELECT rp_id || '|' || origin FROM ro WHERE label = 're_ok'), 'partners.example.test|https://partners.example.test', 'reauth: the options call returns the relying party');
SELECT is((SELECT private.partner_challenge_verify(3::smallint, exp, nonce, :'sid_sx'::uuid, mac) FROM ro WHERE label = 're_ok'), true, 'reauth: the issued MAC is purpose 3 bound to the SESSION');
SELECT is((SELECT private.partner_challenge_verify(3::smallint, exp, nonce, :'sid_sx2'::uuid, mac) FROM ro WHERE label = 're_ok'), false, 'reauth: ... and does NOT verify for another session (the binding is in the HMAC)');
SELECT is((SELECT private.partner_challenge_verify(1::smallint, exp, nonce, '00000000-0000-0000-0000-000000000000'::uuid, mac) FROM ro WHERE label = 're_ok'), false, 'reauth: ... nor as a sign-in challenge');
-- a replay of the same assertion inside the same binding: refused, and the window is untouched
SELECT is(pg_temp.reauth_again('re_replay', 're_ok'), 'replayed', 'reauth: the SAME assertion presented again is `replayed` (the nonce is the single use)');
SELECT is((SELECT (reauth_until = (SELECT o_reauth_until FROM rr WHERE label = 're_ok')) FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'reauth: ... and the window is exactly the first call''s');
SELECT is((SELECT o_reauth_until IS NULL FROM rr WHERE label = 're_replay'), true, 'reauth: a refusal returns no window');
ROLLBACK TO SAVEPOINT re1;

-- PA-27: someone else's credential (a person with a valid passkey of their own) cannot satisfy it
SAVEPOINT re2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT count(*)::int FROM private.partner_session_reauth_credential_for_partner((SELECT cred_id FROM creds WHERE label = 'other'))), 0, 'PA-27: the Edge-side credential read returns NOTHING for a credential of another person');
SELECT is((SELECT count(*)::int FROM private.partner_session_reauth_credential_for_partner(public.gen_random_bytes(32))), 0, 'PA-27: ... nor for an unknown credential id (the same answer)');
SELECT is((SELECT count(*)::int FROM private.partner_session_reauth_credential_for_partner((SELECT cred_id FROM creds WHERE label = 'staff'))), 1, 'PA-27: control: the session''s own credential is returned');
SELECT is((SELECT count(*)::int FROM private.partner_session_reauth_credential_for_partner((SELECT cred_id FROM creds WHERE label = 'staff2'))), 1, 'PA-27: control: ... and so is ANOTHER credential of the same person (reauth is by the person, not by the session''s credential)');
SELECT is((SELECT o_alg || '|' || o_sign_count || '|' || o_rp_id || '|' || (o_user_id = '00000000-0000-0000-0000-1000000000a1') FROM private.partner_session_reauth_credential_for_partner((SELECT cred_id FROM creds WHERE label = 'staff'))), '-7|1|partners.example.test|true', 'PA-27: the read carries the algorithm, the stored counter, the relying party and the person');
SELECT is((SELECT o_public_key FROM private.partner_session_reauth_credential_for_partner((SELECT cred_id FROM creds WHERE label = 'staff'))), :'pk_staff'::bytea, 'PA-27: ... and the stored COSE key');
RESET ROLE;
SELECT pg_temp.reauth('re_other', 'other', 2) AS st_other \gset
SELECT is(:'st_other'::text, 'unknown_credential', 'PA-27: the DATABASE refuses someone else''s credential too (the definer, called directly): `unknown_credential`');
SELECT is((SELECT reauth_until IS NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'PA-27: ... and reauth_until is NOT set');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge WHERE purpose = 'reauth'), 0, 'PA-27: ... and no nonce is burned (the credential check comes before the nonce)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.reauth.%'), 0, 'PA-27: ... and a wrong-person refusal writes no audit row (it is not an alarm)');
ROLLBACK TO SAVEPOINT re2;

SAVEPOINT re3;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.reauth('re_second', 'staff2', 2), 'ok', 'reauth: ANOTHER credential of the same person is accepted');
ROLLBACK TO SAVEPOINT re3;
SAVEPOINT re4;
UPDATE app.partner_credential SET revoked_at = now() WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff2');
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.reauth('re_revoked', 'staff2', 2), 'unknown_credential', 'reauth: a REVOKED credential of the same person is `unknown_credential`');
ROLLBACK TO SAVEPOINT re4;

-- every structural refusal is a STATUS, from an assertion that is otherwise valid and signed over its own bytes (so a mutant that drops the check is not rescued by the signature check after it)
CREATE TEMP TABLE re_cases (label text, opts jsonb, want text);
INSERT INTO re_cases VALUES
  ('c_origin',  '{"client": {"origin": "https://evil.example.test"}}', 'bad_origin'),
  ('c_subdomain', '{"client": {"origin": "https://sub.partners.example.test"}}', 'bad_origin'),
  ('c_rp',      '{"rp": "other.example.test"}', 'bad_rp_id_hash'),
  ('c_nouv',    '{"flags": 1}', 'user_not_verified'),
  ('c_noup',    '{"flags": 4}', 'user_not_present'),
  ('c_type',    '{"client": {"type": "webauthn.create"}}', 'bad_client_type'),
  ('c_cross',   '{"client": {"crossOrigin": true}}', 'cross_origin'),
  ('c_top',     '{"client": {"topOrigin": "https://partners.example.test"}}', 'cross_origin'),
  ('c_chal',    '{"client": {"challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}', 'challenge_mismatch'),
  ('c_cdjson',  '{"client_raw": "not json"}', 'bad_client_data'),
  ('c_cdobj',   '{"client_raw": "[1]"}', 'bad_client_data'),
  ('c_ad',      '{"ad_hex": "00ff"}', 'bad_authenticator_data'),
  ('c_sig',     '{"sig_tamper": true}', 'signature_invalid'),
  ('c_sigkey',  '{"sign_d": "12345678901234567890"}', 'signature_invalid');
DO $$
DECLARE
  c record; v_th text := pg_temp.th('s_sx'); st text;
BEGIN
  FOR c IN SELECT * FROM re_cases ORDER BY label LOOP
    st := NULL;
    BEGIN
      EXECUTE 'SET LOCAL ROLE edge_partner';
      PERFORM private.bind_partner_session(v_th);
      EXECUTE 'RESET ROLE';
      st := pg_temp.reauth(c.label, 'staff', 2, c.opts);
      RAISE EXCEPTION 'rollback this case' USING ERRCODE = 'P0001';
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
      NULL;
    END;
    INSERT INTO rr VALUES ('case:' || c.label, st || '|' || c.want, NULL);
  END LOOP;
END
$$;
SELECT is((SELECT count(*)::int FROM rr WHERE label LIKE 'case:%' AND split_part(o_status, '|', 1) = split_part(o_status, '|', 2)), (SELECT count(*)::int FROM re_cases), 'reauth: every structural refusal is the status it names (all 14 cases)');
SELECT is((SELECT string_agg(label || '=' || o_status, ', ' ORDER BY label) FROM rr WHERE label LIKE 'case:%' AND split_part(o_status, '|', 1) <> split_part(o_status, '|', 2)), NULL, 'reauth: ... and none differs (the list of mismatches is empty)');
SELECT is((SELECT count(*)::int FROM re_cases), 14, 'reauth: the table of cases really holds 14');

-- the challenge itself: another session's, another purpose's, a tampered MAC, and an expired one are `bad_challenge` / `expired`, each from an otherwise valid assertion
SELECT (extract(epoch FROM now())::bigint - 5) AS exp_past \gset
CREATE TEMP TABLE re_cases2 (label text, opts jsonb, want text);
INSERT INTO re_cases2 VALUES
  ('d_other_session', jsonb_build_object('mac_purpose', 3, 'mac_binding', :'sid_sx2'), 'bad_challenge'),
  ('d_signin_purpose', '{"mac_purpose": 1}', 'bad_challenge'),
  ('d_tampered', '{"mac_tamper": true}', 'bad_challenge'),
  ('d_expired', jsonb_build_object('exp_abs', :exp_past, 'mac_purpose', 3, 'mac_binding', :'sid_sx'), 'expired');
DO $$
DECLARE
  c record; v_th text := pg_temp.th('s_sx'); st text;
BEGIN
  FOR c IN SELECT * FROM re_cases2 ORDER BY label LOOP
    st := NULL;
    BEGIN
      EXECUTE 'SET LOCAL ROLE edge_partner';
      PERFORM private.bind_partner_session(v_th);
      EXECUTE 'RESET ROLE';
      st := pg_temp.reauth(c.label, 'staff', 2, c.opts);
      RAISE EXCEPTION 'rollback this case' USING ERRCODE = 'P0001';
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
      NULL;
    END;
    INSERT INTO rr VALUES ('case2:' || c.label, st || '|' || c.want, NULL);
  END LOOP;
END
$$;
SELECT is((SELECT string_agg(label || '=' || o_status, ', ' ORDER BY label) FROM rr WHERE label LIKE 'case2:%'), 'case2:d_expired=expired|expired, case2:d_other_session=bad_challenge|bad_challenge, case2:d_signin_purpose=bad_challenge|bad_challenge, case2:d_tampered=bad_challenge|bad_challenge',
  'reauth: a challenge for ANOTHER SESSION, one of ANOTHER PURPOSE, a TAMPERED MAC and an EXPIRED one each give their own status (the MAC is checked before the expiry, before the session, before the credential)');

-- alarms: a counter that did not advance, and a signature the Edge would have passed, write an audit row (actor = the bound member) and RETURN a status
SAVEPOINT re5;
UPDATE app.partner_credential SET sign_count = 5 WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff');
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.reauth('re_reg', 'staff', 3) AS st_reg \gset
SELECT is(:'st_reg'::text, 'counter_regression', 'reauth: a counter BELOW the stored one is `counter_regression` (a status: the transaction commits)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.reauth.counter_regression' AND subject_id = :'sid_sx' AND subject_table = 'app.partner_session' AND actor_user_id = '00000000-0000-0000-0000-1000000000a1'), 1,
  'reauth: ... it writes ONE audit_log row, naming the member and the session');
SELECT is((SELECT sign_count::int FROM app.partner_credential WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff')), 5, 'reauth: ... the counter did not move');
SELECT is((SELECT reauth_until IS NULL FROM app.partner_session WHERE id = :'sid_sx'::uuid), true, 'reauth: ... and reauth_until is not set');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge WHERE purpose = 'reauth'), 1, 'reauth: ... the nonce is spent, as the mint does for a regression (the signature was valid)');
ROLLBACK TO SAVEPOINT re5;
SAVEPOINT re5b;
UPDATE app.partner_credential SET sign_count = 5 WHERE id = (SELECT cred_row FROM creds WHERE label = 'staff');
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.reauth('re_eq', 'staff', 5), 'counter_regression', 'reauth: an EQUAL non-zero counter is a regression too');
ROLLBACK TO SAVEPOINT re5b;
SAVEPOINT re6;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.reauth('re_badsig', 'staff', 2, '{"sig_tamper": true}'), 'signature_invalid', 'reauth: a bad signature is `signature_invalid`');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.reauth.signature_invalid' AND subject_id = :'sid_sx' AND actor_user_id = '00000000-0000-0000-0000-1000000000a1'), 1, 'reauth: ... it writes ONE audit_log row');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge WHERE purpose = 'reauth'), 0, 'reauth: ... and burns NO nonce (a forged signature must not spend the real challenge)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.reauth.%'), 1, 'reauth: ... and nothing else is audited');
ROLLBACK TO SAVEPOINT re6;
SAVEPOINT re7;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_z');
RESET ROLE;
SELECT is(pg_temp.reauth('re_zero', 'staff3', 0), 'ok', 'reauth: counter 0 against a stored 0 (a synced passkey) is `ok`');
ROLLBACK TO SAVEPOINT re7;

-- R5-L1: reauth_until can be written ONLY through the verifier-owned definer. private_definer (every other `_for_partner` definer's owner) holds no UPDATE on the column
SAVEPOINT col1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$UPDATE app.partner_session SET reauth_until = now() + interval '1 minute' WHERE id = private.partner_binding_session()$$, '42501', NULL, 'R5-L1: private_definer, bound to the session, CANNOT write reauth_until (a definer that skips the verification cannot set it)');
SELECT throws_ok($$SELECT * FROM private.partner_reauth_check(private.partner_binding_session(), '\x00112233445566778899aabbccddeeff'::bytea, public.gen_random_bytes(32), 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '42501', NULL, 'R5-L1: ... and it cannot call the check directly either');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT * FROM private.partner_reauth_apply('\x00112233445566778899aabbccddeeff'::bytea, public.gen_random_bytes(32), 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '42501', NULL, 'R5-L1: edge_partner cannot call the verifier-owned writer directly (only the _for_partner wrapper can, after partner_authorize)');
RESET ROLE;
ROLLBACK TO SAVEPOINT col1;
SAVEPOINT args1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_for_partner('\x00112233445566778899aabbccddeeff'::bytea, NULL, 1, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)$$, '22023', NULL, 'reauth: a NULL nonce is malformed (22023): nothing was written');
RESET ROLE;
ROLLBACK TO SAVEPOINT args1;
SAVEPOINT args2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_credential_for_partner('\x0011'::bytea)$$, '22023', NULL, 'reauth: a credential id of 2 bytes is malformed (22023)');
RESET ROLE;
ROLLBACK TO SAVEPOINT args2;
SAVEPOINT norp;
DELETE FROM app.partner_rp_config;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, '55000', NULL, 'a missing relying-party row is a deploy fault (55000), not a client refusal: the reauth issuer raises');
RESET ROLE;
SET LOCAL ROLE edge_partner_minter;
SELECT throws_ok($$SELECT * FROM private.partner_rp_config_read()$$, '55000', NULL, '... and so does the minter-lane read');
RESET ROLE;
ROLLBACK TO SAVEPOINT norp;

-- ----------------------------------------------------------------------------
-- 6. The minter lane: the credential lookup and the failure counter of design 8 (5 failed verifications per credential per hour, then a 15 minute cooldown)
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.rpc() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE s text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT o_rp_id || '|' || o_origin INTO s FROM private.partner_rp_config_read();
  EXECUTE 'RESET ROLE';
  RETURN s;
END
$f$;
SELECT is(pg_temp.rpc(), 'partners.example.test|https://partners.example.test', 'the relying-party read returns the configured row to the minter');
CREATE FUNCTION pg_temp.fr_id(p_id bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE s text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT o_status INTO s FROM private.partner_sign_in_failure_record(p_id);
  EXECUTE 'RESET ROLE';
  RETURN s;
END
$f$;
CREATE FUNCTION pg_temp.fr(p_cred text) RETURNS text LANGUAGE sql AS $f$ SELECT pg_temp.fr_id((SELECT cred_id FROM creds WHERE label = p_cred)) $f$;
CREATE FUNCTION pg_temp.lk_id(p_id bytea) RETURNS jsonb LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT * INTO r FROM private.partner_credential_lookup(p_id);
  EXECUTE 'RESET ROLE';
  RETURN to_jsonb(r);
END
$f$;
CREATE FUNCTION pg_temp.lk(p_cred text) RETURNS jsonb LANGUAGE sql AS $f$ SELECT pg_temp.lk_id((SELECT cred_id FROM creds WHERE label = p_cred)) $f$;

SELECT pg_temp.newcred('fc', NULL, 7) IS NOT NULL AS ok5 \gset
SELECT pg_temp.newcred('fc_other', NULL, 0) IS NOT NULL AS ok6 \gset
SELECT is(pg_temp.lk('fc') ->> 'o_status', 'ok', 'lookup: a live credential is `ok`');
SELECT is((SELECT (pg_temp.lk('fc') ->> 'o_sign_count') || '|' || (pg_temp.lk('fc') ->> 'o_alg') || '|' || ((pg_temp.lk('fc') ->> 'o_user_id')::uuid = (SELECT uid FROM creds WHERE label = 'fc'))), '7|-7|true', 'lookup: ... with the stored counter, the algorithm and the person');
SELECT is((pg_temp.lk('fc') ->> 'o_public_key')::text, '\x' || encode((SELECT public_key FROM app.partner_credential WHERE id = (SELECT cred_row FROM creds WHERE label = 'fc')), 'hex'), 'lookup: ... and the stored COSE key');
SELECT is(pg_temp.lk_id(public.gen_random_bytes(32)), '{"o_alg": null, "o_status": "unknown", "o_user_id": null, "o_public_key": null, "o_sign_count": null, "o_credential_id": null}'::jsonb, 'lookup: an UNKNOWN credential is `unknown` with nothing else');
SAVEPOINT lkrev;
UPDATE app.partner_credential SET revoked_at = now() WHERE id = (SELECT cred_row FROM creds WHERE label = 'fc_other');
SELECT is(pg_temp.lk('fc_other'), '{"o_alg": null, "o_status": "unknown", "o_user_id": null, "o_public_key": null, "o_sign_count": null, "o_credential_id": null}'::jsonb, 'lookup: a REVOKED credential is the SAME answer as an unknown one (no oracle)');
SELECT is(pg_temp.fr('fc_other'), 'unknown', 'failure record: a revoked credential is `unknown` too');
ROLLBACK TO SAVEPOINT lkrev;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_credential_lookup('\x00112233'::bytea)$$, '22023', NULL, 'lookup: a 4-byte credential id is malformed (22023)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_credential_lookup(NULL)$$, '22023', NULL, 'lookup: NULL is malformed (22023)');
RESET ROLE;
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_sign_in_failure_record('\x00112233'::bytea)$$, '22023', NULL, 'failure record: a 4-byte credential id is malformed (22023)');
RESET ROLE;

-- unknown ids create nothing
SELECT is(pg_temp.fr_id(public.gen_random_bytes(32)), 'unknown', 'failure record: an id nobody holds is `unknown`');
SELECT is((SELECT count(*)::int FROM app.partner_sign_in_failure), 0, 'failure record: ... and writes NOTHING (a caller that presents made-up ids grows no table)');

-- the count: four failures are counted, the fifth starts the cooldown
SELECT is(pg_temp.fr('fc'), 'counted', 'failure 1: counted');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure 2: counted');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure 3: counted');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure 4: counted');
SELECT is((SELECT failed_count::int FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), 4, 'the row says 4');
SELECT is(pg_temp.lk('fc') ->> 'o_status', 'ok', 'lookup: at 4 failures the credential is still `ok`');
SELECT is(pg_temp.fr('fc'), 'cooldown', 'failure 5: starts the COOLDOWN (a status: the refusal''s transaction commits and the counter with it)');
SELECT is((SELECT failed_count::int FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), 0, 'the counter restarts at 0 when the cooldown starts');
SELECT ok((SELECT cooldown_until BETWEEN clock_timestamp() + interval '14 minutes 55 seconds' AND clock_timestamp() + interval '15 minutes 1 second' FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), 'the cooldown is 15 minutes');
SELECT is(pg_temp.lk('fc'), '{"o_alg": null, "o_status": "cooldown", "o_user_id": null, "o_public_key": null, "o_sign_count": null, "o_credential_id": null}'::jsonb, 'lookup: during the cooldown the answer is `cooldown` and NO key material is returned (nothing is verified)');
SELECT is(pg_temp.lk('fc_other') ->> 'o_status', 'ok', 'lookup: ANOTHER credential is unaffected (the cooldown is per credential)');
SELECT cooldown_until AS cd0 FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc') \gset
SELECT is(pg_temp.fr('fc'), 'cooldown', 'failure during the cooldown: answers `cooldown`');
SELECT is((SELECT (cooldown_until = :'cd0'::timestamptz AND failed_count = 0) FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), true, '... and is NOT counted (the cooldown is a fixed 15 minutes: it cannot be stretched)');
-- the cooldown ends
UPDATE app.partner_sign_in_failure SET cooldown_until = now() - interval '1 second' WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc');
SELECT is(pg_temp.lk('fc') ->> 'o_status', 'ok', 'lookup: once the cooldown has passed the credential is `ok` again');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure after the cooldown: counted from 1');
SELECT is((SELECT failed_count::int FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), 1, '... the row says 1');
-- the window: failures older than an hour are forgotten
UPDATE app.partner_sign_in_failure SET failed_count = 3, window_start = now() - interval '2 hours', cooldown_until = NULL WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure with a 2 hour old window: counted');
SELECT is((SELECT failed_count::int FROM app.partner_sign_in_failure WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc')), 1, '... as the FIRST of a new window (the 3 old failures are forgotten)');
UPDATE app.partner_sign_in_failure SET failed_count = 4, window_start = now() - interval '59 minutes', cooldown_until = NULL WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc');
SELECT is(pg_temp.fr('fc'), 'cooldown', 'failure with a 59 minute old window and 4 counted: the fifth starts the cooldown (the window is an hour)');
UPDATE app.partner_sign_in_failure SET failed_count = 4, window_start = now() - interval '61 minutes', cooldown_until = NULL WHERE credential_id = (SELECT cred_row FROM creds WHERE label = 'fc');
SELECT is(pg_temp.fr('fc'), 'counted', 'failure with a 61 minute old window and 4 counted: a new window, counted from 1');
-- a bound transaction cannot use the minter lane (the 0041 rule)
SAVEPOINT fb;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE edge_partner_minter;
SELECT throws_ok($$SELECT * FROM private.partner_credential_lookup(public.gen_random_bytes(32))$$, '42501', NULL, 'lookup: refused inside a bound transaction');
SELECT throws_ok($$SELECT * FROM private.partner_sign_in_failure_record(public.gen_random_bytes(32))$$, '42501', NULL, 'failure record: refused inside a bound transaction');
RESET ROLE;
ROLLBACK TO SAVEPOINT fb;
-- the lookup works with the credential the mint then accepts: lookup -> (Edge verifies) -> mint is one path
SELECT is(pg_temp.signin('s_fc', 'fc', 8), 'ok', 'path: a credential that has just left its cooldown mints a session (the cooldown is the Edge''s gate; the mint does not consult it)');

-- ----------------------------------------------------------------------------
-- 7. hit_partner_rate_limit: keyed on the partner binding's user, never over-cap raising
-- ----------------------------------------------------------------------------
SAVEPOINT rl1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is(private.hit_partner_rate_limit('partner-reauth:member', interval '1 hour', 2), 1, 'rate limit: the first hit counts 1');
SELECT is(private.hit_partner_rate_limit('partner-reauth:member', interval '1 hour', 2), 2, 'rate limit: the second counts 2');
SELECT is(private.hit_partner_rate_limit('partner-reauth:member', interval '1 hour', 2), 3, 'rate limit: the third counts 3 and does NOT raise over the cap (0020: the decision is the caller''s, from the count)');
SELECT throws_ok($$SELECT private.hit_partner_rate_limit('', interval '1 hour', 2)$$, '22023', NULL, 'rate limit: an empty key is refused (22023)');
SELECT throws_ok($$SELECT private.hit_partner_rate_limit(repeat('k', 129), interval '1 hour', 2)$$, '22023', NULL, 'rate limit: a 129 character key is refused');
SELECT throws_ok($$SELECT private.hit_partner_rate_limit('k', interval '0 seconds', 2)$$, '22023', NULL, 'rate limit: a zero window is refused');
SELECT throws_ok($$SELECT private.hit_partner_rate_limit('k', interval '2 days', 2)$$, '22023', NULL, 'rate limit: a window over a day is refused');
SELECT throws_ok($$SELECT private.hit_partner_rate_limit('k', interval '1 hour', 0)$$, '22023', NULL, 'rate limit: a max of 0 is refused');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count FROM private.rate_limit_bucket WHERE bucket_key = '00000000-0000-0000-0000-1000000000a1:partner-reauth:member' ORDER BY window_start DESC LIMIT 1), 3, 'rate limit: the bucket is `<uid>:<key>`, the format delete_my_data''s purge matches, built in the database from the binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT rl1;
SAVEPOINT rl2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT is(private.hit_partner_rate_limit('partner-reauth:member', interval '1 hour', 2), 1, 'rate limit: ANOTHER member has their own bucket (the operator starts at 1)');
RESET ROLE;
ROLLBACK TO SAVEPOINT rl2;
SELECT throws_ok($$SET LOCAL ROLE edge_partner; SELECT private.hit_partner_rate_limit('k', interval '1 hour', 2)$$, '42501', 'hit_partner_rate_limit: no partner session is bound in this transaction', 'rate limit: with NO binding it raises 42501');
RESET ROLE;
SAVEPOINT rl3;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.hit_partner_rate_limit('k', interval '1 hour', 2)$$, '42501', 'hit_partner_rate_limit: no partner session is bound in this transaction', 'rate limit: a USER binding is refused (it takes the bound PARTNER user only)');
RESET ROLE;
ROLLBACK TO SAVEPOINT rl3;

-- every scenario above ran inside a savepoint that was rolled back: nothing leaked into the five sessions or the counters
SELECT is((SELECT count(*)::int FROM app.partner_session s WHERE s.id IN (:'sid_sx'::uuid, :'sid_sx2'::uuid, :'sid_op'::uuid) AND (s.revoked_at IS NOT NULL OR s.reauth_until IS NOT NULL OR s.pin_grant_until IS NOT NULL OR s.otp_proof_until IS NOT NULL)), 0,
  'the scenarios left no trace: no revoked session, no reauth window, no grant (a rolled-back savepoint per scenario)');
SELECT * FROM finish();
ROLLBACK;
