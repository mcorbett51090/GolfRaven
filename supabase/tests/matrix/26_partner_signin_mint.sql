-- 26_partner_signin_mint.sql
-- P5.1a S1.1b (0048): the SIGN-IN MINT, from docs/security/partner-auth-design.md section 12.1 "S1.1": PA-7 (the stateless challenge), PA-8 (only the minter can mint), PA-9 (the counter), PA-9b (every
-- structural refusal), S0-L5 (60 sign-ins per credential per hour, before verification), and the alarm that survives a refusal.
--
-- HOW IT RUNS. One transaction, rolled back at the end. REAL ES256 signatures are generated at RUN TIME by supabase/tests/partner-sign-helpers.sql (a signer in SQL on top of the verifier's own arithmetic: no
-- key is stored anywhere), bound to challenges the database itself issued, and every mint is made AS edge_partner_minter (a real SET ROLE). Each structural refusal is made on an assertion that is RE-SIGNED over
-- the defective data, so the only thing wrong with it is the one field under test: a mutant that drops that check is not rescued by the signature check that comes after it. The two-connection half (12 concurrent mints
-- of one challenge; the counter race; the alarm committing with the refusal) is tools/db/test-partner-serialisation.sh. The HMAC encoding is pinned by vectors computed OUTSIDE the database (Python hmac) from the
-- shim's key (supabase/tests/shim.sql): no secret lives in this file.

\set QUIET 1
BEGIN;
SELECT plan(235);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_partner_minter, edge_actor, partner_session_issuer, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config, app.partner_auth_alarm TO CURRENT_USER;
CREATE POLICY zz26_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz26_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz26_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz26_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz26_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz26_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
-- the relying party, as ops writes it at deploy
INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');

SET LOCAL ROLE private_definer;
\i supabase/tests/partner-sign-helpers.sql
RESET ROLE;

CREATE TEMP TABLE creds (label text PRIMARY KEY, uid uuid, d numeric, qx numeric, qy numeric, cred_id bytea, cred_row uuid);
CREATE TEMP TABLE asr (label text PRIMARY KEY, token text, cred_id bytea, nonce bytea, exp bigint, mac bytea, ad bytea, cd bytea, sig bytea);
CREATE TEMP TABLE mres (label text, o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz);
GRANT ALL ON creds, asr, mres TO PUBLIC;

-- a credential for `uid` with a freshly generated key and the given stored counter; returns its row id
CREATE FUNCTION pg_temp.newcred(p_label text, p_uid uuid DEFAULT NULL, p_stored bigint DEFAULT 0) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  d numeric; pub numeric[]; cid bytea; cose bytea; rid uuid;
BEGIN
  IF p_uid IS NULL THEN
    -- a fresh person per scenario, so the per-person used-nonce count is per scenario too
    p_uid := gen_random_uuid();
    EXECUTE 'SET LOCAL ROLE service_role';
    INSERT INTO auth.users (id, email) VALUES (p_uid, 'mint26-' || p_label || '@example.test');
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

-- build an assertion for credential p_cred (with p_opts, see partner-sign-helpers.sql), store it as p_label, and mint it AS edge_partner_minter; returns the status
CREATE FUNCTION pg_temp.go(p_label text, p_cred text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; a record;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter, p_opts);
  EXECUTE 'RESET ROLE';
  INSERT INTO asr VALUES (p_label, encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex'), coalesce(decode(p_opts ->> 'cred_id_hex', 'hex'), c.cred_id), a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  RETURN pg_temp.present(p_label, p_label);
END
$f$;

-- present the stored assertion `p_src` to the mint as label `p_label` (a replay, or a plain mint), with its own token hash unless one is given
CREATE FUNCTION pg_temp.present(p_label text, p_src text, p_token text DEFAULT NULL) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  a record;
BEGIN
  SELECT * INTO a FROM asr WHERE label = p_src;
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  INSERT INTO mres SELECT p_label, m.* FROM private.partner_session_mint(coalesce(p_token, encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex')), a.cred_id, a.nonce, a.exp, a.mac, a.ad, a.cd, a.sig) m;
  EXECUTE 'RESET ROLE';
  RETURN (SELECT o_status FROM mres WHERE label = p_label ORDER BY ctid DESC LIMIT 1);
END
$f$;

-- like go(), but the mint is presented with a GIVEN token hash (to collide with an existing session's)
CREATE FUNCTION pg_temp.go_dup(p_label text, p_cred text, p_counter bigint, p_token text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; a record;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter, '{}'::jsonb);
  EXECUTE 'RESET ROLE';
  INSERT INTO asr VALUES (p_label, p_token, c.cred_id, a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  RETURN pg_temp.present(p_label, p_label, p_token);
END
$f$;
CREATE FUNCTION pg_temp.st(p_label text) RETURNS text LANGUAGE sql AS $f$ SELECT o_status FROM mres WHERE label = p_label ORDER BY ctid DESC LIMIT 1 $f$;
CREATE FUNCTION pg_temp.side(p_cred text) RETURNS jsonb LANGUAGE sql AS $f$
  -- every side effect the mint can leave for one credential: its sessions, its counter, the used nonces of its person, the alarms, and the audit rows
  SELECT jsonb_build_object(
    'sessions', (SELECT count(*) FROM app.partner_session s JOIN creds c ON c.cred_row = s.credential_id WHERE c.label = p_cred),
    'counter', (SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = p_cred),
    'nonces', (SELECT count(*) FROM app.partner_auth_challenge ch JOIN creds c ON c.uid = ch.user_id WHERE c.label = p_cred),
    'alarms', (SELECT count(*) FROM app.partner_auth_alarm a JOIN creds c ON c.cred_row = a.credential_id WHERE c.label = p_cred),
    'audits', (SELECT count(*) FROM app.audit_log l JOIN creds c ON c.cred_row::text = l.subject_id WHERE c.label = p_cred AND l.action LIKE 'partner.mint.%'))
$f$;

-- principals (helpers.sql): staff_x, manager_x, operator_t, admin; and fresh ones so each scenario owns its person
SELECT pg_temp.newcred('staff', '00000000-0000-0000-0000-1000000000a1', 0) IS NOT NULL AS staff_cred \gset
SELECT pg_temp.newcred('operator', '00000000-0000-0000-0000-3000000000c1', 0) IS NOT NULL AS op_cred \gset
SELECT pg_temp.newcred('admin', '00000000-0000-0000-0000-4000000000d0', 0) IS NOT NULL AS admin_cred \gset

-- ----------------------------------------------------------------------------
-- 1. PA-8: only the minter can mint, and it can execute nothing else
-- ----------------------------------------------------------------------------
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'partner_session_issuer'::regrole FROM pg_proc p WHERE p.oid = 'private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure), true,
  'PA-8: the mint is SECURITY DEFINER with search_path = '''', owned by partner_session_issuer (the 0047 seam: not private_definer)');
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole FROM pg_proc p WHERE p.oid = 'private.partner_challenge_issue_sign_in()'::regprocedure), true,
  'PA-8: the challenge issuer is SECURITY DEFINER with search_path = '''', owned by private_definer (the only Vault reader)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE')), ARRAY['edge_partner_minter'],
  'PA-8: of every client and edge role, ONLY edge_partner_minter can execute the mint');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_challenge_issue_sign_in()'::regprocedure, 'EXECUTE')), ARRAY['edge_partner_minter'],
  'PA-8: ... and ONLY edge_partner_minter can issue a sign-in challenge');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname IN ('app', 'api', 'private', 'public') AND p.prokind IN ('f', 'p') AND has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE')
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
             AND NOT (n.nspname = 'public' AND p.proname ~ '^(is|isnt|ok|plan|diag|finish|no_plan|throws_ok|lives_ok|pass|fail|like|unlike|matches|doesnt_match|cmp_ok|isa_ok|is_empty|isnt_empty|results_eq|set_eq|bag_eq|has_|hasnt_|col_|todo|skip|runtests|_)')), ARRAY['partner_challenge_issue_sign_in', 'partner_credential_lookup', 'partner_credential_register_first', 'partner_enrolment_token_accept', 'partner_enrolment_token_email_for_token', 'partner_invite_accept', 'partner_invite_email_for_token', 'partner_rp_config_read', 'partner_session_mint', 'partner_sign_in_failure_record'],
  'PA-8: the minter can execute NOTHING ELSE in app, api or private but the three minter-lane definers of 0049 (S1.2: the credential lookup, the failure counter and the relying-party read) and the five of 0054 (S1.5: matrix 32 proves them); the pgTAP and extension functions of public aside');
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
             AND (has_any_column_privilege('edge_partner_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_partner_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER'))), 0,
  'PA-8: the minter holds no privilege on any relation (the temp tables of this file aside)');
-- the minter cannot reach the helpers behind the mint
SELECT is((SELECT count(*)::int FROM (VALUES ('private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea)'), ('private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea)'),
                                                 ('private.partner_mint_alarm_write(text, uuid, jsonb)'), ('private.partner_sig_verify(smallint, bytea, bytea, bytea)'), ('private.partner_session_policy(uuid)')) f(sig)
           CROSS JOIN (VALUES ('edge_partner_minter'), ('edge_partner'), ('edge_actor'), ('edge_system'), ('service_role'), ('authenticated'), ('anon')) r(n)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), 0,
  'PA-8: no edge, client or service role can execute the HMAC core, the verifier, the alarm writer or the policy helper behind the mint');
SELECT throws_ok($$SET LOCAL ROLE edge_actor; SELECT * FROM private.partner_challenge_issue_sign_in()$$, '42501', NULL, 'PA-8: edge_actor cannot issue a sign-in challenge');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner; SELECT * FROM private.partner_challenge_issue_sign_in()$$, '42501', NULL, 'PA-8: edge_partner cannot issue a sign-in challenge');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_actor; SELECT * FROM private.partner_session_mint(repeat('0', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$,
  '42501', NULL, 'PA-8: edge_actor cannot mint');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner; SELECT * FROM private.partner_session_mint(repeat('0', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$,
  '42501', NULL, 'PA-8: edge_partner (the partner lane) cannot mint: a handler bug in any partner function cannot create a session');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '42501', NULL, 'PA-8: the minter cannot reach the key-reading core directly (no oracle for an arbitrary MAC)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT private.partner_sig_verify(-7::smallint, '\x00', '\x00', '\x00')$$, '42501', NULL, 'PA-8: nor the signature verifier');
RESET ROLE;
-- a transaction bound by ANY lane refuses to mint or to issue (the 0041 rule)
SAVEPOINT sp_bound;
SELECT lives_ok($$SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$, 'setup: bind a user in this transaction (edge_actor)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_challenge_issue_sign_in()$$, '42501', 'partner_challenge_issue_sign_in: refused inside a bound transaction', 'the issuer refuses inside a USER-bound transaction');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('0', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$,
  '42501', 'partner_session_mint: refused inside a bound transaction', 'the mint refuses inside a USER-bound transaction');
RESET ROLE;
ROLLBACK TO sp_bound;

-- ----------------------------------------------------------------------------
-- 2. PA-7: the stateless challenge: the HMAC is pinned OUTSIDE the database; no purpose or binding argument; no row written
-- ----------------------------------------------------------------------------
-- vectors computed with Python hmac / struct / uuid from the shim's key and the message
--   b'golfraven/partner-challenge/v1' + b'\x00' + bytes([purpose]) + struct.pack('>q', exp) + nonce + uuid.UUID(binding).bytes
SET LOCAL ROLE private_definer;
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)), 'hex'),
  'd3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73b5', 'HMAC vector 1: sign_in, exp 1700000000, nonce ab*32, zero binding');
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(2::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)), 'hex'),
  'a4cb150722f7ec1efaf0838a458554aa8de09b59a3c293c352b85b7a1abf4b88', 'HMAC vector 2: the SAME tuple with purpose 2 (register) is a different MAC: the purpose is in the message');
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(3::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), 'ee260000-0000-0000-0000-0000000000f1', NULL)), 'hex'),
  '4f9a1b82173bd372c4df592066752849d1dd90bd290a0099449a8e715b1a85a2', 'HMAC vector 3: purpose 3 (reauth) bound to a session uuid');
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(1::smallint, 1893456000, decode(repeat('00', 31) || '01', 'hex'), '00000000-0000-0000-0000-000000000000', NULL)), 'hex'),
  '434e63ad39e84eb52888eba00fa440e14346e2119b41a3705ca9c97190dee350', 'HMAC vector 4: a different expiry and nonce');
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(1::smallint, 1700000001, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)), 'hex'),
  '56bf71ab408cdc3f1c04087ec102635d8e99c9c29a298465448f44707dd0afa9', 'HMAC vector 5: exp + 1 is a different MAC (the expiry is in the message, 8 bytes big-endian)');
SELECT is(encode((SELECT o_mac FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), 'ee260000-0000-0000-0000-0000000000f1', NULL)), 'hex'),
  '751b5a345eb970c5cfb964a31186b3e3546287e005d22621d17ffd77b7eda348', 'HMAC vector 6: the binding is in the message (16 bytes)');
-- the comparison, and the core's own argument checks
SELECT is((SELECT o_ok FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000',
  decode('d3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73b5', 'hex'))), true, 'the core accepts the MAC of vector 1 as presented');
SELECT is((SELECT o_ok FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000',
  decode('d3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73b4', 'hex'))), false, 'a MAC that differs in its last bit is refused');
SELECT is((SELECT o_ok FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)), false, 'a NULL presented MAC is refused');
SELECT is((SELECT o_ok FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000',
  decode('d3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73', 'hex'))), false, 'a truncated MAC is refused');
SELECT is((SELECT o_ok FROM private.partner_challenge_core(1::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000',
  decode('d3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73b500', 'hex'))), false, 'a MAC with a trailing byte is refused');
SELECT is((SELECT o_ok FROM private.partner_challenge_core(2::smallint, 1700000000, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000',
  decode('d3270cd5976be1c753e5c36547209c13c1d2e130824e0bd719cc49f8cbcb73b5', 'hex'))), false, 'the MAC of a sign_in challenge does not verify as a register challenge');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(0::smallint, 1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '22023', NULL, 'core: purpose 0 is refused');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(4::smallint, 1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '22023', NULL, 'core: purpose 4 is refused');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 31), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '22023', NULL, 'core: a 31-byte nonce is refused');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 33), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '22023', NULL, 'core: a 33-byte nonce is refused');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 32), 'hex'), NULL, NULL)$$, '22023', NULL, 'core: a NULL binding is refused');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, -1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '22023', NULL, 'core: a negative expiry is refused');
RESET ROLE;
-- K missing / too short fails closed (55000) and names no key material
DELETE FROM vault.secrets WHERE name = 'partner_challenge_key';
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '55000',
  'partner_challenge_core: the partner challenge key is not provisioned in Vault', 'no key in the Vault: 55000, with a message that names no key');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_challenge_issue_sign_in()$$, '55000', NULL, 'and the issuer fails the same way (no challenge without the key)');
RESET ROLE;
INSERT INTO vault.secrets (name, secret) VALUES ('partner_challenge_key', repeat('k', 31));
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1, decode(repeat('ab', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL)$$, '55000', NULL, 'a 31-byte key is refused (the minimum is 32 bytes)');
RESET ROLE;
DELETE FROM vault.secrets WHERE name = 'partner_challenge_key';
INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-0000000000f2', 'partner_challenge_key', 'shim-test-only-partner-challenge-key-32bytes-minimum-qqqqqqqqqqqqqqqqqqqqq');

-- the issuer
CREATE TEMP TABLE issued AS SELECT 0 AS n, NULL::bytea AS nonce, NULL::bigint AS exp, NULL::bytea AS mac, NULL::bigint AS lo, NULL::bigint AS hi WHERE false;
GRANT ALL ON issued TO PUBLIC;
SET LOCAL ROLE edge_partner_minter;
DO $d$
DECLARE
  lo bigint;
BEGIN
  FOR i IN 1 .. 200 LOOP
    lo := floor(extract(epoch FROM clock_timestamp()))::bigint;
    INSERT INTO pg_temp.issued SELECT i, c.o_nonce, c.o_exp, c.o_mac, lo, floor(extract(epoch FROM clock_timestamp()))::bigint FROM private.partner_challenge_issue_sign_in() c;
  END LOOP;
END
$d$;
RESET ROLE;
SELECT is((SELECT count(DISTINCT nonce)::int FROM issued), 200, 'issue: 200 calls give 200 distinct nonces');
SELECT is((SELECT count(*)::int FROM issued WHERE octet_length(nonce) <> 32 OR octet_length(mac) <> 32), 0, 'issue: every nonce and every MAC is 32 bytes');
SELECT is((SELECT count(*)::int FROM issued WHERE exp NOT BETWEEN lo + 120 AND hi + 120), 0, 'issue: the expiry is EXACTLY 120 seconds ahead of the second the call ran in (the ceremony timeout of the options call; bracketed by the clock before and after each call)');
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM issued i WHERE (SELECT o_ok FROM private.partner_challenge_core(1::smallint, i.exp, i.nonce, '00000000-0000-0000-0000-000000000000', i.mac)) IS NOT TRUE), 0,
  'issue: every issued MAC verifies as a sign_in challenge with the zero binding (the encoding of 5.1)');
SELECT is((SELECT count(*)::int FROM issued i WHERE (SELECT o_ok FROM private.partner_challenge_core(2::smallint, i.exp, i.nonce, '00000000-0000-0000-0000-000000000000', i.mac)) IS TRUE), 0,
  'issue: and none verifies under another purpose');
RESET ROLE;
SELECT is((SELECT pronargs::int FROM pg_proc WHERE oid = 'private.partner_challenge_issue_sign_in()'::regprocedure), 0, 'issue: it takes NO argument (no purpose and no binding to choose, R3-M2)');
-- 10,000 option calls write nothing (PA-7)
SELECT count(*)::int AS chal_before FROM app.partner_auth_challenge \gset
SET LOCAL ROLE edge_partner_minter;
SELECT count(*) AS n_calls FROM (SELECT private.partner_challenge_issue_sign_in() FROM generate_series(1, 10000)) x \gset
RESET ROLE;
SELECT is(:n_calls, 10000, 'PA-7: 10,000 option calls ran');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge), :chal_before, 'PA-7: ... and left the used-nonce row count UNCHANGED (stateless: nothing is persisted when a challenge is issued)');
SELECT is((SELECT count(*)::int FROM app.partner_auth_alarm) + (SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.mint.%'), 0, 'PA-7: ... and wrote no alarm and no audit row');

-- ----------------------------------------------------------------------------
-- 3. The mint: a valid assertion mints, and the evidence is what was verified
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.go('ok1', 'staff', 1), 'ok', 'a valid ES256 assertion for a staff member mints (counter 1 against a stored 0)');
SELECT is((SELECT o_aal FROM mres WHERE label = 'ok1'), 1::smallint, 'the session is born at aal 1');
SELECT is((SELECT s.mint_kind || ':' || (s.user_id = c.uid)::text || ':' || (s.credential_id = c.cred_row)::text || ':' || s.aal::text || ':' || (s.revoked_at IS NULL)::text
           FROM app.partner_session s JOIN mres m ON m.o_session_id = s.id JOIN creds c ON c.label = 'staff' WHERE m.label = 'ok1'), 'sign_in:true:true:1:true',
  'the session row: kind sign_in, the credential''s own person and credential, aal 1, live');
SELECT is((SELECT s.token_hash FROM app.partner_session s JOIN mres m ON m.o_session_id = s.id WHERE m.label = 'ok1'), (SELECT token FROM asr WHERE label = 'ok1'), 'the session stores the token HASH the Edge sent (the raw token never reaches the database)');
SELECT is((SELECT (s.mint_nonce_hash = sha256(a.nonce) AND s.mint_authenticator_data = a.ad AND s.mint_client_data_json = a.cd AND s.mint_signature = a.sig)
           FROM app.partner_session s JOIN mres m ON m.o_session_id = s.id JOIN asr a ON a.label = m.label WHERE m.label = 'ok1'), true,
  'the mint_* columns hold exactly the nonce hash, authenticatorData, clientDataJSON and signature that were verified (the record of what the signature covered)');
SELECT is((SELECT (ch.purpose = 'sign_in' AND ch.minted_session_id = m.o_session_id AND ch.nonce_hash = sha256(a.nonce) AND ch.user_id = c.uid)
           FROM app.partner_auth_challenge ch JOIN mres m ON m.label = 'ok1' JOIN asr a ON a.label = 'ok1' JOIN creds c ON c.label = 'staff' WHERE ch.nonce_hash = sha256(a.nonce)), true,
  'the challenge is recorded as USED: sha256(nonce) is the key, purpose sign_in, bound to the session it minted');
SELECT is((SELECT (pc.sign_count = 1 AND pc.last_used_at IS NOT NULL) FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'staff'), true, 'the credential''s counter advanced to 1 and last_used_at is set');
SELECT ok((SELECT o_expires_at FROM mres WHERE label = 'ok1') BETWEEN now() + interval '7 hours 59 minutes' AND now() + interval '8 hours 1 minute', 'a staff session lives at most 8 hours (the role ceiling, 4.1)');
SELECT is(pg_temp.go('ok_op', 'operator', 1), 'ok', 'an operator mints');
SELECT ok((SELECT o_expires_at FROM mres WHERE label = 'ok_op') BETWEEN now() + interval '3 hours 59 minutes' AND now() + interval '4 hours 1 minute', 'an operator session lives at most 4 hours');
SELECT is(pg_temp.go('ok_ad', 'admin', 1), 'ok', 'an admin mints (a person with no membership but an admin_user row)');
SELECT ok((SELECT o_expires_at FROM mres WHERE label = 'ok_ad') BETWEEN now() + interval '59 minutes' AND now() + interval '1 hour 1 minute', 'an admin session lives at most 1 hour');
-- end to end: the session the mint made is the session the binder accepts (a staff member of fac_x)
SAVEPOINT sp_bind;
SELECT lives_ok($$SET LOCAL ROLE edge_partner; SELECT private.bind_partner_session((SELECT token FROM pg_temp.asr WHERE label = 'ok1'))$$, 'bind_partner_session accepts the session the mint created');
RESET ROLE;
ROLLBACK TO sp_bind;

-- ----------------------------------------------------------------------------
-- 4. PA-7: replay, expiry, wrong purpose, tampered HMAC
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.present('replay1', 'ok1'), 'replayed', 'PA-7: the SAME challenge presented again is refused (the used nonce is a primary key): a replay');
SELECT is((SELECT jsonb_build_object('sessions', count(*)) FROM app.partner_session s JOIN creds c ON c.cred_row = s.credential_id WHERE c.label = 'staff'), jsonb_build_object('sessions', 1), 'PA-7: the replay minted no second session');
SELECT is((SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'staff'), 1::bigint, 'PA-7: and did not touch the counter');
-- the same challenge (nonce, exp, mac) used by ANOTHER credential's assertion
SELECT pg_temp.newcred('other', '00000000-0000-0000-0000-2000000000b1', 0) IS NOT NULL AS other_cred \gset
SELECT is(pg_temp.go('replay_other', 'other', 1, (SELECT jsonb_build_object('nonce_hex', encode(nonce, 'hex'), 'mac_hex', encode(mac, 'hex'), 'exp_abs', exp) FROM asr WHERE label = 'ok1')),
  'replayed', 'PA-7: one challenge, one use: a second credential presenting the same challenge token is refused too');
SELECT is(pg_temp.go('expired1', 'other', 1, '{"exp_offset": -5}'), 'expired', 'PA-7: an EXPIRED challenge (a valid MAC over a past expiry) is refused');
SELECT is(pg_temp.go('expired0', 'other', 1, '{"exp_offset": 0}'), 'expired', 'PA-7: a challenge that expires THIS second is expired (exp <= now)');
SELECT is(pg_temp.go('purpose2', 'other', 1, '{"mac_purpose": 2}'), 'bad_challenge', 'PA-7: a challenge of ANOTHER purpose (a register MAC) is refused');
SELECT is(pg_temp.go('purpose3', 'other', 1, '{"mac_purpose": 3}'), 'bad_challenge', 'PA-7: a reauth challenge is refused');
SELECT is(pg_temp.go('binding1', 'other', 1, '{"mac_binding": "ee260000-0000-0000-0000-0000000000f1"}'), 'bad_challenge', 'PA-7: a challenge with a NON-ZERO binding is refused (a sign_in challenge binds nothing)');
SELECT is(pg_temp.go('tamper_mac', 'other', 1, '{"mac_tamper": true}'), 'bad_challenge', 'PA-7: a tampered MAC is refused');
SELECT is(pg_temp.go('tamper_exp', 'other', 1, '{"mac_exp_shift": 600}'), 'bad_challenge', 'PA-7: a tampered expiry (the MAC was made for another one) is refused');
SELECT is(pg_temp.go('short_mac', 'other', 1, jsonb_build_object('mac_hex', repeat('ab', 31))), 'bad_challenge', 'PA-7: a MAC of 31 bytes is refused');
SELECT is(pg_temp.go('zero_mac', 'other', 1, jsonb_build_object('mac_hex', repeat('00', 32))), 'bad_challenge', 'PA-7: an all-zero MAC is refused');
SELECT is(pg_temp.side('other'), '{"sessions": 0, "counter": 0, "nonces": 0, "alarms": 0, "audits": 0}'::jsonb, 'PA-7: none of those refusals left a session, a nonce, an alarm or a counter change');
-- the order: the HMAC is checked before the credential (an unknown credential with a bad MAC is a bad challenge) and the expiry after it
SELECT is(pg_temp.go('badmac_nocred', 'other', 1, '{"mac_tamper": true, "cred_id_hex": "0102030405060708090a0b0c0d0e0f10"}'), 'bad_challenge', 'order: a bad MAC is refused before the credential is even looked up');
SELECT is(pg_temp.go('expired_nocred', 'other', 1, '{"exp_offset": -5, "cred_id_hex": "0102030405060708090a0b0c0d0e0f10"}'), 'expired', 'order: an expired challenge is refused before the credential is looked up');
-- the single use survives a failed attempt of a DIFFERENT shape, and is spent only by the mint (below, 6): here a plain control
SELECT is(pg_temp.go('control_other', 'other', 1), 'ok', 'control: the credential that every refusal above used mints with a fresh, valid challenge');

-- ----------------------------------------------------------------------------
-- 5. Unknown and revoked credentials; the credential comes from the table
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.go('unk', 'staff', 2, '{"cred_id_hex": "a1a2a3a4a5a6a7a8a9aaabacadaeafb0"}'), 'unknown_credential', 'an unknown credential id is refused');
SELECT pg_temp.newcred('revoked') IS NOT NULL AS rev_cred \gset
UPDATE app.partner_credential SET revoked_at = now() WHERE id = (SELECT cred_row FROM creds WHERE label = 'revoked');
SELECT is(pg_temp.go('rev', 'revoked', 1), 'unknown_credential', 'a REVOKED credential is the same answer as an unknown one (no oracle)');
SELECT is(pg_temp.side('revoked'), '{"sessions": 0, "counter": 0, "nonces": 0, "alarms": 0, "audits": 0}'::jsonb, 'and left nothing behind: no alarm either (it is not a forged signature, it is a stale credential)');
-- the key is looked up, never taken from an argument: an assertion signed by ANOTHER key is a bad signature for THIS credential
SELECT pg_temp.newcred('imp') IS NOT NULL AS imp_cred \gset
SELECT is(pg_temp.go('wrongkey', 'imp', 1, (SELECT jsonb_build_object('sign_d', d::text) FROM creds WHERE label = 'other')), 'signature_invalid', 'a signature by another credential''s key is refused: the verifying key is the stored one');

-- ----------------------------------------------------------------------------
-- 6. S0-L5: at most 60 successful sign-ins per credential per hour, BEFORE verification
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('rl') IS NOT NULL AS rl_cred \gset
CREATE FUNCTION pg_temp.fill_sessions(p_cred text, p_n int, p_age interval DEFAULT interval '0', p_kind text DEFAULT 'sign_in', p_revoked boolean DEFAULT false) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  -- fixture rows: the INSERT guard (S1.1a, M2) refuses a back-dated row, so it is off for exactly this statement (ALTER TABLE needs no pending deferred FK events)
  SET CONSTRAINTS ALL IMMEDIATE;
  ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, revoked_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  SELECT encode(sha256(convert_to('fill:' || p_cred || ':' || p_kind || ':' || g || ':' || clock_timestamp()::text || random()::text, 'UTF8')), 'hex'), c.uid, c.cred_row, 1, now() - p_age, now() - p_age, now() + interval '8 hours',
         CASE WHEN p_revoked THEN now() END, p_kind, sha256(convert_to('fn:' || p_cred || ':' || p_kind || ':' || g || ':' || random()::text, 'UTF8')), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'),
         CASE WHEN p_kind = 'sign_in' THEN decode(repeat('05', 70), 'hex') END
  FROM creds c, generate_series(1, p_n) g WHERE c.label = p_cred;
  ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
END
$f$;
SELECT pg_temp.fill_sessions('rl', 59);
SELECT is((SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.cred_row = s.credential_id WHERE c.label = 'rl'), 59, 'setup: 59 sign-in sessions in the last hour for this credential');
-- the ORDER: with 59 the mint reaches verification (a tampered signature is the ALARM status) ...
SELECT is(pg_temp.go('rl_59_bad', 'rl', 1, '{"sig_tamper": true}'), 'signature_invalid', 'S0-L5: with 59 sign-ins in the last hour the mint is NOT rate limited: it reaches the signature check');
SELECT is(pg_temp.go('rl_59_ok', 'rl', 1), 'ok', 'S0-L5: the 60th successful sign-in is accepted');
SELECT is((SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.cred_row = s.credential_id WHERE c.label = 'rl'), 60, 'S0-L5: now exactly 60');
SELECT is((SELECT (pg_temp.side('rl') ->> 'alarms')::int), 1, 'setup: the one alarm so far (the tampered signature at 59)');
-- ... with 60 it stops BEFORE verification: a tampered signature is rate_limited, not signature_invalid, and writes no alarm
SELECT is(pg_temp.go('rl_60_bad', 'rl', 2, '{"sig_tamper": true}'), 'rate_limited', 'S0-L5: the 61st attempt is refused as rate_limited, BEFORE the signature is looked at (a bad signature does not reach the verifier)');
SELECT is((SELECT (pg_temp.side('rl') ->> 'alarms')::int), 1, 'S0-L5: and the refusal wrote no alarm (it never verified anything)');
SELECT is(pg_temp.go('rl_60_good', 'rl', 2), 'rate_limited', 'S0-L5: a perfectly valid assertion is refused too, while 60 are in the window');
SELECT is(pg_temp.go('rl_60_struct', 'rl', 2, '{"client": {"origin": "https://evil.example.test"}}'), 'rate_limited', 'S0-L5: with 60 in the window an assertion that is ALSO structurally defective (another origin) is rate_limited, not bad_origin: the limit is checked before the structural checks');
SELECT is((pg_temp.side('rl') ->> 'nonces')::int, 1, 'S0-L5: neither refusal consumed a nonce (only the one successful mint did)');
SELECT is((pg_temp.side('rl') ->> 'counter')::bigint, 1::bigint, 'S0-L5: nor moved the counter');
-- what does and does not count
SELECT pg_temp.newcred('rl_old') IS NOT NULL AS rl2 \gset
SELECT pg_temp.fill_sessions('rl_old', 60, interval '61 minutes');
SELECT is(pg_temp.go('rl_old_ok', 'rl_old', 1), 'ok', 'S0-L5: sign-ins older than an hour do not count (60 of them, 61 minutes old)');
SELECT pg_temp.newcred('rl_reg') IS NOT NULL AS rl3 \gset
SELECT pg_temp.fill_sessions('rl_reg', 60, interval '0', 'register');
SELECT is(pg_temp.go('rl_reg_ok', 'rl_reg', 1), 'ok', 'S0-L5: a register-kind session is not a sign-in: it does not count');
SELECT pg_temp.newcred('rl_rev') IS NOT NULL AS rl4 \gset
SELECT pg_temp.fill_sessions('rl_rev', 60, interval '0', 'sign_in', true);
SELECT is(pg_temp.go('rl_rev_no', 'rl_rev', 1), 'rate_limited', 'S0-L5: a REVOKED sign-in session still counts (it was a successful sign-in)');
SELECT pg_temp.newcred('rl_other') IS NOT NULL AS rl5 \gset
SELECT is(pg_temp.go('rl_other_ok', 'rl_other', 1), 'ok', 'S0-L5: the count is per CREDENTIAL: another credential (the 60 above belong to a different one) is unaffected');
-- the count is per CREDENTIAL, not per person: the same person with two credentials
SELECT pg_temp.newcred('mx_a') IS NOT NULL AS mx1 \gset
SELECT pg_temp.newcred('mx_b', (SELECT uid FROM creds WHERE label = 'mx_a')) IS NOT NULL AS mx2 \gset
SELECT pg_temp.fill_sessions('mx_a', 59);
SELECT pg_temp.fill_sessions('mx_b', 1);
SELECT is(pg_temp.go('mx_a_ok', 'mx_a', 1), 'ok', 'S0-L5: 59 sign-ins on this credential and 1 on the same person''s other credential (60 for the person) is NOT rate limited: the limit is per credential');
SELECT pg_temp.newcred('mx_c') IS NOT NULL AS mx3 \gset
SELECT pg_temp.newcred('mx_d', (SELECT uid FROM creds WHERE label = 'mx_c')) IS NOT NULL AS mx4 \gset
SELECT pg_temp.fill_sessions('mx_c', 60);
SELECT is(pg_temp.go('mx_d_ok', 'mx_d', 1), 'ok', 'S0-L5: the same person''s OTHER credential, with 60 sign-ins on the first, still mints');
SELECT pg_temp.newcred('rl_edge') IS NOT NULL AS rl6 \gset
SELECT pg_temp.fill_sessions('rl_edge', 60, interval '59 minutes 30 seconds');
SELECT is(pg_temp.go('rl_edge_no', 'rl_edge', 1), 'rate_limited', 'S0-L5: 60 sign-ins 59.5 minutes old are still inside the hour');
SELECT pg_temp.newcred('rl_just_out') IS NOT NULL AS rl7 \gset
SELECT pg_temp.fill_sessions('rl_just_out', 60, interval '60 minutes 30 seconds');
SELECT is(pg_temp.go('rl_just_out_ok', 'rl_just_out', 1), 'ok', 'S0-L5: 60 sign-ins 60.5 minutes old are OUTSIDE the hour (the window is one hour, not 61 minutes)');


-- ----------------------------------------------------------------------------
-- 7. PA-9b: every structural refusal. Each assertion is RE-SIGNED over the defective data, so the structural check (which runs BEFORE the signature
--    check) is the only thing that can refuse it; the unmodified assertion is the control. A refusal leaves nothing behind.
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('struct') IS NOT NULL AS struct_cred \gset
-- clientDataJSON.type
SELECT is(pg_temp.go('s_type_create', 'struct', 1, '{"client": {"type": "webauthn.create"}}'), 'bad_client_type', 'PA-9b: clientDataJSON.type webauthn.create is refused');
SELECT is(pg_temp.go('s_type_none', 'struct', 1, '{"client_drop": ["type"]}'), 'bad_client_type', 'PA-9b: a missing type is refused');
SELECT is(pg_temp.go('s_type_num', 'struct', 1, '{"client": {"type": 7}}'), 'bad_client_type', 'PA-9b: a numeric type is refused');
SELECT is(pg_temp.go('s_type_case', 'struct', 1, '{"client": {"type": "WebAuthn.get"}}'), 'bad_client_type', 'PA-9b: a type in another case is refused (exact match)');
SELECT is(pg_temp.go('s_type_pad', 'struct', 1, '{"client": {"type": "webauthn.get "}}'), 'bad_client_type', 'PA-9b: a type with a trailing space is refused');
-- crossOrigin / topOrigin
SELECT is(pg_temp.go('s_cross_true', 'struct', 1, '{"client": {"crossOrigin": true}}'), 'cross_origin', 'PA-9b: crossOrigin true is refused');
SELECT is(pg_temp.go('s_cross_str', 'struct', 1, '{"client": {"crossOrigin": "true"}}'), 'cross_origin', 'PA-9b: crossOrigin "true" (a string) is refused');
SELECT is(pg_temp.go('s_cross_str_false', 'struct', 1, '{"client": {"crossOrigin": "false"}}'), 'cross_origin', 'PA-9b: crossOrigin "false" (a string) is refused: only the boolean false passes');
SELECT is(pg_temp.go('s_cross_one', 'struct', 1, '{"client": {"crossOrigin": 1}}'), 'cross_origin', 'PA-9b: crossOrigin 1 is refused');
SELECT is(pg_temp.go('s_cross_zero', 'struct', 1, '{"client": {"crossOrigin": 0}}'), 'cross_origin', 'PA-9b: crossOrigin 0 is refused (not the boolean false)');
SELECT is(pg_temp.go('s_cross_null', 'struct', 1, '{"client": {"crossOrigin": null}}'), 'cross_origin', 'PA-9b: crossOrigin null is refused');
SELECT is(pg_temp.go('s_top', 'struct', 1, '{"client": {"topOrigin": "https://partners.example.test"}}'), 'cross_origin', 'PA-9b: any topOrigin is refused, with crossOrigin false');
-- origin: exact, never a prefix, a subdomain, a scheme or a case variant (S0-N1)
-- the ORDER: a structurally defective assertion whose signature is ALSO bad is refused for the structure, and is no alarm (the signature is looked at last; an alarm means the Edge's own verification was bypassed)
SELECT pg_temp.newcred('order') IS NOT NULL AS order_cred \gset
SELECT is(pg_temp.go('o_origin', 'order', 1, '{"client": {"origin": "https://evil.example.test"}, "sig_tamper": true}'), 'bad_origin', 'PA-9b order: a wrong origin AND a bad signature is bad_origin: the structural check runs before the signature check');
SELECT is(pg_temp.go('o_uv', 'order', 1, '{"flags": 1, "sig_tamper": true}'), 'user_not_verified', 'PA-9b order: missing user verification AND a bad signature is user_not_verified');
SELECT is(pg_temp.go('o_rp', 'order', 1, '{"rp": "other.example.test", "sig_tamper": true}'), 'bad_rp_id_hash', 'PA-9b order: another RP ID hash AND a bad signature is bad_rp_id_hash');
SELECT is((SELECT (pg_temp.side('order') ->> 'alarms')::int), 0, 'PA-9b order: and none of those raised an alarm (the signature was never looked at)');
SELECT is(pg_temp.go('s_origin_evil', 'struct', 1, '{"client": {"origin": "https://evil.example.test"}}'), 'bad_origin', 'PA-9b: another origin is refused');
SELECT is(pg_temp.go('s_origin_sub', 'struct', 1, '{"client": {"origin": "https://app.partners.example.test"}}'), 'bad_origin', 'PA-9b / S0-N1: a SUBDOMAIN of the RP ID is a valid WebAuthn origin and is still refused: the origin is matched EXACTLY');
SELECT is(pg_temp.go('s_origin_slash', 'struct', 1, '{"client": {"origin": "https://partners.example.test/"}}'), 'bad_origin', 'PA-9b: a trailing slash is refused');
SELECT is(pg_temp.go('s_origin_http', 'struct', 1, '{"client": {"origin": "http://partners.example.test"}}'), 'bad_origin', 'PA-9b: http is refused');
SELECT is(pg_temp.go('s_origin_case', 'struct', 1, '{"client": {"origin": "https://Partners.example.test"}}'), 'bad_origin', 'PA-9b: a host in another case is refused');
SELECT is(pg_temp.go('s_origin_port', 'struct', 1, '{"client": {"origin": "https://partners.example.test:8443"}}'), 'bad_origin', 'PA-9b: a port is refused');
SELECT is(pg_temp.go('s_origin_prefix', 'struct', 1, '{"client": {"origin": "https://partners.example.test.evil.test"}}'), 'bad_origin', 'PA-9b: a longer host that starts with the origin is refused');
SELECT is(pg_temp.go('s_origin_none', 'struct', 1, '{"client_drop": ["origin"]}'), 'bad_origin', 'PA-9b: a missing origin is refused');
SELECT is(pg_temp.go('s_origin_num', 'struct', 1, '{"client": {"origin": 5}}'), 'bad_origin', 'PA-9b: a numeric origin is refused');
-- challenge: it must be the base64url (no padding) of the token's nonce
SELECT is(pg_temp.go('s_chal_other', 'struct', 1, jsonb_build_object('client', jsonb_build_object('challenge', pg_temp.ps_b64u(decode(repeat('11', 32), 'hex'))))), 'challenge_mismatch', 'PA-9b: a different challenge is refused');
SELECT is(pg_temp.go('s_chal_pad', 'struct', 1, jsonb_build_object('nonce_hex', repeat('cd', 32), 'client', jsonb_build_object('challenge', pg_temp.ps_b64u(decode(repeat('cd', 32), 'hex')) || '='))), 'challenge_mismatch', 'PA-9b: the right challenge WITH base64 padding is refused (base64url, unpadded)');
SELECT is(pg_temp.go('s_chal_std', 'struct', 1, jsonb_build_object('nonce_hex', repeat('fb', 32), 'client', jsonb_build_object('challenge', replace(encode(decode(repeat('fb', 32), 'hex'), 'base64'), '=', '')))), 'challenge_mismatch', 'PA-9b: the standard base64 alphabet (+ and /) instead of base64url (- and _) is refused');
SELECT is(pg_temp.go('s_chal_empty', 'struct', 1, '{"client": {"challenge": ""}}'), 'challenge_mismatch', 'PA-9b: an empty challenge is refused');
SELECT is(pg_temp.go('s_chal_num', 'struct', 1, '{"client": {"challenge": 12345}}'), 'challenge_mismatch', 'PA-9b: a numeric challenge is refused');
SELECT is(pg_temp.go('s_chal_none', 'struct', 1, '{"client_drop": ["challenge"]}'), 'challenge_mismatch', 'PA-9b: a missing challenge is refused');
SELECT is(pg_temp.go('s_chal_upper', 'struct', 1, jsonb_build_object('nonce_hex', repeat('ab', 32), 'client', jsonb_build_object('challenge', upper(pg_temp.ps_b64u(decode(repeat('ab', 32), 'hex')))))), 'challenge_mismatch', 'PA-9b: the right challenge in another case is refused (exact match)');
-- authenticatorData
SELECT is(pg_temp.go('s_rp_other', 'struct', 1, '{"rp": "other.example.test"}'), 'bad_rp_id_hash', 'PA-9b: an rpIdHash of another RP ID is refused');
SELECT is(pg_temp.go('s_rp_case', 'struct', 1, '{"rp": "Partners.Example.Test"}'), 'bad_rp_id_hash', 'PA-9b: the hash of the RP ID in another case is refused');
SELECT is(pg_temp.go('s_rp_dot', 'struct', 1, '{"rp": "partners.example.test."}'), 'bad_rp_id_hash', 'PA-9b: the hash of the RP ID with a trailing dot is refused');
SELECT is(pg_temp.go('s_flag_up_only', 'struct', 1, '{"flags": 1}'), 'user_not_verified', 'PA-9b: user presence without user verification (flags 0x01) is refused: UV is required');
SELECT is(pg_temp.go('s_flag_uv_only', 'struct', 1, '{"flags": 4}'), 'user_not_present', 'PA-9b: user verification without user presence (flags 0x04) is refused: UP is required');
SELECT is(pg_temp.go('s_flag_none', 'struct', 1, '{"flags": 0}'), 'user_not_present', 'PA-9b: no flags at all is refused');
SELECT is(pg_temp.go('s_flag_other', 'struct', 1, '{"flags": 250}'), 'user_not_present', 'PA-9b: other flags without UP (0xfa) are refused');
SELECT is(pg_temp.go('s_ad_short', 'struct', 1, jsonb_build_object('ad_hex', encode(substring(sha256(convert_to('partners.example.test', 'UTF8')) || '\x0500000001'::bytea, 1, 36), 'hex'))), 'bad_authenticator_data', 'PA-9b: authenticatorData one byte short of 37 is refused');
SELECT is(pg_temp.go('s_ad_empty', 'struct', 1, '{"ad_hex": ""}'), 'bad_authenticator_data', 'PA-9b: empty authenticatorData is refused');
SELECT is(pg_temp.go('s_ad_huge', 'struct', 1, jsonb_build_object('ad_hex', encode(sha256(convert_to('partners.example.test', 'UTF8')) || '\x0500000001'::bytea || decode(repeat('00', 4060), 'hex'), 'hex'))), 'bad_authenticator_data', 'PA-9b: authenticatorData over 4096 bytes is refused');
-- clientDataJSON that is not an acceptable JSON object
SELECT is(pg_temp.go('s_cd_junk', 'struct', 1, '{"client_raw": "{\"type\":"}'), 'bad_client_data', 'PA-9b: truncated JSON is refused');
SELECT is(pg_temp.go('s_cd_array', 'struct', 1, '{"client_raw": "[1]"}'), 'bad_client_data', 'PA-9b: a JSON array is refused');
SELECT is(pg_temp.go('s_cd_string', 'struct', 1, '{"client_raw": "\"webauthn.get\""}'), 'bad_client_data', 'PA-9b: a JSON string is refused');
SELECT is(pg_temp.go('s_cd_null', 'struct', 1, '{"client_raw": "null"}'), 'bad_client_data', 'PA-9b: JSON null is refused');
SELECT is(pg_temp.go('s_cd_empty', 'struct', 1, '{"client_raw": ""}'), 'bad_client_data', 'PA-9b: empty clientDataJSON is refused');
SELECT is(pg_temp.go('s_cd_utf8', 'struct', 1, '{"client_raw_hex": "7b2274797065223a22ff227d"}'), 'bad_client_data', 'PA-9b: invalid UTF-8 is refused (a status, not an error)');
SELECT is(pg_temp.go('s_cd_big', 'struct', 1, jsonb_build_object('client_raw', '{"x":"' || repeat('a', 4100) || '"}')), 'bad_client_data', 'PA-9b: clientDataJSON over 4096 bytes is refused');
SELECT is(pg_temp.go('s_cd_obj', 'struct', 1, '{"client_raw": "{}"}'), 'bad_client_type', 'PA-9b: an empty object parses and is refused on its missing type');
SELECT is(pg_temp.side('struct'), '{"sessions": 0, "counter": 0, "nonces": 0, "alarms": 0, "audits": 0}'::jsonb, 'PA-9b: 46 structural refusals left no session, no nonce, no alarm, no audit row and the counter untouched');
-- the controls: the same credential mints with an unmodified assertion and with the harmless variations
SELECT is(pg_temp.go('s_ctl_1', 'struct', 1), 'ok', 'PA-9b control: the unmodified assertion mints');
SELECT is(pg_temp.go('s_ctl_cross_absent', 'struct', 2, '{"client_drop": ["crossOrigin"]}'), 'ok', 'PA-9b control: an ABSENT crossOrigin is accepted (older browsers omit it)');
SELECT is(pg_temp.go('s_ctl_flags_be_bs', 'struct', 3, '{"flags": 29}'), 'ok', 'PA-9b control: backup-eligible and backed-up flags (0x08 | 0x10) do not matter');
SELECT is(pg_temp.go('s_ctl_extra_keys', 'struct', 4, '{"client": {"androidPackageName": "x", "other_keys_can_be_added_here": "do not compare clientDataJSON directly with a template"}}'), 'ok', 'PA-9b control: extra clientDataJSON members are accepted (the spec says to expect them)');
SELECT is(pg_temp.go('s_ctl_ad_extension', 'struct', 5, jsonb_build_object('ad_hex', encode(sha256(convert_to('partners.example.test', 'UTF8')) || '\x8500000005'::bytea || decode('a16b6372656450726f7465637401', 'hex'), 'hex'))), 'ok', 'PA-9b control: authenticatorData with extension data after the counter (the ED flag) is accepted');
SELECT is((SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'struct'), 5::bigint, 'PA-9b control: the five accepted mints advanced the counter 1 to 5');

-- ----------------------------------------------------------------------------
-- 8. PA-9: the counter never decreases except 0 -> 0 (compare-and-set); a regression is an alarm that commits with the refusal
-- ----------------------------------------------------------------------------
-- the alarm rows are bucketed by the CLOCK MINUTE: the cells below that count them must not straddle a minute boundary, so wait it out when fewer than 12 seconds of the minute are left
SELECT pg_sleep(CASE WHEN extract(second FROM clock_timestamp()) > 48 THEN 61 - extract(second FROM clock_timestamp()) ELSE 0 END);
SELECT pg_temp.newcred('cnt') IS NOT NULL AS cnt_cred \gset
SELECT is(pg_temp.go('c0a', 'cnt', 0), 'ok', 'PA-9: 0 against a stored 0 is accepted (a synced passkey never counts) ...');
SELECT is(pg_temp.go('c0b', 'cnt', 0), 'ok', 'PA-9: ... every time');
SELECT is((SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'cnt'), 0::bigint, 'PA-9: and the stored counter stays 0');
SELECT is((SELECT last_used_at IS NOT NULL FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'cnt'), true, 'PA-9: while last_used_at records the use');
SELECT is(pg_temp.go('c5', 'cnt', 5), 'ok', 'PA-9: a higher counter is accepted (5 against 0)');
SELECT is(pg_temp.go('c5_again', 'cnt', 5), 'counter_regression', 'PA-9: the SAME counter again (5 against 5) is refused (equal: a replay of the last value, a clone indicator)');
SELECT is((SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'cnt'), 5::bigint, 'PA-9: a refused regression leaves the counter at 5');
SELECT is((pg_temp.side('cnt') ->> 'alarms')::int || ':' || (pg_temp.side('cnt') ->> 'audits')::int, '1:1', 'PA-9: the regression wrote ONE alarm row and ONE audit row');
SELECT is(pg_temp.go('c4', 'cnt', 4), 'counter_regression', 'PA-9: a LOWER counter (4 against 5) is refused');
SELECT is((pg_temp.side('cnt') ->> 'alarms')::int || ':' || (pg_temp.side('cnt') ->> 'audits')::int, '1:1', 'PA-9: a second regression in the same minute adds nothing (one alarm per credential, kind and minute: a flood cannot grow the tables)');
SELECT is(pg_temp.go('c0_after5', 'cnt', 0), 'counter_regression', 'PA-9: 0 against a stored 5 is a regression (the 0 -> 0 exception is for a stored 0 only)');
SELECT is((SELECT (a.kind = 'counter_regression' AND a.detail ->> 'stage' = 'mint' AND (a.detail ->> 'presented')::bigint IN (5, 4, 0)) FROM app.partner_auth_alarm a JOIN creds c ON c.cred_row = a.credential_id WHERE c.label = 'cnt'), true,
  'PA-9: the alarm row names the kind, the stage and the presented counter');
SELECT is((SELECT (l.actor_user_id IS NULL AND l.subject_table = 'app.partner_credential' AND l.action = 'partner.mint.counter_regression') FROM app.audit_log l JOIN creds c ON c.cred_row::text = l.subject_id WHERE c.label = 'cnt' AND l.action LIKE 'partner.mint.%'), true,
  'PA-9: the audit row has no actor (nobody is bound), names app.partner_credential and the credential id, and the action partner.mint.counter_regression');
SELECT is((pg_temp.side('cnt') ->> 'sessions')::int, 3, 'PA-9: only the three accepted mints made sessions');
SELECT is(pg_temp.present('c5_replay', 'c5_again'), 'replayed', 'PA-9: the nonce of a regression IS spent (documented: a refused counter burns that challenge; a fresh one is cheap)');
SELECT is(pg_temp.go('c6', 'cnt', 6), 'ok', 'PA-9: the legitimate authenticator carries on after the regressions (6 against 5)');
-- the byte weights of the counter (big-endian), by strictly increasing values that differ in exactly one byte position
SELECT is(pg_temp.go('c255', 'cnt', 255), 'ok', 'PA-9: 255');
SELECT is(pg_temp.go('c256', 'cnt', 256), 'ok', 'PA-9: 256 (0x00000100) is above 255: the second byte weighs 256');
SELECT is(pg_temp.go('c65535', 'cnt', 65535), 'ok', 'PA-9: 65535');
SELECT is(pg_temp.go('c65536', 'cnt', 65536), 'ok', 'PA-9: 65536 (0x00010000): the third byte weighs 65536');
SELECT is(pg_temp.go('c16777215', 'cnt', 16777215), 'ok', 'PA-9: 16777215');
SELECT is(pg_temp.go('c16777216', 'cnt', 16777216), 'ok', 'PA-9: 16777216 (0x01000000): the first byte weighs 2^24');
SELECT is(pg_temp.go('c_max', 'cnt', 4294967295), 'ok', 'PA-9: 4294967295 (0xffffffff), the largest counter, is accepted');
SELECT is((SELECT sign_count FROM app.partner_credential pc JOIN creds c ON c.cred_row = pc.id WHERE c.label = 'cnt'), 4294967295::bigint, 'PA-9: stored as 4294967295 (a bigint column: no overflow)');
SELECT is(pg_temp.go('c_max_again', 'cnt', 4294967295), 'counter_regression', 'PA-9: and nothing is above it: the same value again is a regression');
-- direct writes: the counter can neither be lowered by the issuer nor by anything else
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; UPDATE app.partner_credential SET sign_count = 1 WHERE credential_id IN (SELECT cred_id FROM pg_temp.creds WHERE label = 'cnt')$$, '23514', NULL, 'PA-9: the issuer cannot LOWER sign_count even directly (partner_credential_guard)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; UPDATE app.partner_credential SET revoked_at = NULL, user_id = user_id WHERE id IS NOT NULL$$, '42501', NULL, 'the issuer''s UPDATE is column-level: it holds no privilege on user_id or revoked_at');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; UPDATE app.partner_credential SET public_key = '\x00' WHERE id IS NOT NULL$$, '42501', NULL, 'nor on public_key: the key a session is verified against cannot be rewritten by the mint''s owner');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 9. The signature check is LAST, and a failure is an ALARM that commits with the refusal
-- ----------------------------------------------------------------------------
-- the alarm rows are bucketed by the CLOCK MINUTE: the cells below that count them must not straddle a minute boundary, so wait it out when fewer than 12 seconds of the minute are left
SELECT pg_sleep(CASE WHEN extract(second FROM clock_timestamp()) > 48 THEN 61 - extract(second FROM clock_timestamp()) ELSE 0 END);
SELECT pg_temp.newcred('sig') IS NOT NULL AS sig_cred \gset
SELECT is(pg_temp.go('sig_bad', 'sig', 1, '{"sig_tamper": true}'), 'signature_invalid', 'a tampered signature is refused as signature_invalid (the Edge passed it first: an alarm)');
SELECT is(pg_temp.side('sig'), '{"sessions": 0, "counter": 0, "nonces": 0, "alarms": 1, "audits": 1}'::jsonb, 'ONE alarm row and ONE audit row, no session, no spent nonce, the counter untouched');
SELECT is((SELECT (a.kind = 'signature_invalid' AND a.detail ->> 'stage' = 'mint' AND (a.detail ->> 'alg')::int = -7) FROM app.partner_auth_alarm a JOIN creds c ON c.cred_row = a.credential_id WHERE c.label = 'sig'), true, 'the alarm names the kind, the stage and the algorithm');
SELECT is((SELECT (l.actor_user_id IS NULL AND l.action = 'partner.mint.signature_invalid' AND l.subject_table = 'app.partner_credential') FROM app.audit_log l JOIN creds c ON c.cred_row::text = l.subject_id WHERE c.label = 'sig' AND l.action LIKE 'partner.mint.%'), true, 'the audit row: no actor, partner.mint.signature_invalid, app.partner_credential');
-- a failed verification does NOT burn the challenge (5.1): the same challenge, with a good signature, still mints
SELECT is(pg_temp.go('sig_retry', 'sig', 1, (SELECT jsonb_build_object('nonce_hex', encode(nonce, 'hex'), 'mac_hex', encode(mac, 'hex'), 'exp_abs', exp) FROM asr WHERE label = 'sig_bad')), 'ok', 'a failed verification does not burn the challenge: it can be presented again within its 120 s with a real signature');
SELECT is(pg_temp.go('sig_bad2', 'sig', 2, '{"sig_tamper": true}'), 'signature_invalid', 'a second bad signature is refused the same way');
SELECT is((pg_temp.side('sig') ->> 'alarms')::int || ':' || (pg_temp.side('sig') ->> 'audits')::int, '1:1', 'and, within the same minute, adds no second alarm or audit row (bounded)');
-- the dedupe granularity is the CLOCK MINUTE: the bucket is floor(epoch / 60) of the alarm's own instant (not an hour, not a second) ...
SELECT is((SELECT (a.minute_bucket = pg_catalog.floor(extract(epoch FROM clock_timestamp()) / 60)::bigint) FROM app.partner_auth_alarm a JOIN creds c ON c.cred_row = a.credential_id WHERE c.label = 'sig' AND a.kind = 'signature_invalid'), true,
  'the alarm''s bucket is the current clock minute (floor(epoch / 60); the cells above ran inside one minute), so one alarm per credential, kind and MINUTE');
-- ... and an alarm of ANOTHER minute neither suppresses nor is suppressed by it: with a row already present for the previous minute, the next refusal still writes its own row
INSERT INTO app.partner_auth_alarm (kind, credential_id, minute_bucket) SELECT 'counter_regression', c.cred_row, pg_catalog.floor(extract(epoch FROM clock_timestamp()) / 60)::bigint - 1 FROM creds c WHERE c.label = 'sig';
SELECT is(pg_temp.go('sig_cnt', 'sig', 1), 'counter_regression', 'setup: a counter regression on the same credential (counter 1 is not above the stored 1)');
SELECT is((SELECT count(*)::int FROM app.partner_auth_alarm a JOIN creds c ON c.cred_row = a.credential_id WHERE c.label = 'sig' AND a.kind = 'counter_regression'), 2, 'a counter_regression row of the PREVIOUS minute does not suppress this minute''s: two rows, two minutes');
SELECT pg_temp.newcred('sig2') IS NOT NULL AS sig2_cred \gset
SELECT is(pg_temp.go('sig2_bad', 'sig2', 1, '{"sig_tamper": true}'), 'signature_invalid', 'another credential''s bad signature is refused ...');
SELECT is((pg_temp.side('sig2') ->> 'alarms')::int || ':' || (pg_temp.side('sig2') ->> 'audits')::int, '1:1', '... and has an alarm of its own (the key of the dedupe is the credential)');
SELECT is(pg_temp.go('sig_garbage', 'sig2', 2, '{"sig_hex": "30060201010201"}'), 'signature_invalid', 'a malformed signature (truncated DER) is signature_invalid too');
SELECT is(pg_temp.go('sig_empty', 'sig2', 2, '{"sig_hex": ""}'), 'signature_invalid', 'an empty signature is signature_invalid');
SELECT is(pg_temp.go('sig_zero_rs', 'sig2', 2, '{"sig_hex": "3006020100020100"}'), 'signature_invalid', 'r = s = 0 is signature_invalid');
SELECT is(pg_temp.go('sig_other_msg', 'sig2', 2, jsonb_build_object('sig_hex', '30440220' || repeat('10', 32) || '0220' || repeat('20', 32))), 'signature_invalid', 'an arbitrary well-formed signature is signature_invalid');
-- a corrupt stored key and an algorithm that does not match the stored key are the same alarm (a corrupt row is an incident)
SELECT pg_temp.newcred('badkey') IS NOT NULL AS bk_cred \gset
UPDATE creds SET d = d WHERE label = 'badkey';
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_guard_trg;
UPDATE app.partner_credential SET public_key = decode(repeat('01', 77), 'hex') WHERE id = (SELECT cred_row FROM creds WHERE label = 'badkey');
ALTER TABLE app.partner_credential ENABLE TRIGGER partner_credential_guard_trg;
SELECT is(pg_temp.go('bk', 'badkey', 1), 'signature_invalid', 'a stored key that does not parse is signature_invalid (an alarm), never an error');
SELECT pg_temp.newcred('algmis') IS NOT NULL AS am_cred \gset
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_guard_trg;
UPDATE app.partner_credential SET alg = -257 WHERE id = (SELECT cred_row FROM creds WHERE label = 'algmis');
ALTER TABLE app.partner_credential ENABLE TRIGGER partner_credential_guard_trg;
SELECT is(pg_temp.go('am', 'algmis', 1), 'signature_invalid', 'a credential whose alg column (-257) is not the algorithm of its stored key (ES256) is signature_invalid');
-- the alarm is a STATUS, not an exception: nothing raised, so nothing rolls back (the real commit is proved in tools/db/test-partner-serialisation.sh)
SELECT lives_ok($$SELECT pg_temp.go('sig3_bad', 'sig2', 3, '{"sig_tamper": true}')$$, 'a bad signature RETURNS a status (no exception: the alarm rows are written by the same transaction that returns it)');

-- ----------------------------------------------------------------------------
-- 10. Atomicity, the relying-party row, argument validation
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('atom') IS NOT NULL AS atom_cred \gset
-- a failure AFTER the nonce insert and the counter update (here: the session's token hash is taken) rolls ALL of it back
SELECT throws_ok($$SELECT pg_temp.go_dup('atom_dup', 'atom', 1, (SELECT token FROM pg_temp.asr WHERE label = 'ok1'))$$, '23505', NULL, 'the mint is ONE transaction: a session whose token hash already exists fails as a whole (23505)');
SELECT is(pg_temp.side('atom'), '{"sessions": 0, "counter": 0, "nonces": 0, "alarms": 0, "audits": 0}'::jsonb, 'atomic: the failed mint left no nonce, no counter move, no session (the nonce and the counter roll back with the session)');
-- the relying-party row
DELETE FROM app.partner_rp_config;
SELECT throws_ok($$SELECT pg_temp.go('rp_none', 'atom', 1)$$, '55000', 'partner_session_mint: app.partner_rp_config holds no relying party (a deploy step)', 'the mint refuses (55000) while no relying party is configured');
INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');
SELECT is(pg_temp.go('atom_ok', 'atom', 1), 'ok', 'with the relying party back, the same credential mints (nothing of the failed attempts remains)');
-- argument validation: malformed arguments raise 22023 and write nothing
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(NULL, decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a NULL token hash raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(upper(repeat('a', 64)), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'an upper-case token hash raises 22023 (64 LOWER-case hex only)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 63), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a 63-character token hash raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 15), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a 15-byte credential id raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 31), 'hex'), 1, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a 31-byte nonce raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), NULL, '\x00', '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a NULL expiry raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, decode(repeat('00', 129), 'hex'), '\x00', '\x7b7d', '\x00')$$, '22023', NULL, 'a MAC over 128 bytes raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', NULL, '\x7b7d', '\x00')$$, '22023', NULL, 'NULL authenticator data raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', NULL, '\x00')$$, '22023', NULL, 'NULL client data raises 22023');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_session_mint(repeat('a', 64), decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 1, '\x00', '\x00', '\x7b7d', NULL)$$, '22023', NULL, 'a NULL signature raises 22023');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 11. Posture of the new objects: the alarm table, the policies, the registries
-- ----------------------------------------------------------------------------
SELECT is((SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.partner_auth_alarm'::regclass), true, 'app.partner_auth_alarm has ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'), ('partner_session_issuer')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.partner_auth_alarm'::regclass, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.partner_auth_alarm'::regclass, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'no client role, no edge role, not service_role and not even the issuer holds any privilege on the alarm table (it is written by a definer only)');
SELECT is((SELECT count(*)::int FROM pg_attribute a WHERE a.attrelid = 'app.partner_auth_alarm'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.attname ~* 'user|email|account'), 0, 'the alarm table holds no user id (it is not a personal table)');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'app.partner_auth_alarm'::regclass AND k.contype = 'f'), 0, 'and no foreign key (it names a credential by id and survives the credential''s deletion)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'app.partner_auth_alarm'::regclass AND p.polname LIKE 'zz26%'), 1, 'setup: the only other policy on the alarm table is this file''s own temporary one');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'app.partner_auth_alarm'::regclass AND p.polroles = ARRAY['private_definer'::regrole::oid]
             AND coalesce(pg_get_expr(p.polqual, p.polrelid), '') || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') LIKE '%partner_binding_kind() AS partner_binding_kind) IS NULL%'
             AND coalesce(pg_get_expr(p.polqual, p.polrelid), '') || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') NOT LIKE '%current_setting%'), 2,
  'both private_definer policies on the alarm table admit the write only when NO binding exists, and read no setting (the HARD RULE: nothing settable keys an edge-reachable policy)');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_partner_auth_alarm_insert', 'pd_partner_auth_alarm_select', 'psi_update_partner_credential', 'psi_read_partner_rp_config',
                                                                                               'psi_insert_partner_auth_challenge', 'psi_read_partner_auth_challenge')
             AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)), 6, 'all six new policies are registered in private.definer_policy_allowlist with their live expressions');
SELECT is((SELECT array_agg(role_name ORDER BY policy_name) FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_partner_auth_alarm_insert', 'pd_partner_auth_alarm_select', 'psi_update_partner_credential', 'psi_read_partner_rp_config',
                                                                                                                         'psi_insert_partner_auth_challenge', 'psi_read_partner_auth_challenge')),
          ARRAY['private_definer', 'private_definer', 'partner_session_issuer', 'partner_session_issuer', 'partner_session_issuer', 'partner_session_issuer'], 'and each names the role it is for');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name LIKE 'partner\_sig\_%' OR function_name IN ('partner_cbor_head', 'partner_cose_parse', 'partner_challenge_core', 'partner_challenge_issue_sign_in', 'partner_challenge_verify',
                                                                                                                              'partner_mint_alarm_write', 'partner_session_mint')), 29, 'every function of 0048 has a function_inventory row (27, plus the two 8-argument overloads 0054 adds of partner_challenge_core / _verify)');
SELECT is((SELECT count(*)::int FROM private.partner_owner_privilege WHERE role_name = 'partner_session_issuer' AND (object_name LIKE '%partner_credential' AND column_name IN ('public_key', 'alg', 'sign_count', 'last_used_at'))), 5, 'the issuer''s new column privileges on partner_credential are in the owner-privilege registry');
SELECT is((SELECT array_agg(o.privilege || ':' || o.object_name ORDER BY o.object_name) FROM private.partner_owner_privilege o WHERE o.role_name = 'partner_session_issuer' AND o.object_kind = 'function'
             AND o.object_name IN ('private.partner_binding_kind()', 'private.partner_challenge_verify(smallint,bigint,bytea,uuid,bytea)', 'private.partner_mint_alarm_write(text,uuid,jsonb)', 'private.partner_session_policy(uuid)', 'private.partner_sig_verify(smallint,bytea,bytea,bytea)')),
          ARRAY['EXECUTE:private.partner_binding_kind()', 'EXECUTE:private.partner_challenge_verify(smallint,bigint,bytea,uuid,bytea)', 'EXECUTE:private.partner_mint_alarm_write(text,uuid,jsonb)', 'EXECUTE:private.partner_session_policy(uuid)', 'EXECUTE:private.partner_sig_verify(smallint,bytea,bytea,bytea)'],
          'and the issuer''s function privileges of 0048 are still exactly those five (0054 adds its own, listed in matrix 32)');
SELECT tests.clear_actor();
-- the alarm writer is refused under any binding (a partner- or user-bound definer cannot use it as a noise lever)
SAVEPOINT sp_alarm;
SELECT lives_ok($$SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$, 'setup: bind a user');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; SELECT private.partner_mint_alarm_write('signature_invalid', gen_random_uuid(), '{}'::jsonb)$$, '42501', NULL, 'the alarm writer''s INSERT policy refuses while ANY binding exists in the transaction (42501)');
RESET ROLE;
ROLLBACK TO sp_alarm;
SELECT lives_ok($$SET LOCAL ROLE partner_session_issuer; SELECT private.partner_mint_alarm_write('signature_invalid', gen_random_uuid(), '{}'::jsonb)$$, 'and, with no binding, the same call writes the alarm (control)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; SELECT private.partner_mint_alarm_write('anything_else', gen_random_uuid(), '{}'::jsonb)$$, '22023', NULL, 'the alarm writer takes only its two kinds');
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; SELECT private.partner_mint_alarm_write('signature_invalid', NULL, '{}'::jsonb)$$, '22023', NULL, 'the alarm writer refuses a NULL credential with the argument error (22023), not a NOT NULL violation from the table');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_issuer; INSERT INTO app.partner_auth_alarm (kind, credential_id, minute_bucket) VALUES ('signature_invalid', gen_random_uuid(), 1)$$, '42501', NULL, 'the issuer cannot insert alarm rows itself (no privilege): only through the writer');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 12. The cost of a mint in THIS harness (the S0 criterion for the verifier is 200 ms; a whole mint adds a few row operations)
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('timing') IS NOT NULL AS timing_cred \gset
CREATE TEMP TABLE mint_timing (ms double precision);
DO $t$
DECLARE
  i int;
  t0 timestamptz;
  s text;
BEGIN
  FOR i IN 1 .. 12 LOOP
    t0 := clock_timestamp();
    s := pg_temp.go('timing_' || i, 'timing', i);
    INSERT INTO mint_timing VALUES (extract(epoch FROM clock_timestamp() - t0) * 1000);
  END LOOP;
END
$t$;
SELECT diag(format('a whole mint in this harness, including building the assertion in SQL (12 calls): median %s ms, max %s ms',
  (SELECT round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms)::numeric, 1) FROM mint_timing), (SELECT round(max(ms)::numeric, 1) FROM mint_timing)));
SELECT is((SELECT count(*)::int FROM mres WHERE label LIKE 'timing\_%' AND o_status = 'ok'), 12, 'twelve consecutive mints for one credential all succeed');

SELECT * FROM finish();
ROLLBACK;
