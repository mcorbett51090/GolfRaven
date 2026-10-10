-- 33_course_qr_staff.sql
-- P5.1a S2b (0055): THE STAFF LANE OF THE COURSE QR, from docs/security/partner-auth-design.md section 12.1 "S2a/S2b" (AT(19): `staff@X` cannot mint a token or read the PIN for Y; the token refresh route does
-- not extend idle, PA-26) and the as-built S2a notes (the formats S2b mints, `private.course_pin_derive`, the epoch trigger). What is proved here, at the database layer:
--   * "Show today's PIN" (A0) calls private.course_pin_derive and nothing else derives: it equals an INDEPENDENT in-test HMAC implementation and the PIN the PLAYER lane (course_pin_attempt_for_actor) judges a scan made now
--     under; a staff member of another facility, an operator and a person with no binding are refused.
--   * "Rotate PIN" (A2) raises facility_programme.pin_epoch and writes nothing else (the 0046 trigger writes the epoch log); the old PIN still verifies for a scan whose instant is BEFORE the rotation.
--   * "Marker sold" (A1) CONSUMES the single-use PIN grant, INSERTs exactly the course_qr_token row the player lane consumes (issued_at truncated to the second, expires_at = +120 s), releases the Vault key only along
--     with that row, and a rolled-back mint gives the PIN grant back. A missing, malformed, unregistered or revoked key is 55000. A returned `no_programme` is a status.
--   * The refresh (A0_KEEPALIVE) is bound to the staff member's OWN mint, creates nothing, and DOES NOT advance last_seen_at (PA-26): with a control (an A0 call moves it) and an idle-expired session cannot use it.
--   * qr-print (A3: aal 2 and a fresh TOTP window; operator or admin) ensures the PUBLIC key row, writes facility_qr, replaces on a reprint and refuses a kid that is not the Vault key's.
--   * The ten policies are keyed on the partner binding (inert under a USER binding and with nothing bound), no edge role holds a privilege on the three tables, the key reader is executable by nobody, the private
--     key appears in no table and no audit row.
-- WHAT A pgTAP FILE CANNOT SHOW, AND WHERE IT IS SHOWN: that the Ed25519 signature a token carries verifies in the player lane's format.ts, and that a refused mint rolls back through the REAL privileged.ts
-- (supabase/tests/unit/course-qr-handler.test.ts, supabase/tests/integration/course-qr.deno.test.ts).
--
-- HOW THIS FILE RUNS: one transaction, rolled back. The partner tables are FORCE RLS with no policy for the harness role, so fixtures go through temporary CURRENT_USER policies (the 0016 / 0045 / 28 pattern). Every
-- scenario that needs a binding runs inside a SAVEPOINT that is rolled back (a second bind in one transaction is itself refused).
-- Principals are helpers.sql's: staff_x (a1: staff at fac_x), staff_y (a3: staff at fac_y), manager_x (b1), operator_t (c1: operator of trl_t, which fac_x is on), admin (d0).

\set QUIET 1
BEGIN;
SELECT plan(197);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.course_qr_key, app.course_qr_token, app.facility_qr, app.facility_programme, app.course_pin_epoch_log TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz33_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz33_key ON app.course_qr_key FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_tok ON app.course_qr_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_fqr ON app.facility_qr FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_fp ON app.facility_programme FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz33_log ON app.course_pin_epoch_log FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s33:' || p_label) || md5('s33b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c33:' || p_label) || md5('c33b:' || p_label), 'hex'), decode(md5('k33:' || p_label) || md5('k33b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n33:' || p_label) || md5('n33b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
-- step-up state a session cannot be BORN with: the guard is off for the seeding only
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    reauth_until = CASE WHEN p_cols ? 'reauth_s' THEN clock_timestamp() + ((p_cols ->> 'reauth_s')::numeric * interval '1 second') ELSE s.reauth_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    last_seen_at = CASE WHEN p_cols ? 'seen_ago_s' THEN clock_timestamp() - ((p_cols ->> 'seen_ago_s')::numeric * interval '1 second') ELSE s.last_seen_at END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
-- one partner-lane call as edge_partner inside a binding the caller made; the first row as JSON
CREATE FUNCTION pg_temp.ap(p_sql text) RETURNS jsonb LANGUAGE plpgsql AS $f$
DECLARE r jsonb;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  EXECUTE 'SELECT to_jsonb(t) FROM (' || p_sql || ') t LIMIT 1' INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
-- one partner-lane call as edge_partner that is EXPECTED to be refused: 'SQLSTATE|message', or 'OK' when it did not raise
CREATE FUNCTION pg_temp.err(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    EXECUTE p_sql;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN SQLSTATE || '|' || SQLERRM;
  END;
  EXECUTE 'RESET ROLE';
  RETURN 'OK';
END
$f$;
-- the PIN an INDEPENDENT implementation derives (the migration's is private.course_pin_derive): LPAD((first 4 bytes of HMAC-SHA256(pepper, label 0x00 facility 0x00 date 0x00 epoch as 4 bytes big-endian) as uint32) mod 10000, 4)
CREATE FUNCTION pg_temp.pin(p_fac text, p_date date, p_epoch int) RETURNS text LANGUAGE sql AS $f$
  SELECT lpad((((get_byte(m, 0)::bigint << 24) + (get_byte(m, 1) << 16) + (get_byte(m, 2) << 8) + get_byte(m, 3)) % 10000)::text, 4, '0')
  FROM (SELECT public.hmac(convert_to('golfraven/course-pin/v1', 'UTF8') || '\x00'::bytea || convert_to(p_fac, 'UTF8') || '\x00'::bytea || convert_to(to_char(p_date, 'YYYY-MM-DD'), 'UTF8') || '\x00'::bytea
                           || decode(lpad(to_hex(p_epoch), 8, '0'), 'hex'),
                           convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'course_pin_pepper'), 'UTF8'), 'sha256') AS m) h
$f$;
CREATE FUNCTION pg_temp.ldate(p_fac text) RETURNS date LANGUAGE sql AS $f$ SELECT (clock_timestamp() AT TIME ZONE (SELECT tz FROM app.catalog_facility WHERE id = p_fac))::date $f$;

-- the Vault secrets and the registered public key of the rotating-token key (test-only constants; the REAL Ed25519 signing is proved in the Deno suite). The seed is 43 base64url characters.
INSERT INTO vault.secrets (name, secret) VALUES
  ('course_pin_pepper', repeat('p', 40)),
  ('course_qr_signing_key_rotating_token', 'kidrot1:' || repeat('R', 43)),
  ('course_qr_signing_key_printed_qr', 'kidprt1:' || repeat('P', 43));
INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('rotating_token', 'kidrot1', repeat('r', 43));

-- fixtures: a second trail and facility_programme row at fac_x (so "every row of the facility moves together" has a second row), a facility with no programme row, a facility whose programme is the rotating token only
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('trl_u33', 'trail', 'verified', 1), ('fac_n33', 'facility', 'verified', 1), ('fac_r33', 'facility', 'verified', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_u33', 'trail-u33', 'Trail U33', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
  ('fac_n33', 'facility-n33', 'Facility N33', 'US-TN', 'America/Chicago', 1), ('fac_r33', 'facility-r33', 'Facility R33', 'NZ', 'Pacific/Auckland', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.trail_programme (trail_id, status) VALUES ('trl_u33', 'live') ON CONFLICT (trail_id) DO NOTHING;
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES ('trl_u33', 'fac_x', 'accepted'), ('trl_t', 'fac_r33', 'accepted');
RESET ROLE;
-- fac_x takes BOTH variants (the PIN needs the printed QR enabled, the mint the rotating token); fac_r33 only the printed QR (static_pin) and is on the other side of the date line
UPDATE app.facility_programme SET qr_mode = 'both' WHERE facility_id = 'fac_x';
UPDATE app.facility_programme SET qr_mode = 'static_pin' WHERE facility_id = 'fac_r33';

SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('op1', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op1 \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('op1') AS th_op1, pg_temp.th('ad') AS th_ad \gset
SELECT repeat('a', 64) AS nh_a, repeat('b', 64) AS nh_b, repeat('c', 64) AS nh_c, repeat('d', 64) AS nh_d, repeat('e', 64) AS nh_e, repeat('f', 64) AS nh_f \gset
SELECT repeat('S', 86) AS sig_a, repeat('T', 86) AS sig_b, repeat('u', 43) AS pk_p \gset

-- ----------------------------------------------------------------------------
-- 1. Structure: who can execute and touch what, and nothing else
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.course_pin_show_for_partner(text)'::regprocedure, 'private.course_pin_rotate_for_partner(text)'::regprocedure, 'private.course_qr_mint_for_partner(text, text)'::regprocedure,
  'private.course_qr_refresh_for_partner(text, text)'::regprocedure, 'private.course_qr_print_key_for_partner(text)'::regprocedure, 'private.course_qr_print_write_for_partner(text, text, text, text)'::regprocedure,
  'private.course_qr_print_read_for_partner(text)'::regprocedure, 'private.course_qr_signing_key_read(text)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole), 8, 'the eight functions of 0055 are SECURITY DEFINER with search_path = '''', owned by private_definer');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'),
                                                           ('partner_pin_verifier'), ('partner_session_issuer'), ('partner_session_toucher')) r(n)
           CROSS JOIN (VALUES ('private.course_pin_show_for_partner(text)'), ('private.course_pin_rotate_for_partner(text)'), ('private.course_qr_mint_for_partner(text, text)'), ('private.course_qr_refresh_for_partner(text, text)'),
                              ('private.course_qr_print_key_for_partner(text)'), ('private.course_qr_print_write_for_partner(text, text, text, text)'), ('private.course_qr_print_read_for_partner(text)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')),
  ARRAY['edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner'], 'of every client, edge and owner role, ONLY edge_partner can execute any of the seven lane functions (seven grants, no other role)');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'),
                                            ('partner_pin_verifier'), ('partner_session_issuer'), ('partner_session_toucher'), ('partner_totp_verifier'), ('partner_reauth_verifier')) r(n)
           WHERE has_function_privilege(r.n, 'private.course_qr_signing_key_read(text)'::regprocedure, 'EXECUTE')), 0, 'the Vault signing-key reader: no client role, no edge role and no owner role can execute it (only its owner, from inside a wrapper)');
SELECT is((SELECT array_agg(a.grantee::regrole::text || ':' || a.privilege_type ORDER BY a.grantee::regrole::text) FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = 'private.course_qr_signing_key_read(text)'::regprocedure)) a), ARRAY['private_definer:EXECUTE'],
  'the key reader''s whole ACL is its owner: no PUBLIC entry, no other grantee');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'course\_%\_for\_partner' AND (strpos(p.prosrc, chr(36)) > 0 OR strpos(p.prosrc, chr(34)) > 0 OR strpos(p.prosrc, chr(92)) > 0)), 0,
  'check 14 (a0): no dollar sign, double quote or backslash in any course-QR *_for_partner body');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_qr_signing_key_read' AND p.proname <> 'course_qr_signing_key_read'),
  ARRAY['course_qr_mint_for_partner', 'course_qr_print_key_for_partner', 'course_qr_print_write_for_partner'], 'the Vault signing key is read by exactly three functions: the A1 mint and the two A3 qr-print definers');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_derive' AND p.proname NOT IN ('course_pin_derive', 'course_pin_matches')),
  ARRAY['course_pin_show_for_partner'], 'the staff PIN display calls private.course_pin_derive (the only derivation) and no function of this lane reimplements it (no HMAC in a body but the derivation core)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'course\_%\_for\_partner' AND p.prosrc ~* 'hmac|digest|sha256'), 0, 'no course-QR staff wrapper computes an HMAC or a digest itself');
SELECT is((SELECT count(*)::int FROM (VALUES ('edge_partner'), ('edge_partner_minter'), ('edge_actor'), ('edge_system'), ('edge_gateway'), ('anon'), ('authenticated')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.course_qr_token', 'INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.course_qr_token', 'DELETE,TRUNCATE')
              OR has_any_column_privilege(r.n, 'app.facility_qr', 'INSERT,UPDATE,REFERENCES') OR has_any_column_privilege(r.n, 'app.course_qr_key', 'INSERT,UPDATE,REFERENCES')), 0,
  'no client or edge role can WRITE the token, the printed-QR or the key table (every writer is a definer; service_role''s own 0009 DML on the first two predates this file and is the operator key, not an Edge path)');
SELECT is((SELECT count(*)::int FROM (VALUES ('edge_partner'), ('edge_partner_minter'), ('edge_actor'), ('edge_system'), ('edge_gateway'), ('anon'), ('authenticated')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.course_qr_token', 'SELECT') OR has_any_column_privilege(r.n, 'app.facility_qr', 'SELECT') OR has_any_column_privilege(r.n, 'app.course_qr_key', 'SELECT')), 0,
  'no edge role and no client role can READ them either (the signing key''s public row, the printed QR and the tokens are definer-only)');
SELECT is((SELECT array_agg(c.relname::text || ':' || (c.relrowsecurity AND c.relforcerowsecurity)::text ORDER BY c.relname) FROM pg_class c WHERE c.oid IN ('app.course_qr_key'::regclass, 'app.course_qr_token'::regclass, 'app.facility_qr'::regclass)),
  ARRAY['course_qr_key:true', 'course_qr_token:true', 'facility_qr:true'], 'the three tables keep ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT array_agg(c.col ORDER BY c.col) FROM (VALUES ('nonce_hash'), ('facility_id'), ('issued_by_staff'), ('kid'), ('issued_at'), ('expires_at'), ('used_by_user'), ('used_at')) c(col)
           WHERE has_column_privilege('private_definer', 'app.course_qr_token', c.col, 'INSERT')), ARRAY['expires_at', 'facility_id', 'issued_at', 'issued_by_staff', 'kid', 'nonce_hash'],
  'private_definer can INSERT the six issue columns of a token and NOT used_by_user / used_at (a token is born unused)');
SELECT is((SELECT array_agg(c.col ORDER BY c.col) FROM (VALUES ('nonce_hash'), ('facility_id'), ('issued_by_staff'), ('kid'), ('issued_at'), ('expires_at'), ('used_by_user'), ('used_at')) c(col)
           WHERE has_column_privilege('private_definer', 'app.course_qr_token', c.col, 'UPDATE')), ARRAY['used_at', 'used_by_user'], 'private_definer can still UPDATE only the two used_* columns of a token (0046): a minted token''s facts never change');
SELECT is((SELECT array_agg(c.col ORDER BY c.col) FROM (VALUES ('facility_id'), ('qr_kid'), ('sig'), ('printed_at'), ('revoked_at')) c(col) WHERE has_column_privilege('private_definer', 'app.facility_qr', c.col, 'UPDATE')),
  ARRAY['printed_at', 'qr_kid', 'revoked_at', 'sig'], 'private_definer can UPDATE the four reprint columns of facility_qr and not its key (facility_id)');
SELECT is((SELECT array_agg(c.col ORDER BY c.col) FROM (VALUES ('purpose'), ('kid'), ('public_key_b64url'), ('created_at'), ('revoked_at')) c(col) WHERE has_column_privilege('private_definer', 'app.course_qr_key', c.col, 'INSERT')),
  ARRAY['kid', 'public_key_b64url', 'purpose'], 'private_definer can INSERT a PUBLIC key row (purpose, kid, key) and can neither pre-revoke one nor UPDATE any column of one');
SELECT is((SELECT count(*)::int FROM (VALUES ('purpose'), ('kid'), ('public_key_b64url'), ('revoked_at')) c(col) WHERE has_column_privilege('private_definer', 'app.course_qr_key', c.col, 'UPDATE')), 0, '... no UPDATE on app.course_qr_key at all: a revoked key stays revoked');
SELECT is((SELECT array_agg(pol.polname::text || ':' || pol.polcmd::text ORDER BY pol.polname) FROM pg_policy pol WHERE pol.polrelid IN ('app.course_qr_key'::regclass, 'app.course_qr_token'::regclass, 'app.facility_qr'::regclass) AND pol.polname LIKE 'pd\_course\_qr\_staff\_%'),
  ARRAY['pd_course_qr_staff_facility_qr_insert:a', 'pd_course_qr_staff_facility_qr_read:r', 'pd_course_qr_staff_facility_qr_update:w', 'pd_course_qr_staff_key_insert:a', 'pd_course_qr_staff_key_read:r', 'pd_course_qr_staff_token_insert:a', 'pd_course_qr_staff_token_read:r'],
  'the three tables carry exactly the seven staff-lane policies (and nothing writes them but private_definer)');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd\_course\_qr\_staff\_%'
           AND (pol.polroles <> ARRAY['private_definer'::regrole::oid] OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') ~* 'current_setting|pg_settings|actor_uid' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') ~* 'current_setting|pg_settings|actor_uid'
                OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), pg_get_expr(pol.polwithcheck, pol.polrelid)) NOT LIKE '%partner_binding_kind()%')), 0,
  'the OR rule: every one of the ten policies is TO private_definer alone, reads no settable GUC and not actor_uid(), and is keyed on the partner BINDING (nothing can be planted)');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('course_qr_signing_key_read', 'course_pin_show_for_partner', 'course_pin_rotate_for_partner', 'course_qr_mint_for_partner', 'course_qr_refresh_for_partner',
  'course_qr_print_key_for_partner', 'course_qr_print_write_for_partner', 'course_qr_print_read_for_partner')), 8, 'registry: all 8 functions have a function_inventory row');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name LIKE 'course\_%\_for\_partner' AND expected_edge_partner AND NOT (expected_anon OR expected_authenticated OR expected_service_role OR expected_edge_actor OR expected_edge_system OR expected_edge_partner_minter)), 7,
  'registry: the seven lane functions are expected for edge_partner and nobody else');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_course\_qr\_staff\_%' AND role_name = 'private_definer' AND scoped), 10, 'registry: the ten policies are in definer_policy_allowlist');
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. check 14 (a) behavioural cells: every course-QR `_for_partner` definer raises 42501 with no binding and under a USER binding
-- ----------------------------------------------------------------------------
SELECT throws_ok($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_pin_show_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_pin_rotate_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', repeat('a', 64))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_qr_mint_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', repeat('a', 64))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_qr_refresh_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_qr_print_key_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', repeat('S', 86), repeat('u', 43))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_qr_print_write_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.course_qr_print_read_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): course_qr_print_read_for_partner with NO binding raises 42501');
SAVEPOINT user_bound;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
SELECT throws_ok($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): course_pin_show_for_partner refuses a USER binding (staff_x bound as a player)');
SELECT throws_ok($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', repeat('a', 64))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): course_qr_mint_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): course_pin_rotate_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', repeat('a', 64))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): course_qr_refresh_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): course_qr_print_key_for_partner refuses a USER binding');
SELECT throws_ok($$INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at) VALUES (repeat('9', 64), 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'kidrot1', date_trunc('second', now()), date_trunc('second', now()) + interval '120 seconds')$$,
  '42501', NULL, 'the policies are inert under a USER binding: private_definer cannot insert a token with the staff member bound as a player');
SELECT throws_ok($$INSERT INTO app.facility_qr (facility_id, qr_kid, sig) VALUES ('fac_x', 'kidprt1', repeat('S', 86))$$, '42501', NULL, '... nor a printed QR');
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'kidprt9', repeat('u', 43))$$, '42501', NULL, '... nor a public key');
RESET ROLE;
ROLLBACK TO SAVEPOINT user_bound;


-- ----------------------------------------------------------------------------
-- 3. Today's PIN (A0): staff@X reads the PIN of X and of nothing else; it is the PIN the player lane judges
-- ----------------------------------------------------------------------------
SELECT pg_temp.pin('fac_x', pg_temp.ldate('fac_x'), 0) AS pin_x0, pg_temp.pin('fac_x', pg_temp.ldate('fac_x'), 1) AS pin_x1 \gset
SAVEPOINT show_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$)::text AS shown \gset
SELECT is((:'shown'::jsonb ->> 'o_status'), 'ok', 'AT(19): staff_x reads today''s PIN of fac_x: ok');
SELECT is((:'shown'::jsonb ->> 'o_pin'), pg_temp.pin('fac_x', pg_temp.ldate('fac_x'), 0), 'the displayed PIN equals an INDEPENDENT in-test HMAC implementation (Vault pepper, facility, facility-local date, epoch 0)');
SELECT matches((:'shown'::jsonb ->> 'o_pin'), '^[0-9]{4}$', 'the PIN is four digits');
SELECT is((:'shown'::jsonb ->> 'o_local_date')::date, pg_temp.ldate('fac_x'), 'it is the facility-LOCAL date''s PIN');
SELECT is((:'shown'::jsonb ->> 'o_pin_epoch')::int, 0, 'under the epoch live now (0: never rotated)');
SELECT ok((:'shown'::jsonb ->> 'o_valid_until')::timestamptz > now() AND (:'shown'::jsonb ->> 'o_valid_until')::timestamptz <= now() + interval '25 hours', 'it is valid until the next facility-local midnight (within 25 h)');
SELECT is((SELECT count(*)::int FROM jsonb_object_keys(:'shown'::jsonb)), 5, 'the answer carries five fields: status, PIN, local date, valid-until and epoch; no key material');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_y')$$), '42501|partner_authorize: no scope', 'AT(19): staff_x CANNOT read the PIN of fac_y');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_nope')$$), '42501|partner_authorize: no scope', 'an unknown facility is a scope refusal for a member (it names nothing)');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner(NULL)$$), '22023|course_pin_show_for_partner: a facility is required', 'a NULL facility is not the "anywhere" branch of the seam: refused 22023 (and only after the role was checked)');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$), 'OK', 'the A0 read can be repeated (nothing is consumed)');
ROLLBACK TO SAVEPOINT show_a;
-- the same PIN, judged by the PLAYER lane: private.course_pin_attempt_for_actor, bound as a player, for a scan made now
SAVEPOINT show_player;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_x', :'pin_x0', now())), 'ok', 'THE STAFF SCREEN AND THE APP CANNOT DIFFER: the PIN staff_x was shown is accepted by the player lane''s gate for a scan made now');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_x', :'pin_x1', now())), 'wrong', 'control: the PIN of the NEXT epoch is a wrong guess for now (the gate is not a yes-machine)');
RESET ROLE;
ROLLBACK TO SAVEPOINT show_player;
-- scope: another facility's staff, a manager, an operator, an admin
SAVEPOINT show_y;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$), '42501|partner_authorize: no scope', 'AT(19): staff_y (staff at fac_y) CANNOT read the PIN of fac_x');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_y')$$) ->> 'o_status', 'no_programme', 'staff_y at its OWN facility passes the seam (fac_y has no programme, so there is no PIN: a status, not a leak)');
ROLLBACK TO SAVEPOINT show_y;
SAVEPOINT show_m;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_pin', :'shown'::jsonb ->> 'o_pin', 'a manager of fac_x sees the same PIN as staff');
ROLLBACK TO SAVEPOINT show_m;
SAVEPOINT show_op;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$), '42501|partner_authorize: no scope', 'an operator (aal 2, trail scope covering fac_x) does NOT read the shop PIN: staff and manager only');
ROLLBACK TO SAVEPOINT show_op;
SAVEPOINT show_ad;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_pin', :'shown'::jsonb ->> 'o_pin', 'an admin (audited, any facility) reads the same PIN');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_nope')$$) ->> 'o_status', 'no_facility', 'an admin asking for an unknown facility gets a status, no_facility');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_n33')$$) ->> 'o_status', 'no_programme', 'a facility with no programme row has no PIN: no_programme');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_r33')$$) ->> 'o_pin', pg_temp.pin('fac_r33', pg_temp.ldate('fac_r33'), 0), 'a facility on the far side of the date line: its PIN is the one for ITS local date (independent implementation)');
SELECT is((pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_r33')$$) ->> 'o_local_date')::date, pg_temp.ldate('fac_r33'), '... and the local date is the facility''s own, not UTC''s');
UPDATE app.facility_programme SET qr_mode = 'rotating' WHERE facility_id = 'fac_x';
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_status', 'no_programme', 'a facility whose programme takes only the rotating token has no PIN to show');
UPDATE app.facility_programme SET qr_mode = 'both', participation = 'invited' WHERE facility_id = 'fac_x';
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_status', 'no_programme', '... nor one whose rows are only invited (not accepted)');
ROLLBACK TO SAVEPOINT show_ad;
SAVEPOINT show_pepper;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
DELETE FROM vault.secrets WHERE name = 'course_pin_pepper';
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$), '55000|course_pin_derive: the course PIN pepper is not provisioned in Vault', 'a missing pepper is a deploy fault, 55000 (the Edge answers a bare 503), never a made-up PIN');
ROLLBACK TO SAVEPOINT show_pepper;

-- ----------------------------------------------------------------------------
-- 4. Rotate PIN (A2): pin_epoch + 1 and nothing else
-- ----------------------------------------------------------------------------
SELECT md5(string_agg(concat_ws('|', trail_id, facility_id, participation, stocks_markers, holds_special_marker, connectivity, staff_network, wifi_note, qr_mode), ';' ORDER BY trail_id)) AS fp_before FROM app.facility_programme WHERE facility_id = 'fac_x' \gset
SAVEPOINT rot_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a passkey assertion in the last 5 minutes is required', 'A2: with no passkey assertion in the last 5 minutes the rotation is refused');
SELECT pg_temp.seed_step('sx', '{"reauth_s": 200}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'A2: a fresh passkey but no PIN grant: refused');
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 20}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'A2: a PIN grant 40 s old (more than 30 s) is too old');
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_y')$$), '42501|partner_authorize: no scope', 'AT(19): staff_x CANNOT rotate the PIN of fac_y, even with a fresh PIN and passkey');
SELECT is((SELECT count(*)::int FROM app.facility_programme WHERE facility_id = 'fac_x' AND pin_epoch = 0), 2, '... and nothing moved');
SELECT pg_temp.ap($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$)::text AS rotated \gset
SELECT is((:'rotated'::jsonb ->> 'o_status'), 'ok', 'staff_x rotates the PIN of fac_x with a fresh passkey and a fresh PIN: ok');
SELECT is((:'rotated'::jsonb ->> 'o_pin_epoch')::int, 1, '... to epoch 1');
SELECT is((SELECT array_agg(pin_epoch ORDER BY trail_id) FROM app.facility_programme WHERE facility_id = 'fac_x'), ARRAY[1, 1], 'EVERY programme row of the facility moved together (two trails)');
SELECT is((SELECT array_agg(pin_epoch ORDER BY facility_id) FROM app.facility_programme WHERE facility_id IN ('fac_r33')), ARRAY[0], 'another facility''s rows did not move');
SELECT is((SELECT md5(string_agg(concat_ws('|', trail_id, facility_id, participation, stocks_markers, holds_special_marker, connectivity, staff_network, wifi_note, qr_mode), ';' ORDER BY trail_id)) FROM app.facility_programme WHERE facility_id = 'fac_x'), :'fp_before',
  'NOTHING but pin_epoch changed on the programme rows (participation, qr_mode and every other column are byte-identical)');
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x' AND pin_epoch = 1 AND previous_epoch = 0), 1, 'the 0046 TRIGGER logged the new epoch, once, for two rows');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'course_pin_rotate_for_partner' AND p.prosrc ~ 'course_pin_epoch_log'), 0, '... and the rotation definer never names the log table: it cannot have written it');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.course_pin.rotate' AND subject_id = 'fac_x' AND detail = '{"pin_epoch": 1}'::jsonb), 1, 'one audit_log row: the facility and the new epoch, no PIN');
SELECT is((SELECT pin_grant_until IS NULL AND reauth_until IS NOT NULL FROM app.partner_session WHERE token_hash = :'th_sx'), true, 'A2 CONSUMED the PIN grant (single use) and left the passkey window');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'one PIN, one rotation: a second rotation in the same transaction needs a second PIN');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_pin', pg_temp.pin('fac_x', pg_temp.ldate('fac_x'), 1), 'after the rotation the staff screen shows the epoch-1 PIN (independent implementation)');
SELECT isnt(pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$) ->> 'o_pin', :'shown'::jsonb ->> 'o_pin', 'and it is not the old one');
ROLLBACK TO SAVEPOINT rot_a;
-- the rotated PIN as the player lane judges it: the new epoch for now, the OLD epoch for a scan whose instant is before the rotation (a queued offline scan is not broken by a rotation)
SAVEPOINT rot_player;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT pg_temp.seed_step('mx', '{"reauth_s": 200, "pin_grant_s": 50}'::jsonb);
SELECT pg_temp.ap($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$)::text AS rotated_m \gset
SELECT is((:'rotated_m'::jsonb ->> 'o_status'), 'ok', 'a manager of fac_x rotates too');
ROLLBACK TO SAVEPOINT rot_player;
SAVEPOINT rot_player2;
UPDATE app.facility_programme SET pin_epoch = 1 WHERE facility_id = 'fac_x';
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_x', :'pin_x1', now())), 'ok', 'the player lane accepts the NEW epoch''s PIN for a scan made now');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_x', :'pin_x0', now())), 'wrong', 'the ROTATED-OUT PIN is a counted wrong guess for an instant at or after the rotation');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_x', :'pin_x0', now() - interval '1 second')), 'ok', 'but it is still RIGHT for a scan whose instant is before the rotation: a rotation does not break a queued scan');
RESET ROLE;
ROLLBACK TO SAVEPOINT rot_player2;
SAVEPOINT rot_y;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
RESET ROLE;
SELECT pg_temp.seed_step('sy', '{"reauth_s": 200, "pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: no scope', 'AT(19): staff_y CANNOT rotate the PIN of fac_x');
ROLLBACK TO SAVEPOINT rot_y;
SAVEPOINT rot_op;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a passkey assertion in the last 5 minutes is required', 'an operator needs the passkey window too');
SELECT pg_temp.seed_step('op', '{"reauth_s": 200}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$), '42501|partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', '... and, with no PIN and no fresh TOTP, is refused');
SELECT pg_temp.seed_step('op', '{"mfa_s": 200}'::jsonb);
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_rotate_for_partner('fac_x')$$) ->> 'o_status', 'ok', 'a PIN-less operator whose trail covers fac_x rotates under the A3 substitution (aal 2, TOTP in the last 5 minutes, passkey)');
ROLLBACK TO SAVEPOINT rot_op;
SAVEPOINT rot_ad;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT pg_temp.seed_step('ad', '{"reauth_s": 200, "mfa_s": 200}'::jsonb);
SELECT is(pg_temp.ap($$SELECT * FROM private.course_pin_rotate_for_partner('fac_n33')$$) ->> 'o_status', 'no_programme', 'a facility with no programme row: no_programme (an admin may ask)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.course_pin.rotate' AND subject_id = 'fac_n33'), 0, '... and a rotation that moved nothing writes no audit row');
SELECT is(pg_temp.err($$SELECT * FROM private.course_pin_rotate_for_partner(NULL)$$), '22023|course_pin_rotate_for_partner: a facility is required', 'a NULL facility is 22023');
ROLLBACK TO SAVEPOINT rot_ad;

-- ----------------------------------------------------------------------------
-- 5. "Marker sold" (A1): consumes the single-use PIN grant, writes the row the player lane consumes, releases the key only with it
-- ----------------------------------------------------------------------------
SAVEPOINT mint_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '42501|partner_authorize: a PIN verified in the last minute and not yet used is required', 'A1: with no PIN grant the mint is refused (and no key is released)');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 0, '... and no token row exists');
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a'))::text AS minted \gset
SELECT is((:'minted'::jsonb ->> 'o_status'), 'ok', 'with a fresh PIN grant staff_x mints a token at fac_x: ok');
SELECT is((:'minted'::jsonb ->> 'o_kid'), 'kidrot1', 'it carries the registered rotating-token kid');
SELECT is((:'minted'::jsonb ->> 'o_signing_key'), repeat('R', 43), 'the Vault signing key (the 43-character seed) is released WITH the token row, to this authorized call only');
SELECT is((:'minted'::jsonb ->> 'o_public_key'), repeat('r', 43), 'and the PUBLIC key of that kid, so the Edge can self-verify what it signs');
SELECT is((SELECT (t.issued_by_staff, t.facility_id, t.kid, t.used_by_user IS NULL, t.used_at IS NULL, t.expires_at - t.issued_at)::text FROM app.course_qr_token t WHERE t.nonce_hash = :'nh_a'),
  '(00000000-0000-0000-0000-1000000000a1,fac_x,kidrot1,t,t,00:02:00)', 'the token row: issued by staff_x, for fac_x, under kidrot1, UNUSED, expiring exactly 120 s after issue');
SELECT is((SELECT t.issued_at = date_trunc('second', t.issued_at) FROM app.course_qr_token t WHERE t.nonce_hash = :'nh_a'), true, 'issued_at is truncated to the SECOND: the row''s instant IS the token''s iat claim (the player lane judges the 120 s rule against the row)');
SELECT is((:'minted'::jsonb ->> 'o_issued_at')::bigint, (SELECT extract(epoch FROM t.issued_at)::bigint FROM app.course_qr_token t WHERE t.nonce_hash = :'nh_a'), 'the returned iat equals the row''s issued_at in whole seconds');
SELECT is((:'minted'::jsonb ->> 'o_expires_at')::bigint - (:'minted'::jsonb ->> 'o_issued_at')::bigint, 120::bigint, '... and exp = iat + 120');
SELECT ok((SELECT abs(extract(epoch FROM (clock_timestamp() - t.issued_at))) < 5 FROM app.course_qr_token t WHERE t.nonce_hash = :'nh_a'), 'the issue instant is the database''s clock, now');
SELECT is((SELECT pin_grant_until IS NULL FROM app.partner_session WHERE token_hash = :'th_sx'), true, 'A1 CONSUMED the single-use PIN grant');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_b')), '42501|partner_authorize: a PIN verified in the last minute and not yet used is required', 'one PIN, one token: the second mint needs a second PIN');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 1, '... and exactly one token row exists');
SELECT is((SELECT count(*)::int FROM app.course_qr_key WHERE public_key_b64url = repeat('R', 43)), 0, 'the PRIVATE key is in no key row');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE detail::text LIKE '%RRRRRRRR%' OR subject_id LIKE '%RRRRRRRR%'), 0, '... and in no audit row');
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '23505|duplicate key value violates unique constraint "course_qr_token_pkey"', 'the same nonce hash twice is the primary key''s 23505 (the Edge answers 409)');
ROLLBACK TO SAVEPOINT mint_a;
-- a rolled-back mint gives the PIN grant back: nothing is spent unless the whole transaction commits
SAVEPOINT mint_rb;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SAVEPOINT mint_rb_inner;
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a'))::text AS minted2 \gset
SELECT is((SELECT pin_grant_until IS NULL FROM app.partner_session WHERE token_hash = :'th_sx'), true, 'control: the mint consumed the grant inside the inner savepoint');
ROLLBACK TO SAVEPOINT mint_rb_inner;
SELECT is((SELECT pin_grant_until IS NOT NULL FROM app.partner_session WHERE token_hash = :'th_sx') AND (SELECT count(*)::int FROM app.course_qr_token) = 0, true, 'the transaction that rolls the mint back gets the PIN grant back and leaves no token (what the handler does with a returned no_programme)');
ROLLBACK TO SAVEPOINT mint_rb;
-- bad arguments (after A1: a failed mint rolls the consumption back)
SAVEPOINT mint_args;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', 'abc')$$), '22023|course_qr_mint_for_partner: the nonce hash is 64 lower-case hex characters', 'a short nonce hash is 22023');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, upper(:'nh_a'))), '22023|course_qr_mint_for_partner: the nonce hash is 64 lower-case hex characters', 'an upper-case nonce hash is 22023 (the player lane hashes to lower-case hex)');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, repeat('g', 64))), '22023|course_qr_mint_for_partner: the nonce hash is 64 lower-case hex characters', 'a non-hex nonce hash is 22023');
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', NULL)$$), '22023|course_qr_mint_for_partner: the nonce hash is 64 lower-case hex characters', 'a NULL nonce hash is 22023');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner(NULL, %L)$$, :'nh_a')), '22023|course_qr_mint_for_partner: a facility is required', 'a NULL facility is 22023');
ROLLBACK TO SAVEPOINT mint_args;
-- scope: AT(19) staff@X cannot mint for Y
SAVEPOINT mint_scope;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_y', %L)$$, :'nh_a')), '42501|partner_authorize: no scope', 'AT(19): staff_x CANNOT mint a token for fac_y');
SELECT is((SELECT pin_grant_until IS NOT NULL FROM app.partner_session WHERE token_hash = :'th_sx'), true, 'a scope refusal comes BEFORE the PIN grant is consumed (the seam checks scope first)');
ROLLBACK TO SAVEPOINT mint_scope;
SAVEPOINT mint_scope_y;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
RESET ROLE;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '42501|partner_authorize: no scope', 'AT(19): staff_y (fac_y) CANNOT mint a token for fac_x');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 0, '... and writes no row');
ROLLBACK TO SAVEPOINT mint_scope_y;
SAVEPOINT mint_op;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT pg_temp.seed_step('op', '{"mfa_s": 200}'::jsonb);
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '42501|partner_authorize: no scope', 'an operator does not sell markers: refused even with a fresh TOTP');
ROLLBACK TO SAVEPOINT mint_op;
SAVEPOINT mint_m;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50}'::jsonb);
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_c')) ->> 'o_status', 'ok', 'a manager of fac_x mints too');
SELECT is((SELECT issued_by_staff::text FROM app.course_qr_token WHERE nonce_hash = :'nh_c'), '00000000-0000-0000-0000-2000000000b1', '... and the row names the MANAGER as the issuer (the bound person, never an argument)');
ROLLBACK TO SAVEPOINT mint_m;
SAVEPOINT mint_ad;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 200}'::jsonb);
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_n33', %L)$$, :'nh_d')) ->> 'o_status', 'no_programme', 'a facility with no programme row cannot sell a marker: no_programme (a status, no token)');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 0, '... and no row');
UPDATE app.facility_programme SET qr_mode = 'static_pin' WHERE facility_id = 'fac_x';
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_d')) ->> 'o_status', 'no_programme', 'a facility whose programme takes only the printed QR cannot mint a rotating token');
ROLLBACK TO SAVEPOINT mint_ad;
-- the key: missing, malformed, unregistered, revoked
SAVEPOINT mint_key1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
DELETE FROM vault.secrets WHERE name = 'course_qr_signing_key_rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_signing_key_read: the course QR signing key is not provisioned in Vault', 'no Vault secret: 55000, a deploy fault (a bare 503 at the Edge), no token');
ROLLBACK TO SAVEPOINT mint_key1;
SAVEPOINT mint_key2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
UPDATE vault.secrets SET secret = 'kidrot1:short' WHERE name = 'course_qr_signing_key_rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_signing_key_read: the course QR signing key is not provisioned in Vault', 'a malformed secret (seed of the wrong length): 55000');
UPDATE vault.secrets SET secret = 'bad kid:' || repeat('R', 43) WHERE name = 'course_qr_signing_key_rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_signing_key_read: the course QR signing key is not provisioned in Vault', 'a malformed kid (a space): 55000');
UPDATE vault.secrets SET secret = repeat('R', 43) WHERE name = 'course_qr_signing_key_rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_signing_key_read: the course QR signing key is not provisioned in Vault', 'a secret with no kid (the bare seed): 55000');
ROLLBACK TO SAVEPOINT mint_key2;
SAVEPOINT mint_key3;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
DELETE FROM app.course_qr_key WHERE purpose = 'rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_mint_for_partner: no usable rotating-token key is registered', 'the Vault key''s PUBLIC row is not registered: no token is minted (no player could verify it)');
ROLLBACK TO SAVEPOINT mint_key3;
SAVEPOINT mint_key4;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
UPDATE app.course_qr_key SET revoked_at = now() WHERE purpose = 'rotating_token';
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a')), '55000|course_qr_mint_for_partner: no usable rotating-token key is registered', 'a REVOKED key mints nothing (a compromise revocation takes effect at once)');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 0, '... no row');
ROLLBACK TO SAVEPOINT mint_key4;
-- the key is released only with a token row: the printed-QR key is not a thing a mint can return, and the key reader is not callable from the lane
SAVEPOINT mint_key5;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_signing_key_read('rotating_token')$$), '42501|permission denied for function course_qr_signing_key_read', 'edge_partner cannot call the Vault key reader directly: the key leaves the database only inside an authorized A1 mint or A3 print');
SELECT is(pg_temp.err($$SELECT * FROM app.course_qr_token$$), '42501|permission denied for schema app', 'edge_partner holds no privilege on the token table (it has no USAGE on schema app at all)');
SELECT is(pg_temp.err($$SELECT * FROM app.course_qr_key$$), '42501|permission denied for schema app', '... nor on the key table');
SELECT is(pg_temp.err($$SELECT * FROM app.facility_qr$$), '42501|permission denied for schema app', '... nor on the printed-QR table');
SELECT is(pg_temp.err($$SELECT * FROM vault.decrypted_secrets$$), '42501|permission denied for schema vault', '... nor on Vault');
ROLLBACK TO SAVEPOINT mint_key5;

-- the row a mint writes is EXACTLY what the player lane consumes: capture it, roll the mint back, re-insert the same facts, scan it as a player (the S2a function), twice
SAVEPOINT mint_cap;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a'))::text AS _m \gset
SELECT nonce_hash AS m_nh, kid AS m_kid, issued_by_staff::text AS m_by, issued_at::text AS m_iat, expires_at::text AS m_exp FROM app.course_qr_token WHERE nonce_hash = :'nh_a' \gset
ROLLBACK TO SAVEPOINT mint_cap;
SAVEPOINT scan_a;
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at) VALUES (:'m_nh', 'fac_x', :'m_by'::uuid, :'m_kid', :'m_iat'::timestamptz, :'m_exp'::timestamptz);
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a');
SELECT is((SELECT array_agg(DISTINCT o_result) FROM private.marker_scan_for_actor('fac_x', 'rotating', :'m_nh', :'m_kid', NULL, now(), NULL, NULL, NULL)), ARRAY['accepted'], 'AT(19): the token row the staff lane wrote is ACCEPTED by the player lane''s scan (no fix: a pending purchase)');
SELECT is((SELECT array_agg(DISTINCT o_result) FROM private.marker_scan_for_actor('fac_x', 'rotating', :'m_nh', :'m_kid', NULL, now(), NULL, NULL, NULL)), ARRAY['qr_used'], 'AT(19): the same token again is qr_used (409): single use');
RESET ROLE;
ROLLBACK TO SAVEPOINT scan_a;

-- ----------------------------------------------------------------------------
-- 6. The refresh (A0_KEEPALIVE): bound to one's own mint, creates nothing, never advances last_seen_at (PA-26)
-- ----------------------------------------------------------------------------
SAVEPOINT ref_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_mint_for_partner('fac_x', %L)$$, :'nh_a'))::text AS minted3 \gset
SELECT is((pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')) ->> 'o_state'), 'live', 'refresh of the staff member''s own fresh token: live');
SELECT ok((pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')) ->> 'o_seconds_left')::int BETWEEN 115 AND 120, '... with the whole seconds left of the 120 s');
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 1, 'the refresh created NO token (it can create no authority)');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_b')) ->> 'o_state', 'unknown', 'a nonce no one minted: unknown');
-- the PIN grant is not touched by a refresh
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a'))::text AS _r1 \gset
SELECT is((SELECT pin_grant_until IS NOT NULL FROM app.partner_session WHERE token_hash = :'th_sx'), true, 'a refresh does NOT consume a PIN grant (it is class A0_KEEPALIVE, not A1)');
-- used and expired
UPDATE app.course_qr_token SET used_at = now(), used_by_user = '00000000-0000-0000-0000-00000000000a' WHERE nonce_hash = :'nh_a';
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')) ->> 'o_state', 'used', 'a token the player scanned: used (the sale screen can say so)');
ROLLBACK TO SAVEPOINT ref_a;
SAVEPOINT ref_b;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
  VALUES (:'nh_a', 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'kidrot1', date_trunc('second', now() - interval '200 seconds'), date_trunc('second', now() - interval '200 seconds') + interval '120 seconds'),
         (:'nh_b', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'kidrot1', date_trunc('second', now()), date_trunc('second', now()) + interval '120 seconds'),
         (:'nh_c', 'fac_y', '00000000-0000-0000-0000-1000000000a1', 'kidrot1', date_trunc('second', now()), date_trunc('second', now()) + interval '120 seconds');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')) ->> 'o_state', 'expired', 'a token more than 120 s old: expired');
SELECT is((pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')) ->> 'o_seconds_left')::int, 0, '... with no seconds left');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_b')) ->> 'o_state', 'unknown', 'ANOTHER person''s token (the manager''s): unknown, the same answer as a nonce that does not exist (no oracle)');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_c')) ->> 'o_state', 'unknown', 'one''s own nonce asked about at the WRONG facility: unknown');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_y', %L)$$, :'nh_c')), '42501|partner_authorize: no scope', 'AT(19): a staff member of fac_x cannot refresh against fac_y at all: refused by the seam');
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', 'zz')$$), '22023|course_qr_refresh_for_partner: the nonce hash is 64 lower-case hex characters', 'a malformed nonce hash is 22023');
ROLLBACK TO SAVEPOINT ref_b;
-- planted GUC: nothing a session can set makes another person's token visible
SAVEPOINT ref_guc;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
  VALUES (:'nh_b', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'kidrot1', date_trunc('second', now()), date_trunc('second', now()) + interval '120 seconds');
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-2000000000b1', true);
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_b')) ->> 'o_state', 'unknown', 'a planted delete_my_data GUC (the 0016 window) does not make the manager''s token visible to the refresh: the partner conjunct closes it');
ROLLBACK TO SAVEPOINT ref_guc;
-- PA-26: the refresh does not extend idle; an ordinary A0 call does (control); an idle-expired session cannot use the refresh to come back
SAVEPOINT ref_idle;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"seen_ago_s": 600}'::jsonb);
SELECT last_seen_at AS seen0 FROM app.partner_session WHERE token_hash = :'th_sx' \gset
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a'))::text AS _r2 \gset
SELECT pg_temp.ap(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a'))::text AS _r3 \gset
SELECT is((SELECT last_seen_at FROM app.partner_session WHERE token_hash = :'th_sx'), :'seen0'::timestamptz, 'PA-26: two refreshes on a session idle for 10 minutes do NOT advance last_seen_at (the 30 s heartbeat cannot defeat the idle timeout)');
SELECT pg_temp.ap($$SELECT * FROM private.course_pin_show_for_partner('fac_x')$$)::text AS _r4 \gset
SELECT ok((SELECT last_seen_at > :'seen0'::timestamptz FROM app.partner_session WHERE token_hash = :'th_sx'), 'PA-26 control: an ordinary A0 call (today''s PIN) DOES advance it, so the probe above can see a bump');
ROLLBACK TO SAVEPOINT ref_idle;
SAVEPOINT ref_idle2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.seed_step('sx', '{"seen_ago_s": 1900}'::jsonb);
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_refresh_for_partner('fac_x', %L)$$, :'nh_a')), '42501|partner_authorize: the session is not live', 'PA-26: a session idle past 30 minutes is dead: the refresh cannot revive it (the same refusal as any call)');
ROLLBACK TO SAVEPOINT ref_idle2;

-- ----------------------------------------------------------------------------
-- 7. qr-print (A3): operator or admin at an aal 2 session with a fresh TOTP; the public key row; facility_qr
-- ----------------------------------------------------------------------------
SAVEPOINT pr_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$), '42501|partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required', 'A3: an aal 2 operator with no TOTP in the last 5 minutes cannot even fetch the printing key');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p')), '42501|partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required', '... nor register a QR');
SELECT pg_temp.seed_step('op', '{"mfa_s": 200}'::jsonb);
SELECT pg_temp.ap($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$)::text AS pkey \gset
SELECT is((:'pkey'::jsonb ->> 'o_status'), 'ok', 'a fresh TOTP: the operator of the trail that fac_x is on gets the printing key');
SELECT is((:'pkey'::jsonb ->> 'o_kid'), 'kidprt1', '... the printed-QR kid');
SELECT is((:'pkey'::jsonb ->> 'o_signing_key'), repeat('P', 43), '... the Vault seed of THAT purpose (not the rotating-token key)');
SELECT is((:'pkey'::jsonb ->> 'o_slug'), 'facility-x', '... and the facility slug (the print link''s path)');
SELECT is((:'pkey'::jsonb -> 'o_public_key'), 'null'::jsonb, '... and NO public key: none is registered yet (the write ensures it)');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_read_for_partner('fac_x')$$) ->> 'o_status', 'not_printed', 'nothing is registered for fac_x yet');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_key_for_partner('fac_y')$$)), '42501|partner_authorize: no scope', 'an operator of trl_t has no scope at fac_y (not on its trail): refused');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p'))::text, '{"o_status": "ok", "o_changed": true}', 'the write registers the QR: ok, changed');
SELECT is((SELECT (k.public_key_b64url, k.revoked_at IS NULL)::text FROM app.course_qr_key k WHERE k.purpose = 'printed_qr' AND k.kid = 'kidprt1'), '(' || repeat('u', 43) || ',t)', 'the PUBLIC key row was inserted for the Vault kid (purpose printed_qr, not revoked)');
SELECT is((SELECT (q.qr_kid, q.sig, q.revoked_at IS NULL)::text FROM app.facility_qr q WHERE q.facility_id = 'fac_x'), '(kidprt1,' || repeat('S', 86) || ',t)', 'facility_qr holds the kid and the signature, unrevoked');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_read_for_partner('fac_x')$$) ->> 'o_qr_kid', 'kidprt1', 'the read returns the registered kid');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.course_qr.print' AND subject_id = 'fac_x' AND detail = '{"qr_kid": "kidprt1"}'::jsonb), 1, 'one audit_log row: the facility and the kid, no key material');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE detail::text LIKE '%PPPPPPPP%'), 0, 'the Vault seed is in no audit row');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p'))::text, '{"o_status": "ok", "o_changed": false}', 'the same QR again (Ed25519 is deterministic): ok, NOT changed');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.course_qr.print'), 1, '... and no second audit row');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_b', :'pk_p'))::text, '{"o_status": "ok", "o_changed": true}', 'a different signature for the same kid replaces the registration (a reprint)');
SELECT is((SELECT q.sig FROM app.facility_qr q WHERE q.facility_id = 'fac_x'), repeat('T', 86), '... facility_qr holds the new signature');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt2', %L, %L)$$, :'sig_a', :'pk_p'))::text, '{"o_status": "kid_mismatch", "o_changed": false}', 'a kid that is not the Vault key''s is never registered: kid_mismatch');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', repeat('v', 43)))::text, '{"o_status": "key_mismatch", "o_changed": false}', 'a public key different from the registered one: key_mismatch (an existing key row is never replaced)');
SELECT is((SELECT public_key_b64url FROM app.course_qr_key WHERE purpose = 'printed_qr' AND kid = 'kidprt1'), repeat('u', 43), '... the registered key is unchanged');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', 'short', %L)$$, :'pk_p')), '22023|course_qr_print_write_for_partner: a kid (1 to 64), a signature (86) and a public key (43), all base64url, are required', 'a malformed signature is 22023');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kid space', %L, %L)$$, :'sig_a', :'pk_p')), '22023|course_qr_print_write_for_partner: a kid (1 to 64), a signature (86) and a public key (43), all base64url, are required', 'a malformed kid is 22023');
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_y', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p')), '42501|partner_authorize: no scope', 'the operator cannot register a QR for a facility outside its trail');
UPDATE app.course_qr_key SET revoked_at = now() WHERE purpose = 'printed_qr' AND kid = 'kidprt1';
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$) ->> 'o_status', 'key_revoked', 'a revoked Vault key releases nothing to qr-print: key_revoked (the operator must provision a new key)');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p')) ->> 'o_status', 'key_revoked', '... and nothing is registered under it');
ROLLBACK TO SAVEPOINT pr_a;
SAVEPOINT pr_reprint;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT pg_temp.seed_step('op', '{"mfa_s": 200}'::jsonb);
INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'kidprt0', repeat('w', 43));
INSERT INTO app.facility_qr (facility_id, qr_kid, sig, printed_at, revoked_at) VALUES ('fac_x', 'kidprt0', repeat('Q', 86), now() - interval '30 days', now() - interval '1 day');
INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'kidprt1', repeat('u', 43));
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p'))::text, '{"o_status": "ok", "o_changed": true}', 'a reprint after a key rotation: the old kid is replaced by the Vault key''s');
SELECT is((SELECT (q.qr_kid, q.revoked_at IS NULL, q.printed_at > now() - interval '1 minute')::text FROM app.facility_qr q WHERE q.facility_id = 'fac_x'), '(kidprt1,t,t)', '... the old revocation is cleared and printed_at is renewed: an older kid is qr_revoked in the player lane');
ROLLBACK TO SAVEPOINT pr_reprint;
SAVEPOINT pr_op1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$), '42501|partner_authorize: the session''s assurance level is below the member''s required level', 'an aal 1 operator session is refused outright');
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_read_for_partner('fac_x')$$), '42501|partner_authorize: the session''s assurance level is below the member''s required level', '... even the read');
ROLLBACK TO SAVEPOINT pr_op1;
SAVEPOINT pr_staff;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$), '42501|partner_authorize: no scope', 'a MANAGER of fac_x cannot print: qr-print is an operator and admin action');
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_read_for_partner('fac_x')$$), '42501|partner_authorize: no scope', '... nor read the registration');
ROLLBACK TO SAVEPOINT pr_staff;
SAVEPOINT pr_sx;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.err(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_x', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p')), '42501|partner_authorize: no scope', 'staff cannot register a printed QR');
ROLLBACK TO SAVEPOINT pr_sx;
SAVEPOINT pr_ad;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 200}'::jsonb);
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_key_for_partner('fac_n33')$$) ->> 'o_status', 'ok', 'an admin prints for any facility');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_key_for_partner('fac_nope')$$) ->> 'o_status', 'no_facility', '... and an unknown facility is a status');
SELECT is(pg_temp.ap(format($$SELECT * FROM private.course_qr_print_write_for_partner('fac_nope', 'kidprt1', %L, %L)$$, :'sig_a', :'pk_p')) ->> 'o_status', 'no_facility', '... on the write too (nothing is registered)');
SELECT is(pg_temp.ap($$SELECT * FROM private.course_qr_print_read_for_partner('fac_nope')$$) ->> 'o_status', 'no_facility', '... and on the read');
ROLLBACK TO SAVEPOINT pr_ad;
SAVEPOINT pr_missing;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT pg_temp.seed_step('op', '{"mfa_s": 200}'::jsonb);
DELETE FROM vault.secrets WHERE name = 'course_qr_signing_key_printed_qr';
SELECT is(pg_temp.err($$SELECT * FROM private.course_qr_print_key_for_partner('fac_x')$$), '55000|course_qr_signing_key_read: the course QR signing key is not provisioned in Vault', 'no printed-QR key in Vault: 55000');
ROLLBACK TO SAVEPOINT pr_missing;

-- ----------------------------------------------------------------------------
-- 8. The three tables are definer-only and the policies are inert under any other binding
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM app.course_qr_token), 0, 'nothing leaked out of the savepoints: no token rows remain');
SELECT is((SELECT count(*)::int FROM app.facility_qr), 0, '... no printed-QR rows');
SELECT is((SELECT count(*)::int FROM app.course_qr_key WHERE purpose = 'printed_qr'), 0, '... no printed-QR key rows');
SELECT is((SELECT array_agg(pin_epoch ORDER BY trail_id, facility_id) FROM app.facility_programme WHERE facility_id IN ('fac_x', 'fac_r33')), ARRAY[0, 0, 0], '... and no epoch moved');
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id IN ('fac_x', 'fac_r33')), 0, '... and the epoch log is empty');

SELECT * FROM finish();
ROLLBACK;
