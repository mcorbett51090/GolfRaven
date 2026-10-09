-- 31_partner_totp_aal2.sql
-- P5.1a S1.4 (0053): PARTNER TOTP AND aal 2, from docs/security/partner-auth-design.md section 12.1 "S1.4": PA-20 (SQL HOTP equals the RFC 6238 / independent oracle; replay refused; +/-1 step;
-- lockout is a status; an aal 1 operator/admin is refused every call except sign-out, lock, GET session and step-up/totp; A3 needs aal2 + mfa_until; PIN-less elevated A1/A2 substitution),
-- PA-24 (enrol after confirmed refused; first enrol needs enrolment/otp proof; unconfirmed re-enrol bumps seed; confirm from another session refused; reset by non-admin refused;
-- admin reset of another operator/admin ok and sessions revoked) and PA-28 (aal1 with no confirmed TOTP reaches enrol/confirm/otp-proof/reauth; after confirm the same A0_ENROL calls refuse).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end. The partner tables are FORCE RLS with no policy for the harness role, so fixtures are written through a temporary
-- CURRENT_USER policy (the 0016 / 0045 / 28 seeding pattern). Every scenario that needs a clean binding runs inside a SAVEPOINT that is rolled back. The seed oracle is an independent
-- HMAC-SHA256 of the shim Vault key (pg_temp.seed_of), so derive / enrol are checked against something other than themselves.
--
-- Principals are helpers.sql's: staff_x (a1), manager_x (b1), operator_t (c1), admin (d0).

\set QUIET 1
BEGIN;
SELECT plan(84);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, partner_totp_verifier, partner_pin_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_totp, app.partner_rp_config TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz31_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz31_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz31_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz31_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz31_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s31:' || p_label) || md5('s31b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c31:' || p_label) || md5('c31b:' || p_label), 'hex'), decode(md5('k31:' || p_label) || md5('k31b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1, p_mint_kind text DEFAULT 'sign_in', p_enrol interval DEFAULT NULL) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature, enrolment_until)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', p_mint_kind,
          decode(md5('n31:' || p_label) || md5('n31b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'),
          CASE WHEN p_mint_kind = 'sign_in' THEN decode(repeat('05', 70), 'hex') END, now() + p_enrol)
  RETURNING id
$f$;
-- independent seed oracle: HMAC-SHA256(shim partner_totp_key, label || 0x00 || uid || int4send(ver))
CREATE FUNCTION pg_temp.seed_of(p_uid uuid, p_ver integer) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(
    convert_to('golfraven/partner-totp/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_uid::text, '-', ''), 'hex') || int4send(p_ver),
    convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_totp_key'), 'UTF8'),
    'sha256')
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    reauth_until = CASE WHEN p_cols ? 'reauth_s' THEN clock_timestamp() + ((p_cols ->> 'reauth_s')::numeric * interval '1 second') ELSE s.reauth_until END,
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END,
    enrolment_until = CASE WHEN p_cols ? 'enrol_s' THEN clock_timestamp() + ((p_cols ->> 'enrol_s')::numeric * interval '1 second') ELSE s.enrolment_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.seed_totp(p_uid uuid, p_ver integer DEFAULT 1, p_confirmed boolean DEFAULT true, p_last bigint DEFAULT NULL, p_sid uuid DEFAULT NULL) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
  VALUES (p_uid, p_ver, clock_timestamp(), p_sid,
          CASE WHEN p_confirmed THEN clock_timestamp() END, p_last, 0, NULL, NULL, clock_timestamp())
$f$;
CREATE FUNCTION pg_temp.hotp_at(p_seed bytea, p_delta integer DEFAULT 0) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE c text;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.hotp(p_seed, floor(extract(epoch from clock_timestamp()) / 30.0)::bigint + p_delta, 6, 'sha1') INTO c;
  EXECUTE 'RESET ROLE';
  RETURN c;
END
$f$;
CREATE FUNCTION pg_temp.derive(p_uid uuid, p_ver integer) RETURNS bytea LANGUAGE plpgsql AS $f$
DECLARE s bytea;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.partner_totp_seed_derive(p_uid, p_ver) INTO s;
  EXECUTE 'RESET ROLE';
  RETURN s;
END
$f$;
CREATE FUNCTION pg_temp.hotp_vec(p_seed bytea, p_counter bigint, p_digits integer, p_algo text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE c text;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.hotp(p_seed, p_counter, p_digits, p_algo) INTO c;
  EXECUTE 'RESET ROLE';
  RETURN c;
END
$f$;
CREATE FUNCTION pg_temp.enrol() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_enrol_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(encode(r.o_seed, 'hex'), '') || '|' || coalesce(r.o_seed_version::text, '');
END
$f$;
CREATE FUNCTION pg_temp.confirm(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_confirm_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.verify(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_verify_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after || '|' || (r.o_mfa_until IS NOT NULL)::text;
END
$f$;
CREATE FUNCTION pg_temp.reset_totp(p_uid uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_reset_for_partner(p_uid);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;

GRANT CREATE ON SCHEMA private TO private_definer;
SET LOCAL ROLE private_definer;
CREATE FUNCTION private.zz31_authz_for_partner(p_fac text, p_trail text, p_roles text[], p_class text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RETURN private.partner_authorize(p_fac, p_trail, p_roles::app.partner_role[], p_class);
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz31_authz_for_partner(text, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.zz31_authz_for_partner(text, text, text[], text) TO edge_partner, edge_actor;
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('op1', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op1 \gset
SELECT pg_temp.mk_session('op1b', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op1b \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.mk_session('ad1', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 1) AS s_ad1 \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('op1') AS th_op1,
       pg_temp.th('op1b') AS th_op1b, pg_temp.th('ad') AS th_ad, pg_temp.th('ad1') AS th_ad1 \gset

-- ----------------------------------------------------------------------------
-- 1. Structure / privilege
-- ----------------------------------------------------------------------------
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.partner_totp'::regclass), true, 'app.partner_totp has ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_pin_verifier'), ('partner_reauth_verifier')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.partner_totp', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.partner_totp', 'DELETE,TRUNCATE,TRIGGER')), 0,
  'PA-1: no client, edge, service_role or other owner role holds ANY privilege on app.partner_totp');
SELECT is((SELECT array_agg(c.n ORDER BY c.n) FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) c(n) WHERE has_table_privilege('partner_totp_verifier', 'app.partner_totp', c.n)),
  ARRAY['INSERT', 'SELECT', 'UPDATE'], 'partner_totp_verifier holds SELECT, INSERT and UPDATE only (no DELETE)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.partner_totp_enrol_for_partner()'::regprocedure, 'private.partner_totp_confirm_for_partner(text)'::regprocedure,
  'private.partner_totp_verify_for_partner(text)'::regprocedure, 'private.partner_totp_reset_for_partner(uuid)'::regprocedure,
  'private.partner_admin_enrolment_issue_for_partner(uuid, text)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole), 5,
  'the five edge_partner TOTP/admin wrappers are SECURITY DEFINER search_path='''', owned by private_definer');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'), ('partner_totp_verifier')) r(n)
           CROSS JOIN (VALUES ('private.partner_totp_enrol_for_partner()'), ('private.partner_totp_confirm_for_partner(text)'),
                              ('private.partner_totp_verify_for_partner(text)'), ('private.partner_totp_reset_for_partner(uuid)'),
                              ('private.partner_admin_enrolment_issue_for_partner(uuid, text)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')),
  ARRAY['edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner'],
  'ONLY edge_partner can execute the five lane wrappers');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.partner_totp_attempt(uuid, text)'::regprocedure, 'private.partner_totp_verify_apply(text)'::regprocedure,
  'private.partner_totp_enrol_apply()'::regprocedure, 'private.partner_totp_confirm_apply(text)'::regprocedure,
  'private.partner_totp_mfa_clear()'::regprocedure, 'private.partner_totp_reset_apply(uuid)'::regprocedure, 'private.partner_totp_confirmed(uuid)'::regprocedure)
  AND p.prosecdef AND p.proowner = 'partner_totp_verifier'::regrole), 7,
  'R5-L1: the seven verifier-owned writers/predicates are owned by partner_totp_verifier');
SELECT is((has_column_privilege('private_definer', 'app.partner_session', 'aal', 'UPDATE'), has_column_privilege('partner_totp_verifier', 'app.partner_session', 'aal', 'UPDATE'),
           has_column_privilege('private_definer', 'app.partner_session', 'mfa_until', 'UPDATE'), has_column_privilege('partner_totp_verifier', 'app.partner_session', 'mfa_until', 'UPDATE'))::text,
  '(f,t,f,t)', 'R5-L1: partner_totp_verifier alone writes aal and mfa_until');
SELECT is(pg_temp.hotp_vec(convert_to('12345678901234567890', 'UTF8'), 1, 6, 'sha1'), '287082', 'PA-20: private.hotp SHA-1 RFC 4226/6238 vector (seed 20 ASCII, counter 1) = 287082');
SELECT is(pg_temp.hotp_vec(convert_to('12345678901234567890', 'UTF8'), 0, 6, 'sha1'), '755224', 'PA-20: ... counter 0 = 755224');
SELECT is(pg_temp.hotp_vec(convert_to('12345678901234567890123456789012', 'UTF8'), 1, 6, 'sha256'), '119246', 'PA-20: private.hotp SHA-256 offline-style vector (32-byte seed, counter 1, 6 digits)');
SELECT is(octet_length(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1)), 32, 'partner_totp_seed_derive returns 32 bytes');
SELECT is(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1),
  'PA-20 oracle: derive equals independent HMAC-SHA256(shim key, label||0x00||uid||int4send(ver))');
SELECT is(encode(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), 'hex'), 'b9494b5ddb884547eee93411f3bbdd81bdc339fa306286ef3c0a33c29af5bfb0',
  'PA-20 oracle: the operator v1 seed matches the vector computed OUTSIDE the database');
SELECT isnt(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 2), 'different seed_versions differ');
SELECT isnt(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), pg_temp.derive('00000000-0000-0000-0000-4000000000d0', 1), 'different users differ');
SELECT is(pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1), 'derive is deterministic for the same (user, version)');
SAVEPOINT key_missing;
DELETE FROM vault.secrets WHERE name = 'partner_totp_key';
SELECT throws_ok($$SELECT pg_temp.derive('00000000-0000-0000-0000-3000000000c1', 1)$$, '55000',
  'partner_totp_seed_derive: the partner TOTP key is not provisioned in Vault', 'missing Vault partner_totp_key → 55000');
ROLLBACK TO SAVEPOINT key_missing;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN (
  'hotp', 'partner_totp_seed_derive', 'partner_totp_confirmed', 'partner_is_pinless_elevated', 'partner_totp_attempt', 'partner_totp_verify_apply',
  'partner_totp_enrol_apply', 'partner_totp_confirm_apply', 'partner_totp_mfa_clear', 'partner_totp_reset_apply', 'partner_totp_enrol_for_partner',
  'partner_totp_confirm_for_partner', 'partner_totp_verify_for_partner', 'partner_totp_reset_for_partner', 'partner_admin_bootstrap_token',
  'partner_admin_enrolment_issue_for_partner')), 16, 'registry: all 16 new 0053 functions have a function_inventory row');
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name = 'partner_totp' AND action = 'delete_row')
        + (SELECT count(*)::int FROM private.pii_export_policy WHERE table_name = 'partner_totp' AND action = 'exclude'), 2,
  'registry: partner_totp is classified for deletion and export');
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. check 14: wrappers begin with partner_authorize (no binding → 42501)
-- ----------------------------------------------------------------------------
SELECT throws_ok($$SELECT * FROM private.partner_totp_enrol_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): enrol with NO binding');
SELECT throws_ok($$SELECT * FROM private.partner_totp_confirm_for_partner('000000')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): confirm with NO binding');
SELECT throws_ok($$SELECT * FROM private.partner_totp_verify_for_partner('000000')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): verify with NO binding');
SELECT throws_ok($$SELECT * FROM private.partner_totp_reset_for_partner('00000000-0000-0000-0000-3000000000c1')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): reset with NO binding');
SELECT throws_ok($$SELECT * FROM private.partner_admin_enrolment_issue_for_partner('00000000-0000-0000-0000-3000000000c1', repeat('ab', 32))$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): admin enrolment issue with NO binding');

-- ----------------------------------------------------------------------------
-- 3. PA-20: enrol → confirm → verify; replay; +/-1; lockout; aal gates; A3; pinless
-- ----------------------------------------------------------------------------
SAVEPOINT happy;
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.enrol(), '|', 1), 'ok', 'PA-20/PA-24: enrol under otp_proof → ok');
SELECT is((SELECT seed_version FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), 1, 'first enrol writes seed_version 1');
SELECT is((SELECT encode(pg_temp.seed_of(user_id, seed_version), 'hex') FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'),
  'b9494b5ddb884547eee93411f3bbdd81bdc339fa306286ef3c0a33c29af5bfb0', 'enrolled seed matches the independent oracle');
SELECT is((SELECT otp_proof_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('op1')), true, 'MEDIUM-1: enrol spends otp_proof_until on ok');
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'ok|0', 'PA-20/PA-24: confirm with the current HOTP code → ok');
SELECT is((SELECT confirmed_at IS NOT NULL FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true, 'confirm sets confirmed_at');
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 1)), 'ok|0|true', 'PA-20: step-up verify with step+1 → ok + mfa_until');
SELECT is((SELECT aal FROM app.partner_session WHERE token_hash = pg_temp.th('op1')), 2::smallint, 'PA-20: verify sets aal = 2 on the BOUND session');
SELECT ok((SELECT mfa_until > clock_timestamp() + interval '4 minutes 50 seconds' AND mfa_until <= clock_timestamp() + interval '5 minutes'
           FROM app.partner_session WHERE token_hash = pg_temp.th('op1')), 'PA-20: mfa_until is now + 5 minutes');
SELECT is((SELECT mfa_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('op')), true, 'PA-20: promotion does not set mfa_until on another session');
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 1)), '|', 1), 'wrong', 'PA-20: replay of the same step is refused (wrong)');
ROLLBACK TO SAVEPOINT happy;

SAVEPOINT enrol_win;
SELECT pg_temp.seed_step('op1', '{"enrol_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.enrol(), '|', 1), 'ok', 'PA-24: enrol under enrolment_until → ok');
ROLLBACK TO SAVEPOINT enrol_win;

SAVEPOINT enrol_params;
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT is((SELECT (o_issuer, o_period, o_digits, o_algo)::text FROM private.partner_totp_enrol_for_partner()),
  '(GolfRaven,30,6,SHA1)', 'PA-24: enrol returns otpauth params (issuer GolfRaven, period 30, digits 6, SHA1)');
RESET ROLE;
ROLLBACK TO SAVEPOINT enrol_params;

SAVEPOINT win_m1;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), -1)), '|', 1), 'ok', 'PA-20: step-1 window accepts');
ROLLBACK TO SAVEPOINT win_m1;
SAVEPOINT win_0;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), '|', 1), 'ok', 'PA-20: current step accepts');
ROLLBACK TO SAVEPOINT win_0;
SAVEPOINT win_p1;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 1)), '|', 1), 'ok', 'PA-20: step+1 window accepts');
ROLLBACK TO SAVEPOINT win_p1;

SAVEPOINT lockout;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.verify('000000'), '|', 1), 'wrong', 'PA-20: failure 1 → status wrong (no RAISE)');
SELECT is(split_part(pg_temp.verify('000001'), '|', 1), 'wrong', 'PA-20: failure 2');
SELECT is(split_part(pg_temp.verify('000002'), '|', 1), 'wrong', 'PA-20: failure 3');
SELECT is(split_part(pg_temp.verify('000003'), '|', 1), 'wrong', 'PA-20: failure 4');
SELECT is(pg_temp.verify('000004'), 'locked|900|false', 'PA-20: failure 5 → status locked (retry_after 900)');
SELECT is((SELECT failed_count FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), 0::smallint, 'PA-20: failed_count resets on lock');
SELECT is(split_part(pg_temp.verify('000005'), '|', 1), 'locked', 'PA-20: a further wrong attempt during lock returns locked');
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), '|', 1), 'locked', 'PA-20: the CORRECT code during lock is still refused');
SELECT is((SELECT failed_count FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), 0::smallint, 'PA-20: failures during lock are not counted');
ROLLBACK TO SAVEPOINT lockout;

SAVEPOINT aal1_gates;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT is(private.zz31_authz_for_partner(NULL, NULL, NULL, 'SESSION'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'PA-20: aal1 operator: SESSION ok');
SELECT is(private.zz31_authz_for_partner(NULL, NULL, NULL, 'PEEK'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'PA-20: aal1 operator: PEEK ok');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'PA-20: aal1 operator: lock (SESSION) ok');
SELECT lives_ok($$SELECT private.partner_session_revoke_for_partner()$$, 'PA-20: aal1 operator: sign-out (SESSION) ok');
RESET ROLE;
ROLLBACK TO SAVEPOINT aal1_gates;

SAVEPOINT aal1_classes;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0')$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-20: aal1 operator: A0 (normal) refused');
SELECT is(private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0_MFA'), '00000000-0000-0000-0000-3000000000c1'::uuid,
  'PA-20: aal1 operator: A0_MFA (step-up verify) ok');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0_ENROL')$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-20/PA-28: aal1 operator AFTER confirm: A0_ENROL refused');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A3')$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-20: A3 refused at aal1 (aal gate)');
RESET ROLE;
ROLLBACK TO SAVEPOINT aal1_classes;

SAVEPOINT a3_ok;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is(private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A3'), '00000000-0000-0000-0000-4000000000d0'::uuid,
  'PA-20 / check 14: A3 ENABLED — admin aal2 + fresh mfa_until passes (no longer fail-closed)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a3_ok;
SAVEPOINT a3_nomfa;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A3')$$, '42501',
  'partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required', 'PA-20: A3 at aal2 without mfa_until is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a3_nomfa;

SAVEPOINT pinless;
SELECT pg_temp.seed_step('op', '{"reauth_s": 240, "mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT is(private.zz31_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A1'), '00000000-0000-0000-0000-3000000000c1'::uuid,
  'PA-20: PIN-less elevated operator with fresh mfa_until passes A1 without a PIN grant');
SELECT is(private.zz31_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A2'), '00000000-0000-0000-0000-3000000000c1'::uuid,
  'PA-20: ... and A2 with reauth + mfa (no PIN grant)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pinless;

-- ----------------------------------------------------------------------------
-- 4. PA-24 enrol / confirm / reset
-- ----------------------------------------------------------------------------
-- After confirm, A0_ENROL needs aal 2 (PA-28). Seed aal 2 so authorize reaches enrol_apply's already_confirmed status.
SAVEPOINT already;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SELECT pg_temp.seed_step('op1', '{"otp_s": 500, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT is(split_part(pg_temp.enrol(), '|', 1), 'already_confirmed', 'PA-24: enrol after confirmed (aal 2 session) → already_confirmed');
ROLLBACK TO SAVEPOINT already;

SAVEPOINT no_proof;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.enrol()$$, '42501',
  'partner_totp_enrol_apply: TOTP is enrolled only inside an enrolment window or after an email proof',
  'PA-24: first enrol without enrolment_until/otp_proof → 42501');
ROLLBACK TO SAVEPOINT no_proof;

SAVEPOINT reenrol;
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
RESET ROLE;
SELECT pg_temp.enrol() AS e1 \gset
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SELECT pg_temp.enrol() AS e2 \gset
SELECT is(split_part(:'e1', '|', 3)::int, 1, 'PA-24: first unconfirmed enrol is version 1');
SELECT is(split_part(:'e2', '|', 3)::int, 2, 'PA-24: unconfirmed re-enrol bumps seed_version to 2');
SELECT isnt(split_part(:'e1', '|', 2), split_part(:'e2', '|', 2), 'PA-24: ... and returns a DIFFERENT seed (H4)');
ROLLBACK TO SAVEPOINT reenrol;

SAVEPOINT wrong_sess;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, false, NULL, :'s_op1'::uuid);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1b');
RESET ROLE;
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'wrong_session|0',
  'PA-24: confirm from another session → wrong_session');
ROLLBACK TO SAVEPOINT wrong_sess;

SAVEPOINT reset_op;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-4000000000d0', 1, true, NULL);
SELECT pg_temp.seed_step('op', '{"mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
-- pg_temp helpers are not executable as edge_partner; the binding survives RESET ROLE.
SELECT throws_ok($$SELECT pg_temp.reset_totp('00000000-0000-0000-0000-4000000000d0')$$, '42501',
  'partner_totp_reset_for_partner: only an admin may reset another person''s TOTP', 'PA-24: reset by non-admin (operator) → 42501');
ROLLBACK TO SAVEPOINT reset_op;

SAVEPOINT reset_admin;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 3, true, NULL);
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is(pg_temp.reset_totp('00000000-0000-0000-0000-3000000000c1'), 'ok', 'PA-24: admin resetting an operator → ok');
SELECT is((SELECT confirmed_at IS NULL AND seed_version = 4 FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true,
  'PA-24: reset clears confirmed_at and bumps seed_version');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-3000000000c1' AND revoked_at IS NOT NULL),
  (SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-3000000000c1'),
  'PA-24: reset revokes every session of the target');
ROLLBACK TO SAVEPOINT reset_admin;

-- ----------------------------------------------------------------------------
-- 5. PA-28 shape: A0_ENROL before/after confirm
-- ----------------------------------------------------------------------------
SAVEPOINT pa28_before;
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT is(private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0_ENROL'), '00000000-0000-0000-0000-3000000000c1'::uuid,
  'PA-28: aal1 operator with NO confirmed TOTP: A0_ENROL ok');
RESET ROLE;
SELECT is(split_part(pg_temp.enrol(), '|', 1), 'ok', 'PA-28: ... totp/enrol reachable');
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'ok|0', 'PA-28: ... totp/confirm reachable');
ROLLBACK TO SAVEPOINT pa28_before;

SAVEPOINT pa28_otp;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)), 'refused',
  'PA-28: aal1 no-TOTP operator reaches otp-proof (A0_ENROL); bad GoTrue id → status refused');
SELECT lives_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, 'PA-28: ... and reauth/options');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0')$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-28: ... but not A0 (nothing else)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa28_otp;

SAVEPOINT pa28_after;
SELECT pg_temp.seed_totp('00000000-0000-0000-0000-3000000000c1', 1, true, NULL);
SELECT pg_temp.seed_step('op1', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT throws_ok($$SELECT private.zz31_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0_ENROL')$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level',
  'PA-28: after confirm, aal1 A0_ENROL refuses');
SELECT throws_ok($$SELECT * FROM private.partner_totp_enrol_for_partner()$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-28: ... enrol refused');
SELECT throws_ok($$SELECT * FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-28: ... otp-proof refused');
SELECT throws_ok($$SELECT * FROM private.partner_session_reauth_options_for_partner()$$, '42501',
  'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-28: ... reauth refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa28_after;

-- ----------------------------------------------------------------------------
-- 6. lock clears mfa_until; staff cannot enrol
-- ----------------------------------------------------------------------------
SAVEPOINT lock_mfa;
SELECT pg_temp.seed_step('op', '{"mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT private.partner_session_lock_for_partner();
RESET ROLE;
SELECT is((SELECT mfa_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('op')), true, 'lock clears mfa_until through partner_totp_mfa_clear');
ROLLBACK TO SAVEPOINT lock_mfa;

SAVEPOINT staff_enrol;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_totp_enrol_for_partner()$$, '42501', 'partner_authorize: no scope',
  'PA-24: staff (no operator/admin) cannot enrol TOTP');
RESET ROLE;
ROLLBACK TO SAVEPOINT staff_enrol;

SELECT is((SELECT count(*)::int FROM app.partner_totp) + (SELECT count(*)::int FROM app.partner_session s WHERE s.mfa_until IS NOT NULL OR s.revoked_at IS NOT NULL)
          + (SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.totp.%'), 0,
  'the scenarios left no trace: no totp row, no mfa window, no totp audit (a rolled-back savepoint per scenario)');
SELECT * FROM finish();
ROLLBACK;
