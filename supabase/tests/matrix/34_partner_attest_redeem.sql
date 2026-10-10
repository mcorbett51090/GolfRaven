-- 34_partner_attest_redeem.sql
-- P5.1a S3 (0056): ATTEST, from docs/security/partner-auth-design.md 12.1 "S3": AT(1) (staff at X cannot attest at Y; an operator cannot attest), AT(2) (the online token path: one attestation per token, the
-- player derived from the token, an expired or foreign-facility token is one answer), AT(12) (the offline code VERIFIED AND RECORDED IN THE DATABASE: a right code at the current step and one step either side is
-- accepted, two steps away is not; the result carries no seed, no expected code and no device), AT(13) (a replayed code step is refused, and counts), AT(15) (the same-device rule holds a purchase and opens a signal;
-- the cold-start cap), AT(16) part one (self-attest is 22023, per ACCOUNT), the shift-log read (the old view's rows and a subset of its columns) and the staff-activity read (managers and operators, never staff),
-- the check-14 (a) behavioural cells of the four new `_for_partner` definers, and the binding-keyed policies (closed without a partner binding, closed under another kind of binding, not opened by a planted GUC).
--
-- WHAT A pgTAP FILE CANNOT SHOW: that the failure counters of a refusal survive a REAL commit (statuses, no RAISE: by construction, and supabase/tests/integration/partner-attest.deno.test.ts), and that 12
-- parallel verifications of one code step record it once (a primary key; the Deno suite and 23_offline_totp_seed_record.sql keep the 0045 race proof).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end; every scenario inside a SAVEPOINT that is rolled back (a second bind in one transaction is itself refused). The partner tables are FORCE RLS with no
-- policy for the harness role, so fixtures are written and read through temporary CURRENT_USER policies (the 28 pattern). The offline code is computed here by an INDEPENDENT implementation (pg_temp.ref_code),
-- plus one vector computed OUTSIDE the database.
--
-- Principals are helpers.sql's: staff_x (a1: staff at fac_x), manager_x (b1), staff_y (a3: staff at fac_y), operator_t (c1), admin (d0), and player_a (a staff member of the fac_x org AND a player: the
-- self-attest and the third-staff principal) and player_b (a plain player).

\set QUIET 1
BEGIN;
SELECT plan(112);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT ON app.attestation, app.attestation_shift_log, app.staff_activity, app.purchase_evidence, app.marker_credit, app.fraud_signal, app.offline_code_step, app.audit_log, private.rate_limit_bucket TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz34_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz34_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz34_att ON app.attestation FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_log ON app.attestation_shift_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_act ON app.staff_activity FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_pur ON app.purchase_evidence FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_cr ON app.marker_credit FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_fr ON app.fraud_signal FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_st ON app.offline_code_step FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz34_rl ON private.rate_limit_bucket FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s34:' || p_label) || md5('s34b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c34:' || p_label) || md5('c34b:' || p_label), 'hex'), decode(md5('k34:' || p_label) || md5('k34b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n34:' || p_label) || md5('n34b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
-- a PIN grant a session cannot be BORN with: the guard is off for the seeding only
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;

-- the two partner calls, as edge_partner, inside a binding the caller made, with a fresh PIN grant each time; 'status|held'
CREATE FUNCTION pg_temp.onl(p_label text, p_fac text, p_kind text, p_jti uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_attest_for_partner(p_fac, p_kind, p_jti);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_held::text;
END
$f$;
CREATE FUNCTION pg_temp.off(p_label text, p_fac text, p_kind text, p_handle text, p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"pin_grant_s": 50}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offline_attest_for_partner(p_fac, p_kind, p_handle, p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_held::text;
END
$f$;
-- the offline code by an INDEPENDENT implementation (the migration's is private.offline_seed_derive + private.hotp): seed = HMAC-SHA256(K, label || 0x00 || user (16) || device (16) || int4send(version)),
-- code = RFC 4226 truncation of HMAC-SHA256(seed, 8-byte big-endian step), 6 digits
CREATE FUNCTION pg_temp.ref_code(p_user uuid, p_dev uuid, p_ver int, p_step bigint) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  k text := (SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'offline_seed_key');
  seed bytea;
  h bytea;
  o int;
  b bigint;
BEGIN
  seed := public.hmac(convert_to('golfraven/offline-seed/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_user::text, '-', ''), 'hex') || decode(replace(p_dev::text, '-', ''), 'hex') || int4send(p_ver),
                      convert_to(k, 'UTF8'), 'sha256');
  h := public.hmac(int8send(p_step), seed, 'sha256');
  o := get_byte(h, 31) & 15;
  b := ((get_byte(h, o)::bigint & 127) << 24) | (get_byte(h, o + 1)::bigint << 16) | (get_byte(h, o + 2)::bigint << 8) | get_byte(h, o + 3)::bigint;
  RETURN lpad((b % 1000000)::text, 6, '0');
END
$f$;
CREATE FUNCTION pg_temp.now_step() RETURNS bigint LANGUAGE sql AS $f$ SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint $f$;

-- principals: every membership is older than the cold-start window unless a scenario says otherwise
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET created_at = now() - interval '60 days';
RESET ROLE;
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_cred('pa', '00000000-0000-0000-0000-00000000000a') AS c_pa \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.mk_session('pa', '00000000-0000-0000-0000-00000000000a', :'c_pa') AS s_pa \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad, pg_temp.th('pa') AS th_pa \gset

-- the players' devices and the check-in tokens the online path resolves (service_role writes them, as the checkin-token endpoint's runtime does)
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, devicecheck_token_hash) VALUES
  ('34000000-0000-0000-0000-00000000d0b1', '00000000-0000-0000-0000-00000000000b', 'ios', 'dc-player-b'),
  ('34000000-0000-0000-0000-00000000d0b2', '00000000-0000-0000-0000-00000000000b', 'ios', 'dc-shared'),
  ('34000000-0000-0000-0000-00000000d0a1', '00000000-0000-0000-0000-1000000000a1', 'ios', 'dc-shared'),
  ('34000000-0000-0000-0000-00000000d0e1', '00000000-0000-0000-0000-5000000000e0', 'ios', 'dc-demo');
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) VALUES
  ('34100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n34-1', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', NULL, 'n34-2', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n34-3', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_y', 'n34-4', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b2', 'fac_x', 'n34-5', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'n34-6', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'n34-7', now() + interval '10 minutes', 'live'),
  ('34100000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-5000000000e0', '34000000-0000-0000-0000-00000000d0e1', 'fac_x', 'n34-8', now() + interval '10 minutes', 'live');
INSERT INTO app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) VALUES
  ('34200000-0000-0000-0000-000000000001', '34100000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000002', '34100000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', NULL, 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000003', '34100000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now() - interval '20 minutes', now() - interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000004', '34100000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_y', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000005', '34100000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b2', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000006', '34100000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000007', '34100000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes'),
  ('34200000-0000-0000-0000-000000000008', '34100000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-5000000000e0', '34000000-0000-0000-0000-00000000d0e1', 'fac_x', 'attested', 'live', now(), now() + interval '10 minutes');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Structure: who can execute what, and nothing else
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.partner_attest_for_partner(text, text, uuid)'::regprocedure, 'private.partner_offline_attest_for_partner(text, text, text, text)'::regprocedure,
  'private.partner_shift_log_for_partner(text)'::regprocedure, 'private.partner_staff_activity_for_partner(text, integer)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole), 4, 'the four _for_partner definers are SECURITY DEFINER, search_path = empty, owned by private_definer');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'),
                                                              ('partner_session_toucher'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_reauth_verifier')) r(n)
           CROSS JOIN (VALUES ('private.partner_attest_for_partner(text, text, uuid)'), ('private.partner_offline_attest_for_partner(text, text, text, text)'),
                              ('private.partner_shift_log_for_partner(text)'), ('private.partner_staff_activity_for_partner(text, integer)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), ARRAY['edge_partner', 'edge_partner', 'edge_partner', 'edge_partner'],
  'of every client, edge and owner role ONLY edge_partner can execute the four (not edge_actor: the user lane has no verify-and-record, X9)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'),
                                                              ('partner_session_toucher'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_reauth_verifier')) r(n)
           CROSS JOIN (VALUES ('private.partner_attest_write(uuid, text, uuid, text, text, text, boolean, boolean, timestamptz, timestamptz)'), ('private.partner_attest_same_device(uuid, uuid)'),
                              ('private.partner_bound_staff_at(text)'), ('private.partner_bound_manager_at(text)'), ('private.partner_bound_staff_any()'),
                              ('private.offline_code_record_step_for_actor(uuid, integer, bigint, text)'), ('private.offline_seed_derive(uuid, uuid, integer)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[],
  'X9: the writer, the same-device rule, the three predicates, the 0045 recorder and the seed derivation are executable by no client, edge or owner role');
SELECT is((SELECT p.proacl::text FROM pg_proc p WHERE p.oid = 'private.partner_attest_write(uuid, text, uuid, text, text, text, boolean, boolean, timestamptz, timestamptz)'::regprocedure), '{private_definer=X/private_definer}', 'the writer''s ACL is its owner alone');
SELECT is((SELECT pg_get_function_result('private.partner_offline_attest_for_partner(text, text, text, text)'::regprocedure)), 'TABLE(o_status text, o_attestation_id uuid, o_held boolean)',
  'AT(12): the verify-and-record definer RETURNS a status, an attestation id and a held flag: no seed, no expected code, no device, no step');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname IN ('partner_attest_for_partner', 'partner_offline_attest_for_partner', 'partner_shift_log_for_partner', 'partner_staff_activity_for_partner', 'partner_attest_write', 'partner_attest_same_device')
           AND p.pronamespace = 'private'::regnamespace AND strpos(p.prosrc, chr(36)) > 0), 0, 'check 14 (a0): no new body holds a dollar sign');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'offline_seed_key'), 1, 'K: still exactly ONE function names the key (the derivation): the verify-and-record definer calls it, never reads the key');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname = 'partner_offline_attest_for_partner' AND p.prosrc ~* 'return query select [^;]*(seed|expected)'), 0,
  'AT(12): no RETURN QUERY in the verify-and-record body names a seed or an expected code');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.offline_code_step', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.offline_code_step', 'DELETE,TRUNCATE')
              OR has_any_column_privilege(r.n, 'app.attestation', 'INSERT,UPDATE')), 0, 'no edge role holds a privilege on the replay table or can write an attestation (the definers are the only path)');
-- the independent vector: (player_a, device 1, version 1, step 2955000) under the harness K, computed outside the database
SET LOCAL ROLE private_definer;
SELECT is(encode(private.offline_seed_derive('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1), 'hex'), '2d988728fd23990c3cc25fa7ca0125d4d7b163fb469b03cd6cf59e6b9738e6c3', 'vector: the seed (outside the database)');
SELECT is(private.hotp(private.offline_seed_derive('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1), 2955000, 6, 'sha256'), '659955', 'vector: the code at step 2955000 (outside the database)');
SELECT is(private.hotp(private.offline_seed_derive('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1), 1, 6, 'sha256'), '574060', 'vector: the code at step 1 (outside the database)');
RESET ROLE;
SELECT is(pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, 2955000), '659955', 'the independent SQL implementation in this file agrees with the outside vector');

-- ----------------------------------------------------------------------------
-- 2. AT(1) and check 14 (a): scope, role and class. Each call raises 42501 under a partner binding with no scope.
-- ----------------------------------------------------------------------------
SAVEPOINT sc1;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', '34200000-0000-0000-0000-000000000001')$$, '42501', 'partner_authorize: no scope', 'AT(1): staff at Y attests at X: 42501');
SELECT throws_ok($$SELECT * FROM private.partner_offline_attest_for_partner('fac_x', 'presence', 'player_b', '123456')$$, '42501', 'partner_authorize: no scope', 'AT(1): staff at Y verifies an offline code at X: 42501');
SELECT throws_ok($$SELECT * FROM private.partner_shift_log_for_partner('fac_x')$$, '42501', 'partner_authorize: no scope', 'the shift log of another facility: 42501');
SELECT throws_ok($$SELECT * FROM private.partner_staff_activity_for_partner('fac_x', 7)$$, '42501', NULL, 'staff-activity: staff at Y cannot read X');
RESET ROLE;
ROLLBACK TO SAVEPOINT sc1;
SAVEPOINT sc2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', '34200000-0000-0000-0000-000000000001')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'AT(1): class A1: no PIN grant, no attestation');
SELECT throws_ok($$SELECT * FROM private.partner_offline_attest_for_partner('fac_x', 'presence', 'player_b', '123456')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'class A1: no PIN grant, no offline verification');
SELECT throws_ok($$SELECT * FROM private.partner_staff_activity_for_partner('fac_x', 7)$$, '42501', 'partner_authorize: no scope', 'plan line 843: staff must NOT read staff_activity');
RESET ROLE;
ROLLBACK TO SAVEPOINT sc2;
SAVEPOINT sc3;
SELECT pg_temp.seed_step('op', '{"pin_grant_s": 50, "mfa_s": 120}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', '34200000-0000-0000-0000-000000000001')$$, '42501', NULL, 'AT(1): an operator cannot attest (the roles are staff and manager, by explicit array)');
SELECT throws_ok($$SELECT * FROM private.partner_shift_log_for_partner('fac_x')$$, '42501', NULL, 'an operator cannot read the player-level shift log (the old view: staff and managers only)');
SELECT is((SELECT count(*)::int FROM private.partner_staff_activity_for_partner('fac_x', 7)) > 0, true, 'the operator whose trail covers fac_x reads staff_activity');
RESET ROLE;
ROLLBACK TO SAVEPOINT sc3;
SAVEPOINT sc4;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT is((SELECT count(*)::int FROM private.partner_staff_activity_for_partner('fac_x', 7)) > 0, true, 'a manager reads staff_activity');
SELECT throws_ok($$SELECT * FROM private.partner_staff_activity_for_partner('fac_x', 0)$$, '22023', NULL, 'a window of 0 days is refused');
SELECT throws_ok($$SELECT * FROM private.partner_staff_activity_for_partner('fac_x', 91)$$, '22023', NULL, 'a window of 91 days is refused');
SELECT throws_ok($$SELECT * FROM private.partner_staff_activity_for_partner(NULL, 7)$$, '22023', NULL, 'no facility: refused');
RESET ROLE;
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid = 'app.staff_activity'::regclass AND a.attnum > 0 AND NOT a.attisdropped),
          ARRAY['staff_user_id', 'facility_id', 'day', 'attests', 'activations', 'anomalies'], 'control: staff_activity has no player column to leak');
ROLLBACK TO SAVEPOINT sc4;

-- ----------------------------------------------------------------------------
-- 3. AT(2) the online path
-- ----------------------------------------------------------------------------
SAVEPOINT on1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000001'), 'ok|false', 'AT(2): the online attest by a staff member at the facility of the token');
SELECT is((SELECT a.player_user_id::text || '|' || a.staff_user_id::text || '|' || a.kind::text || '|' || a.cosignal_ok::text FROM app.attestation a WHERE a.token_jti = '34200000-0000-0000-0000-000000000001'),
          '00000000-0000-0000-0000-00000000000b|00000000-0000-0000-0000-1000000000a1|presence|false', 'the player is the OWNER OF THE TOKEN (never named by the caller), the staff member the bound member, no co-signal claimed');
SELECT is((SELECT count(*)::int FROM app.attestation_shift_log l WHERE l.facility_id = 'fac_x' AND l.player_handle_snapshot = 'player_b' AND l.staff_handle LIKE 'staff-%'), 1, 'one shift-log row: the player''s handle snapshot, a derived staff handle');
SELECT is((SELECT a.attests FROM app.staff_activity a WHERE a.staff_user_id = '00000000-0000-0000-0000-1000000000a1' AND a.facility_id = 'fac_x' ORDER BY a.day DESC LIMIT 1), 2, 'staff_activity counted it (the fixture row had 1)');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = '00000000-0000-0000-0000-00000000000b'), 0, 'a presence attestation writes no purchase');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.attest'), 1, 'one audit row, carrying no player id');
SELECT is((SELECT (detail::text !~ '00000000-0000-0000-0000-00000000000b') FROM app.audit_log WHERE action = 'partner.attest'), true, 'the audit detail names no player');
-- the PIN grant was consumed by the attest (single use): a second call without a new grant is refused
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', '34200000-0000-0000-0000-000000000002')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'one PIN, one attest: the grant is consumed');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000001'), 'replayed|false', 'AT(2): the same token again is `replayed` (a status the handler maps to 409)');
SELECT is((SELECT count(*)::int FROM app.attestation a WHERE a.token_jti = '34200000-0000-0000-0000-000000000001'), 1, '... and one attestation row stands');
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000002'), 'ok|false', 'a token with no facility (a prefetched one) is accepted at the staff member''s facility');
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000003'), 'token_invalid|false', 'an EXPIRED token');
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000004'), 'token_invalid|false', 'a token issued for ANOTHER facility');
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-0000000000ff'), 'token_invalid|false', 'an unknown token: the same one answer (no oracle on which of the three it was)');
SELECT is(pg_temp.onl('sx', 'fac_x', 'marker_purchase', '34200000-0000-0000-0000-000000000008'), 'token_invalid|false', 'the App Store review (demo) account is never attested: the same one answer');
SELECT is((SELECT count(*)::int FROM app.attestation WHERE player_user_id = '00000000-0000-0000-0000-5000000000e0') + (SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = '00000000-0000-0000-0000-5000000000e0'), 0, '... and nothing was written for it');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'demo_player', '123456'), 'verification_failed|false', 'the review account''s handle on the offline path: the same one answer as an unknown handle');
ROLLBACK TO SAVEPOINT on1;
-- malformed arguments
SAVEPOINT on2;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'offer_redemption', '34200000-0000-0000-0000-000000000001')$$, '22023', NULL, 'a kind other than presence or marker_purchase is refused (offers-redeem is not this slice)');
RESET ROLE;
ROLLBACK TO SAVEPOINT on2;
SAVEPOINT on3;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', NULL)$$, '22023', NULL, 'a NULL token is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT on3;
-- AT(16) part one: self-attest, per ACCOUNT
SAVEPOINT self1;
SELECT pg_temp.seed_step('pa', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_pa');
SELECT throws_ok($$SELECT * FROM private.partner_attest_for_partner('fac_x', 'presence', '34200000-0000-0000-0000-000000000006')$$, '22023', 'self_attestation_refused: a staff member cannot attest their own account', 'AT(16): a staff member attests their OWN account through its own token: 22023');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.attestation WHERE staff_user_id = '00000000-0000-0000-0000-00000000000a'), 0, '... and nothing was written');
ROLLBACK TO SAVEPOINT self1;

-- marker purchase: pending with cosignal.awaiting (the S2a seam), one row per eligible trail; held on the same-device rule
SAVEPOINT mp1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'marker_purchase', '34200000-0000-0000-0000-000000000001'), 'ok|false', 'a marker purchase by staff scan');
SELECT is((SELECT p.method::text || '|' || p.status::text || '|' || p.offline::text || '|' || p.ref_id || '|' || (p.cosignal #>> '{awaiting,until}' IS NOT NULL)::text FROM app.purchase_evidence p WHERE p.user_id = '00000000-0000-0000-0000-00000000000b'),
          'staff_scan|pending|false|token:34200000-0000-0000-0000-000000000001|true', 'the purchase is PENDING with a co-signal window (a marker purchase alone credits nothing)');
SELECT is((SELECT c.status::text FROM app.marker_credit c WHERE c.user_id = '00000000-0000-0000-0000-00000000000b'), 'pending', 'the credit is pending');
SELECT is((SELECT ((p.cosignal #>> '{awaiting,to}')::timestamptz - (p.cosignal #>> '{awaiting,from}')::timestamptz) FROM app.purchase_evidence p WHERE p.user_id = '00000000-0000-0000-0000-00000000000b'), interval '30 minutes',
          'the window is 30 minutes around the scan');
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = '00000000-0000-0000-0000-00000000000b'), 0, 'AT(4) holds: a staff scan creates no play');
ROLLBACK TO SAVEPOINT mp1;
SAVEPOINT mp2;
SELECT pg_temp.seed_step('sy', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
RESET ROLE;
SELECT is(pg_temp.onl('sy', 'fac_y', 'marker_purchase', '34200000-0000-0000-0000-000000000004'), 'no_programme|false', 'a facility with no accepted programme row writes NOTHING (a status, before any write)');
SELECT is((SELECT count(*)::int FROM app.attestation WHERE token_jti = '34200000-0000-0000-0000-000000000004'), 0, '... no attestation either');
ROLLBACK TO SAVEPOINT mp2;

-- AT(15): the same-device rule
SAVEPOINT sd1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'marker_purchase', '34200000-0000-0000-0000-000000000005'), 'ok|true', 'AT(15): the player''s device shares a DeviceCheck token with the staff member''s own: the attest completes, HELD');
SELECT is((SELECT p.status::text || '|' || (p.cosignal IS NULL)::text FROM app.purchase_evidence p WHERE p.user_id = '00000000-0000-0000-0000-00000000000b'), 'held_review|true', 'the purchase is held_review with no co-signal window');
SELECT is((SELECT c.status::text FROM app.marker_credit c WHERE c.user_id = '00000000-0000-0000-0000-00000000000b'), 'held_review', 'the credit is held_review');
SELECT is((SELECT count(*)::int FROM app.fraud_signal f WHERE f.kind = 'same_device_attest' AND f.user_id = '00000000-0000-0000-0000-00000000000b' AND f.cleared_at IS NULL), 1, 'a same_device_attest fraud_signal is open for the player');
SELECT is((SELECT jsonb_array_length(a.anomalies) > 0 FROM app.staff_activity a WHERE a.staff_user_id = '00000000-0000-0000-0000-1000000000a1' AND a.facility_id = 'fac_x' ORDER BY a.day DESC LIMIT 1), true, 'the anomaly shows in the staff member''s activity');
ROLLBACK TO SAVEPOINT sd1;
SAVEPOINT sd2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'marker_purchase', '34200000-0000-0000-0000-000000000001'), 'ok|false', 'control: a player whose device shares nothing with the staff member is not held');
SELECT is((SELECT count(*)::int FROM app.fraud_signal f WHERE f.kind = 'same_device_attest'), 0, '... and no signal opens');
ROLLBACK TO SAVEPOINT sd2;

-- the cold-start cap: a member under 7 days old, 30 attestations in 24 hours
SAVEPOINT cs1;
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET created_at = now() - interval '1 day' WHERE user_id = '00000000-0000-0000-0000-1000000000a1';
INSERT INTO app.attestation (facility_id, staff_user_id, staff_pseudonym, staff_pseudonym_hmac_id, player_user_id, player_pseudonym, player_pseudonym_hmac_id, kind, token_jti)
SELECT 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'sp', 'a0000000-1111-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'pp', 'a0000000-1111-0000-0000-000000000001', 'presence', 'cold-' || g
FROM generate_series(1, 30) g;
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000001'), 'cold_start_cap|false', 'AT(15): a new member (1 day) with 30 attestations in 24 hours is capped (a status)');
ROLLBACK TO SAVEPOINT cs1;
SAVEPOINT cs2;
SET LOCAL ROLE service_role;
INSERT INTO app.attestation (facility_id, staff_user_id, staff_pseudonym, staff_pseudonym_hmac_id, player_user_id, player_pseudonym, player_pseudonym_hmac_id, kind, token_jti)
SELECT 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'sp', 'a0000000-1111-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'pp', 'a0000000-1111-0000-0000-000000000001', 'presence', 'cold-' || g
FROM generate_series(1, 30) g;
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.onl('sx', 'fac_x', 'presence', '34200000-0000-0000-0000-000000000001'), 'ok|false', 'control: the same count for a member of 60 days is not capped');
ROLLBACK TO SAVEPOINT cs2;

-- ----------------------------------------------------------------------------
-- 4. AT(12) / AT(13): the offline code, verified and recorded in the database
-- ----------------------------------------------------------------------------
SAVEPOINT of1;
SET LOCAL ROLE service_role;
UPDATE app.device SET last_seen = now() WHERE id = '20000000-0000-0000-0000-000000000001';
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'ok|false', 'AT(12): the code of the CURRENT step verifies and records');
SELECT is((SELECT s.user_id::text || '|' || s.device_id::text || '|' || s.seed_version::text || '|' || s.facility_id FROM app.offline_code_step s WHERE s.step = pg_temp.now_step()),
          '00000000-0000-0000-0000-00000000000a|20000000-0000-0000-0000-000000000001|1|fac_x', 'the replay row: the player, the matched device, the version, the facility');
SELECT is((SELECT a.token_jti FROM app.attestation a WHERE a.player_user_id = '00000000-0000-0000-0000-00000000000a' AND a.staff_user_id = '00000000-0000-0000-0000-1000000000a1' AND a.token_jti LIKE 'offline:%'),
          'offline:20000000-0000-0000-0000-000000000001:1:' || pg_temp.now_step()::text, 'the attestation is keyed on the (device, version, step) it consumed');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'replayed|false',
          'AT(13): the SAME code step again is `replayed` (the 409), and writes no second attestation');
SELECT is((SELECT count(*)::int FROM app.attestation a WHERE a.token_jti LIKE 'offline:%'), 1, '... one attestation');
SELECT is((SELECT coalesce(sum(r.count), 0)::int FROM private.rate_limit_bucket r WHERE r.bucket_key = 'offline-code-fail:staff:00000000-0000-0000-0000-1000000000a1'), 1, 'a replay is a FAILED verification and counts against the staff member');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step() + 1)), 'ok|false', '+1 step is accepted');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step() - 1)), 'ok|false', '-1 step is accepted');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step() + 2)), 'verification_failed|false', '+2 steps is refused');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 2, pg_temp.now_step())), 'verification_failed|false', 'a code of ANOTHER seed version (a rotation) is refused');
ROLLBACK TO SAVEPOINT of1;

SAVEPOINT of2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', '000000'), 'verification_failed|false', 'a wrong code');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'no_such_handle', '000000'), 'verification_failed|false', 'an UNKNOWN handle: the same one answer as a wrong code');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', '12345'), 'verification_failed|false', 'a malformed code: the same answer, counted');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'Player A!', '123456'), 'verification_failed|false', 'a malformed handle: the same answer, counted');
SELECT is((SELECT coalesce(sum(r.count), 0)::int FROM private.rate_limit_bucket r WHERE r.bucket_key = 'offline-code-fail:staff:00000000-0000-0000-0000-1000000000a1'), 4, 'every failure was counted against the STAFF member (4)');
SELECT is((SELECT coalesce(sum(r.count), 0)::int FROM private.rate_limit_bucket r WHERE r.bucket_key = 'offline-code-fail:target-h:00000000-0000-0000-0000-00000000000a'), 2, 'and against the TARGET player when the handle resolved (2: the wrong code and the malformed code)');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', '000001'), 'verification_failed|false', 'the 5th failure is still evaluated');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'rate_limited|false',
          'SP13: after 5 failures an hour the 6th attempt is refused EVEN WITH THE RIGHT CODE');
SELECT is((SELECT count(*)::int FROM app.attestation a WHERE a.token_jti LIKE 'offline:%'), 0, '... nothing was recorded');
ROLLBACK TO SAVEPOINT of2;

-- the per-target counter holds across staff accounts (a second and third account start fresh staff counters)
SAVEPOINT of3b;
SET LOCAL ROLE service_role;
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count)
VALUES ('offline-code-fail:target-h:00000000-0000-0000-0000-00000000000a', to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600), 10);
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.off('mx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'rate_limited|false',
          'SP13 NIT-2: 10 failures an hour against ONE target across all staff: a fresh staff account with the RIGHT code is refused');
ROLLBACK TO SAVEPOINT of3b;
SAVEPOINT of3c;
SET LOCAL ROLE service_role;
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count)
VALUES ('offline-code-fail:target-d:00000000-0000-0000-0000-00000000000a', to_timestamp(floor(extract(epoch FROM now()) / 86400) * 86400), 30);
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.off('mx', 'fac_x', 'presence', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'rate_limited|false', '30 failures a day against one target: refused');
ROLLBACK TO SAVEPOINT of3c;

-- the candidate set: the 5 most recently seen devices of the last 90 days
SAVEPOINT of4;
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, last_seen)
SELECT ('34000000-0000-0000-0000-0000000d0c' || lpad(g::text, 2, '0'))::uuid, '00000000-0000-0000-0000-00000000000b', 'ios', now() - (g || ' hours')::interval FROM generate_series(1, 6) g;
UPDATE app.device SET last_seen = now() - interval '100 days' WHERE id = '34000000-0000-0000-0000-00000000d0b1';
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_b', pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-00000000d0b1', 1, pg_temp.now_step())), 'verification_failed|false',
          'a device unseen for 100 days is not a candidate');
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_b', pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-0000000d0c02', 1, pg_temp.now_step())), 'ok|false',
          'the code of the 2nd most recent device verifies (the definer tries the candidates and takes the match)');
ROLLBACK TO SAVEPOINT of4;
SAVEPOINT of4b;
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, last_seen)
SELECT ('34000000-0000-0000-0000-0000000d0c' || lpad(g::text, 2, '0'))::uuid, '00000000-0000-0000-0000-00000000000b', 'ios', now() - (g || ' hours')::interval FROM generate_series(1, 6) g;
UPDATE app.device SET last_seen = now() - interval '30 days' WHERE id IN ('34000000-0000-0000-0000-00000000d0b1', '34000000-0000-0000-0000-00000000d0b2');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_b', pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-0000000d0c05', 1, pg_temp.now_step())), 'ok|false', 'the 5th most recent device (c05) is the last candidate and verifies');
ROLLBACK TO SAVEPOINT of4b;
SAVEPOINT of4c;
SET LOCAL ROLE service_role;
INSERT INTO app.device (id, user_id, platform, last_seen)
SELECT ('34000000-0000-0000-0000-0000000d0c' || lpad(g::text, 2, '0'))::uuid, '00000000-0000-0000-0000-00000000000b', 'ios', now() - (g || ' hours')::interval FROM generate_series(1, 6) g;
UPDATE app.device SET last_seen = now() - interval '30 days' WHERE id IN ('34000000-0000-0000-0000-00000000d0b1', '34000000-0000-0000-0000-00000000d0b2');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'presence', 'player_b', pg_temp.ref_code('00000000-0000-0000-0000-00000000000b', '34000000-0000-0000-0000-0000000d0c06', 1, pg_temp.now_step())), 'verification_failed|false',
          'the 6th most recent device (c06) is NOT a candidate (5 devices, 15 codes a guess)');
ROLLBACK TO SAVEPOINT of4c;

-- self-attest, offline: the staff member's own handle
SAVEPOINT of5;
SELECT pg_temp.seed_step('pa', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_pa');
SELECT throws_ok($$SELECT * FROM private.partner_offline_attest_for_partner('fac_x', 'presence', 'player_a', '123456')$$, '22023', 'self_attestation_refused: a staff member cannot attest their own account', 'AT(16): a staff member verifies a code for their OWN handle: 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT of5;

-- the offline marker purchase: pending, offline, the step window of the S2a seam
SAVEPOINT of6;
SET LOCAL ROLE service_role;
UPDATE app.device SET last_seen = now() WHERE id = '20000000-0000-0000-0000-000000000001';
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.off('sx', 'fac_x', 'marker_purchase', 'player_a', pg_temp.ref_code('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 1, pg_temp.now_step())), 'ok|false', 'AT(12): an offline marker purchase');
SELECT is((SELECT p.method::text || '|' || p.status::text || '|' || p.offline::text FROM app.purchase_evidence p WHERE p.ref_id LIKE 'offline:%' AND p.user_id = '00000000-0000-0000-0000-00000000000a'), 'staff_scan|pending|true', 'staff_scan, pending, offline = true');
SELECT is((SELECT (p.cosignal #>> '{awaiting,from}')::timestamptz FROM app.purchase_evidence p WHERE p.ref_id LIKE 'offline:%'), to_timestamp(((pg_temp.now_step()) * 600)::double precision) - interval '10 minutes', 'the window starts 10 minutes before the code step');
SELECT is((SELECT (p.cosignal #>> '{awaiting,to}')::timestamptz FROM app.purchase_evidence p WHERE p.ref_id LIKE 'offline:%'), to_timestamp(((pg_temp.now_step()) * 600)::double precision) + interval '20 minutes', 'and ends 20 minutes after it');
ROLLBACK TO SAVEPOINT of6;

-- ----------------------------------------------------------------------------
-- 5. The shift-log read: the old view's rows, a subset of its columns, never another facility's
-- ----------------------------------------------------------------------------
SAVEPOINT sl1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT count(*)::int FROM private.partner_shift_log_for_partner('fac_x')), 1, 'the shift log: the fixture row of fac_x');
SELECT is((SELECT o_player_handle || '|' || o_staff_handle FROM private.partner_shift_log_for_partner('fac_x')), 'player_a|staff_x_handle', 'its handle snapshot and staff handle');
RESET ROLE;
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid = 'api.staff_shift_log'::regclass AND a.attnum > 0 AND NOT a.attisdropped),
          ARRAY['id', 'facility_id', 'created_at', 'kind', 'player_handle_snapshot', 'player_pseudonym', 'staff_handle'], 'control: the old view carried exactly these seven columns');
SELECT is((SELECT pg_get_function_result('private.partner_shift_log_for_partner(text)'::regprocedure)),
          'TABLE(o_id uuid, o_facility_id text, o_created_at timestamp with time zone, o_kind app.attestation_kind, o_player_handle text, o_staff_handle text)',
          'the read returns six of them and NOT the player''s pseudonym: a subset, never more than the old view');
ROLLBACK TO SAVEPOINT sl1;
SAVEPOINT sl2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT is((SELECT count(*)::int FROM private.partner_shift_log_for_partner('fac_x')), 1, 'a manager reads it too');
RESET ROLE;
ROLLBACK TO SAVEPOINT sl2;

-- ----------------------------------------------------------------------------
-- 6. The binding-keyed policies: closed without a partner binding, under another binding, and not opened by a planted GUC
-- ----------------------------------------------------------------------------
SAVEPOINT pol1;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$INSERT INTO app.attestation (facility_id, staff_user_id, staff_pseudonym, staff_pseudonym_hmac_id, player_user_id, player_pseudonym, player_pseudonym_hmac_id, kind, token_jti)
  VALUES ('fac_x', '00000000-0000-0000-0000-1000000000a1', 'sp', 'a0000000-1111-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'pp', 'a0000000-1111-0000-0000-000000000001', 'presence', 'no-binding')$$,
  '42501', NULL, 'private_definer with NO binding cannot insert an attestation (the policy is keyed on the partner binding)');
SELECT is((SELECT count(*)::int FROM app.checkin_token), 0, 'private_definer with no binding sees no check-in token');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = '00000000-0000-0000-0000-00000000000b'), 0, 'private_definer with no binding sees no player device');
SELECT is((SELECT count(*)::int FROM app.profile WHERE handle = 'player_b'), 0, 'private_definer with no binding resolves no handle');
RESET ROLE;
ROLLBACK TO SAVEPOINT pol1;
SAVEPOINT pol2;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1'::uuid);
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.checkin_token), 0, 'under a USER binding of a staff member the partner token policy is closed');
SELECT is((SELECT count(*)::int FROM app.profile WHERE handle = 'player_b'), 0, 'and so is the profile policy');
RESET ROLE;
ROLLBACK TO SAVEPOINT pol2;
SAVEPOINT pol3;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sy');
SELECT bool_and(set_config(g, '34000000-0000-0000-0000-00000000d0b1', true) IS NOT NULL) AS planted
FROM unnest(ARRAY['app.offline_code.target_device_id', 'app.delete_my_data.target_user_id', 'app.guard.play_id', 'app.guard.offer_code_id', 'app.guard.entitlement_id']) g \gset
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.offline_code_step), 0, 'a planted device GUC opens nothing on the replay table under a partner binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT pol3;

-- ----------------------------------------------------------------------------
-- 7. Registries and the one-step guarantee
-- ----------------------------------------------------------------------------
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name IN (
  'pd_partner_attest_insert', 'pd_partner_attest_select', 'pd_partner_attest_nonce_insert', 'pd_partner_attest_nonce_select', 'pd_partner_shift_log_insert', 'pd_partner_shift_log_select',
  'pd_partner_staff_activity_insert', 'pd_partner_staff_activity_update', 'pd_partner_staff_activity_select', 'pd_partner_attest_profile_select', 'pd_partner_attest_token_select',
  'pd_partner_attest_device_select', 'pd_partner_offline_step_insert', 'pd_partner_offline_step_select', 'pd_partner_offline_step_prune', 'pd_partner_offline_step_prune_r', 'pd_partner_attest_purchase_insert',
  'pd_partner_attest_purchase_select', 'pd_partner_attest_credit_insert', 'pd_partner_attest_fraud_insert', 'pd_partner_attest_facility_read', 'pd_partner_attest_trail_programme_read')), 22, 'all 22 policies of 0056 are registered in definer_policy_allowlist');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname IN ('pd_partner_attest_insert', 'pd_partner_attest_select', 'pd_partner_attest_nonce_insert', 'pd_partner_attest_nonce_select', 'pd_partner_shift_log_insert', 'pd_partner_shift_log_select',
  'pd_partner_staff_activity_insert', 'pd_partner_staff_activity_update', 'pd_partner_staff_activity_select', 'pd_partner_attest_profile_select', 'pd_partner_attest_token_select',
  'pd_partner_attest_device_select', 'pd_partner_offline_step_insert', 'pd_partner_offline_step_select', 'pd_partner_offline_step_prune', 'pd_partner_offline_step_prune_r', 'pd_partner_attest_purchase_insert',
  'pd_partner_attest_purchase_select', 'pd_partner_attest_credit_insert', 'pd_partner_attest_fraud_insert', 'pd_partner_attest_facility_read', 'pd_partner_attest_trail_programme_read') AND pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'private_definer')]
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'current_setting'), 0, 'none of the 0056 policies reads a setting: no GUC window');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname IN ('pd_partner_attest_insert', 'pd_partner_attest_select', 'pd_partner_shift_log_insert', 'pd_partner_attest_token_select', 'pd_partner_attest_device_select')
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'partner_binding_kind'), 5, 'each of them is keyed on the partner binding kind');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('partner_attest_for_partner', 'partner_offline_attest_for_partner', 'partner_shift_log_for_partner', 'partner_staff_activity_for_partner') AND expected_edge_partner), 4, 'the four partner functions are in function_inventory as edge_partner');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname IN ('attestation', 'attestation_shift_log', 'staff_activity', 'offline_code_step') AND c.relrowsecurity AND c.relforcerowsecurity), 4,
          'FORCE ROW LEVEL SECURITY is still on every table the definers write');

SELECT * FROM finish();
ROLLBACK;
