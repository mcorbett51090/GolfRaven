-- 28_partner_pin_step_up.sql
-- P5.1a S1.3 (0052): THE PARTNER STEP-UP PIN, from docs/security/partner-auth-design.md section 12.1 "S1.3": PA-18 (the verifier is not a function of the PIN alone; five failures lock and the sixth CORRECT attempt is still
-- refused; the lock survives a new session; the counters are a returned STATUS), PA-19 (a PIN grant is single-use and session-bound; A1 and A2 refuse outside their prerequisites; A3 and the PIN-less substitution
-- are covered in 31_partner_totp_aal2.sql after S1.4) and PA-21 (a PIN is set or changed only inside an enrolment window or after an email proof: a passkey assertion alone is refused), plus the OTP-proof definers, the
-- check-14 (a) behavioural cells of the six new `_for_partner` definers, the OR rule on partner_pin (a planted GUC opens nothing under a partner binding) and account deletion.
--
-- WHAT A pgTAP FILE CANNOT SHOW, AND WHERE IT IS SHOWN: that a refusal's TRANSACTION COMMITS (the counters after a REAL commit), and that 20 CONCURRENT wrong attempts evaluate at most 5 (a row lock needs two connections):
-- tools/db/test-partner-serialisation.sh (case 7) and supabase/tests/integration/partner-pin.deno.test.ts. The deny-list is NOT a database matter (the PIN never reaches the server): supabase/tests/unit/partner-pin-contract.test.ts.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end. The partner tables are FORCE RLS with no policy for the harness role, so fixtures are written and read through a temporary CURRENT_USER policy (the 0016 / 0045
-- seeding pattern). Every scenario that needs a clean binding runs inside a SAVEPOINT that is rolled back (a second bind in one transaction is itself refused). A verifier is seeded by an independent implementation
-- (pg_temp.vf, plus ONE vector computed OUTSIDE the database), so the real set / verify definers are checked against something other than themselves.
--
-- Principals are helpers.sql's: staff_x (a1: staff at fac_x), manager_x (b1), staff_y (a3), operator_t (c1), admin (d0).

\set QUIET 1
BEGIN;
SELECT plan(204);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, partner_pin_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_pin TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz28_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz28_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz28_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz28_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s28:' || p_label) || md5('s28b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c28:' || p_label) || md5('c28b:' || p_label), 'hex'), decode(md5('k28:' || p_label) || md5('k28b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1, p_mint_kind text DEFAULT 'sign_in', p_enrol interval DEFAULT NULL) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature, enrolment_until)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', p_mint_kind,
          decode(md5('n28:' || p_label) || md5('n28b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'),
          CASE WHEN p_mint_kind = 'sign_in' THEN decode(repeat('05', 70), 'hex') END, now() + p_enrol)
  RETURNING id
$f$;
-- the verifier an INDEPENDENT implementation computes (the migration's is private.partner_pin_core): HMAC-SHA256(pepper, label || 0x00 || user (16) || derived (32))
CREATE FUNCTION pg_temp.vf(p_uid uuid, p_derived bytea) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(convert_to('golfraven/partner-pin/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_uid::text, '-', ''), 'hex') || p_derived,
                     convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper'), 'UTF8'), 'sha256')
$f$;
-- a PIN row for a person, with the verifier of `p_derived`; p_opts overrides the counters
CREATE FUNCTION pg_temp.seed_pin(p_uid uuid, p_derived bytea, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, failed_day, last_failed_at, next_attempt_at, locked_at, must_change)
  VALUES (p_uid, decode(repeat('0a', 16), 'hex'), 600000, pg_temp.vf(p_uid, p_derived),
          coalesce((p_opts ->> 'failed_count')::smallint, 0), coalesce((p_opts ->> 'failed_today')::smallint, 0), (p_opts ->> 'failed_day')::date, NULL,
          (p_opts ->> 'next_attempt_at')::timestamptz, (p_opts ->> 'locked_at')::timestamptz, coalesce((p_opts ->> 'must_change')::boolean, false))
$f$;
-- step-up state a session cannot be BORN with: the guard is off for the seeding only
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = CASE WHEN p_cols ? 'pin_grant_s' THEN clock_timestamp() + ((p_cols ->> 'pin_grant_s')::numeric * interval '1 second') ELSE s.pin_grant_until END,
    reauth_until = CASE WHEN p_cols ? 'reauth_s' THEN clock_timestamp() + ((p_cols ->> 'reauth_s')::numeric * interval '1 second') ELSE s.reauth_until END,
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END,
    enrolment_until = CASE WHEN p_cols ? 'enrol_s' THEN clock_timestamp() + ((p_cols ->> 'enrol_s')::numeric * interval '1 second') ELSE s.enrolment_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;

-- the partner lane's calls, as edge_partner, inside a binding the caller made; each returns 'status|retry_after' (verify, set, change) so one cell shows both
CREATE FUNCTION pg_temp.pv(p_derived bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_verify_for_partner(p_derived);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after || '|' || (r.o_grant_until IS NOT NULL)::text;
END
$f$;
CREATE FUNCTION pg_temp.pset(p_derived bytea, p_salt bytea DEFAULT NULL, p_iters int DEFAULT 600000) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_set_for_partner(p_derived, coalesce(p_salt, decode(repeat('0b', 16), 'hex')), p_iters);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.pchg(p_current bytea, p_derived bytea, p_salt bytea DEFAULT NULL, p_iters int DEFAULT 600000) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_pin_change_for_partner(p_current, p_derived, coalesce(p_salt, decode(repeat('0c', 16), 'hex')), p_iters);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;

-- a test-only *_for_partner definer so the authorization seam can be driven with a chosen class
GRANT CREATE ON SCHEMA private TO private_definer;
SET LOCAL ROLE private_definer;
CREATE FUNCTION private.zz28_authz_for_partner(p_fac text, p_trail text, p_roles text[], p_class text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RETURN private.partner_authorize(p_fac, p_trail, p_roles::app.partner_role[], p_class);
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz28_authz_for_partner(text, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.zz28_authz_for_partner(text, text, text[], text) TO edge_partner, edge_actor;
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- principals: credentials and sessions
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sx2', '00000000-0000-0000-0000-1000000000a1') AS c_sx2 \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sx2', '00000000-0000-0000-0000-1000000000a1', :'c_sx2') AS s_sx2 \gset
SELECT pg_temp.mk_session('sx_reg', '00000000-0000-0000-0000-1000000000a1', :'c_sx', 1, 'register', interval '10 minutes') AS s_sx_reg \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('op1', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op1 \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sx2') AS th_sx2, pg_temp.th('sx_reg') AS th_sx_reg, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('op1') AS th_op1, pg_temp.th('ad') AS th_ad \gset
SELECT '\x' || repeat('11', 32) AS dk_ok, '\x' || repeat('22', 32) AS dk_bad, '\x' || repeat('33', 32) AS dk_new, '\x' || repeat('44', 32) AS dk_new2 \gset
SELECT '\x' || repeat('0a', 16) AS salt_a, '\x' || repeat('0b', 16) AS salt_b, '\x' || repeat('0c', 16) AS salt_c \gset

-- ----------------------------------------------------------------------------
-- 1. Structure: who can execute and touch what, and nothing else
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN (
  'private.partner_pin_params_for_partner()'::regprocedure, 'private.partner_pin_verify_for_partner(bytea)'::regprocedure, 'private.partner_pin_set_for_partner(bytea, bytea, integer)'::regprocedure,
  'private.partner_pin_change_for_partner(bytea, bytea, bytea, integer)'::regprocedure, 'private.partner_session_otp_target_for_partner()'::regprocedure, 'private.partner_session_otp_proof_for_partner(uuid)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole), 6, 'PA-13b: the six edge_partner functions of 0052 are SECURITY DEFINER with search_path = '''', owned by private_definer');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'), ('partner_pin_verifier')) r(n)
           CROSS JOIN (VALUES ('private.partner_pin_params_for_partner()'), ('private.partner_pin_verify_for_partner(bytea)'), ('private.partner_pin_set_for_partner(bytea, bytea, integer)'),
                              ('private.partner_pin_change_for_partner(bytea, bytea, bytea, integer)'), ('private.partner_session_otp_target_for_partner()'), ('private.partner_session_otp_proof_for_partner(uuid)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), ARRAY['edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner', 'edge_partner'],
  'PA-13b: of every client, edge and owner role, ONLY edge_partner can execute any of the six (not edge_actor, not the minter, not partner_pin_verifier)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.partner_pin_attempt(uuid, bytea)'::regprocedure, 'private.partner_pin_verify_apply(bytea)'::regprocedure,
  'private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)'::regprocedure, 'private.partner_pin_params_read()'::regprocedure, 'private.partner_pin_grant_consume_fresh(integer)'::regprocedure)
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'partner_pin_verifier'::regrole), 5,
  'R5-L1: the verify, set, params and attempt definers and the A2 consumer are owned by partner_pin_verifier (the role that holds the ONLY column grant on pin_grant_until)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_reauth_verifier'), ('partner_session_issuer'), ('partner_session_toucher')) r(n)
           CROSS JOIN (VALUES ('private.partner_pin_attempt(uuid, bytea)'), ('private.partner_pin_verify_apply(bytea)'), ('private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)'),
                              ('private.partner_pin_params_read()'), ('private.partner_pin_grant_consume_fresh(integer)'), ('private.partner_pin_core(uuid, bytea, bytea)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[],
  'the verifier internals and the pepper core: no client role, no edge role and no other owner role can execute them');
SELECT is((SELECT array_agg(f.sig ORDER BY f.sig) FROM (VALUES ('private.partner_pin_verify_apply(bytea)'), ('private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)'), ('private.partner_pin_params_read()'), ('private.partner_pin_grant_consume_fresh(integer)'),
                                                           ('private.partner_pin_attempt(uuid, bytea)')) f(sig) WHERE has_function_privilege('private_definer', f.sig::regprocedure, 'EXECUTE')),
  ARRAY['private.partner_pin_grant_consume_fresh(integer)', 'private.partner_pin_params_read()', 'private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)', 'private.partner_pin_verify_apply(bytea)'],
  'private_definer (the wrappers'' owner) executes the four apply / read / consume definers and NOT partner_pin_attempt');
SELECT is((SELECT array_agg(f.sig ORDER BY f.sig) FROM (VALUES ('private.partner_pin_core(uuid, bytea, bytea)'), ('private.partner_binding_user()')) f(sig) WHERE has_function_privilege('partner_pin_verifier', f.sig::regprocedure, 'EXECUTE')),
  ARRAY['private.partner_binding_user()', 'private.partner_pin_core(uuid, bytea, bytea)'], 'partner_pin_verifier executes exactly the pepper core and the binding-user predicate');
-- N1 (S1.3 gate): the FULL ACL, not only "which of the listed roles": the owner holds EXECUTE on its own function, PUBLIC does not, and nobody else does
SELECT is((SELECT array_agg(f.sig || ' -> ' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END || ':' || a.privilege_type || ':' || a.grantor::regrole::text ORDER BY f.sig, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
           FROM (VALUES ('private.partner_pin_core(uuid, bytea, bytea)'), ('private.partner_binding_user()')) f(sig)
           CROSS JOIN LATERAL aclexplode((SELECT p.proacl FROM pg_proc p WHERE p.oid = f.sig::regprocedure)) a),
  ARRAY['private.partner_binding_user() -> partner_pin_verifier:EXECUTE:private_definer', 'private.partner_binding_user() -> partner_session_toucher:EXECUTE:private_definer', 'private.partner_binding_user() -> partner_totp_verifier:EXECUTE:private_definer', 'private.partner_binding_user() -> private_definer:EXECUTE:private_definer',
        'private.partner_pin_core(uuid, bytea, bytea) -> partner_pin_verifier:EXECUTE:private_definer', 'private.partner_pin_core(uuid, bytea, bytea) -> private_definer:EXECUTE:private_definer'],
  'N1: partner_pin_core has exactly two ACL entries (pin verifier + owner); partner_binding_user has four (pin verifier, totp verifier from 0053, the toucher from 0054 for its member-revoke policy, owner); no PUBLIC, no edge role');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_reauth_verifier'), ('partner_session_issuer'), ('partner_session_toucher')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.partner_pin', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.partner_pin', 'DELETE,TRUNCATE,TRIGGER')), 0,
  'PA-1: no client role, no edge role, no service_role and no other owner role holds ANY privilege on app.partner_pin');
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.partner_pin'::regclass), true, 'app.partner_pin has ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT array_agg(c.n ORDER BY c.n) FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) c(n) WHERE has_table_privilege('partner_pin_verifier', 'app.partner_pin', c.n)), ARRAY['INSERT', 'SELECT', 'UPDATE'],
  'partner_pin_verifier holds SELECT, INSERT and UPDATE on the PIN table, and cannot DELETE');
SELECT is((has_column_privilege('private_definer', 'app.partner_pin', 'user_id', 'SELECT'), has_column_privilege('private_definer', 'app.partner_pin', 'verifier', 'SELECT'), has_column_privilege('private_definer', 'app.partner_pin', 'salt', 'SELECT'),
           has_any_column_privilege('private_definer', 'app.partner_pin', 'INSERT,UPDATE'), has_table_privilege('private_definer', 'app.partner_pin', 'DELETE'))::text,
  '(t,f,f,f,t)', 'private_definer holds SELECT (user_id) and DELETE (the delete_my_data window pair) and cannot read the verifier or the salt or write anything');
SELECT is((SELECT array_agg(pol.polname::text || ':' || pol.polcmd::text ORDER BY pol.polname) FROM pg_policy pol WHERE pol.polrelid = 'app.partner_pin'::regclass AND pol.polname NOT LIKE 'zz28%'),
  ARRAY['pd_delete_partner_pin_user_id:d', 'pd_delete_partner_pin_user_id_r:r', 'pd_lastmember_delete_partner_pin:d', 'pd_lastmember_delete_partner_pin_r:r', 'ppv_insert_partner_pin:a', 'ppv_read_partner_pin:r', 'ppv_read_partner_pin_reach:r', 'ppv_update_partner_pin:w', 'ppv_update_partner_pin_reach:w'],
  'the PIN table carries exactly the five registered policies of 0052, the two last-membership delete policies and the two reach-rule policies of 0054');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polrelid = 'app.partner_pin'::regclass AND pol.polname LIKE 'ppv\_%'
           AND (pol.polroles <> ARRAY['partner_pin_verifier'::regrole::oid] OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') ~* 'current_setting|pg_settings' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') ~* 'current_setting|pg_settings'
              OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), pg_get_expr(pol.polwithcheck, pol.polrelid)) NOT LIKE '%partner_binding_user()%')), 0,
  'the OR rule: every verifier policy is TO partner_pin_verifier alone, keyed on the BINDING''s user and reads no settable GUC (nothing here can be planted)');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polrelid = 'app.partner_pin'::regclass AND pol.polname LIKE 'pd\_%' AND pol.polname NOT LIKE 'pd\_lastmember\_%'
           AND (pol.polroles <> ARRAY['private_definer'::regrole::oid] OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') NOT LIKE '%AND (( SELECT private.partner_binding_kind() AS partner_binding_kind) IS DISTINCT FROM ''partner''::text))')), 0,
  'the delete_my_data window pair on the PIN table carries the partner conjunct as its top-level trailing AND (check 15)');
SELECT is((has_column_privilege('private_definer', 'app.partner_session', 'pin_grant_until', 'UPDATE'), has_column_privilege('partner_pin_verifier', 'app.partner_session', 'pin_grant_until', 'UPDATE'),
           has_column_privilege('partner_reauth_verifier', 'app.partner_session', 'pin_grant_until', 'UPDATE'), has_column_privilege('edge_partner', 'app.partner_session', 'pin_grant_until', 'UPDATE'))::text, '(f,t,f,f)',
  'R5-L1: partner_pin_verifier is the ONLY role that can write pin_grant_until (not private_definer, not the reauth verifier, not the edge lane)');
-- MEDIUM-1: the wrappers spend the proof by clearing the column, which only private_definer (0047:329) may write, and only down (0047 guard: "cleared or shortened"). No other role gained the column.
SELECT is((has_column_privilege('private_definer', 'app.partner_session', 'otp_proof_until', 'UPDATE'), has_column_privilege('partner_pin_verifier', 'app.partner_session', 'otp_proof_until', 'UPDATE'),
           has_column_privilege('partner_reauth_verifier', 'app.partner_session', 'otp_proof_until', 'UPDATE'), has_column_privilege('edge_partner', 'app.partner_session', 'otp_proof_until', 'UPDATE'))::text, '(t,f,f,f)',
  'MEDIUM-1: private_definer (the wrappers'' owner) is the only role that can write otp_proof_until: the verifier gained nothing, and the single-use clear is a write the guard allows');
SELECT is(has_function_privilege('edge_partner', 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE')
          OR has_function_privilege('partner_pin_verifier', 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE'), false, 'the authorization seam is still executable by nobody');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('partner_binding_user', 'partner_pin_core', 'partner_pin_attempt', 'partner_pin_verify_apply', 'partner_pin_set_apply', 'partner_pin_params_read',
  'partner_pin_grant_consume_fresh', 'partner_pin_params_for_partner', 'partner_pin_verify_for_partner', 'partner_pin_set_for_partner', 'partner_pin_change_for_partner', 'partner_session_otp_target_for_partner',
  'partner_session_otp_proof_for_partner')), 13, 'registry: all 13 new functions have a function_inventory row');
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name = 'partner_pin' AND column_name = 'user_id' AND action = 'delete_row')
        + (SELECT count(*)::int FROM private.pii_export_policy WHERE table_name = 'partner_pin' AND action = 'exclude'), 2, 'registry: the PIN table is classified for deletion (delete_row) and for export (exclude)');
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. check 14 (a) behavioural cells: every `_for_partner` definer raises 42501 with no binding and under a USER binding
-- ----------------------------------------------------------------------------
SELECT throws_ok($$SELECT * FROM private.partner_pin_params_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_pin_params_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_pin_verify_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_pin_verify_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_pin_set_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_pin_set_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_pin_change_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x2222222222222222222222222222222222222222222222222222222222222222'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_pin_change_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_session_otp_target_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_otp_target_for_partner with NO binding raises 42501');
SELECT throws_ok($$SELECT * FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', '14 (a): partner_session_otp_proof_for_partner with NO binding raises 42501');
SAVEPOINT user_bound;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
SELECT throws_ok($$SELECT * FROM private.partner_pin_params_for_partner()$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_pin_params_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_pin_verify_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_pin_verify_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_pin_set_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_pin_set_for_partner refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): partner_session_otp_proof_for_partner refuses a USER binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT user_bound;
-- the apply definers refuse a call with no partner binding too (a USER binding has no session id): a wrapper that skipped partner_authorize still could not reach the person's row
SAVEPOINT user_bound2;
SET LOCAL ROLE private_definer;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
SELECT throws_ok($$SELECT * FROM private.partner_pin_verify_apply('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_pin_verify_apply: no partner session is bound in this transaction', 'the verify writer refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_pin_set_apply('set', '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000, NULL)$$, '42501', 'partner_pin_set_apply: no partner session is bound in this transaction', 'the set writer refuses a USER binding');
SELECT throws_ok($$SELECT * FROM private.partner_pin_params_read()$$, '42501', 'partner_pin_params_read: no partner session is bound in this transaction', 'the params reader refuses a USER binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT user_bound2;
-- the assurance gate: an aal 1 OPERATOR is refused the A0 step-up calls (S1.4 adds the aal 1 exception for the TOTP-less)
SAVEPOINT op_aal1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT throws_ok($$SELECT * FROM private.partner_pin_verify_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-20 shape: partner_pin_verify_for_partner is class A0_WRITE: an aal 1 OPERATOR session is refused');
-- S1.4 reclassed otp-proof to A0_ENROL: an aal 1 operator with no confirmed TOTP may reach it (PA-28); a bad GoTrue session id is a STATUS, not an aal refusal. Full PA-28 cells are in 31_partner_totp_aal2.sql.
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)), 'refused', 'PA-28 shape (S1.4): otp-proof is A0_ENROL — aal1 operator without confirmed TOTP reaches it; bad GoTrue id → refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT op_aal1;

-- ----------------------------------------------------------------------------
-- 3. PA-18 the verifier: not a function of the PIN alone, computed by the REAL set definer, checked against a vector computed OUTSIDE the database
-- ----------------------------------------------------------------------------
SAVEPOINT setvec;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_reg');
RESET ROLE;
SELECT is(pg_temp.pset(:'dk_ok'::bytea, :'salt_a'::bytea, 600000), 'ok|0', 'PA-18: the first PIN is set through the REAL set definer inside an enrolment window');
SELECT is((SELECT encode(verifier, 'hex') FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'f7ec22b8d9d73175337ffbeda60184417ad5e636b2329e59e50c44ed237286f6',
  'PA-18: the stored verifier equals HMAC-SHA256(shim pepper, label || 0x00 || user || derived) computed OUTSIDE the database (Python hmac): the vector');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea), 'PA-18: ... and the independent in-test implementation agrees');
SELECT isnt((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), sha256(:'dk_ok'::bytea), 'PA-18: the verifier is NOT an unkeyed hash of the derived key (a dump without the Vault pepper verifies nothing)');
SELECT isnt((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea), 'PA-18: ... and not a function of the derived key alone: the SAME key for ANOTHER person gives another verifier (the user id is in the message)');
SELECT is((SELECT salt = :'salt_a'::bytea FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), true, 'the browser''s salt and iteration count are stored as sent');
SELECT is((SELECT iterations FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 600000, '... iterations too');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.pin.set' AND subject_id = '00000000-0000-0000-0000-1000000000a1'), 1, 'a set writes one audit_log row (no secret in it)');
SELECT is((SELECT detail::text FROM app.audit_log WHERE action = 'partner.pin.set' AND subject_id = '00000000-0000-0000-0000-1000000000a1'), '{}', 'PA-18: ... and the row carries no key material');
ROLLBACK TO SAVEPOINT setvec;
-- the pepper IS used: with the pepper changed, the SAME derived key no longer verifies (a mutant that ignored the pepper would still say ok)
SAVEPOINT pepper;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'ok|0|true', 'PA-18: control: the seeded verifier verifies under the shim pepper');
UPDATE vault.secrets SET secret = 'a-different-pepper-of-at-least-32-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' WHERE name = 'partner_pin_pepper';
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'wrong|0|false', 'PA-18: with a DIFFERENT pepper the same derived key is wrong: the verifier depends on the Vault pepper');
ROLLBACK TO SAVEPOINT pepper;
SAVEPOINT pepper_missing;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
DELETE FROM vault.secrets WHERE name = 'partner_pin_pepper';
SELECT throws_ok($$SELECT pg_temp.pv('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '55000', 'partner_pin_core: the partner PIN pepper is not provisioned in Vault', 'a missing pepper is a deploy fault: 55000 (the Edge answers a bare 503), never a pass');
ROLLBACK TO SAVEPOINT pepper_missing;
SAVEPOINT pepper_short;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
UPDATE vault.secrets SET secret = 'too-short' WHERE name = 'partner_pin_pepper';
SELECT throws_ok($$SELECT pg_temp.pv('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '55000', NULL, 'a pepper shorter than 32 bytes is refused (55000)');
ROLLBACK TO SAVEPOINT pepper_short;

-- ----------------------------------------------------------------------------
-- 4. PA-18 the lockout: every outcome a returned STATUS; backoff; five consecutive failures lock; the sixth, CORRECT attempt is still refused; a lock survives a new session
-- ----------------------------------------------------------------------------
SAVEPOINT lock_a;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|0|false', 'PA-18: failure 1: a returned STATUS wrong (no raise), no backoff yet');
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|0|false', 'PA-18: failure 2: wrong, no backoff yet');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 2::smallint, 'PA-18: the counter moved by the refusals (a status: nothing rolled it back)');
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|30|false', 'PA-18: failure 3: wrong, and the NEXT attempt is refused for 30 s');
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'retry_after|30|false', 'PA-18: a CORRECT key inside the 30 s backoff is refused without being evaluated (retry_after)');
SELECT ok((SELECT next_attempt_at > clock_timestamp() + interval '25 seconds' AND next_attempt_at < clock_timestamp() + interval '31 seconds' FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'the 30 s backoff is stored');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 3::smallint, 'a refused-for-backoff attempt is NOT counted');
UPDATE app.partner_pin SET next_attempt_at = clock_timestamp() - interval '1 second' WHERE user_id = '00000000-0000-0000-0000-1000000000a1';
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|300|false', 'PA-18: failure 4 (after the backoff): wrong, and the next attempt is refused for 5 minutes');
SELECT ok((SELECT next_attempt_at > clock_timestamp() + interval '4 minutes 55 seconds' AND next_attempt_at < clock_timestamp() + interval '5 minutes 1 second' FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'the 5 minute backoff is stored');
UPDATE app.partner_pin SET next_attempt_at = clock_timestamp() - interval '1 second' WHERE user_id = '00000000-0000-0000-0000-1000000000a1';
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'locked|0|false', 'PA-18: failure 5: the PIN LOCKS (status locked)');
SELECT is((SELECT (locked_at IS NOT NULL)::text || ',' || failed_count::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'true,5', 'PA-18: locked_at is set and the counter reads 5');
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'locked|0|false', 'PA-18: attempt 6 with the CORRECT key is STILL refused: locked');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 5::smallint, 'PA-18: ... and a refused attempt on a locked PIN moves nothing');
SELECT is((SELECT pin_grant_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'PA-18: a locked PIN sets NO grant');
SELECT is((SELECT array_agg(action ORDER BY action) FROM app.audit_log WHERE subject_id = '00000000-0000-0000-0000-1000000000a1' AND action LIKE 'partner.pin.%'),
          ARRAY['partner.pin.locked', 'partner.pin.wrong', 'partner.pin.wrong', 'partner.pin.wrong', 'partner.pin.wrong'], 'every wrong key and the lock write an audit_log row (four wrong, one lock); the refused attempts on a locked PIN write none');
SELECT is((SELECT detail::text FROM app.audit_log WHERE action = 'partner.pin.locked' AND subject_id = '00000000-0000-0000-0000-1000000000a1'), '{"stage": "verify"}', 'the audit row names the stage and carries no key');
ROLLBACK TO SAVEPOINT lock_a;
-- the lock survives a NEW session of the same member
SAVEPOINT lock_b;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 5, 'locked_at', clock_timestamp()));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx2');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'locked|0|false', 'PA-18: the lock survives a new session (a different credential, a different token): the correct key is refused');
ROLLBACK TO SAVEPOINT lock_b;
-- 20 failures in a (UTC) day lock regardless of the successes in between
SAVEPOINT lock_c;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 2, 'failed_today', 19, 'failed_day', (clock_timestamp() AT TIME ZONE 'UTC')::date));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'locked|0|false', 'PA-18: the 20th failure of the day LOCKS although only 3 were consecutive');
SELECT is((SELECT (locked_at IS NOT NULL)::text || ',' || failed_today::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'true,20', '... and the day counter reads 20');
ROLLBACK TO SAVEPOINT lock_c;
SAVEPOINT lock_d;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 2, 'failed_today', 10, 'failed_day', (clock_timestamp() AT TIME ZONE 'UTC')::date));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'ok|0|true', 'PA-18: a success after 2 failures is ok');
SELECT is((SELECT failed_count::text || ',' || failed_today::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), '0,10', 'PA-18: ... it resets the CONSECUTIVE count and NOT the day count (a success does not forgive the day)');
ROLLBACK TO SAVEPOINT lock_d;
SAVEPOINT lock_e;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 0, 'failed_today', 19, 'failed_day', (clock_timestamp() AT TIME ZONE 'UTC')::date - 1));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|0|false', 'PA-18: the day counter is per UTC day: 19 failures YESTERDAY do not lock on today''s first');
SELECT is((SELECT failed_today::text || ',' || (failed_day = (clock_timestamp() AT TIME ZONE 'UTC')::date)::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), '1,true', '... and the day rolls over to 1');
ROLLBACK TO SAVEPOINT lock_e;
-- unset and must_change are statuses, not errors, and they count nothing
SAVEPOINT st_unset;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'unset|0|false', 'verify with NO PIN row: a status unset');
ROLLBACK TO SAVEPOINT st_unset;
SAVEPOINT st_must;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, '{"must_change": true}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'must_change|0|false', 'a must_change PIN (after a reset) verifies NOTHING, even with the old key: a status must_change');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0::smallint, '... and counts nothing');
ROLLBACK TO SAVEPOINT st_must;
-- the grant a success sets: now + at most 60 s, on THIS session only
SAVEPOINT grant1;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'ok|0|true', 'PA-19: a correct key answers ok and a grant');
SELECT ok((SELECT pin_grant_until > clock_timestamp() + interval '55 seconds' AND pin_grant_until <= clock_timestamp() + interval '60 seconds' FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), 'PA-19: the grant is now + 60 s (the S1.1a guard caps it there)');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE token_hash = pg_temp.th('sx2') AND pin_grant_until IS NOT NULL), 0, 'PA-19: ANOTHER session of the same member (another credential) holds no grant: it is bound to the session that verified');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE pin_grant_until IS NOT NULL), 1, 'PA-19: exactly ONE session of anyone holds a grant');
ROLLBACK TO SAVEPOINT grant1;

-- ----------------------------------------------------------------------------
-- 5. PA-19 the action classes through the seam (a test-only _for_partner definer drives partner_authorize with a chosen class)
-- ----------------------------------------------------------------------------
-- A1: a PIN grant verified in the last 60 s and not yet used; consumed by the action; single use; session-bound
SAVEPOINT a1_single;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'PA-19: A1 with NO PIN verified is refused');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'PA-19 control: A0 needs no grant (the refusal above is the class prerequisite)');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'ok|0|true', 'PA-19: the PIN is verified');
SET LOCAL ROLE edge_partner;
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'PA-19: A1 with a fresh grant passes and returns the member');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'PA-19: the SECOND action needs a SECOND PIN: the grant was consumed (single use)');
RESET ROLE;
SELECT is((SELECT pin_grant_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'PA-19: ... the grant column is cleared by the consumption');
ROLLBACK TO SAVEPOINT a1_single;
-- the grant is bound to the SESSION that verified: a second session of the same member does not inherit it
SAVEPOINT a1_bound;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx2');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'PA-19: a second session of the SAME member does not inherit the first session''s grant');
RESET ROLE;
ROLLBACK TO SAVEPOINT a1_bound;
SAVEPOINT a1_bound2;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'PA-19 control: the session that holds the grant spends it');
RESET ROLE;
ROLLBACK TO SAVEPOINT a1_bound2;
-- an EXPIRED grant, and a grant for the wrong scope
SAVEPOINT a1_exp;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": -1}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'PA-19: an EXPIRED grant (60 s passed) is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a1_exp;
SAVEPOINT a1_scope;
SELECT pg_temp.seed_step('sx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_y', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: no scope', 'PA-19: A1 with a grant but no scope at the facility is refused for the scope (the grant does not widen it)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a1_scope;
-- A2: a PIN grant at most 30 s old AND a passkey assertion at most 5 minutes old; both single use / windowed
SAVEPOINT a2_ok;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50, "reauth_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2'), '00000000-0000-0000-0000-2000000000b1'::uuid, 'PA-19: A2 with a grant 10 s old and a reauth window open PASSES (A2 is ENABLED by S1.3)');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'PA-19: the grant was consumed: a SECOND A2 action is refused (one PIN, one action)');
RESET ROLE;
SELECT is((SELECT reauth_until IS NOT NULL FROM app.partner_session WHERE token_hash = pg_temp.th('mx')), true, 'PA-19: the reauth window is NOT consumed (it is a window: 5 minutes)');
ROLLBACK TO SAVEPOINT a2_ok;
SAVEPOINT a2_noreauth;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required', 'PA-19: A2 with a fresh PIN grant but NO reauth is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_noreauth;
SAVEPOINT a2_nopin;
SELECT pg_temp.seed_step('mx', '{"reauth_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'PA-19: A2 with a reauth window but NO PIN grant is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_nopin;
SAVEPOINT a2_old;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 25, "reauth_s": 240}'::jsonb);   -- a grant minted 35 s ago: valid for A1 (60 s), too old for A2 (30 s)
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'PA-19: A2 needs a grant AT MOST 30 s old: one 35 s old is refused');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A1'), '00000000-0000-0000-0000-2000000000b1'::uuid, 'PA-19 control: the same 35 s old grant is good for A1 (60 s): a refused A2 did not burn it, and the A1 window is the longer one');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_old;
SAVEPOINT a2_edge;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 31, "reauth_s": 240}'::jsonb);   -- minted 29 s ago: inside the 30 s
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2'), '00000000-0000-0000-0000-2000000000b1'::uuid, 'PA-19: a grant 29 s old passes A2 (the boundary is 30 s, not 20)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_edge;
-- N2 (S1.3 gate): the other side of the 30 s boundary, so a boundary that drifted to 35 s (or to 60) is caught from BOTH sides
SAVEPOINT a2_edge31;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 29, "reauth_s": 240}'::jsonb);   -- minted 31 s ago: outside the 30 s
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required', 'PA-19 / N2: a grant 31 s old is REFUSED by A2 (the boundary is 30 s, not 35)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_edge31;
-- LOW-1 (S1.3 gate): class A0_WRITE is A0 in every respect (aal, role list, scope, no PIN grant, no reauth); only the lock mode on the session row differs (FOR NO KEY UPDATE up front: tools/db/test-partner-serialisation.sh case 9)
SAVEPOINT a0w;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT is(private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A0_WRITE'), '00000000-0000-0000-0000-2000000000b1'::uuid, 'LOW-1: A0_WRITE passes for a live session of the right role and scope, with no PIN grant and no reauth required');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, NULL, 'A0_WRITE')$$, '22023', 'partner_authorize: an explicit, non-empty role list without sponsor is required', 'LOW-1: A0_WRITE still demands an explicit role list (it is not a session class)');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_y', NULL, ARRAY['manager'], 'A0_WRITE')$$, '42501', 'partner_authorize: no scope', 'LOW-1: A0_WRITE still enforces scope');
RESET ROLE;
SELECT is((SELECT pin_grant_until IS NOT NULL FROM app.partner_session WHERE token_hash = pg_temp.th('mx')), true, 'LOW-1: A0_WRITE does NOT consume a PIN grant (only A1 and A2 do)');
ROLLBACK TO SAVEPOINT a0w;
SAVEPOINT a0w_aal;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0_WRITE')$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'LOW-1: A0_WRITE still refuses an aal 1 session of an operator (M2)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a0w_aal;
-- the wrappers that WRITE the session row under A0_WRITE (PIN only after 0053): otp-proof / reauth moved to A0_ENROL (PA-28); GET pin stays A0
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE '%\_for\_partner'
           AND regexp_replace(p.prosrc, '--[^\n]*', '', 'g') ~ 'partner_authorize\([^;]*''A0_WRITE''\)'),
  ARRAY['partner_pin_change_for_partner', 'partner_pin_set_for_partner', 'partner_pin_verify_for_partner'],
  'LOW-1: exactly the three PIN wrappers that write the session row use class A0_WRITE (otp-proof and reauth moved to A0_ENROL in 0053)');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE '%\_for\_partner'
           AND regexp_replace(p.prosrc, '--[^\n]*', '', 'g') ~ 'partner_authorize\([^;]*''A0''\)'),
  ARRAY['partner_credential_list_for_partner', 'partner_held_queue_for_partner', 'partner_invite_list_for_partner', 'partner_pin_params_for_partner', 'partner_review_sla_for_partner', 'partner_shift_log_for_partner', 'partner_staff_activity_for_partner'],
  'LOW-1: GET pin stays A0 (read-only; otp-target / reauth options / credential moved to A0_ENROL in 0053), next to the two read-only list definers of 0054, the two read definers of 0056 and the two admin reads of 0057');
SAVEPOINT a2_reauthexp;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50, "reauth_s": -1}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required', 'PA-19: an EXPIRED reauth window (5 minutes passed) is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_reauthexp;
SAVEPOINT a2_scope;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50, "reauth_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_y', NULL, ARRAY['manager'], 'A2')$$, '42501', 'partner_authorize: no scope', 'PA-19: A2 with every prerequisite but NO scope at the facility is refused for the scope');
RESET ROLE;
ROLLBACK TO SAVEPOINT a2_scope;
-- A3 is ENABLED by S1.4 (0053): admin aal2 + fresh mfa_until passes; manager at aal1 still refuses (needs aal2)
SAVEPOINT a3_closed;
SELECT pg_temp.seed_step('ad', '{"pin_grant_s": 50, "reauth_s": 240, "mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is(private.zz28_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A3'), '00000000-0000-0000-0000-4000000000d0'::uuid, 'PA-19 / PA-4b (S1.4): A3 ENABLED — ADMIN at aal 2 with fresh mfa_until passes');
SELECT is(private.zz28_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0'), '00000000-0000-0000-0000-4000000000d0'::uuid, 'control: the same admin passes A0');
RESET ROLE;
ROLLBACK TO SAVEPOINT a3_closed;
SAVEPOINT a3_closed2;
SELECT pg_temp.seed_step('mx', '{"pin_grant_s": 50, "reauth_s": 240, "mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz28_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A3')$$, '42501', 'partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required', 'PA-19: MANAGER at aal1 is refused A3 (needs aal2 + mfa; full A3 cells in 31)');
RESET ROLE;
ROLLBACK TO SAVEPOINT a3_closed2;
-- the A3-for-a-PIN-less-member substitution (S1.4): an OPERATOR with fresh mfa_until (and reauth for A2) passes A1/A2 without a PIN grant
SAVEPOINT pinless;
SELECT pg_temp.seed_step('op', '{"reauth_s": 240, "mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT is(private.zz28_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A1'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'PA-19 (S1.4): PIN-less OPERATOR with fresh mfa_until passes A1 (A3 substitution)');
SELECT is(private.zz28_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A2'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'PA-19 (S1.4): ... and A2 with reauth + mfa');
RESET ROLE;
ROLLBACK TO SAVEPOINT pinless;
SAVEPOINT pinless2;
SELECT pg_temp.seed_step('op', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_pin_set_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_authorize: no scope', 'PA-19: an operator who holds no staff or manager role cannot set a PIN even with an email proof (it has no PIN: the A3 substitution is S1.4)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pinless2;
SAVEPOINT pinless3;
SELECT pg_temp.seed_step('ad', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT throws_ok($$SELECT * FROM private.partner_pin_set_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_pin_set_for_partner: only an active staff or manager member holds a PIN', 'an ADMIN (who passes the "anywhere" scope branch) with no staff or manager membership cannot set a PIN either');
SELECT throws_ok($$SELECT * FROM private.partner_pin_change_for_partner('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x2222222222222222222222222222222222222222222222222222222222222222'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000)$$, '42501', 'partner_pin_change_for_partner: only an active staff or manager member holds a PIN', '... nor change one');
RESET ROLE;
ROLLBACK TO SAVEPOINT pinless3;

-- ----------------------------------------------------------------------------
-- 6. PA-21 set and change: only inside an enrolment window or after an email proof; a passkey assertion alone is refused
-- ----------------------------------------------------------------------------
SAVEPOINT set_none;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof', 'PA-21: a plain sign-in session (no enrolment window, no email proof) cannot set a PIN');
ROLLBACK TO SAVEPOINT set_none;
SAVEPOINT set_passkey;
-- a passkey assertion and a PIN grant are NOT enough (on a shared iPad anyone with the passcode holds both)
SELECT pg_temp.seed_step('sx', '{"reauth_s": 240, "pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof', 'PA-21: a passkey assertion (reauth) plus a PIN grant is refused: only an enrolment window or an email proof counts');
SELECT is((SELECT count(*)::int FROM app.partner_pin), 0, 'PA-21: ... and nothing was written');
ROLLBACK TO SAVEPOINT set_passkey;
SAVEPOINT set_passkey2;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SELECT pg_temp.seed_step('sx', '{"reauth_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pchg('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x4444444444444444444444444444444444444444444444444444444444444444'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof', 'PA-21: a CHANGE with the CORRECT current PIN is refused without the proof as well');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0::smallint, 'PA-21: ... and the refusal before the proof counts nothing (a passkey-only caller cannot probe the PIN through change)');
ROLLBACK TO SAVEPOINT set_passkey2;
SAVEPOINT set_expired;
SELECT pg_temp.seed_step('sx', '{"enrol_s": -1, "otp_s": -1}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof', 'PA-21: an EXPIRED enrolment window and an EXPIRED email proof are refused');
ROLLBACK TO SAVEPOINT set_expired;
SAVEPOINT set_otp;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pset(:'dk_ok'::bytea, :'salt_a'::bytea), 'ok|0', 'PA-21: with an email proof, the first PIN is set');
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'ok|0|true', 'PA-21: ... and verifies');
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|0|false', 'PA-21: ... and a different key does not');
ROLLBACK TO SAVEPOINT set_otp;
SAVEPOINT set_enrol;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_reg');
RESET ROLE;
SELECT is(pg_temp.pset(:'dk_ok'::bytea, :'salt_a'::bytea), 'ok|0', 'PA-21: inside the enrolment window of a register session, the first PIN is set (no email proof needed)');
SELECT is(pg_temp.pset(:'dk_new'::bytea, :'salt_b'::bytea), 'already_set|0', 'a SET on a live PIN is `already_set` and changes nothing (a change needs the current PIN)');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea), '... the stored verifier is still the first one');
ROLLBACK TO SAVEPOINT set_enrol;
-- change
SAVEPOINT chg1;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_bad'::bytea, :'dk_new'::bytea, :'salt_c'::bytea), 'wrong|0', 'PA-21: a change with a WRONG current PIN is a status wrong (it commits, the counter moved)');
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 1::smallint, 'PA-21: ... counted exactly like a verify');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea), 'PA-21: ... and the verifier did not change');
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea, :'salt_c'::bytea, 700000), 'ok|0', 'PA-21: a change with the CORRECT current PIN under an email proof succeeds');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_new'::bytea), 'PA-21: the new verifier is stored');
SELECT is((SELECT (salt = :'salt_c'::bytea)::text || ',' || iterations::text || ',' || failed_count::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'true,700000,0', 'PA-21: ... with the NEW salt and iteration count, and the consecutive counter reset');
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'wrong|0|false', 'PA-21: the OLD key no longer verifies');
SELECT is(pg_temp.pv(:'dk_new'::bytea), 'ok|0|true', 'PA-21: the new key does');
SELECT is((SELECT array_agg(action ORDER BY action) FROM app.audit_log WHERE subject_id = '00000000-0000-0000-0000-1000000000a1' AND action LIKE 'partner.pin.%'),
          ARRAY['partner.pin.change', 'partner.pin.wrong', 'partner.pin.wrong'], 'the audit trail: the wrong current key, the change, and the old key tried afterwards');
ROLLBACK TO SAVEPOINT chg1;
SAVEPOINT chg_nopin;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea), 'no_pin|0', 'a CHANGE with no PIN set is a status no_pin (use set)');
ROLLBACK TO SAVEPOINT chg_nopin;
SAVEPOINT chg_lock;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 4, 'next_attempt_at', clock_timestamp() - interval '1 second'));
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_bad'::bytea, :'dk_new'::bytea), 'locked|0', 'PA-18: the 5th wrong CURRENT key of a change LOCKS the PIN (the change path shares the verify counter)');
SELECT is((SELECT array_agg(action ORDER BY action) FROM app.audit_log WHERE subject_id = '00000000-0000-0000-0000-1000000000a1' AND action LIKE 'partner.pin.%'), ARRAY['partner.pin.locked'], '... and writes the lock audit row');
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea), 'locked|0', 'a CHANGE on a locked PIN is refused even with the correct current key');
SELECT is(pg_temp.pset(:'dk_new'::bytea), 'locked|0', 'PA-21: ... and a SET on a locked PIN is refused even under an email proof (only a manager''s reset clears a lock)');
ROLLBACK TO SAVEPOINT chg_lock;
-- after a reset (must_change): the old key is dead, a coworker session cannot set, the email proof can
SAVEPOINT reset_flow;
-- a reset that left stale counters and a stale backoff behind: the SET must clear every one of them (the day count, the consecutive count, next_attempt_at)
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('must_change', true, 'failed_count', 3, 'failed_today', 7, 'failed_day', (clock_timestamp() AT TIME ZONE 'UTC')::date, 'next_attempt_at', clock_timestamp() + interval '1 hour'));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pset('\x4444444444444444444444444444444444444444444444444444444444444444'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof',
  'PA-21: after a reset, a coworker session (a valid passkey session of the member, no email proof) cannot set the new PIN');
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea), 'must_change|0', 'a CHANGE of a must_change PIN is refused as must_change (use set under the proof)');
SELECT is(pg_temp.pset(:'dk_new'::bytea, :'salt_b'::bytea), 'ok|0', 'PA-21 / PA-18: with the email proof the SET replaces the reset PIN');
SELECT is((SELECT must_change::text || ',' || failed_count::text || ',' || failed_today::text || ',' || (next_attempt_at IS NULL)::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 'false,0,0,true', 'PA-18: the new PIN clears must_change, the consecutive and day counters and a stale backoff');
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'wrong|0|false', 'PA-18: the pre-reset key is dead');
SELECT is(pg_temp.pv(:'dk_new'::bytea), 'ok|0|true', 'PA-18: the new key verifies');
ROLLBACK TO SAVEPOINT reset_flow;
-- a CHANGE under a correct current key keeps the day count (only a SET after a reset forgives it) and clears the consecutive count
SAVEPOINT chg_day;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 2, 'failed_today', 7, 'failed_day', (clock_timestamp() AT TIME ZONE 'UTC')::date));
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea), 'ok|0', 'a CHANGE under the correct current key succeeds');
SELECT is((SELECT failed_count::text || ',' || failed_today::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), '0,7', 'PA-18: ... it clears the consecutive count and KEEPS the day count (a change does not forgive the day)');
ROLLBACK TO SAVEPOINT chg_day;
-- MEDIUM-1 (S1.3 gate): the email proof is SINGLE USE for a PIN set or change. Spent in the SAME transaction as the write, on `ok` only; a refused outcome keeps it.
SAVEPOINT proof_set_once;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pset(:'dk_ok'::bytea, :'salt_a'::bytea), 'ok|0', 'MEDIUM-1: the first PIN is set under the email proof');
SELECT is((SELECT otp_proof_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'MEDIUM-1: ... and the proof is SPENT (otp_proof_until cleared by the same call)');
SELECT throws_ok($$SELECT pg_temp.pchg('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x4444444444444444444444444444444444444444444444444444444444444444'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof',
  'MEDIUM-1: a CHANGE under the same, spent proof is refused (42501): one proof, one PIN write');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea), 'MEDIUM-1: ... and the PIN is still the first one');
ROLLBACK TO SAVEPOINT proof_set_once;
SAVEPOINT proof_chg_once;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_bad'::bytea, :'dk_new'::bytea, :'salt_c'::bytea), 'wrong|0', 'MEDIUM-1: a change with a WRONG current PIN is a status wrong');
SELECT is((SELECT otp_proof_until IS NOT NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'MEDIUM-1 (decision): a NON-ok outcome (a wrong current PIN) does NOT spend the proof: the lockout, not the proof, bounds that guess');
SELECT is(pg_temp.pset(:'dk_new'::bytea, :'salt_b'::bytea), 'already_set|0', 'MEDIUM-1: a SET on a live PIN is already_set ...');
SELECT is((SELECT otp_proof_until IS NOT NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'MEDIUM-1: ... and it does not spend the proof either (nothing was written)');
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea, :'salt_c'::bytea), 'ok|0', 'MEDIUM-1: the change with the CORRECT current PIN succeeds');
SELECT is((SELECT otp_proof_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'MEDIUM-1: ... and spends the proof');
SELECT throws_ok($$SELECT pg_temp.pchg('\x2222222222222222222222222222222222222222222222222222222222222222'::bytea, '\x4444444444444444444444444444444444444444444444444444444444444444'::bytea)$$, '42501', 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof',
  'MEDIUM-1: a SECOND change under the same proof is refused (42501)');
SELECT is((SELECT verifier FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), pg_temp.vf('00000000-0000-0000-0000-1000000000a1', :'dk_new'::bytea), 'MEDIUM-1: ... the PIN is the first change''s, the refused second one wrote nothing');
SELECT is(pg_temp.pv(:'dk_new'::bytea), 'ok|0|true', 'MEDIUM-1: ... and the new key verifies (a verify needs no proof)');
ROLLBACK TO SAVEPOINT proof_chg_once;
SAVEPOINT proof_lock_keep;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('locked_at', clock_timestamp(), 'failed_count', 5));
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pchg(:'dk_ok'::bytea, :'dk_new'::bytea), 'locked|0', 'MEDIUM-1: a change on a LOCKED PIN is the status locked ...');
SELECT is((SELECT otp_proof_until IS NOT NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'MEDIUM-1: ... and a refusal keeps the proof (spent on ok only)');
ROLLBACK TO SAVEPOINT proof_lock_keep;
-- argument validation (after the prerequisite)
SAVEPOINT args;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok($$SELECT pg_temp.pset('\x11111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '22023', NULL, 'a derived key of 31 bytes is refused (22023)');
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea)$$, '22023', NULL, 'a salt of 15 bytes is refused (22023)');
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, NULL, 209999)$$, '22023', NULL, '209,999 iterations (below the floor) are refused (22023)');
SELECT throws_ok($$SELECT pg_temp.pset('\x1111111111111111111111111111111111111111111111111111111111111111'::bytea, NULL, 1000001)$$, '22023', NULL, '1,000,001 iterations (above the ceiling) are refused (22023)');
SELECT is(pg_temp.pset(:'dk_ok'::bytea, NULL, 210000), 'ok|0', 'the floor, 210,000 iterations, is accepted');
SELECT is((SELECT count(*)::int FROM app.partner_pin), 1, 'only the valid call wrote a row');
ROLLBACK TO SAVEPOINT args;
SAVEPOINT args2;
SELECT pg_temp.seed_step('sx', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pset(:'dk_ok'::bytea, NULL, 1000000), 'ok|0', 'the ceiling, 1,000,000 iterations, is accepted');
ROLLBACK TO SAVEPOINT args2;
-- the table's own CHECKs are the second line (a writer that skipped the argument check)
SELECT throws_ok($$INSERT INTO app.partner_pin (user_id, salt, iterations, verifier) VALUES ('00000000-0000-0000-0000-2000000000b1', '\x0a'::bytea, 600000, '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '23514', NULL, 'the table: a salt that is not 16 bytes is refused');
SELECT throws_ok($$INSERT INTO app.partner_pin (user_id, salt, iterations, verifier) VALUES ('00000000-0000-0000-0000-2000000000b1', '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 1, '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '23514', NULL, 'the table: an iteration count below the floor is refused');
SELECT throws_ok($$INSERT INTO app.partner_pin (user_id, salt, iterations, verifier) VALUES ('00000000-0000-0000-0000-2000000000b1', '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000, '\x11'::bytea)$$, '23514', NULL, 'the table: a verifier that is not 32 bytes is refused');

-- ----------------------------------------------------------------------------
-- 7. GET pin (params)
-- ----------------------------------------------------------------------------
SAVEPOINT params;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_status || ',' || (o_salt IS NULL)::text || ',' || (o_iterations IS NULL)::text FROM private.partner_pin_params_for_partner()), 'unset,true,true', 'params: no PIN: unset, no salt');
RESET ROLE;
ROLLBACK TO SAVEPOINT params;
SAVEPOINT params2;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_status || ',' || encode(o_salt, 'hex') || ',' || o_iterations::text || ',' || o_retry_after::text FROM private.partner_pin_params_for_partner()), 'ok,0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a,600000,0', 'params: a live PIN: the salt and the iteration count the browser derives with');
RESET ROLE;
ROLLBACK TO SAVEPOINT params2;
SAVEPOINT params3;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 3, 'next_attempt_at', clock_timestamp() + interval '20 seconds'));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_status || ',' || (o_retry_after BETWEEN 19 AND 21)::text FROM private.partner_pin_params_for_partner()), 'ok,true', 'params: a running backoff is reported (so the browser can wait) and the salt is still returned');
RESET ROLE;
ROLLBACK TO SAVEPOINT params3;
SAVEPOINT params4;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, jsonb_build_object('failed_count', 5, 'locked_at', clock_timestamp()));
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_status || ',' || (o_salt IS NULL)::text FROM private.partner_pin_params_for_partner()), 'locked,true', 'params: a LOCKED PIN returns no salt (refused while locked)');
RESET ROLE;
ROLLBACK TO SAVEPOINT params4;
SAVEPOINT params5;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea, '{"must_change": true}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_status || ',' || (o_salt IS NULL)::text FROM private.partner_pin_params_for_partner()), 'must_change,true', 'params: a must_change PIN returns no salt (the browser sets a fresh one)');
RESET ROLE;
ROLLBACK TO SAVEPOINT params5;

-- ----------------------------------------------------------------------------
-- 8. The OTP proof definers
-- ----------------------------------------------------------------------------
SELECT gen_random_uuid() AS g_ok, gen_random_uuid() AS g_stale, gen_random_uuid() AS g_other \gset
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email) VALUES ('ee280000-0000-0000-0000-0000000000f1', 'someone-else28@example.test') ON CONFLICT (id) DO NOTHING;
INSERT INTO auth.sessions (id, user_id, created_at) VALUES
  (:'g_ok', '00000000-0000-0000-0000-1000000000a1', clock_timestamp()),
  (:'g_stale', '00000000-0000-0000-0000-1000000000a1', clock_timestamp() - interval '5 minutes'),
  (:'g_other', 'ee280000-0000-0000-0000-0000000000f1', clock_timestamp());
RESET ROLE;
SELECT lower(btrim(email)) AS mail_sx FROM auth.users WHERE id = '00000000-0000-0000-0000-1000000000a1' \gset
SAVEPOINT otp1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is((SELECT o_email FROM private.partner_session_otp_target_for_partner()), :'mail_sx'::text, 'otp target: the member''s OWN mailbox, normalised');
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner(:'g_stale'::uuid)), 'refused', 'otp proof: a GoTrue session older than a minute is a status refused (the 0041 freshness)');
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner(:'g_other'::uuid)), 'refused', 'otp proof: a fresh GoTrue session of ANOTHER user is refused');
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)), 'refused', 'otp proof: a GoTrue session that does not exist is refused');
RESET ROLE;
SELECT is((SELECT otp_proof_until IS NULL AND otp_proof_gotrue_session_id IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'otp proof: the refusals wrote nothing');
SET LOCAL ROLE edge_partner;
SELECT is((SELECT o_status FROM private.partner_session_otp_proof_for_partner(:'g_ok'::uuid)), 'ok', 'otp proof: a fresh GoTrue session of this user is accepted');
RESET ROLE;
SELECT ok((SELECT otp_proof_until > clock_timestamp() + interval '9 minutes' AND otp_proof_until <= clock_timestamp() + interval '10 minutes' AND otp_proof_gotrue_session_id = :'g_ok'::uuid FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), 'otp proof: otp_proof_until is now + 10 minutes, bound to that GoTrue session');
SELECT is(pg_temp.pset(:'dk_ok'::bytea, :'salt_a'::bytea), 'ok|0', 'otp proof: the REAL proof opens the PIN set (the chain: proof, then set)');
ROLLBACK TO SAVEPOINT otp1;
-- one GoTrue session proves at most ONE proof (the UNIQUE index): a second session of the same member cannot reuse it
SAVEPOINT otp2;
SELECT pg_temp.seed_step('sx', '{"otp_s": 100}'::jsonb);
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
UPDATE app.partner_session SET otp_proof_gotrue_session_id = :'g_ok'::uuid WHERE token_hash = pg_temp.th('sx');
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx2');
SELECT throws_ok(format($$SELECT * FROM private.partner_session_otp_proof_for_partner(%L::uuid)$$, :'g_ok'), '23505', NULL, 'otp proof: a GoTrue session that already proved another session''s proof is refused by the UNIQUE index (23505)');
RESET ROLE;
ROLLBACK TO SAVEPOINT otp2;
-- lock clears the proof (0049) and the proof does not outlive it
SAVEPOINT otp3;
SELECT pg_temp.seed_step('sx', '{"otp_s": 100, "pin_grant_s": 50}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT lives_ok($$SELECT private.partner_session_lock_for_partner()$$, 'lock runs');
RESET ROLE;
SELECT is((SELECT otp_proof_until IS NULL AND pin_grant_until IS NULL FROM app.partner_session WHERE token_hash = pg_temp.th('sx')), true, 'lock clears the OTP proof AND the PIN grant: a locked till needs a fresh PIN');
ROLLBACK TO SAVEPOINT otp3;

-- ----------------------------------------------------------------------------
-- 9. Cross-person isolation (the role + the binding-keyed policies): a partner-bound session reaches ITS person's PIN row and nobody else's
-- ----------------------------------------------------------------------------
SAVEPOINT iso1;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE partner_pin_verifier;
SELECT is((SELECT array_agg(user_id::text) FROM app.partner_pin), ARRAY['00000000-0000-0000-0000-1000000000a1'], 'isolation: under staff_x''s binding the PIN verifier role sees staff_x''s row ONLY (not the manager''s)');
WITH u AS (UPDATE app.partner_pin SET failed_count = 4 WHERE user_id = '00000000-0000-0000-0000-2000000000b1' RETURNING 1) SELECT is((SELECT count(*)::int FROM u), 0, 'isolation: ... an UPDATE of the manager''s row touches 0 rows');
SELECT throws_ok($$INSERT INTO app.partner_pin (user_id, salt, iterations, verifier) VALUES ('00000000-0000-0000-0000-1000000000a3', '\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'::bytea, 600000, '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)$$, '42501', NULL, 'isolation: ... an INSERT of a row for ANOTHER person is refused by the policy');
SELECT throws_ok($$DELETE FROM app.partner_pin$$, '42501', NULL, 'isolation: the PIN verifier role cannot DELETE at all');
RESET ROLE;
SELECT is((SELECT failed_count FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-2000000000b1'), 0::smallint, 'isolation: the manager''s counter is untouched');
ROLLBACK TO SAVEPOINT iso1;
SAVEPOINT iso2;
-- no binding at all: the PIN verifier sees NOTHING (the policy's predicate is NULL)
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE partner_pin_verifier;
SELECT is((SELECT count(*)::int FROM app.partner_pin), 0, 'isolation: with NO partner binding the PIN verifier role reads 0 rows');
RESET ROLE;
ROLLBACK TO SAVEPOINT iso2;
-- the verify of one person never reads another's row, even when the verifiers are IDENTICAL: the manager's key is not staff_x's
SAVEPOINT iso3;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_new'::bytea);
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_ok'::bytea), 'wrong|0|false', 'isolation: staff_x presenting the MANAGER''s key (same derived bytes, a PIN the manager holds) is wrong for staff_x');
ROLLBACK TO SAVEPOINT iso3;

-- ----------------------------------------------------------------------------
-- 10. The OR rule: a planted GUC opens nothing under a partner binding (PA-4c (ii) re-run on the PIN table)
-- ----------------------------------------------------------------------------
SAVEPOINT guc1;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-2000000000b1', true) IS NOT NULL AS planted \gset
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_pin), 0, 'PA-4c (ii): with the delete_my_data window PLANTED for the manager, private_definer under staff_x''s PARTNER binding reads 0 PIN rows');
WITH d AS (DELETE FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-2000000000b1' RETURNING 1) SELECT is((SELECT count(*)::int FROM d), 0, 'PA-4c (ii): ... and deletes 0');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.partner_pin), 2, 'PA-4c (ii): both PIN rows are still there');
ROLLBACK TO SAVEPOINT guc1;
SAVEPOINT guc2;
-- control: the same window with NO partner binding IS open (so the cells above are not vacuous)
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-2000000000b1', true) IS NOT NULL AS planted2 \gset
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_pin), 1, 'PA-4c control: with NO binding the planted window shows the target''s row (delete_my_data''s own use)');
RESET ROLE;
ROLLBACK TO SAVEPOINT guc2;
-- the verify definer under every planted GUC for ANOTHER member changes only the bound member's row
SAVEPOINT guc3;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT bool_and(set_config(g, CASE WHEN g IN ('app.edge.purge_fix_coords', 'app.signin.proof_purge') THEN 'on' WHEN g LIKE '%email' THEN 'm@example.test' WHEN g IN ('app.delete_my_data.target_handle', 'app.delete_my_data.target_pseudonym', 'app.edge.link_attest_key', 'app.edge.link_hash') THEN 'x'
                                ELSE '00000000-0000-0000-0000-2000000000b1' END, true) IS NOT NULL) AS planted3
FROM unnest(ARRAY['app.delete_my_data.target_user_id', 'app.delete_my_data.target_email', 'app.delete_my_data.target_handle', 'app.delete_my_data.target_pseudonym', 'app.edge.link_attest_key', 'app.edge.link_device_id', 'app.edge.link_hash',
                  'app.edge.purge_fix_coords', 'app.guard.entitlement_id', 'app.guard.offer_code_id', 'app.guard.play_id', 'app.offline_code.target_device_id', 'app.signin.proof_id', 'app.signin.proof_purge', 'app.signin.target_user_id']) g \gset
RESET ROLE;
SELECT is(pg_temp.pv(:'dk_bad'::bytea), 'wrong|0|false', 'PA-4c (ii): the verify under every planted GUC still evaluates staff_x''s own row');
SELECT is((SELECT failed_count::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-2000000000b1'), '0', 'PA-4c (ii): the manager the GUCs name kept a counter of 0');
SELECT is((SELECT failed_count::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), '1', 'PA-4c (ii): staff_x''s own counter moved');
ROLLBACK TO SAVEPOINT guc3;

-- ----------------------------------------------------------------------------
-- 11. Account deletion removes the PIN row
-- ----------------------------------------------------------------------------
SAVEPOINT del1;
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-1000000000a1', :'dk_ok'::bytea);
SELECT pg_temp.seed_pin('00000000-0000-0000-0000-2000000000b1', :'dk_ok'::bytea);
SET LOCAL ROLE service_role;
SELECT private.delete_my_data('00000000-0000-0000-0000-1000000000a1'::uuid) AS _d \gset
RESET ROLE;
SELECT is((SELECT array_agg(user_id::text) FROM app.partner_pin), ARRAY['00000000-0000-0000-0000-2000000000b1'], 'delete_my_data removes the account''s PIN row (the delete_row window pair) and only that one');
ROLLBACK TO SAVEPOINT del1;

-- every scenario above ran inside a savepoint that was rolled back: nothing leaked into the sessions or the PIN table
SELECT is((SELECT count(*)::int FROM app.partner_pin) + (SELECT count(*)::int FROM app.partner_session s WHERE s.pin_grant_until IS NOT NULL OR s.reauth_until IS NOT NULL OR s.otp_proof_until IS NOT NULL OR s.revoked_at IS NOT NULL)
          + (SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.pin.%'), 0, 'the scenarios left no trace: no PIN row, no grant, no reauth window, no proof, no audit row (a rolled-back savepoint per scenario)');
SELECT * FROM finish();
ROLLBACK;
