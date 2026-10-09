-- 32_partner_invites_enrolment.sql
-- P5.1a S1.5 (0054): INVITES, ENROLMENT AND MEMBERS, from docs/security/partner-auth-design.md section 12.1 "S1.5": PA-14 (a forwarded invite fails for a non-matching verified email; single use;
-- expired / revoked / unknown are one answer; the email-mismatch attempt count is a STATUS, so it commits), PA-15 (grant subset and rank with the explicit role arrays), PA-16 (email OTP alone
-- cannot add a credential to a person with an active one), PA-22 (adding and revoking a credential are A2), PA-23 (branch N statuses: existing_member_sign_in, recover_required, one registration
-- per acceptance), PA-25 (the reach rule and recovery), PA-29 (the last-membership delete), PA-7b / PA-7c (the register challenge and the DB-side create checks), the purges of section 9, and PA-4c
-- (iii) (every policy 0054 adds on partner_member, partner_credential, partner_pin and partner_invite, under a planted GUC).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end. The partner tables are FORCE RLS with no policy for the harness role, so fixtures are written through temporary CURRENT_USER policies
-- (the 0016 / 0045 / 28 / 31 seeding pattern). Every scenario that needs a clean binding runs inside a SAVEPOINT that is rolled back. The register-challenge MAC and the WebAuthn create ceremony are
-- built by independent pg_temp helpers (an HMAC over the shim Vault key; a CBOR attestation object assembled byte by byte), so register_first is checked against something other than itself.
--
-- Principals are helpers.sql's: staff_x (a1) staff@X, staff_y (a3) staff@Y, manager_x (b1), operator_t (c1) with the trail T that includes fac_x only, admin (d0); the rest are made here.

\set QUIET 1
BEGIN;
SELECT plan(483);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_partner_minter, edge_system, edge_actor, partner_session_issuer, partner_session_toucher, partner_pin_verifier, partner_totp_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_invite, app.partner_enrolment_token, app.partner_member, app.partner_pin, app.partner_totp,
  app.partner_auth_challenge, app.partner_sign_in_failure, app.partner_rp_config, app.admin_user TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz32_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_tok ON app.partner_enrolment_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_mem ON app.partner_member FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_sif ON app.partner_sign_in_failure FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_adm ON app.admin_user FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz32_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');

-- principals made here (fixed ids, ee32...): a manager at Y, a second admin, a person at both X and Y, a staff member who is also an admin, a person with no membership, a second operator, three people to invite
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email, email_confirmed_at) VALUES
  ('ee320000-0000-0000-0000-000000000001', 'manager-y@example.test', now()),
  ('ee320000-0000-0000-0000-000000000002', 'admin2@example.test', now()),
  ('ee320000-0000-0000-0000-000000000003', 'multi@example.test', now()),
  ('ee320000-0000-0000-0000-000000000004', 'staff-admin@example.test', now()),
  ('ee320000-0000-0000-0000-000000000005', 'nomember@example.test', now()),
  ('ee320000-0000-0000-0000-000000000006', 'operator2@example.test', now()),
  ('ee320000-0000-0000-0000-000000000007', 'rv@example.test', now()),
  ('ee320000-0000-0000-0000-000000000008', 'rc@example.test', now()),
  ('ee320000-0000-0000-0000-000000000009', 'em@example.test', now()),
  ('ee320000-0000-0000-0000-00000000000a', 'eu@example.test', NULL),
  ('ee320000-0000-0000-0000-000000000011', 'newbie1@example.test', now()),
  ('ee320000-0000-0000-0000-000000000012', 'newbie2@example.test', now()),
  ('ee320000-0000-0000-0000-000000000013', 'unconfirmed@example.test', NULL);
RESET ROLE;
INSERT INTO app.partner_member (user_id, org_id, role, invited_by) VALUES
  ('ee320000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000002', 'manager', NULL),
  ('ee320000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001', 'staff', NULL),
  ('ee320000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002', 'staff', NULL),
  ('ee320000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000001', 'staff', NULL),
  ('ee320000-0000-0000-0000-000000000006', '10000000-0000-0000-0000-000000000003', 'operator', NULL),
  ('ee320000-0000-0000-0000-000000000008', '10000000-0000-0000-0000-000000000001', 'staff', NULL),
  ('ee320000-0000-0000-0000-000000000009', '10000000-0000-0000-0000-000000000001', 'staff', NULL),
  ('ee320000-0000-0000-0000-00000000000a', '10000000-0000-0000-0000-000000000001', 'staff', NULL);
INSERT INTO app.partner_member (user_id, org_id, role, invited_by, revoked_at) VALUES ('ee320000-0000-0000-0000-000000000007', '10000000-0000-0000-0000-000000000001', 'staff', NULL, now());
INSERT INTO app.admin_user (user_id) VALUES ('ee320000-0000-0000-0000-000000000002'), ('ee320000-0000-0000-0000-000000000004');

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s32:' || p_label) || md5('s32b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c32:' || p_label) || md5('c32b:' || p_label), 'hex'), decode(md5('k32:' || p_label) || md5('k32b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1, p_age interval DEFAULT interval '1 hour') RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - p_age, now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n32:' || p_label) || md5('n32b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
-- the A2 prerequisites of a session, seeded straight into the columns (the guard trigger is off for the moment): a PIN grant 5 s old (single use; re-seed per call), a passkey assertion, a TOTP window
CREATE FUNCTION pg_temp.a2(p_label text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET pin_grant_until = clock_timestamp() + interval '55 seconds', reauth_until = clock_timestamp() + interval '240 seconds', mfa_until = clock_timestamp() + interval '240 seconds'
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.seed_cols(p_label text, p_set text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  EXECUTE format('UPDATE app.partner_session s SET %s WHERE s.token_hash = %L', p_set, pg_temp.th(p_label));
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
-- fixture edits of columns the immutability guards protect (the guards stay ON for every statement the definers make)
CREATE FUNCTION pg_temp.fix(p_sql text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_invite DISABLE TRIGGER partner_invite_guard_trg';
  EXECUTE 'ALTER TABLE app.partner_enrolment_token DISABLE TRIGGER partner_enrolment_token_guard_trg';
  EXECUTE p_sql;
  EXECUTE 'ALTER TABLE app.partner_invite ENABLE TRIGGER partner_invite_guard_trg';
  EXECUTE 'ALTER TABLE app.partner_enrolment_token ENABLE TRIGGER partner_enrolment_token_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.mk_pin(p_uid uuid, p_locked boolean DEFAULT false) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, failed_day, last_failed_at, next_attempt_at, locked_at)
  VALUES (p_uid, decode(repeat('01', 16), 'hex'), 210000, decode(repeat('02', 32), 'hex'),
          CASE WHEN p_locked THEN 5 ELSE 0 END, CASE WHEN p_locked THEN 5 ELSE 0 END, CASE WHEN p_locked THEN current_date END,
          CASE WHEN p_locked THEN now() END, CASE WHEN p_locked THEN now() + interval '5 minutes' END, CASE WHEN p_locked THEN now() END)
  ON CONFLICT (user_id) DO NOTHING
$f$;
CREATE FUNCTION pg_temp.mk_totp(p_uid uuid) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, confirmed_at) VALUES (p_uid, 1, now(), now()) ON CONFLICT (user_id) DO NOTHING
$f$;
-- an invite row, written directly (what the create definer writes), and its token hash
CREATE FUNCTION pg_temp.mk_inv(p_label text, p_org uuid, p_role app.partner_role, p_email text, p_by uuid DEFAULT '00000000-0000-0000-0000-2000000000b1') RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (p_org, p_role, CASE WHEN p_org = '10000000-0000-0000-0000-000000000001' THEN 'fac_x' WHEN p_org = '10000000-0000-0000-0000-000000000002' THEN 'fac_y' END, p_by, p_email, encode(sha256(convert_to('h32:' || p_label, 'UTF8')), 'hex'), now() + interval '72 hours', now())
  RETURNING id
$f$;
-- independent register / reauth challenge MAC: HMAC-SHA256(shim partner_challenge_key, label || 0x00 || purpose || exp || nonce || binding [|| ref_kind || ref_id || accepted_at_us])
CREATE FUNCTION pg_temp.mac_of(p_purpose int, p_exp bigint, p_nonce bytea, p_binding uuid, p_kind int DEFAULT NULL, p_ref uuid DEFAULT NULL, p_us bigint DEFAULT NULL) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(
    convert_to('golfraven/partner-challenge/v1', 'UTF8') || decode('00', 'hex') || set_byte('\x00'::bytea, 0, p_purpose) || int8send(p_exp) || p_nonce || decode(replace(p_binding::text, '-', ''), 'hex')
      || CASE WHEN p_kind IS NOT NULL THEN set_byte('\x00'::bytea, 0, p_kind) || decode(replace(p_ref::text, '-', ''), 'hex') || int8send(p_us) ELSE ''::bytea END,
    convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_challenge_key'), 'UTF8'), 'sha256')
$f$;
CREATE FUNCTION pg_temp.us_of(p_t timestamptz) RETURNS bigint LANGUAGE sql AS $f$ SELECT (extract(epoch FROM p_t) * 1000000)::bigint $f$;
CREATE FUNCTION pg_temp.b64u(p_b bytea) RETURNS text LANGUAGE sql AS $f$ SELECT rtrim(translate(encode(p_b, 'base64'), E'+/\n', '-_'), '=') $f$;
-- a GoTrue session row for a person, `p_age` old
CREATE FUNCTION pg_temp.gotrue(p_uid uuid, p_age interval DEFAULT interval '5 seconds') RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE g uuid;
BEGIN
  EXECUTE 'SET LOCAL ROLE service_role';
  INSERT INTO auth.sessions (id, user_id, created_at) VALUES (gen_random_uuid(), p_uid, now() - p_age) RETURNING id INTO g;
  EXECUTE 'RESET ROLE';
  RETURN g;
END
$f$;
-- the WebAuthn create ceremony, byte by byte (design 6.1, R4-L2): the COSE key, authenticatorData, the attestation object (fmt none) and clientDataJSON
CREATE FUNCTION pg_temp.cose(p_x bytea DEFAULT decode(repeat('11', 32), 'hex'), p_y bytea DEFAULT decode(repeat('22', 32), 'hex')) RETURNS bytea LANGUAGE sql AS $f$
  SELECT decode('a5010203262001215820', 'hex') || p_x || decode('225820', 'hex') || p_y
$f$;
CREATE FUNCTION pg_temp.authdata(p_credid bytea, p_cose bytea, p_flags int DEFAULT 69, p_rp text DEFAULT 'partners.example.test', p_counter int DEFAULT 0) RETURNS bytea LANGUAGE sql AS $f$
  SELECT sha256(convert_to(p_rp, 'UTF8')) || set_byte('\x00'::bytea, 0, p_flags) || int4send(p_counter) || decode(repeat('ab', 16), 'hex')
         || set_byte(set_byte('\x0000'::bytea, 0, octet_length(p_credid) / 256), 1, octet_length(p_credid) % 256) || p_credid || p_cose
$f$;
CREATE FUNCTION pg_temp.attobj(p_authdata bytea, p_fmt text DEFAULT 'none', p_empty_stmt boolean DEFAULT true) RETURNS bytea LANGUAGE sql AS $f$
  SELECT decode('a3', 'hex') || decode('63666d74', 'hex') || (set_byte('\x60'::bytea, 0, 96 + octet_length(convert_to(p_fmt, 'UTF8'))) || convert_to(p_fmt, 'UTF8'))
         || decode('6761747453746d74', 'hex') || CASE WHEN p_empty_stmt THEN decode('a0', 'hex') ELSE decode('a163616c6726', 'hex') END
         || decode('686175746844617461', 'hex') || CASE WHEN octet_length(p_authdata) < 256 THEN decode('58', 'hex') || set_byte('\x00'::bytea, 0, octet_length(p_authdata))
                                                        ELSE decode('59', 'hex') || set_byte(set_byte('\x0000'::bytea, 0, octet_length(p_authdata) / 256), 1, octet_length(p_authdata) % 256) END || p_authdata
$f$;
CREATE FUNCTION pg_temp.cdj(p_nonce bytea, p_type text DEFAULT 'webauthn.create', p_origin text DEFAULT 'https://partners.example.test', p_extra text DEFAULT '') RETURNS bytea LANGUAGE sql AS $f$
  SELECT convert_to('{"type":"' || p_type || '","challenge":"' || pg_temp.b64u(p_nonce) || '","origin":"' || p_origin || '"' || p_extra || '}', 'UTF8')
$f$;
CREATE FUNCTION pg_temp.credid(p_label text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $f$ SELECT decode(md5('cid32:' || p_label) || md5('cid32b:' || p_label), 'hex') $f$;

SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('my', 'ee320000-0000-0000-0000-000000000001') AS c_my \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('my', 'ee320000-0000-0000-0000-000000000001', :'c_my') AS s_my \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('my') AS th_my, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad \gset

-- run a statement as a lane role, in this transaction, and return its result as text
CREATE FUNCTION pg_temp.as_role(p_role text, p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE ' || p_role;
  EXECUTE p_sql INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
-- bind a partner session as edge_partner (the harness holds SET on it); the caller runs inside a SAVEPOINT
CREATE FUNCTION pg_temp.bind(p_hash text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(p_hash);
  EXECUTE 'RESET ROLE';
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure and privilege
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE '%\_for\_partner' AND p.proname IN (
  'partner_invite_create_for_partner', 'partner_invite_list_for_partner', 'partner_invite_revoke_for_partner', 'partner_invite_accept_for_partner', 'partner_member_revoke_for_partner',
  'partner_member_recover_for_partner', 'partner_pin_reset_for_partner', 'partner_org_sessions_revoke_for_partner', 'partner_credential_options_for_partner',
  'partner_credential_register_for_partner', 'partner_credential_list_for_partner', 'partner_credential_revoke_for_partner')
  AND p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')), 12,
  'the twelve 0054 partner-lane definers are SECURITY DEFINER search_path = '''', owned by private_definer, executable by edge_partner');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner_minter'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier')) r(n)
           CROSS JOIN (VALUES ('private.partner_invite_create_for_partner(uuid, app.partner_role, text, text)'), ('private.partner_invite_list_for_partner(uuid)'), ('private.partner_invite_revoke_for_partner(uuid)'),
             ('private.partner_invite_accept_for_partner(text)'), ('private.partner_member_revoke_for_partner(uuid, uuid)'), ('private.partner_member_recover_for_partner(uuid, text)'), ('private.partner_pin_reset_for_partner(uuid)'),
             ('private.partner_org_sessions_revoke_for_partner(uuid, timestamptz)'), ('private.partner_credential_options_for_partner()'),
             ('private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])'), ('private.partner_credential_list_for_partner()'), ('private.partner_credential_revoke_for_partner(uuid)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[], 'ONLY edge_partner can execute the twelve partner-lane definers');
SELECT is((SELECT array_agg(r.n || ':' || f.sig ORDER BY r.n, f.sig) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_session_toucher')) r(n)
           CROSS JOIN (VALUES ('private.partner_invite_email_for_token(text)'), ('private.partner_invite_accept(text, uuid, uuid)'), ('private.partner_enrolment_token_email_for_token(text)'),
             ('private.partner_enrolment_token_accept(text, uuid, uuid)'),
             ('private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[], 'the five minter-lane definers are executable by edge_partner_minter and by nobody else (not the partner lane, not edge_system, not a verifier)');
SELECT is((SELECT count(*)::int FROM (VALUES ('private.partner_invite_email_for_token(text)'), ('private.partner_invite_accept(text, uuid, uuid)'), ('private.partner_enrolment_token_email_for_token(text)'),
             ('private.partner_enrolment_token_accept(text, uuid, uuid)'),
             ('private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])')) f(sig)
           WHERE has_function_privilege('edge_partner_minter', f.sig::regprocedure, 'EXECUTE') AND (SELECT proowner FROM pg_proc WHERE oid = f.sig::regprocedure) = 'partner_session_issuer'::regrole), 5,
  'the five minter-lane definers are owned by partner_session_issuer (so private_definer keeps no read of a pending invite without a binding: M1 of matrix 25)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_partner'), ('edge_partner_minter')) r(n)
           CROSS JOIN (VALUES ('private.purge_partner_challenges()'), ('private.purge_partner_sessions()'), ('private.purge_partner_credentials()'), ('private.purge_partner_invites()'),
             ('private.purge_partner_enrolment_tokens()'), ('private.purge_partner_sign_in_failures()')) f(sig) WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), NULL::text[],
  'the six partner purges: no client role, no edge role but edge_system can execute them');
SELECT is((SELECT count(*)::int FROM (VALUES ('private.partner_reach_covers(uuid, uuid)'), ('private.partner_reach_covers_org(uuid, uuid, uuid)'),
             ('private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'), ('private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'),
             ('private.partner_challenge_issue_register(uuid, smallint, uuid, bigint)'), ('private.partner_auth_identity(uuid, uuid)'), ('private.partner_member_revoke_apply(uuid, uuid)'),
             ('private.partner_credential_revoke_apply(uuid, uuid, text)'), ('private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz)'), ('private.partner_sessions_evict_oldest(uuid, integer)'),
             ('private.partner_pin_reset_apply(uuid)'), ('private.partner_invite_accept_core(text, uuid, uuid, text)'), ('private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid)'),
             ('private.partner_member_last_membership()')) f(sig)
           CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')), 0, 'the fourteen helpers (reach rule, cores, writers, trigger function) are executable by no edge, client or service role');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname IN ('partner_challenge_core', 'partner_challenge_verify')), 4,
  'the 5-argument partner_challenge_core / _verify (the matrix 26 vectors) still exist next to the two 8-argument overloads');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE note LIKE '0054%' OR function_name IN ('partner_totp_reset_for_partner')), 39 + 1, 'registry: the 39 new 0054 functions (37 definers, 2 trigger functions) have a function_inventory row (and the replaced totp reset keeps its 0053 one)');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_purge_partner_auth_challenge', 'pd_purge_partner_auth_challenge_r', 'pd_purge_partner_credential', 'pd_purge_partner_credential_r', 'pd_read_partner_credential_bound', 'pd_insert_partner_enrolment_token_recover', 'pd_purge_partner_enrolment_token', 'pd_purge_partner_enrolment_token_r', 'pd_read_partner_enrolment_token_admin_issue', 'pd_read_partner_enrolment_token_recover', 'pd_revoke_partner_enrolment_token_recover', 'psi_read_partner_enrolment_token', 'psi_update_partner_enrolment_token_accept', 'psi_update_partner_enrolment_token_register', 'pd_insert_partner_invite', 'pd_purge_partner_invite', 'pd_purge_partner_invite_r', 'pd_read_partner_invite_scope', 'pd_revoke_partner_invite', 'psi_read_partner_invite', 'psi_update_partner_invite_accept', 'psi_update_partner_invite_register', 'psi_insert_partner_member', 'psi_read_partner_member', 'psi_update_partner_member', 'pst_revoke_partner_member', 'pd_lastmember_delete_partner_pin', 'pd_lastmember_delete_partner_pin_r', 'ppv_read_partner_pin_reach', 'ppv_update_partner_pin_reach', 'pd_purge_partner_session', 'pd_purge_partner_session_r', 'pd_purge_partner_sign_in_failure', 'pd_purge_partner_sign_in_failure_r', 'pd_lastmember_delete_partner_totp', 'pd_lastmember_delete_partner_totp_r')), 36, 'registry: the 36 new 0054 policies are in private.definer_policy_allowlist');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_purge_partner_auth_challenge', 'pd_purge_partner_auth_challenge_r', 'pd_purge_partner_credential', 'pd_purge_partner_credential_r', 'pd_read_partner_credential_bound', 'pd_insert_partner_enrolment_token_recover', 'pd_purge_partner_enrolment_token', 'pd_purge_partner_enrolment_token_r', 'pd_read_partner_enrolment_token_admin_issue', 'pd_read_partner_enrolment_token_recover', 'pd_revoke_partner_enrolment_token_recover', 'psi_read_partner_enrolment_token', 'psi_update_partner_enrolment_token_accept', 'psi_update_partner_enrolment_token_register', 'pd_insert_partner_invite', 'pd_purge_partner_invite', 'pd_purge_partner_invite_r', 'pd_read_partner_invite_scope', 'pd_revoke_partner_invite', 'psi_read_partner_invite', 'psi_update_partner_invite_accept', 'psi_update_partner_invite_register', 'psi_insert_partner_member', 'psi_read_partner_member', 'psi_update_partner_member', 'pst_revoke_partner_member', 'pd_lastmember_delete_partner_pin', 'pd_lastmember_delete_partner_pin_r', 'ppv_read_partner_pin_reach', 'ppv_update_partner_pin_reach', 'pd_purge_partner_session', 'pd_purge_partner_session_r', 'pd_purge_partner_sign_in_failure', 'pd_purge_partner_sign_in_failure_r', 'pd_lastmember_delete_partner_totp', 'pd_lastmember_delete_partner_totp_r')
            AND (coalesce(using_expr, '') || coalesce(with_check_expr, '')) ~* 'current_setting|pg_settings'), 0, 'registry: none of the 36 reads a setting (every one is keyed on the binding, a row state, or the rule in the data)');

-- ----------------------------------------------------------------------------
-- 2. THE REGISTER CHALLENGE (5.1, PA-7b): the 8-argument HMAC against an independent oracle; refs only for purpose 2
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.core8(p_purpose int, p_exp bigint, p_nonce bytea, p_binding uuid, p_kind int, p_ref uuid, p_us bigint) RETURNS bytea LANGUAGE plpgsql AS $f$
DECLARE m bytea;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT c.o_mac INTO m FROM private.partner_challenge_core(p_purpose::smallint, p_exp, p_nonce, p_binding, NULL, p_kind::smallint, p_ref, p_us) c;
  EXECUTE 'RESET ROLE';
  RETURN m;
END
$f$;
CREATE FUNCTION pg_temp.verify8(p_purpose int, p_exp bigint, p_nonce bytea, p_binding uuid, p_mac bytea, p_kind int, p_ref uuid, p_us bigint) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE ok boolean;
BEGIN
  EXECUTE 'SET LOCAL ROLE partner_session_issuer';
  SELECT private.partner_challenge_verify(p_purpose::smallint, p_exp, p_nonce, p_binding, p_mac, p_kind::smallint, p_ref, p_us) INTO ok;
  EXECUTE 'RESET ROLE';
  RETURN ok;
END
$f$;
SELECT is(pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  'PA-7b: the register MAC (purpose 2, ref kind 1) equals the independent HMAC: label || 0x00 || 2 || exp || nonce || uid || 1 || ref id || int8send(accepted_at_us)');
SELECT is(pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 2, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 2, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 'PA-7b: ... ref kind 2 (an enrolment token) likewise');
SELECT isnt(pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 2, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 'PA-7b: the ref kind is inside the MAC');
SELECT isnt(pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  pg_temp.core8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123457), 'PA-7b: ... and so is the acceptance time (one microsecond apart differs)');
SELECT is(pg_temp.core8(1, 1900000000, decode(repeat('0a', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL, NULL, NULL),
  pg_temp.mac_of(1, 1900000000, decode(repeat('0a', 32), 'hex'), '00000000-0000-0000-0000-000000000000'), 'the 8-argument form with no refs gives the sign-in MAC of the 5-argument layout (the 0048 vectors are untouched)');
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(1::smallint, 1900000000, decode(repeat('0a', 32), 'hex'), '00000000-0000-0000-0000-000000000000', NULL, 1::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456)$$,
  '22023', 'partner_challenge_core: only a register challenge carries a reference', 'PA-7b: a sign_in challenge refuses refs');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(3::smallint, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', NULL, NULL, NULL, 5)$$,
  '22023', 'partner_challenge_core: only a register challenge carries a reference', 'PA-7b: a reauth challenge refuses refs (any one of the three)');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(2::smallint, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', NULL, NULL, NULL, NULL)$$,
  '22023', 'partner_challenge_core: a register challenge needs a ref kind (1 or 2), a ref id and an acceptance time', 'PA-7b: a register challenge REQUIRES its refs');
SELECT throws_ok($$SELECT * FROM private.partner_challenge_core(2::smallint, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', NULL, 3::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 5)$$,
  '22023', 'partner_challenge_core: a register challenge needs a ref kind (1 or 2), a ref id and an acceptance time', 'PA-7b: ref kind 3 does not exist');
RESET ROLE;
SELECT is(pg_temp.verify8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  true, 'PA-7b: the verifier accepts the independent MAC');
SELECT is(pg_temp.verify8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 1, 'aaaaaaaa-0000-0000-0000-0000000000ff', 1700000000123456),
  false, 'PA-7b: a challenge bound to invite X does not verify for invite Y');
SELECT is(pg_temp.verify8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000012',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  false, 'PA-7b: ... nor for a different uid');
SELECT is(pg_temp.verify8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 2, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  false, 'PA-7b: ... nor for the other ref kind');
SELECT is(pg_temp.verify8(2, 1900000001, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456),
  false, 'PA-7b: ... nor with a tampered expiry');
SELECT is(pg_temp.verify8(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011',
    pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), 'ee320000-0000-0000-0000-000000000011', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123456), 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 1700000000123457),
  false, 'PA-7b: ... nor with another acceptance time');
SELECT is(pg_temp.verify8(1, 1900000000, decode(repeat('0a', 32), 'hex'), '00000000-0000-0000-0000-000000000000', pg_temp.mac_of(2, 1900000000, decode(repeat('0a', 32), 'hex'), '00000000-0000-0000-0000-000000000000', 1, 'aaaaaaaa-0000-0000-0000-00000000000f', 5), NULL, NULL, NULL),
  false, 'PA-7b: a register MAC is not a sign_in MAC (purpose is in the message)');
SET LOCAL ROLE partner_session_issuer;
SELECT is((SELECT length(o.o_nonce) || ':' || (o.o_exp > extract(epoch FROM now()) + 590 AND o.o_exp <= extract(epoch FROM now()) + 601)::text
           FROM private.partner_challenge_issue_register('ee320000-0000-0000-0000-000000000011', 1::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 5) o), '32:true',
  'the register issuer returns a 32-byte nonce and an expiry about 600 s ahead (its MAC is proved against the oracle through the accept definers below)');
SELECT is((SELECT private.partner_challenge_verify(2::smallint, o.o_exp, o.o_nonce, 'ee320000-0000-0000-0000-000000000011', o.o_mac, 1::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 5)
           FROM private.partner_challenge_issue_register('ee320000-0000-0000-0000-000000000011', 1::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 5) o), true,
  'PA-7b: what the issuer issues verifies for exactly that tuple');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_challenge_issue_register('ee320000-0000-0000-0000-000000000011', 1::smallint, 'aaaaaaaa-0000-0000-0000-00000000000f', 5)$$, '42501', NULL,
  'PA-7b (i): the register issuer is not callable by the minter role: no handler can ask for a register challenge');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 3. THE REACH RULE (6.5), unit cells: partner_reach_covers(actor, target), conditions (1) to (5)
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.u(p_who text) RETURNS uuid LANGUAGE sql IMMUTABLE AS $f$
  SELECT CASE p_who
    WHEN 'sx' THEN '00000000-0000-0000-0000-1000000000a1' WHEN 'sxr' THEN '00000000-0000-0000-0000-1000000000a2' WHEN 'sy' THEN '00000000-0000-0000-0000-1000000000a3'
    WHEN 'mx' THEN '00000000-0000-0000-0000-2000000000b1' WHEN 'mxr' THEN '00000000-0000-0000-0000-2000000000b2' WHEN 'op' THEN '00000000-0000-0000-0000-3000000000c1' WHEN 'ad' THEN '00000000-0000-0000-0000-4000000000d0'
    WHEN 'my' THEN 'ee320000-0000-0000-0000-000000000001' WHEN 'ad2' THEN 'ee320000-0000-0000-0000-000000000002' WHEN 'mu' THEN 'ee320000-0000-0000-0000-000000000003'
    WHEN 'sa' THEN 'ee320000-0000-0000-0000-000000000004' WHEN 'nm' THEN 'ee320000-0000-0000-0000-000000000005' WHEN 'op2' THEN 'ee320000-0000-0000-0000-000000000006'
    WHEN 'rv' THEN 'ee320000-0000-0000-0000-000000000007' WHEN 'rc' THEN 'ee320000-0000-0000-0000-000000000008' WHEN 'em' THEN 'ee320000-0000-0000-0000-000000000009' WHEN 'eu' THEN 'ee320000-0000-0000-0000-00000000000a'
    WHEN 'nb1' THEN 'ee320000-0000-0000-0000-000000000011' WHEN 'nb2' THEN 'ee320000-0000-0000-0000-000000000012' WHEN 'nbu' THEN 'ee320000-0000-0000-0000-000000000013' END::uuid
$f$;
CREATE FUNCTION pg_temp.reach(p_actor text, p_target text) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE r boolean; a uuid := pg_temp.u(p_actor); t uuid := pg_temp.u(p_target);
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.partner_reach_covers(a, t) INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
CREATE FUNCTION pg_temp.reach_org(p_actor text, p_target text, p_org uuid) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE r boolean; a uuid := pg_temp.u(p_actor); t uuid := pg_temp.u(p_target);
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.partner_reach_covers_org(a, t, p_org) INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
-- the person with only a REVOKED membership (manager_x_revoked): a non-admin with no active membership
SELECT is(pg_temp.reach('mx', 'sx'), true, 'reach: a manager at X covers staff at X');
SELECT is(pg_temp.reach('mx', 'sy'), false, 'reach (2): a manager at X does NOT cover staff at Y (another facility)');
SELECT is(pg_temp.reach('mx', 'mu'), false, 'reach (2): ... nor a person who works at X AND Y (one membership is out of reach: a manager at A cannot lock out a person who also works at B)');
SELECT is(pg_temp.reach('mx', 'mx'), false, 'reach (5): never oneself');
SELECT is(pg_temp.reach('mx', 'my'), false, 'reach (2): a manager does not cover a manager (the role must be STRICTLY above), nor at another facility');
SELECT is(pg_temp.reach('mx', 'ad'), false, 'reach (3): a manager cannot act on a ZERO-MEMBERSHIP admin (R2-M1)');
SELECT is(pg_temp.reach('mx', 'sa'), false, 'reach (3): ... nor on a staff member who is also an admin (an admin target needs an admin actor, whatever memberships it holds)');
SELECT is(pg_temp.reach('mx', 'op'), false, 'reach (4): a manager cannot act on an operator');
SELECT is(pg_temp.reach('op', 'op2'), false, 'reach (4): ... nor can another operator (an operator is an admin matter)');
SELECT is(pg_temp.reach('mx', 'nm'), false, 'reach (1): a target with no active membership who is not an admin is refused for a manager');
SELECT is(pg_temp.reach('op', 'nm'), false, 'reach (1): ... and for an operator');
SELECT is(pg_temp.reach('mx', 'mxr'), false, 'reach (1): a person with only a REVOKED membership holds none: refused for a non-admin');
SELECT is(pg_temp.reach('op', 'sx'), true, 'reach (2): an operator whose trail includes fac_x covers staff at X');
SELECT is(pg_temp.reach('op', 'sy'), false, 'reach (2): ... but not staff at Y (fac_y is not on the trail)');
SELECT is(pg_temp.reach('op', 'mu'), false, 'reach (2): ... and not a person who also works at Y');
SELECT is(pg_temp.reach('op', 'mx'), true, 'reach (2): an operator covers a manager at X (an operator is strictly above a manager)');
SELECT is(pg_temp.reach('sx', 'sxr'), false, 'reach: staff cover nobody');
SELECT is(pg_temp.reach('ad', 'op'), true, 'reach (4): an admin covers an operator');
SELECT is(pg_temp.reach('ad', 'sx'), true, 'reach: an admin covers staff anywhere');
SELECT is(pg_temp.reach('ad', 'nm'), true, 'reach (1): an admin covers a non-admin with NO active membership (a zero-membership non-admin is an admin-only matter)');
SELECT is(pg_temp.reach('ad', 'ad2'), true, 'reach (3): an admin covers a DIFFERENT admin, including a zero-membership one (admin recovery works)');
SELECT is(pg_temp.reach('ad', 'sa'), true, 'reach (3): ... and a staff member who is also an admin');
SELECT is(pg_temp.reach('ad', 'ad'), false, 'reach (5): an admin acting on themselves is refused');
SELECT is(pg_temp.reach('ad2', 'ad'), true, 'reach: and the other way round');
SELECT is(pg_temp.reach('sa', 'sx'), true, 'reach: an admin who also holds a staff membership is still an admin actor');
SELECT is(pg_temp.reach(NULL, 'sx'), false, 'reach: a NULL actor covers nobody');
SELECT is(pg_temp.reach('mx', NULL), false, 'reach: a NULL target is covered by nobody');
SELECT is(pg_temp.reach_org('mx', 'mu', '10000000-0000-0000-0000-000000000001'), true, 'reach_org: a manager at X covers the person''s membership AT X');
SELECT is(pg_temp.reach_org('mx', 'mu', '10000000-0000-0000-0000-000000000002'), false, 'reach_org: ... but not their membership at Y');
SELECT is(pg_temp.reach_org('mx', 'sx', '10000000-0000-0000-0000-000000000002'), false, 'reach_org: a membership the person does not hold is covered by nobody (staff_x is not at Y)');
SELECT is(pg_temp.reach_org('mx', 'sa', '10000000-0000-0000-0000-000000000001'), false, 'reach_org (3): the admin-target rule holds per membership too');
SELECT is(pg_temp.reach_org('op', 'op2', '10000000-0000-0000-0000-000000000003'), false, 'reach_org: an operator membership is admin-only');
SELECT is(pg_temp.reach_org('ad', 'op2', '10000000-0000-0000-0000-000000000003'), true, 'reach_org: ... and an admin covers it');
SELECT is(pg_temp.reach_org('ad', 'sx', '10000000-0000-0000-0000-000000000002'), false, 'reach_org: even an admin needs the membership to exist');

-- ----------------------------------------------------------------------------
-- 4. INVITES (6.1): create (PA-15), list, revoke, under the real class A2
-- ----------------------------------------------------------------------------
-- as the partner lane, in this transaction, after re-seeding the A2 prerequisites of the named session (a PIN grant is single use)
CREATE FUNCTION pg_temp.call_a2(p_label text, p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  PERFORM pg_temp.a2(p_label);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  EXECUTE p_sql INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
CREATE FUNCTION pg_temp.call(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  EXECUTE p_sql INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to('h32:' || p_label, 'UTF8')), 'hex') $f$;

SAVEPOINT inv_mx;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', '  New-Staff@Example.TEST ', encode(sha256(convert_to('h32:i1', 'UTF8')), 'hex'))$q$), 'ok',
  'PA-15: a manager invites {staff} at their own facility');
SELECT is((SELECT (role::text, facility_id, invited_by::text, invitee_email, accepted_at IS NULL, attempts, token_hash = encode(sha256(convert_to('h32:i1', 'UTF8')), 'hex'))::text FROM app.partner_invite WHERE token_hash = encode(sha256(convert_to('h32:i1', 'UTF8')), 'hex')),
  '(staff,fac_x,00000000-0000-0000-0000-2000000000b1,new-staff@example.test,t,0,t)', 'PA-15: the row: role, facility, inviter, the email NORMALISED (lower, btrim), unaccepted, no attempts, only the hash');
SELECT ok((SELECT expires_at - created_at BETWEEN interval '71 hours 59 minutes' AND interval '72 hours' FROM app.partner_invite WHERE token_hash = encode(sha256(convert_to('h32:i1', 'UTF8')), 'hex')), 'PA-15: the invite expires 72 hours after creation');
SELECT is((SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'partner_invite' AND column_name ~* 'token' AND column_name <> 'token_hash'), 0, 'PA-14: only the hash is stored (no plaintext token column)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.invite.create' AND actor_user_id = '00000000-0000-0000-0000-2000000000b1' AND detail ->> 'role' = 'staff'), 1, 'the create wrote an audit_log row naming the actor');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'manager', 'm2@example.test', encode(sha256(convert_to('h32:i2', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach',
  'PA-15: a manager inviting a MANAGER is 403 (rank: the role must be strictly below)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000003', 'operator', 'o2@example.test', encode(sha256(convert_to('h32:i3', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: only an admin invites an operator, into an operator org',
  'PA-15: a manager inviting an OPERATOR is 403');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000002', 'staff', 'sy2@example.test', encode(sha256(convert_to('h32:i4', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach',
  'PA-15: a manager inviting at ANOTHER facility is 403 (the grant is a subset of the inviter reach)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'sponsor', 'sp@example.test', encode(sha256(convert_to('h32:i5', 'UTF8')), 'hex'))$q$)$t$, '22023', 'partner_invite_create_for_partner: a staff, manager or operator role is required (sponsor invites are disabled)',
  'PA-15: a sponsor invite is refused (disabled until P6)');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'Staff-X@example.test', encode(sha256(convert_to('h32:i6', 'UTF8')), 'hex'))$q$), 'already_member',
  'PA-14/6.1: an invite to a person who holds an ACTIVE membership in that org is a status (409), nothing written');
SELECT is((SELECT count(*)::int FROM app.partner_invite WHERE token_hash = encode(sha256(convert_to('h32:i6', 'UTF8')), 'hex')), 0, '... and no invite row exists for it');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'staff-x-revoked@example.test', encode(sha256(convert_to('h32:i7', 'UTF8')), 'hex'))$q$), 'ok',
  '6.1: a REVOKED member can be invited again (the membership is reactivated at accept)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'x@example.test', 'ABCDEF')$q$)$t$, '22023', NULL, 'a token hash that is not 64 lowercase hex is 22023');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'x@example.test', upper(encode(sha256(convert_to('h32:i8', 'UTF8')), 'hex')))$q$)$t$, '22023', NULL, '... uppercase hex included');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'not-an-email', encode(sha256(convert_to('h32:i9', 'UTF8')), 'hex'))$q$)$t$, '22023', NULL, 'a malformed invitee email is 22023');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'a b@example.test', encode(sha256(convert_to('h32:i9', 'UTF8')), 'hex'))$q$)$t$, '22023', NULL, '... and one with whitespace inside');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('ffffffff-0000-0000-0000-000000000000', 'staff', 'x@example.test', encode(sha256(convert_to('h32:i9', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: no scope', 'an unknown org is 403 (indistinguishable from a foreign one)');
-- the A2 prerequisites are real: no PIN grant, then a PIN grant but no passkey assertion
SELECT throws_ok($$SELECT pg_temp.call('SELECT o_status FROM private.partner_invite_create_for_partner(''10000000-0000-0000-0000-000000000001'', ''staff'', ''x@example.test'', ''' || repeat('a', 64) || ''')')$$, '42501', 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required',
  'PA-22 shape: invite create is A2: the PIN grant is SINGLE USE, so a create without a fresh one is refused');
ROLLBACK TO SAVEPOINT inv_mx;

SAVEPOINT inv_no_reauth;
SELECT pg_temp.bind(:'th_mx');
SELECT pg_temp.seed_cols('mx', $$pin_grant_until = clock_timestamp() + interval '55 seconds'$$);
SELECT throws_ok($$SELECT pg_temp.call('SELECT o_status FROM private.partner_invite_create_for_partner(''10000000-0000-0000-0000-000000000001'', ''staff'', ''x@example.test'', ''' || repeat('a', 64) || ''')')$$, '42501',
  'partner_authorize: a passkey assertion in the last 5 minutes is required', 'PA-22: a PIN grant without a fresh passkey assertion is refused (A2 needs reauth)');
ROLLBACK TO SAVEPOINT inv_no_reauth;

SAVEPOINT inv_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'op-staff@example.test', encode(sha256(convert_to('h32:o1', 'UTF8')), 'hex'))$q$), 'ok', 'PA-15: an operator whose trail includes the facility invites {staff} (A3 stands in for the PIN of a PIN-less operator)');
SELECT is(pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'manager', 'op-mgr@example.test', encode(sha256(convert_to('h32:o2', 'UTF8')), 'hex'))$q$), 'ok', 'PA-15: ... and {manager}');
SELECT throws_ok($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000002', 'staff', 'op-y@example.test', encode(sha256(convert_to('h32:o3', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach',
  'PA-15: an operator inviting at a facility NOT on its trail is 403');
SELECT throws_ok($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000003', 'operator', 'op-op@example.test', encode(sha256(convert_to('h32:o4', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: only an admin invites an operator, into an operator org',
  'PA-15: an operator inviting an OPERATOR is 403 (only an admin does)');
ROLLBACK TO SAVEPOINT inv_op;

SAVEPOINT inv_ad;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000003', 'operator', 'new-op@example.test', encode(sha256(convert_to('h32:a1', 'UTF8')), 'hex'))$q$), 'ok', 'PA-15: an admin invites an {operator} into an operator org');
SELECT throws_ok($t$SELECT pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'operator', 'new-op2@example.test', encode(sha256(convert_to('h32:a2', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: only an admin invites an operator, into an operator org',
  'PA-15: ... but not into a FACILITY org (the role must match the org kind)');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000002', 'manager', 'new-my@example.test', encode(sha256(convert_to('h32:a3', 'UTF8')), 'hex'))$q$), 'ok', 'PA-15: an admin invites a {manager} at any facility');
ROLLBACK TO SAVEPOINT inv_ad;

SAVEPOINT inv_staff;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok($t$SELECT pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'x@example.test', encode(sha256(convert_to('h32:s1', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_authorize: no scope', 'PA-15: a staff member cannot invite');
SELECT throws_ok($$SELECT pg_temp.call('SELECT o_id FROM private.partner_invite_list_for_partner(NULL)')$$, '42501', 'partner_authorize: no scope', 'a staff member cannot list invites (class A0 for manager / operator / admin)');
ROLLBACK TO SAVEPOINT inv_staff;

SAVEPOINT inv_other_facility;
SELECT pg_temp.bind(:'th_my');
SELECT throws_ok($t$SELECT pg_temp.call_a2('my', $q$SELECT o_status FROM private.partner_invite_create_for_partner('10000000-0000-0000-0000-000000000001', 'staff', 'x@example.test', encode(sha256(convert_to('h32:y1', 'UTF8')), 'hex'))$q$)$t$, '42501', 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach',
  'PA-15: a manager at Y inviting at X is 403');
ROLLBACK TO SAVEPOINT inv_other_facility;

-- list and revoke
SELECT pg_temp.mk_inv('l1', '10000000-0000-0000-0000-000000000001', 'staff', 'list1@example.test', '00000000-0000-0000-0000-2000000000b1') AS inv_l1 \gset
SELECT pg_temp.mk_inv('l2', '10000000-0000-0000-0000-000000000002', 'staff', 'list2@example.test', 'ee320000-0000-0000-0000-000000000001') AS inv_l2 \gset
SELECT pg_temp.mk_inv('l3', '10000000-0000-0000-0000-000000000001', 'staff', 'list3@example.test', '00000000-0000-0000-0000-2000000000b1') AS inv_l3 \gset
UPDATE app.partner_invite SET accepted_at = now(), accepted_by = 'ee320000-0000-0000-0000-000000000011' WHERE id = :'inv_l3';
SAVEPOINT inv_list;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call($$SELECT string_agg(o_invitee_email, ',' ORDER BY o_invitee_email) FROM private.partner_invite_list_for_partner(NULL) WHERE o_invitee_email LIKE 'list%'$$), 'list1@example.test,list3@example.test',
  'a manager lists the invites of their own facility (and not those of Y)');
SELECT is(pg_temp.call($$SELECT count(*)::text FROM private.partner_invite_list_for_partner('10000000-0000-0000-0000-000000000002')$$), '0', 'a manager listing a FOREIGN org gets nothing');
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid = 'app.partner_invite'::regclass AND a.attnum > 0 AND a.attname ~* 'token'), ARRAY['token_hash'],
  'sanity: the only token-ish column is token_hash');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.partner_invite_list_for_partner(uuid)'::regprocedure AND pg_get_function_result(p.oid) ~* 'token'), 0, 'PA-14: the list never returns the token hash (it is not an output column)');
ROLLBACK TO SAVEPOINT inv_list;
SAVEPOINT inv_list_admin;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call($$SELECT string_agg(o_invitee_email, ',' ORDER BY o_invitee_email) FROM private.partner_invite_list_for_partner(NULL) WHERE o_invitee_email LIKE 'list%'$$), 'list1@example.test,list2@example.test,list3@example.test', 'an admin lists every org''s invites');
ROLLBACK TO SAVEPOINT inv_list_admin;
SAVEPOINT inv_list_my;
SELECT pg_temp.bind(:'th_my');
SELECT is(pg_temp.call($$SELECT string_agg(o_invitee_email, ',' ORDER BY o_invitee_email) FROM private.partner_invite_list_for_partner(NULL) WHERE o_invitee_email LIKE 'list%'$$), 'list2@example.test', 'a manager at Y sees only Y''s invites');
ROLLBACK TO SAVEPOINT inv_list_my;

SAVEPOINT inv_revoke;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$, :'inv_l1')), 'ok', 'a manager revokes an invite of their facility');
SELECT is((SELECT (revoked_at IS NOT NULL, revoked_by::text)::text FROM app.partner_invite WHERE id = :'inv_l1'), '(t,00000000-0000-0000-0000-2000000000b1)', '... revoked_at and revoked_by are written');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$, :'inv_l1')), 'already_revoked', 'a second revoke is a status, not an error');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$, :'inv_l3')), 'already_accepted', 'an ACCEPTED invite cannot be revoked');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$, :'inv_l2')), 'not_found', 'an invite of ANOTHER facility is not_found (a foreign id is not probeable)');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_invite WHERE id = :'inv_l2'), true, '... and it is untouched');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_invite_revoke_for_partner('ffffffff-0000-0000-0000-000000000000')$q$), 'not_found', 'an unknown id is the same not_found');
ROLLBACK TO SAVEPOINT inv_revoke;
SAVEPOINT inv_revoke_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', format($q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$, :'inv_l1')), 'ok', 'an operator whose trail covers the facility revokes its invite too');
ROLLBACK TO SAVEPOINT inv_revoke_op;
SAVEPOINT inv_revoke_staff;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_invite_revoke_for_partner(%L)$q$)$t$, :'inv_l1'), '42501', 'partner_authorize: no scope', 'a staff member cannot revoke an invite');
ROLLBACK TO SAVEPOINT inv_revoke_staff;

-- ----------------------------------------------------------------------------
-- 5. THE MINTER LANE, BRANCH N (6.1, PA-14, PA-23): email_for_token, then accept in its order, every outcome a status
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE acc (kind int, status text, user_id uuid, ref_id uuid, org_id uuid, role text, nonce bytea, exp bigint, mac bytea, us bigint);
GRANT ALL ON acc TO PUBLIC;
CREATE FUNCTION pg_temp.accept_n(p_label text, p_who text, p_gotrue uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; h text := pg_temp.hh(p_label); u uuid := pg_temp.u(p_who);
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT * INTO r FROM private.partner_invite_accept(h, u, p_gotrue);
  EXECUTE 'RESET ROLE';
  DELETE FROM acc;
  INSERT INTO acc VALUES (1, r.o_status, r.o_user_id, r.o_invite_id, r.o_org_id, r.o_role::text, r.o_nonce, r.o_exp, r.o_mac, r.o_accepted_at_us);
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.accept_t(p_label text, p_who text, p_gotrue uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; h text := pg_temp.hh(p_label); u uuid := pg_temp.u(p_who);
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT * INTO r FROM private.partner_enrolment_token_accept(h, u, p_gotrue);
  EXECUTE 'RESET ROLE';
  DELETE FROM acc;
  INSERT INTO acc VALUES (2, r.o_status, r.o_user_id, r.o_token_id, NULL, r.o_purpose, r.o_nonce, r.o_exp, r.o_mac, r.o_accepted_at_us);
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.email_for(p_kind text, p_label text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text; h text := pg_temp.hh(p_label);
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  IF p_kind = 'invite' THEN SELECT count(*) || ':' || coalesce(min(o_email), '') INTO r FROM private.partner_invite_email_for_token(h);
  ELSE SELECT count(*) || ':' || coalesce(min(o_email), '') INTO r FROM private.partner_enrolment_token_email_for_token(h); END IF;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
-- pg_temp.hh as a function the harness can call (the earlier global rewrite kept the definition itself)
SELECT pg_temp.mk_inv('n1', '10000000-0000-0000-0000-000000000001', 'staff', 'Newbie1@example.test') AS inv_n1 \gset
SELECT pg_temp.mk_inv('n2', '10000000-0000-0000-0000-000000000001', 'staff', 'newbie2@example.test') AS inv_n2 \gset
SELECT pg_temp.mk_inv('nu', '10000000-0000-0000-0000-000000000001', 'staff', 'unconfirmed@example.test') AS inv_nu \gset
SELECT pg_temp.mk_inv('nx', '10000000-0000-0000-0000-000000000001', 'staff', 'newbie1@example.test') AS inv_nx \gset
SELECT pg_temp.mk_inv('nr', '10000000-0000-0000-0000-000000000001', 'staff', 'newbie1@example.test') AS inv_nr \gset
SELECT pg_temp.mk_inv('na', '10000000-0000-0000-0000-000000000001', 'staff', 'newbie1@example.test') AS inv_na \gset
SELECT pg_temp.mk_inv('nm', '10000000-0000-0000-0000-000000000001', 'staff', 'multi@example.test') AS inv_nm \gset
SELECT pg_temp.mk_inv('nad', '10000000-0000-0000-0000-000000000001', 'staff', 'admin2@example.test') AS inv_nad \gset
SELECT pg_temp.mk_inv('nrv', '10000000-0000-0000-0000-000000000001', 'manager', 'rv@example.test') AS inv_nrv \gset
SELECT pg_temp.fix(format($$UPDATE app.partner_invite SET created_at = now() - interval '2 days', expires_at = now() - interval '1 hour' WHERE id = %L$$, :'inv_nx'));
UPDATE app.partner_invite SET revoked_at = now(), revoked_by = '00000000-0000-0000-0000-2000000000b1' WHERE id = :'inv_nr';
UPDATE app.partner_invite SET accepted_at = now() - interval '1 hour', accepted_by = 'ee320000-0000-0000-0000-000000000012' WHERE id = :'inv_na';
SELECT is(pg_temp.email_for('invite', 'n1'), '1:newbie1@example.test', 'PA-17 shape: email_for_token returns the NORMALISED address of a live invite');
SELECT is(pg_temp.email_for('invite', 'nx') || '|' || pg_temp.email_for('invite', 'nr') || '|' || pg_temp.email_for('invite', 'na') || '|' || pg_temp.email_for('invite', 'zz-unknown'), '0:|0:|0:|0:',
  'PA-14: an EXPIRED, a REVOKED, an ACCEPTED and an UNKNOWN token are one answer: no row');
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_invite_email_for_token('nothex')$$, '22023', 'partner_invite_email_for_token: a 64-hex token hash is required', 'a malformed hash is 22023');
RESET ROLE;
SELECT throws_ok(format($$SELECT pg_temp.bind(%L); SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_invite_email_for_token(%L)$$, :'th_mx', repeat('a', 64)), '42501', NULL, 'the minter-lane definers are refused inside a BOUND transaction (the 0041 rule)');
RESET ROLE;

SAVEPOINT acc_notfound;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011') AS g_nb1 \gset
SELECT is(pg_temp.accept_n('n1-unknown', 'nb1', :'g_nb1'), 'not_found', 'PA-14: an UNKNOWN token is not_found');
SELECT is(pg_temp.accept_n('nx', 'nb1', :'g_nb1'), 'not_found', 'PA-14: an EXPIRED invite is the same not_found');
SELECT is(pg_temp.accept_n('nr', 'nb1', :'g_nb1'), 'not_found', 'PA-14: a REVOKED invite likewise');
SELECT is(pg_temp.accept_n('na', 'nb1', :'g_nb1'), 'not_found', 'PA-14: an ACCEPTED (spent) invite likewise');
SELECT is((SELECT attempts::text FROM app.partner_invite WHERE id = :'inv_nx'), '0', '... and none of them counts an attempt (nothing to count against)');
ROLLBACK TO SAVEPOINT acc_notfound;

SAVEPOINT acc_mismatch;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000012') AS g_nb2 \gset
SELECT lives_ok(format($$SELECT pg_temp.accept_n('n1', 'nb2', %L)$$, :'g_nb2'), 'PA-14: a verified uid whose email is NOT the invite''s does not RAISE: it is a status the handler commits');
SELECT is((SELECT status FROM acc), 'email_mismatch', 'PA-14: the forwarded-link cell: the status is email_mismatch (403 at the handler)');
SELECT is((SELECT attempts::text FROM app.partner_invite WHERE id = :'inv_n1'), '1', 'PA-14: the mismatch ATTEMPT COUNT was written (a status commits; a RAISE would have rolled it back)');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id IN ('ee320000-0000-0000-0000-000000000011', 'ee320000-0000-0000-0000-000000000012')), 0, 'PA-14: ... and no membership was written for anyone');
SELECT is((SELECT (accepted_at IS NULL AND accepted_by IS NULL)::text FROM app.partner_invite WHERE id = :'inv_n1'), 'true', 'PA-14: ... and the invite is not consumed');
SELECT is((SELECT nonce IS NULL AND mac IS NULL FROM acc), true, 'PA-14: no register challenge is issued on a mismatch');
ROLLBACK TO SAVEPOINT acc_mismatch;

SAVEPOINT acc_lock;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000012') AS g_nb2 \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011') AS g_nb1 \gset
SELECT sum((pg_temp.accept_n('n1', 'nb2', :'g_nb2') = 'email_mismatch')::int) AS n_mismatch FROM generate_series(1, 10) i \gset
SELECT is((SELECT attempts::text FROM app.partner_invite WHERE id = :'inv_n1'), '10', 'PA-14: ten attempts are counted');
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_nb1'), 'locked', 'PA-14: the 11th, even with the RIGHT person and a fresh session, is locked');
SELECT is((SELECT attempts::text FROM app.partner_invite WHERE id = :'inv_n1'), '10', '... and a locked attempt is not counted again');
SELECT is(pg_temp.email_for('invite', 'n1'), '0:', 'PA-17 shape: a locked invite sends no OTP (email_for_token answers no row)');
ROLLBACK TO SAVEPOINT acc_lock;

SAVEPOINT acc_unconfirmed;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000013') AS g_nbu \gset
SELECT is(pg_temp.accept_n('nu', 'nbu', :'g_nbu'), 'email_unconfirmed', 'an unconfirmed mailbox is refused (a status)');
SELECT is((SELECT attempts::text FROM app.partner_invite WHERE id = :'inv_nu'), '1', '... and counted');
ROLLBACK TO SAVEPOINT acc_unconfirmed;

SAVEPOINT acc_stale;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011', interval '5 minutes') AS g_old \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000012') AS g_other \gset
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_old'), 'session_stale', 'the GoTrue session must be FRESH (60 s): a five-minute-old one is refused');
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_other'), 'session_stale', 'the GoTrue session must be THIS user''s: another user''s fresh session is refused');
SELECT is(pg_temp.accept_n('n1', 'nb1', gen_random_uuid()), 'session_stale', '... and a GoTrue session that does not exist is refused');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000011'), 0, 'no membership was written by any of them');
ROLLBACK TO SAVEPOINT acc_stale;

-- PA-23: a person who already has an active credential
SAVEPOINT acc_existing;
SELECT pg_temp.mk_cred('nb1x', 'ee320000-0000-0000-0000-000000000011') AS c_nb1x \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011') AS g_nb1 \gset
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_nb1'), 'existing_member_sign_in', 'PA-23: a person with an ACTIVE credential gets existing_member_sign_in (409)');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000011'), 0, 'PA-23: ... no membership is written');
SELECT is((SELECT (accepted_at IS NULL)::text || ',' || attempts FROM app.partner_invite WHERE id = :'inv_n1'), 'true,1', 'PA-23: ... the invite is NOT consumed (only attempts moved), so it still works for branch E');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000011'), 1, 'PA-16/PA-23: ... and no credential was created (email OTP alone never adds one)');
SELECT is((SELECT nonce IS NULL FROM acc), true, 'PA-23: ... and no register challenge was issued');
ROLLBACK TO SAVEPOINT acc_existing;

SAVEPOINT acc_recover_required;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000003') AS g_mu \gset
SELECT is(pg_temp.accept_n('nm', 'mu', :'g_mu'), 'recover_required', 'PA-23 (R2-L1): a person with an active membership and NO active credential gets recover_required (409)');
SELECT is((SELECT (accepted_at IS NULL)::text || ',' || attempts FROM app.partner_invite WHERE id = :'inv_nm'), 'true,1', 'PA-23: ... the invite is unconsumed');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000003'), 0, 'PA-23: ... and no credential exists');
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000002') AS g_ad2 \gset
SELECT is(pg_temp.accept_n('nad', 'ad2', :'g_ad2'), 'recover_required', 'PA-23: an ADMIN with no credential is recover_required too (an invite is not a way round the reach rule)');
ROLLBACK TO SAVEPOINT acc_recover_required;

-- the happy path
SAVEPOINT acc_ok;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011') AS g_nb1 \gset
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_nb1'), 'ok', 'PA-14: a matching, confirmed, fresh, credential-less, membership-less person is accepted');
SELECT is((SELECT (role::text, revoked_at IS NULL, invited_by::text)::text FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000011' AND org_id = '10000000-0000-0000-0000-000000000001'),
  '(staff,t,00000000-0000-0000-0000-2000000000b1)', '(c): the membership is inserted with the invite''s role, active, invited_by the inviter');
SELECT is((SELECT (accepted_at IS NOT NULL, accepted_by::text, attempts)::text FROM app.partner_invite WHERE id = :'inv_n1'), '(t,ee320000-0000-0000-0000-000000000011,1)', '(c): accepted_at and accepted_by are set; one attempt');
SELECT is((SELECT (octet_length(nonce), exp > extract(epoch FROM now()) + 590, user_id::text = 'ee320000-0000-0000-0000-000000000011', ref_id = :'inv_n1'::uuid, kind)::text FROM acc), '(32,t,t,t,1)',
  '(c): the register challenge is issued: a 32-byte nonce, about 600 s, bound to the uid and the invite, ref kind 1');
SELECT is((SELECT mac FROM acc), pg_temp.mac_of(2, (SELECT exp FROM acc), (SELECT nonce FROM acc), 'ee320000-0000-0000-0000-000000000011', 1, :'inv_n1'::uuid,
  pg_temp.us_of((SELECT accepted_at FROM app.partner_invite WHERE id = :'inv_n1'))), 'PA-7b: the MAC the accept returned equals the independent oracle over (uid, invite id, the acceptance time READ FROM THE ROW)');
SELECT is((SELECT us FROM acc), pg_temp.us_of((SELECT accepted_at FROM app.partner_invite WHERE id = :'inv_n1')), 'PA-7b: the acceptance time it returns is the stored microsecond value');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.invite.accept' AND subject_id = :'inv_n1' AND detail ->> 'branch' = 'new'), 1, 'the accept wrote an audit_log row');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000011') + (SELECT count(*)::int FROM app.partner_session WHERE user_id = 'ee320000-0000-0000-0000-000000000011'), 0,
  'the accept creates no credential and no session (register_first does, against the challenge)');
SELECT is(pg_temp.accept_n('n1', 'nb1', :'g_nb1'), 'not_found', 'PA-14: the token is single use: a second accept is not_found');
ROLLBACK TO SAVEPOINT acc_ok;

SAVEPOINT acc_reactivate;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000007') AS g_rv \gset
SELECT is(pg_temp.accept_n('nrv', 'rv', :'g_rv'), 'ok', '6.1: a REVOKED member is accepted again');
SELECT is((SELECT (role::text, revoked_at IS NULL)::text FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000007' AND org_id = '10000000-0000-0000-0000-000000000001'), '(manager,t)',
  '6.1: the membership is REACTIVATED with the INVITE''s role (manager), not the old one');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000007'), 1, '... in place: still one row');
ROLLBACK TO SAVEPOINT acc_reactivate;

-- ----------------------------------------------------------------------------
-- 6. register_first (6.1 step 4, R3-L3, R4-L2): the DB-side create checks, one registration per acceptance, the first session in the same transaction
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE reg_out (status text, cred uuid, sid uuid, aal smallint, expires timestamptz, enrol timestamptz);
GRANT ALL ON reg_out TO PUBLIC;
CREATE FUNCTION pg_temp.reg_std(p_label text, p_flags int DEFAULT 69, p_rp text DEFAULT 'partners.example.test', p_type text DEFAULT 'webauthn.create', p_origin text DEFAULT 'https://partners.example.test',
  p_extra text DEFAULT '', p_fmt text DEFAULT 'none', p_empty boolean DEFAULT true, p_cose bytea DEFAULT NULL, p_att_cid bytea DEFAULT NULL, p_arg_cid bytea DEFAULT NULL, p_arg_key bytea DEFAULT NULL,
  p_transports text[] DEFAULT NULL, p_nonce bytea DEFAULT NULL, p_mac bytea DEFAULT NULL, p_exp bigint DEFAULT NULL, p_ref uuid DEFAULT NULL, p_uid uuid DEFAULT NULL, p_cdj_nonce bytea DEFAULT NULL,
  p_att bytea DEFAULT NULL, p_counter int DEFAULT 0) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE a record; v_cose bytea; v_cid bytea; v_ad bytea; v_att bytea; v_cdj bytea; v_nonce bytea; v_h text; r record; v_uid uuid; v_ref uuid; v_exp bigint; v_mac bytea; v_arg_cid bytea; v_arg_key bytea;
BEGIN
  SELECT * INTO a FROM acc;
  v_cose := coalesce(p_cose, pg_temp.cose()); v_cid := pg_temp.credid(p_label);
  v_ad := pg_temp.authdata(coalesce(p_att_cid, v_cid), v_cose, p_flags, p_rp, p_counter);
  v_att := coalesce(p_att, pg_temp.attobj(v_ad, p_fmt, p_empty));
  v_nonce := coalesce(p_nonce, a.nonce);
  v_cdj := pg_temp.cdj(coalesce(p_cdj_nonce, v_nonce), p_type, p_origin, p_extra);
  v_h := pg_temp.hh('sess_' || p_label); v_uid := coalesce(p_uid, a.user_id); v_ref := coalesce(p_ref, a.ref_id); v_exp := coalesce(p_exp, a.exp); v_mac := coalesce(p_mac, a.mac);
  v_arg_cid := coalesce(p_arg_cid, v_cid); v_arg_key := coalesce(p_arg_key, v_cose);
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT * INTO r FROM private.partner_credential_register_first(v_h, v_uid, a.kind::smallint, v_ref, v_nonce, v_exp, v_mac, v_att, v_cdj, v_arg_cid, v_arg_key, p_transports);
  EXECUTE 'RESET ROLE';
  DELETE FROM reg_out;
  INSERT INTO reg_out VALUES (r.o_status, r.o_credential_id, r.o_session_id, r.o_aal, r.o_expires_at, r.o_enrolment_until);
  RETURN r.o_status;
END
$f$;
-- sets up "nb1 accepted invite n1" (the challenge is in acc) inside the caller's savepoint
CREATE FUNCTION pg_temp.accepted_nb1() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE g uuid := pg_temp.gotrue('ee320000-0000-0000-0000-000000000011');
BEGIN
  RETURN pg_temp.accept_n('n1', 'nb1', g);
END
$f$;
CREATE FUNCTION pg_temp.n_cred_sess_chal() RETURNS text LANGUAGE sql AS $f$
  SELECT (SELECT count(*) FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000011') || '/' ||
         (SELECT count(*) FROM app.partner_session WHERE user_id = 'ee320000-0000-0000-0000-000000000011') || '/' ||
         (SELECT count(*) FROM app.partner_auth_challenge WHERE user_id = 'ee320000-0000-0000-0000-000000000011')
$f$;

SAVEPOINT reg_ok;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup: nb1 accepts invite n1 (challenge issued)');
SELECT is(pg_temp.reg_std('r1', p_transports => ARRAY['internal', 'hybrid']), 'ok', 'PA-7b: register_first with a well-formed create ceremony is ok');
SELECT is((SELECT (c.alg, c.sign_count, c.backup_eligible, c.backup_state, c.transports, c.revoked_at IS NULL, c.note IS NULL, c.created_via_credential_id IS NULL)::text FROM app.partner_credential c
           WHERE c.id = (SELECT cred FROM reg_out)), '(-7,0,f,f,"{internal,hybrid}",t,t,t)', 'the credential: alg -7, counter and backup flags FROM authData, transports as given, no note, no creating credential (the first one)');
SELECT is((SELECT c.credential_id = pg_temp.credid('r1') AND c.public_key = pg_temp.cose() FROM app.partner_credential c WHERE c.id = (SELECT cred FROM reg_out)), true, 'the credential id and the COSE key stored are the ones in authData (and equal the arguments)');
SELECT matches((SELECT c.label FROM app.partner_credential c WHERE c.id = (SELECT cred FROM reg_out)), '^[0-9]{4}-[0-9]{2}-[0-9]{2} / abababab-abab-abab-abab-abababababab$', 'the label is DATABASE-DERIVED (date / aaguid from authData), never client-supplied');
SELECT is((SELECT (s.mint_kind, s.mint_signature IS NULL, s.aal, s.user_id::text, s.credential_id = (SELECT cred FROM reg_out), s.token_hash = pg_temp.hh('sess_r1'), s.revoked_at IS NULL)::text FROM app.partner_session s WHERE s.id = (SELECT sid FROM reg_out)),
  '(register,t,1,ee320000-0000-0000-0000-000000000011,t,t,t)', 'PA-7b (iv): the FIRST SESSION exists in the same transaction: mint_kind register, NO signature (an attestation-none ceremony has none), aal 1, the token hash given');
SELECT ok((SELECT s.enrolment_until > now() + interval '14 minutes 55 seconds' AND s.enrolment_until <= now() + interval '15 minutes 5 seconds' FROM app.partner_session s WHERE s.id = (SELECT sid FROM reg_out)), 'the session carries enrolment_until = now + 15 minutes');
SELECT is((SELECT (s.mint_client_data_json = pg_temp.cdj(a.nonce), s.mint_nonce_hash = sha256(a.nonce), octet_length(s.mint_authenticator_data) > 100)::text FROM app.partner_session s, acc a WHERE s.id = (SELECT sid FROM reg_out)), '(t,t,t)',
  '... storing the create ceremony''s evidence: the client data, sha256 of the nonce, the authenticator data');
SELECT is((SELECT (purpose, user_id::text, minted_session_id = (SELECT sid FROM reg_out))::text FROM app.partner_auth_challenge WHERE nonce_hash = sha256((SELECT nonce FROM acc))), '(register,ee320000-0000-0000-0000-000000000011,t)',
  'PA-7b (iv): the nonce is recorded ONCE, purpose register, naming the session it minted');
SELECT is((SELECT registered_credential_id = (SELECT cred FROM reg_out) FROM app.partner_invite WHERE id = :'inv_n1'), true, 'PA-23: the registration is recorded on the invite (one registration per acceptance)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.credential.register_first' AND subject_id = (SELECT cred::text FROM reg_out)), 1, 'the registration wrote an audit_log row');
SELECT is(pg_temp.reg_std('r2'), 'already_registered', 'PA-7b (iii) / PA-23: a SECOND registration from one acceptance is refused');
SELECT is(pg_temp.n_cred_sess_chal(), '1/1/1', '... and wrote no second credential, session or nonce');
SELECT is((SELECT status FROM (SELECT pg_temp.accept_n('n1', 'nb1', pg_temp.gotrue('ee320000-0000-0000-0000-000000000011')) AS status) x), 'not_found', 'PA-14: the invite is spent: it cannot be accepted again');
ROLLBACK TO SAVEPOINT reg_ok;

SAVEPOINT reg_flags;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT is(pg_temp.reg_std('f1', p_flags => 93, p_counter => 7), 'ok', 'BE and BS set and a non-zero counter are taken FROM authData');
SELECT is((SELECT (c.sign_count, c.backup_eligible, c.backup_state)::text FROM app.partner_credential c WHERE c.id = (SELECT cred FROM reg_out)), '(7,t,t)', '... into sign_count, backup_eligible and backup_state');
ROLLBACK TO SAVEPOINT reg_flags;

-- PA-7c: each refusal leaves NO credential, NO session and does not burn the nonce
SAVEPOINT reg_refuse;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT is(pg_temp.reg_std('x1', p_type => 'webauthn.get'), 'bad_client_type', 'PA-7c: clientDataJSON.type other than webauthn.create');
SELECT is(pg_temp.reg_std('x2', p_extra => ',"crossOrigin":true'), 'cross_origin', 'PA-7c: crossOrigin: true');
SELECT is(pg_temp.reg_std('x3', p_extra => ',"topOrigin":"https://evil.example"'), 'cross_origin', 'PA-7c: a topOrigin (a cross-origin iframe)');
SELECT is(pg_temp.reg_std('x4', p_origin => 'https://evil.example'), 'bad_origin', 'PA-7c: a wrong origin');
SELECT is(pg_temp.reg_std('x5', p_cdj_nonce => decode(repeat('0b', 32), 'hex')), 'challenge_mismatch', 'PA-7c: a challenge that does not match the bound nonce');
SELECT is(pg_temp.reg_std('x6', p_fmt => 'packed', p_empty => false), 'bad_fmt', 'PA-7c: an attestation fmt other than none (packed, with a statement)');
SELECT is(pg_temp.reg_std('x7', p_fmt => 'none', p_empty => false), 'bad_fmt', 'PA-7c: ... and fmt none carrying a non-empty attStmt');
SELECT is(pg_temp.reg_std('x8', p_att => '\x00'::bytea), 'bad_attestation', 'PA-7c: an attestation object that is not CBOR of the three keys');
SELECT is(pg_temp.reg_std('x9', p_rp => 'other.example.test'), 'bad_rp_id_hash', 'PA-7c: a wrong rpIdHash');
SELECT is(pg_temp.reg_std('x10', p_flags => 68), 'flags_missing', 'PA-7c: UP missing');
SELECT is(pg_temp.reg_std('x11', p_flags => 65), 'flags_missing', 'PA-7c: UV missing');
SELECT is(pg_temp.reg_std('x12', p_flags => 5), 'flags_missing', 'PA-7c: AT missing');
SELECT is(pg_temp.reg_std('x13', p_flags => 69 + 128), 'bad_authenticator_data', 'PA-7c: the extension-data flag (the key would no longer be the rest of authData)');
SELECT is(pg_temp.reg_std('x14', p_flags => 69 + 16), 'bad_authenticator_data', 'PA-7c: backup state without backup eligibility');
SELECT is(pg_temp.reg_std('x15', p_att_cid => pg_temp.credid('another')), 'bad_credential', 'PA-7c: a credential id in authData that differs from the one being stored');
SELECT is(pg_temp.reg_std('x16', p_arg_key => pg_temp.cose(decode(repeat('33', 32), 'hex'))), 'bad_key', 'PA-7c: a key argument that differs from the key in authData');
SELECT is(pg_temp.reg_std('x17', p_cose => substr(pg_temp.cose(), 1, 40)), 'bad_key', 'PA-7c: a COSE key that does not parse (truncated)');
SELECT is(pg_temp.reg_std('x18', p_cose => decode('a5010203272001215820', 'hex') || decode(repeat('11', 32), 'hex') || decode('225820', 'hex') || decode(repeat('22', 32), 'hex')), 'bad_key', 'PA-7c: an algorithm other than -7 or -257 (-8)');
SELECT is(pg_temp.reg_std('x19', p_transports => ARRAY['usb2']), 'bad_transports', 'a transport outside the WebAuthn list');
SELECT is(pg_temp.n_cred_sess_chal(), '0/0/0', 'PA-7c: NONE of the nineteen refusals created a credential or a session, or burned the nonce');
SELECT is(pg_temp.reg_std('x20', p_mac => decode(repeat('00', 32), 'hex')), 'bad_challenge', 'PA-7b: a tampered MAC');
SELECT is(pg_temp.reg_std('x21', p_exp => (SELECT exp + 1 FROM acc)), 'bad_challenge', 'PA-7b: a tampered expiry');
SELECT is(pg_temp.reg_std('x22', p_nonce => decode(repeat('0c', 32), 'hex')), 'bad_challenge', 'PA-7b: a nonce the MAC does not cover');
SELECT is(pg_temp.reg_std('x23', p_ref => :'inv_n2'::uuid), 'not_accepted', 'PA-7b (ii): a challenge bound to invite X cannot enrol for invite Y (Y was not accepted by this uid)');
SELECT is(pg_temp.reg_std('x24', p_uid => 'ee320000-0000-0000-0000-000000000012'), 'not_accepted', 'PA-7b (ii): ... nor for a different uid');
SELECT is(pg_temp.reg_std('x25', p_exp => 1000, p_mac => pg_temp.mac_of(2, 1000, (SELECT nonce FROM acc), 'ee320000-0000-0000-0000-000000000011', 1, :'inv_n1'::uuid, (SELECT us FROM acc))), 'expired',
  'PA-7b: an EXPIRED challenge with a VALID MAC (built with the independent oracle) is refused');
SELECT is(pg_temp.n_cred_sess_chal(), '0/0/0', '... still nothing written');
ROLLBACK TO SAVEPOINT reg_refuse;

SAVEPOINT reg_age;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT pg_temp.fix(format($$UPDATE app.partner_invite SET accepted_at = now() - interval '16 minutes' WHERE id = %L$$, :'inv_n1'));
SELECT is(pg_temp.reg_std('a1'), 'accept_expired', 'PA-7b (iii): a registration more than 15 minutes after the acceptance is refused');
ROLLBACK TO SAVEPOINT reg_age;

SAVEPOINT reg_race;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT pg_temp.mk_cred('nb1race', 'ee320000-0000-0000-0000-000000000011') AS c_race \gset
SELECT is(pg_temp.reg_std('c1'), 'credential_exists', 'PA-23: register_first refuses when an ACTIVE credential exists (the race with another enrolment)');
SELECT is(pg_temp.n_cred_sess_chal(), '1/0/0', '... nothing else written');
ROLLBACK TO SAVEPOINT reg_race;

SAVEPOINT reg_other_org;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee320000-0000-0000-0000-000000000011', '10000000-0000-0000-0000-000000000002', 'staff');
SELECT is(pg_temp.reg_std('o1'), 'other_membership', 'PA-23 (R2-L1): an invite-bound enrolment is refused when the person holds an active membership in ANY other org');
ROLLBACK TO SAVEPOINT reg_other_org;

SAVEPOINT reg_inuse;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT is(pg_temp.reg_std('u1', p_att_cid => decode(md5('c32:sx') || md5('c32b:sx'), 'hex'), p_arg_cid => decode(md5('c32:sx') || md5('c32b:sx'), 'hex')), 'credential_in_use', 'a credential id that already belongs to someone is refused');
SELECT is(pg_temp.reg_std('u2'), 'replayed', 'PA-7b: ... and that attempt BURNED the challenge nonce (single use is the primary key): a retry on it is replayed');
ROLLBACK TO SAVEPOINT reg_inuse;

SAVEPOINT reg_evict;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT pg_temp.mk_cred('nb1old', 'ee320000-0000-0000-0000-000000000011') AS c_old \gset
UPDATE app.partner_credential SET revoked_at = now() WHERE id = :'c_old';
SELECT pg_temp.mk_session('old1', 'ee320000-0000-0000-0000-000000000011', :'c_old', 1, interval '5 hours');
SELECT pg_temp.mk_session('old2', 'ee320000-0000-0000-0000-000000000011', :'c_old', 1, interval '4 hours');
SELECT pg_temp.mk_session('old3', 'ee320000-0000-0000-0000-000000000011', :'c_old', 1, interval '3 hours');
SELECT pg_temp.mk_session('old4', 'ee320000-0000-0000-0000-000000000011', :'c_old', 1, interval '2 hours');
SELECT is(pg_temp.reg_std('e1'), 'ok', '4.1: register_first with four older live sessions of the person');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = 'ee320000-0000-0000-0000-000000000011' AND revoked_at IS NULL), 3, '4.1: at most THREE live sessions remain');
SELECT is((SELECT array_agg(s.token_hash = pg_temp.th('old1') OR s.token_hash = pg_temp.th('old2') ORDER BY s.created_at) FROM app.partner_session s WHERE s.user_id = 'ee320000-0000-0000-0000-000000000011' AND s.revoked_at IS NOT NULL),
  ARRAY[true, true], '4.1: the two OLDEST were revoked (REVOKED, not deleted: the row stays)');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = 'ee320000-0000-0000-0000-000000000011' AND revoke_reason = 'session_limit'), 2, '... with reason session_limit');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = (SELECT sid FROM reg_out)), true, '... and the NEW session is among the live ones');
ROLLBACK TO SAVEPOINT reg_evict;

CREATE FUNCTION pg_temp.mint_cross() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE a record; s record; r record; v_cid bytea := pg_temp.credid('m1'); h text := pg_temp.hh('mint_cross');
BEGIN
  SELECT * INTO a FROM acc;
  SELECT s2.mint_authenticator_data AS ad, s2.mint_client_data_json AS cdj INTO s FROM app.partner_session s2 WHERE s2.id = (SELECT sid FROM reg_out);
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  SELECT * INTO r FROM private.partner_session_mint(h, v_cid, a.nonce, a.exp, a.mac, s.ad, s.cdj, decode(repeat('05', 70), 'hex'));
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
SAVEPOINT reg_mint_cross;
SELECT is(pg_temp.accepted_nb1(), 'ok', 'setup');
SELECT is(pg_temp.reg_std('m1'), 'ok', 'setup: registered');
SELECT is(pg_temp.mint_cross(), 'bad_challenge', 'PA-7b (iv): a sign-in mint on the REGISTER challenge fails (its MAC is purpose 2, the mint verifies purpose 1)');
ROLLBACK TO SAVEPOINT reg_mint_cross;

-- ----------------------------------------------------------------------------
-- 7. MEMBERS (6.5): revoke one membership, recover, pin reset, under the reach rule (PA-25); the last-membership delete (PA-29)
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('ad2', 'ee320000-0000-0000-0000-000000000002') AS c_ad2 \gset
SELECT pg_temp.mk_session('ad2', 'ee320000-0000-0000-0000-000000000002', :'c_ad2', 2) AS s_ad2 \gset
SELECT pg_temp.th('ad2') AS th_ad2 \gset
SELECT pg_temp.mk_session('mx2', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx2 \gset
SELECT pg_temp.mk_session('op2', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op2 \gset

SAVEPOINT rev_mx;
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000003');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000003');
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001')$q$), 'ok', 'a manager revokes staff at their facility');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001'), true, '... the membership carries revoked_at');
SELECT is((SELECT (revoke_reason, revoked_at IS NOT NULL)::text FROM app.partner_session WHERE id = :'s_sx'), '(authority_changed,t)', '6.5: the revoke kills the person''s sessions (the authority trigger)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.member.revoke' AND actor_user_id = '00000000-0000-0000-0000-2000000000b1'), 1, '... and an audit_log row names the actor');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001')$q$), 'not_found', 'revoking an already revoked membership is not_found');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-1000000000a3', '10000000-0000-0000-0000-000000000001')$q$), 'not_found', 'revoking a membership the person does not hold (staff_y at X) is not_found');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-1000000000a3', '10000000-0000-0000-0000-000000000002')$q$)$t$, '42501',
  'partner_member_revoke_for_partner: the reach rule does not cover this membership', 'PA-25: a manager at X revoking staff at Y is 403');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-3000000000c1', '10000000-0000-0000-0000-000000000003')$q$)$t$, '42501',
  'partner_member_revoke_for_partner: the reach rule does not cover this membership', 'PA-25: ... and an operator (an admin matter)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-2000000000b1', '10000000-0000-0000-0000-000000000001')$q$)$t$, '22023',
  'partner_member_revoke_for_partner: a different target person and an org are required', 'a manager cannot revoke themselves here (5): never oneself');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('ee320000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001')$q$), 'ok',
  'PA-25: a person who works at X AND Y: the manager at X revokes their membership AT X (one membership)');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000003' AND org_id = '10000000-0000-0000-0000-000000000002'), true, '... their membership at Y is untouched');
SELECT is((SELECT (count(*) FILTER (WHERE user_id = 'ee320000-0000-0000-0000-000000000003'))::text FROM app.partner_pin) || '/' || (SELECT count(*)::text FROM app.partner_totp WHERE user_id = 'ee320000-0000-0000-0000-000000000003'), '1/1',
  'PA-29: a person with a membership LEFT keeps their PIN and TOTP');
ROLLBACK TO SAVEPOINT rev_mx;

SAVEPOINT rev_admin;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-3000000000c1', '10000000-0000-0000-0000-000000000003')$q$), 'ok', 'PA-25: an admin revokes an operator membership');
ROLLBACK TO SAVEPOINT rev_admin;
SAVEPOINT rev_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-2000000000b1', '10000000-0000-0000-0000-000000000001')$q$), 'ok', 'an operator whose trail covers X revokes a manager there');
ROLLBACK TO SAVEPOINT rev_op;
SAVEPOINT rev_staff;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok($t$SELECT pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001')$q$)$t$, '42501', 'partner_authorize: no scope', 'staff cannot revoke');
ROLLBACK TO SAVEPOINT rev_staff;

-- PA-29: the last-membership delete, by the function, by a plain UPDATE and by a DELETE
SAVEPOINT pa29_last;
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000003');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000003');
UPDATE app.partner_member SET revoked_at = now() WHERE user_id = 'ee320000-0000-0000-0000-000000000003' AND org_id = '10000000-0000-0000-0000-000000000002';
SELECT is((SELECT count(*)::int FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000003'), 1, 'PA-29 setup: one membership (X) is left, so the PIN is still there');
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('ee320000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001')$q$), 'ok', 'the LAST active membership is revoked');
SELECT is((SELECT count(*)::int FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000003'), 0, 'PA-29: revoking the last membership of a NON-admin deletes their PIN ...');
SELECT is((SELECT count(*)::int FROM app.partner_totp WHERE user_id = 'ee320000-0000-0000-0000-000000000003'), 0, 'PA-29: ... and their TOTP');
ROLLBACK TO SAVEPOINT pa29_last;

SAVEPOINT pa29_admin;
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000004');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000004');
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_member_revoke_for_partner('ee320000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000001')$q$), 'ok', 'an admin revokes the staff membership of a person who is also an admin');
SELECT is((SELECT count(*)::int FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000004'), 0, 'PA-29: a user in app.admin_user loses the PIN with their last membership ...');
SELECT is((SELECT count(*)::int FROM app.partner_totp WHERE user_id = 'ee320000-0000-0000-0000-000000000004'), 1, 'PA-29: ... but NOT the TOTP (an admin holds no membership and needs it regardless)');
ROLLBACK TO SAVEPOINT pa29_admin;

SAVEPOINT pa29_delete;
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000006');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000006');
SELECT pg_temp.mk_totp('00000000-0000-0000-0000-4000000000d0');
DELETE FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000006';
SELECT is((SELECT count(*)::int FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000006') + (SELECT count(*)::int FROM app.partner_totp WHERE user_id = 'ee320000-0000-0000-0000-000000000006'), 0,
  'PA-29: a membership DELETE (an ops delete, or an org-delete cascade) of the last membership deletes the PIN and the TOTP of a non-admin too');
ROLLBACK TO SAVEPOINT pa29_delete;
SAVEPOINT pa29_reinstate;
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000006');
UPDATE app.partner_member SET revoked_at = NULL WHERE user_id = 'ee320000-0000-0000-0000-000000000006';
UPDATE app.partner_member SET role = 'operator' WHERE user_id = 'ee320000-0000-0000-0000-000000000006';
SELECT is((SELECT count(*)::int FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000006'), 1, 'PA-29: an update that does not revoke deletes nothing');
ROLLBACK TO SAVEPOINT pa29_reinstate;

-- PA-25: recovery
SELECT pg_temp.mk_pin('00000000-0000-0000-0000-1000000000a1', true);
SELECT pg_temp.mk_cred('sx2', '00000000-0000-0000-0000-1000000000a1') AS c_sx2 \gset
SAVEPOINT recover_mx;
INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
VALUES ('00000000-0000-0000-0000-1000000000a1', 'recover', '00000000-0000-0000-0000-2000000000b1', pg_temp.hh('old-recover'), now() - interval '1 hour', now() + interval '23 hours');
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-1000000000a1', %L)$q$, pg_temp.hh('rec1'))), 'ok', 'PA-25: a manager recovers staff at their facility');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 0, 'PA-25: EVERY credential of the person is revoked');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoke_reason = 'recovered' AND revoked_by = '00000000-0000-0000-0000-2000000000b1'), 2, 'PA-25: ... both, with reason recovered and the actor');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 0, 'PA-25: ... and every session');
SELECT is((SELECT (must_change, locked_at IS NULL, failed_count, failed_today, next_attempt_at IS NULL)::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), '(t,t,0,0,t)', 'PA-25: the PIN is must_change with the lock and counters cleared');
SELECT is((SELECT (purpose, issued_by::text, consumed_at IS NULL, token_hash = pg_temp.hh('rec1'))::text FROM app.partner_enrolment_token WHERE token_hash = pg_temp.hh('rec1')), '(recover,00000000-0000-0000-0000-2000000000b1,t,t)', 'PA-25: a recover token is issued (purpose, issuer, unconsumed, only the hash)');
SELECT ok((SELECT expires_at - created_at BETWEEN interval '23 hours 59 minutes' AND interval '24 hours' FROM app.partner_enrolment_token WHERE token_hash = pg_temp.hh('rec1')), 'PA-25: ... valid for 24 hours');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_enrolment_token WHERE token_hash = pg_temp.hh('old-recover')), true, 'PA-25: an EARLIER live recover token of that person is retired');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.member.recover' AND (detail ->> 'credentials_revoked')::int = 2), 1, '... and an audit_log row records the recovery');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 1, '6.5: recovery does not touch the membership');
ROLLBACK TO SAVEPOINT recover_mx;

SAVEPOINT recover_refuse;
SELECT pg_temp.bind(:'th_mx');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000003', %L)$q$)$t$, pg_temp.hh('rec2')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25: a manager at X cannot recover a person who also works at Y');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-4000000000d0', %L)$q$)$t$, pg_temp.hh('rec3')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25 (R2-M1): a manager acting on a ZERO-MEMBERSHIP admin is 403');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000004', %L)$q$)$t$, pg_temp.hh('rec4')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25 (R2-M1): ... and on a staff member who is also an admin');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-3000000000c1', %L)$q$)$t$, pg_temp.hh('rec5')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25 (R2-M1): ... and on an operator');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000005', %L)$q$)$t$, pg_temp.hh('rec6')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25: ... and on a non-admin with no active membership');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-2000000000b1', %L)$q$)$t$, pg_temp.hh('rec7')), '22023',
  'partner_member_recover_for_partner: a different target person and a 64-hex token hash are required', 'PA-25: a manager recovering themselves is refused');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id IN ('ee320000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-3000000000c1') AND revoked_at IS NOT NULL), 0, 'PA-25: ... and none of those refusals revoked anything');
SELECT is((SELECT count(*)::int FROM app.partner_enrolment_token WHERE purpose = 'recover' AND token_hash LIKE ANY (SELECT pg_temp.hh('rec' || i) FROM generate_series(2, 7) i)), 0, '... or issued a token');
ROLLBACK TO SAVEPOINT recover_refuse;

SAVEPOINT recover_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-1000000000a1', %L)$q$, pg_temp.hh('rec8'))), 'ok', 'PA-25: an operator whose trail covers the facility recovers staff there');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000006', %L)$q$)$t$, pg_temp.hh('rec9')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25: an operator cannot recover ANOTHER operator');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000003', %L)$q$)$t$, pg_temp.hh('rec10')), '42501',
  'partner_member_recover_for_partner: the reach rule does not cover this person', 'PA-25: ... nor a person who also works at Y (fac_y is not on the trail)');
ROLLBACK TO SAVEPOINT recover_op;

SAVEPOINT recover_admin;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-3000000000c1', %L)$q$, pg_temp.hh('rec11'))), 'ok', 'PA-25: an admin recovers an operator');
SELECT is(pg_temp.call_a2('ad', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000002', %L)$q$, pg_temp.hh('rec12'))), 'ok', 'PA-25: an admin recovers a DIFFERENT, zero-membership admin (admin recovery works)');
SELECT is(pg_temp.call_a2('ad', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-000000000005', %L)$q$, pg_temp.hh('rec13'))), 'ok', 'PA-25: ... and a non-admin with no active membership (allowed for an admin)');
SELECT throws_ok(format($t$SELECT pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-4000000000d0', %L)$q$)$t$, pg_temp.hh('rec14')), '22023',
  'partner_member_recover_for_partner: a different target person and a 64-hex token hash are required', 'PA-25: an admin acting on themselves is refused');
ROLLBACK TO SAVEPOINT recover_admin;
SAVEPOINT recover_admin2;
SELECT pg_temp.bind(:'th_ad2');
SELECT is(pg_temp.call_a2('ad2', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-4000000000d0', %L)$q$, pg_temp.hh('rec15'))), 'ok', 'PA-25: ... and another admin recovers the first');
ROLLBACK TO SAVEPOINT recover_admin2;
SAVEPOINT recover_noemail;
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email) VALUES ('ee320000-0000-0000-0000-0000000000f1', NULL);
RESET ROLE;
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee320000-0000-0000-0000-0000000000f1', '10000000-0000-0000-0000-000000000001', 'staff');
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('ee320000-0000-0000-0000-0000000000f1', %L)$q$, pg_temp.hh('rec16'))), 'no_email', 'a person with no auth email cannot be sent a recovery token: a status, nothing written');
ROLLBACK TO SAVEPOINT recover_noemail;
SAVEPOINT recover_mx_second;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-1000000000a1', %L)$q$, pg_temp.hh('rec17'))), 'ok', 'setup: a first recovery');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_member_recover_for_partner('00000000-0000-0000-0000-1000000000a1', %L)$q$, pg_temp.hh('rec18'))), 'ok', 'a SECOND recovery is fine ...');
SELECT is((SELECT count(*)::int FROM app.partner_enrolment_token WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND purpose = 'recover' AND revoked_at IS NULL AND consumed_at IS NULL), 1, '... and leaves exactly ONE live recover token (the earlier one retired)');
ROLLBACK TO SAVEPOINT recover_mx_second;

-- PIN reset
SAVEPOINT pinreset;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-1000000000a1')$q$), 'ok', 'a manager unlocks a LOCKED PIN of staff at their facility');
SELECT is((SELECT (locked_at IS NULL, failed_count, failed_today, failed_day IS NULL, last_failed_at IS NULL, next_attempt_at IS NULL, must_change)::text FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'),
  '(t,0,0,t,t,t,t)', '6.3: the lock and every failure counter are cleared and must_change is set (the person chooses a new PIN under an OTP proof)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-2000000000b1')$q$)$t$, '22023',
  'partner_pin_reset_for_partner: a different target person is required', '6.3: never for oneself');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-1000000000a3')$q$)$t$, '42501',
  'partner_pin_reset_for_partner: the reach rule does not cover this person', 'PA-25: a manager at X cannot reset the PIN of staff at Y');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('ee320000-0000-0000-0000-000000000003')$q$)$t$, '42501',
  'partner_pin_reset_for_partner: the reach rule does not cover this person', 'PA-25: ... nor of a person who also works at Y');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-3000000000c1')$q$)$t$, '42501',
  'partner_pin_reset_for_partner: the reach rule does not cover this person', 'PA-25: ... nor of an operator');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-4000000000d0')$q$)$t$, '42501',
  'partner_pin_reset_for_partner: the reach rule does not cover this person', 'PA-25: ... nor of an admin');
ROLLBACK TO SAVEPOINT pinreset;
SAVEPOINT pinreset_unset;
DELETE FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1';
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-1000000000a1')$q$), 'unset', 'a person with no PIN row: a status (unset), nothing to reset');
ROLLBACK TO SAVEPOINT pinreset_unset;
SAVEPOINT pinreset_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-1000000000a1')$q$), 'ok', 'an operator whose trail covers the facility resets staff PINs there');
ROLLBACK TO SAVEPOINT pinreset_op;
SAVEPOINT pinreset_admin;
SELECT pg_temp.mk_pin('00000000-0000-0000-0000-3000000000c1', true);
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-3000000000c1')$q$), 'ok', 'an admin resets an operator''s PIN (an admin matter)');
ROLLBACK TO SAVEPOINT pinreset_admin;
SAVEPOINT pinreset_staff;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok($t$SELECT pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_pin_reset_for_partner('00000000-0000-0000-0000-1000000000a1')$q$)$t$, '42501', 'partner_authorize: no scope', 'staff cannot reset a PIN, not even their own (the unlock is a manager action)');
ROLLBACK TO SAVEPOINT pinreset_staff;

-- the people the enrolment and branch-E flows need (confirmed mailboxes; made here because the harness cannot confirm an existing auth.users row): a recoverable staff member with two credentials,
-- a signed-in member with two credentials and two sessions (branch E), and one whose mailbox is NOT confirmed
SELECT pg_temp.mk_cred('rc1', 'ee320000-0000-0000-0000-000000000008');
SELECT pg_temp.mk_cred('rc2', 'ee320000-0000-0000-0000-000000000008');
SELECT pg_temp.mk_cred('em1', 'ee320000-0000-0000-0000-000000000009') AS c_em \gset
SELECT pg_temp.mk_cred('em2', 'ee320000-0000-0000-0000-000000000009');
SELECT pg_temp.mk_cred('eu1', 'ee320000-0000-0000-0000-00000000000a') AS c_eu \gset
SELECT pg_temp.mk_session('em', 'ee320000-0000-0000-0000-000000000009', :'c_em') AS s_em \gset
SELECT pg_temp.mk_session('emb', 'ee320000-0000-0000-0000-000000000009', :'c_em') AS s_emb \gset
SELECT pg_temp.mk_session('eu', 'ee320000-0000-0000-0000-00000000000a', :'c_eu') AS s_eu \gset
SELECT pg_temp.th('em') AS th_em, pg_temp.th('eu') AS th_eu \gset

-- ----------------------------------------------------------------------------
-- 8. ENROLMENT TOKENS (6.1, 6.4, 6.5): recover and admin tokens, accepted in the same order; first credential for a PERSON (ref kind 2)
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.mk_tok(p_label text, p_uid uuid, p_purpose text, p_by uuid DEFAULT '00000000-0000-0000-0000-2000000000b1') RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
  VALUES (p_uid, p_purpose, p_by, encode(sha256(convert_to('h32:' || p_label, 'UTF8')), 'hex'), now(), now() + interval '24 hours') RETURNING id
$f$;
SELECT pg_temp.mk_tok('tk1', 'ee320000-0000-0000-0000-000000000008', 'recover') AS tok_rec \gset
SELECT pg_temp.mk_tok('tk2', 'ee320000-0000-0000-0000-000000000004', 'admin', NULL) AS tok_adm \gset
SELECT pg_temp.mk_tok('tk3', 'ee320000-0000-0000-0000-000000000011', 'admin', '00000000-0000-0000-0000-4000000000d0') AS tok_badadm \gset
SELECT pg_temp.mk_tok('tk4', 'ee320000-0000-0000-0000-000000000005', 'recover') AS tok_nomem \gset
SELECT pg_temp.mk_tok('tk5', 'ee320000-0000-0000-0000-000000000013', 'recover') AS tok_unc \gset
SELECT pg_temp.mk_tok('tk6', 'ee320000-0000-0000-0000-000000000008', 'recover') AS tok_exp \gset
SELECT pg_temp.mk_tok('tk7', 'ee320000-0000-0000-0000-000000000008', 'recover') AS tok_rev \gset
SELECT pg_temp.fix(format($$UPDATE app.partner_enrolment_token SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = %L$$, :'tok_exp'));
UPDATE app.partner_enrolment_token SET revoked_at = now() WHERE id = :'tok_rev';
SELECT is(pg_temp.email_for('token', 'tk1'), '1:rc@example.test', 'email_for_token returns the PERSON''S OWN auth email for a live token');
SELECT is(pg_temp.email_for('token', 'tk6') || '|' || pg_temp.email_for('token', 'tk7') || '|' || pg_temp.email_for('token', 'zz-unknown'), '0:|0:|0:', 'an expired, a revoked and an unknown token are one answer: no row');
SELECT throws_ok($$SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_enrolment_token_email_for_token('x')$$, '22023', 'partner_enrolment_token_email_for_token: a 64-hex token hash is required', 'a malformed hash is 22023');
RESET ROLE;
SELECT throws_ok(format($$SELECT pg_temp.bind(%L); SET LOCAL ROLE edge_partner_minter; SELECT * FROM private.partner_enrolment_token_accept(%L, %L, gen_random_uuid())$$, :'th_mx', repeat('b', 64), 'ee320000-0000-0000-0000-000000000011'),
  '42501', 'partner_enrolment_token_accept: refused inside a bound transaction', 'the token accept is refused inside a bound transaction');
RESET ROLE;

SAVEPOINT tok_statuses;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000008') AS g_rc \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000011') AS g_nb1 \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000013') AS g_nbu \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000005') AS g_nm \gset
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000008', interval '5 minutes') AS g_rc_old \gset
SELECT is(pg_temp.accept_t('tk6', 'rc', :'g_rc') || '|' || pg_temp.accept_t('tk7', 'rc', :'g_rc') || '|' || pg_temp.accept_t('zz-unknown', 'rc', :'g_rc'), 'not_found|not_found|not_found', 'PA-14: expired, revoked and unknown tokens are one not_found');
SELECT is(pg_temp.accept_t('tk1', 'nb1', :'g_nb1'), 'email_mismatch', 'a verified uid that is NOT the token''s person is a status (email_mismatch), never a RAISE');
SELECT is((SELECT attempts::text FROM app.partner_enrolment_token WHERE id = :'tok_rec'), '1', '... and the attempt count is written (it commits)');
SELECT is(pg_temp.accept_t('tk5', 'nbu', :'g_nbu'), 'email_unconfirmed', 'an unconfirmed mailbox is refused');
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc_old'), 'session_stale', 'a stale GoTrue session is refused');
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc'), 'existing_member_sign_in', 'PA-16: email OTP alone does NOT add a credential to a person with an ACTIVE one (the person has two)');
SELECT is((SELECT consumed_at IS NULL FROM app.partner_enrolment_token WHERE id = :'tok_rec'), true, 'PA-16: ... and the token is not consumed');
SELECT is(pg_temp.accept_t('tk3', 'nb1', :'g_nb1'), 'refused', 'an ADMIN token for a person who is not in admin_user is refused');
SELECT is(pg_temp.accept_t('tk4', 'nm', :'g_nm'), 'refused', 'a RECOVER token for a person with no active membership who is not an admin is refused');
SELECT count(*) FROM generate_series(1, 1) \gset
SELECT sum((pg_temp.accept_t('tk1', 'nb1', :'g_nb1') = 'email_mismatch')::int) AS n9 FROM generate_series(1, 9) i \gset
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc'), 'locked', 'PA-14: after ten attempts the token is locked, whoever presents it');
ROLLBACK TO SAVEPOINT tok_statuses;

SAVEPOINT tok_recover_ok;
UPDATE app.partner_credential SET revoked_at = now() WHERE user_id = 'ee320000-0000-0000-0000-000000000008';
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000008') AS g_rc \gset
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc'), 'ok', 'PA-25: after recovery (no active credential) the person accepts the recover token');
SELECT is((SELECT (kind, status, role, octet_length(nonce))::text FROM acc), '(2,ok,recover,32)', '... the register challenge comes back with ref kind 2 and the purpose');
SELECT is((SELECT mac FROM acc), pg_temp.mac_of(2, (SELECT exp FROM acc), (SELECT nonce FROM acc), 'ee320000-0000-0000-0000-000000000008', 2, :'tok_rec'::uuid,
  pg_temp.us_of((SELECT consumed_at FROM app.partner_enrolment_token WHERE id = :'tok_rec'))), 'PA-7b: its MAC equals the independent oracle over (uid, token id, consumed_at), ref kind 2');
SELECT is((SELECT (consumed_at IS NOT NULL, attempts)::text FROM app.partner_enrolment_token WHERE id = :'tok_rec'), '(t,1)', 'the token is consumed (single use) with one attempt');
SELECT is(pg_temp.reg_std('t1'), 'ok', 'PA-25: the person registers their new credential against the TOKEN (no org rule applies: they keep their membership)');
SELECT is((SELECT (c.user_id::text, c.revoked_at IS NULL)::text FROM app.partner_credential c WHERE c.id = (SELECT cred FROM reg_out)), '(ee320000-0000-0000-0000-000000000008,t)', '... a new ACTIVE credential of that person');
SELECT is((SELECT registered_credential_id = (SELECT cred FROM reg_out) FROM app.partner_enrolment_token WHERE id = :'tok_rec'), true, '... recorded on the token');
SELECT is((SELECT s.mint_kind || ':' || (s.mint_signature IS NULL)::text FROM app.partner_session s WHERE s.id = (SELECT sid FROM reg_out)), 'register:true', '... and the first session minted in the same transaction (no signature)');
SELECT is(pg_temp.reg_std('t2'), 'already_registered', 'one registration per acceptance holds for tokens too');
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc'), 'not_found', 'PA-14: ... and cannot be accepted again');
ROLLBACK TO SAVEPOINT tok_recover_ok;

SAVEPOINT tok_admin_ok;
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000004') AS g_sa \gset
SELECT is(pg_temp.accept_t('tk2', 'sa', :'g_sa'), 'ok', '6.4: an admin enrolment token is accepted by the admin it names (the branch-N flow against the token table)');
SELECT is((SELECT role FROM acc), 'admin', '... with purpose admin');
SELECT is(pg_temp.reg_std('t3'), 'ok', '6.4: ... and the admin registers their first credential');
ROLLBACK TO SAVEPOINT tok_admin_ok;

CREATE FUNCTION pg_temp.bootstrap(p_uid uuid, p_hash text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.partner_admin_bootstrap_token(p_uid, p_hash)::text INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
SAVEPOINT tok_bootstrap;
SELECT pg_temp.bootstrap('ee320000-0000-0000-0000-000000000004', pg_temp.hh('bt1')) AS tok_bt \gset
SELECT is((SELECT (purpose, issued_by IS NULL, consumed_at IS NULL, expires_at <= created_at + interval '24 hours', expires_at > created_at + interval '23 hours')::text FROM app.partner_enrolment_token WHERE id = :'tok_bt'::uuid),
  '(admin,t,t,t,t)', '6.4 (M4): the ops bootstrap writes an admin token (issued_by NULL, 24 h): 0053''s function could never insert (an RLS violation on RETURNING, then the 24 h CHECK); 0054 replaces it');
SELECT throws_ok($$SELECT pg_temp.bootstrap('ee320000-0000-0000-0000-000000000005', repeat('f', 64))$$, '42501', 'partner_admin_bootstrap_token: the user must already be in app.admin_user', 'the bootstrap refuses a user who is not in admin_user');
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000004') AS g_sa \gset
SELECT is(pg_temp.accept_t('bt1', 'sa', :'g_sa'), 'ok', '6.4: the bootstrapped admin token is accepted by the admin it names');
ROLLBACK TO SAVEPOINT tok_bootstrap;
SAVEPOINT tok_admin_issue;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', format($q$SELECT o_status FROM private.partner_admin_enrolment_issue_for_partner('ee320000-0000-0000-0000-000000000004', %L)$q$, pg_temp.hh('bt2'))), 'ok', '6.4: an admin issues an admin enrolment token for a different admin (A3)');
SELECT is((SELECT (purpose, issued_by::text, expires_at <= created_at + interval '24 hours')::text FROM app.partner_enrolment_token WHERE token_hash = pg_temp.hh('bt2')), '(admin,00000000-0000-0000-0000-4000000000d0,t)', '... recorded with its issuer, within the 24 h CHECK');
ROLLBACK TO SAVEPOINT tok_admin_issue;

SAVEPOINT tok_race;
UPDATE app.partner_credential SET revoked_at = now() WHERE user_id = 'ee320000-0000-0000-0000-000000000008';
SELECT pg_temp.gotrue('ee320000-0000-0000-0000-000000000008') AS g_rc \gset
SELECT is(pg_temp.accept_t('tk1', 'rc', :'g_rc'), 'ok', 'setup');
SELECT pg_temp.mk_cred('rcrace', 'ee320000-0000-0000-0000-000000000008');
SELECT is(pg_temp.reg_std('t4'), 'credential_exists', 'PA-16: register_first refuses when an active credential appeared in the gap (token-bound too)');
ROLLBACK TO SAVEPOINT tok_race;

-- ----------------------------------------------------------------------------
-- 9. BRANCH E (6.1, PA-23, PA-14): a member with an active credential joins another org; the session user's confirmed email must equal the invite's
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_inv('e1', '10000000-0000-0000-0000-000000000002', 'staff', 'em@example.test', 'ee320000-0000-0000-0000-000000000001') AS inv_e1 \gset
SELECT pg_temp.mk_inv('e2', '10000000-0000-0000-0000-000000000002', 'staff', 'forwardee-target@example.test', 'ee320000-0000-0000-0000-000000000001') AS inv_e2 \gset
SELECT pg_temp.mk_inv('e3', '10000000-0000-0000-0000-000000000001', 'staff', 'em@example.test') AS inv_e3 \gset
SELECT pg_temp.mk_inv('e4', '10000000-0000-0000-0000-000000000002', 'manager', 'em@example.test', 'ee320000-0000-0000-0000-000000000001') AS inv_e4 \gset
CREATE FUNCTION pg_temp.accept_e(p_label text, p_sess text DEFAULT 'em') RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text; h text := pg_temp.hh(p_label);
BEGIN
  PERFORM pg_temp.a2(p_sess);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT o_status || ':' || coalesce(o_org_id::text, '') || ':' || coalesce(o_role::text, '') INTO r FROM private.partner_invite_accept_for_partner(h);
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
SAVEPOINT e_ok;
SELECT pg_temp.bind(:'th_em');
SELECT is(pg_temp.accept_e('e1'), 'ok:10000000-0000-0000-0000-000000000002:staff', 'PA-23: branch E: the session user''s confirmed email equals the invite''s: the membership at Y is activated');
SELECT is((SELECT (role::text, revoked_at IS NULL, invited_by::text)::text FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000009' AND org_id = '10000000-0000-0000-0000-000000000002'), '(staff,t,ee320000-0000-0000-0000-000000000001)', 'branch E: the membership is written with the invite''s role and inviter');
SELECT is((SELECT (accepted_by::text, attempts)::text FROM app.partner_invite WHERE id = :'inv_e1'), '(ee320000-0000-0000-0000-000000000009,1)', 'branch E: the invite is consumed by the session user');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000009' AND created_at >= now() - interval '1 minute' AND label <> ''), 2, 'branch E: NO credential was created (the two credentials of the member are the ones that existed)');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'s_em'), true, '6.1: the ACCEPTING session is exempt from the authority trigger and stays live');
SELECT is((SELECT (revoke_reason, revoked_at IS NOT NULL)::text FROM app.partner_session WHERE id = :'s_emb'), '(authority_changed,t)', '6.5: ... while the person''s OTHER sessions are revoked by the membership INSERT');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.invite.accept' AND subject_id = :'inv_e1' AND detail ->> 'branch' = 'member'), 1, 'an audit_log row records the branch-E accept');
SELECT is(pg_temp.accept_e('e1'), 'not_found::', 'the token is single use: a second accept is not_found');
ROLLBACK TO SAVEPOINT e_ok;
SAVEPOINT e_forwarded;
SELECT pg_temp.bind(:'th_em');
SELECT is(pg_temp.accept_e('e2'), 'email_mismatch::', 'PA-14: a FORWARDED link: the session user''s email is not the invite''s: a status (403 at the handler), never a RAISE');
SELECT is((SELECT (attempts, accepted_at IS NULL)::text FROM app.partner_invite WHERE id = :'inv_e2'), '(1,t)', 'PA-14: the mismatch attempt count is written, the invite is not consumed');
SELECT is((SELECT count(*)::int FROM app.partner_member WHERE user_id = 'ee320000-0000-0000-0000-000000000009' AND org_id = '10000000-0000-0000-0000-000000000002'), 0, 'PA-14: ... and no membership was written');
ROLLBACK TO SAVEPOINT e_forwarded;
SAVEPOINT e_member;
SELECT pg_temp.bind(:'th_em');
SELECT is(pg_temp.accept_e('e3'), 'already_member::', 'an invite to an org the person is already ACTIVE in is a status (already_member)');
ROLLBACK TO SAVEPOINT e_member;
SAVEPOINT e_unconfirmed;
SELECT pg_temp.mk_inv('e5', '10000000-0000-0000-0000-000000000002', 'staff', 'eu@example.test', 'ee320000-0000-0000-0000-000000000001') AS inv_e5 \gset
SELECT pg_temp.bind(:'th_eu');
SELECT is(pg_temp.accept_e('e5', 'eu'), 'email_unconfirmed::', 'the session user''s mailbox must be CONFIRMED');
ROLLBACK TO SAVEPOINT e_unconfirmed;
SAVEPOINT e_react;
INSERT INTO app.partner_member (user_id, org_id, role, revoked_at) VALUES ('ee320000-0000-0000-0000-000000000009', '10000000-0000-0000-0000-000000000002', 'staff', now());
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000009', true);
SELECT pg_temp.mk_session('eme', 'ee320000-0000-0000-0000-000000000009', :'c_em') AS s_eme \gset
SELECT pg_temp.bind(pg_temp.th('eme'));
SELECT is(pg_temp.accept_e('e4', 'eme'), 'ok:10000000-0000-0000-0000-000000000002:manager', '6.1: a REVOKED membership is reactivated with the invite''s role');
SELECT is((SELECT (must_change, locked_at IS NULL, failed_count)::text FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000009'), '(t,t,0)', '6.1: ... and the PIN is reset (must_change) on a reactivation');
ROLLBACK TO SAVEPOINT e_react;
SAVEPOINT e_lock;
SELECT pg_temp.bind(:'th_em');
SELECT sum((pg_temp.accept_e('e2') = 'email_mismatch::')::int) AS n10 FROM generate_series(1, 10) i \gset
SELECT is(pg_temp.accept_e('e2'), 'locked::', 'PA-14: branch E locks after ten attempts too');
ROLLBACK TO SAVEPOINT e_lock;
SAVEPOINT e_a2;
SELECT pg_temp.bind(:'th_em');
SELECT throws_ok(format($t$SELECT pg_temp.call($q$SELECT o_status FROM private.partner_invite_accept_for_partner(%L)$q$)$t$, repeat('c', 64)), '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required', 'PA-23: branch E is class A2: without a PIN grant and a fresh passkey assertion it is refused');
ROLLBACK TO SAVEPOINT e_a2;
SAVEPOINT e_malformed;
SELECT pg_temp.bind(:'th_em');
SELECT throws_ok($t$SELECT pg_temp.call_a2('em', $q$SELECT o_status FROM private.partner_invite_accept_for_partner('not-a-hash')$q$)$t$, '22023', 'partner_invite_accept_for_partner: a 64-hex token hash is required', 'a malformed token hash is 22023');
ROLLBACK TO SAVEPOINT e_malformed;

-- ----------------------------------------------------------------------------
-- 10. CREDENTIALS (4.5, 6.5, PA-22): add a second one (A2 + reauth, session-bound challenge, the create core's checks), list, revoke (A2, own or reach)
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.opts(p_sess text) RETURNS jsonb LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.a2(p_sess);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_credential_options_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN jsonb_build_object('status', r.o_status, 'nonce', encode(r.o_nonce, 'hex'), 'exp', r.o_exp, 'mac', encode(r.o_mac, 'hex'), 'rp', r.o_rp_id, 'origin', r.o_origin,
    'exclude', (SELECT jsonb_agg(encode(x, 'hex') ORDER BY x) FROM unnest(r.o_exclude) x));
END
$f$;
CREATE FUNCTION pg_temp.reg2(p_sess text, p_cred text, p_o jsonb, p_flags int DEFAULT 69, p_origin text DEFAULT 'https://partners.example.test', p_mac bytea DEFAULT NULL, p_exp bigint DEFAULT NULL,
  p_transports text[] DEFAULT NULL) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; v_nonce bytea := decode(p_o ->> 'nonce', 'hex'); v_cose bytea := pg_temp.cose(); v_cid bytea := pg_temp.credid(p_cred);
        v_att bytea; v_cdj bytea; v_mac bytea := coalesce(p_mac, decode(p_o ->> 'mac', 'hex')); v_exp bigint := coalesce(p_exp, (p_o ->> 'exp')::bigint);
BEGIN
  v_att := pg_temp.attobj(pg_temp.authdata(v_cid, v_cose, p_flags));
  v_cdj := pg_temp.cdj(v_nonce, 'webauthn.create', p_origin);
  PERFORM pg_temp.a2(p_sess);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_credential_register_for_partner(v_nonce, v_exp, v_mac, v_att, v_cdj, v_cid, v_cose, p_transports);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
SELECT pg_temp.mk_session('sxc', '00000000-0000-0000-0000-1000000000a1', :'c_sx2') AS s_sxc \gset
SELECT pg_temp.th('sxc') AS th_sxc \gset
SAVEPOINT cred_add;
SELECT pg_temp.bind(:'th_sx');
SELECT pg_temp.opts('sx') AS o \gset
SELECT is(:'o'::jsonb ->> 'status', 'ok', 'PA-22: credentials/options (A2 + reauth) issues a challenge');
SELECT is(:'o'::jsonb ->> 'mac', encode(pg_temp.mac_of(3, (:'o'::jsonb ->> 'exp')::bigint, decode(:'o'::jsonb ->> 'nonce', 'hex'), :'s_sx'::uuid), 'hex'), 'PA-7b (v): the options MAC is the purpose-3 HMAC bound to the BOUND SESSION id (independent oracle)');
SELECT is((:'o'::jsonb ->> 'rp') || ' ' || (:'o'::jsonb ->> 'origin'), 'partners.example.test https://partners.example.test', 'the relying party comes from partner_rp_config');
SELECT ok((:'o'::jsonb ->> 'exp')::bigint BETWEEN extract(epoch FROM now())::bigint + 115 AND extract(epoch FROM now())::bigint + 125, 'the challenge lives 120 s');
SELECT is((:'o'::jsonb -> 'exclude'), (SELECT jsonb_agg(encode(x, 'hex') ORDER BY x) FROM (SELECT credential_id AS x FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL) y),
  'the exclude list is the person''s OWN active credential ids (so the authenticator is not asked to register one it already holds)');
-- the refusals that must not burn the challenge
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_mac => decode(repeat('00', 32), 'hex')), 'bad_challenge', 'PA-7b: a tampered MAC is bad_challenge');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_exp => (:'o'::jsonb ->> 'exp')::bigint + 1), 'bad_challenge', 'PA-7b: a tampered expiry likewise');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_origin => 'https://evil.example'), 'bad_origin', 'the create core''s checks apply to a second credential too (a wrong origin)');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_flags => 5), 'flags_missing', '... (AT missing)');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_transports => ARRAY['nope']), 'bad_transports', '... (an unknown transport)');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_exp => 1000, p_mac => pg_temp.mac_of(3, 1000, decode(:'o'::jsonb ->> 'nonce', 'hex'), :'s_sx'::uuid)), 'expired', 'PA-7b: an EXPIRED challenge with a valid MAC is refused');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 2, '... and no credential was added by any refusal');
SELECT is(pg_temp.reg2('sx', 'a1', :'o'::jsonb, p_transports => ARRAY['internal']), 'ok', 'PA-22: a second credential is registered (A2: PIN grant + passkey assertion, session-bound challenge)');
SELECT is((SELECT (c.created_via_credential_id = :'c_sx'::uuid, c.revoked_at IS NULL, c.transports, c.note IS NULL)::text FROM app.partner_credential c WHERE c.credential_id = pg_temp.credid('a1')), '(t,t,{internal},t)',
  'the new credential records the credential of the session that created it, is active, has no note');
SELECT matches((SELECT c.label FROM app.partner_credential c WHERE c.credential_id = pg_temp.credid('a1')), '^[0-9]{4}-[0-9]{2}-[0-9]{2} / abababab-abab-abab-abab-abababababab / added via [0-9a-f]{8}$',
  'PA-22: the label is DATABASE-DERIVED: creation date, the AAGUID and the creating credential''s id prefix (nothing the client sent)');
SELECT is((SELECT left(:'c_sx', 8)), (SELECT substring(c.label from 'added via ([0-9a-f]{8})$') FROM app.partner_credential c WHERE c.credential_id = pg_temp.credid('a1')), '... and the prefix is the SESSION''s credential');
SELECT is((SELECT (purpose, session_id = :'s_sx'::uuid, minted_session_id IS NULL, user_id::text)::text FROM app.partner_auth_challenge WHERE nonce_hash = sha256(decode(:'o'::jsonb ->> 'nonce', 'hex'))), '(register,t,t,00000000-0000-0000-0000-1000000000a1)',
  'the challenge nonce is recorded once, naming the session');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.credential.add' AND actor_user_id = '00000000-0000-0000-0000-1000000000a1'), 1, 'PA-22: the add wrote an audit_log row (the interim notice, open item U1)');
SELECT is(pg_temp.reg2('sx', 'a2', :'o'::jsonb), 'replayed', 'PA-7b: the SAME challenge cannot add a second credential (the nonce is single use)');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 3, '... the person holds three');
ROLLBACK TO SAVEPOINT cred_add;

SAVEPOINT cred_session_bound;
SELECT pg_temp.bind(:'th_sxc');
SELECT is(pg_temp.reg2('sxc', 'b1', jsonb_build_object('nonce', repeat('0d', 32), 'exp', extract(epoch FROM now())::bigint + 100,
    'mac', encode(pg_temp.mac_of(3, extract(epoch FROM now())::bigint + 100, decode(repeat('0d', 32), 'hex'), :'s_sx'::uuid), 'hex'))), 'bad_challenge',
  'PA-7b (v): a challenge issued for ANOTHER session (the same person, another device) is bad_challenge: the session id is inside the MAC');
ROLLBACK TO SAVEPOINT cred_session_bound;

SAVEPOINT cred_too_many;
SELECT pg_temp.mk_cred('sx3', '00000000-0000-0000-0000-1000000000a1');
SELECT pg_temp.mk_cred('sx4', '00000000-0000-0000-0000-1000000000a1');
SELECT pg_temp.mk_cred('sx5', '00000000-0000-0000-0000-1000000000a1');
SELECT pg_temp.bind(:'th_sx');
SELECT is(pg_temp.opts('sx') ->> 'status', 'too_many', 'at most FIVE active credentials: options refuses a sixth');
SELECT is(pg_temp.reg2('sx', 'a6', jsonb_build_object('nonce', repeat('0e', 32), 'exp', extract(epoch FROM now())::bigint + 100,
    'mac', encode(pg_temp.mac_of(3, extract(epoch FROM now())::bigint + 100, decode(repeat('0e', 32), 'hex'), :'s_sx'::uuid), 'hex'))), 'too_many', '... and so does register');
ROLLBACK TO SAVEPOINT cred_too_many;

SAVEPOINT cred_a2;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok($$SELECT pg_temp.call('SELECT o_status FROM private.partner_credential_options_for_partner()')$$, '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required',
  'PA-22: credentials/options without a fresh passkey assertion (reauth) is refused');
SELECT throws_ok($$SELECT pg_temp.call('SELECT o_status FROM private.partner_credential_register_for_partner(decode(repeat(''0d'', 32), ''hex''), 1, decode(repeat(''00'', 32), ''hex''), decode(''00'', ''hex''), decode(''00'', ''hex''), decode(''00'', ''hex''), decode(''00'', ''hex''), NULL)')$$,
  '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required', 'PA-22: ... and so is registering (adding a credential is A2 plus notice)');
ROLLBACK TO SAVEPOINT cred_a2;

SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])'::regprocedure
           AND (pg_get_function_arguments(p.oid) ~* 'label|note')), 0, 'PA-22: the register definer takes NO label and NO note: nothing the client sends reaches the label');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'partner\_%' AND p.prosrc ~* '\mc\.note\M|\.note\M' AND p.proname NOT IN ('partner_credential_list_for_partner')), 0,
  'PA-22: no partner definer reads the display-only note (only the list returns it, as a column, never in a decision)');

SAVEPOINT cred_list;
SELECT pg_temp.bind(:'th_sx');
SELECT is(pg_temp.call($$SELECT count(*)::text FROM private.partner_credential_list_for_partner()$$), '2', 'GET credentials: the person''s own two credentials');
SELECT is(pg_temp.call($$SELECT count(*)::text FROM private.partner_credential_list_for_partner() WHERE o_label ~ '^[0-9]{4}-'$$), '2', '... with their database-derived labels');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.partner_credential_list_for_partner()'::regprocedure AND pg_get_function_result(p.oid) ~* 'public_key|credential_id|sign_count'), 0, 'the list never returns the key, the credential id or the counter');
ROLLBACK TO SAVEPOINT cred_list;

-- revoke: A2 for every revoke, one's own included; the reach rule for another person's
SAVEPOINT cred_revoke_own;
SELECT pg_temp.bind(:'th_sx');
SELECT is(pg_temp.call_a2('sx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_sx2')), 'ok', 'PA-22: a person revokes their OWN credential (A2)');
SELECT is((SELECT (revoked_at IS NOT NULL, revoke_reason, revoked_by::text)::text FROM app.partner_credential WHERE id = :'c_sx2'), '(t,revoked,00000000-0000-0000-0000-1000000000a1)', '... revoked_at, reason and revoked_by');
SELECT is((SELECT (revoked_at IS NOT NULL, revoke_reason)::text FROM app.partner_session WHERE id = :'s_sxc'), '(t,credential_revoked)', 'PA-16: ... and the credential''s sessions are dead with it');
SELECT is(pg_temp.call_a2('sx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_sx2')), 'already_revoked', 'a second revoke is a status');
SELECT is(pg_temp.call_a2('sx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_sy')), 'not_found', 'ANOTHER person''s credential, outside the reach rule, is not_found (not probeable)');
SELECT is(pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_credential_revoke_for_partner('ffffffff-0000-0000-0000-000000000000')$q$), 'not_found', 'an unknown credential id is the same not_found');
ROLLBACK TO SAVEPOINT cred_revoke_own;
SAVEPOINT cred_revoke_a2;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok(format($t$SELECT pg_temp.call($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$)$t$, :'c_sx2'), '42501', 'partner_authorize: a passkey assertion in the last 5 minutes is required',
  'PA-22: ANY credential revoke, one''s own included, needs a fresh passkey assertion and a PIN (a coworker with the passcode cannot revoke them all)');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_credential WHERE id = :'c_sx2'), true, '... and nothing was revoked');
ROLLBACK TO SAVEPOINT cred_revoke_a2;
SAVEPOINT cred_revoke_mx;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_sx2')), 'ok', 'PA-25: a manager revokes the credential of staff at their facility (the reach rule)');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_sy')), 'not_found', 'PA-25: a manager at X cannot revoke the credential of staff at Y');
SELECT is(pg_temp.call_a2('mx', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_op')), 'not_found', 'PA-25: ... nor an operator''s');
ROLLBACK TO SAVEPOINT cred_revoke_mx;
SAVEPOINT cred_revoke_ad;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', format($q$SELECT o_status FROM private.partner_credential_revoke_for_partner(%L)$q$, :'c_op')), 'ok', 'PA-25: an admin revokes an operator''s credential');
ROLLBACK TO SAVEPOINT cred_revoke_ad;

-- ----------------------------------------------------------------------------
-- 11. THE STOLEN-IPAD BUTTON (6.5) and the TOTP reset under the full reach rule (6.4, 6.5)
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('mu1', 'ee320000-0000-0000-0000-000000000003') AS c_mu \gset
SELECT pg_temp.mk_session('mu', 'ee320000-0000-0000-0000-000000000003', :'c_mu') AS s_mu \gset
SAVEPOINT revall_mx;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status || ':' || o_credentials FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000001', NULL)$q$), 'ok:0', 'a manager revokes every session of their facility (no credentials without a time)');
SELECT is((SELECT count(*)::int FROM app.partner_session s WHERE s.user_id IN (SELECT user_id FROM app.partner_member WHERE org_id = '10000000-0000-0000-0000-000000000001' AND revoked_at IS NULL) AND s.revoked_at IS NULL), 0,
  '6.5: every live session of the org''s ACTIVE members is revoked (the revoker''s own included)');
SELECT is((SELECT revoke_reason FROM app.partner_session WHERE id = :'s_sx'), 'panic_revoke_all', '... with reason panic_revoke_all');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE id = :'s_sy' AND revoked_at IS NULL), 1, '... and the sessions of ANOTHER facility are untouched');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NOT NULL), 0, '... and no credential is revoked without a time');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.org.revoke_all'), 1, 'an audit_log row records it');
ROLLBACK TO SAVEPOINT revall_mx;
SAVEPOINT revall_t;
SELECT pg_temp.bind(:'th_mx');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status || ':' || o_credentials FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000001', now() - interval '1 minute')$q$), 'ok:7',
  '6.5: "every credential created after T": the seven credentials of the staff at X the manager covers are revoked');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = 'ee320000-0000-0000-0000-000000000003' AND revoked_at IS NOT NULL), 0, '6.5: ... but not the credential of a person who ALSO works at Y (the reach rule does not cover them)');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-2000000000b1' AND revoked_at IS NOT NULL), 0, '... nor the revoker''s own credential');
ROLLBACK TO SAVEPOINT revall_t;
SAVEPOINT revall_refuse;
SELECT pg_temp.bind(:'th_mx');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000002', NULL)$q$)$t$, '42501', 'partner_org_sessions_revoke_for_partner: no scope', 'a manager at X revoking all at Y is 403');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000003', NULL)$q$)$t$, '42501', 'partner_org_sessions_revoke_for_partner: no scope', '... and on an operator org (admin only)');
SELECT throws_ok($t$SELECT pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000001', now() + interval '1 day')$q$)$t$, '22023', NULL, 'a time in the future is refused');
SELECT is(pg_temp.call_a2('mx', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('ffffffff-0000-0000-0000-000000000000', NULL)$q$), 'not_found', 'an unknown org is a status');
ROLLBACK TO SAVEPOINT revall_refuse;
SAVEPOINT revall_op;
SELECT pg_temp.bind(:'th_op');
SELECT is(pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000001', NULL)$q$), 'ok', 'an operator whose trail covers the facility revokes all there');
ROLLBACK TO SAVEPOINT revall_op;
SAVEPOINT revall_ad;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000003', NULL)$q$), 'ok', 'an admin revokes all of an operator org');
ROLLBACK TO SAVEPOINT revall_ad;
SAVEPOINT revall_staff;
SELECT pg_temp.bind(:'th_sx');
SELECT throws_ok($t$SELECT pg_temp.call_a2('sx', $q$SELECT o_status FROM private.partner_org_sessions_revoke_for_partner('10000000-0000-0000-0000-000000000001', NULL)$q$)$t$, '42501', 'partner_authorize: no scope', 'staff cannot press the button');
ROLLBACK TO SAVEPOINT revall_staff;

-- the TOTP reset, full reach (S1.4 seam)
SELECT pg_temp.mk_totp('00000000-0000-0000-0000-3000000000c1');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000002');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000006');
SELECT pg_temp.mk_totp('00000000-0000-0000-0000-4000000000d0');
SAVEPOINT totp_reset;
SELECT pg_temp.bind(:'th_ad');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('00000000-0000-0000-0000-3000000000c1')$q$), 'ok', 'PA-24 / 6.4: an admin resets an operator''s TOTP (A3)');
SELECT is((SELECT (seed_version, confirmed_at IS NULL)::text FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), '(2,t)', '... bumps seed_version and clears confirmed_at');
SELECT is((SELECT revoke_reason FROM app.partner_session WHERE id = :'s_op'), 'totp_reset', '... and revokes the target''s sessions');
SELECT is(pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('ee320000-0000-0000-0000-000000000002')$q$), 'ok', 'PA-24 / 6.5: an admin resets a DIFFERENT admin''s TOTP');
SELECT throws_ok($t$SELECT pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('00000000-0000-0000-0000-4000000000d0')$q$)$t$, '22023', 'partner_totp_reset_for_partner: a different target user is required', '... never one''s own');
SELECT throws_ok($t$SELECT pg_temp.call_a2('ad', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('00000000-0000-0000-0000-1000000000a1')$q$)$t$, '42501', 'partner_totp_reset_for_partner: the target must be an operator or an admin', 'the target must be an operator or an admin (staff hold no TOTP)');
ROLLBACK TO SAVEPOINT totp_reset;
SAVEPOINT totp_reset_op;
SELECT pg_temp.bind(:'th_op');
SELECT throws_ok($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('ee320000-0000-0000-0000-000000000006')$q$)$t$, '42501', 'partner_totp_reset_for_partner: the reach rule does not cover this person',
  'PA-24: a reset by a non-admin (an operator on another operator) is refused by the reach rule');
SELECT throws_ok($t$SELECT pg_temp.call_a2('op', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('ee320000-0000-0000-0000-000000000002')$q$)$t$, '42501', 'partner_totp_reset_for_partner: the reach rule does not cover this person',
  'PA-24: ... or on an admin');
ROLLBACK TO SAVEPOINT totp_reset_op;
SAVEPOINT totp_reset_ad2;
SELECT pg_temp.bind(:'th_ad2');
SELECT is(pg_temp.call_a2('ad2', $q$SELECT o_status FROM private.partner_totp_reset_for_partner('00000000-0000-0000-0000-4000000000d0')$q$), 'ok', 'PA-24: the OTHER admin resets the first admin''s TOTP (an admin target needs a different admin)');
ROLLBACK TO SAVEPOINT totp_reset_ad2;

-- ----------------------------------------------------------------------------
-- 12. THE PURGES (9): each floor, repeated in a policy; edge_system only; a younger row is never touched
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.purge_as(p_role text, p_fn text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE ' || p_role;
  EXECUTE 'SELECT private.' || p_fn || '()::text' INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
SAVEPOINT purge_all;
-- challenges (1 h)
INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id, used_at) VALUES
  (sha256('pc-old'), 'sign_in', '00000000-0000-0000-0000-1000000000a1', now() - interval '2 hours'),
  (sha256('pc-young'), 'sign_in', '00000000-0000-0000-0000-1000000000a1', now() - interval '10 minutes');
-- sessions (30 days after expires_at or revoked_at)
SELECT pg_temp.mk_cred('pc1', '00000000-0000-0000-0000-3000000000c1') AS c_pc \gset
SELECT pg_temp.mk_session('ps-exp', '00000000-0000-0000-0000-3000000000c1', :'c_pc', 1, interval '60 days');
SELECT pg_temp.mk_session('ps-rev', '00000000-0000-0000-0000-3000000000c1', :'c_pc', 1, interval '60 days');
SELECT pg_temp.mk_session('ps-rev-young', '00000000-0000-0000-0000-3000000000c1', :'c_pc', 1, interval '60 days');
SELECT pg_temp.mk_session('ps-live', '00000000-0000-0000-0000-3000000000c1', :'c_pc');
SELECT pg_temp.seed_cols('ps-exp', $$expires_at = now() - interval '31 days'$$);
SELECT pg_temp.seed_cols('ps-rev', $$revoked_at = now() - interval '31 days', revoke_reason = 'x_old'$$);
SELECT pg_temp.seed_cols('ps-rev-young', $$revoked_at = now() - interval '10 days', revoke_reason = 'x_young'$$);
-- credentials (180 days after revoked_at)
INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, revoked_at, revoke_reason) VALUES
  ('00000000-0000-0000-0000-1000000000a1', decode(md5('pcr-old') || md5('pcr-old2'), 'hex'), decode(md5('k1') || md5('k2'), 'hex'), -7, now() - interval '181 days', 'x_old'),
  ('00000000-0000-0000-0000-1000000000a1', decode(md5('pcr-young') || md5('pcr-young2'), 'hex'), decode(md5('k3') || md5('k4'), 'hex'), -7, now() - interval '100 days', 'x_young'),
  ('00000000-0000-0000-0000-1000000000a1', decode(md5('pcr-live') || md5('pcr-live2'), 'hex'), decode(md5('k5') || md5('k6'), 'hex'), -7, NULL, NULL);
-- invites (90 days after accepted, revoked or expired) and enrolment tokens (consumed, revoked or expired)
INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, created_at, expires_at, accepted_at, accepted_by, revoked_at) VALUES
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi1@example.test', repeat('a1', 32), now() - interval '99 days', now() - interval '96 days', now() - interval '91 days', 'ee320000-0000-0000-0000-000000000011', NULL),
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi2@example.test', repeat('a2', 32), now() - interval '98 days', now() - interval '92 days', NULL, NULL, NULL),
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi3@example.test', repeat('a3', 32), now() - interval '99 days', now() - interval '93 days', NULL, NULL, now() - interval '91 days'),
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi4@example.test', repeat('a4', 32), now() - interval '20 days', now() - interval '14 days', NULL, NULL, now() - interval '10 days'),
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi5@example.test', repeat('a5', 32), now(), now() + interval '72 hours', NULL, NULL, NULL),
  ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-2000000000b1', 'pi6@example.test', repeat('a6', 32), now() - interval '20 days', now() - interval '15 days', now() - interval '10 days', 'ee320000-0000-0000-0000-000000000012', NULL);
INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at, consumed_at, revoked_at) VALUES
  ('00000000-0000-0000-0000-1000000000a1', 'recover', NULL, repeat('b1', 32), now() - interval '100 days', now() - interval '99 days', now() - interval '91 days', NULL),
  ('00000000-0000-0000-0000-1000000000a1', 'recover', NULL, repeat('b2', 32), now() - interval '100 days', now() - interval '99 days', NULL, NULL),
  ('00000000-0000-0000-0000-1000000000a1', 'recover', NULL, repeat('b3', 32), now() - interval '100 days', now() - interval '99 days', NULL, now() - interval '91 days'),
  ('00000000-0000-0000-0000-1000000000a1', 'recover', NULL, repeat('b4', 32), now() - interval '20 days', now() - interval '19 days', NULL, now() - interval '10 days'),
  ('00000000-0000-0000-0000-1000000000a1', 'recover', NULL, repeat('b5', 32), now(), now() + interval '24 hours', NULL, NULL);
-- sign-in failure counters (a day)
INSERT INTO app.partner_sign_in_failure (credential_id, window_start, failed_count, updated_at) VALUES
  ('aaaaaaaa-3200-0000-0000-000000000001', now() - interval '3 days', 2, now() - interval '2 days'),
  ('aaaaaaaa-3200-0000-0000-000000000002', now(), 1, now());

SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_challenges')::int >= 1, true, 'purge_partner_challenges (edge_system) deletes a used nonce more than an hour old');
SELECT is((SELECT array_agg(nonce_hash = sha256('pc-old') ORDER BY nonce_hash) FROM app.partner_auth_challenge WHERE nonce_hash IN (sha256('pc-old'), sha256('pc-young'))), ARRAY[false], '... and keeps the young one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_sessions')::int >= 2, true, 'purge_partner_sessions deletes sessions 30 days past expires_at and 30 days past revoked_at');
SELECT is((SELECT array_agg(token_hash ORDER BY token_hash) FROM app.partner_session WHERE token_hash IN (pg_temp.th('ps-exp'), pg_temp.th('ps-rev'), pg_temp.th('ps-rev-young'), pg_temp.th('ps-live'))),
  (SELECT array_agg(h ORDER BY h) FROM unnest(ARRAY[pg_temp.th('ps-rev-young'), pg_temp.th('ps-live')]) h), '... and keeps the one revoked 10 days ago and the live one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_credentials')::int >= 1, true, 'purge_partner_credentials deletes a credential revoked more than 180 days ago');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE credential_id IN (decode(md5('pcr-old') || md5('pcr-old2'), 'hex'), decode(md5('pcr-young') || md5('pcr-young2'), 'hex'), decode(md5('pcr-live') || md5('pcr-live2'), 'hex'))), 2,
  '... and keeps the one revoked 100 days ago and the ACTIVE one (an active credential is never purged)');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_invites')::int >= 3, true, 'purge_partner_invites deletes invites 90 days past accepted, expired and revoked');
SELECT is((SELECT array_agg(invitee_email ORDER BY invitee_email) FROM app.partner_invite WHERE invitee_email LIKE 'pi_@example.test'), ARRAY['pi4@example.test', 'pi5@example.test', 'pi6@example.test'],
  '... and keeps the one revoked 10 days ago, the PENDING one and the one accepted 10 days ago');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_enrolment_tokens')::int >= 3, true, 'purge_partner_enrolment_tokens deletes tokens 90 days past consumed, expired and revoked');
SELECT is((SELECT array_agg(token_hash ORDER BY token_hash) FROM app.partner_enrolment_token WHERE token_hash IN (repeat('b1', 32), repeat('b2', 32), repeat('b3', 32), repeat('b4', 32), repeat('b5', 32))),
  ARRAY[repeat('b4', 32), repeat('b5', 32)], '... and keeps the one revoked 10 days ago and the live one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_sign_in_failures')::int >= 1, true, 'purge_partner_sign_in_failures deletes a counter untouched for a day');
SELECT is((SELECT array_agg(credential_id::text ORDER BY credential_id::text) FROM app.partner_sign_in_failure WHERE credential_id IN ('aaaaaaaa-3200-0000-0000-000000000001', 'aaaaaaaa-3200-0000-0000-000000000002')), ARRAY['aaaaaaaa-3200-0000-0000-000000000002'], '... and keeps the current one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_challenges')::int, 0, 'a second run finds nothing more (idempotent)');
SELECT throws_ok($$SELECT pg_temp.purge_as('edge_actor', 'purge_partner_sessions')$$, '42501', NULL, 'edge_actor cannot run a partner purge');
SELECT throws_ok($$SELECT pg_temp.purge_as('edge_partner', 'purge_partner_invites')$$, '42501', NULL, 'edge_partner cannot run one either');
SELECT throws_ok($$SELECT pg_temp.purge_as('anon', 'purge_partner_credentials')$$, '42501', NULL, 'nor anon');
ROLLBACK TO SAVEPOINT purge_all;

-- ----------------------------------------------------------------------------
-- 13. PA-4c (i) and (iii): every policy 0054 adds, with every GUC the repository uses PLANTED at another person, under a PARTNER binding. The rows a statement reaches must be the
-- same planted or not (no policy reads a setting), and zero where the target is out of reach. Each statement runs in a sub-transaction that is rolled back.
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.rows_reached(p_role text, p_sql text, p_plant boolean) RETURNS integer LANGUAGE plpgsql AS $f$
DECLARE n integer := -1;
BEGIN
  BEGIN
    IF p_plant THEN
      PERFORM set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-1000000000a3', true);
      PERFORM set_config('app.delete_my_data.target_email', 'staff-y@example.test', true);
      PERFORM set_config('app.partner.authority_touch', '00000000-0000-0000-0000-1000000000a3', true);
      PERFORM set_config('app.offline_code.target_device_id', '20000000-0000-0000-0000-000000000001', true);
      PERFORM set_config('app.signin.proof_purge', 'on', true);
      PERFORM set_config('app.edge.purge_fix_coords', 'on', true);
    END IF;
    EXECUTE 'SET LOCAL ROLE ' || p_role;
    EXECUTE p_sql;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'P0001';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    NULL;
  END;
  RETURN n;
END
$f$;
-- the same statement planted and unplanted: both numbers, as "unplanted/planted"
CREATE FUNCTION pg_temp.both(p_role text, p_sql text) RETURNS text LANGUAGE sql AS $f$ SELECT pg_temp.rows_reached(p_role, p_sql, false) || '/' || pg_temp.rows_reached(p_role, p_sql, true) $f$;

SELECT pg_temp.mk_pin('00000000-0000-0000-0000-1000000000a1');
SELECT pg_temp.mk_pin('00000000-0000-0000-0000-1000000000a3');
SELECT pg_temp.mk_pin('00000000-0000-0000-0000-2000000000b1');
SELECT pg_temp.mk_pin('ee320000-0000-0000-0000-000000000005');
SELECT pg_temp.mk_totp('ee320000-0000-0000-0000-000000000005');
SELECT pg_temp.mk_tok('g1', '00000000-0000-0000-0000-1000000000a3', 'recover') AS tok_gy \gset
SELECT pg_temp.mk_tok('g2', '00000000-0000-0000-0000-1000000000a1', 'recover') AS tok_gx \gset
INSERT INTO app.partner_member (user_id, org_id, role, revoked_at) VALUES ('ee320000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000001', 'staff', now());
-- a lapsed session (31 days past expiry) to prove the purge floor is closed under a partner binding
SELECT pg_temp.mk_cred('pcg', '00000000-0000-0000-0000-3000000000c1') AS c_pcg \gset
SELECT pg_temp.mk_session('old-planted', '00000000-0000-0000-0000-3000000000c1', :'c_pcg') AS s_oldp \gset
SELECT pg_temp.seed_cols('old-planted', $$expires_at = now() - interval '31 days', created_at = now() - interval '40 days'$$);

UPDATE app.partner_invite SET attempts = 3 WHERE id = :'inv_l1';
SAVEPOINT guc_bound;
SELECT pg_temp.bind(:'th_mx');
-- private_definer: partner_member (PA-4c (i): the bound user's own row; and another person's)
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_member SET revoked_at = NULL, role = 'manager', invited_by = NULL WHERE user_id = '00000000-0000-0000-0000-2000000000b1'$$), '0/0',
  'PA-4c (i): private_definer, partner-bound as the manager, cannot SET revoked_at = NULL, role = manager, invited_by = NULL on the bound user''s own membership row (0 rows, planted or not)');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... nor revoke another person''s membership (private_definer holds no revoke policy)');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_member SET invited_by = NULL WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... nor null an inviter with the delete_my_data window planted (it is closed under a partner binding)');
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... nor delete one');
-- the toucher's member revoke: the reach rule itself, keyed on the binding
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001'$$), '1/1',
  'PA-4c (iii) control: the toucher''s revoke reaches a member the bound manager covers (staff at X), planted or not');
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... and 0 rows for staff at Y, with the GUCs planted AT staff at Y');
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-2000000000b1'$$), '0/0', 'PA-4c (iii): ... and 0 rows for the bound user''s own membership (never oneself)');
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$), '0/0', 'PA-4c (iii): ... and for an operator');
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = 'ee320000-0000-0000-0000-000000000003'$$), '1/1', 'PA-4c (iii): ... a person who works at X and Y is reachable AT X only: the policy admits the X row ...');
SELECT is(pg_temp.both('partner_session_toucher', $$UPDATE app.partner_member SET revoked_at = now() WHERE user_id = 'ee320000-0000-0000-0000-000000000003' AND org_id = '10000000-0000-0000-0000-000000000002'$$), '0/0', 'PA-4c (iii): ... and refuses the Y row');
-- the issuer's activation policies
SELECT throws_ok($$SELECT pg_temp.rows_reached('partner_session_issuer', $q$UPDATE app.partner_member SET revoked_at = NULL, role = 'manager' WHERE user_id = '00000000-0000-0000-0000-1000000000a2'$q$, true)$$, '42501', NULL,
  'PA-4c (iii): the issuer cannot reactivate a revoked membership without an accepted invite for that user, org and role (WITH CHECK refuses, GUCs planted)');
SELECT throws_ok($$SELECT pg_temp.rows_reached('partner_session_issuer', $q$INSERT INTO app.partner_member (user_id, org_id, role, invited_by) VALUES ('ee320000-0000-0000-0000-000000000012', '10000000-0000-0000-0000-000000000001', 'manager', NULL)$q$, true)$$, '42501', NULL,
  'PA-4c (iii): ... nor insert a membership without one (WITH CHECK, GUCs planted)');
SELECT is(pg_temp.both('partner_session_issuer', $$UPDATE app.partner_invite SET accepted_at = now(), accepted_by = '00000000-0000-0000-0000-1000000000a3' WHERE revoked_at IS NOT NULL$$), '0/0', 'the issuer cannot accept a REVOKED invite (the policy is the live state)');
SELECT throws_ok($$SELECT pg_temp.rows_reached('partner_session_issuer', $q$UPDATE app.partner_invite SET accepted_by = '00000000-0000-0000-0000-1000000000a3' WHERE accepted_at IS NOT NULL$q$, true)$$, '23514', NULL,
  'OR rule: the issuer cannot REWRITE who accepted an accepted invite (partner_invite_guard: an acceptance is final), planted or not');
SELECT throws_ok($$SELECT pg_temp.rows_reached('partner_session_issuer', $q$UPDATE app.partner_invite SET attempts = 0 WHERE attempts > 0$q$, true)$$, '23514', NULL, 'OR rule: ... nor reset the attempt count');
-- the pin verifier
SELECT is(pg_temp.both('partner_pin_verifier', $$UPDATE app.partner_pin SET must_change = true WHERE user_id = '00000000-0000-0000-0000-1000000000a1'$$), '1/1', 'PA-4c (iii) control: the PIN reset policy reaches staff at X for the bound manager');
SELECT is(pg_temp.both('partner_pin_verifier', $$UPDATE app.partner_pin SET must_change = true WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... and 0 rows for staff at Y with the GUCs planted at them');
SELECT is(pg_temp.both('partner_pin_verifier', $$SELECT 1 FROM app.partner_pin WHERE user_id <> '00000000-0000-0000-0000-2000000000b1' AND user_id IN ('00000000-0000-0000-0000-1000000000a3', 'ee320000-0000-0000-0000-000000000005')$$), '0/0', 'PA-4c (iii): the verifier cannot even SEE the PIN row of a person outside the reach rule');
-- credentials, invites and tokens as read by private_definer
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): private_definer, partner-bound as the manager, reads no credential of staff at Y (GUC planted at them)');
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1'$$), '2/2', 'PA-4c (iii) control: ... but reads the credentials of staff at X (the reach rule) ...');
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-2000000000b1'$$), '1/1', '... and its own');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_credential SET revoked_by = NULL WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): ... and cannot null a revoked_by with the window planted');
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_invite WHERE facility_id = 'fac_y'$$), '0/0', 'PA-4c (iii): the bound manager''s private_definer sees no invite of another facility');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_invite SET revoked_at = now(), revoked_by = '00000000-0000-0000-0000-2000000000b1' WHERE facility_id = 'fac_y'$$), '0/0', '... and revokes none');
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_invite WHERE facility_id = 'fac_x'$$)::text ~ '^[1-9][0-9]*/[1-9][0-9]*$', true, 'control: ... but sees its own facility''s');
SELECT throws_ok($$SELECT pg_temp.rows_reached('private_definer', $q$UPDATE app.partner_invite SET accepted_at = now() WHERE facility_id = 'fac_x'$q$, true)$$, '42501', NULL, 'PA-4c (iii): private_definer cannot ACCEPT an invite (no UPDATE grant on accepted_at)');
SELECT is(pg_temp.both('private_definer', $$SELECT 1 FROM app.partner_enrolment_token WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', 'PA-4c (iii): no recover token of staff at Y is visible');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_enrolment_token SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$), '0/0', '... or revocable');
SELECT is(pg_temp.both('private_definer', $$UPDATE app.partner_enrolment_token SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND purpose = 'recover'$$)::text ~ '^[1-9]/[1-9]$', true, 'control: ... but an unconsumed recover token of staff at X is');
SELECT throws_ok($$SELECT pg_temp.rows_reached('private_definer', $q$INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at) VALUES ('00000000-0000-0000-0000-1000000000a3', 'recover', '00000000-0000-0000-0000-2000000000b1', repeat('c1', 32), now(), now() + interval '24 hours')$q$, true)$$,
  '42501', NULL, 'PA-4c (iii): private_definer, partner-bound, cannot INSERT a recover token for a person outside the reach rule');
SELECT throws_ok($$SELECT pg_temp.rows_reached('private_definer', $q$INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at) VALUES ('10000000-0000-0000-0000-000000000001', 'staff', 'fac_x', '00000000-0000-0000-0000-1000000000a3', 'x@example.test', repeat('c2', 32), now() + interval '72 hours')$q$, true)$$,
  '42501', NULL, 'PA-4c (iii): ... nor an invite in somebody else''s name (invited_by is the BOUND user)');
-- the purge and last-membership policies are closed or data-derived
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_session WHERE expires_at <= now() - interval '31 days'$$), '0/0', 'PA-4c (iii): the session purge floor is CLOSED under a partner binding (a lapsed session is not deletable by it)');
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_pin WHERE user_id = '00000000-0000-0000-0000-1000000000a1'$$), '0/0', 'PA-29: the last-membership delete policy admits no PIN of a person who still has a membership');
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_pin WHERE user_id = 'ee320000-0000-0000-0000-000000000005'$$), '1/1', 'PA-29 control: ... and admits the PIN of a person with none left (the rule is in the data)');
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-4000000000d0'$$), '0/0', 'PA-29: ... never the TOTP of an admin');
SELECT is(pg_temp.both('private_definer', $$DELETE FROM app.partner_totp WHERE user_id = 'ee320000-0000-0000-0000-000000000005'$$), '1/1', 'PA-29 control: ... but that of a non-admin with no membership');
ROLLBACK TO SAVEPOINT guc_bound;

SAVEPOINT guc_unbound;
SELECT is(pg_temp.rows_reached('private_definer', $$SELECT 1 FROM app.partner_invite$$, false), 0, 'M1 holds: with NO binding, private_definer sees no invite (the accept definers are the issuer''s, not its)');
SELECT is(pg_temp.rows_reached('private_definer', $$DELETE FROM app.partner_session WHERE expires_at <= now() - interval '31 days'$$, false), 1, 'control: with NO binding the session purge floor admits the lapsed session (so the closed cell above is not vacuous)');
SELECT is(pg_temp.rows_reached('private_definer', $$SELECT 1 FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a3'$$, false), 0, 'with no binding and no window private_definer reads no credential either');
SELECT is(pg_temp.rows_reached('private_definer', $$SELECT 1 FROM app.partner_enrolment_token WHERE purpose = 'recover'$$, false), 0, '... nor a recover token (the hash-free admin tokens 0053 inserts are visible by design: the INSERT ... RETURNING policy)');
ROLLBACK TO SAVEPOINT guc_unbound;

-- ----------------------------------------------------------------------------
-- 14. THE IMMUTABILITY GUARDS (5.4 item 2, the OR rule): what no writer may change, whatever the policies admit
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('gcred1', 'ee320000-0000-0000-0000-000000000012') AS c_g1 \gset
SELECT pg_temp.mk_cred('gcred2', 'ee320000-0000-0000-0000-000000000012') AS c_g2 \gset
SELECT pg_temp.mk_inv('gi1', '10000000-0000-0000-0000-000000000001', 'staff', 'guard1@example.test') AS inv_g1 \gset
UPDATE app.partner_invite SET accepted_at = now(), accepted_by = 'ee320000-0000-0000-0000-000000000012', registered_credential_id = :'c_g1' WHERE id = :'inv_g1';
SELECT throws_ok(format($$UPDATE app.partner_invite SET accepted_by = '00000000-0000-0000-0000-1000000000a3' WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: who accepted an invite cannot be rewritten');
SELECT throws_ok(format($$UPDATE app.partner_invite SET accepted_at = now() + interval '1 second' WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: the acceptance time is final (the register challenge is bound to it)');
SELECT throws_ok(format($$UPDATE app.partner_invite SET revoked_at = now() WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: an accepted invite cannot be revoked (accepted or revoked, never both)');
SELECT throws_ok(format($$UPDATE app.partner_invite SET registered_credential_id = %L WHERE id = %L$$, :'c_g2', :'inv_g1'), '23514', NULL, 'guard: ONE registration per acceptance: the credential cannot be swapped');
SELECT throws_ok(format($$UPDATE app.partner_invite SET token_hash = repeat('d', 64) WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: the token hash never changes');
SELECT throws_ok(format($$UPDATE app.partner_invite SET expires_at = expires_at + interval '1 day' WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: an expiry is never extended');
SELECT throws_ok(format($$UPDATE app.partner_invite SET role = 'manager' WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: the role never changes');
SELECT throws_ok(format($$UPDATE app.partner_invite SET invitee_email = 'other@example.test' WHERE id = %L$$, :'inv_g1'), '23514', NULL, 'guard: the address never changes');
SELECT throws_ok(format($$UPDATE app.partner_invite SET attempts = 0 WHERE id = %L$$, :'inv_l1'), '23514', NULL, 'guard: attempts never decrease');
SELECT lives_ok(format($$UPDATE app.partner_invite SET accepted_by = NULL, registered_credential_id = NULL WHERE id = %L$$, :'inv_g1'), 'guard: the ON DELETE SET NULL actions (accepted_by, registered_credential_id) stay possible, so account deletion and the credential purge work');
SELECT throws_ok(format($$UPDATE app.partner_invite SET accepted_by = '00000000-0000-0000-0000-1000000000a3' WHERE id = %L$$, :'inv_g1'), '23514', NULL, '... but once erased the acceptor cannot be set again');
SELECT pg_temp.mk_tok('gt1', '00000000-0000-0000-0000-1000000000a1', 'recover') AS tok_g1 \gset
UPDATE app.partner_enrolment_token SET consumed_at = now() WHERE id = :'tok_g1';
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET consumed_at = NULL WHERE id = %L$$, :'tok_g1'), '23514', NULL, 'guard: a consumed token cannot be un-consumed (single use)');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET revoked_at = now() WHERE id = %L$$, :'tok_g1'), '23514', NULL, 'guard: ... nor revoked afterwards');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET user_id = '00000000-0000-0000-0000-1000000000a3' WHERE id = %L$$, :'tok_g1'), '23514', NULL, 'guard: a token never moves to another person');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET purpose = 'admin' WHERE id = %L$$, :'tok_g1'), '23514', NULL, 'guard: ... nor changes purpose');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET expires_at = expires_at + interval '1 hour' WHERE id = %L$$, :'tok_g1'), '23514', NULL, 'guard: ... nor lives longer');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET registered_credential_id = %L WHERE id = %L$$, :'c_g1', :'tok_rec'), '23514', NULL, 'guard: a registration needs a consumed token (an unconsumed one cannot be marked registered)');
SELECT lives_ok(format($$UPDATE app.partner_enrolment_token SET issued_by = NULL WHERE id = %L$$, :'tok_g1'), 'guard: the issuer may be erased (ON DELETE SET NULL)');
SELECT throws_ok(format($$UPDATE app.partner_enrolment_token SET issued_by = '00000000-0000-0000-0000-1000000000a3' WHERE id = %L$$, :'tok_g1'), '23514', NULL, '... but never set to someone else');
SELECT is((SELECT count(*)::int FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgname IN ('partner_invite_guard_trg', 'partner_enrolment_token_guard_trg') AND t.tgenabled = 'O'), 2, 'both guards are enabled');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname IN ('partner_invite_guard', 'partner_enrolment_token_guard') AND p.pronamespace = 'app'::regnamespace
           AND (has_function_privilege('edge_partner', p.oid, 'EXECUTE') OR has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE')
                OR has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE') OR has_function_privilege('service_role', p.oid, 'EXECUTE'))), 0, 'the guard functions are executable by no edge, client or service role');

-- ----------------------------------------------------------------------------
-- 15. Registries
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.partner_owner_privilege WHERE role_name = 'partner_session_issuer' AND object_name IN ('app.partner_invite', 'app.partner_enrolment_token', 'app.partner_member')), 39,
  'registry: the issuer''s 0054 column privileges on the invite, token and member tables are in private.partner_owner_privilege (checks 9 and 12 re-derive them from the catalog)');
SELECT is((SELECT array_agg(substr(object_name, 9) ORDER BY object_name) FROM private.partner_owner_privilege WHERE role_name = 'partner_session_issuer' AND object_kind = 'function' AND object_name LIKE 'private.partner_%'
             AND object_name IN ('private.partner_audit_write(text,text,text,jsonb)', 'private.partner_auth_identity(uuid,uuid)', 'private.partner_cbor_head(bytea,integer)', 'private.partner_challenge_issue_register(uuid,smallint,uuid,bigint)',
               'private.partner_challenge_verify(smallint,bigint,bytea,uuid,bytea,smallint,uuid,bigint)', 'private.partner_cose_parse(bytea)', 'private.partner_sessions_evict_oldest(uuid,integer)')),
  ARRAY['partner_audit_write(text,text,text,jsonb)', 'partner_auth_identity(uuid,uuid)', 'partner_cbor_head(bytea,integer)', 'partner_challenge_issue_register(uuid,smallint,uuid,bigint)',
        'partner_challenge_verify(smallint,bigint,bytea,uuid,bytea,smallint,uuid,bigint)', 'partner_cose_parse(bytea)', 'partner_sessions_evict_oldest(uuid,integer)'],
  'registry: the issuer''s seven new function privileges (the register verifier and issuer, the identity helper, the COSE parser and its head reader, the audit writer, the eviction) are registered');
SELECT is((SELECT count(*)::int FROM private.partner_owner_privilege WHERE role_name = 'partner_session_toucher' AND ((object_name = 'app.partner_member' AND privilege = 'UPDATE' AND column_name = 'revoked_at')
             OR (object_name = 'app.partner_credential' AND column_name = 'created_at') OR object_name IN ('private.partner_reach_covers_org(uuid,uuid,uuid)', 'private.partner_binding_user()', 'private.partner_binding_kind()'))), 5,
  'registry: the toucher''s five new privileges (UPDATE of partner_member.revoked_at ONLY, credential created_at, the reach rule and the two binding predicates its policy calls) are registered');
SELECT is((SELECT count(*)::int FROM private.partner_owner_privilege WHERE role_name = 'partner_pin_verifier' AND object_name = 'private.partner_reach_covers(uuid,uuid)'), 1, 'registry: the PIN verifier''s one new privilege (the reach rule its policies call) is registered');
SELECT tests.clear_actor();
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polrelid IN ('app.partner_member'::regclass, 'app.partner_invite'::regclass, 'app.partner_enrolment_token'::regclass, 'app.partner_credential'::regclass, 'app.partner_pin'::regclass)
             AND pol.polname ~ '^(pd|pst|psi|ppv)_' AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~* 'current_setting'
             AND pol.polname NOT IN ('pd_delete_partner_member_user_id', 'pd_delete_partner_member_user_id_r', 'pd_setnull_partner_member_invited_by', 'pd_setnull_partner_member_invited_by_r', 'pd_partner_invite_delete', 'pd_partner_invite_delete_r',
               'pd_setnull_partner_invite_accepted_by', 'pd_setnull_partner_invite_accepted_by_r', 'pd_setnull_partner_invite_revoked_by', 'pd_setnull_partner_invite_revoked_by_r', 'pd_delete_partner_enrolment_token_user_id',
               'pd_delete_partner_enrolment_token_user_id_r', 'pd_setnull_partner_enrolment_token_issued_by', 'pd_setnull_partner_enrolment_token_issued_by_r', 'pd_delete_partner_credential_user_id', 'pd_delete_partner_credential_user_id_r',
               'pd_setnull_partner_credential_revoked_by', 'pd_setnull_partner_credential_revoked_by_r', 'pd_delete_partner_pin_user_id', 'pd_delete_partner_pin_user_id_r')), 0,
  'PA-4c (iii): the ONLY policies on those five tables that read a setting are the delete_my_data window pairs that already existed; none of the 36 added by 0054 does');

SELECT * FROM finish();
ROLLBACK;
