-- 25_partner_auth_spine.sql
-- P5.1a S1.1a (0047): the DATABASE SPINE of partner authentication, from docs/security/partner-auth-design.md section 12.1 "S1.1": PA-1, PA-1b, PA-2, PA-3, PA-3b, PA-4 (the single-connection half;
-- the two-connection half is tools/db/test-partner-serialisation.sh), PA-4b, PA-4c, PA-4d, PA-5, PA-6 and PA-9c (its other half is 10_function_inventory.sql check 14 (b) and
-- 23_offline_totp_seed_record.sql).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end, so nothing it creates survives. The harness role (the migrating role: `postgres` in HARNESS_MODE=superuser,
-- `migration_owner` in `restricted`) is made a member of the roles it must act as WITH SET, for this transaction only (it holds ADMIN on every role it created, and SET on
-- private_definer since 0016). Every case that needs a clean binding runs inside a SAVEPOINT that is rolled back, because a second bind in one transaction is itself refused.
-- The partner tables are FORCE RLS with no policy for the harness role and no privilege for service_role (by design), so the fixtures are written through a temporary
-- CURRENT_USER policy (the 0016 / 0045 seeding pattern) and read back the same way.
--
-- Principals are helpers.sql's: staff_x (a1: staff at fac_x), staff_x_revoked (a2), staff_y (a3: staff at fac_y), manager_x (b1), manager_x_revoked (b2), operator_t (c1), admin (d0),
-- demo (e0), player A (0a: also a staff member of org 1, helpers.sql) and player B (0b: no membership). New principals use the prefix ee240000-.

\set QUIET 1
BEGIN;
SELECT plan(393);

-- ----------------------------------------------------------------------------
-- 0. Setup: roles, a temporary seeding policy on the new tables, fixture helpers
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_partner_minter, edge_actor, partner_session_toucher, partner_session_issuer,
      partner_pin_verifier, partner_totp_verifier, partner_reauth_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_enrolment_token, app.partner_auth_challenge, app.partner_rp_config TO CURRENT_USER;
-- the INSERT guards (S1.1a gate M2) refuse a back-dated or pre-revoked fixture: they are switched off for the SEEDING below and switched back on, with their own cells, in PA-4e
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz24_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24_tok ON app.partner_enrolment_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s24:' || p_label) || md5('s24b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid, p_revoked boolean DEFAULT false) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, revoked_at)
  VALUES (p_uid, decode(md5('c24:' || p_label) || md5('c24b:' || p_label), 'hex'), decode(md5('k24:' || p_label) || md5('k24b:' || p_label), 'hex'), -7, CASE WHEN p_revoked THEN now() END)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_idle interval DEFAULT interval '0', p_expires_in interval DEFAULT interval '8 hours',
                                   p_aal int DEFAULT 1, p_revoked boolean DEFAULT false) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, revoked_at, mint_kind, mint_nonce_hash,
                                   mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '2 days', now() - p_idle, now() + p_expires_in, CASE WHEN p_revoked THEN now() END, 'sign_in',
          decode(md5('n24:' || p_label) || md5('n24b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
-- a test-only *_for_partner definer (owned by private_definer, so it may call the authorization seam), callable by the partner lane
GRANT CREATE ON SCHEMA private TO private_definer;
SET LOCAL ROLE private_definer;
CREATE FUNCTION private.zz24_authz_for_partner(p_fac text, p_trail text, p_roles text[], p_class text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RETURN private.partner_authorize(p_fac, p_trail, p_roles::app.partner_role[], p_class);
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz24_authz_for_partner(text, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.zz24_authz_for_partner(text, text, text[], text) TO edge_partner, edge_actor;
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- principals the helpers do not have: a sponsor-only member and a second facility org for the invariants
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email) VALUES
  ('ee240000-0000-0000-0000-0000000000a1', 'sponsor24@example.test'),
  ('ee240000-0000-0000-0000-0000000000a2', 'newmember24@example.test');
INSERT INTO app.partner_org (id, kind, name) VALUES
  ('ee240000-0000-0000-0000-00000000f001', 'sponsor', 'Sponsor 24'),
  ('ee240000-0000-0000-0000-00000000f002', 'facility', 'Facility 24 (no scope yet)'),
  ('ee240000-0000-0000-0000-00000000f003', 'operator', 'Operator 24');
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a1', 'ee240000-0000-0000-0000-00000000f001', 'sponsor');
RESET ROLE;

-- ============================================================================
-- PA-1: structure. FORCE RLS; no privilege for anyone on the new tables; the lane holds nothing
-- ============================================================================
SELECT is((SELECT count(*)::int FROM pg_class c WHERE c.oid IN ('app.partner_credential'::regclass, 'app.partner_auth_challenge'::regclass, 'app.partner_session'::regclass,
                                                                 'app.partner_enrolment_token'::regclass, 'app.partner_rp_config'::regclass)
           AND c.relrowsecurity AND c.relforcerowsecurity), 5, 'PA-1: all five new tables have ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
           CROSS JOIN (VALUES ('app.partner_credential'), ('app.partner_auth_challenge'), ('app.partner_session'), ('app.partner_enrolment_token'), ('app.partner_rp_config')) t(rel)
           WHERE has_any_column_privilege(r.n, t.rel::regclass, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, t.rel::regclass, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'PA-1: NO privilege for anon, authenticated, service_role, edge_gateway or any edge role (the minters included) on any of the five new tables');
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
             AND (has_any_column_privilege(r.n, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, c.oid, 'DELETE,TRUNCATE,TRIGGER'))), 0,
  'PA-1: edge_partner and edge_partner_minter hold NO privilege on ANY relation in ANY schema (the lane acts only through definers; the PUBLIC views of the postgis / pgtap extensions are not ours)');
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname IN ('app', 'private', 'auth', 'api', 'storage', 'vault')
             AND (has_any_column_privilege(r.n, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, c.oid, 'DELETE,TRUNCATE,TRIGGER'))), 0,
  'PA-1: in particular none in app, private, auth, api, storage or vault (an unqualified sweep, extension exemption OFF)');
SELECT is((SELECT count(*)::int FROM pg_namespace n CROSS JOIN (VALUES ('edge_partner'), ('edge_partner_minter')) r(n)
           WHERE (n.nspname NOT LIKE 'pg\_temp%' AND has_schema_privilege(r.n, n.oid, 'CREATE')) OR (n.nspname <> 'private' AND n.nspname NOT IN ('public', 'tests', 'information_schema') AND n.nspname NOT LIKE 'pg\_%' AND has_schema_privilege(r.n, n.oid, 'USAGE'))), 0,
  'PA-1: and no CREATE anywhere (the always-open TEMP schema aside), and USAGE on no schema but private (plus the PUBLIC-open public, tests, pg_catalog and information_schema): in particular NONE on app');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname IN ('app', 'api', 'private') AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')),
          ARRAY['bind_partner_session', 'partner_binding', 'partner_binding_kind', 'zz24_authz_for_partner'],
  'PA-1: edge_partner can EXECUTE exactly the binder, the two read-only binding helpers (4.3) and this file''s own planted definer, and no other function (it has no bind_actor and no actor_uid)');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname::text) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('app', 'api', 'private') AND has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE')),
          ARRAY['partner_challenge_issue_sign_in', 'partner_session_mint'],
  'PA-1: edge_partner_minter can EXECUTE exactly the two mint functions of 0048 (S1.1b) and no other function (26_partner_signin_mint.sql PA-8 proves them one by one)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure,
             'private.partner_session_guard()'::regprocedure, 'private.partner_member_role_invariant()'::regprocedure, 'private.partner_scope_invariant()'::regprocedure)
           AND (SELECT count(*) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'),
                                            ('partner_session_toucher'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_reauth_verifier')) r(n)
                WHERE has_function_privilege(r.n, p.oid, 'EXECUTE')) = 0), 4,
  'PA-1: partner_authorize and the three guard / invariant trigger functions are executable by NO role at all but their owner');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter'),
                                            ('partner_session_toucher'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_reauth_verifier')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_session_policy(uuid)'::regprocedure, 'EXECUTE')), ARRAY['partner_session_issuer'],
  'PA-1: the policy helper is executable by its owner and, since 0048, by partner_session_issuer alone (the mint reads the absolute session ceiling from it)');
SELECT is((SELECT p.provolatile::text FROM pg_proc p WHERE p.oid = 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure), 'v',
  'PA-1: partner_authorize is VOLATILE (it writes last_seen_at and consumes a PIN grant; a STABLE function could not, and its reads must see a concurrent revoke)');
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole FROM pg_proc p WHERE p.oid = 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure), true,
  'PA-1: partner_authorize is SECURITY DEFINER, owned by private_definer, search_path = ''''');
-- the guard is SECURITY DEFINER with an empty search_path, owned by a role that owns no table and so cannot disable it (R5-N1)
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] FROM pg_proc p WHERE p.oid = 'private.partner_session_guard()'::regprocedure), true, 'R5-N1: partner_session_guard is SECURITY DEFINER with search_path = ''''');
SELECT is((SELECT count(*)::int FROM pg_class c WHERE c.relnamespace IN ('app'::regnamespace, 'private'::regnamespace) AND c.relkind = 'r'
           AND c.relowner IN ('private_definer'::regrole, 'partner_session_toucher'::regrole, 'partner_session_issuer'::regrole,
                              'partner_pin_verifier'::regrole, 'partner_totp_verifier'::regrole, 'partner_reauth_verifier'::regrole)), 0,
  'R5-N1: private_definer and the six owner roles own NO table in app or private, so none of them can ALTER TABLE ... DISABLE TRIGGER');
SELECT throws_ok($$SET LOCAL ROLE private_definer; ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg$$, '42501', NULL, 'R5-N1: private_definer (the guard''s owner) cannot disable the guard');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE partner_session_toucher; ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg$$, '42501', NULL, 'R5-N1: nor can the toucher');
RESET ROLE;
-- the table shapes and checks
SELECT throws_ok($$INSERT INTO app.partner_session (token_hash, user_id, credential_id, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  SELECT 'not-hex', '00000000-0000-0000-0000-1000000000a1', gen_random_uuid(), now() + interval '1 hour', 'sign_in', decode(repeat('01', 32), 'hex'), decode(repeat('04', 40), 'hex'), '{}'::bytea, decode(repeat('05', 70), 'hex')$$,
  '23514', NULL, 'L4: partner_session.token_hash must be 64 lowercase hex characters (a plaintext-looking value is a CHECK violation)');
SELECT throws_ok($$SET LOCAL ROLE service_role; INSERT INTO app.partner_invite (org_id, role, invited_by, invitee_email, token_hash, expires_at)
  VALUES ('10000000-0000-0000-0000-000000000001', 'staff', '00000000-0000-0000-0000-2000000000b1', 'x@example.test', 'th-not-hex', now() + interval '3 days')$$,
  '23514', NULL, 'L4: partner_invite.token_hash is CHECKed to 64 hex characters too (the helpers.sql fixtures moved to sha256 digests)');
SELECT is((SELECT count(*)::int FROM pg_indexes WHERE schemaname = 'app' AND tablename = 'partner_session' AND indexdef LIKE 'CREATE UNIQUE INDEX%(otp_proof_gotrue_session_id)%'), 1,
  'R5-L1: the UNIQUE index on otp_proof_gotrue_session_id exists (one GoTrue session proves at most one OTP proof, as in 0041)');
SELECT is((SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'partner_invite'
           AND column_name IN ('accepted_by', 'registered_credential_id', 'revoked_at', 'revoked_by', 'attempts')), 5, '5.2: the partner_invite additions exist');
SELECT is((SELECT count(*)::int FROM app.partner_rp_config), 0, 'the relying-party configuration is EMPTY until ops writes it (the mint refuses while it is absent, S1.1b)');
SELECT throws_ok($$INSERT INTO app.partner_rp_config (singleton, rp_id, origin) VALUES (true, 'partners.example.test', 'http://partners.example.test')$$, '23514', NULL, 'partner_rp_config: the origin must be https');
SELECT lives_ok($$INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test')$$, 'partner_rp_config: a well-formed row is accepted ...');
SELECT throws_ok($$INSERT INTO app.partner_rp_config (singleton, rp_id, origin) VALUES (false, 'other.example.test', 'https://other.example.test')$$, '23514', NULL, '... and there can be only ONE row (singleton CHECK)');
SELECT throws_ok($$INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('second.example.test', 'https://second.example.test')$$, '23505', NULL, '... a second row is a duplicate of the singleton key');

-- the credential: label derived by the database; identity immutable; revocation final; sign count never down
SELECT pg_temp.mk_cred('label', '00000000-0000-0000-0000-1000000000a1') AS c_label \gset
SELECT is((SELECT label FROM app.partner_credential WHERE id = :'c_label'), to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD') || ' / unknown', 'the credential label is DERIVED by the database (date / aaguid or unknown)');
SELECT throws_ok(format($$UPDATE app.partner_credential SET label = 'chosen by the client' WHERE id = %L$$, :'c_label'), '23514', NULL, 'the label cannot be changed afterwards either');
SELECT throws_ok(format($$UPDATE app.partner_credential SET public_key = decode(repeat('09', 40), 'hex') WHERE id = %L$$, :'c_label'), '23514', NULL, 'a credential''s public key never changes');
SELECT throws_ok(format($$UPDATE app.partner_credential SET user_id = '00000000-0000-0000-0000-1000000000a3' WHERE id = %L$$, :'c_label'), '23514', NULL, 'nor its owner');
SELECT lives_ok(format($$UPDATE app.partner_credential SET sign_count = 5, last_used_at = now() WHERE id = %L$$, :'c_label'), 'the sign count may rise');
SELECT throws_ok(format($$UPDATE app.partner_credential SET sign_count = 4 WHERE id = %L$$, :'c_label'), '23514', NULL, 'and never falls (PA-9 is the mint''s compare-and-set; this is the table''s own floor)');
SELECT lives_ok(format($$UPDATE app.partner_credential SET revoked_at = now(), revoke_reason = 'test' WHERE id = %L$$, :'c_label'), 'a credential can be revoked ...');
SELECT throws_ok(format($$UPDATE app.partner_credential SET revoked_at = NULL WHERE id = %L$$, :'c_label'), '23514', NULL, '... and the revocation is final');

-- ============================================================================
-- PA-5: the invariants. One facility org = exactly one facility scope; a role must match the org's kind
-- ============================================================================
SET LOCAL ROLE service_role;
SELECT lives_ok($$INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('ee240000-0000-0000-0000-00000000f002', 'fac_y')$$, 'PA-5: a facility org may hold ONE facility scope');
SELECT throws_ok($$INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('ee240000-0000-0000-0000-00000000f002', 'fac_x')$$, '23514', NULL, 'PA-5: a SECOND scope row in a facility org is refused');
SELECT throws_ok($$INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('ee240000-0000-0000-0000-00000000f002', 'fac_y')$$, '23514', NULL, 'PA-5: ... the same facility twice is refused (by the trigger first; UNIQUE (org_id, facility_id) is the table-level floor)');
SELECT throws_ok($$INSERT INTO app.partner_scope (org_id, trail_id) VALUES ('10000000-0000-0000-0000-000000000001', 'trl_t')$$, '23514', NULL, 'PA-5: a facility org cannot hold a TRAIL scope');
SELECT throws_ok($$UPDATE app.partner_scope SET facility_id = NULL, trail_id = 'trl_t' WHERE org_id = '10000000-0000-0000-0000-000000000001'$$, '23514', NULL, 'PA-5: and an existing facility scope cannot be rewritten into a trail scope');
SELECT lives_ok($$INSERT INTO app.partner_scope (org_id, trail_id) VALUES ('ee240000-0000-0000-0000-00000000f003', 'trl_t'), ('ee240000-0000-0000-0000-00000000f003', 'trl_u')$$, 'PA-5: an OPERATOR org may hold several trail scopes (only a facility org is limited)');
SELECT throws_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f001', 'staff')$$, '23514', NULL, 'PA-5: a STAFF role in a SPONSOR org is refused');
SELECT throws_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f002', 'sponsor')$$, '23514', NULL, 'PA-5: a SPONSOR role in a FACILITY org is refused');
SELECT throws_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f002', 'operator')$$, '23514', NULL, 'PA-5: an OPERATOR in a facility org is refused');
SELECT throws_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f003', 'manager')$$, '23514', NULL, 'PA-5: a MANAGER in an operator org is refused');
SELECT throws_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f003', 'staff')$$, '23514', NULL, 'PA-5: a STAFF role in an operator org is refused');
SELECT lives_ok($$INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('ee240000-0000-0000-0000-0000000000a2', 'ee240000-0000-0000-0000-00000000f002', 'manager')$$, 'PA-5: control: a manager in a facility org is accepted');
SELECT throws_ok($$UPDATE app.partner_member SET role = 'operator' WHERE user_id = 'ee240000-0000-0000-0000-0000000000a2' AND org_id = 'ee240000-0000-0000-0000-00000000f002'$$, '23514', NULL, 'PA-5: a role UPDATE to one the org kind forbids is refused');
SELECT throws_ok($$UPDATE app.partner_member SET org_id = 'ee240000-0000-0000-0000-00000000f003' WHERE user_id = 'ee240000-0000-0000-0000-0000000000a2'$$, '23514', NULL, 'PA-5: moving a member to an org of another kind is refused');
SELECT throws_ok($$UPDATE app.partner_org SET kind = 'operator' WHERE id = 'ee240000-0000-0000-0000-00000000f002'$$, '23514', NULL, 'PA-5: an org''s kind is immutable (both invariants are about the kind)');
RESET ROLE;

-- ============================================================================
-- PA-6: the PostgREST partner read surface is DENIED to every actor (D12 / 5.5); live offers stay for players, masked
-- ============================================================================
-- one draft offer at fac_x (written as service_role, the way every offer is)
SET LOCAL ROLE service_role;
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, budget_used, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-0000000000d1', 'trl_t', 'fac_x', '{"op":"always"}'::jsonb, 'operator', 777, 5, current_date, current_date + 30, 'draft');
RESET ROLE;
CREATE FUNCTION pg_temp.denied_count(p_actor uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_rel text;
  v_n int := 0;
BEGIN
  FOREACH v_rel IN ARRAY ARRAY[
    'api.staff_shift_log', 'api.staff_activity', 'api.special_marker_stock', 'api.special_marker_stock_movement', 'api.facility_programme', 'api.marker_code_batch', 'api.facility_qr',
    'api.sponsorship', 'api.operator_rollup', 'api.sponsor_rollup', 'api.my_partner_org', 'api.my_partner_member', 'api.my_partner_scope', 'api.my_partner_invite',
    'app.partner_org', 'app.partner_member', 'app.partner_scope', 'app.partner_invite', 'app.facility_programme', 'app.attestation_shift_log', 'app.staff_activity', 'app.special_marker_stock',
    'app.special_marker_stock_movement', 'app.sponsorship', 'app.operator_rollup', 'app.sponsor_rollup', 'app.marker_code_batch', 'app.facility_qr'] LOOP
    BEGIN
      EXECUTE format('SELECT count(*) FROM %s', v_rel);
    EXCEPTION WHEN insufficient_privilege THEN
      v_n := v_n + 1;
    END;
  END LOOP;
  RETURN v_n;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.denied_count(uuid) TO PUBLIC;
SELECT is((SELECT array_agg(r ORDER BY r) FROM unnest(ARRAY[
    'api.staff_shift_log', 'api.staff_activity', 'api.special_marker_stock', 'api.special_marker_stock_movement', 'api.facility_programme', 'api.marker_code_batch', 'api.facility_qr',
    'api.sponsorship', 'api.operator_rollup', 'api.sponsor_rollup', 'api.my_partner_org', 'api.my_partner_member', 'api.my_partner_scope', 'api.my_partner_invite',
    'app.partner_org', 'app.partner_member', 'app.partner_scope', 'app.partner_invite', 'app.facility_programme', 'app.attestation_shift_log', 'app.staff_activity', 'app.special_marker_stock',
    'app.special_marker_stock_movement', 'app.sponsorship', 'app.operator_rollup', 'app.sponsor_rollup', 'app.marker_code_batch', 'app.facility_qr']) r
  WHERE has_table_privilege('authenticated', r, 'SELECT') OR has_table_privilege('anon', r, 'SELECT')), NULL::text[],
  'PA-6: none of the 28 relations holds SELECT for authenticated or anon at the PRIVILEGE level either (the views are security_invoker, so the base-table revoke would deny them anyway: the view-level revoke is the defence in depth a future non-invoker view would otherwise lose)');
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a1'::uuid));
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-1000000000a1'), 28, 'PA-6: staff@X (valid JWT, IN scope) is DENIED on all 14 api views and all 14 base tables');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-2000000000b1'::uuid));
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-2000000000b1'), 28, 'PA-6: manager@X is denied on all 28');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-3000000000c1'::uuid));
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-3000000000c1'), 28, 'PA-6: operator@T is denied on all 28');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-4000000000d0'::uuid));
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-4000000000d0'), 28, 'PA-6: the ADMIN is denied on all 28 (admin reaches the partner plane only through the Edge)');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000b'::uuid));
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-00000000000b'), 28, 'PA-6: a plain player (B) is denied on all 28');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT is(pg_temp.denied_count('00000000-0000-0000-0000-00000000000b'), 28, 'PA-6: anon is denied on all 28');
SELECT tests.clear_actor();
-- offers: live only, no budget or eligibility, to EVERY reader; the draft is invisible through every PostgREST path
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a1'::uuid));
SELECT is((SELECT count(*)::int FROM api.offer WHERE id = '60000000-0000-0000-0000-0000000000d1'), 0, 'PA-6: a DRAFT offer is invisible to a scoped staff member through api.offer (offer_read is live-only now)');
SELECT is((SELECT count(*)::int FROM api.my_offers() WHERE id = '60000000-0000-0000-0000-0000000000d1'), 0, 'PA-6: ... through api.my_offers()');
SELECT is((SELECT count(*)::int FROM app.offer WHERE id = '60000000-0000-0000-0000-0000000000d1'), 0, 'PA-6: ... and through the base table itself (the offer_read policy no longer has a scope leg)');
SELECT is((SELECT count(*)::int FROM api.offer WHERE status <> 'live'), 0, 'PA-6: api.offer returns live offers ONLY, to a scoped member');
SELECT is((SELECT count(*)::int FROM api.offer WHERE id = '60000000-0000-0000-0000-000000000001'), 1, 'PA-6: control: a LIVE offer is still readable (players browse offers)');
SELECT is((SELECT count(*)::int FROM api.offer WHERE eligibility IS NOT NULL OR budget_cap IS NOT NULL OR budget_used IS NOT NULL OR budget_reserved IS NOT NULL OR max_redemptions IS NOT NULL), 0, 'PA-6: no live offer shows eligibility or budget to a SCOPED member (M1)');
SELECT is((SELECT count(*)::int FROM api.my_offers() WHERE eligibility IS NOT NULL OR budget_cap IS NOT NULL OR budget_used IS NOT NULL OR budget_reserved IS NOT NULL OR max_redemptions IS NOT NULL), 0, 'PA-6: nor through api.my_offers() (M1)');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-3000000000c1'::uuid));
SELECT is((SELECT count(*)::int FROM api.offer WHERE id = '60000000-0000-0000-0000-0000000000d1'), 0, 'PA-6: the operator of the trail does not see the draft either');
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000b'::uuid));
SELECT is((SELECT count(*)::int FROM api.my_profile), 1, 'PA-6: control: the player-own views still answer (api.my_profile: player B''s own row)');
SELECT is((SELECT count(*)::int FROM api.catalog_trail), 3, 'PA-6: control: catalog views still answer');
SELECT tests.clear_actor();

-- ============================================================================
-- Fixtures for the binder, the seam and the guard: credentials and sessions for the principals
-- ============================================================================
-- demo (e0) gets a staff membership here (rolled back) so the DEMO refusal is isolated from the "no membership" refusal
SET LOCAL ROLE service_role;
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('00000000-0000-0000-0000-5000000000e0', '10000000-0000-0000-0000-000000000001', 'staff');
RESET ROLE;
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sx_rev', '00000000-0000-0000-0000-1000000000a1', true) AS c_sx_rev \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('mxr', '00000000-0000-0000-0000-2000000000b2') AS c_mxr \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_cred('demo', '00000000-0000-0000-0000-5000000000e0') AS c_demo \gset
SELECT pg_temp.mk_cred('sp', 'ee240000-0000-0000-0000-0000000000a1') AS c_sp \gset
SELECT pg_temp.mk_cred('pb', '00000000-0000-0000-0000-00000000000b') AS c_pb \gset
SELECT pg_temp.mk_cred('pa', '00000000-0000-0000-0000-00000000000a') AS c_pa \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('sx2', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx2 \gset
SELECT pg_temp.mk_session('sx_idle', '00000000-0000-0000-0000-1000000000a1', :'c_sx', interval '31 minutes') AS s_sx_idle \gset
SELECT pg_temp.mk_session('sx_idle_ok', '00000000-0000-0000-0000-1000000000a1', :'c_sx', interval '29 minutes') AS s_sx_idle_ok \gset
SELECT pg_temp.mk_session('sx_abs', '00000000-0000-0000-0000-1000000000a1', :'c_sx', interval '0', interval '-1 minute') AS s_sx_abs \gset
SELECT pg_temp.mk_session('sx_rev', '00000000-0000-0000-0000-1000000000a1', :'c_sx', interval '0', interval '8 hours', 1, true) AS s_sx_rev \gset
SELECT pg_temp.mk_session('sx_credrev', '00000000-0000-0000-0000-1000000000a1', :'c_sx_rev') AS s_sx_credrev \gset
SELECT pg_temp.mk_session('sy', '00000000-0000-0000-0000-1000000000a3', :'c_sy') AS s_sy \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('mxr', '00000000-0000-0000-0000-2000000000b2', :'c_mxr') AS s_mxr \gset
SELECT pg_temp.mk_session('op1', '00000000-0000-0000-0000-3000000000c1', :'c_op') AS s_op1 \gset
SELECT pg_temp.mk_session('op2', '00000000-0000-0000-0000-3000000000c1', :'c_op', interval '0', interval '4 hours', 2) AS s_op2 \gset
SELECT pg_temp.mk_session('op_idle', '00000000-0000-0000-0000-3000000000c1', :'c_op', interval '16 minutes', interval '4 hours', 2) AS s_op_idle \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', interval '0', interval '1 hour', 2) AS s_ad \gset
SELECT pg_temp.mk_session('ad_idle', '00000000-0000-0000-0000-4000000000d0', :'c_ad', interval '11 minutes', interval '1 hour', 2) AS s_ad_idle \gset
SELECT pg_temp.mk_session('demo', '00000000-0000-0000-0000-5000000000e0', :'c_demo') AS s_demo \gset
SELECT pg_temp.mk_session('sp', 'ee240000-0000-0000-0000-0000000000a1', :'c_sp') AS s_sp \gset
SELECT pg_temp.mk_session('pb', '00000000-0000-0000-0000-00000000000b', :'c_pb') AS s_pb \gset
SELECT pg_temp.mk_session('pa', '00000000-0000-0000-0000-00000000000a', :'c_pa') AS s_pa \gset
SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('sx_idle') AS th_sx_idle, pg_temp.th('sx_idle_ok') AS th_sx_idle_ok, pg_temp.th('sx_abs') AS th_sx_abs, pg_temp.th('sx_rev') AS th_sx_rev,
       pg_temp.th('sx_credrev') AS th_sx_credrev, pg_temp.th('sy') AS th_sy, pg_temp.th('mx') AS th_mx, pg_temp.th('mxr') AS th_mxr, pg_temp.th('op1') AS th_op1, pg_temp.th('op2') AS th_op2,
       pg_temp.th('op_idle') AS th_op_idle, pg_temp.th('ad') AS th_ad, pg_temp.th('ad_idle') AS th_ad_idle, pg_temp.th('demo') AS th_demo, pg_temp.th('sp') AS th_sp, pg_temp.th('pb') AS th_pb,
       pg_temp.th('pa') AS th_pa, pg_temp.th('sx2') AS th_sx2 \gset

-- ============================================================================
-- PA-2: bind_partner_session accepts a live session and refuses everything else with ONE SQLSTATE and ONE message
-- ============================================================================
SAVEPOINT pa2_ok;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), 'PA-2: a live session of an active staff member binds');
SELECT is(private.partner_binding_kind(), 'partner', 'PA-2: the binding reads back as kind partner (the Edge''s post-bind assertion)');
SELECT is((SELECT session_id FROM private.partner_binding()), :'s_sx'::uuid, 'PA-2: partner_binding() names the bound session');
SELECT is(current_user::text, 'edge_partner', 'PA-2: the transaction runs as edge_partner');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa2_ok;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, md5('nope') || md5('nope2')), '28000', 'partner_session_refused', 'PA-2: an UNKNOWN hash is refused');
SELECT throws_ok($$SELECT private.bind_partner_session('abc')$$, '28000', 'partner_session_refused', 'PA-2: a malformed hash is refused with the SAME message');
SELECT throws_ok($$SELECT private.bind_partner_session(NULL)$$, '28000', 'partner_session_refused', 'PA-2: NULL is refused with the SAME message');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx_idle'), '28000', 'partner_session_refused', 'PA-2: an IDLE-expired staff session (31 minutes) is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx_abs'), '28000', 'partner_session_refused', 'PA-2: an ABSOLUTE-expired session is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx_rev'), '28000', 'partner_session_refused', 'PA-2: a REVOKED session is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx_credrev'), '28000', 'partner_session_refused', 'PA-2: a session of a REVOKED credential is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_demo'), '28000', 'partner_session_refused', 'PA-2: the app-review DEMO account is refused (it holds a membership here, so this is the demo check itself)');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sp'), '28000', 'partner_session_refused', 'PA-2: a SPONSOR-ONLY member is refused (sponsors have no partner session before P6)');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_pb'), '28000', 'partner_session_refused', 'PA-2: a person with NO membership is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_mxr'), '28000', 'partner_session_refused', 'PA-2: a member whose ONLY membership is revoked is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_op_idle'), '28000', 'partner_session_refused', 'PA-2: an idle OPERATOR (16 minutes, limit 15) is refused');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_ad_idle'), '28000', 'partner_session_refused', 'PA-2: an idle ADMIN (11 minutes, limit 10) is refused');
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx_idle_ok'), 'PA-2: control: 29 idle minutes is still inside the staff limit (30)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa2_ok;
-- a second bind in one transaction, and a bind after a user binding, are refused with the same message (R2-N2)
SAVEPOINT pa2_two;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), 'PA-2: first bind');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx2'), '28000', 'partner_session_refused', 'PA-2 / PA-27: a SECOND bind in one transaction is refused (a transaction cannot be re-bound), even for the same member');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '28000', 'partner_session_refused', 'PA-2: ... even for the SAME session');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa2_two;
SAVEPOINT pa2_user;
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'PA-2: a USER binding is made first (as the owner: the harness holds SET on private_definer)');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '28000', 'partner_session_refused', 'PA-2: a partner bind when ANY binding (here a user one) exists in the transaction is refused, with the same message');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa2_user;
-- the binding row's own shape (CHECK actor_binding_session_id_check), written as the only role with a policy on the table
SELECT throws_ok($$SET LOCAL ROLE private_definer; INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, session_id) VALUES (pg_backend_pid(), pg_current_xact_id(), '00000000-0000-0000-0000-1000000000a1', 'partner', NULL)$$, '23514', NULL,
  'a partner binding must name its session (CHECK actor_binding_session_id_check)');
RESET ROLE;
SELECT throws_ok($$SET LOCAL ROLE private_definer; INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, session_id) VALUES (pg_backend_pid(), pg_current_xact_id(), '00000000-0000-0000-0000-1000000000a1', 'user', gen_random_uuid())$$, '23514', NULL,
  'and no other kind may carry a session id');
RESET ROLE;

-- ============================================================================
-- PA-3: LANE SEPARATION. (i) a partner binding is invisible to the user lane; (ii) a user binding is refused by the partner seam; (iii) the lane holds nothing
-- ============================================================================
SAVEPOINT pa3_i;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_pa'), 'PA-3 (i): bind PLAYER A''s partner session (A is a staff member of org 1 in helpers.sql, so A owns rows in many user-lane tables)');
RESET ROLE;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'PA-3 (i): under a planted partner binding private.actor_uid() is NULL for edge_actor (the defence in depth: every edge policy keys on it)');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('pa3', interval '1 minute', 5)$$, '42501', 'hit_actor_rate_limit: no actor is bound in this transaction', 'PA-3 (i): hit_actor_rate_limit (checks ONLY actor_uid(), E3) refuses');
SELECT throws_ok($$SELECT * FROM private.device_link_signals_for_actor('20000000-0000-0000-0000-000000000001')$$, '42501', 'device_link_signals_for_actor: no actor is bound in this transaction', 'PA-3 (i): device_link_signals_for_actor refuses');
SELECT throws_ok($$SELECT private.hold_play_rewards_for_actor('40000000-0000-0000-0000-000000000001')$$, '42501', 'hold_play_rewards_for_actor: no actor is bound in this transaction', 'PA-3 (i): hold_play_rewards_for_actor refuses');
SELECT throws_ok($$SELECT private.lock_own_reward_for_actor('50000000-0000-0000-0000-000000000001')$$, '42501', 'lock_own_reward_for_actor: no actor is bound in this transaction', 'PA-3 (i): lock_own_reward_for_actor refuses');
SELECT throws_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'PA-3 (i): a partner-bound transaction cannot be re-bound as a USER (the same player, here)');
SELECT is((SELECT count(*)::int FROM app.device), 0, 'PA-3 (i): edge_actor reads ZERO rows of app.device under the partner binding of the very account that owns one (every edge policy is keyed on actor_uid())');
SELECT is((SELECT count(*)::int FROM app.play), 0, 'PA-3 (i): zero rows of app.play');
SELECT is((SELECT count(*)::int FROM app.evidence), 0, 'PA-3 (i): zero rows of app.evidence');
SELECT throws_ok($$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, local_date, status, catalog_version) VALUES ('00000000-0000-0000-0000-00000000000a', 'foreground_checkin', 'pa3', 'h', current_date, 'accepted', 1)$$, '42501', NULL, 'PA-3 (i): and an INSERT for that very account fails its WITH CHECK');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3_i;
-- control: the same reads under a USER binding of the same player see rows (so the zero rows above are the binding kind, not an empty table)
SAVEPOINT pa3_ctl;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$, 'PA-3 control: bind player A as a USER');
SELECT is(private.actor_uid(), '00000000-0000-0000-0000-00000000000a'::uuid, 'PA-3 control: actor_uid() is A');
SELECT is((SELECT count(*)::int FROM app.device), 1, 'PA-3 control: edge_actor reads A''s device under a USER binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3_ctl;
-- (ii) a user binding is refused by every partner-seam caller
SAVEPOINT pa3_ii;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'PA-3 (ii): bind staff-x as a USER');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: no partner session is bound in this transaction', 'PA-3 (ii): a *_for_partner definer (here a planted one) refuses a USER binding');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '42501', NULL, 'PA-3 (ii): edge_actor cannot even EXECUTE the partner binder');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3_ii;
-- (iii) as edge_partner every table denies and the user lane is not executable
SAVEPOINT pa3_iii;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), 'PA-3 (iii): bind');
SELECT throws_ok($$SELECT count(*) FROM app.partner_session$$, '42501', NULL, 'PA-3 (iii): edge_partner cannot read app.partner_session');
SELECT throws_ok($$SELECT count(*) FROM app.partner_credential$$, '42501', NULL, 'PA-3 (iii): ... app.partner_credential');
SELECT throws_ok($$SELECT count(*) FROM app.partner_member$$, '42501', NULL, 'PA-3 (iii): ... app.partner_member');
SELECT throws_ok($$SELECT count(*) FROM app.device$$, '42501', NULL, 'PA-3 (iii): ... app.device (any user-lane table)');
SELECT throws_ok($$SELECT count(*) FROM private.actor_binding$$, '42501', NULL, 'PA-3 (iii): ... private.actor_binding');
SELECT throws_ok($$SELECT count(*) FROM private.rate_limit_bucket$$, '42501', NULL, 'PA-3 (iii): ... private.rate_limit_bucket');
SELECT throws_ok($$SELECT count(*) FROM auth.users$$, '42501', NULL, 'PA-3 (iii): ... auth.users');
SELECT throws_ok($$SELECT count(*) FROM auth.sessions$$, '42501', NULL, 'PA-3 (iii): ... auth.sessions');
SELECT throws_ok($$SELECT count(*) FROM vault.decrypted_secrets$$, '42501', NULL, 'PA-3 (iii): ... the Vault');
SELECT throws_ok($$INSERT INTO app.partner_session (token_hash) VALUES ('x')$$, '42501', NULL, 'PA-3 (iii): and cannot write a session either');
SELECT throws_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, '42501', NULL, 'PA-3 (iii): bind_actor is NOT executable by edge_partner');
SELECT throws_ok($$SELECT private.actor_uid()$$, '42501', NULL, 'PA-3 (iii): nor is actor_uid() (4.2: the post-bind assertion does not call it)');
SELECT throws_ok($$SELECT private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0')$$, '42501', NULL, 'PA-3 (iii): nor is partner_authorize (executable by nobody: only a *_for_partner definer reaches it)');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('x', interval '1 minute', 5)$$, '42501', NULL, 'PA-3 (iii): nor any user-lane definer');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3_iii;
SAVEPOINT pa3_minter;
SET LOCAL ROLE edge_partner_minter;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '42501', NULL, 'PA-8 (so far): the minter role cannot bind either (it holds no EXECUTE yet)');
SELECT throws_ok($$SELECT count(*) FROM app.partner_credential$$, '42501', NULL, 'PA-8 (so far): and reads no table');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3_minter;

-- ============================================================================
-- PA-3b: CATALOG-DRIVEN. Every function EXECUTE-able by edge_actor, and every table edge_actor can read, delete from or update, is run under a planted PARTNER binding
-- (player A's, who owns rows in most user-lane tables), so a user-lane object added later is covered with no hand list.
-- ============================================================================
-- what is allowed to answer under a partner binding: functions whose answer does not depend on the actor at all (a function of its arguments or of a Vault key)
CREATE TEMP TABLE zz24_allowed_fn (fn text PRIMARY KEY);
INSERT INTO zz24_allowed_fn VALUES
  ('private.account_pseudonyms'),               -- a pure function of the uid ARGUMENT and the Vault keys (the pseudonym-keyed install-link tombstone, 0027)
  ('private.actor_uid'),                        -- answers NULL under a partner binding: that is the point
  ('private.get_signin_token_kek'),             -- returns the sign-in KEK by id; not actor-dependent (the Edge unwraps with it); R6 territory, unchanged
  ('private.record_consumed_nonce'),            -- appends a nonce tombstone; not actor-dependent
  ('private.validate_and_register_pseudonym_hmac_id'); -- a validator of its ARGUMENT against Vault
GRANT SELECT ON zz24_allowed_fn TO PUBLIC;
-- the SELECT-open tables (scope open_read in private.edge_policy_allowlist): public catalog data every actor may read, so a row count there proves nothing about a binding
SET LOCAL ROLE service_role;
CREATE TEMP TABLE zz24_open_read AS SELECT schema_name || '.' || table_name AS rel FROM private.edge_policy_allowlist WHERE scope = 'open_read' AND command = 'SELECT';
GRANT SELECT ON zz24_open_read TO PUBLIC;
RESET ROLE;
CREATE FUNCTION pg_temp.sweep_functions(p_uid uuid) RETURNS text[] LANGUAGE plpgsql AS $f$
DECLARE
  f record;
  v_args text;
  v_sql text;
  v_out text;
  v_ok text[] := '{}';
  a regtype;
BEGIN
  FOR f IN SELECT p.oid, n.nspname, p.proname, p.proargtypes FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND has_function_privilege('edge_actor', p.oid, 'EXECUTE')
             AND NOT (n.nspname = 'private' AND p.proname IN ('bind_actor', 'zz24_authz_for_partner')) ORDER BY 2, 3 LOOP
    v_args := '';
    FOREACH a IN ARRAY f.proargtypes::oid[]::regtype[] LOOP
      v_args := v_args || CASE WHEN v_args = '' THEN '' ELSE ', ' END ||
        CASE a::text WHEN 'uuid' THEN quote_literal(p_uid::text) || '::uuid' WHEN 'text' THEN '''x''::text' WHEN 'integer' THEN '1' WHEN 'bigint' THEN '1::bigint' WHEN 'boolean' THEN 'false'
          WHEN 'interval' THEN '''1 minute''::interval' WHEN 'timestamp with time zone' THEN 'now()' WHEN 'bytea' THEN '''\x00''::bytea' WHEN 'jsonb' THEN '''{}''::jsonb'
          ELSE 'NULL::' || a::text END;
    END LOOP;
    v_sql := format('SELECT coalesce(string_agg(x::text, '',''), '''') FROM (SELECT %I.%I(%s) AS x) s', f.nspname, f.proname, v_args);
    BEGIN
      EXECUTE v_sql INTO v_out;
      v_ok := v_ok || (f.nspname || '.' || f.proname);
    EXCEPTION WHEN OTHERS THEN
      NULL; -- refused: the expected answer
    END;
  END LOOP;
  RETURN v_ok;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.sweep_functions(uuid) TO PUBLIC;
CREATE FUNCTION pg_temp.sweep_tables(p_cmd text) RETURNS TABLE (rel text, n int) LANGUAGE plpgsql AS $f$
DECLARE
  t record;
  v_n int;
  v_col text;
BEGIN
  FOR t IN SELECT n.nspname, c.relname, c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
             AND CASE p_cmd WHEN 'SELECT' THEN has_table_privilege('edge_actor', c.oid, 'SELECT')
                            WHEN 'DELETE' THEN has_table_privilege('edge_actor', c.oid, 'DELETE')
                            WHEN 'INSERT' THEN has_any_column_privilege('edge_actor', c.oid, 'INSERT')
                            ELSE has_any_column_privilege('edge_actor', c.oid, 'UPDATE') END
           ORDER BY 2 LOOP
    BEGIN
      IF p_cmd = 'SELECT' THEN
        EXECUTE format('SELECT count(*)::int FROM %I.%I', t.nspname, t.relname) INTO v_n;
      ELSIF p_cmd = 'DELETE' THEN
        EXECUTE format('WITH d AS (DELETE FROM %I.%I RETURNING 1) SELECT count(*)::int FROM d', t.nspname, t.relname) INTO v_n;
      ELSIF p_cmd = 'INSERT' THEN
        -- RLS WITH CHECK is evaluated BEFORE the table's constraints, but AFTER its BEFORE ROW triggers (which pg_temp.disable_insert_triggers() has switched off for the sweep, inside the
        -- savepoint), so SQLSTATE 42501 (a policy refusal or no privilege) means REFUSED; success OR any other error (a NOT NULL violation, say) means the policy let the row through.
        -- n = 1 when it got through, 0 when refused.
        BEGIN
          EXECUTE format('INSERT INTO %I.%I DEFAULT VALUES', t.nspname, t.relname);
          v_n := 1;
        EXCEPTION WHEN insufficient_privilege THEN
          v_n := 0;
        WHEN OTHERS THEN
          v_n := 1;
        END;
      ELSE
        SELECT a.attname INTO v_col FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('edge_actor', t.oid, a.attnum, 'UPDATE') ORDER BY a.attnum LIMIT 1;
        EXECUTE format('WITH u AS (UPDATE %I.%I SET %I = %I RETURNING 1) SELECT count(*)::int FROM u', t.nspname, t.relname, v_col, v_col) INTO v_n;
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_n := -1;
    END;
    rel := t.nspname || '.' || t.relname;
    n := v_n;
    RETURN NEXT;
  END LOOP;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.sweep_tables(text) TO PUBLIC;
CREATE FUNCTION pg_temp.disable_insert_triggers() RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  t record;
  n int := 0;
BEGIN
  FOR t IN SELECT ns.nspname, c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
           WHERE c.relkind = 'r' AND ns.nspname NOT IN ('pg_catalog', 'information_schema') AND ns.nspname !~ '^pg_' AND has_any_column_privilege('edge_actor', c.oid, 'INSERT')
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') LOOP
    EXECUTE format('ALTER TABLE %I.%I DISABLE TRIGGER USER', t.nspname, t.relname);
    n := n + 1;
  END LOOP;
  RETURN n;
END
$f$;
-- under a PARTNER binding of player A
SAVEPOINT pa3b_p;
SELECT pg_temp.disable_insert_triggers() AS _n \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_pa');
RESET ROLE;
SET LOCAL ROLE edge_actor;
SELECT is((SELECT array_agg(fn ORDER BY fn) FROM unnest(pg_temp.sweep_functions('00000000-0000-0000-0000-00000000000a')) fn WHERE fn NOT IN (SELECT a.fn FROM zz24_allowed_fn a)), NULL::text[],
  'PA-3b: every function EXECUTE-able by edge_actor (generated from the catalog, called with the owner''s own uid) REFUSES under a planted partner binding, apart from the five whose answer does not depend on the actor');
SELECT is((SELECT array_agg(s.rel || '=' || s.n ORDER BY s.rel) FROM pg_temp.sweep_tables('SELECT') s WHERE s.n > 0 AND s.rel NOT IN (SELECT o.rel FROM zz24_open_read o)), NULL::text[],
  'PA-3b: every app table edge_actor can SELECT answers ZERO rows under the partner binding (the open-read catalog tables aside)');
SELECT is((SELECT array_agg(s.rel || '=' || s.n ORDER BY s.rel) FROM pg_temp.sweep_tables('DELETE') s WHERE s.n > 0), NULL::text[], 'PA-3b: a DELETE on every table edge_actor can delete from affects ZERO rows under the partner binding');
SELECT is((SELECT array_agg(s.rel || '=' || s.n ORDER BY s.rel) FROM pg_temp.sweep_tables('UPDATE') s WHERE s.n > 0), NULL::text[], 'PA-3b: an UPDATE on every table edge_actor can update affects ZERO rows under the partner binding');
SELECT is((SELECT array_agg(s.rel || '=' || s.n ORDER BY s.rel) FROM pg_temp.sweep_tables('INSERT') s WHERE s.n > 0), NULL::text[], 'PA-3b (S1.1a gate L3): an INSERT into every table edge_actor holds any INSERT privilege on is REFUSED by RLS under the partner binding (every schema, not only app)');
SELECT cmp_ok((SELECT count(*)::int FROM pg_temp.sweep_tables('SELECT')), '>', 10, 'PA-3b: the sweep is not vacuous: it covers more than 10 tables (generated from the catalog)');
SELECT cmp_ok((SELECT count(*)::int FROM pg_temp.sweep_tables('INSERT')), '>', 0, 'PA-3b: ... and the INSERT sweep is not vacuous either (edge_actor holds INSERT on at least one table)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3b_p;
-- the SAME sweeps under a USER binding of the same player: they find rows, so the zeros above are the binding kind and not empty tables
SAVEPOINT pa3b_u;
SELECT pg_temp.disable_insert_triggers() AS _n \gset
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a');
SELECT cmp_ok((SELECT count(*)::int FROM pg_temp.sweep_tables('SELECT') s WHERE s.n > 0 AND s.rel NOT IN (SELECT o.rel FROM zz24_open_read o)), '>=', 8, 'PA-3b control: under a USER binding the same SELECT sweep finds rows in at least 8 non-open tables');
-- (edge_actor holds no DELETE on any app table today, so the DELETE sweep above is empty: it is there so a table granted DELETE later is covered without a hand list)
SELECT cmp_ok((SELECT count(*)::int FROM pg_temp.sweep_tables('UPDATE') s WHERE s.n > 0), '>=', 1, 'PA-3b control: ... and the UPDATE sweep updates rows in at least 1');
-- the INSERT sweep's detector, proved on a planted table whose policy lets a row through (edge_actor INSERT, WITH CHECK (true)): it must answer 1 for it
RESET ROLE;
CREATE TABLE app.zz24_ins (a int);
GRANT INSERT ON app.zz24_ins TO edge_actor;
ALTER TABLE app.zz24_ins ENABLE ROW LEVEL SECURITY;
CREATE POLICY zz24_ins_p ON app.zz24_ins FOR INSERT TO edge_actor WITH CHECK (true);
SET LOCAL ROLE edge_actor;
SELECT is((SELECT s.n FROM pg_temp.sweep_tables('INSERT') s WHERE s.rel = 'app.zz24_ins'), 1, 'PA-3b control: the INSERT sweep reports a planted table whose policy lets a row through (the detector is not blind)');
RESET ROLE;
SET LOCAL ROLE edge_actor;
SELECT cmp_ok(cardinality(pg_temp.sweep_functions('00000000-0000-0000-0000-00000000000a')), '>', 5, 'PA-3b control: ... and more functions answer than the five binding-independent ones');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa3b_u;

-- ============================================================================
-- partner_authorize, single connection: scope, classes, aal, idle, the PIN grant
-- ============================================================================
SAVEPOINT az1;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is(private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff', 'manager'], 'A0'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'authorize: staff@X at fac_x with a staff / manager role list: returns the member''s uid');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_y', NULL, ARRAY['staff', 'manager'], 'A0')$$, '42501', 'partner_authorize: no scope', 'PA-4: staff@X acting at facility Y is refused (403)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: an EXPLICIT role list is honoured: staff@X is not a manager at fac_x');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['operator'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: ... nor an operator');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', 'trl_t', ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: a facility AND a trail must BOTH be in scope (staff@X holds no trail scope)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: a trail scope the member does not hold');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, ARRAY['staff'], 'A0'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'authorize: with no facility and no trail, an active membership with a listed role is enough');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, NULL, ARRAY['manager', 'operator'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: ... and not otherwise');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff', 'sponsor'], 'A0')$$, '22023', NULL, 'authorize: a role list naming SPONSOR is refused outright (sponsor ties operator in partner_role_rank; only explicit lists, and no sponsor, before P6)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY[]::text[], 'A0')$$, '22023', NULL, 'authorize: an empty role list is refused');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, NULL, 'A0')$$, '22023', NULL, 'authorize: a NULL role list is refused');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A9')$$, '22023', NULL, 'authorize: an unknown class is refused');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], NULL)$$, '22023', NULL, 'authorize: a NULL class is refused');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, NULL, 'SESSION'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'authorize: the SESSION class (sign-out, lock, GET session) needs a live session and nothing else');
RESET ROLE;
ROLLBACK TO SAVEPOINT az1;

-- PA-4b: A2 and A3 FAIL CLOSED, for every actor, admin included, until S1.3 / S1.4 (no interim relaxation)
SAVEPOINT az4b;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A2')$$, '42501', 'partner_authorize: class A2 is not enabled (fails closed until its prerequisite exists)', 'PA-4b: the ADMIN (aal 2) is refused class A2');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A3')$$, '42501', 'partner_authorize: class A3 is not enabled (fails closed until its prerequisite exists)', 'PA-4b: ... and class A3');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, ARRAY['operator'], 'A0'), '00000000-0000-0000-0000-4000000000d0'::uuid, 'PA-4b control: the same admin session passes class A0 (so the A2 / A3 refusals are the class, not the session)');
RESET ROLE;
ROLLBACK TO SAVEPOINT az4b;
SAVEPOINT az4b2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A2')$$, '42501', NULL, 'PA-4b: the MANAGER at the facility is refused class A2 as well');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['manager'], 'A3')$$, '42501', NULL, 'PA-4b: ... and A3');
RESET ROLE;
ROLLBACK TO SAVEPOINT az4b2;
SAVEPOINT az4b3;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A2')$$, '42501', NULL, 'PA-4b: staff is refused A2');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_y', NULL, ARRAY['staff'], 'A3')$$, '42501', NULL, 'PA-4b: ... and A3 (the refusal comes BEFORE the scope check: the same answer in or out of scope)');
RESET ROLE;
ROLLBACK TO SAVEPOINT az4b3;

-- the aal gate (M2): an aal 1 session of an operator or admin is refused EVERY class except SESSION
SAVEPOINT az_aal;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0')$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'M2: an OPERATOR session at aal 1 is refused even class A0');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0_KEEPALIVE')$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'M2: ... and the keep-alive A0');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, NULL, 'SESSION'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'M2: ... except the SESSION class (sign-out, lock, GET session, step-up are how an aal 1 session becomes aal 2)');
RESET ROLE;
ROLLBACK TO SAVEPOINT az_aal;
SAVEPOINT az_aal2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op2');
SELECT is(private.zz24_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'M2: control: the operator''s aal 2 session passes A0 at its trail');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, 'trl_u', ARRAY['manager'], 'A0')$$, '42501', 'partner_authorize: no scope', 'authorize: ... and an operator at a trail with a role list that is not its own is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT az_aal2;
-- a person promoted to operator keeps an aal 1 session, usable for nothing but SESSION: staff_x joins an operator org mid-session ... (the membership trigger kills sessions; with it disabled the aal gate is the second line)
SAVEPOINT az_promote;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_member DISABLE TRIGGER partner_member_authority_ins_trg;
SET LOCAL ROLE service_role;
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('00000000-0000-0000-0000-1000000000a1', 'ee240000-0000-0000-0000-00000000f003', 'operator');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'PA-20 (seam): a person PROMOTED to operator mid-session is at once refused every class at aal 1 (the required aal is recomputed on every call)');
RESET ROLE;
ROLLBACK TO SAVEPOINT az_promote;

-- idle: last_seen_at advances at most once a minute and never on the keep-alive class
SAVEPOINT az_idle;
UPDATE app.partner_session SET last_seen_at = now() - interval '5 minutes' WHERE id = :'s_sx_idle_ok'::uuid;
SELECT last_seen_at AS ls0 FROM app.partner_session WHERE id = :'s_sx_idle_ok' \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_idle_ok');
SELECT is(private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0_KEEPALIVE'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'idle: the keep-alive class passes ...');
RESET ROLE;
SELECT is((SELECT last_seen_at = :'ls0'::timestamptz FROM app.partner_session WHERE id = :'s_sx_idle_ok'), true, 'idle: ... and did NOT advance last_seen_at (a 30 s token refresh must not defeat the idle timeout, L12)');
SET LOCAL ROLE edge_partner;
SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0') AS _x \gset
RESET ROLE;
SELECT is((SELECT last_seen_at > :'ls0'::timestamptz AND last_seen_at <= clock_timestamp() FROM app.partner_session WHERE id = :'s_sx_idle_ok'), true, 'idle: an ordinary call advances last_seen_at (a 5-minute-old value moved to now)');
SELECT last_seen_at AS ls1 FROM app.partner_session WHERE id = :'s_sx_idle_ok' \gset
SET LOCAL ROLE edge_partner;
SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0') AS _x \gset
RESET ROLE;
SELECT is((SELECT last_seen_at = :'ls1'::timestamptz FROM app.partner_session WHERE id = :'s_sx_idle_ok'), true, 'idle: a second call within the minute does not write the row again');
ROLLBACK TO SAVEPOINT az_idle;

-- ============================================================================
-- PA-4 (single connection): authority is re-read per call, and a change of authority kills or touches sessions in the SAME transaction
-- ============================================================================
-- (1) the seam is the SECOND line: with the revoking trigger disabled, a revoked member's session is still live, and every call is refused
SAVEPOINT pa4_a;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_member DISABLE TRIGGER partner_member_authority_upd_trg;
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4 (trigger disabled): the member is revoked but the SESSION row is still live (the setup of the next cell)');
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the member holds no active partner role', 'PA-4: a REVOKED member''s next call is 403 on a still-LIVE session (authority is re-read per call, not cached in the session)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, NULL, NULL, 'SESSION')$$, '42501', 'partner_authorize: the member holds no active partner role', 'PA-4: ... even the SESSION class (a person with no active role has no session)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_a;
-- (2) deleting the scope row refuses the next call (AT 1, authentication half), with the touch trigger disabled so only the re-read can be responsible
SAVEPOINT pa4_b;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT is(private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'PA-4: control: in scope before the scope row is deleted');
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_scope DISABLE TRIGGER partner_scope_authority_del_trg;
SET LOCAL ROLE service_role;
DELETE FROM app.partner_scope WHERE org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: no scope', 'PA-4: deleting the scope row refuses the very next call');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_b;
-- (3) the credential revoked mid-session
SAVEPOINT pa4_c;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
UPDATE app.partner_credential SET revoked_at = now(), revoke_reason = 'stolen' WHERE id = :'c_sx'::uuid;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the session is not live', 'PA-4: revoking the CREDENTIAL kills its sessions on the next call (the session row itself is untouched)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_c;
-- (4) the triggers: a member revoke, a reactivation, a DELETE then re-INSERT, an org-delete cascade and an admin delete then insert do NOT revive old sessions
SAVEPOINT pa4_d;
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL AND revoke_reason = 'authority_changed' FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4: a member REVOKE revokes the member''s live sessions in the same transaction (reason authority_changed)');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL), 0, 'PA-4: ... every live session of that member (the other principals'' sessions are untouched, below)');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id <> '00000000-0000-0000-0000-1000000000a1' AND revoked_at IS NULL AND id IN (:'s_sy'::uuid, :'s_mx'::uuid, :'s_op2'::uuid, :'s_ad'::uuid)), 4, 'PA-4: ... and no OTHER member''s session is touched');
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '28000', 'partner_session_refused', 'PA-4: the revoked member''s session no longer binds');
RESET ROLE;
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET revoked_at = NULL WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx'), '28000', 'partner_session_refused', 'PA-4: REACTIVATING the member does not revive the old session (a revoked session stays revoked)');
RESET ROLE;
SET LOCAL ROLE service_role;
DELETE FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001', 'staff');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_sx2'), '28000', 'partner_session_refused', 'PA-4: a membership DELETE then re-INSERT does not revive (the second session of the member died with the delete)');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_d;
SAVEPOINT pa4_e;
-- an org-delete cascade: the members' sessions are revoked by the cascaded DELETE triggers
SELECT pg_temp.mk_cred('cascade', 'ee240000-0000-0000-0000-0000000000a2') AS c_cas \gset
SELECT pg_temp.mk_session('cascade', 'ee240000-0000-0000-0000-0000000000a2', :'c_cas') AS s_cas \gset
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'s_cas'::uuid), true, 'PA-4 (cascade): the org''s member (a manager since PA-5) has a live session (setup)');
SET LOCAL ROLE service_role;
DELETE FROM app.partner_org WHERE id = 'ee240000-0000-0000-0000-00000000f002';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'s_cas'::uuid), true, 'PA-4: an ORG DELETE (the cascade deletes its members) revokes their sessions');
ROLLBACK TO SAVEPOINT pa4_e;
SAVEPOINT pa4_f;
SET LOCAL ROLE service_role;
DELETE FROM app.admin_user WHERE user_id = '00000000-0000-0000-0000-4000000000d0';
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-4000000000d0' AND revoked_at IS NULL), 0, 'PA-4: removing a person from admin_user revokes their sessions');
SET LOCAL ROLE service_role;
INSERT INTO app.admin_user (user_id) VALUES ('00000000-0000-0000-0000-4000000000d0');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'th_ad'), '28000', 'partner_session_refused', 'PA-4: an admin_user DELETE then INSERT does not revive the old admin session');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_f;
SAVEPOINT pa4_g;
SELECT pg_temp.mk_session('newadmin', '00000000-0000-0000-0000-5000000000e0', :'c_demo') AS s_x \gset
SET LOCAL ROLE service_role;
INSERT INTO app.admin_user (user_id) VALUES ('00000000-0000-0000-0000-5000000000e0');
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'s_x'::uuid), true, 'PA-4: INSERTing an admin_user row revokes the person''s existing sessions (a session minted as a non-admin must not silently become an admin session)');
ROLLBACK TO SAVEPOINT pa4_g;
-- the accepting session is exempt on an INSERT / reactivation, never on a revoke
SAVEPOINT pa4_h;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
-- staff_x (bound as sx) joins a second org (the branch-E accept): the ACCEPTING session survives, every OTHER session of the member dies
SET LOCAL ROLE service_role;
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('00000000-0000-0000-0000-1000000000a1', 'ee240000-0000-0000-0000-00000000f002', 'manager');
RESET ROLE;
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4 (R2): an INSERT of a membership leaves the ACCEPTING (bound) session alive ...');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'s_sx2'::uuid), true, 'PA-4 (R2): ... and revokes every other session of that member');
-- a self-revoke is NOT exempt
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = 'ee240000-0000-0000-0000-00000000f002';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4: a REVOKE of the member''s own membership kills the bound session too (the exemption is for an INSERT / reactivation only)');
ROLLBACK TO SAVEPOINT pa4_h;
-- scope UPDATE and DELETE TOUCH the org members' sessions (authority_touched_at) and revoke nothing
SAVEPOINT pa4_i;
SET LOCAL ROLE service_role;
UPDATE app.partner_scope SET facility_id = 'fac_y' WHERE org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT authority_touched_at IS NOT NULL AND revoked_at IS NULL FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4: a scope UPDATE TOUCHES the org members'' sessions (authority_touched_at) and revokes none');
SELECT is((SELECT authority_touched_at IS NULL FROM app.partner_session WHERE id = :'s_sy'::uuid), true, 'PA-4: ... another org''s sessions are untouched');
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: no scope', 'PA-4: ... and the next call re-reads: the old facility is out of scope');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4_i;
SAVEPOINT pa4_j;
SET LOCAL ROLE service_role;
DELETE FROM app.partner_scope WHERE org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT authority_touched_at IS NOT NULL AND revoked_at IS NULL FROM app.partner_session WHERE id = :'s_sx'::uuid), true, 'PA-4: a scope DELETE touches (and revokes nothing)');
ROLLBACK TO SAVEPOINT pa4_j;

-- ============================================================================
-- PA-4c: THE OR RULE AND THE PLANTED GUC. Permissive policies are OR-ed; a GUC persists into a later definer call (R3-M1, R4-M1)
-- ============================================================================
CREATE FUNCTION pg_temp.upd_rows(p_sql text) RETURNS int LANGUAGE plpgsql AS $f$ DECLARE n int; BEGIN EXECUTE p_sql; GET DIAGNOSTICS n = ROW_COUNT; RETURN n; END $f$;
GRANT EXECUTE ON FUNCTION pg_temp.upd_rows(text) TO PUBLIC;
CREATE FUNCTION pg_temp.consume() RETURNS boolean LANGUAGE sql AS $f$ SELECT private.partner_pin_grant_consume() $f$;
GRANT EXECUTE ON FUNCTION pg_temp.consume() TO PUBLIC;
-- (i) THE WINDOWS (S1.1a gate H1). Every GUC-keyed private_definer policy in the schema is a window; inside a PARTNER-bound transaction none may be open. The first version of this cell never
-- planted a GUC, so it proved nothing about the 0016 windows (the gate un-revoked and promoted a member, deleted a membership and an admin_user row through them). It now plants EVERY
-- setting the repository has ever keyed a policy on, runs the three gate probes with a no-binding control, and then does the same over the CATALOG: for every (table, command) a window
-- policy covers, the rows reached with the settings planted must equal the rows reached with them unset, under a partner binding.
-- THE SETTINGS, in one place: every setting a GUC-keyed private_definer policy has ever read, and the value that makes a row keyed on it visible (the settings are PLANTED at one player, A)
CREATE FUNCTION pg_temp.plant_settings() RETURNS text[] LANGUAGE sql IMMUTABLE AS $f$
  SELECT ARRAY['app.delete_my_data.target_user_id', 'app.delete_my_data.target_email', 'app.delete_my_data.target_handle', 'app.delete_my_data.target_pseudonym',
               'app.edge.link_attest_key', 'app.edge.link_device_id', 'app.edge.link_hash', 'app.edge.purge_fix_coords', 'app.guard.entitlement_id', 'app.guard.offer_code_id',
               'app.guard.play_id', 'app.offline_code.target_device_id', 'app.signin.proof_id', 'app.signin.proof_purge', 'app.signin.target_user_id']
$f$;
CREATE FUNCTION pg_temp.plant_value(p_setting text, p_user uuid) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT CASE p_setting WHEN 'app.delete_my_data.target_email' THEN 'player-a@example.test'
                        WHEN 'app.delete_my_data.target_handle' THEN 'x' WHEN 'app.delete_my_data.target_pseudonym' THEN 'x'
                        WHEN 'app.edge.link_attest_key' THEN 'x' WHEN 'app.edge.link_hash' THEN 'x'
                        WHEN 'app.edge.purge_fix_coords' THEN 'on' WHEN 'app.signin.proof_purge' THEN 'on'
                        ELSE p_user::text END
$f$;
CREATE FUNCTION pg_temp.plant_all(p_user uuid) RETURNS void LANGUAGE plpgsql AS $f$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY pg_temp.plant_settings() LOOP
    PERFORM set_config(g, pg_temp.plant_value(g, p_user), true);
  END LOOP;
END
$f$;
CREATE FUNCTION pg_temp.unplant_all() RETURNS void LANGUAGE plpgsql AS $f$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY pg_temp.plant_settings() LOOP
    PERFORM set_config(g, '', true);
  END LOOP;
END
$f$;
-- Is this policy GUC-keyed? Its own text reads a setting, OR it calls a function (pg_depend, one level deep: the HIGH-1 wrapper rule) whose body does (the S1.1b gate's L-2: `USING (user_id::text = private.zz_guc())`)
CREATE FUNCTION pg_temp.policy_is_window(p_pol oid) RETURNS boolean LANGUAGE sql STABLE AS $f$
  SELECT EXISTS (SELECT 1 FROM pg_policy pol WHERE pol.oid = p_pol AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') LIKE '%current_setting(%' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%current_setting(%'))
      OR EXISTS (SELECT 1 FROM pg_depend d JOIN pg_proc fp ON fp.oid = d.refobjid WHERE d.classid = 'pg_policy'::regclass AND d.objid = p_pol AND d.refclassid = 'pg_proc'::regclass AND fp.prosrc ILIKE '%current_setting(%')
$f$;
-- a setting a window policy reads that plant_all does not know: the cell below would silently test nothing for it, so it FAILS (a later slice that adds a window must add its setting here)
CREATE FUNCTION pg_temp.unplanted_settings() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(DISTINCT x.m[1] ORDER BY x.m[1])
  FROM pg_policy pol
  CROSS JOIN LATERAL (
    SELECT regexp_matches(coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || ' ' || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), ''), 'current_setting\(''([^'']+)''', 'g') AS m
    UNION ALL
    SELECT regexp_matches(fp.prosrc, 'current_setting\s*\(\s*''([^'']+)''', 'gi')
    FROM pg_depend d JOIN pg_proc fp ON fp.oid = d.refobjid WHERE d.classid = 'pg_policy'::regclass AND d.objid = pol.oid AND d.refclassid = 'pg_proc'::regclass
  ) x(m)
  WHERE pol.polroles = ARRAY['private_definer'::regrole::oid]
    AND x.m[1] <> ALL (pg_temp.plant_settings())
$f$;
-- measure one statement in a sub-transaction that is always rolled back: the number of rows it reached (-1 if it raised), with the settings planted or unset
CREATE FUNCTION pg_temp.measure(p_sql text, p_planted boolean, p_user uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_n int;
  v_msg text;
BEGIN
  IF p_planted THEN PERFORM pg_temp.plant_all(p_user); ELSE PERFORM pg_temp.unplant_all(); END IF;
  IF p_sql LIKE 'INSERT%' THEN EXECUTE p_sql; v_n := 1; ELSE EXECUTE p_sql INTO v_n; END IF;
  RAISE EXCEPTION 'measured:%', v_n USING ERRCODE = 'P0001';
EXCEPTION WHEN SQLSTATE 'P0001' THEN
  GET STACKED DIAGNOSTICS v_msg = MESSAGE_TEXT;
  IF v_msg LIKE 'measured:%' THEN RETURN substr(v_msg, 10)::int; END IF;
  RETURN -1;
WHEN OTHERS THEN
  RETURN -1;
END
$f$;
-- every (relation, command) a GUC-keyed private_definer policy covers, as one statement each
CREATE FUNCTION pg_temp.window_statements(p_user uuid DEFAULT '00000000-0000-0000-0000-00000000000a') RETURNS TABLE (rel text, cmd text, stmt text) LANGUAGE plpgsql AS $f$
DECLARE
  w record;
  v_col text;
BEGIN
  FOR w IN SELECT DISTINCT n.nspname || '.' || c.relname AS rel, c.oid AS relid, x.cmd
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           CROSS JOIN LATERAL unnest(CASE pol.polcmd WHEN '*' THEN ARRAY['r', 'w', 'd'] ELSE ARRAY[pol.polcmd::text] END) AS x(cmd)
           WHERE pol.polroles = ARRAY['private_definer'::regrole::oid]
             AND pg_temp.policy_is_window(pol.oid)
           ORDER BY 1, 3 LOOP
    rel := w.rel;
    cmd := w.cmd;
    IF w.cmd = 'r' THEN
      stmt := format('SELECT count(*)::int FROM %s', w.rel);
    ELSIF w.cmd = 'd' THEN
      stmt := format('WITH d AS (DELETE FROM %s RETURNING 1) SELECT count(*)::int FROM d', w.rel);
    ELSIF w.cmd = 'a' THEN
      stmt := pg_temp.sweep_insert_stmt(w.relid, w.rel, p_user) || ' ON CONFLICT DO NOTHING';
    ELSE
      SELECT a.attname INTO v_col FROM pg_attribute a WHERE a.attrelid = w.relid AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', w.relid, a.attnum, 'UPDATE') ORDER BY a.attnum LIMIT 1;
      IF v_col IS NULL THEN CONTINUE; END IF;
      stmt := format('WITH u AS (UPDATE %s SET %I = %I RETURNING 1) SELECT count(*)::int FROM u', w.rel, v_col, v_col);
    END IF;
    RETURN NEXT;
  END LOOP;
END
$f$;
-- the pairs whose reach CHANGES when the settings are planted
CREATE FUNCTION pg_temp.window_diffs(p_user uuid) RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(s.rel || ':' || s.cmd || '=' || pg_temp.measure(s.stmt, false, p_user) || '->' || pg_temp.measure(s.stmt, true, p_user) ORDER BY s.rel, s.cmd)
  FROM pg_temp.window_statements(p_user) s
  WHERE pg_temp.measure(s.stmt, false, p_user) IS DISTINCT FROM pg_temp.measure(s.stmt, true, p_user)
$f$;
-- the INSERT statement of one swept table: the columns a window policy compares with a setting get the planted value, a primary-key column nothing keys and nothing defaults gets a fresh one
CREATE FUNCTION pg_temp.sweep_insert_stmt(p_relid oid, p_rel text, p_user uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record;
  k record;
  v_cols text[];
  v_vals text[];
BEGIN
  v_cols := ARRAY[]::text[];
  v_vals := ARRAY[]::text[];
  FOR k IN SELECT DISTINCT ON (m[1]) m[1] AS col, m[2] AS setting, a.atttypid, a.atttypmod
           FROM pg_policy pol
           CROSS JOIN LATERAL regexp_matches(coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || ' ' || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), ''),
                                             '\(*(\w+)\)*(?:::text)? = \(*NULLIF\(current_setting\(''([^'']+)''', 'g') AS m
           JOIN pg_attribute a ON a.attrelid = pol.polrelid AND a.attname = m[1] AND a.attnum > 0 AND NOT a.attisdropped
           WHERE pol.polrelid = p_relid AND pol.polroles = ARRAY['private_definer'::regrole::oid]
           ORDER BY m[1] LOOP
    v_cols := v_cols || quote_ident(k.col);
    v_vals := v_vals || format('%L::%s', pg_temp.plant_value(k.setting, p_user), format_type(k.atttypid, k.atttypmod));
  END LOOP;
  -- a policy that compares a column with a WRAPPER's result (`col::text = private.fn()`, the function body reading the setting) is keyed on that column too
  FOR k IN SELECT DISTINCT ON (m[1]) m[1] AS col, (regexp_match(fp.prosrc, 'current_setting\s*\(\s*''([^'']+)''', 'i'))[1] AS setting, a.atttypid, a.atttypmod
           FROM pg_policy pol
           CROSS JOIN LATERAL regexp_matches(coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || ' ' || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), ''), '\(*(\w+)\)*(?:::text)? = \(*(?:\w+\.)?(\w+)\(\)', 'g') AS m
           JOIN pg_proc fp ON fp.proname = m[2] AND fp.prosrc ILIKE '%current_setting(%'
           JOIN pg_attribute a ON a.attrelid = pol.polrelid AND a.attname = m[1] AND a.attnum > 0 AND NOT a.attisdropped
           WHERE pol.polrelid = p_relid AND pol.polroles = ARRAY['private_definer'::regrole::oid] AND quote_ident(m[1]) <> ALL (v_cols)
           ORDER BY m[1] LOOP
    v_cols := v_cols || quote_ident(k.col);
    v_vals := v_vals || format('%L::%s', pg_temp.plant_value(k.setting, p_user), format_type(k.atttypid, k.atttypmod));
  END LOOP;
  IF p_rel = 'storage.objects' THEN
    v_cols := v_cols || 'bucket_id'::text;
    v_vals := v_vals || $$'receipts'$$::text;
  END IF;
  -- a primary-key column nothing keys and nothing defaults gets a fresh value (the planted ones may collide with an existing row, which is the ON CONFLICT above)
  FOR c IN SELECT a.attname, a.atttypid FROM pg_attribute a JOIN pg_index i ON i.indrelid = a.attrelid AND i.indisprimary AND a.attnum = ANY (i.indkey)
           WHERE a.attrelid = p_relid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = '' AND a.attidentity = ''
             AND NOT EXISTS (SELECT 1 FROM pg_attrdef d WHERE d.adrelid = a.attrelid AND d.adnum = a.attnum)
             AND quote_ident(a.attname) <> ALL (v_cols) LOOP
    v_cols := v_cols || quote_ident(c.attname);
    v_vals := v_vals || CASE c.atttypid WHEN 'uuid'::regtype THEN 'gen_random_uuid()' WHEN 'text'::regtype THEN 'md5(random()::text)'
                                        WHEN 'date'::regtype THEN 'current_date' WHEN 'timestamptz'::regtype THEN 'now()' WHEN 'timestamp'::regtype THEN 'now()::timestamp' WHEN 'bool'::regtype THEN 'false' WHEN 'int2'::regtype THEN '0::int2'
                                        WHEN 'bytea'::regtype THEN 'decode(md5(random()::text), ''hex'')' WHEN 'int4'::regtype THEN '(random() * 1000000000)::int4' WHEN 'int8'::regtype THEN '(random() * 1000000000)::int8'
                                        ELSE 'NULL::' || format_type(c.atttypid, NULL) END;
  END LOOP;
  IF cardinality(v_cols) = 0 THEN RETURN format('INSERT INTO %s DEFAULT VALUES', p_rel); END IF;
  RETURN format('INSERT INTO %s (%s) VALUES (%s)', p_rel, array_to_string(v_cols, ', '), array_to_string(v_vals, ', '));
END
$f$;
-- SEED (S1.1a LOW 2): one row per swept table, keyed to player A on every column a window policy compares with a setting, so that a pair's difference between "planted" and "unplanted" can be OBSERVED
-- in the no-binding control instead of being 0 -> 0 on an empty table. It runs as the HARNESS role (before SET ROLE private_definer), in a savepoint the caller rolls back. The question the sweep asks is what the
-- POLICY SET reaches, not whether the table would accept the row, so the table's FOREIGN KEY / CHECK / EXCLUDE constraints, its non-key NOT NULLs and its USER triggers are stripped first (all of it is
-- transactional DDL, undone by the rollback). A row that already exists for A is left alone (ON CONFLICT DO NOTHING): the existing one is observed instead.
CREATE FUNCTION pg_temp.sweep_seed(p_user uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  t record;
  c record;
  k record;
  v_cols text[];
  v_vals text[];
  v_n int := 0;
  v_got int;
BEGIN
  SET CONSTRAINTS ALL IMMEDIATE;
  FOR t IN SELECT DISTINCT c2.oid AS relid, n.nspname || '.' || c2.relname AS rel
           FROM pg_policy pol JOIN pg_class c2 ON c2.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c2.relnamespace
           WHERE pol.polroles = ARRAY['private_definer'::regrole::oid]
             AND pg_temp.policy_is_window(pol.oid)
           ORDER BY 2 LOOP
    FOR c IN SELECT kc.conname FROM pg_constraint kc WHERE kc.conrelid = t.relid AND kc.contype IN ('f', 'c', 'x') LOOP
      EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', t.rel, c.conname);
    END LOOP;
    FOR c IN SELECT a.attname FROM pg_attribute a
             WHERE a.attrelid = t.relid AND a.attnum > 0 AND NOT a.attisdropped AND a.attnotnull AND a.attgenerated = '' AND a.attidentity = ''
               AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = a.attrelid AND i.indisprimary AND a.attnum = ANY (i.indkey)) LOOP
      EXECUTE format('ALTER TABLE %s ALTER COLUMN %I DROP NOT NULL', t.rel, c.attname);
    END LOOP;
    EXECUTE format('ALTER TABLE %s DISABLE TRIGGER USER', t.rel);
    EXECUTE format('CREATE POLICY zz_sweep ON %s FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true)', t.rel);
    -- an earlier file may have revoked a privilege from the harness role for good (23_offline_totp_seed_edge.sql revokes INSERT on app.offline_code_step and commits): the owner gives it back to itself, inside this rolled-back savepoint
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO CURRENT_USER', t.rel);
    EXECUTE pg_temp.sweep_insert_stmt(t.relid, t.rel, p_user) || ' ON CONFLICT DO NOTHING';
    GET DIAGNOSTICS v_got = ROW_COUNT;
    v_n := v_n + v_got;
  END LOOP;
  RETURN v_n;
END
$f$;
-- the pairs whose reach does NOT change when the settings are planted (with no binding these are the pairs the settings do not open: the sweep must name every one of them)
CREATE FUNCTION pg_temp.window_same(p_user uuid) RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(s.rel || ':' || s.cmd ORDER BY s.rel, s.cmd)
  FROM pg_temp.window_statements(p_user) s
  WHERE pg_temp.measure(s.stmt, false, p_user) IS NOT DISTINCT FROM pg_temp.measure(s.stmt, true, p_user)
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.policy_is_window(oid), pg_temp.sweep_insert_stmt(oid, text, uuid), pg_temp.plant_settings(), pg_temp.plant_value(text, uuid), pg_temp.plant_all(uuid), pg_temp.unplant_all(), pg_temp.unplanted_settings(), pg_temp.measure(text, boolean, uuid), pg_temp.window_statements(uuid), pg_temp.window_diffs(uuid), pg_temp.window_same(uuid) TO PUBLIC;
SELECT is(pg_temp.unplanted_settings(), NULL::text[], 'PA-4c (i): every setting a GUC-keyed private_definer policy reads is one this file plants (a new window must be added to plant_all, or the catalog cells below would test nothing for it)');
SELECT cmp_ok((SELECT count(*)::int FROM pg_temp.window_statements()), '>=', 60, 'PA-4c (i): the catalog-driven statements cover at least 60 (table, command) pairs (not vacuous)');
-- the gate's three probes: a revoked staff member (a2) invited by manager_x (b1)
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET invited_by = '00000000-0000-0000-0000-2000000000b1' WHERE user_id = '00000000-0000-0000-0000-1000000000a2';
RESET ROLE;
SAVEPOINT pa4c_i;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-2000000000b1') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.upd_rows($$UPDATE app.partner_member SET revoked_at = NULL, role = 'manager', invited_by = NULL WHERE user_id = '00000000-0000-0000-0000-1000000000a2'$$), 0, 'PA-4c (i): with the windows PLANTED at the inviter, UPDATE partner_member SET revoked_at = NULL, role = manager, invited_by = NULL on the revoked member he invited affects 0 rows under a partner binding (the R3-M1 outcome the gate reproduced)');
SELECT is(pg_temp.upd_rows($$DELETE FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-2000000000b1'$$), 0, 'PA-4c (i): ... nor can it DELETE the planted user''s membership');
RESET ROLE;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-4000000000d0') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.upd_rows($$DELETE FROM app.admin_user WHERE user_id = '00000000-0000-0000-0000-4000000000d0'$$), 0, 'PA-4c (i): ... nor DELETE an admin_user row');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_i;
-- the SAME three statements with the SAME settings planted and NO partner binding reach their rows: the windows are real and the zeros above are the binding kind
SAVEPOINT pa4c_i_ctl;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-2000000000b1') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.upd_rows($$UPDATE app.partner_member SET revoked_at = NULL, role = 'manager', invited_by = NULL WHERE user_id = '00000000-0000-0000-0000-1000000000a2'$$), 1, 'PA-4c (i) control: the same UPDATE with the same settings and NO partner binding un-revokes and promotes (1 row): the window is the delete_my_data one, open as designed');
SELECT is(pg_temp.upd_rows($$DELETE FROM app.partner_member WHERE user_id = '00000000-0000-0000-0000-2000000000b1'$$), 1, 'PA-4c (i) control: ... and the DELETE of the membership reaches its row');
RESET ROLE;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-4000000000d0') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.upd_rows($$DELETE FROM app.admin_user WHERE user_id = '00000000-0000-0000-0000-4000000000d0'$$), 1, 'PA-4c (i) control: ... and the admin_user DELETE');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_i_ctl;
-- catalog-driven, under a partner binding: planting changes nothing for ANY covered (table, command)
SAVEPOINT pa4c_i_cat;
SELECT pg_temp.sweep_seed('00000000-0000-0000-0000-00000000000a') AS _seeded \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.window_diffs('00000000-0000-0000-0000-00000000000a'), NULL::text[], 'PA-4c (i): CATALOG-DRIVEN: under a partner binding, for every (table, command) a GUC-keyed private_definer policy covers, the rows reached with every setting planted at player A equal the rows reached with them unset');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_i_cat;
SAVEPOINT pa4c_i_cat2;
SELECT pg_temp.sweep_seed('00000000-0000-0000-0000-00000000000a') AS _seeded2 \gset
SET LOCAL ROLE private_definer;
SELECT cmp_ok(:_seeded2, '>=', 20, 'PA-4c (i) control: the sweep SEEDED at least 20 rows keyed to player A (so the no-binding comparison below is not 0 -> 0 on empty tables)');
SELECT is(pg_temp.window_same('00000000-0000-0000-0000-00000000000a'), ARRAY['app.admin_user:r', 'app.app_review_demo_account:r', 'app.partner_member:r'],
  'PA-4c (i) control: with NO partner binding, planting the settings changes the rows reached for EVERY (table, command) pair a GUC-keyed private_definer policy covers (select, update, delete and insert alike) except exactly three SELECT pairs, whose rows a second, unconditional private_definer read policy (pd_read_admin_user / pd_read_demo_account / pd_read_partner_member, USING true) already returns with nothing planted: for those the planted window adds nothing to observe, and a pair that joins that list (or leaves it) fails here');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_i_cat2;
-- (S1.1b gate L-2) a GUC read BEHIND A WRAPPER is a window too: the catalog sweep must find the policy, know its setting and its key column, and refuse a setting nobody plants
SAVEPOINT pa4c_i_wrap;
CREATE TABLE app.zz25w (id int, owner_id uuid);
ALTER TABLE app.zz25w ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION private.zz25_guc() RETURNS text LANGUAGE sql STABLE AS $z$ SELECT nullif(current_setting('zz.target', true), '') $z$;
CREATE POLICY zz25w_pol ON app.zz25w FOR SELECT TO private_definer USING (owner_id::text = private.zz25_guc());
SELECT ok('zz.target' = ANY (pg_temp.unplanted_settings()), 'PA-4c (i) wrapper: a setting read only through a wrapper function is found and reported as one the cell does not plant (so a window behind a wrapper fails the cell instead of passing it)');
SELECT ok(EXISTS (SELECT 1 FROM pg_temp.window_statements() WHERE rel = 'app.zz25w' AND cmd = 'r'), 'PA-4c (i) wrapper: the catalog sweep covers the (table, command) pair of a policy whose wrapper reads a setting');
SELECT ok(pg_temp.sweep_insert_stmt('app.zz25w'::regclass::oid, 'app.zz25w', '00000000-0000-0000-0000-00000000000a') LIKE '%(owner_id) VALUES (%', 'PA-4c (i) wrapper: the seed keys the column the wrapper policy compares');
ROLLBACK TO SAVEPOINT pa4c_i_wrap;
-- (ii) as edge_partner PLANT every GUC the repository uses, then drive each writer of partner_session against ANOTHER user's session: 0 rows every time
SAVEPOINT pa4c_ii;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-2000000000b1', true) IS NOT NULL AS planted_1,
       set_config('app.delete_my_data.target_email', 'manager-x@example.test', true) IS NOT NULL AS planted_2,
       set_config('app.delete_my_data.target_handle', 'x', true) IS NOT NULL AS planted_3,
       set_config('app.delete_my_data.target_pseudonym', 'x', true) IS NOT NULL AS planted_4,
       set_config('app.offline_code.target_device_id', '20000000-0000-0000-0000-000000000001', true) IS NOT NULL AS planted_5,
       set_config('app.edge.link_device_id', '20000000-0000-0000-0000-000000000001', true) IS NOT NULL AS planted_6,
       set_config('app.edge.link_hash', 'x', true) IS NOT NULL AS planted_7,
       set_config('app.edge.link_attest_key', 'x', true) IS NOT NULL AS planted_8,
       set_config('app.edge.purge_fix_coords', 'on', true) IS NOT NULL AS planted_9,
       set_config('app.signin.proof_id', '00000000-0000-0000-0000-000000000000', true) IS NOT NULL AS planted_10,
       set_config('app.signin.proof_purge', 'on', true) IS NOT NULL AS planted_11,
       set_config('app.partner.authority_touch', 'on', true) IS NOT NULL AS planted_12,
       set_config('app.partner.session_id', :'s_mx', true) IS NOT NULL AS planted_13 \gset
RESET ROLE;
-- every writer role: its own bound session is writable, manager_x's is NOT (0 rows), with the GUCs planted
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET revoked_at = clock_timestamp(), revoke_reason = 'planted' WHERE id = %L$$, :'s_mx')), 0,
  'PA-4c (ii): private_definer, partner-bound as staff_x, with every GUC planted at manager_x: revoking MANAGER_X''s session affects 0 rows (the own-session policy is keyed on the binding, not on a GUC)');
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET last_seen_at = clock_timestamp() WHERE id = %L$$, :'s_mx')), 0, 'PA-4c (ii): ... nor can it touch last_seen_at there');
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET last_seen_at = clock_timestamp() WHERE id = %L$$, :'s_sx')), 1, 'PA-4c (ii): control: its OWN bound session is writable (1 row)');
RESET ROLE;
SET LOCAL ROLE partner_pin_verifier;
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = %L$$, :'s_mx')), 0, 'PA-4c (ii): the PIN verifier role, planted: manager_x''s session: 0 rows');
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = %L$$, :'s_sx')), 1, 'PA-4c (ii): control: its own bound session: 1 row');
RESET ROLE;
SET LOCAL ROLE partner_totp_verifier;
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET aal = 2, mfa_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_mx')), 0, 'PA-4c (ii): the TOTP verifier role, planted: manager_x''s session: 0 rows (it could otherwise raise another person''s aal)');
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET aal = 2, mfa_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_sx')), 1, 'PA-4c (ii): control: its own bound session: 1 row');
RESET ROLE;
SET LOCAL ROLE partner_reauth_verifier;
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET reauth_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_mx')), 0, 'PA-4c (ii): the reauth verifier role, planted: manager_x''s session: 0 rows');
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET reauth_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_sx')), 1, 'PA-4c (ii): control: its own bound session: 1 row');
RESET ROLE;
-- the authority triggers and the toucher / issuer have NO GUC in any policy: the planted values change nothing about THEIR reach (the toucher's policy is USING (true): its reach is its COLUMN grants)
SET LOCAL ROLE partner_session_toucher;
SELECT is(pg_temp.upd_rows(format($$UPDATE app.partner_session SET authority_touched_at = clock_timestamp() WHERE id = %L$$, :'s_mx')), 1, 'PA-4c (ii): the toucher reaches any live session by DESIGN (revoke / touch columns only): its reach is a column grant, identical with and without the GUCs');
SELECT throws_ok(format($$UPDATE app.partner_session SET aal = 2 WHERE id = %L$$, :'s_mx'), '42501', NULL, 'PA-4c (ii): ... but it cannot raise aal (no column grant)');
RESET ROLE;
-- the policies themselves: not one policy on partner_session for any role names current_setting except the delete_my_data pair
SELECT is((SELECT array_agg(pol.polname::text ORDER BY pol.polname::text) FROM pg_policy pol WHERE pol.polrelid = 'app.partner_session'::regclass
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) LIKE '%current_setting%'),
          ARRAY['pd_delete_partner_session_user_id', 'pd_delete_partner_session_user_id_r'],
  'PA-4c: the ONLY policies on partner_session that read a GUC are the delete_my_data DELETE / SELECT pair (the registry pass requires them); no UPDATE or INSERT policy does, for any role');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polrelid IN ('app.partner_member'::regclass, 'app.partner_scope'::regclass, 'app.admin_user'::regclass)
           AND pol.polname ~ '^(pst|psi|psf|ppv|ptv|prv)_(update|insert|lock)' ), 0, 'R3-M1: no lock policy of any role exists on partner_member, partner_scope or admin_user');
ROLLBACK TO SAVEPOINT pa4c_ii;

-- (iii) the delete_my_data WINDOW is closed under a partner binding: the DELETE / SELECT / set-null pairs on the four tables this migration creates carry
-- `AND private.partner_binding_kind() IS DISTINCT FROM 'partner'`, so a planted app.delete_my_data.target_user_id cannot make ANOTHER person's session, credential,
-- enrolment token or used challenge visible, deletable or redactable to a definer a partner transaction reaches (probed: without the conjunct a partner-bound
-- private_definer DELETEd another user's session). The control is the same statements with the same GUC planted and NO partner binding: they reach every row (this is
-- delete_my_data's own shape, and PA-1b proves the real pass end to end).
CREATE FUNCTION pg_temp.win_probe(p_uid uuid, p_cred uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE s int; c int; t int; ch int; sv int; cv int; sn int;
BEGIN
  PERFORM set_config('app.delete_my_data.target_user_id', p_uid::text, true);
  SELECT count(*) INTO sv FROM app.partner_session WHERE user_id = p_uid;
  SELECT count(*) INTO cv FROM app.partner_credential WHERE user_id = p_uid;
  UPDATE app.partner_credential SET revoked_by = NULL WHERE revoked_by = p_uid;
  GET DIAGNOSTICS sn = ROW_COUNT;
  DELETE FROM app.partner_session WHERE user_id = p_uid;
  GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM app.partner_enrolment_token WHERE user_id = p_uid;
  GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM app.partner_auth_challenge WHERE user_id = p_uid;
  GET DIAGNOSTICS ch = ROW_COUNT;
  DELETE FROM app.partner_credential WHERE user_id = p_uid;
  GET DIAGNOSTICS c = ROW_COUNT;
  RETURN format('visible sessions=%s credentials=%s; setnull=%s; deleted sessions=%s tokens=%s challenges=%s credentials=%s', sv, cv, sn, s, t, ch, c);
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.win_probe(uuid, uuid) TO PUBLIC;
SAVEPOINT pa4c_iii_bound;
INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, expires_at)
VALUES ('00000000-0000-0000-0000-2000000000b1', 'recover', NULL, repeat('7', 64), now() + interval '1 hour');
INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id) VALUES (decode(repeat('7a', 32), 'hex'), 'sign_in', '00000000-0000-0000-0000-2000000000b1');
INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, revoked_at, revoked_by)
VALUES ('00000000-0000-0000-0000-1000000000a3', decode(repeat('7b', 32), 'hex'), decode(repeat('7c', 77), 'hex'), -7, now(), '00000000-0000-0000-0000-2000000000b1');
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.win_probe('00000000-0000-0000-0000-2000000000b1', :'c_mx'::uuid), 'visible sessions=0 credentials=0; setnull=0; deleted sessions=0 tokens=0 challenges=0 credentials=0',
  'PA-4c (iii): a partner-bound private_definer with the delete_my_data GUC planted at another user sees none of their sessions or credentials and deletes / redacts nothing in the four tables');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_iii_bound;
SAVEPOINT pa4c_iii_unbound;
INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, expires_at)
VALUES ('00000000-0000-0000-0000-2000000000b1', 'recover', NULL, repeat('7', 64), now() + interval '1 hour');
INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id) VALUES (decode(repeat('7a', 32), 'hex'), 'sign_in', '00000000-0000-0000-0000-2000000000b1');
INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, revoked_at, revoked_by)
VALUES ('00000000-0000-0000-0000-1000000000a3', decode(repeat('7b', 32), 'hex'), decode(repeat('7c', 77), 'hex'), -7, now(), '00000000-0000-0000-0000-2000000000b1');
SET LOCAL ROLE private_definer;
SELECT matches(pg_temp.win_probe('00000000-0000-0000-0000-2000000000b1', :'c_mx'::uuid), '^visible sessions=[1-9][0-9]* credentials=[1-9][0-9]*; setnull=1; deleted sessions=[1-9][0-9]* tokens=1 challenges=1 credentials=[1-9][0-9]*$',
  'PA-4c (iii) control: the same statements with the same GUC and NO partner binding reach every row (the window is open: it is delete_my_data''s own shape), so the cell above is not vacuous');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4c_iii_unbound;

-- ============================================================================
-- PA-4d: the guard trigger, one cell per row of its table (R4-L1, R5-L1), driven as the harness role (a role with every column privilege: the guard is what is under test)
-- ============================================================================
CREATE FUNCTION pg_temp.guard_try(p_set text, p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE format('UPDATE app.partner_session SET %s WHERE id = %L', p_set, p_id);
  RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$f$;
SET LOCAL ROLE service_role;
INSERT INTO auth.sessions (id, user_id, created_at) VALUES
  ('ee240000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-1000000000a1', clock_timestamp()),
  ('ee240000-0000-0000-0000-00000000c002', '00000000-0000-0000-0000-1000000000a1', clock_timestamp()),
  ('ee240000-0000-0000-0000-00000000c003', '00000000-0000-0000-0000-2000000000b1', clock_timestamp()),
  ('ee240000-0000-0000-0000-00000000c004', '00000000-0000-0000-0000-1000000000a1', clock_timestamp() - interval '5 minutes');
RESET ROLE;
SELECT is(pg_temp.guard_try('user_id = ''00000000-0000-0000-0000-2000000000b1'', aal = 2', :'s_sx'), '23514', 'PA-4d: user_id cannot change, and SET user_id = <other>, aal = 2 (which the author showed succeeds under the bare policy) is refused');
SELECT is(pg_temp.guard_try('credential_id = ''' || :'c_mx' || '''', :'s_sx'), '23514', 'PA-4d: credential_id cannot change');
SELECT is(pg_temp.guard_try('token_hash = repeat(''b'', 64)', :'s_sx'), '23514', 'PA-4d: token_hash cannot change');
SELECT is(pg_temp.guard_try('created_at = now()', :'s_sx'), '23514', 'PA-4d: created_at cannot change');
SELECT is(pg_temp.guard_try('id = gen_random_uuid()', :'s_sx'), '23514', 'PA-4d: id cannot change');
SELECT is(pg_temp.guard_try('mint_kind = ''register'', mint_signature = NULL', :'s_sx'), '23514', 'PA-4d: mint_kind cannot change');
SELECT is(pg_temp.guard_try('mint_nonce_hash = decode(repeat(''09'', 32), ''hex'')', :'s_sx'), '23514', 'PA-4d: mint_nonce_hash cannot change');
SELECT is(pg_temp.guard_try('mint_authenticator_data = decode(repeat(''09'', 40), ''hex'')', :'s_sx'), '23514', 'PA-4d: mint_authenticator_data cannot change (the S1.6 evidence)');
SELECT is(pg_temp.guard_try('mint_client_data_json = convert_to(''{"a":1}'', ''UTF8'')', :'s_sx'), '23514', 'PA-4d: mint_client_data_json cannot change');
SELECT is(pg_temp.guard_try('mint_signature = decode(repeat(''09'', 70), ''hex'')', :'s_sx'), '23514', 'PA-4d: mint_signature cannot change');
SELECT is(pg_temp.guard_try('enrolment_until = now() + interval ''1 hour''', :'s_sx'), '23514', 'PA-4d: enrolment_until is set at insert and never after');
SELECT is(pg_temp.guard_try('pop_jkt = ''thumb''', :'s_sx'), '23514', 'PA-4d: pop_jkt (the reserved proof-of-possession slot) is set at mint only');
SELECT is(pg_temp.guard_try('expires_at = expires_at + interval ''1 second''', :'s_sx'), '23514', 'PA-4d: expires_at may NOT increase');
SELECT is(pg_temp.guard_try('expires_at = expires_at - interval ''1 minute''', :'s_sx'), 'ok', 'PA-4d: ... but may be shortened');
SELECT is(pg_temp.guard_try('revoked_at = now(), revoke_reason = ''first''', :'s_sx'), 'ok', 'PA-4d: revoked_at goes from NULL to non-NULL ...');
SELECT is(pg_temp.guard_try('revoked_at = NULL', :'s_sx'), '23514', 'PA-4d: ... never back to NULL');
SELECT is(pg_temp.guard_try('revoked_at = now() + interval ''1 hour''', :'s_sx'), '23514', 'PA-4d: ... and a revoked_at, once set, never changes (it cannot be pushed into the future)');
SELECT is(pg_temp.guard_try('revoke_reason = ''rewritten''', :'s_sx'), '23514', 'PA-4d: ... nor its reason');
-- aal, mfa_until, pin_grant_until, reauth_until on s_sx2 (a live one)
SELECT is(pg_temp.guard_try('aal = 2, mfa_until = clock_timestamp() + interval ''4 minutes''', :'s_sx2'), 'ok', 'PA-4d: aal goes 1 to 2 with mfa_until within 5 minutes');
SELECT is(pg_temp.guard_try('aal = 1', :'s_sx2'), '23514', 'PA-4d: aal never goes back down');
SELECT is(pg_temp.guard_try('mfa_until = clock_timestamp() + interval ''6 minutes''', :'s_sx2'), '23514', 'PA-4d: mfa_until is at most now + 5 minutes');
SELECT is(pg_temp.guard_try('mfa_until = NULL', :'s_sx2'), 'ok', 'PA-4d: ... and may be cleared (lock)');
SELECT is(pg_temp.guard_try('pin_grant_until = clock_timestamp() + interval ''61 seconds''', :'s_sx2'), '23514', 'PA-4d: pin_grant_until is at most now + 60 seconds');
SELECT is(pg_temp.guard_try('pin_grant_until = clock_timestamp() + interval ''59 seconds''', :'s_sx2'), 'ok', 'PA-4d: ... 59 seconds is accepted');
SELECT is(pg_temp.guard_try('pin_grant_until = NULL', :'s_sx2'), 'ok', 'PA-4d: ... and clearing (consumption) is always allowed');
SELECT is(pg_temp.guard_try('reauth_until = clock_timestamp() + interval ''301 seconds''', :'s_sx2'), '23514', 'PA-4d: reauth_until is at most now + 5 minutes');
SELECT is(pg_temp.guard_try('reauth_until = clock_timestamp() + interval ''299 seconds''', :'s_sx2'), 'ok', 'PA-4d: ... 299 seconds is accepted');
-- last_seen_at: monotone and at most now + 1 minute
SELECT is(pg_temp.guard_try('last_seen_at = last_seen_at - interval ''1 second''', :'s_sx2'), '23514', 'PA-4d: last_seen_at cannot decrease');
SELECT is(pg_temp.guard_try('last_seen_at = clock_timestamp() + interval ''2 minutes''', :'s_sx2'), '23514', 'PA-4d: ... nor run into the future (it would extend the idle window)');
SELECT is(pg_temp.guard_try('last_seen_at = clock_timestamp()', :'s_sx2'), 'ok', 'PA-4d: ... a real now() is accepted');
-- the OTP proof (R5-L1: no artefact row; the GoTrue session is checked, as in 0041)
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes''', :'s_sx2'), '23514', 'PA-4d: otp_proof_until without a GoTrue session id is refused');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes'', otp_proof_gotrue_session_id = gen_random_uuid()', :'s_sx2'), '23514', 'PA-4d: ... with a GoTrue session that does not exist: refused');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c003''', :'s_sx2'), '23514', 'PA-4d: ... with ANOTHER USER''s GoTrue session: refused');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c004''', :'s_sx2'), '23514', 'PA-4d: ... with a STALE GoTrue session (5 minutes old, not fresh): refused');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''11 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c001''', :'s_sx2'), '23514', 'PA-4d: ... with a window over 10 minutes: refused');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''9 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c001''', :'s_sx2'), 'ok', 'PA-4d: ... with this user''s fresh GoTrue session and at most 10 minutes: accepted');
SELECT is(pg_temp.guard_try('otp_proof_until = otp_proof_until + interval ''5 minutes''', :'s_sx2'), '23514', 'PA-4d: the window cannot be EXTENDED without a new GoTrue session');
SELECT is(pg_temp.guard_try('otp_proof_until = otp_proof_until - interval ''5 minutes''', :'s_sx2'), 'ok', 'PA-4d: ... but may be shortened');
SELECT is(pg_temp.guard_try('otp_proof_until = NULL', :'s_sx2'), 'ok', 'PA-4d: ... or cleared');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes''', :'s_sx2'), '23514', 'PA-4d: ... and cleared does NOT mean re-armable with the same GoTrue session id');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c002''', :'s_sx2'), 'ok', 'PA-4d: a NEW proof with a NEW fresh GoTrue session is accepted');
SELECT is(pg_temp.guard_try('otp_proof_until = clock_timestamp() + interval ''5 minutes'', otp_proof_gotrue_session_id = ''ee240000-0000-0000-0000-00000000c002''', :'s_sx_idle_ok'), '23505', 'R5-L1: the UNIQUE index: ONE GoTrue session proves at most one OTP proof (a second session of the member naming it is a unique violation)');
-- the table's own CHECKs
SELECT is(pg_temp.guard_try('aal = 3', :'s_sx_idle_ok'), '23514', 'aal is 1 or 2 (CHECK)');
SELECT is(pg_temp.guard_try('mint_signature = NULL', :'s_sx_idle_ok'), '23514', 'a sign_in mint carries a signature (the guard refuses the change; the CHECK says why)');

-- column PRIVILEGES: the verifier columns are written by their own role only (R5-L1); private_definer has none of them
SAVEPOINT pa4d_priv;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_idle_ok');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT throws_ok(format($$UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: private_definer has NO UPDATE on pin_grant_until (only partner_pin_verifier does)');
SELECT throws_ok(format($$UPDATE app.partner_session SET aal = 2 WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... none on aal');
SELECT throws_ok(format($$UPDATE app.partner_session SET mfa_until = clock_timestamp() WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... none on mfa_until');
SELECT throws_ok(format($$UPDATE app.partner_session SET reauth_until = clock_timestamp() WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... none on reauth_until');
SELECT throws_ok(format($$UPDATE app.partner_session SET user_id = %L WHERE id = %L$$, '00000000-0000-0000-0000-2000000000b1', :'s_sx_idle_ok'), '42501', NULL, 'R4-L1: ... none on user_id (the column the bare policy let it rewrite)');
SELECT throws_ok(format($$UPDATE app.partner_session SET expires_at = expires_at + interval '1 day' WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R4-L1: ... none on expires_at');
SELECT throws_ok(format($$UPDATE app.partner_session SET token_hash = repeat('c', 64) WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R4-L1: ... none on token_hash');
SELECT throws_ok(format($$SELECT token_hash FROM app.partner_session WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'and it cannot READ token_hash or the mint evidence at all (column-level SELECT)');
SELECT throws_ok(format($$SELECT mint_signature FROM app.partner_session WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R4-L1: ... nor mint_signature');
SELECT lives_ok(format($$UPDATE app.partner_session SET last_seen_at = clock_timestamp(), revoked_at = NULL WHERE id = %L$$, :'s_sx_idle_ok'), 'control: its own columns (last_seen_at ...) are writable on its own bound session');
RESET ROLE;
SET LOCAL ROLE partner_pin_verifier;
SELECT lives_ok(format($$UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = %L$$, :'s_sx_idle_ok'), 'R5-L1 / PA-4d: the PIN verifier role sets pin_grant_until on the bound session (a stub call: the real verifier is S1.3)');
SELECT throws_ok(format($$UPDATE app.partner_session SET aal = 2 WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... and holds no other verifier column');
SELECT throws_ok(format($$UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '61 seconds' WHERE id = %L$$, :'s_sx_idle_ok'), '23514', NULL, 'PA-4d: ... and the guard still caps it at 60 seconds, whoever the writer');
RESET ROLE;
SET LOCAL ROLE partner_totp_verifier;
SELECT lives_ok(format($$UPDATE app.partner_session SET aal = 2, mfa_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_sx_idle_ok'), 'R5-L1 / PA-4d: the TOTP verifier role sets aal 2 and mfa_until (a stub)');
SELECT throws_ok(format($$UPDATE app.partner_session SET pin_grant_until = NULL WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... and cannot touch the PIN grant');
SELECT throws_ok(format($$UPDATE app.partner_session SET aal = 1 WHERE id = %L$$, :'s_sx_idle_ok'), '23514', NULL, 'PA-4d: ... nor lower aal (the guard)');
RESET ROLE;
SET LOCAL ROLE partner_reauth_verifier;
SELECT lives_ok(format($$UPDATE app.partner_session SET reauth_until = clock_timestamp() + interval '4 minutes' WHERE id = %L$$, :'s_sx_idle_ok'), 'R5-L1 / PA-4d: the reauth verifier role sets reauth_until (a stub)');
SELECT throws_ok(format($$UPDATE app.partner_session SET mfa_until = NULL WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'R5-L1: ... and holds no other verifier column');
RESET ROLE;
-- the toucher: revoke and touch only
SET LOCAL ROLE partner_session_toucher;
SELECT lives_ok(format($$UPDATE app.partner_session SET authority_touched_at = clock_timestamp() WHERE id = %L$$, :'s_sx_idle_ok'), 'the toucher touches sessions');
SELECT throws_ok(format($$UPDATE app.partner_session SET expires_at = expires_at + interval '1 day' WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'the toucher has no UPDATE on expires_at');
SELECT throws_ok(format($$UPDATE app.partner_session SET aal = 2 WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'the toucher cannot raise aal');
SELECT throws_ok(format($$SELECT mint_signature FROM app.partner_session WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'the toucher cannot read the mint evidence');
SELECT throws_ok(format($$DELETE FROM app.partner_session WHERE id = %L$$, :'s_sx_idle_ok'), '42501', NULL, 'the toucher cannot delete a session');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4d_priv;

-- a fresh session (s_sx was revoked by the guard cells above)
SELECT pg_temp.mk_session('sx_pin', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx_pin \gset
SELECT pg_temp.th('sx_pin') AS th_sx_pin \gset
-- the PIN grant: a single-use consumption, atomic, by the verifier-owned function; class A1 spends it
SAVEPOINT pa4d_pin;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_pin');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.consume(), false, 'PIN grant: with no grant outstanding the consumption answers false');
RESET ROLE;
SET LOCAL ROLE partner_pin_verifier;
UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = :'s_sx_pin'::uuid;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.consume(), true, 'PIN grant: a verified, unexpired grant is consumed once ...');
SELECT is(pg_temp.consume(), false, 'PIN grant: ... and a second consumption is refused (ONE PIN, ONE action)');
RESET ROLE;
SELECT is((SELECT pin_grant_until IS NULL FROM app.partner_session WHERE id = :'s_sx_pin'::uuid), true, 'PIN grant: the grant was cleared by the consumption');
SET LOCAL ROLE partner_pin_verifier;
UPDATE app.partner_session SET pin_grant_until = clock_timestamp() - interval '1 second' WHERE id = :'s_sx_pin'::uuid;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.consume(), false, 'PIN grant: an EXPIRED grant is not consumable');
RESET ROLE;
-- class A1
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'class A1: refused without a PIN grant');
RESET ROLE;
SET LOCAL ROLE partner_pin_verifier;
UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '30 seconds' WHERE id = :'s_sx_pin'::uuid;
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_y', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: no scope', 'class A1: out of scope the call is refused BEFORE the grant is spent');
SELECT is(private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'class A1: with a fresh grant and in scope the call is authorised ... (the refused call above did not burn the grant)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A1')$$, '42501', 'partner_authorize: a PIN verified in the last minute and not yet used is required', 'class A1: ... and the same grant cannot authorise a SECOND action');
RESET ROLE;
ROLLBACK TO SAVEPOINT pa4d_pin;

-- ============================================================================
-- PA-1b: delete_my_data and export_my_data cover the new tables (partner-auth-design 5.4)
-- ============================================================================
SAVEPOINT pa1b;
INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, expires_at)
VALUES ('00000000-0000-0000-0000-1000000000a1', 'recover', '00000000-0000-0000-0000-2000000000b1', repeat('1', 64), now() + interval '1 hour'),
       ('00000000-0000-0000-0000-2000000000b1', 'recover', '00000000-0000-0000-0000-1000000000a1', repeat('2', 64), now() + interval '1 hour');
INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id) VALUES (decode(repeat('0a', 32), 'hex'), 'sign_in', '00000000-0000-0000-0000-1000000000a1');
INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, revoked_at, revoked_by)
VALUES ('00000000-0000-0000-0000-2000000000b1', decode(repeat('0b', 32), 'hex'), decode(repeat('0c', 77), 'hex'), -7, now(), '00000000-0000-0000-0000-1000000000a1');
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 3, 'PA-1b precondition: the account has its credentials (three: fixtures)');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 8, 'PA-1b precondition: ... and its sessions');
-- export: metadata only, never the key material (the export is service_role's: captured as a psql variable, then asserted as the harness)
SET LOCAL ROLE service_role;
SELECT private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid)::text AS exp_json \gset
RESET ROLE;
SELECT is((SELECT jsonb_array_length(:'exp_json'::jsonb -> 'partner_credential')), 3, 'PA-1b: export_my_data carries the account''s partner credential block');
SELECT is((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys((:'exp_json'::jsonb -> 'partner_credential') -> 0) k),
          ARRAY['aaguid', 'alg', 'backup_eligible', 'backup_state', 'created_at', 'id', 'label', 'last_used_at', 'note', 'revoke_reason', 'revoked_at', 'transports', 'user_id'],
  'PA-1b: ... metadata only: never public_key, credential_id or sign_count');
SELECT is(:'exp_json' ~ 'token_hash|mint_signature|nonce_hash|public_key', false, 'PA-1b: and no session, token, challenge or key artefact appears anywhere in the export');
SET LOCAL ROLE service_role;
SELECT private.delete_my_data('00000000-0000-0000-0000-1000000000a1'::uuid) AS _d \gset
RESET ROLE;
SELECT is((SELECT count(*)::int FROM app.partner_credential WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0, 'PA-1b: delete_my_data removes the account''s credentials');
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0, 'PA-1b: ... its sessions');
SELECT is((SELECT count(*)::int FROM app.partner_enrolment_token WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0, 'PA-1b: ... its enrolment tokens');
SELECT is((SELECT count(*)::int FROM app.partner_auth_challenge WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0, 'PA-1b: ... its challenges');
SELECT is((SELECT issued_by IS NULL FROM app.partner_enrolment_token WHERE token_hash = repeat('2', 64)), true, 'PA-1b: a token it ISSUED to someone else survives with issued_by redacted');
SELECT is((SELECT revoked_by IS NULL FROM app.partner_credential WHERE credential_id = decode(repeat('0b', 32), 'hex')), true, 'PA-1b: a credential it REVOKED for someone else survives with revoked_by redacted');
ROLLBACK TO SAVEPOINT pa1b;

-- ============================================================================
-- PA-9c: the offline-code recorder is not an edge_actor surface (X9); the other half (a planted edge_actor function reading partner scope) is check 14 (b) in 10_function_inventory.sql
-- ============================================================================
SELECT is(has_function_privilege('edge_actor', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE'), false, 'PA-9c: edge_actor cannot EXECUTE offline_code_record_step_for_actor');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname = 'offline_code_record_step_for_actor' AND (has_function_privilege('edge_actor', p.oid, 'EXECUTE') OR has_function_privilege('edge_partner', p.oid, 'EXECUTE') OR has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE'))), 0,
  'PA-9c: ... under any signature, and neither can any partner lane role');

-- ============================================================================
-- S1.1a gate M1: private_definer's view of partner_invite (the invitee_email and token_hash of every pending invite)
-- ============================================================================
SAVEPOINT g_m1_none;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_invite), 0, 'M1: private_definer sees NO partner_invite row with no binding and no window (it used to see every pending invite: 2 of 2, with the invitee address and the token hash)');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_m1_none;
SAVEPOINT g_m1_user;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_invite), 0, 'M1: ... nor under a USER binding');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_m1_user;
SAVEPOINT g_m1_partner;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_pin');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_invite), 0, 'M1: ... nor under a PARTNER binding');
RESET ROLE;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-00000000000a') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_invite), 0, 'M1: ... not even under a partner binding with every window planted');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_m1_partner;
SAVEPOINT g_m1_window;
SELECT pg_temp.plant_all('00000000-0000-0000-0000-00000000000a') AS _p \gset
SET LOCAL ROLE private_definer;
SELECT cmp_ok((SELECT count(*)::int FROM app.partner_invite), '>=', 2, 'M1 control: with the delete_my_data window OPEN (a setting planted, no partner binding) the set-null companions see the rows delete_my_data must redact (so the fix did not close the real window)');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_m1_window;
SAVEPOINT g_m1_cred;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_credential) + (SELECT count(*)::int FROM app.partner_enrolment_token), 0, 'M1: the same for the other two set-null companions this migration adds (partner_credential, partner_enrolment_token): no rows without a window');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_m1_cred;

-- ============================================================================
-- S1.1a gate M2: the INSERT guards (the issuer has a relation-wide INSERT with WITH CHECK (true))
-- ============================================================================
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential ENABLE TRIGGER partner_credential_insert_guard_trg;
CREATE FUNCTION pg_temp.try_ins_session(p_user uuid, p_cred uuid, p_over jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  j jsonb := jsonb_build_object('id', gen_random_uuid(), 'token_hash', md5(random()::text) || md5(random()::text), 'user_id', p_user, 'credential_id', p_cred, 'aal', 1,
                                'created_at', clock_timestamp(), 'last_seen_at', clock_timestamp(), 'expires_at', clock_timestamp() + interval '7 hours 59 minutes', 'mint_kind', 'sign_in',
                                'mint_nonce_hash', '\x' || md5(random()::text) || md5(random()::text), 'mint_authenticator_data', '\x' || repeat('04', 40),
                                'mint_client_data_json', '\x7b7d', 'mint_signature', '\x' || repeat('05', 70));
BEGIN
  INSERT INTO app.partner_session SELECT * FROM jsonb_populate_record(NULL::app.partner_session, j || p_over);
  RAISE EXCEPTION 'inserted' USING ERRCODE = 'P0001';
EXCEPTION WHEN SQLSTATE 'P0001' THEN
  RETURN 'ok';
WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$f$;
CREATE FUNCTION pg_temp.try_ins_cred(p_user uuid, p_over jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  j jsonb := jsonb_build_object('id', gen_random_uuid(), 'user_id', p_user, 'credential_id', '\x' || md5(random()::text) || md5(random()::text), 'public_key', '\x' || repeat('0c', 77),
                                'alg', -7, 'created_at', clock_timestamp(), 'sign_count', 0, 'transports', '{}', 'backup_eligible', false, 'backup_state', false, 'label', '');
BEGIN
  INSERT INTO app.partner_credential SELECT * FROM jsonb_populate_record(NULL::app.partner_credential, j || p_over);
  RAISE EXCEPTION 'inserted' USING ERRCODE = 'P0001';
EXCEPTION WHEN SQLSTATE 'P0001' THEN
  RETURN 'ok';
WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.try_ins_session(uuid, uuid, jsonb), pg_temp.try_ins_cred(uuid, jsonb) TO PUBLIC;
SELECT gen_random_uuid() AS g_gosess \gset
SET LOCAL ROLE service_role;
INSERT INTO auth.sessions (id, user_id, created_at) VALUES (:'g_gosess', '00000000-0000-0000-0000-1000000000a1', clock_timestamp());
RESET ROLE;
SET LOCAL ROLE partner_session_issuer;
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', '{}'::jsonb), 'ok', 'M2 control: the issuer inserts a well-formed sign_in session (aal 1, nothing verified, the database clock, just under the 8 hour ceiling: created_at and expires_at are read at different microseconds, so the base row keeps a minute of margin)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', '{"aal": 2}'::jsonb), '23514', 'M2: a session is born at aal 1: aal 2 is refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('pin_grant_until', clock_timestamp() + interval '1 day')), '23514', 'M2: ... with a PIN grant: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('reauth_until', clock_timestamp() + interval '1 day')), '23514', 'M2: ... with a reauth window: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('mfa_until', clock_timestamp() + interval '1 day')), '23514', 'M2: ... with an mfa window: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('otp_proof_until', clock_timestamp() + interval '1 hour')), '23514', 'M2: ... with an OTP proof window: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('otp_proof_gotrue_session_id', :'g_gosess'::uuid, 'otp_proof_until', clock_timestamp() + interval '5 minutes')), '23514', 'M2: ... with an OTP proof bound to a GoTrue session: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('revoked_at', clock_timestamp())), '23514', 'M2: ... already revoked: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', '{"revoke_reason": "x"}'::jsonb), '23514', 'M2: ... with a revoke reason: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('authority_touched_at', clock_timestamp())), '23514', 'M2: ... with a touch: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('expires_at', clock_timestamp() + interval '10 years')), '23514', 'M2: a 10-YEAR session is refused (the gate''s issuer insert)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('expires_at', clock_timestamp() + interval '8 hours 2 minutes')), '23514', 'M2: ... staff: 8 hours is the ceiling (8 h 2 min refused)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-3000000000c1', :'c_op', jsonb_build_object('expires_at', clock_timestamp() + interval '3 hours 59 minutes')), 'ok', 'M2: ... an OPERATOR session of 3 h 59 min is accepted ...');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-3000000000c1', :'c_op', jsonb_build_object('expires_at', clock_timestamp() + interval '4 hours 2 minutes')), '23514', 'M2: ... and 4 h 2 min is refused (operator ceiling 4 h)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-4000000000d0', :'c_ad', jsonb_build_object('expires_at', clock_timestamp() + interval '59 minutes')), 'ok', 'M2: ... an ADMIN session of 59 minutes is accepted ...');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-4000000000d0', :'c_ad', jsonb_build_object('expires_at', clock_timestamp() + interval '1 hour 2 minutes')), '23514', 'M2: ... and 1 h 2 min is refused (admin ceiling 1 h)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('created_at', clock_timestamp() - interval '1 day', 'expires_at', clock_timestamp() + interval '1 hour')), '23514', 'M2: a back-dated created_at is refused (the clock is the database''s)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('last_seen_at', clock_timestamp() + interval '1 day')), '23514', 'M2: ... and a last_seen_at a day in the future (it would extend the idle window)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('last_seen_at', clock_timestamp() - interval '1 day')), '23514', 'M2: ... or in the past');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('enrolment_until', clock_timestamp() + interval '10 minutes')), '23514', 'M2: an enrolment window on a SIGN-IN mint is refused (it belongs to a register mint)');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('mint_kind', 'register', 'mint_signature', NULL, 'enrolment_until', clock_timestamp() + interval '10 minutes')), 'ok', 'M2: ... a REGISTER mint with a 10-minute enrolment window is accepted ...');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('mint_kind', 'register', 'mint_signature', NULL, 'enrolment_until', clock_timestamp() + interval '16 minutes')), '23514', 'M2: ... and 16 minutes is refused (at most 15)');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', '{}'::jsonb), 'ok', 'M2 control: the issuer inserts a well-formed credential');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', jsonb_build_object('revoked_at', clock_timestamp())), '23514', 'M2: a credential is born LIVE: a revoked one is refused');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', jsonb_build_object('revoked_by', '00000000-0000-0000-0000-2000000000b1'::uuid)), '23514', 'M2: ... with a revoked_by: refused');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', '{"revoke_reason": "x"}'::jsonb), '23514', 'M2: ... with a revoke reason: refused');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', jsonb_build_object('last_used_at', clock_timestamp())), '23514', 'M2: ... already used: refused');
SELECT is(pg_temp.try_ins_cred('00000000-0000-0000-0000-1000000000a1', jsonb_build_object('created_at', clock_timestamp() - interval '1 year')), '23514', 'M2: ... back-dated: refused');
SELECT is(pg_temp.try_ins_session('00000000-0000-0000-0000-1000000000a1', :'c_sx', jsonb_build_object('aal', 2, 'expires_at', clock_timestamp() + interval '10 years', 'pin_grant_until', clock_timestamp() + interval '1 day',
          'reauth_until', clock_timestamp() + interval '1 day', 'mfa_until', clock_timestamp() + interval '1 day')), '23514', 'M2: the gate''s own insert (aal 2, 10 years, 1-day PIN / reauth / mfa windows) is refused');
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;

-- ============================================================================
-- S1.1a gate M3 / L1: partner_sessions_revoke (R5-L2) had NO test; the member trigger's column list and its re-point branch; authorize's re-reads
-- ============================================================================
-- fresh, live fixtures for these cells (the guard cells above revoked s_sx)
CREATE FUNCTION pg_temp.live_count(p_uid uuid) RETURNS int LANGUAGE sql AS $f$ SELECT count(*)::int FROM app.partner_session WHERE user_id = p_uid AND revoked_at IS NULL $f$;
GRANT EXECUTE ON FUNCTION pg_temp.live_count(uuid) TO PUBLIC;
CREATE FUNCTION pg_temp.audit_rows(p_action text, p_subject text) RETURNS jsonb LANGUAGE sql AS $f$
  SELECT coalesce(jsonb_agg(jsonb_build_object('table', a.subject_table, 'actor', a.actor_user_id, 'detail', a.detail) ORDER BY a.created_at), '[]'::jsonb) FROM app.audit_log a WHERE a.action = p_action AND a.subject_id = p_subject
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.audit_rows(text, text) TO PUBLIC;
-- who may call it
SELECT is(has_function_privilege('private_definer', 'private.partner_sessions_revoke(text, uuid, text)', 'EXECUTE'), true, 'R5-L2: private_definer may EXECUTE partner_sessions_revoke ...');
SELECT is((SELECT array_agg(r ORDER BY r) FROM unnest(ARRAY['edge_actor', 'edge_partner', 'edge_partner_minter', 'partner_session_issuer', 'partner_pin_verifier', 'anon', 'authenticated', 'service_role']) r
           WHERE has_function_privilege(r, 'private.partner_sessions_revoke(text, uuid, text)', 'EXECUTE')), NULL::text[], 'R5-L2: ... and no edge role, owner role or API role can');
SELECT is((SELECT count(*)::int FROM pg_proc p, aclexplode(p.proacl) a WHERE p.oid = 'private.partner_sessions_revoke(text, uuid, text)'::regprocedure AND a.grantee = 0), 0, 'R5-L2: ... and not PUBLIC');
-- the USER subject
SAVEPOINT g_rev_user;
SELECT pg_temp.mk_cred('g_ra', '00000000-0000-0000-0000-1000000000a1') AS g_ca \gset
SELECT pg_temp.mk_session('g_r1', '00000000-0000-0000-0000-1000000000a1', :'g_ca') AS g_s1 \gset
SELECT pg_temp.mk_session('g_r2', '00000000-0000-0000-0000-1000000000a1', :'g_ca') AS g_s2 \gset
SELECT pg_temp.mk_session('g_r3', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS g_s3 \gset
SELECT pg_temp.live_count('00000000-0000-0000-0000-1000000000a1') AS g_before \gset
SET LOCAL ROLE private_definer;
SELECT private.partner_sessions_revoke('user', '00000000-0000-0000-0000-1000000000a1', 'zz_user') AS g_n \gset
RESET ROLE;
SELECT is(:g_n::int, :g_before::int, 'R5-L2 user: the call returns the number of live sessions it revoked (all of the user''s)');
SELECT is(pg_temp.live_count('00000000-0000-0000-0000-1000000000a1'), 0, 'R5-L2 user: ... and the user has none left');
SELECT is((SELECT revoke_reason FROM app.partner_session WHERE id = :'g_s1'::uuid), 'zz_user', 'R5-L2 user: ... with the reason given');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'g_s3'::uuid), true, 'R5-L2 user: ... and another user''s session is untouched');
SET LOCAL ROLE service_role;
SELECT pg_temp.audit_rows('partner.sessions_revoke', '00000000-0000-0000-0000-1000000000a1') AS g_aud \gset
RESET ROLE;
SELECT is(jsonb_array_length(:'g_aud'::jsonb), 1, 'R5-L2 user: exactly ONE audit_log row per call');
SELECT is((:'g_aud'::jsonb -> 0) ->> 'table', 'auth.users', 'R5-L2 user: ... naming the SUBJECT''s own table (auth.users, not app.partner_session)');
SELECT is(((:'g_aud'::jsonb -> 0) -> 'detail') ->> 'kind', 'user', 'R5-L2 user: ... the subject kind');
SELECT is((((:'g_aud'::jsonb -> 0) -> 'detail') ->> 'revoked')::int, :g_n::int, 'R5-L2 user: ... and how many sessions died');
SELECT is(((:'g_aud'::jsonb -> 0) -> 'detail') ->> 'reason', 'zz_user', 'R5-L2 user: ... and the reason');
ROLLBACK TO SAVEPOINT g_rev_user;
-- the ORG subject: active members only (S1.1a gate L1)
SAVEPOINT g_rev_org;
SET LOCAL ROLE service_role;
INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('00000000-0000-0000-0000-2000000000b2', '10000000-0000-0000-0000-000000000002', 'staff');
RESET ROLE;
SELECT pg_temp.mk_session('g_r4', '00000000-0000-0000-0000-2000000000b2', :'c_mxr') AS g_s4 \gset
SELECT pg_temp.mk_session('g_r5', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS g_s5 \gset
SELECT pg_temp.mk_session('g_r6', '00000000-0000-0000-0000-3000000000c1', :'c_op') AS g_s6 \gset
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'g_s4'::uuid), true, 'L1 precondition: manager_x_revoked is REVOKED in org 1 (helpers) and ACTIVE in org 2 (just added), with a live session');
SELECT (SELECT count(*)::int FROM app.partner_session s WHERE s.revoked_at IS NULL AND s.user_id IN (SELECT m.user_id FROM app.partner_member m WHERE m.org_id = '10000000-0000-0000-0000-000000000001' AND m.revoked_at IS NULL)) AS g_exp \gset
SET LOCAL ROLE private_definer;
SELECT private.partner_sessions_revoke('org', '10000000-0000-0000-0000-000000000001', 'zz_org') AS g_n \gset
RESET ROLE;
SELECT is(:g_n::int, :g_exp::int, 'R5-L2 org: the call revokes the live sessions of the org''s ACTIVE members, and only those (the count the catalog predicts)');
SELECT is((SELECT revoked_at IS NOT NULL AND revoke_reason = 'zz_org' FROM app.partner_session WHERE id = :'g_s5'::uuid), true, 'R5-L2 org: an active member of the org (manager_x) lost his session');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'g_s4'::uuid), true, 'L1: a REVOKED member of org 1 who is ACTIVE in org 2 keeps his session there (the org revoke no longer reaches former members)');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'g_s6'::uuid), true, 'R5-L2 org: a member of ANOTHER org (the operator) is untouched');
SET LOCAL ROLE service_role;
SELECT pg_temp.audit_rows('partner.sessions_revoke', '10000000-0000-0000-0000-000000000001') AS g_aud \gset
RESET ROLE;
SELECT is((:'g_aud'::jsonb -> 0) ->> 'table', 'app.partner_org', 'R5-L2 org: the audit row names app.partner_org and the org id');
SELECT is(((:'g_aud'::jsonb -> 0) -> 'detail') ->> 'kind', 'org', 'R5-L2 org: ... kind org');
ROLLBACK TO SAVEPOINT g_rev_org;
-- the CREDENTIAL subject: that credential's sessions, not the user's
SAVEPOINT g_rev_cred;
SELECT pg_temp.mk_cred('g_rb', '00000000-0000-0000-0000-1000000000a1') AS g_cb \gset
SELECT pg_temp.mk_session('g_r7', '00000000-0000-0000-0000-1000000000a1', :'g_cb') AS g_s7 \gset
SELECT pg_temp.mk_session('g_r8', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s8 \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx_pin');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT private.partner_sessions_revoke('credential', :'g_cb'::uuid, 'zz_cred') AS g_n \gset
RESET ROLE;
SELECT is(:g_n::int, 1, 'R5-L2 credential: exactly the sessions of THAT credential die (1)');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'g_s7'::uuid), true, 'R5-L2 credential: ... the session minted by it');
SELECT is((SELECT revoked_at IS NULL FROM app.partner_session WHERE id = :'g_s8'::uuid), true, 'R5-L2 credential: ... and the same user''s session under ANOTHER credential is untouched (it revokes by credential, not by user)');
SET LOCAL ROLE service_role;
SELECT pg_temp.audit_rows('partner.sessions_revoke', :'g_cb') AS g_aud \gset
RESET ROLE;
SELECT is((:'g_aud'::jsonb -> 0) ->> 'table', 'app.partner_credential', 'R5-L2 credential: the audit row names app.partner_credential');
SELECT is((:'g_aud'::jsonb -> 0) ->> 'actor', '00000000-0000-0000-0000-1000000000a1', 'R5-L2: the audit row carries the CALLER''s binding (the partner-bound staff_x)');
ROLLBACK TO SAVEPOINT g_rev_cred;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.partner_sessions_revoke('team', gen_random_uuid(), 'zz_reason')$$, '22023', NULL, 'R5-L2: an unknown subject kind is refused');
SELECT throws_ok($$SELECT private.partner_sessions_revoke('user', NULL, 'zz_reason')$$, '22023', NULL, 'R5-L2: a NULL subject id is refused');
SELECT throws_ok($$SELECT private.partner_sessions_revoke('user', gen_random_uuid(), 'Not A Reason')$$, '22023', NULL, 'R5-L2: a reason that is not a short snake_case token is refused');
SELECT throws_ok($$SELECT private.partner_sessions_revoke('user', gen_random_uuid(), NULL)$$, '22023', NULL, 'R5-L2: a NULL reason is refused');
RESET ROLE;

-- the member trigger: a ROLE change and a RE-POINT of user_id both kill sessions (the column list and the OLD uid)
SAVEPOINT g_t_role;
SELECT pg_temp.mk_session('g_t1', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s1 \gset
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET role = 'manager' WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL AND revoke_reason = 'authority_changed' FROM app.partner_session WHERE id = :'g_s1'::uuid), true, 'M3: a ROLE change (staff to manager) of a membership revokes the member''s sessions (the trigger fires on UPDATE OF role)');
ROLLBACK TO SAVEPOINT g_t_role;
SAVEPOINT g_t_repoint;
SELECT pg_temp.mk_session('g_t2', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s1 \gset
SELECT pg_temp.mk_session('g_t3', '00000000-0000-0000-0000-00000000000b', :'c_pb') AS g_s2 \gset
SET LOCAL ROLE service_role;
UPDATE app.partner_member SET user_id = '00000000-0000-0000-0000-00000000000b' WHERE user_id = '00000000-0000-0000-0000-1000000000a1' AND org_id = '10000000-0000-0000-0000-000000000001';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'g_s1'::uuid), true, 'M3: RE-POINTING a membership to another user revokes the OLD user''s sessions (the OLD uid is not ignored)');
SELECT is((SELECT revoked_at IS NOT NULL FROM app.partner_session WHERE id = :'g_s2'::uuid), true, 'M3: ... and the NEW user''s too (a new membership is new authority)');
ROLLBACK TO SAVEPOINT g_t_repoint;

-- ============================================================================
-- S1.1a gate L6: admin_user UPDATE and TRUNCATE (service_role holds UPDATE; TRUNCATE fires no row trigger)
-- ============================================================================
SAVEPOINT g_t_adm;
SELECT pg_temp.mk_session('g_t4', '00000000-0000-0000-0000-4000000000d0', :'c_ad', interval '0', interval '1 hour', 2) AS g_s1 \gset
SET LOCAL ROLE service_role;
UPDATE app.admin_user SET user_id = '00000000-0000-0000-0000-00000000000b' WHERE user_id = '00000000-0000-0000-0000-4000000000d0';
RESET ROLE;
SELECT is((SELECT revoked_at IS NOT NULL AND revoke_reason = 'authority_changed' FROM app.partner_session WHERE id = :'g_s1'::uuid), true, 'L6: an UPDATE of an admin_user row (re-pointing the admin) revokes the old admin''s sessions');
ROLLBACK TO SAVEPOINT g_t_adm;
SAVEPOINT g_t_tr1;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT pg_temp.live_count('00000000-0000-0000-0000-4000000000d0') AS g_live0 \gset
TRUNCATE app.admin_user;
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE revoked_at IS NULL), 0, 'L6: TRUNCATE app.admin_user revokes EVERY live session (a statement trigger: no row trigger fires on TRUNCATE)');
ROLLBACK TO SAVEPOINT g_t_tr1;
SAVEPOINT g_t_tr2;
SET CONSTRAINTS ALL IMMEDIATE;
TRUNCATE app.partner_member CASCADE;
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE revoked_at IS NULL), 0, 'L6: TRUNCATE app.partner_member (CASCADE) revokes every live session');
ROLLBACK TO SAVEPOINT g_t_tr2;
SAVEPOINT g_t_tr3;
SET CONSTRAINTS ALL IMMEDIATE;
TRUNCATE app.partner_scope CASCADE;
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE revoked_at IS NULL), 0, 'L6: TRUNCATE app.partner_scope (CASCADE) revokes every live session');
ROLLBACK TO SAVEPOINT g_t_tr3;

-- ============================================================================
-- authorize re-reads that were proven only at BIND (S1.1a gate M3 / NIT): a session that goes revoked, idle, expired or demo AFTER the bind
-- ============================================================================
SAVEPOINT g_az_rev;
SELECT pg_temp.mk_session('g_az1', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s1 \gset
SELECT pg_temp.th('g_az1') AS g_th \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'g_th');
SELECT is(private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'authorize re-read: control: the freshly bound session is authorised');
RESET ROLE;
UPDATE app.partner_session SET revoked_at = clock_timestamp(), revoke_reason = 'zz' WHERE id = :'g_s1'::uuid;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the session is not live', 'M3: a session REVOKED in the SAME transaction after the bind is refused by the very next authorize (the revoked_at re-check is its own line of defence)');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_az_rev;
SAVEPOINT g_az_idle;
SELECT pg_temp.mk_session('g_az2', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s1 \gset
SELECT pg_temp.th('g_az2') AS g_th \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'g_th');
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
UPDATE app.partner_session SET last_seen_at = clock_timestamp() - interval '31 minutes' WHERE id = :'g_s1'::uuid;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the session is not live', 'NIT: a session that goes IDLE (31 minutes, staff limit 30) after the bind is refused at authorize (the idle rule is not only the binder''s)');
RESET ROLE;
UPDATE app.partner_session SET last_seen_at = clock_timestamp(), expires_at = clock_timestamp() - interval '1 second' WHERE id = :'g_s1'::uuid;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the session is not live', 'NIT: ... and one that passes its ABSOLUTE expiry');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_az_idle;
SAVEPOINT g_az_demo;
SELECT pg_temp.mk_session('g_az3', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS g_s1 \gset
SELECT pg_temp.th('g_az3') AS g_th \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'g_th');
RESET ROLE;
SET LOCAL ROLE service_role;
INSERT INTO app.app_review_demo_account (user_id) VALUES ('00000000-0000-0000-0000-1000000000a1');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.zz24_authz_for_partner('fac_x', NULL, ARRAY['staff'], 'A0')$$, '42501', 'partner_authorize: the member holds no active partner role', 'NIT: an account that becomes the app-review DEMO account after the bind is refused at authorize (the demo rule is not only the binder''s)');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_az_demo;

-- ============================================================================
-- S1.1a gate L5: the PEEK class (GET session: a live session, no scope, no aal gate, and it must NOT advance last_seen_at)
-- ============================================================================
SAVEPOINT g_peek;
SELECT pg_temp.mk_session('g_pk1', '00000000-0000-0000-0000-1000000000a1', :'c_sx', interval '5 minutes') AS g_s1 \gset
SELECT pg_temp.th('g_pk1') AS g_th \gset
SELECT last_seen_at AS g_ls0 FROM app.partner_session WHERE id = :'g_s1' \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'g_th');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, NULL, 'PEEK'), '00000000-0000-0000-0000-1000000000a1'::uuid, 'L5: PEEK needs a live session and nothing else (no scope, no role list)');
RESET ROLE;
SELECT is((SELECT last_seen_at = :'g_ls0'::timestamptz FROM app.partner_session WHERE id = :'g_s1'), true, 'L5: ... and did NOT advance last_seen_at (reading one''s own session does not keep it alive: 4.2)');
SET LOCAL ROLE edge_partner;
SELECT private.zz24_authz_for_partner(NULL, NULL, NULL, 'SESSION') AS _x \gset
RESET ROLE;
SELECT is((SELECT last_seen_at > :'g_ls0'::timestamptz FROM app.partner_session WHERE id = :'g_s1'), true, 'L5 control: the SESSION class (sign-out, lock) DOES advance it, so the cell above is the class');
ROLLBACK TO SAVEPOINT g_peek;
SAVEPOINT g_peek2;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op1');
SELECT is(private.zz24_authz_for_partner(NULL, NULL, NULL, 'PEEK'), '00000000-0000-0000-0000-3000000000c1'::uuid, 'L5: PEEK has no aal gate: an aal 1 operator session can read itself (GET session reports the required assurance)');
SELECT throws_ok($$SELECT private.zz24_authz_for_partner(NULL, 'trl_t', ARRAY['operator'], 'A0')$$, '42501', 'partner_authorize: the session''s assurance level is below the member''s required level', 'L5: ... and the same session is refused a real class (control)');
RESET ROLE;
ROLLBACK TO SAVEPOINT g_peek2;

-- ============================================================================
-- S1.1a gate L7: authenticated keeps SELECT on the masked offer columns only
-- ============================================================================
SELECT is((SELECT array_agg(c ORDER BY c) FROM unnest(ARRAY['budget_cap', 'budget_used', 'budget_reserved', 'eligibility', 'max_redemptions']) c WHERE has_column_privilege('authenticated', 'app.offer', c, 'SELECT')), NULL::text[], 'L7: authenticated has NO SELECT on the five budget / eligibility columns of app.offer');
SELECT is(has_table_privilege('authenticated', 'app.offer', 'SELECT'), false, 'L7: ... and no whole-table SELECT');
SELECT is((SELECT array_agg(c ORDER BY c) FROM unnest(ARRAY['id', 'terms_id', 'trail_id', 'facility_id', 'funder', 'sponsorship_id', 'valid_from', 'valid_to', 'status']) c WHERE NOT has_column_privilege('authenticated', 'app.offer', c, 'SELECT')), NULL::text[], 'L7: ... but keeps the nine columns the masked api.offer view reads');
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000b'::uuid));
SELECT lives_ok($$SELECT id, status FROM api.offer$$, 'L7: the masked api.offer view still answers for a player (it reads only the granted columns)');
SELECT lives_ok($$SELECT * FROM api.my_offers()$$, 'L7: ... and api.my_offers()');
SELECT throws_ok($$SELECT budget_cap FROM app.offer$$, '42501', NULL, 'L7: ... while a direct read of app.offer.budget_cap is refused');
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
