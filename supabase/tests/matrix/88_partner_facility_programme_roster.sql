-- 88_partner_facility_programme_roster.sql
-- P5 section 140 (0110): the programme editor refuses a facility that is not on the trail's CURRENT roster (the owner's decision A on the section 138 finding). Before 0110
-- partner_facility_programme_upsert_for_partner wrote a facility_programme row for ANY facility, and private.has_facility_scope lets an operator reach any facility for which such a row exists for
-- a trail it operates, so an operator could write itself reach to a facility that has nothing to do with its trail (138.1 / 138.4).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 / 36 / 37 / 87 pattern), with matrix 37's principals: staff_x (a1), manager_x (b1), operator_t (c1, scoped to trl_t only), admin (d0). The
-- catalogue (facilities, courses, holes, trails, roster versions and members, programme rows) is planted by the OWNER as service_role. Every refusal is read back by a helper that catches it, so the transaction
-- survives and the SQLSTATE AND the message are both asserted (22023 is also the code of the argument-shape refusal, so the code alone cannot tell the two apart). Authority cells sit in SAVEPOINTs (a
-- second bind in one transaction is itself refused); the admin's scenario cells sit in one SAVEPOINT; the operator binds once for the main body.
--
--   A  the function and what registers it                                  B  what private_definer may now read, and what it may not
--   C  staff and manager are refused first (42501, never 22023)             D  the admin is held to the same rule: the four roster legs, and every way to be OFF the roster
--   E  the owner's off-roster query agrees with the definer, row by row    F  the operator: the 138.4 reproduction, the four legs as a positive control, and the negatives

\set QUIET 1
BEGIN;
SELECT plan(98);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.trail_programme, app.facility_programme, app.partner_org TO CURRENT_USER;
GRANT SELECT ON app.audit_log, app.partner_invite TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz88_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_tp ON app.trail_programme FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_fp ON app.facility_programme FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_po ON app.partner_org FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz88_pi ON app.partner_invite FOR SELECT TO CURRENT_USER USING (true);

\set m_roster 'ERR 22023 partner_facility_programme_upsert_for_partner: the facility must be on the current roster of this trail'
\set m_shape 'ERR 22023 partner_facility_programme_upsert_for_partner: a trail, a facility, participation and qr_mode are required'
\set m_scope 'ERR 42501 partner_authorize: no scope'

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s88:' || p_label) || md5('s88b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c88:' || p_label) || md5('c88b:' || p_label), 'hex'), decode(md5('k88:' || p_label) || md5('k88b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n88:' || p_label) || md5('n88b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    reauth_until = CASE WHEN p_cols ? 'reauth_s' THEN clock_timestamp() + ((p_cols ->> 'reauth_s')::numeric * interval '1 second') ELSE s.reauth_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;

-- the facility programme upsert as the BOUND member: the status ('ok' | 'no_trail'), or 'ERR <sqlstate> <message>' (the refusal rolls back to the block, so a refused call has written nothing)
CREATE FUNCTION pg_temp.fp_try(p_label text, p_trail text, p_fac text, p_part text DEFAULT 'accepted', p_qr text DEFAULT 'rotating') RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_facility_programme_upsert_for_partner(p_trail, p_fac, p_part, true, false, 'ok', true, NULL, p_qr);
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE || ' ' || SQLERRM;
  END;
END
$f$;
-- an invite at a facility organisation, as the bound member (the role is an unknown-typed literal: edge_partner has no USAGE on schema app, so a ::app.partner_role cast in the caller is 42501)
CREATE FUNCTION pg_temp.inv(p_label text, p_org uuid, p_role text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2, "reauth_s": 240}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    EXECUTE format('SELECT * FROM private.partner_invite_create_for_partner(%L::uuid, %L, %L, %L)', p_org, p_role, 'invitee@example.test', repeat('ab', 32)) INTO r;
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE || ' ' || SQLERRM;
  END;
END
$f$;
-- has_facility_scope(operator_t, facility, {operator}): the reach the invite, PIN-reset and credential rules read
CREATE FUNCTION pg_temp.reach(p_fac text) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE b boolean;
BEGIN
  EXECUTE 'SET LOCAL ROLE service_role';
  SELECT private.has_facility_scope('00000000-0000-0000-0000-3000000000c1', p_fac, ARRAY['operator']::app.partner_role[]) INTO b;
  EXECUTE 'RESET ROLE';
  RETURN b;
END
$f$;
-- a SELECT under private_definer (with whatever binding the caller has made), returning the text of its result or 'ERR <sqlstate>'
CREATE FUNCTION pg_temp.as_definer(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE t text;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  BEGIN
    EXECUTE p_sql INTO t;
    EXECUTE 'RESET ROLE';
    RETURN t;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx', 2) AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx', 2) AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

-- ----------------------------------------------------------------------------
-- The catalogue. Every facility has courses of its own; holes only where a hole leg needs one.
--   fac_z   the 138.4 facility: on NO roster of any trail; its organisation exists (the invite target)       fac_ra  named as a FACILITY member
--   fac_rb  named through a COURSE member           fac_rc  named through a HOLE member that carries NO course_id (so the hole leg stands alone)
--   fac_rd  named through an any_of_course_ids member         fac_re  named through a hole member written the way the importer writes it (course_id AND hole_id)
--   fac_rf  a facility that exists and is on no roster          fac_rg  on an OLDER roster version only        fac_rh  on the LATEST version only
--   fac_rj  on ANOTHER trail's roster only          fac_rk / fac_rl  two unrelated facilities, one named by a roster and one not          fac_rm / fac_rn  named by a removed member (rn also by a current one)
-- ----------------------------------------------------------------------------
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES
  ('fac_z', 'facility', 'verified', 1), ('fac_ra', 'facility', 'verified', 1), ('fac_rb', 'facility', 'verified', 1), ('fac_rc', 'facility', 'verified', 1), ('fac_rd', 'facility', 'verified', 1),
  ('fac_re', 'facility', 'verified', 1), ('fac_rf', 'facility', 'verified', 1), ('fac_rg', 'facility', 'verified', 1), ('fac_rh', 'facility', 'verified', 1), ('fac_rj', 'facility', 'verified', 1),
  ('fac_rk', 'facility', 'verified', 1), ('fac_rl', 'facility', 'verified', 1), ('fac_rm', 'facility', 'verified', 1), ('fac_rn', 'facility', 'verified', 1),
  ('crs_z1', 'course', 'verified', 1), ('crs_z2', 'course', 'verified', 1), ('crs_ra1', 'course', 'verified', 1), ('crs_rb1', 'course', 'verified', 1), ('crs_rc1', 'course', 'verified', 1),
  ('crs_rd1', 'course', 'verified', 1), ('crs_rd2', 'course', 'verified', 1), ('crs_re1', 'course', 'verified', 1), ('crs_rf1', 'course', 'verified', 1), ('crs_rg1', 'course', 'verified', 1),
  ('crs_rh1', 'course', 'verified', 1), ('crs_rj1', 'course', 'verified', 1), ('crs_rk1', 'course', 'verified', 1), ('crs_rk2', 'course', 'verified', 1), ('crs_rk3', 'course', 'verified', 1),
  ('crs_rl1', 'course', 'verified', 1), ('crs_rm1', 'course', 'verified', 1), ('crs_rn1', 'course', 'verified', 1),
  ('hol_z1', 'hole', 'verified', 1), ('hol_rc1', 'hole', 'verified', 1), ('hol_re1', 'hole', 'verified', 1), ('hol_rk1', 'hole', 'verified', 1),
  ('trl_88a', 'trail', 'verified', 1), ('trl_88b', 'trail', 'verified', 1), ('trl_88c', 'trail', 'verified', 1), ('trl_88c2', 'trail', 'verified', 1), ('trl_88d', 'trail', 'verified', 1),
  ('trl_88e', 'trail', 'verified', 1), ('trl_88f', 'trail', 'verified', 1), ('trl_88g', 'trail', 'verified', 1), ('trl_88h', 'trail', 'verified', 1), ('trl_88i', 'trail', 'verified', 1),
  ('trl_88k', 'trail', 'verified', 1), ('trl_88n', 'trail', 'verified', 1);
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version)
SELECT f, replace(f, '_', '-'), 'Facility ' || f, 'US-TN', 'America/Chicago', 1
FROM unnest(ARRAY['fac_z', 'fac_ra', 'fac_rb', 'fac_rc', 'fac_rd', 'fac_re', 'fac_rf', 'fac_rg', 'fac_rh', 'fac_rj', 'fac_rk', 'fac_rl', 'fac_rm', 'fac_rn']) AS f;
INSERT INTO app.catalog_course (id, facility_id, name, catalog_version) VALUES
  ('crs_z1', 'fac_z', 'Z1', 1), ('crs_z2', 'fac_z', 'Z2', 1), ('crs_ra1', 'fac_ra', 'RA1', 1), ('crs_rb1', 'fac_rb', 'RB1', 1), ('crs_rc1', 'fac_rc', 'RC1', 1), ('crs_rd1', 'fac_rd', 'RD1', 1),
  ('crs_rd2', 'fac_rd', 'RD2', 1), ('crs_re1', 'fac_re', 'RE1', 1), ('crs_rf1', 'fac_rf', 'RF1', 1), ('crs_rg1', 'fac_rg', 'RG1', 1), ('crs_rh1', 'fac_rh', 'RH1', 1), ('crs_rj1', 'fac_rj', 'RJ1', 1),
  ('crs_rk1', 'fac_rk', 'RK1', 1), ('crs_rk2', 'fac_rk', 'RK2', 1), ('crs_rk3', 'fac_rk', 'RK3', 1), ('crs_rl1', 'fac_rl', 'RL1', 1), ('crs_rm1', 'fac_rm', 'RM1', 1), ('crs_rn1', 'fac_rn', 'RN1', 1);
INSERT INTO app.catalog_hole (id, course_id, number, catalog_version) VALUES
  ('hol_z1', 'crs_z1', 1, 1), ('hol_rc1', 'crs_rc1', 1, 1), ('hol_re1', 'crs_re1', 1, 1), ('hol_rk1', 'crs_rk1', 1, 1);
INSERT INTO app.catalog_trail (id, slug, name, catalog_version)
SELECT t, replace(t, '_', '-'), 'Trail ' || t, 1
FROM unnest(ARRAY['trl_88a', 'trl_88b', 'trl_88c', 'trl_88c2', 'trl_88d', 'trl_88e', 'trl_88f', 'trl_88g', 'trl_88h', 'trl_88i', 'trl_88k', 'trl_88n']) AS t;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from)
SELECT t, v, 'facility', 'facility', now()
FROM (VALUES ('trl_88a', 1), ('trl_88b', 1), ('trl_88c', 1), ('trl_88c2', 1), ('trl_88d', 1), ('trl_88e', 1), ('trl_88f', 1), ('trl_88f', 2), ('trl_88g', 1), ('trl_88g', 2), ('trl_88h', 1), ('trl_88k', 1)) AS x(t, v);
--   trl_88i has a programme and NO roster version at all; trl_88n has neither a programme nor a roster; trl_88g's LATEST version (2) has no members
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, course_id, any_of_course_ids, facility_id, hole_id, stop_order, removed_on) VALUES
  ('trl_88a', 1, 'facility', NULL, NULL, 'fac_ra', NULL, 1, NULL),
  ('trl_88b', 1, 'course',   'crs_rb1', NULL, NULL, NULL, 1, NULL),
  ('trl_88c', 1, 'hole',     NULL, NULL, NULL, 'hol_rc1', 1, NULL),
  ('trl_88c2', 1, 'hole',    'crs_re1', NULL, NULL, 'hol_re1', 1, NULL),
  ('trl_88d', 1, 'course',   NULL, ARRAY['crs_rd1', 'crs_rd2'], NULL, NULL, 1, NULL),
  ('trl_88e', 1, 'facility', NULL, NULL, 'fac_rm', NULL, 1, current_date - 1),
  ('trl_88e', 1, 'facility', NULL, NULL, 'fac_rn', NULL, 2, current_date - 1),
  ('trl_88e', 1, 'course',   'crs_rn1', NULL, NULL, NULL, 3, NULL),
  ('trl_88f', 1, 'facility', NULL, NULL, 'fac_rg', NULL, 1, NULL),
  ('trl_88f', 2, 'facility', NULL, NULL, 'fac_rh', NULL, 1, NULL),
  ('trl_88g', 1, 'facility', NULL, NULL, 'fac_rg', NULL, 1, NULL),
  ('trl_88h', 1, 'facility', NULL, NULL, 'fac_rj', NULL, 1, NULL),
  ('trl_88k', 1, 'hole',     NULL, NULL, NULL, 'hol_rk1', 1, NULL),
  ('trl_88k', 1, 'course',   'crs_rk2', NULL, NULL, NULL, 2, NULL),
  ('trl_88k', 1, 'course',   NULL, ARRAY['crs_rk3'], NULL, NULL, 3, NULL);
-- trl_u (helpers.sql) has no programme and no roster here: the admin's no-programme cells use it
INSERT INTO app.trail_programme (trail_id, status)
SELECT t, 'live' FROM unnest(ARRAY['trl_88a', 'trl_88b', 'trl_88c', 'trl_88c2', 'trl_88d', 'trl_88e', 'trl_88f', 'trl_88g', 'trl_88h', 'trl_88i', 'trl_88k']) AS t;
-- the facility organisation at fac_z: the invite target of the 138.4 reproduction
INSERT INTO app.partner_org (id, kind, name) VALUES ('10000000-0000-0000-0000-00000000887a', 'facility', 'Facility Z Pro Shop');
INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('10000000-0000-0000-0000-00000000887a', 'fac_z');
-- programme rows the OWNER writes directly (as rows written before 0110 would exist): for every scenario, one on the roster and one off it. They are what the off-roster query is run over (section E).
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES
  ('trl_88a', 'fac_ra', 'accepted'), ('trl_88a', 'fac_z', 'accepted'), ('trl_88a', 'fac_rj', 'invited'),
  ('trl_88b', 'fac_rb', 'accepted'), ('trl_88b', 'fac_ra', 'accepted'),
  ('trl_88c', 'fac_rc', 'accepted'), ('trl_88c2', 'fac_re', 'accepted'), ('trl_88d', 'fac_rd', 'accepted'),
  ('trl_88e', 'fac_rm', 'accepted'), ('trl_88e', 'fac_rn', 'accepted'),
  ('trl_88f', 'fac_rg', 'accepted'), ('trl_88f', 'fac_rh', 'accepted'), ('trl_88g', 'fac_rg', 'declined'),
  ('trl_88h', 'fac_rj', 'accepted'), ('trl_88i', 'fac_x', 'accepted'),
  ('trl_88k', 'fac_rk', 'accepted'), ('trl_88k', 'fac_rl', 'left');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- A. The function and what registers it  (11)
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE'), 'the programme editor is still edge_partner''s');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM unnest(ARRAY['anon', 'authenticated', 'service_role', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter', 'edge_gateway']) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE')),
  ARRAY['edge_partner'], 'and nobody else may execute it (no grant was added)');
SELECT is((SELECT pg_get_userbyid(proowner) || '/' || prosecdef::text || '/' || provolatile::text || '/' || coalesce(array_to_string(proconfig, ','), '')
           FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure),
  'private_definer/true/v/search_path=""', 'owner private_definer, SECURITY DEFINER, VOLATILE, search_path = '''' (CREATE OR REPLACE kept them)');
SELECT is((SELECT pg_get_function_result(oid) FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure),
  'TABLE(o_status text)', 'the return shape is unchanged: one o_status column');
SELECT ok((SELECT position('v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY[''operator'']::app.partner_role[], ''A3'');' IN prosrc) > 0
              AND position('v_uid := private.partner_authorize(' IN prosrc) < position('catalog_roster_member' IN prosrc)
              AND position('catalog_roster_member' IN prosrc) < position('INSERT INTO app.facility_programme' IN prosrc)
              AND position('no_trail' IN prosrc) < position('catalog_roster_member' IN prosrc)
           FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure),
  'the leading partner_authorize call (check 14) is still first; the roster check comes after no_trail and BEFORE the write');
SELECT ok((SELECT obj_description(oid, 'pg_proc') LIKE '0059/0110 (S6, section 140)%22023%' FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure),
  'the function comment says 0110 and the refusal');
SET LOCAL ROLE service_role;
SELECT is((SELECT note FROM private.function_inventory WHERE function_name = 'partner_facility_programme_upsert_for_partner'),
  '0059/0110 (S6, section 140): edge_partner only; class A3; facility_programme upsert; the facility must be on the trail''s current roster (22023)', 'the function_inventory note says 0110');
SELECT ok((SELECT expected_edge_partner AND NOT expected_anon AND NOT expected_authenticated AND NOT expected_service_role AND NOT expected_edge_actor AND NOT expected_edge_system
           FROM private.function_inventory WHERE function_name = 'partner_facility_programme_upsert_for_partner'), 'and its registered EXECUTE set is still edge_partner alone');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist
           WHERE policy_name IN ('pd_partner_roster_read_member', 'pd_partner_roster_read_version', 'pd_partner_roster_read_course', 'pd_partner_roster_read_hole')
             AND role_name = 'private_definer' AND command = 'SELECT' AND scoped AND using_expr LIKE '%partner_binding_kind%' AND using_expr NOT LIKE '%current_setting%' AND with_check_expr IS NULL), 4,
  'the four new private_definer policies are registered in definer_policy_allowlist: SELECT, scoped, keyed on the partner binding, none on a setting');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd\_partner\_roster\_read\_%' AND pol.polcmd = 'r' AND pol.polpermissive
             AND pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'private_definer')]), 4, 'the four policies are permissive SELECT policies for private_definer alone');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd\_partner\_roster\_read\_%'
             AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'current_setting|pg_settings'), 0,
  'no new policy reads a setting: no GUC window (the hard rule)');

-- ----------------------------------------------------------------------------
-- B. What private_definer may now read, and what it may not  (17)
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_attribute a
           WHERE a.attrelid IN ('app.catalog_roster_member'::regclass, 'app.catalog_roster_version'::regclass, 'app.catalog_course'::regclass, 'app.catalog_hole'::regclass)
             AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'SELECT')), 13, 'private_definer holds column-level SELECT on exactly 13 columns of the four tables');
SELECT is((SELECT array_agg(c.relname || '.' || a.attname ORDER BY c.relname, a.attname) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
           WHERE c.oid IN ('app.catalog_roster_member'::regclass, 'app.catalog_roster_version'::regclass, 'app.catalog_course'::regclass, 'app.catalog_hole'::regclass)
             AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'SELECT')),
  ARRAY['catalog_course.facility_id', 'catalog_course.id', 'catalog_hole.course_id', 'catalog_hole.id', 'catalog_roster_member.any_of_course_ids', 'catalog_roster_member.course_id',
        'catalog_roster_member.facility_id', 'catalog_roster_member.hole_id', 'catalog_roster_member.removed_on', 'catalog_roster_member.roster_version', 'catalog_roster_member.trail_id',
        'catalog_roster_version.trail_id', 'catalog_roster_version.version'], 'and they are the columns the roster check reads and no others');
SELECT ok(NOT EXISTS (SELECT 1 FROM unnest(ARRAY['app.catalog_roster_member', 'app.catalog_roster_version', 'app.catalog_course', 'app.catalog_hole']) t(n)
                      WHERE has_table_privilege('private_definer', t.n, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')), 'no table-level privilege of any kind on the four tables');
SELECT ok(NOT EXISTS (SELECT 1 FROM pg_attribute a
                      WHERE a.attrelid IN ('app.catalog_roster_member'::regclass, 'app.catalog_roster_version'::regclass, 'app.catalog_course'::regclass, 'app.catalog_hole'::regclass)
                        AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'INSERT,UPDATE,REFERENCES')), 'and no column-level write on them');
SELECT ok(NOT EXISTS (SELECT 1 FROM unnest(ARRAY['edge_partner', 'anon', 'edge_partner_minter']) r(n), unnest(ARRAY['app.catalog_roster_member', 'app.catalog_roster_version']) t(n)
                      WHERE has_table_privilege(r.n, t.n, 'SELECT,INSERT,UPDATE,DELETE')), 'edge_partner, edge_partner_minter and anon hold nothing on the roster tables: the lane reads the roster only through the definer');
-- the policies: with NO binding private_definer reads no roster row, with every setting the repository has ever keyed a policy on planted
SELECT is(pg_temp.as_definer($q$SELECT (SELECT count(*) FROM app.catalog_roster_member)::text || '/' || (SELECT count(*) FROM app.catalog_roster_version)::text
                                       || '/' || (SELECT count(*) FROM app.catalog_course)::text || '/' || (SELECT count(*) FROM app.catalog_hole)::text$q$),
  '0/0/0/0', 'B1: private_definer with no binding reads no roster, version, course or hole row');
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-3000000000c1', true), set_config('app.edge.rollups_refresh', 'on', true),
       set_config('app.partner.session_id', :'s_op', true), set_config('app.edge.purge_for', 'on', true);
SELECT is(pg_temp.as_definer($q$SELECT (SELECT count(*) FROM app.catalog_roster_member)::text || '/' || (SELECT count(*) FROM app.catalog_roster_version)::text
                                       || '/' || (SELECT count(*) FROM app.catalog_course)::text || '/' || (SELECT count(*) FROM app.catalog_hole)::text$q$),
  '0/0/0/0', 'B2: and with settings planted at the operator and the rollup / purge windows it still reads nothing (no policy is keyed on a setting)');
SELECT set_config('app.delete_my_data.target_user_id', '', true), set_config('app.edge.rollups_refresh', '', true), set_config('app.partner.session_id', '', true), set_config('app.edge.purge_for', '', true);

SAVEPOINT b_staff;
SELECT pg_temp.seed_step('sx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.as_definer($q$SELECT (SELECT count(*) FROM app.catalog_roster_member)::text || '/' || (SELECT count(*) FROM app.catalog_roster_version)::text$q$),
  '0/0', 'B3: bound to a STAFF member (operator of no trail): no roster member and no roster version is visible');
SELECT is(pg_temp.as_definer($q$SELECT ((SELECT count(*) FROM app.catalog_course) > 0 AND (SELECT count(*) FROM app.catalog_hole) > 0)::text$q$), 'true',
  'B4: but the course / hole -> facility mapping (public catalogue data) is visible under a partner binding');
ROLLBACK TO SAVEPOINT b_staff;

SAVEPOINT b_operator;
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.as_definer($q$SELECT count(*) FILTER (WHERE trail_id = 'trl_t')::text || '/' || count(*) FILTER (WHERE trail_id <> 'trl_t')::text FROM app.catalog_roster_member$q$),
  '2/0', 'B5: bound to the operator of trl_t: its two roster members (helpers.sql) and NOT ONE member of any other trail (the section 140 fixtures hold 15)');
SELECT is(pg_temp.as_definer($q$SELECT count(*) FILTER (WHERE trail_id = 'trl_t')::text || '/' || count(*) FILTER (WHERE trail_id <> 'trl_t')::text FROM app.catalog_roster_version$q$),
  '1/0', 'B6: and its roster version, no other trail''s');
SELECT is(pg_temp.as_definer($q$SELECT id FROM app.catalog_roster_member LIMIT 1$q$), 'ERR 42501', 'B7: the roster member id is not a granted column (permission denied, not an empty result)');
SELECT is(pg_temp.as_definer($q$SELECT stop_order::text FROM app.catalog_roster_member LIMIT 1$q$), 'ERR 42501', 'B8: nor is stop_order');
SELECT is(pg_temp.as_definer($q$SELECT unit::text FROM app.catalog_roster_member LIMIT 1$q$), 'ERR 42501', 'B9: nor is unit');
SELECT is(pg_temp.as_definer($q$SELECT name FROM app.catalog_course LIMIT 1$q$), 'ERR 42501', 'B10: nor is anything of a course beyond id and facility_id');
SELECT is(pg_temp.as_definer($q$WITH d AS (DELETE FROM app.catalog_roster_member RETURNING 1) SELECT count(*)::text FROM d$q$), 'ERR 42501', 'B11: and it cannot delete a roster member');
ROLLBACK TO SAVEPOINT b_operator;

SAVEPOINT b_admin;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is(pg_temp.as_definer($q$SELECT (count(*) FILTER (WHERE trail_id <> 'trl_t') >= 15 AND count(*) FILTER (WHERE trail_id = 'trl_t') = 2)::text FROM app.catalog_roster_member$q$), 'true',
  'B12: bound to an ADMIN: every trail''s roster (the control that the cells above can fail)');
ROLLBACK TO SAVEPOINT b_admin;

-- ----------------------------------------------------------------------------
-- C. Authority is checked FIRST: a caller with no scope gets 42501 whatever the facility  (5)
-- ----------------------------------------------------------------------------
SAVEPOINT c_staff;
SELECT pg_temp.seed_step('sx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.fp_try('sx', 'trl_t', 'fac_z'), :'m_scope', 'C1: STAFF at fac_x, off-roster facility: 42501 (no scope), not 22023');
SELECT is(pg_temp.fp_try('sx', 'trl_t', 'fac_x'), :'m_scope', 'C2: STAFF with a facility that IS on the roster: still 42501 (the roster rule is no way in)');
ROLLBACK TO SAVEPOINT c_staff;

SAVEPOINT c_manager;
SELECT pg_temp.seed_step('mx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.fp_try('mx', 'trl_t', 'fac_z'), :'m_scope', 'C3: a MANAGER of fac_x, off-roster facility: 42501, not 22023');
SELECT is(pg_temp.fp_try('mx', 'trl_t', 'fac_x'), :'m_scope', 'C4: a MANAGER with a facility on the roster: 42501');
ROLLBACK TO SAVEPOINT c_manager;

SAVEPOINT c_a3;
SELECT pg_temp.seed_step('op', '{"mfa_s": -5, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_facility_programme_upsert_for_partner('trl_t', 'fac_z', 'accepted', true, false, 'ok', true, NULL, 'rotating')$$,
  '42501', 'partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required', 'C5: an operator whose TOTP window has lapsed and an off-roster facility: 42501 (A3 first), not 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT c_a3;

-- ----------------------------------------------------------------------------
-- D. The ADMIN is held to the same rule: each roster leg, and every way to be off the roster  (34)
-- ----------------------------------------------------------------------------
SAVEPOINT d_admin;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT count(*)::int AS audits_d0 FROM app.audit_log WHERE action = 'partner.facility_programme_upsert' \gset

-- the four legs, each with a control that a facility NOT named by that leg is refused on the same roster
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_ra'), 'ok', 'D1 leg 1: a FACILITY member names the facility: ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_rb'), :'m_roster', 'D2 ... and a facility that member does not name is 22023 (the admin is not exempt)');
SELECT is(pg_temp.fp_try('ad', 'trl_88b', 'fac_rb'), 'ok', 'D3 leg 2: a COURSE member names a course of the facility: ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88b', 'fac_ra'), :'m_roster', 'D4 ... another facility''s course does not admit it');
SELECT is(pg_temp.fp_try('ad', 'trl_88c', 'fac_rc'), 'ok', 'D5 leg 3: a HOLE member names a hole of the facility (the member carries NO course_id): ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88c', 'fac_rb'), :'m_roster', 'D6 ... and another facility is refused on that roster');
SELECT is(pg_temp.fp_try('ad', 'trl_88c2', 'fac_re'), 'ok', 'D7 leg 3 as the importer writes it (hole_id AND course_id): ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88d', 'fac_rd'), 'ok', 'D8 leg 4: a course member with any_of_course_ids naming courses of the facility: ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88d', 'fac_rc'), :'m_roster', 'D9 ... and a facility with none of those courses is refused');
-- roster members that name ANOTHER facility's hole / course / any_of do not admit this one
SELECT is(pg_temp.fp_try('ad', 'trl_88k', 'fac_rk'), 'ok', 'D10: control: the roster of trl_88k names a hole, a course and an any_of course of fac_rk: fac_rk is ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88k', 'fac_rl'), :'m_roster', 'D11: fac_rl (the roster names three things, none of them fac_rl''s) is 22023');
-- every way to be off the roster
SELECT is(pg_temp.fp_try('ad', 'trl_88e', 'fac_rm'), :'m_roster', 'D12: a member with removed_on set (the latest version) does not count');
SELECT is(pg_temp.fp_try('ad', 'trl_88e', 'fac_rn'), 'ok', 'D13: the same facility named by a removed member AND by a current member (a course of it) is ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88f', 'fac_rg'), :'m_roster', 'D14: a facility on an OLDER roster version only (removed_on NULL there) is 22023');
SELECT is(pg_temp.fp_try('ad', 'trl_88f', 'fac_rh'), 'ok', 'D15: a facility on the LATEST version only is ok (the latest version is the one that counts)');
SELECT is(pg_temp.fp_try('ad', 'trl_88g', 'fac_rg'), :'m_roster', 'D16: a latest version with NO members refuses even a facility the previous version named');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_rj'), :'m_roster', 'D17: a facility on ANOTHER trail''s roster only is 22023');
SELECT is(pg_temp.fp_try('ad', 'trl_88h', 'fac_rj'), 'ok', 'D18: control: the same facility on its own trail''s roster is ok');
SELECT is(pg_temp.fp_try('ad', 'trl_88i', 'fac_x'), :'m_roster', 'D19: a trail with a programme and no roster version at all refuses every facility');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_z'), :'m_roster', 'D20: a facility that exists and is on no roster is 22023');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_nope'), :'m_roster', 'D21: a facility that does not exist is the SAME 22023 (it was a raw foreign-key error, 23503, which the Edge does not translate)');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', NULL), :'m_shape', 'D22: a NULL facility is the argument-shape 22023');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', ''), :'m_shape', 'D23: an empty facility is the argument-shape 22023');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', ' fac_ra'), :'m_roster', 'D24: an id with a leading space is not the facility (ids are compared exactly)');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'FAC_RA'), :'m_roster', 'D25: nor is a different case');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_r%'), :'m_roster', 'D26: nor is a pattern (an LIKE would match fac_ra)');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_ra', 'bogus'), :'m_shape', 'D27: argument shapes are checked before the roster (a bad participation on an on-roster facility is the shape 22023)');
SELECT is(pg_temp.fp_try('ad', 'trl_88a', 'fac_z', 'bogus'), :'m_shape', 'D28: ... and on an off-roster one');
SELECT is(pg_temp.fp_try('ad', 'trl_88n', 'fac_z'), 'no_trail', 'D29: a trail with no programme row answers no_trail BEFORE the roster is consulted (an unchanged status)');
SELECT is(pg_temp.fp_try('ad', 'trl_u', 'fac_z'), 'no_trail', 'D30: ... also for a trail with no roster (trl_u)');
-- what a refusal does and does not do: eight owner-planted rows that are OFF the roster, each refused as an UPDATE (participation -> left); the table, byte for byte, is what it was
SELECT count(*)::int AS audits_d1 FROM app.audit_log WHERE action = 'partner.facility_programme_upsert' \gset
SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t.trail_id, t.facility_id), '')) AS h_d0 FROM app.facility_programme t \gset
SELECT count(*)::int AS n_refused FROM (VALUES ('trl_88a', 'fac_z'), ('trl_88a', 'fac_rj'), ('trl_88b', 'fac_ra'), ('trl_88e', 'fac_rm'), ('trl_88f', 'fac_rg'), ('trl_88g', 'fac_rg'), ('trl_88i', 'fac_x'), ('trl_88k', 'fac_rl')) v(t, f)
  WHERE pg_temp.fp_try('ad', v.t, v.f, 'left') = :'m_roster' \gset
SELECT is(:n_refused, 8, 'D31: all eight owner-planted off-roster rows are refused as an UPDATE too (the check is on the upsert, not on the insert only)');
SELECT is(md5(coalesce((SELECT string_agg(t::text, '|' ORDER BY t.trail_id, t.facility_id) FROM app.facility_programme t), '')), :'h_d0', 'D32: and the programme table is byte for byte what it was: a refused call changes no row');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits_d1, 0, 'D33: and writes no audit row');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits_d0, 9, 'D34: the nine successful writes of this section (D1 D3 D5 D7 D8 D10 D13 D15 D18) are the only audited ones; no_trail and every refusal wrote none');
ROLLBACK TO SAVEPOINT d_admin;

-- ----------------------------------------------------------------------------
-- E. The owner's off-roster query lists exactly what the definer would refuse  (4)
-- ----------------------------------------------------------------------------
-- The query text between the markers is the one in tools/db/facility-programme-off-roster.sql, held identical by supabase/tests/unit/facility-programme-off-roster-parity.test.ts. It is run as service_role
-- (BYPASSRLS): the roster tables are FORCE ROW LEVEL SECURITY, and a role that is subject to RLS would read an empty roster and list every row.
CREATE TEMP TABLE e88_rows AS SELECT trail_id, facility_id FROM app.facility_programme;
SET LOCAL ROLE service_role;
CREATE TEMP TABLE e88_off AS
-- BEGIN off-roster query
SELECT fp.trail_id, fp.facility_id, fp.participation::text AS participation
FROM app.facility_programme fp
WHERE NOT EXISTS (
  SELECT 1
  FROM app.catalog_roster_member rm
  WHERE rm.trail_id = fp.trail_id
    AND rm.removed_on IS NULL
    AND rm.roster_version = (SELECT max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = fp.trail_id)
    AND (
      rm.facility_id = fp.facility_id
      OR rm.course_id IN (SELECT c.id FROM app.catalog_course c WHERE c.facility_id = fp.facility_id)
      OR rm.hole_id IN (SELECT h.id FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id WHERE c.facility_id = fp.facility_id)
      OR rm.any_of_course_ids && ARRAY(SELECT c.id FROM app.catalog_course c WHERE c.facility_id = fp.facility_id)
    )
)
ORDER BY fp.trail_id, fp.facility_id
-- END off-roster query
;
SELECT is((SELECT array_agg(trail_id || ':' || facility_id ORDER BY trail_id, facility_id) FROM e88_off),
  ARRAY['trl_88a:fac_rj', 'trl_88a:fac_z', 'trl_88b:fac_ra', 'trl_88e:fac_rm', 'trl_88f:fac_rg', 'trl_88g:fac_rg', 'trl_88i:fac_x', 'trl_88k:fac_rl'],
  'E1: over the eighteen programme rows (seventeen planted, plus trl_t / fac_x from helpers.sql) the query lists the eight whose facility is off its trail''s roster');
SELECT is((SELECT array_agg(trail_id || ':' || participation ORDER BY trail_id, facility_id) FROM e88_off WHERE trail_id IN ('trl_88g', 'trl_88k', 'trl_88i')),
  ARRAY['trl_88g:declined', 'trl_88i:accepted', 'trl_88k:left'], 'E2: and it shows each row''s participation (a declined or left row is listed too: it is still a grant, G3 is a separate decision)');
RESET ROLE;
SAVEPOINT e_admin;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is((SELECT array_agg(trail_id || ':' || facility_id ORDER BY trail_id, facility_id) FROM e88_rows WHERE pg_temp.fp_try('ad', trail_id, facility_id) = :'m_roster'),
  ARRAY['trl_88a:fac_rj', 'trl_88a:fac_z', 'trl_88b:fac_ra', 'trl_88e:fac_rm', 'trl_88f:fac_rg', 'trl_88g:fac_rg', 'trl_88i:fac_x', 'trl_88k:fac_rl'],
  'E3: the DEFINER, asked for every one of the eighteen pairs, refuses exactly the same eight (the query and the check are one rule)');
SELECT is((SELECT count(*)::int FROM e88_rows WHERE pg_temp.fp_try('ad', trail_id, facility_id) = 'ok'), 10, 'E4: and accepts the other ten');
ROLLBACK TO SAVEPOINT e_admin;

-- ----------------------------------------------------------------------------
-- F. The OPERATOR of trl_t: the 138.4 reproduction, the four legs as a positive control, and the negatives  (27)
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2, "reauth_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT count(*)::int AS audits_f0 FROM app.audit_log WHERE action = 'partner.facility_programme_upsert' \gset

-- the reproduction (138.4): fac_z is on no roster; its organisation exists; the operator is at aal 2 with a fresh TOTP and a fresh assertion
SELECT is(pg_temp.reach('fac_z'), false, 'F1: has_facility_scope(operator_t, fac_z, {operator}) is false before anything');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000887a', 'manager'), 'ERR 42501 partner_invite_create_for_partner: the grant is not a subset of the inviter reach', 'F2: and an invite of a MANAGER at the organisation of fac_z is 42501');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z'), :'m_roster', 'F3: THE FIX: the operator writing fac_z into its programme is refused, 22023 (it was ok, and stored)');
SELECT is((SELECT count(*)::int FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z'), 0, 'F4: no row was written');
SELECT is(pg_temp.reach('fac_z'), false, 'F5: so has_facility_scope(operator_t, fac_z, {operator}) STAYS false');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000887a', 'manager'), 'ERR 42501 partner_invite_create_for_partner: the grant is not a subset of the inviter reach', 'F6: and the invite of a manager at fac_z''s organisation STAYS 42501');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000887a', 'staff'), 'ERR 42501 partner_invite_create_for_partner: the grant is not a subset of the inviter reach', 'F7: so does the invite of a staff member');
SELECT is((SELECT count(*)::int FROM app.partner_invite WHERE org_id = '10000000-0000-0000-0000-00000000887a'), 0, 'F8: no invite exists at fac_z');
SELECT is(pg_temp.fp_try('op', 'trl_u', 'fac_z'), :'m_scope', 'F9: an operator of trl_t has no scope on trl_u (the scope check comes first)');

-- the positive control, each of the four ways to put fac_z on the trail's roster (each a NEW latest version holding only that member; the row is removed between legs so each leg is what admits it)
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_t', 2, 'facility', 'facility', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, facility_id, stop_order) VALUES ('trl_t', 2, 'facility', 'fac_z', 1);
RESET ROLE;
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z'), 'ok', 'F10 leg 1: a facility member names fac_z: the same upsert is ok');
SELECT is(pg_temp.reach('fac_z'), true, 'F11: and now the operator has reach to fac_z, as the design intends for a facility on its trail');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000887a', 'manager'), 'ok', 'F12: and the invite of a manager at fac_z''s organisation is ok');
DELETE FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z';
SELECT is(pg_temp.reach('fac_z'), false, 'F13: (control: with the row gone the reach is gone, so each leg below is admitted by its own roster member)');
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_t', 3, 'course', 'course', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, course_id, stop_order) VALUES ('trl_t', 3, 'course', 'crs_z1', 1);
RESET ROLE;
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z'), 'ok', 'F14 leg 2: a course member names a course of fac_z: ok');
DELETE FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z';
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_t', 4, 'hole', 'hole', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, hole_id, stop_order) VALUES ('trl_t', 4, 'hole', 'hol_z1', 1);
RESET ROLE;
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z'), 'ok', 'F15 leg 3: a hole member (no course_id) names a hole of fac_z: ok');
DELETE FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z';
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_t', 5, 'course', 'course', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, any_of_course_ids, stop_order) VALUES ('trl_t', 5, 'course', ARRAY['crs_z1', 'crs_z2'], 1);
RESET ROLE;
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z'), 'ok', 'F16 leg 4: an any_of_course_ids member naming courses of fac_z: ok');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits_f0, 4, 'F17: the four successful writes are audited (the four refusals above wrote none)');

-- the negatives, against the latest version (5: one any_of member naming the courses of fac_z)
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_x'), :'m_roster', 'F18: fac_x was on version 1 (and removed_on is NULL there) but is not on the latest: 22023');
SELECT is((SELECT participation::text || '/' || holds_special_marker::text FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 'accepted/true', 'F19: and the existing trl_t / fac_x row (helpers.sql) is exactly as it was');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_rj'), :'m_roster', 'F20: a facility on another trail''s roster is 22023');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_nope'), :'m_roster', 'F21: an unknown facility id is 22023');
SELECT is(pg_temp.fp_try('op', 'trl_t', NULL), :'m_shape', 'F22: NULL is the argument-shape 22023');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z', 'bogus'), :'m_shape', 'F23: a bad participation on an on-roster facility: the shape refusal, before the roster');

-- a roster version with no members, then the limit this change does not remove
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_t', 6, 'facility', 'facility', now());
RESET ROLE;
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z', 'left'), :'m_roster', 'F24: version 6 has no members: the EXISTING fac_z row cannot be updated (participation left) either');
SELECT is((SELECT participation::text FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z'), 'accepted', 'F25: and it still says accepted');
SELECT is(pg_temp.reach('fac_z'), true, 'F26: KNOWN LIMIT, pinned: that row, written while fac_z was on the roster, is still a grant after the roster dropped it (0110 changes the WRITE only; the owner''s query lists such rows; option B of section 138.3 is the fix for the read, and this cell flips to false when it lands)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits_f0, 4, 'F27: the refusals since wrote no audit row');

SELECT * FROM finish();
ROLLBACK;
