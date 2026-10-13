-- 89_partner_facility_scope_participation.sql
-- P5 section 142 (0111): the G3 filter. The operator leg of private.has_facility_scope counts a programme row only when its participation is invited or accepted; declined and left give no
-- reach. The direct leg (a partner_scope row on the facility) and the admin leg do not look at the programme at all and are unchanged.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 / 36 / 37 / 88 pattern), with matrix 37's principals and helpers: staff a1 and manager b1 of fac_x (org 1), staff a3 of fac_y
-- (org 2), operator c1 (scoped to trl_t) and its revoked colleague c2 (org 3), the admin d0. Reads of has_facility_scope run as service_role (the execute grant is authenticated and service_role).
-- The end-to-end block binds the operator ONCE and drives the real definers: the programme upsert (0110) and the invite create (0101).

\set QUIET 1
BEGIN;
SELECT plan(31);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.trail_programme, app.facility_programme, app.offer, app.sponsorship, app.partner_org TO CURRENT_USER;
GRANT SELECT ON app.operator_rollup, app.sponsor_rollup, app.special_marker_stock, app.audit_log TO CURRENT_USER;
GRANT SELECT, INSERT ON app.catalog_id_ledger, app.catalog_facility, app.partner_scope, app.partner_invite TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz37_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_tp ON app.trail_programme FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_fp ON app.facility_programme FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_of ON app.offer FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_sp ON app.sponsorship FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_po ON app.partner_org FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz37_or ON app.operator_rollup FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz37_sr ON app.sponsor_rollup FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz37_st ON app.special_marker_stock FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz37_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

CREATE POLICY zz89_led ON app.catalog_id_ledger FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz89_fac ON app.catalog_facility FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz89_psc ON app.partner_scope FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz89_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s37:' || p_label) || md5('s37b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c37:' || p_label) || md5('c37b:' || p_label), 'hex'), decode(md5('k37:' || p_label) || md5('k37b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n37:' || p_label) || md5('n37b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END,
    reauth_until = CASE WHEN p_cols ? 'reauth_s' THEN clock_timestamp() + ((p_cols ->> 'reauth_s')::numeric * interval '1 second') ELSE s.reauth_until END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;

CREATE FUNCTION pg_temp.tp_up(p_label text, p_trail text, p_status text DEFAULT 'live') RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_trail_programme_upsert_for_partner(
    p_trail, p_status, 'any_purchase', true, NULL, 3, false, NULL, NULL, NULL, NULL, current_date, current_date + 90);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.fp_up(p_label text, p_trail text, p_fac text, p_holds boolean DEFAULT false) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_facility_programme_upsert_for_partner(
    p_trail, p_fac, 'accepted', true, p_holds, 'ok', true, NULL, 'rotating');
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.off_up(p_label text, p_id uuid, p_trail text, p_fac text, p_cap numeric DEFAULT 100, p_face numeric DEFAULT 10) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offer_upsert_for_partner(
    p_id, p_trail, p_fac, '{}'::jsonb, 'operator', NULL, p_cap, NULL, p_face, current_date, current_date + 30);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_id::text, '');
END
$f$;
CREATE FUNCTION pg_temp.off_ap(p_label text, p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offer_approve_for_partner(p_id);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.off_end(p_label text, p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_offer_end_for_partner(p_id);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
CREATE FUNCTION pg_temp.sp_up(p_label text, p_id uuid, p_org uuid, p_trail text, p_scope text DEFAULT 'offers') RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_sponsorship_upsert_for_partner(
    p_id, p_org, p_trail, 'equipment', p_scope, 'Matrix Sponsor', NULL, 0, current_date, current_date + 90);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_id::text, '');
END
$f$;
CREATE FUNCTION pg_temp.sp_ap(p_label text, p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_sponsorship_approve_for_partner(p_id);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-000000003701', 'sponsor', 'Matrix Sponsor Org');

-- 0110 (section 141): the facility programme editor refuses a facility that is not on the trail's current roster. trl_t's roster (helpers.sql) names fac_x and fac_y through their courses;
-- trl_u has none, so the admin's facility cell below needs one that names fac_x (the roster rows are the OWNER's, planted as service_role like the rest of the catalogue).
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_u', 1, 'facility', 'facility', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, facility_id, stop_order) VALUES ('trl_u', 1, 'facility', 'fac_x', 1);
RESET ROLE;

INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000003701', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 250, 15, current_date, current_date + 30, 'draft');


-- ----------------------------------------------------------------------------
-- 0. Fixture
-- ----------------------------------------------------------------------------
-- seven facilities that are on no roster (the owner plants programme rows directly: the roster gate of 0110 is for the editor, not for the owner)
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) SELECT 'fac_g' || n, 'facility', 'verified', 1 FROM generate_series(1, 7) AS n;
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) SELECT 'fac_g' || n, 'facility-g' || n, 'Facility G' || n, 'US-TN', 'America/Chicago', 1 FROM generate_series(1, 7) AS n;
-- one row per participation value, all on trl_t (the operator c1's trail)
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES
  ('trl_t', 'fac_g1', 'invited'), ('trl_t', 'fac_g2', 'accepted'), ('trl_t', 'fac_g3', 'declined'), ('trl_t', 'fac_g4', 'left');
-- the operator org of c1 is ALSO scoped to trl_u, so a facility can be reached through either trail: fac_g5 is left on trl_t and accepted on trl_u, fac_g6 left on trl_t and declined on trl_u
INSERT INTO app.partner_scope (org_id, trail_id) VALUES ('10000000-0000-0000-0000-000000000003', 'trl_u');
-- a programme row's trail must have a trail_programme (the foreign key): trl_u and trl_v get one
INSERT INTO app.trail_programme (trail_id, status) VALUES ('trl_u', 'live'), ('trl_v', 'live');
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES
  ('trl_t', 'fac_g5', 'left'), ('trl_u', 'fac_g5', 'accepted'), ('trl_t', 'fac_g6', 'left'), ('trl_u', 'fac_g6', 'declined');
-- fac_g7 is accepted on trl_v, a trail the operator is not scoped to
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES ('trl_v', 'fac_g7', 'accepted');

-- has_facility_scope(uid, facility, role), the way a policy or a definer reads it, as service_role
CREATE FUNCTION pg_temp.scope(p_uid uuid, p_fac text, p_role text) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE b boolean;
BEGIN
  EXECUTE 'SET LOCAL ROLE service_role';
  SELECT private.has_facility_scope(p_uid, p_fac, ARRAY[p_role]::app.partner_role[]) INTO b;
  EXECUTE 'RESET ROLE';
  RETURN b;
END
$f$;
CREATE FUNCTION pg_temp.op(p_fac text) RETURNS boolean LANGUAGE sql AS $f$ SELECT pg_temp.scope('00000000-0000-0000-0000-3000000000c1', p_fac, 'operator') $f$;
-- the programme upsert (status or SQLSTATE) and the invite (status or SQLSTATE), as the bound operator
CREATE FUNCTION pg_temp.fp_set(p_label text, p_trail text, p_fac text, p_participation text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_facility_programme_upsert_for_partner(p_trail, p_fac, p_participation, true, false, 'ok', true, NULL, 'rotating');
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;
CREATE FUNCTION pg_temp.inv_staff(p_label text, p_org uuid, p_email text, p_hash text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2, "reauth_s": 240}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_invite_create_for_partner(p_org, 'staff', p_email, p_hash);
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;
CREATE FUNCTION pg_temp.wrap(p_fn text, p_fac text) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE b boolean;
BEGIN
  EXECUTE 'SET LOCAL ROLE service_role';
  EXECUTE format('SELECT private.%I(%L::uuid, %L)', p_fn, '00000000-0000-0000-0000-3000000000c1', p_fac) INTO b;
  EXECUTE 'RESET ROLE';
  RETURN b;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. The operator leg follows the row's participation
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.op('fac_g1'), true, 'invited: the operator reaches the facility (it is how an operator brings a facility in)');
SELECT is(pg_temp.op('fac_g2'), true, 'accepted: the operator reaches the facility');
SELECT is(pg_temp.op('fac_g3'), false, 'declined: no reach (before 0111 this was true)');
SELECT is(pg_temp.op('fac_g4'), false, 'left: no reach (before 0111 this was true)');

-- ----------------------------------------------------------------------------
-- 2. What the filter does not touch
-- ----------------------------------------------------------------------------
UPDATE app.facility_programme SET participation = 'left' WHERE trail_id = 'trl_t' AND facility_id = 'fac_x';
SELECT is(pg_temp.scope('00000000-0000-0000-0000-2000000000b1', 'fac_x', 'manager'), true, 'a manager of the facility keeps its scope when the programme row says left (the direct leg does not read the programme)');
SELECT is(pg_temp.scope('00000000-0000-0000-0000-1000000000a1', 'fac_x', 'staff'), true, 'and so does staff');
SELECT is(pg_temp.op('fac_x'), false, 'while the operator, whose reach was the row, has none');
SELECT is(pg_temp.scope('00000000-0000-0000-0000-4000000000d0', 'fac_g4', 'operator') || '/' || pg_temp.scope('00000000-0000-0000-0000-4000000000d0', 'fac_nowhere', 'staff'), 'true/true', 'the admin passes whatever the programme says (a left row, and a facility that does not exist)');
SELECT is(pg_temp.scope('00000000-0000-0000-0000-3000000000c2', 'fac_g2', 'operator'), false, 'a revoked operator has none on an accepted row (unchanged)');
SELECT is(pg_temp.op('fac_g5'), true, 'a facility left on one trail of the operator but accepted on another is reached through the accepted one');
SELECT is(pg_temp.op('fac_g6'), false, 'and left on one, declined on the other: no reach');
SELECT is(pg_temp.op('fac_g7'), false, 'an accepted row of a trail the operator is not scoped to gives nothing (unchanged)');
SELECT is(pg_temp.scope('00000000-0000-0000-0000-3000000000c1', 'fac_g2', 'manager'), false, 'the operator is not a manager: the role list still applies (unchanged)');

-- ----------------------------------------------------------------------------
-- 3. The wrappers every policy and view calls follow it
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.wrap('is_operator_of_facility', 'fac_g2') || '/' || pg_temp.wrap('is_operator_of_facility', 'fac_g4'), 'true/false', 'is_operator_of_facility: accepted yes, left no');
SELECT is(pg_temp.wrap('is_manager_or_operator_of_facility', 'fac_g1') || '/' || pg_temp.wrap('is_manager_or_operator_of_facility', 'fac_g3'), 'true/false', 'is_manager_or_operator_of_facility: invited yes, declined no');
SELECT is((SELECT string_agg(participation::text, ',' ORDER BY facility_id) FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id IN ('fac_g1', 'fac_g2', 'fac_g3', 'fac_g4')), 'invited,accepted,declined,left', 'reading the scope touched no programme row: each still says what the owner planted');

-- ----------------------------------------------------------------------------
-- 4. The operator's off-switch, end to end through the real definers
--    fac_y is on trl_t's roster (helpers.sql) and has an organisation (org 2); the operator is bound once
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT count(*)::int AS audits0 FROM app.audit_log WHERE action = 'partner.facility_programme_upsert' \gset

SELECT is(pg_temp.op('fac_y'), false, 'control: fac_y is on the roster but has no programme row, so no reach yet');
SELECT is(pg_temp.fp_set('op', 'trl_t', 'fac_y', 'invited'), 'ok', 'the operator invites fac_y into the programme');
SELECT is(pg_temp.op('fac_y') || '/' || pg_temp.inv_staff('op', '10000000-0000-0000-0000-000000000002', 'one@example.test', repeat('ab', 32)), 'true/ok', 'invited: reach, and the operator may invite staff at fac_y''s organisation');
SELECT is(pg_temp.fp_set('op', 'trl_t', 'fac_y', 'accepted') || '/' || pg_temp.op('fac_y'), 'ok/true', 'the facility accepts: reach');
SELECT is(pg_temp.fp_set('op', 'trl_t', 'fac_y', 'left'), 'ok', 'THE OFF-SWITCH: the operator sets the row to left');
SELECT is(pg_temp.op('fac_y'), false, 'and the reach goes with it (section 141 F31 pinned this as true until G3)');
SELECT is(pg_temp.inv_staff('op', '10000000-0000-0000-0000-000000000002', 'two@example.test', repeat('cd', 32)), 'ERR 42501', 'so the operator may no longer invite staff at the facility that left (design 6.1)');
SELECT is(pg_temp.fp_set('op', 'trl_t', 'fac_y', 'declined') || '/' || pg_temp.op('fac_y'), 'ok/false', 'left -> declined is ok and still no reach');
SELECT is(pg_temp.fp_set('op', 'trl_t', 'fac_y', 'accepted') || '/' || pg_temp.op('fac_y'), 'ok/true', 'the operator can bring a facility that is on the roster back (the existing row, accepted again) and the reach returns');

-- ----------------------------------------------------------------------------
-- 5. What did not change
-- ----------------------------------------------------------------------------
SELECT is((SELECT pg_get_userbyid(proowner) || '/' || prosecdef::text || '/' || provolatile::text || '/' || (proconfig = ARRAY['search_path=""'])::text FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure), 'private_definer/true/s/true', 'owner private_definer, SECURITY DEFINER, STABLE, search_path empty');
SELECT is((SELECT pg_get_function_arguments(oid) FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure), 'p_uid uuid, p_facility_id text, p_roles app.partner_role[] DEFAULT ARRAY[''staff''::app.partner_role, ''manager''::app.partner_role, ''operator''::app.partner_role]', 'the signature and the default role list are as 0007 left them');
SELECT ok(has_function_privilege('authenticated', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE') AND has_function_privilege('service_role', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE'), 'authenticated and service_role may still execute it');
SELECT ok(NOT has_function_privilege('anon', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE') AND NOT has_function_privilege('edge_partner', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE'), 'and anon and edge_partner may not');
SELECT is((SELECT md5(prosrc) <> '7f59ffd3e54275daf6f1aeadc554c60d' AND prosrc LIKE '%fp.participation IN (''invited'', ''accepted'')%' FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure), true, 'the body is no longer the 0007 body (the md5 the migration pinned) and carries the predicate');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits0, 5, 'the five successful programme writes of the end-to-end block are audited, the reach reads wrote nothing');

SELECT * FROM finish();
ROLLBACK;
