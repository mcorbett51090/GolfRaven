-- 88_partner_facility_programme_roster_gate.sql
-- P5 section 139 (0110): a NEW (trail, facility) programme row needs the facility on the trail's CURRENT roster (latest roster_version, members not removed; a member names the facility directly,
-- through a course (course_id or any_of_course_ids) or through a hole). An existing row stays editable. Before 0110 the operator could write a row for ANY facility and thereby gave itself reach
-- to it (has_facility_scope, E6): design section 138.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 / 36 / 37 pattern), with matrix 37's principals and helpers: operator_t (c1, scoped to trl_t only) and the admin (d0).
-- The roster variants live on trails of their own (trl_r1 .. trl_r7) so trl_t's roster is never touched; the admin (who passes the scope check on any trail) writes on those, inside a SAVEPOINT
-- that is rolled back before the operator is bound (a second bind in one transaction is itself refused).

\set QUIET 1
BEGIN;
SELECT plan(34);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT ON app.catalog_id_ledger, app.catalog_trail, app.catalog_facility, app.catalog_course, app.catalog_hole, app.catalog_roster_version, app.catalog_roster_member TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.trail_programme, app.facility_programme, app.offer, app.sponsorship, app.partner_org TO CURRENT_USER;
GRANT SELECT ON app.operator_rollup, app.sponsor_rollup, app.special_marker_stock, app.audit_log TO CURRENT_USER;
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

CREATE POLICY zz88_led ON app.catalog_id_ledger FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_trl ON app.catalog_trail FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_fac ON app.catalog_facility FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_crs ON app.catalog_course FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_hol ON app.catalog_hole FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_rv ON app.catalog_roster_version FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_rm ON app.catalog_roster_member FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

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

INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000003701', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 250, 15, current_date, current_date + 30, 'draft');

-- ----------------------------------------------------------------------------



-- ----------------------------------------------------------------------------
-- 0. Fixture: facilities and courses, and one roster shape per trail
-- ----------------------------------------------------------------------------
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES
  ('fac_p', 'facility', 'verified', 1), ('fac_q', 'facility', 'verified', 1), ('fac_r', 'facility', 'verified', 1), ('fac_z', 'facility', 'verified', 1), ('fac_z2', 'facility', 'verified', 1),
  ('crs_p1', 'course', 'verified', 1), ('crs_q1', 'course', 'verified', 1), ('crs_r1', 'course', 'verified', 1), ('hol_r1', 'hole', 'verified', 1),
  ('trl_r1', 'trail', 'verified', 1), ('trl_r2', 'trail', 'verified', 1), ('trl_r3', 'trail', 'verified', 1), ('trl_r4', 'trail', 'verified', 1),
  ('trl_r5', 'trail', 'verified', 1), ('trl_r6', 'trail', 'verified', 1), ('trl_r7', 'trail', 'verified', 1);
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
  ('fac_p', 'facility-p', 'Facility P', 'US-TN', 'America/Chicago', 1), ('fac_q', 'facility-q', 'Facility Q', 'US-TN', 'America/Chicago', 1),
  ('fac_r', 'facility-r', 'Facility R', 'US-TN', 'America/Chicago', 1), ('fac_z', 'facility-z', 'Facility Z', 'US-TN', 'America/Chicago', 1),
  ('fac_z2', 'facility-z2', 'Facility Z2', 'US-TN', 'America/Chicago', 1);
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, catalog_version) VALUES
  ('crs_p1', 'fac_p', 'Course P1', 'play-verified', 1), ('crs_q1', 'fac_q', 'Course Q1', 'play-verified', 1), ('crs_r1', 'fac_r', 'Course R1', 'play-verified', 1);
INSERT INTO app.catalog_hole (id, course_id, number, catalog_version) VALUES ('hol_r1', 'crs_r1', 1, 1);
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) SELECT t, replace(t, '_', '-'), 'Trail ' || t, 1 FROM unnest(ARRAY['trl_r1','trl_r2','trl_r3','trl_r4','trl_r5','trl_r6','trl_r7']) AS t;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from)
  SELECT t, 1, 'course', 'facility', now() FROM unnest(ARRAY['trl_r1','trl_r2','trl_r3','trl_r4','trl_r5','trl_r6']) AS t;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_r6', 2, 'course', 'facility', now());
-- trl_r1: a member of unit facility; trl_r2: a course; trl_r3: any_of_course_ids (the facility is the SECOND element); trl_r4: a hole;
-- trl_r5: a course whose member was removed; trl_r6: version 1 names P, the latest version 2 names Q; trl_r7: no roster at all
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, course_id, any_of_course_ids, facility_id, hole_id, stop_order, removed_on) VALUES
  ('trl_r1', 1, 'facility', NULL, NULL, 'fac_p', NULL, 1, NULL),
  ('trl_r2', 1, 'course', 'crs_q1', NULL, NULL, NULL, 1, NULL),
  ('trl_r3', 1, 'course', NULL, ARRAY['crs_p1', 'crs_q1'], NULL, NULL, 1, NULL),
  ('trl_r4', 1, 'hole', NULL, NULL, NULL, 'hol_r1', 1, NULL),
  ('trl_r5', 1, 'course', 'crs_p1', NULL, NULL, NULL, 1, current_date),
  ('trl_r6', 1, 'course', 'crs_p1', NULL, NULL, NULL, 1, NULL),
  ('trl_r6', 2, 'course', 'crs_q1', NULL, NULL, NULL, 1, NULL);

-- the org of fac_z2, for the invite cells
INSERT INTO app.partner_org (id, kind, name) VALUES ('10000000-0000-0000-0000-00000000008a', 'facility', 'Facility Z2 Pro Shop');
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_scope, app.partner_invite TO CURRENT_USER;
CREATE POLICY zz88_scope ON app.partner_scope FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz88_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('10000000-0000-0000-0000-00000000008a', 'fac_z2');
-- an EXISTING programme row for an off-roster facility (written before the gate, or after the roster changed), planted by the owner
INSERT INTO app.facility_programme (trail_id, facility_id, participation) VALUES ('trl_t', 'fac_z', 'accepted');

-- helpers: the upsert (status or SQLSTATE), the invite (status or SQLSTATE) and a programme-row read
CREATE FUNCTION pg_temp.fp_try(p_label text, p_trail text, p_fac text, p_participation text DEFAULT 'accepted') RETURNS text LANGUAGE plpgsql AS $f$
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
CREATE FUNCTION pg_temp.inv(p_label text, p_org uuid, p_role text, p_email text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2, "reauth_s": 240}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    IF p_role = 'manager' THEN
      SELECT * INTO r FROM private.partner_invite_create_for_partner(p_org, 'manager', p_email, repeat('ab', 32));
    ELSE
      SELECT * INTO r FROM private.partner_invite_create_for_partner(p_org, 'staff', p_email, repeat('cd', 32));
    END IF;
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;

CREATE FUNCTION pg_temp.scope_of(p_fac text) RETURNS boolean LANGUAGE plpgsql AS $f$
DECLARE b boolean;
BEGIN
  EXECUTE 'SET LOCAL ROLE service_role';
  SELECT private.has_facility_scope('00000000-0000-0000-0000-3000000000c1'::uuid, p_fac, ARRAY['operator']::app.partner_role[]) INTO b;
  EXECUTE 'RESET ROLE';
  RETURN b;
END
$f$;
CREATE FUNCTION pg_temp.def_count(p_tbl text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  EXECUTE 'SELECT count(*)::int FROM ' || p_tbl INTO n;
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
SELECT count(*)::int AS audits0 FROM app.audit_log WHERE action = 'partner.facility_programme_upsert' \gset

-- ----------------------------------------------------------------------------
-- 1. The new reads are open only under a partner binding  (4)
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.def_count('app.catalog_roster_version') || '/' || (SELECT count(*) > 0)::text, '0/true', 'private_definer reads no roster_version row without a partner binding (rows exist)');
SELECT is(pg_temp.def_count('app.catalog_roster_member') || '/' || (SELECT count(*) > 0)::text, '0/true', 'private_definer reads no roster_member row without a partner binding (rows exist)');
SELECT is(pg_temp.def_count('app.catalog_course') || '/' || (SELECT count(*) > 0)::text, '0/true', 'private_definer reads no course row without a partner binding (rows exist)');
SELECT is(pg_temp.def_count('app.catalog_hole') || '/' || (SELECT count(*) > 0)::text, '0/true', 'private_definer reads no hole row without a partner binding (rows exist)');

-- ----------------------------------------------------------------------------
-- 2. Every way a roster can name a facility, and the ways it does not  (the admin, on trails of their own)  (12)
-- ----------------------------------------------------------------------------
SAVEPOINT admin_seg;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT count(pg_temp.tp_up('ad', t, 'live')) AS n_tp FROM unnest(ARRAY['trl_r1', 'trl_r2', 'trl_r3', 'trl_r4', 'trl_r5', 'trl_r6', 'trl_r7']) AS t \gset

SELECT is(pg_temp.fp_try('ad', 'trl_r1', 'fac_p'), 'ok', 'a member of unit facility names its facility');
SELECT is(pg_temp.fp_try('ad', 'trl_r1', 'fac_q'), 'ERR 22023', 'and not another facility (even one that is on another trail''s roster)');
SELECT is(pg_temp.fp_try('ad', 'trl_r2', 'fac_q'), 'ok', 'a course member names the facility of its course');
SELECT is(pg_temp.fp_try('ad', 'trl_r2', 'fac_p'), 'ERR 22023', 'and not another facility');
SELECT is(pg_temp.fp_try('ad', 'trl_r3', 'fac_p') || '/' || pg_temp.fp_try('ad', 'trl_r3', 'fac_q'), 'ok/ok', 'any_of_course_ids names the facility of EVERY course in the array (the second element too)');
SELECT is(pg_temp.fp_try('ad', 'trl_r4', 'fac_r'), 'ok', 'a hole member names the facility of the hole''s course');
SELECT is(pg_temp.fp_try('ad', 'trl_r5', 'fac_p'), 'ERR 22023', 'a REMOVED member (removed_on set) names nothing');
SELECT is(pg_temp.fp_try('ad', 'trl_r6', 'fac_p') || '/' || pg_temp.fp_try('ad', 'trl_r6', 'fac_q'), 'ERR 22023/ok', 'only the LATEST roster version counts (version 1 names P, version 2 names Q)');
SELECT is(pg_temp.fp_try('ad', 'trl_r7', 'fac_x'), 'ERR 22023', 'a trail with no roster has no facility on it (even the seeded fac_x), and the gate applies to an admin too');
SELECT is(pg_temp.fp_try('ad', 'trl_r1', 'fac_nope'), 'ERR 22023', 'a facility id that is in no catalog is the same refusal, not a foreign-key error');
SELECT is(pg_temp.fp_try('ad', 'trl_u', 'fac_z'), 'no_trail', 'a trail with no trail_programme is still no_trail (that check comes first)');
SELECT is((SELECT count(*)::int FROM app.facility_programme WHERE (trail_id, facility_id) IN (('trl_r1', 'fac_q'), ('trl_r2', 'fac_p'), ('trl_r5', 'fac_p'), ('trl_r6', 'fac_p'), ('trl_r7', 'fac_x'), ('trl_r1', 'fac_nope'))), 0, 'no refusal wrote a row');
ROLLBACK TO SAVEPOINT admin_seg;

-- ----------------------------------------------------------------------------
-- 3. The operator: reach follows rows, a row follows the roster, and the section 138 escalation is closed  (11)
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;

SELECT is(pg_temp.scope_of('fac_y'), false, 'control: fac_y is on trl_t''s roster but has no programme row, so the operator has no reach to it yet');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_y'), 'ok', 'the operator adds fac_y (on the roster): ok');
SELECT is(pg_temp.scope_of('fac_y'), true, 'and now reaches it (the legitimate path is unchanged)');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000008a', 'manager', 'a@example.test') || '/' || pg_temp.inv('op', '10000000-0000-0000-0000-00000000008a', 'staff', 'b@example.test'), 'ERR 42501/ERR 42501', 'fac_z2 is on no roster: the operator may not invite a manager or staff at its organisation');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z2'), 'ERR 22023', 'the operator tries to add fac_z2 to its programme: refused (section 138: this used to be ok)');
SELECT is((SELECT count(*)::int FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z2'), 0, 'no row was written');
SELECT is(pg_temp.scope_of('fac_z2'), false, 'so the operator still has no reach to fac_z2');
SELECT is(pg_temp.inv('op', '10000000-0000-0000-0000-00000000008a', 'manager', 'a@example.test') || '/' || pg_temp.inv('op', '10000000-0000-0000-0000-00000000008a', 'staff', 'b@example.test'), 'ERR 42501/ERR 42501', 'and still may not invite there (section 138: this used to be ok, ok)');
SELECT is((SELECT count(*)::int FROM app.partner_invite WHERE org_id = '10000000-0000-0000-0000-00000000008a'), 0, 'no invite exists at fac_z2');
SELECT is(pg_temp.fp_try('op', 'trl_t', 'fac_z', 'left'), 'ok', 'an EXISTING row of a facility that is off the roster stays editable: the operator sets it to left');
SELECT is((SELECT participation::text FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_z'), 'left', 'and the row says left');

-- ----------------------------------------------------------------------------
-- 3b. The repair query of design section 139.3 finds exactly the rows the gate would not have let in  (1)
--     (run as the owner, the way an operator of the database would; the planted (trl_t, fac_z) row is off the roster, (trl_t, fac_x) and the fac_y row written above are on it)
-- ----------------------------------------------------------------------------
SELECT is((SELECT string_agg(fp.trail_id || '/' || fp.facility_id, ',' ORDER BY fp.trail_id, fp.facility_id)
           FROM app.facility_programme fp
           WHERE fp.trail_id = 'trl_t'
             AND NOT EXISTS (
               SELECT 1 FROM app.catalog_roster_member rm
               WHERE rm.trail_id = fp.trail_id AND rm.removed_on IS NULL
                 AND rm.roster_version = (SELECT max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = fp.trail_id)
                 AND (rm.facility_id = fp.facility_id
                      OR EXISTS (SELECT 1 FROM app.catalog_course c WHERE c.facility_id = fp.facility_id AND (c.id = rm.course_id OR c.id = ANY (rm.any_of_course_ids)))
                      OR EXISTS (SELECT 1 FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id WHERE h.id = rm.hole_id AND c.facility_id = fp.facility_id)))),
          'trl_t/fac_z', 'the repair query lists the off-roster row and only it');

-- ----------------------------------------------------------------------------
-- 4. What did not change  (6)
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE'), 'the facility programme upsert is still edge_partner');
SELECT ok(NOT has_function_privilege('authenticated', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE')
      AND NOT has_function_privilege('anon', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE'), 'and nobody else may execute it');
SELECT is((SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure), 'private_definer', 'the owner is still private_definer');
SELECT ok((SELECT prosecdef AND 'search_path=""' = ANY (proconfig) FROM pg_proc WHERE oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure), 'still SECURITY DEFINER with an empty search_path');
SELECT is((SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND policyname LIKE 'pd\_partner\_roster\_gate\_%' AND roles = '{private_definer}' AND cmd = 'SELECT'), 4, 'the four roster-gate policies exist, SELECT only, for private_definer only');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.facility_programme_upsert') - :audits0, 2, 'only the two successful operator writes (fac_y, and the edit of fac_z) are audited: refusals write nothing');

SELECT * FROM finish();
ROLLBACK;
