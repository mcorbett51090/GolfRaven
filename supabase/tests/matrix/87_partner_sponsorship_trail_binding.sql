-- 87_partner_sponsorship_trail_binding.sql
-- P5 section 137 (0109): the sponsorship that funds an offer, or a trail's special marker, is a sponsorship OF THAT TRAIL. Before 0109 partner_offer_upsert_for_partner checked that a sponsor offer names a
-- sponsorship and nothing else, and partner_trail_programme_upsert_for_partner took any id; another trail's sponsorship was accepted and an id that names none was a raw foreign-key error (23503).
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 / 36 / 37 pattern), with matrix 37's principals and helpers: operator_t (c1, scoped to trl_t only). Sponsorships of trl_u, and of trl_t in
-- every status and scope, are planted by the owner. Each refusal is read back as its status (offer) or its SQLSTATE (programme) by a helper that catches it, so the transaction survives.

\set QUIET 1
BEGIN;
SELECT plan(24);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
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
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
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


CREATE FUNCTION pg_temp.off_sp(p_label text, p_id uuid, p_trail text, p_fac text, p_funder text, p_sp uuid, p_cap numeric DEFAULT 100) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_offer_upsert_for_partner(
      p_id, p_trail, p_fac, '{}'::jsonb, p_funder, p_sp, p_cap, NULL, 10, current_date, current_date + 30);
    EXECUTE 'RESET ROLE';
    RETURN r.o_status || '|' || coalesce(r.o_id::text, '');
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;
CREATE FUNCTION pg_temp.tp_sp(p_label text, p_trail text, p_funded text, p_sp uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_trail_programme_upsert_for_partner(
      p_trail, 'live', 'any_purchase', true, p_funded, 3, false, NULL, p_sp, NULL, NULL, current_date, current_date + 90);
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;

-- sponsorships the OWNER plants: one on the other trail (trl_u), and on trl_t one of each status / scope
INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, starts_on, ends_on, status) VALUES
 ('70000000-0000-0000-0000-000000008701','10000000-0000-0000-0000-000000003701','trl_u','other','offers','FOREIGN TRAIL', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000008702','10000000-0000-0000-0000-000000003701','trl_t','other','offers','OWN live offers', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000008703','10000000-0000-0000-0000-000000003701','trl_t','other','special_marker','OWN live marker', current_date, current_date+90,'live');

SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;

SELECT count(*)::int AS audits0 FROM app.audit_log WHERE action = 'partner.offer_upsert' \gset
-- 1. the offer upsert (10)
SELECT pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000008702') AS o_own \gset
SELECT is(split_part(:'o_own', '|', 1), 'ok', 'control: a sponsor offer funded by a sponsorship of its own trail is ok');
SELECT is((SELECT sponsorship_id::text FROM app.offer WHERE id = split_part(:'o_own', '|', 2)::uuid), '70000000-0000-0000-0000-000000008702', 'the control offer names that sponsorship');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000008701'), 'bad_funder|', 'another trail''s sponsorship is bad_funder');
SELECT is((SELECT count(*)::int FROM app.offer WHERE sponsorship_id = '70000000-0000-0000-0000-000000008701'), 0, 'and no offer was written for it');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-0000000087ff'), 'bad_funder|', 'an id that names no sponsorship is the SAME answer (not a foreign-key error)');
SELECT is(pg_temp.off_sp('op', split_part(:'o_own', '|', 2)::uuid, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000008701', 999), 'bad_funder|', 'an edit of a draft to another trail''s sponsorship is bad_funder');
SELECT is((SELECT sponsorship_id::text || '/' || budget_cap::text FROM app.offer WHERE id = split_part(:'o_own', '|', 2)::uuid), '70000000-0000-0000-0000-000000008702/100.00', 'and the draft kept its sponsorship and its budget');
SELECT pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'operator', NULL) AS o_op \gset
SELECT is(split_part(:'o_op', '|', 1), 'ok', 'an operator offer with no sponsorship is untouched by the new rule');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'operator', '70000000-0000-0000-0000-000000008702'), 'bad_funder|', 'the existing rule stands: a non-sponsor offer with a sponsorship is bad_funder');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', NULL), 'bad_funder|', 'the existing rule stands: a sponsor offer with none is bad_funder');

-- 2. the trail programme upsert (8)
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000008703'), 'ok', 'control: the special marker funded by a sponsorship of its own trail is ok');
SELECT is((SELECT special_marker_sponsorship_id::text FROM app.trail_programme WHERE trail_id = 'trl_t'), '70000000-0000-0000-0000-000000008703', 'and the programme names it');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000008701'), 'ERR 22023', 'another trail''s sponsorship is 22023');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-0000000087ff'), 'ERR 22023', 'an id that names no sponsorship is 22023, not a foreign-key error');
SELECT is((SELECT special_marker_sponsorship_id::text FROM app.trail_programme WHERE trail_id = 'trl_t'), '70000000-0000-0000-0000-000000008703', 'neither refusal changed the programme');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'trail', NULL), 'ok', 'no sponsorship at all is untouched by the new rule');
SELECT is((SELECT special_marker_sponsorship_id IS NULL FROM app.trail_programme WHERE trail_id = 'trl_t'), true, 'and clears the sponsorship');
SELECT is(pg_temp.tp_sp('op', 'trl_u', 'sponsor', '70000000-0000-0000-0000-000000008701'), 'ERR 42501', 'an operator of trl_t still has no scope on trl_u (the scope check comes first)');

-- 3. what did not change (6)
SELECT ok(has_function_privilege('edge_partner', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE'), 'offer upsert is still edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE'), 'trail programme upsert is still edge_partner');
SELECT ok(NOT has_function_privilege('authenticated', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE')
      AND NOT has_function_privilege('anon', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE'), 'and nobody else may execute either');
SELECT is((SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure), 'private_definer', 'the owner of the offer upsert is still private_definer');
SELECT ok((SELECT prosecdef AND 'search_path=""' = ANY (proconfig) FROM pg_proc WHERE oid = 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure), 'the programme upsert is still SECURITY DEFINER with an empty search_path');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.offer_upsert') - :audits0, 2, 'only the two successful offer writes (the control and the operator offer) are audited: refusals write nothing');

SELECT * FROM finish();
ROLLBACK;
