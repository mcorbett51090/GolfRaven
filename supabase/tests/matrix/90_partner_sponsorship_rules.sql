-- 90_partner_sponsorship_rules.sql
-- P5 section 143 (0112): what a sponsorship has to BE before it funds an offer or a trail's special marker. Before 0112 (and after 0109, which made it a sponsorship OF THE TRAIL) a draft, an ended and a
-- special-marker-only sponsorship all funded an offer, the admin's approve read nothing about the sponsorship, a special marker could name an offers-only sponsorship, and a programme could say
-- special_marker_funded_by = trail and still carry a sponsorship id.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 / 35 / 36 / 37 / 87 pattern), with matrix 37's principals and helpers: operator_t (c1, scoped to trl_t only) and the seeded admin. Sponsorships of every
-- status and scope are planted by the owner (trl_t) or, for the foreign ones, on trl_u. A refusal is read back as its status or its SQLSTATE by a helper that catches it, so the transaction survives.

\set QUIET 1
BEGIN;
SELECT plan(47);

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
-- bind the transaction to the session of p_label (operator or admin), with a fresh second factor
CREATE FUNCTION pg_temp.bind(p_label text) RETURNS void LANGUAGE plpgsql AS $f$
DECLARE v_th text := pg_temp.th(p_label);
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(v_th);
  EXECUTE 'RESET ROLE';
END
$f$;

-- offer upsert: 'status|id', or 'ERR sqlstate'
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
-- offer approve: the status, or 'ERR sqlstate'
CREATE FUNCTION pg_temp.off_ap(p_label text, p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_offer_approve_for_partner(p_id);
    EXECUTE 'RESET ROLE';
    RETURN r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN 'ERR ' || SQLSTATE;
  END;
END
$f$;
-- trail programme upsert: the status, or 'ERR sqlstate'; tp_msg returns the message of the refusal instead
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
CREATE FUNCTION pg_temp.tp_msg(p_label text, p_trail text, p_funded text, p_sp uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  BEGIN
    SELECT * INTO r FROM private.partner_trail_programme_upsert_for_partner(
      p_trail, 'live', 'any_purchase', true, p_funded, 3, false, NULL, p_sp, NULL, NULL, current_date, current_date + 90);
    EXECUTE 'RESET ROLE';
    RETURN 'ACCEPTED ' || r.o_status;
  EXCEPTION WHEN OTHERS THEN
    EXECUTE 'RESET ROLE';
    RETURN SQLERRM;
  END;
END
$f$;
-- sponsorship upsert (the operator edits a draft): 'status|id'
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

SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-000000009001', 'sponsor', 'Matrix Sponsor Org');

-- sponsorships the OWNER plants. On trl_t: 9001 live offers, 9002 live both, 9003 live special_marker, 9004 draft offers, 9005 ended offers, 9006 draft special_marker. On trl_u: 9010 live offers, 9011 live special_marker.
INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, starts_on, ends_on, status) VALUES
 ('70000000-0000-0000-0000-000000009001','10000000-0000-0000-0000-000000009001','trl_t','other','offers','T live offers', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000009002','10000000-0000-0000-0000-000000009001','trl_t','other','both','T live both', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000009003','10000000-0000-0000-0000-000000009001','trl_t','other','special_marker','T live marker', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000009004','10000000-0000-0000-0000-000000009001','trl_t','other','offers','T draft offers', current_date, current_date+90,'draft'),
 ('70000000-0000-0000-0000-000000009005','10000000-0000-0000-0000-000000009001','trl_t','other','offers','T ended offers', current_date-90, current_date-1,'ended'),
 ('70000000-0000-0000-0000-000000009006','10000000-0000-0000-0000-000000009001','trl_t','other','special_marker','T draft marker', current_date, current_date+90,'draft'),
 ('70000000-0000-0000-0000-000000009010','10000000-0000-0000-0000-000000009001','trl_u','other','offers','U live offers', current_date, current_date+90,'live'),
 ('70000000-0000-0000-0000-000000009011','10000000-0000-0000-0000-000000009001','trl_u','other','special_marker','U live marker', current_date, current_date+90,'live');

-- draft offers the OWNER plants for the admin to approve (the shapes a legacy row, or an edit after the write, can leave): each names a different sponsorship. 9101 operator-funded (no sponsorship).
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, face_value, valid_from, valid_to, status) VALUES
 ('60000000-0000-0000-0000-000000009101','trl_t','fac_x','{}'::jsonb,'operator',NULL,100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009102','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009001',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009103','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009002',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009104','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009004',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009105','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009005',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009106','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009003',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009107','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009010',100,10,current_date,current_date+30,'draft'),
 ('60000000-0000-0000-0000-000000009108','trl_t','fac_x','{}'::jsonb,'sponsor','70000000-0000-0000-0000-000000009005',100,10,current_date,current_date+30,'live');

-- ----------------------------------------------------------------------------
-- 1. The admin's approve and the flow behind it (17): a sponsor-funded offer goes live only on a live sponsorship of its trail that covers offers.
--    A second bind in one transaction is itself refused (matrix 37), so the admin cells sit in a SAVEPOINT that is rolled back, before the durable operator section binds once.
-- ----------------------------------------------------------------------------
SAVEPOINT admin_approve;
SELECT pg_temp.bind('ad');
SELECT count(*)::int AS audits_ap0 FROM app.audit_log WHERE action = 'partner.offer_approve' \gset
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009101'), 'ok', 'control: an operator-funded offer (no sponsorship) is approved as before');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009102'), 'ok', 'a sponsor offer on a LIVE sponsorship of scope offers is approved');
SELECT is((SELECT status::text FROM app.offer WHERE id = '60000000-0000-0000-0000-000000009102'), 'live', 'and is live');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009103'), 'ok', 'a sponsor offer on a live sponsorship of scope both is approved');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009104'), 'ERR 22023', 'a sponsor offer on a DRAFT sponsorship is refused (22023)');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009105'), 'ERR 22023', 'a sponsor offer on an ENDED sponsorship is refused (22023)');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009106'), 'ERR 22023', 'a sponsor offer on a live sponsorship of the special marker alone is refused (22023)');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009107'), 'ERR 22023', 'a sponsor offer on a live offers sponsorship of ANOTHER trail (a row written before 0109) is refused (22023)');
SELECT is((SELECT string_agg(status::text, ',' ORDER BY id) FROM app.offer WHERE id IN ('60000000-0000-0000-0000-000000009104', '60000000-0000-0000-0000-000000009105', '60000000-0000-0000-0000-000000009106', '60000000-0000-0000-0000-000000009107')), 'draft,draft,draft,draft', 'every refused offer is still a draft');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009108'), 'not_draft', 'a LIVE offer whose sponsorship has ended is not_draft, as before (the status check comes first)');
SELECT is(pg_temp.off_ap('ad', '60000000-0000-0000-0000-000000009199'), 'not_found', 'an unknown offer is not_found, as before');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.offer_approve') - :audits_ap0, 3, 'only the three approvals are audited: the four refusals wrote nothing');

-- the flow the rule exists for: a draft offer is written against a draft sponsorship that is then EDITED to another scope and goes live (the admin may call the operator definers: they read only the trail's scope)
SELECT pg_temp.sp_up('ad', NULL, '10000000-0000-0000-0000-000000009001', 'trl_t', 'offers') AS sp_new \gset
SELECT pg_temp.off_sp('ad', NULL, 'trl_t', 'fac_x', 'sponsor', split_part(:'sp_new', '|', 2)::uuid) AS o_flow \gset
SELECT is(split_part(:'o_flow', '|', 1), 'ok', 'the flow: a draft offer is written against a draft sponsorship of scope offers');
SELECT is(split_part(pg_temp.sp_up('ad', split_part(:'sp_new', '|', 2)::uuid, '10000000-0000-0000-0000-000000009001', 'trl_t', 'special_marker'), '|', 1), 'ok', 'the draft sponsorship is edited to the special marker alone');
UPDATE app.sponsorship SET status = 'live' WHERE id = split_part(:'sp_new', '|', 2)::uuid;
SELECT is(pg_temp.off_ap('ad', split_part(:'o_flow', '|', 2)::uuid), 'ERR 22023', 'the offer cannot be approved: its sponsorship no longer covers offers');
SELECT is(split_part(pg_temp.off_sp('ad', split_part(:'o_flow', '|', 2)::uuid, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009001'), '|', 1), 'ok', 'the draft is repointed at a live offers sponsorship');
SELECT is(pg_temp.off_ap('ad', split_part(:'o_flow', '|', 2)::uuid), 'ok', 'and then it is approved');
ROLLBACK TO SAVEPOINT admin_approve;

SELECT pg_temp.bind('op');

-- ----------------------------------------------------------------------------
-- 2. The offer write (12): a sponsorship funds an offer only if its scope is offers or both (live status is NOT asked at the write)
-- ----------------------------------------------------------------------------
SELECT pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009001') AS o_offers \gset
SELECT is(split_part(:'o_offers', '|', 1), 'ok', 'control: a sponsor offer funded by a live sponsorship of scope offers is ok');
SELECT is((SELECT sponsorship_id::text FROM app.offer WHERE id = split_part(:'o_offers', '|', 2)::uuid), '70000000-0000-0000-0000-000000009001', 'and the offer names it');
SELECT is(split_part(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009002'), '|', 1), 'ok', 'a sponsorship of scope both funds an offer');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009003'), 'bad_funder|', 'a LIVE sponsorship of this trail whose scope is the special marker alone is bad_funder');
SELECT is((SELECT count(*)::int FROM app.offer WHERE sponsorship_id = '70000000-0000-0000-0000-000000009003' AND id <> '60000000-0000-0000-0000-000000009106'), 0, 'and no offer was written for it');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009006'), 'bad_funder|', 'a DRAFT sponsorship of the special marker alone is bad_funder too (the scope is asked whatever the status)');
SELECT is(split_part(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009004'), '|', 1), 'ok', 'a DRAFT sponsorship of scope offers still funds a DRAFT offer (the live check is at the approve, not here)');
SELECT is(split_part(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009005'), '|', 1), 'ok', 'an ENDED sponsorship of scope offers is accepted for a draft too (also left to the approve)');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009010'), 'bad_funder|', '0109 stands: another trail''s sponsorship is bad_funder');
SELECT is(pg_temp.off_sp('op', NULL, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009011'), 'bad_funder|', 'another trail''s sponsorship of the wrong scope is the SAME answer');
SELECT is(pg_temp.off_sp('op', split_part(:'o_offers', '|', 2)::uuid, 'trl_t', 'fac_x', 'sponsor', '70000000-0000-0000-0000-000000009003', 999), 'bad_funder|', 'an edit of a draft offer to a sponsorship of the wrong scope is bad_funder');
SELECT is((SELECT sponsorship_id::text || '/' || budget_cap::text FROM app.offer WHERE id = split_part(:'o_offers', '|', 2)::uuid), '70000000-0000-0000-0000-000000009001/100.00', 'and the draft kept its sponsorship and its budget');

-- ----------------------------------------------------------------------------
-- 3. The trail programme (14): the special marker's sponsorship covers the special marker, and a trail-funded marker names none
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009003'), 'ok', 'control: the special marker funded by a live sponsorship of scope special_marker is ok');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009002'), 'ok', 'a sponsorship of scope both is ok');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009006'), 'ok', 'a DRAFT sponsorship of the special marker is ok (the programme write asks the scope, not the status)');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009001'), 'ERR 22023', 'a sponsorship of this trail whose scope is offers alone is 22023');
SELECT is((SELECT special_marker_sponsorship_id::text FROM app.trail_programme WHERE trail_id = 'trl_t'), '70000000-0000-0000-0000-000000009006', 'and the programme kept the sponsorship it had');
SELECT is(pg_temp.tp_msg('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009001'), 'partner_trail_programme_upsert_for_partner: the sponsorship must cover the special marker', 'and the message says why (it is the operator''s own sponsorship)');
SELECT is(pg_temp.tp_msg('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009010'), 'partner_trail_programme_upsert_for_partner: the sponsorship must be one of this trail', 'another trail''s offers-scope sponsorship is answered "not one of this trail"');
SELECT is(pg_temp.tp_msg('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-000000009011'), pg_temp.tp_msg('op', 'trl_t', 'sponsor', '70000000-0000-0000-0000-0000000090ff'), 'another trail''s sponsorship of the RIGHT scope is answered exactly as an id that names none: the scope answer is never given about somebody else''s id');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'trail', '70000000-0000-0000-0000-000000009003'), 'ERR 22023', 'a programme that says trail with a sponsorship id is 22023');
SELECT is(pg_temp.tp_msg('op', 'trl_t', 'trail', '70000000-0000-0000-0000-000000009003'), 'partner_trail_programme_upsert_for_partner: a trail-funded special marker names no sponsorship', 'and the message says so');
SELECT is((SELECT special_marker_funded_by::text || '/' || special_marker_sponsorship_id::text FROM app.trail_programme WHERE trail_id = 'trl_t'), 'sponsor/70000000-0000-0000-0000-000000009006', 'neither refusal changed the programme');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'sponsor', NULL), 'ok', 'a programme that says sponsor with NO id is still accepted (it may say so before the sponsorship exists)');
SELECT is(pg_temp.tp_sp('op', 'trl_t', 'trail', NULL), 'ok', 'a trail-funded marker with no sponsorship is untouched by the new rule');
SELECT is(pg_temp.tp_sp('op', 'trl_t', NULL, '70000000-0000-0000-0000-000000009003'), 'ok', 'a programme with NO funder and a valid id is still accepted (recorded as not changed)');

-- ----------------------------------------------------------------------------
-- 4. What did not change (4)
-- ----------------------------------------------------------------------------
SELECT ok(has_function_privilege('edge_partner', 'private.partner_offer_approve_for_partner(uuid)'::regprocedure, 'EXECUTE')
      AND has_function_privilege('edge_partner', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE')
      AND has_function_privilege('edge_partner', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE'), 'the three definers are still edge_partner');
SELECT ok(NOT has_function_privilege('authenticated', 'private.partner_offer_approve_for_partner(uuid)'::regprocedure, 'EXECUTE')
      AND NOT has_function_privilege('anon', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE')
      AND NOT has_function_privilege('authenticated', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE'), 'and nobody else may execute any of them');
SELECT is((SELECT string_agg(DISTINCT pg_get_userbyid(proowner), ',') FROM pg_proc WHERE oid IN (
  'private.partner_offer_approve_for_partner(uuid)'::regprocedure,
  'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure,
  'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure)), 'private_definer', 'all three are still owned by private_definer');
SELECT ok((SELECT bool_and(prosecdef AND proconfig = ARRAY['search_path=""'] AND provolatile = 'v') FROM pg_proc WHERE oid IN (
  'private.partner_offer_approve_for_partner(uuid)'::regprocedure,
  'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure,
  'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure)), 'and are all still SECURITY DEFINER, volatile, with an empty search_path');

SELECT * FROM finish();
ROLLBACK;
