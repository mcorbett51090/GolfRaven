-- 35_partner_review_queue.sql
-- P5.1a S4 (0057): RECEIPTS AND REVIEW, from docs/security/partner-auth-design.md 12.1 "S4": resolve_held_* reachable only through an A3 definer (E20 / F7); AT(11)/AT(18) shape as the admin queue and resolve path;
-- the held-review queue and SLA summary reads (class A0, admin only); staff / manager / operator cannot resolve or read the queue; a missing A3 (no fresh TOTP window) is refused; not_found / not_held / budget_short
-- are returned statuses; edge_partner has no EXECUTE on app.resolve_held_*; the binding-keyed policies are closed without a partner binding and not opened by a planted GUC.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end (the 34 pattern). Token hashes are precomputed with \gset so they can be passed under SET LOCAL ROLE edge_partner
-- (edge_partner cannot EXECUTE pg_temp helpers). Inventory / allow-list reads run as service_role (FORCE RLS; SELECT is granted to service_role only).
--
-- Principals are helpers.sql's: staff_x (a1), manager_x (b1), operator_t (c1), admin (d0), player_a / player_b.

\set QUIET 1
BEGIN;
SELECT plan(44);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT ON app.offer_code, app.entitlement, app.review_item, app.audit_log, app.device_reward_ledger, app.offer TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz35_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz35_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz35_oc ON app.offer_code FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz35_ent ON app.entitlement FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz35_ri ON app.review_item FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz35_au ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz35_ld ON app.device_reward_ledger FOR SELECT TO CURRENT_USER USING (true);
CREATE POLICY zz35_of ON app.offer FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s35:' || p_label) || md5('s35b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c35:' || p_label) || md5('c35b:' || p_label), 'hex'), decode(md5('k35:' || p_label) || md5('k35b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n35:' || p_label) || md5('n35b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
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

-- call a resolve as edge_partner under a binding; returns status|state. Hash captured BEFORE SET ROLE (edge_partner cannot EXECUTE pg_temp.th).
CREATE FUNCTION pg_temp.res_oc(p_label text, p_id uuid, p_approve boolean) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; v_th text;
BEGIN
  v_th := pg_temp.th(p_label);
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(v_th);
  SELECT * INTO r FROM private.partner_resolve_held_offer_code_for_partner(p_id, p_approve);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_state, '');
END
$f$;
CREATE FUNCTION pg_temp.res_ent(p_label text, p_id uuid, p_approve boolean) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record; v_th text;
BEGIN
  v_th := pg_temp.th(p_label);
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(v_th);
  SELECT * INTO r FROM private.partner_resolve_held_entitlement_for_partner(p_id, p_approve);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_state, '');
END
$f$;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('mx') AS th_mx, pg_temp.th('op') AS th_op, pg_temp.th('ad') AS th_ad \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

-- a held offer_code with a reservation (approve -> issued); a held entitlement (approve -> redeemable); a held offer_code with no reservation and a short budget (budget_short)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000003501', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
       ('60000000-0000-0000-0000-000000003502', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 5, 10, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, activated_device_id, activated_at, hold_detail, earned_at)
VALUES ('70000000-0000-0000-0000-000000003501', '60000000-0000-0000-0000-000000003501',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', 10, '20000000-0000-0000-0000-000000000001', now() - interval '1 hour',
        '{"heldFor":"test"}'::jsonb, now() - interval '2 hours'),
       ('70000000-0000-0000-0000-000000003502', '60000000-0000-0000-0000-000000003502',
        '00000000-0000-0000-0000-00000000000b', 'fac_x', 'held_review', 0, '20000000-0000-0000-0000-000000000001', now() - interval '1 hour',
        '{"heldFor":"offer_budget"}'::jsonb, now() - interval '3 days');
UPDATE app.offer SET budget_reserved = 10 WHERE id = '60000000-0000-0000-0000-000000003501';
-- player_a already holds special_marker on trl_t and trl_u (helpers.sql); use player_b on trl_t
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_device_id, activated_at, hold_detail)
VALUES ('51000000-0000-0000-0000-000000003501', '00000000-0000-0000-0000-00000000000b', 'special_marker', 'trl_t', 'held_review',
        '20000000-0000-0000-0000-000000000001', now() - interval '3 days', '{"heldFor":"test"}'::jsonb);
INSERT INTO app.review_item (id, kind, subject_table, subject_id, detail, created_at)
VALUES ('91000000-0000-0000-0000-000000003501', 'held_offer_budget_unreserved', 'offer_code', '70000000-0000-0000-0000-000000003502',
        '{}'::jsonb, now() - interval '3 days');

-- ----------------------------------------------------------------------------
-- 1. Inventory and EXECUTE: resolve_held_* not on any edge role; the four partner wrappers are
-- ----------------------------------------------------------------------------
SELECT ok(NOT has_function_privilege('edge_partner', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE'), 'E20: edge_partner cannot EXECUTE resolve_held_offer_code');
SELECT ok(NOT has_function_privilege('edge_partner', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE'), 'E20: edge_partner cannot EXECUTE resolve_held_entitlement');
SELECT ok(NOT has_function_privilege('edge_actor', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE'), 'E20: edge_actor cannot EXECUTE resolve_held_offer_code');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_resolve_held_offer_code_for_partner(uuid, boolean)'::regprocedure, 'EXECUTE'), 'the A3 offer-code wrapper is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_resolve_held_entitlement_for_partner(uuid, boolean)'::regprocedure, 'EXECUTE'), 'the A3 entitlement wrapper is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_held_queue_for_partner()'::regprocedure, 'EXECUTE'), 'the queue read is edge_partner');
SELECT ok(has_function_privilege('edge_partner', 'private.partner_review_sla_for_partner()'::regprocedure, 'EXECUTE'), 'the SLA read is edge_partner');
SELECT ok(NOT has_function_privilege('edge_partner', 'private.partner_resolve_held_offer_code_apply(uuid, boolean, uuid)'::regprocedure, 'EXECUTE'), 'the apply helper is not edge_partner');
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN (
  'partner_resolve_held_offer_code_for_partner', 'partner_resolve_held_entitlement_for_partner', 'partner_held_queue_for_partner', 'partner_review_sla_for_partner') AND expected_edge_partner), 4,
  'the four partner functions are in function_inventory as edge_partner');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. Authority: only an admin with A3 may resolve; only an admin may read the queue
-- ----------------------------------------------------------------------------
SAVEPOINT staff_resolve;
SELECT pg_temp.seed_step('sx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner('70000000-0000-0000-0000-000000003501', true)$$, '42501', NULL, 'staff cannot resolve (admin only after A3)');
SELECT throws_ok($$SELECT * FROM private.partner_held_queue_for_partner()$$, '42501', NULL, 'staff cannot read the queue');
RESET ROLE;
ROLLBACK TO SAVEPOINT staff_resolve;

SAVEPOINT mgr_resolve;
SELECT pg_temp.seed_step('mx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner('70000000-0000-0000-0000-000000003501', true)$$, '42501', NULL, 'manager cannot resolve');
SELECT throws_ok($$SELECT * FROM private.partner_review_sla_for_partner()$$, '42501', NULL, 'manager cannot read the SLA summary');
RESET ROLE;
ROLLBACK TO SAVEPOINT mgr_resolve;

SAVEPOINT op_resolve;
SELECT pg_temp.seed_step('op', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner('70000000-0000-0000-0000-000000003501', true)$$, '42501', 'partner_resolve_held_offer_code_for_partner: only an admin may resolve a held reward', 'operator with A3 still cannot resolve (admin only)');
SELECT throws_ok($$SELECT * FROM private.partner_held_queue_for_partner()$$, '42501', NULL, 'operator cannot read the queue');
RESET ROLE;
ROLLBACK TO SAVEPOINT op_resolve;

SAVEPOINT a3_missing;
-- admin at aal 2 but no mfa_until: A3 refused
SELECT pg_temp.seed_step('ad', '{"aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner('70000000-0000-0000-0000-000000003501', true)$$, '42501', NULL, 'A3 without a fresh TOTP window is refused');
RESET ROLE;
ROLLBACK TO SAVEPOINT a3_missing;

-- ----------------------------------------------------------------------------
-- 3. Happy path: admin approves a held code and a held entitlement; rejects the budget-short path
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.res_oc('ad', '70000000-0000-0000-0000-000000003501', true), 'ok|issued', 'admin approves a reserved held offer_code -> issued');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = '70000000-0000-0000-0000-000000003501'), 'issued', 'the code is issued');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'held_reward_approved' AND subject_id = '70000000-0000-0000-0000-000000003501'), 1, 'an audit row records the approval');
SELECT is((SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = '70000000-0000-0000-0000-000000003501' AND reward_kind = 'offer'), 1, 'the ledger row is written');

SELECT is(pg_temp.res_ent('ad', '51000000-0000-0000-0000-000000003501', true), 'ok|redeemable', 'admin approves a held entitlement -> redeemable');
SELECT is((SELECT state::text FROM app.entitlement WHERE id = '51000000-0000-0000-0000-000000003501'), 'redeemable', 'the entitlement is redeemable');

SELECT is(pg_temp.res_oc('ad', '70000000-0000-0000-0000-000000003502', true), 'budget_short|', 'approve of an unreserved hold the cap cannot cover is budget_short');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = '70000000-0000-0000-0000-000000003502'), 'held_review', 'budget_short leaves the code held');
SELECT is(pg_temp.res_oc('ad', '70000000-0000-0000-0000-000000003502', false), 'ok|void', 'admin rejects the held code -> void');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = '70000000-0000-0000-0000-000000003502'), 'void', 'the code is void');

SELECT is(pg_temp.res_oc('ad', '70000000-0000-0000-0000-000000003501', true), 'not_held|', 'resolving an already-issued code is not_held');
SELECT is(pg_temp.res_oc('ad', '70000000-0000-0000-0000-000000003599', true), 'not_found|', 'an unknown code is not_found');
SELECT is(pg_temp.res_ent('ad', '51000000-0000-0000-0000-000000003599', false), 'not_found|', 'an unknown entitlement is not_found');

SAVEPOINT bad_args;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner(NULL, true)$$, '22023', NULL, 'a NULL code id is 22023');
SELECT throws_ok($$SELECT * FROM private.partner_resolve_held_offer_code_for_partner('70000000-0000-0000-0000-000000003501', NULL)$$, '22023', NULL, 'a NULL approve flag is 22023');
RESET ROLE;
ROLLBACK TO SAVEPOINT bad_args;

-- ----------------------------------------------------------------------------
-- 4. Queue and SLA reads (admin)
-- ----------------------------------------------------------------------------
-- re-seed a held code for the queue (the earlier codes were resolved; the first entitlement was approved)
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000003503', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 0, current_date, current_date + 30, 'live');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, reserved_amount, hold_detail, earned_at)
VALUES ('70000000-0000-0000-0000-000000003503', '60000000-0000-0000-0000-000000003503',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'held_review', 0, '{"heldFor":"play"}'::jsonb, now() - interval '1 hour');
-- put player_b's entitlement back on hold for the SLA cell (it was approved above)
UPDATE app.entitlement SET state = 'held_review', hold_detail = '{"heldFor":"test"}'::jsonb, activated_at = now() - interval '3 days'
WHERE id = '51000000-0000-0000-0000-000000003501';

SELECT count(*)::int AS held_oc_n FROM app.offer_code WHERE state = 'held_review' \gset

SAVEPOINT queue_read;
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT ok((SELECT count(*)::int FROM private.partner_held_queue_for_partner() WHERE o_kind = 'offer_code') >= 1, 'the queue lists held offer_codes');
SELECT ok((SELECT count(*)::int FROM private.partner_held_queue_for_partner() WHERE o_kind = 'entitlement') >= 1, 'the queue lists held entitlements');
SELECT ok((SELECT count(*)::int FROM private.partner_held_queue_for_partner() WHERE o_kind = 'review_item') >= 1, 'the queue lists open review_items');
SELECT ok((SELECT bool_or(o_sla_breached) FROM private.partner_held_queue_for_partner() WHERE o_kind = 'entitlement' AND o_id = '51000000-0000-0000-0000-000000003501'), 'a hold older than 48 h is sla_breached');
SELECT ok(NOT coalesce((SELECT bool_or(o_sla_breached) FROM private.partner_held_queue_for_partner() WHERE o_id = '70000000-0000-0000-0000-000000003503'), true), 'a fresh hold is not sla_breached');
SELECT is((SELECT o_held_offer_codes::int FROM private.partner_review_sla_for_partner()), :held_oc_n, 'SLA summary held_offer_codes matches');
SELECT is((SELECT o_sla_hours FROM private.partner_review_sla_for_partner()), 48, 'SLA hours is 48 ([inference])');
SELECT ok((SELECT o_sla_breached_rewards FROM private.partner_review_sla_for_partner()) >= 1, 'SLA summary counts breached rewards');
RESET ROLE;
ROLLBACK TO SAVEPOINT queue_read;

-- ----------------------------------------------------------------------------
-- 5. Policies: registered, no GUC, partner_bound_admin not opened by a planted GUC
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_review_%'), 11, 'eleven pd_partner_review_* policies exist');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_review_%'
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'current_setting'), 0,
  'none of the 0057 review policies reads a setting: no GUC window');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname LIKE 'pd_partner_review_%'
           AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')) ~ 'partner_bound_admin'), 11,
  'each of them is keyed on partner_bound_admin');
SET LOCAL ROLE private_definer;
SELECT set_config('app.delete_my_data.target_user_id', '00000000-0000-0000-0000-4000000000d0', true);
SELECT ok(NOT private.partner_bound_admin(), 'a planted delete_my_data GUC does not make partner_bound_admin true');
RESET ROLE;
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd_partner_review_%'), 11, 'the eleven policies are in definer_policy_allowlist');
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
