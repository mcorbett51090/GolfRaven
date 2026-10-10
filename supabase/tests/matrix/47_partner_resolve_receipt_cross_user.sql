-- 47_partner_resolve_receipt_cross_user.sql
-- 0069: admin A3 resolve of open receipt_cross_user_match (approve keeps money path; reject voids subject).
-- Pattern: seed rows like matrix 35 (no bind_actor in this xact — partner bind is once).

\set QUIET 1
BEGIN;
SELECT plan(15);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE ON app.review_item, app.purchase_evidence, app.marker_credit, app.receipt_fingerprint, app.evidence, app.fraud_signal TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz47_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_ri ON app.review_item FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_pe ON app.purchase_evidence FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_mc ON app.marker_credit FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_rf ON app.receipt_fingerprint FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_ev ON app.evidence FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz47_fs ON app.fraud_signal FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s47:' || p_label) || md5('s47b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c47:' || p_label) || md5('c47b:' || p_label), 'hex'),
          decode(md5('k47:' || p_label) || md5('k47b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n47:' || p_label) || md5('n47b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
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
CREATE FUNCTION pg_temp.res_xu(p_label text, p_id uuid, p_approve boolean) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_step(p_label, '{"mfa_s": 240, "aal": 2}'::jsonb);
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_resolve_receipt_cross_user_match_for_partner(p_id, p_approve);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_state, '');
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_step(text, jsonb), pg_temp.res_xu(text, uuid, boolean) TO PUBLIC;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('ad') AS th_ad \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

-- Seed two open cross-user matches for player B (approve / reject subjects).
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status)
VALUES
  ('a7000000-0000-0000-0000-000000004701', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'receipt',
   'receipts/b/xu-approve.jpg', false, '{"awaiting":{}}'::jsonb, current_date, 'pending'),
  ('a7000000-0000-0000-0000-000000004702', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'receipt',
   'receipts/b/xu-reject.jpg', false, '{"awaiting":{}}'::jsonb, current_date, 'pending');
INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status)
VALUES
  ('b7000000-0000-0000-0000-000000004701', '00000000-0000-0000-0000-00000000000b', 'trl_t', 'fac_x', 'a7000000-0000-0000-0000-000000004701', 'pending'),
  ('b7000000-0000-0000-0000-000000004702', '00000000-0000-0000-0000-00000000000b', 'trl_t', 'fac_x', 'a7000000-0000-0000-0000-000000004702', 'pending');
INSERT INTO app.evidence (id, user_id, source, source_ref, facility_id, summary, attestation_grade, local_date, input_hash, status)
VALUES
  ('c7000000-0000-0000-0000-000000004701', '00000000-0000-0000-0000-00000000000b', 'receipt_green_fee',
   'receipt:fac_x:phash-xu-approve', 'fac_x',
   jsonb_build_object('localDate', current_date::text, 'status', 'pending', 'fingerprint', 'phash-xu-approve'),
   'unattestable', current_date, 'h47-approve', 'accepted'),
  ('c7000000-0000-0000-0000-000000004702', '00000000-0000-0000-0000-00000000000b', 'receipt_green_fee',
   'receipt:fac_x:phash-xu-reject', 'fac_x',
   jsonb_build_object('localDate', current_date::text, 'status', 'pending', 'fingerprint', 'phash-xu-reject'),
   'unattestable', current_date, 'h47-reject', 'accepted');
INSERT INTO app.review_item (id, kind, subject_table, subject_id, detail)
VALUES
  ('91000000-0000-0000-0000-000000004701', 'receipt_cross_user_match', 'purchase_evidence', 'a7000000-0000-0000-0000-000000004701',
   jsonb_build_object('purchase_evidence_id', 'a7000000-0000-0000-0000-000000004701',
                      'matched_purchase_evidence_id', '90000000-0000-0000-0000-000000000001',
                      'matched_receipt_fingerprint_id', '80000000-0000-0000-0000-000000000001',
                      'phash', 'phash-xu-approve', 'facility_id', 'fac_x', 'local_date', current_date)),
  ('91000000-0000-0000-0000-000000004702', 'receipt_cross_user_match', 'purchase_evidence', 'a7000000-0000-0000-0000-000000004702',
   jsonb_build_object('purchase_evidence_id', 'a7000000-0000-0000-0000-000000004702',
                      'matched_purchase_evidence_id', '90000000-0000-0000-0000-000000000001',
                      'matched_receipt_fingerprint_id', '80000000-0000-0000-0000-000000000001',
                      'phash', 'phash-xu-reject', 'facility_id', 'fac_x', 'local_date', current_date));
INSERT INTO app.fraud_signal (id, user_id, kind, detail)
VALUES
  ('d7000000-0000-0000-0000-000000004701', '00000000-0000-0000-0000-00000000000b', 'receipt_cross_user_match',
   jsonb_build_object('purchase_evidence_id', 'a7000000-0000-0000-0000-000000004701', 'phash', 'phash-xu-approve')),
  ('d7000000-0000-0000-0000-000000004702', '00000000-0000-0000-0000-00000000000b', 'receipt_cross_user_match',
   jsonb_build_object('purchase_evidence_id', 'a7000000-0000-0000-0000-000000004702', 'phash', 'phash-xu-reject'));

-- ----------------------------------------------------------------------------
-- 1. Inventory / EXECUTE
-- ----------------------------------------------------------------------------
SELECT ok(
  has_function_privilege('edge_partner', 'private.partner_resolve_receipt_cross_user_match_for_partner(uuid, boolean)'::regprocedure, 'EXECUTE'),
  'wrapper is edge_partner'
);
SELECT ok(
  NOT has_function_privilege('edge_partner', 'private.partner_resolve_receipt_cross_user_match_apply(uuid, boolean, uuid)'::regprocedure, 'EXECUTE'),
  'apply helper is not edge_partner'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policies WHERE policyname = 'pd_partner_receipt_review_item_update'),
  1,
  'pd_partner_receipt_review_item_update exists'
);

-- ----------------------------------------------------------------------------
-- 2. Staff cannot resolve (42501); roll back the staff bind
-- ----------------------------------------------------------------------------
SAVEPOINT staff_resolve;
SELECT pg_temp.seed_step('sx', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok(
  $$SELECT * FROM private.partner_resolve_receipt_cross_user_match_for_partner('91000000-0000-0000-0000-000000004701'::uuid, true)$$,
  '42501',
  NULL,
  'staff cannot resolve receipt_cross_user_match'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT staff_resolve;

-- ----------------------------------------------------------------------------
-- 3. One admin bind for the rest of the file
-- ----------------------------------------------------------------------------
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240, "aal": 2}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;

SELECT is(
  pg_temp.res_xu('ad', '91000000-0000-0000-0000-000000004701'::uuid, true),
  'ok|approved',
  'admin approve closes the item'
);
SELECT is(
  (SELECT r.status || '|' || (r.resolved_at IS NOT NULL)::text || '|' || (r.resolved_by = '00000000-0000-0000-0000-4000000000d0')::text
     FROM app.review_item r WHERE r.id = '91000000-0000-0000-0000-000000004701'),
  'approved|true|true',
  'review_item approved with resolved_by admin'
);
SELECT is(
  (SELECT count(*)::int FROM app.receipt_fingerprint rf
    WHERE rf.purchase_evidence_id = 'a7000000-0000-0000-0000-000000004701' AND rf.phash = 'phash-xu-approve'),
  1,
  'approve inserts subject fingerprint'
);
SELECT is(
  (SELECT pe.status::text FROM app.purchase_evidence pe WHERE pe.id = '90000000-0000-0000-0000-000000000001'),
  'valid',
  'matched earlier purchase stays valid'
);
SELECT is(
  pg_temp.res_xu('ad', '91000000-0000-0000-0000-000000004701'::uuid, true),
  'not_open|',
  'second resolve is not_open'
);

-- ----------------------------------------------------------------------------
-- 4. Reject: subject void/reviewer; evidence void; fraud cleared
-- ----------------------------------------------------------------------------
SELECT is(
  pg_temp.res_xu('ad', '91000000-0000-0000-0000-000000004702'::uuid, false),
  'ok|rejected',
  'admin reject closes the item'
);
SELECT is(
  (SELECT pe.status::text || '|' || pe.void_reason::text FROM app.purchase_evidence pe
    WHERE pe.id = 'a7000000-0000-0000-0000-000000004702'),
  'void|reviewer',
  'reject voids subject purchase with void_reason=reviewer'
);
SELECT is(
  (SELECT e.summary->>'status' || '|' || (e.summary->>'voidReason')
     FROM app.evidence e WHERE e.id = 'c7000000-0000-0000-0000-000000004702'),
  'void|reviewer',
  'reject voids receipt_green_fee evidence summary'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal fs
    WHERE fs.id = 'd7000000-0000-0000-0000-000000004702' AND fs.cleared_at IS NOT NULL),
  1,
  'reject clears the open fraud_signal'
);

-- ----------------------------------------------------------------------------
-- 5. Missing id → not_found; bad args → 22023
-- ----------------------------------------------------------------------------
SELECT is(
  pg_temp.res_xu('ad', '91000000-0000-0000-0000-00000000dead'::uuid, true),
  'not_found|',
  'unknown review id is not_found'
);
SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  $$SELECT * FROM private.partner_resolve_receipt_cross_user_match_for_partner(NULL, true)$$,
  '22023',
  NULL,
  'NULL review id is 22023'
);
RESET ROLE;

SELECT finish();
ROLLBACK;
