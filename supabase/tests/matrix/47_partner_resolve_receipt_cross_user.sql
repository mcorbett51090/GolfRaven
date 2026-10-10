-- 47_partner_resolve_receipt_cross_user.sql
-- 0069: admin A3 resolve of open receipt_cross_user_match (approve keeps money path; reject voids subject).

\set QUIET 1
BEGIN;
SELECT plan(16);

GRANT edge_partner, edge_actor, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT ON app.review_item, app.purchase_evidence, app.marker_credit, app.receipt_fingerprint, app.evidence, app.fraud_signal, app.audit_log TO CURRENT_USER;
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

SAVEPOINT s47_root;

-- ----------------------------------------------------------------------------
-- 2. Staff cannot resolve (42501)
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s47_root;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok(
  $$SELECT * FROM private.partner_resolve_receipt_cross_user_match_for_partner('91000000-0000-0000-0000-000000004701'::uuid, true)$$,
  '42501',
  NULL,
  'staff cannot resolve receipt_cross_user_match'
);
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 3. Cross-user intake → admin approve: fingerprint + closed item; matched purchase untouched
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s47_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash1',
    'receipts/00000000-0000-0000-0000-00000000000b/xu-approve.jpg', NULL, NULL
  ) LIMIT 1),
  'review',
  'cross-user intake is review'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT id AS ri_approve FROM app.review_item
 WHERE kind = 'receipt_cross_user_match' AND resolved_at IS NULL
 ORDER BY created_at DESC LIMIT 1 \gset
SELECT subject_id AS pe_approve FROM app.review_item WHERE id = :'ri_approve'::uuid \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is(
  pg_temp.res_xu('ad', :'ri_approve'::uuid, true),
  'ok|approved',
  'admin approve closes the item'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT r.status || '|' || (r.resolved_at IS NOT NULL)::text || '|' || (r.resolved_by = '00000000-0000-0000-0000-4000000000d0')::text
     FROM app.review_item r WHERE r.id = :'ri_approve'::uuid),
  'approved|true|true',
  'review_item approved with resolved_by admin'
);
SELECT is(
  (SELECT count(*)::int FROM app.receipt_fingerprint rf WHERE rf.purchase_evidence_id = :'pe_approve'::uuid AND rf.phash = 'phash1'),
  1,
  'approve inserts subject fingerprint'
);
SELECT is(
  (SELECT pe.status::text FROM app.purchase_evidence pe
    WHERE pe.id = '90000000-0000-0000-0000-000000000001'),
  'valid',
  'matched earlier purchase (helpers seed) stays valid'
);

-- Second resolve is not_open (partner binding from the approve call is still live in this xact)
SELECT is(
  pg_temp.res_xu('ad', :'ri_approve'::uuid, true),
  'not_open|',
  'second resolve is not_open'
);

-- ----------------------------------------------------------------------------
-- 4. Cross-user intake → admin reject: subject void/reviewer; evidence void; matched untouched
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s47_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT private.receipt_intake_for_actor(
  'fac_x', 'phash1',
  'receipts/00000000-0000-0000-0000-00000000000b/xu-reject.jpg', NULL, NULL
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT id AS ri_reject FROM app.review_item
 WHERE kind = 'receipt_cross_user_match' AND resolved_at IS NULL
 ORDER BY created_at DESC LIMIT 1 \gset
SELECT subject_id AS pe_reject FROM app.review_item WHERE id = :'ri_reject'::uuid \gset
SELECT user_id AS uid_reject, facility_id AS fac_reject, ref_id AS ref_reject
  FROM app.purchase_evidence WHERE id = :'pe_reject'::uuid \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
SELECT is(
  pg_temp.res_xu('ad', :'ri_reject'::uuid, false),
  'ok|rejected',
  'admin reject closes the item'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT pe.status::text || '|' || pe.void_reason::text FROM app.purchase_evidence pe WHERE pe.id = :'pe_reject'::uuid),
  'void|reviewer',
  'reject voids subject purchase with void_reason=reviewer'
);
SELECT is(
  (SELECT e.summary->>'status' || '|' || (e.summary->>'voidReason')
     FROM app.evidence e
    WHERE e.user_id = :'uid_reject'::uuid
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash1'),
  'void|reviewer',
  'reject voids receipt_green_fee evidence summary'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal fs
    WHERE fs.kind = 'receipt_cross_user_match'
      AND fs.user_id = :'uid_reject'::uuid
      AND (fs.detail ->> 'purchase_evidence_id') = :'pe_reject'::text
      AND fs.cleared_at IS NOT NULL),
  1,
  'reject clears the open fraud_signal'
);

-- ----------------------------------------------------------------------------
-- 5. Missing id → not_found; bad args → 22023 (admin binding from §4 still live)
-- ----------------------------------------------------------------------------
SELECT is(
  pg_temp.res_xu('ad', '91000000-0000-0000-0000-00000000dead'::uuid, true),
  'not_found|',
  'unknown review id is not_found'
);
SELECT throws_ok(
  $$SELECT * FROM private.partner_resolve_receipt_cross_user_match_for_partner(NULL, true)$$,
  '22023',
  NULL,
  'NULL review id is 22023'
);

SELECT finish();
ROLLBACK;
