-- 48_partner_receipt_preview.sql
-- 0070: admin A0 preview refs for open receipt_cross_user_match (subject + matched storage paths).

\set QUIET 1
BEGIN;
SELECT plan(8);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE ON app.review_item, app.purchase_evidence TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz48_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz48_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz48_ri ON app.review_item FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz48_pe ON app.purchase_evidence FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s48:' || p_label) || md5('s48b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c48:' || p_label) || md5('c48b:' || p_label), 'hex'),
          decode(md5('k48:' || p_label) || md5('k48b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n48:' || p_label) || md5('n48b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
-- Assumes a partner binding is already planted in this transaction (bind once; never re-bind).
CREATE FUNCTION pg_temp.preview(p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_receipt_cross_user_preview_for_partner(p_id);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_subject_ref, '') || '|' || coalesce(r.o_matched_ref, '');
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.preview(uuid) TO PUBLIC;

SELECT pg_temp.th('sx') AS th_sx, pg_temp.th('ad') AS th_ad \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset

INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status)
VALUES
  ('a8000000-0000-0000-0000-000000004801', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'receipt',
   'receipts/b/preview-subj.jpg', false, '{"awaiting":{}}'::jsonb, current_date, 'pending'),
  ('a8000000-0000-0000-0000-000000004802', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'receipt',
   'receipts/a/preview-match.jpg', false, '{}'::jsonb, current_date, 'valid'),
  ('a8000000-0000-0000-0000-000000004803', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'receipt',
   NULL, false, '{"awaiting":{}}'::jsonb, current_date, 'pending');
INSERT INTO app.review_item (id, kind, subject_table, subject_id, detail)
VALUES
  ('91000000-0000-0000-0000-000000004801', 'receipt_cross_user_match', 'purchase_evidence', 'a8000000-0000-0000-0000-000000004801',
   jsonb_build_object('purchase_evidence_id', 'a8000000-0000-0000-0000-000000004801',
                      'matched_purchase_evidence_id', 'a8000000-0000-0000-0000-000000004802',
                      'phash', 'phash-preview', 'facility_id', 'fac_x', 'local_date', current_date)),
  ('91000000-0000-0000-0000-000000004803', 'receipt_cross_user_match', 'purchase_evidence', 'a8000000-0000-0000-0000-000000004803',
   jsonb_build_object('purchase_evidence_id', 'a8000000-0000-0000-0000-000000004803',
                      'phash', 'phash-no-img', 'facility_id', 'fac_x', 'local_date', current_date)),
  ('91000000-0000-0000-0000-000000004810', 'held_offer_budget_unreserved', 'offer_code',
   '81000000-0000-0000-0000-000000008101', '{}'::jsonb);
INSERT INTO app.review_item (id, kind, subject_table, subject_id, detail, status, resolved_at, resolved_by)
VALUES
  ('91000000-0000-0000-0000-000000004809', 'receipt_cross_user_match', 'purchase_evidence', 'a8000000-0000-0000-0000-000000004801',
   jsonb_build_object('purchase_evidence_id', 'a8000000-0000-0000-0000-000000004801'),
   'approved', now(), '00000000-0000-0000-0000-4000000000d0');

SELECT ok(
  has_function_privilege('edge_partner', 'private.partner_receipt_cross_user_preview_for_partner(uuid)'::regprocedure, 'EXECUTE'),
  'preview wrapper is edge_partner'
);

SAVEPOINT staff_preview;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
SELECT throws_ok(
  $$SELECT * FROM private.partner_receipt_cross_user_preview_for_partner('91000000-0000-0000-0000-000000004801'::uuid)$$,
  '42501',
  NULL,
  'staff cannot preview receipt_cross_user_match'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT staff_preview;

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;

SELECT is(
  pg_temp.preview('91000000-0000-0000-0000-000000004801'::uuid),
  'ok|receipts/b/preview-subj.jpg|receipts/a/preview-match.jpg',
  'admin preview returns subject and matched refs'
);
SELECT is(
  pg_temp.preview('91000000-0000-0000-0000-000000004803'::uuid),
  'no_image||',
  'admin preview no_image when subject has no ref'
);
SELECT is(
  pg_temp.preview('91000000-0000-0000-0000-000000004809'::uuid),
  'not_open||',
  'admin preview not_open for closed item'
);
SELECT is(
  pg_temp.preview('91000000-0000-0000-0000-000000004899'::uuid),
  'not_found||',
  'admin preview not_found for missing id'
);
SELECT is(
  pg_temp.preview('91000000-0000-0000-0000-000000004810'::uuid),
  'not_found||',
  'wrong review kind is not_found'
);

SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  $$SELECT * FROM private.partner_receipt_cross_user_preview_for_partner(NULL)$$,
  '22023',
  NULL,
  'NULL review id is 22023'
);
RESET ROLE;

SELECT finish();
ROLLBACK;
