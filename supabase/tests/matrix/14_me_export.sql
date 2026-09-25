-- 14_me_export.sql
-- build plan §4.7.1a inventory ("me-export"). Companion to
-- 09_delete_my_data.sql. Rewritten for the P3d gate's BLOCKING HIGH: the
-- export must never leak another account's data or secret/token
-- material — see 0021_export_my_data.sql's own header for the full
-- account of what was wrong and why.

BEGIN;
SELECT plan(27);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- Local fixtures this file needs that helpers.sql doesn't seed:
-- connector_account/signin_provider_token (to prove token material is
-- excluded/omitted) and a review_item resolved by admin, naming player
-- A's own purchase_evidence as its subject with a non-trivial `detail`
-- (to prove neither the subject reference nor the detail ever reaches
-- admin's own export).
-- ============================================================================
INSERT INTO app.connector_account (id, user_id, provider, external_user_id, refresh_token_ciphertext, dek_wrapped, kek_id, scopes, status)
VALUES ('c0000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'ghin', 'ext-1', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-export-test', ARRAY['read'], 'active');
INSERT INTO app.signin_provider_token (user_id, provider, refresh_token_ciphertext, dek_wrapped, kek_id)
VALUES ('00000000-0000-0000-0000-00000000000a', 'google', '\xfeedface'::bytea, '\xfeedface'::bytea, 'kek-export-test-2');
INSERT INTO app.review_item (id, kind, subject_table, subject_id, detail, resolved_at, resolved_by)
VALUES ('d0000000-0000-0000-0000-000000000001', 'receipt_review', 'app.purchase_evidence', '90000000-0000-0000-0000-000000000001',
        jsonb_build_object('player_a_uuid_in_detail', '00000000-0000-0000-0000-00000000000a', 'note', 'internal reviewer notes'),
        now(), '00000000-0000-0000-0000-4000000000d0');
-- P3d gate round 3, S1 nit: helpers.sql's own purchase_evidence row for
-- player A leaves ref_id NULL (never exercising the exclusion), so it is
-- populated here with a real value -- the shape a course-QR-variant row
-- actually carries (the consumed course_qr_token's own nonce hash) --
-- so the "ref_id is excluded" assertion below is proving something real,
-- not vacuously true against an already-empty column.
UPDATE app.purchase_evidence SET ref_id = 'zz-fixture-course-qr-nonce-hash'
  WHERE id = '90000000-0000-0000-0000-000000000001';

-- ============================================================================
-- Registry sync: every table private.pii_retention_policy classifies at
-- all (delete_row/set_null/special) has a private.pii_export_policy row
-- — the fail-closed coverage check export_my_data itself runs, restated
-- here as a schema-level assertion.
-- ============================================================================
SELECT is(
  (
    SELECT count(*)::int
    FROM (SELECT DISTINCT table_name FROM private.pii_retention_policy WHERE schema_name = 'app') t
    WHERE NOT EXISTS (SELECT 1 FROM private.pii_export_policy p WHERE p.schema_name = 'app' AND p.table_name = t.table_name)
  ),
  0,
  'every table private.pii_retention_policy classifies at all has a private.pii_export_policy row (export or exclude, with a reason)'
);
SELECT is(
  (SELECT count(*)::int FROM private.pii_export_policy WHERE reason IS NULL OR length(trim(reason)) = 0),
  0,
  'every private.pii_export_policy row has a non-empty reason'
);

-- ============================================================================
-- Player A's own export: her own data is present.
-- ============================================================================
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'evidence') @>
    jsonb_build_array(jsonb_build_object('id', '30000000-0000-0000-0000-000000000001')),
  'player A''s export includes her own seeded evidence row'
);
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'device') @>
    jsonb_build_array(jsonb_build_object('id', '20000000-0000-0000-0000-000000000001')),
  'player A''s export includes her own seeded device row'
);
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'push_token') @>
    jsonb_build_array(jsonb_build_object('device_id', '20000000-0000-0000-0000-000000000001', 'expo_token', 'ExponentPushToken[test]')),
  'player A''s export includes her own seeded push_token row'
);
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'connector_account') @>
    jsonb_build_array(jsonb_build_object('id', 'c0000000-0000-0000-0000-000000000001', 'provider', 'ghin')),
  'player A''s export includes her own connector_account row (without token columns)'
);

-- ============================================================================
-- (b) Secret/token material: never present, anywhere, for anyone.
-- ============================================================================
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'connector_account' -> 0 ? 'refresh_token_ciphertext'),
  'connector_account export never includes refresh_token_ciphertext'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) ? 'signin_provider_token'),
  'signin_provider_token is excluded entirely -- the key itself is absent from the export, not merely an empty array'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid)::text ~* 'ciphertext|dek_wrapped|kek_id|token_hash|code_hmac|pepper_kid|nonce_hash'),
  'player A''s WHOLE export (recursively) contains none of the denylisted secret/hash/pepper/key substrings'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid)::text ~* 'ciphertext|dek_wrapped|kek_id|token_hash|code_hmac|pepper_kid|nonce_hash'),
  'staff-x''s WHOLE export ALSO contains none of the denylisted substrings'
);

-- ============================================================================
-- (a) set_null actor columns never leak another account's row.
-- offer_code #2 and entitlement #2 (helpers.sql) are player A's own rows,
-- REDEEMED by staff-x (redeemed_by_staff). Staff-x's own export must
-- contain neither.
-- ============================================================================
SELECT is(
  jsonb_array_length(private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid) -> 'offer_code'),
  0,
  'staff-x''s export has ZERO offer_code rows -- redeeming player A''s offer as staff must not export it under staff-x''s own account'
);
SELECT is(
  jsonb_array_length(private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid) -> 'entitlement'),
  0,
  'staff-x''s export has ZERO entitlement rows for the same reason'
);
-- Staff-x's own partner_member row (user_id = staff-x) is fine to
-- export; player A's partner_member row (invited_by = staff-x) must not
-- appear in staff-x's export.
SELECT is(
  (SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid) -> 'partner_member') pm WHERE (pm ->> 'user_id') <> '00000000-0000-0000-0000-1000000000a1'),
  0,
  'every partner_member row in staff-x''s export carries staff-x''s OWN user_id -- never player A''s row (reached only via invited_by, an actor column)'
);

-- No account's uuid but the requester's OWN ever appears anywhere in
-- staff-x's or admin's export -- the strongest form of the "no other
-- user's uuid anywhere" test, scanning the ENTIRE serialized JSON.
SELECT ok(
  private.export_my_data('00000000-0000-0000-0000-1000000000a1'::uuid)::text NOT ILIKE '%00000000-0000-0000-0000-00000000000a%',
  'staff-x''s export contains player A''s uuid NOWHERE in the serialized JSON'
);
SELECT ok(
  private.export_my_data('00000000-0000-0000-0000-4000000000d0'::uuid)::text NOT ILIKE '%00000000-0000-0000-0000-00000000000a%',
  'admin''s export contains player A''s uuid NOWHERE in the serialized JSON (incl. inside review_item, which admin resolved for player A''s own receipt)'
);

-- ============================================================================
-- (c) fraud_signal / review_item: kind + created_at only, never detail,
-- cleared_by or (for review_item) subject_table/subject_id/resolved_by.
-- ============================================================================
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'fraud_signal') @>
    jsonb_build_array(jsonb_build_object('kind', 'manual_review_seed')),
  'player A''s export includes her own fraud_signal row, restricted to kind (+ id/created_at)'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'fraud_signal' -> 0 ? 'detail'),
  'fraud_signal export never includes detail'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'fraud_signal' -> 0 ? 'cleared_by'),
  'fraud_signal export never includes cleared_by'
);
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-4000000000d0'::uuid) -> 'review_item') @>
    jsonb_build_array(jsonb_build_object('id', 'd0000000-0000-0000-0000-000000000001', 'kind', 'receipt_review')),
  'admin''s export includes the review_item admin resolved, restricted to id/kind (+ created_at)'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-4000000000d0'::uuid) -> 'review_item' -> 0 ? 'detail'),
  'review_item export never includes detail (which named player A''s uuid in this fixture)'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-4000000000d0'::uuid) -> 'review_item' -> 0 ? 'subject_id'),
  'review_item export never includes subject_id (another row''s identity)'
);
SELECT ok(
  private.export_my_data('00000000-0000-0000-0000-4000000000d0'::uuid)::text NOT ILIKE '%"detail"%',
  'admin''s WHOLE export contains no "detail" key anywhere (fraud_signal, review_item and audit_log all omit it by construction)'
);

-- ============================================================================
-- P3d gate round 3, S1: "Add a pgTAP check that the export's top-level
-- keys exactly equal the set of export-classified pii_export_policy
-- tables, so an export row with no SELECT fails." A table registered
-- `action = 'export'` but never actually given its own SELECT block in
-- export_my_data's body (or a typo'd jsonb_build_object key) would
-- otherwise pass every OTHER assertion in this file silently -- none of
-- them enumerate the FULL key set, only individual keys' contents.
-- ============================================================================
SELECT is(
  (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid)) k),
  (SELECT array_agg(table_name ORDER BY table_name) FROM private.pii_export_policy WHERE schema_name = 'app' AND action = 'export'),
  'export''s top-level keys exactly equal the set of export-classified private.pii_export_policy tables -- an export-classified table with no real SELECT block in export_my_data would fail this'
);

-- ============================================================================
-- P3d gate round 3, S1 (should-fixes, do now): audit_log.subject_id and
-- purchase_evidence.ref_id are no longer exported at all (0022's own
-- header: subject_id is a polymorphic reference that can itself BE
-- another account's own id; ref_id, for a course-QR row, is the
-- consumed token's own nonce hash -- an internal matching key, not the
-- caller's own data).
-- ============================================================================
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'audit_log' -> 0 ? 'subject_id'),
  'audit_log export never includes subject_id (a polymorphic reference that can itself name another account)'
);
SELECT ok(
  NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'purchase_evidence' -> 0 ? 'ref_id'),
  'purchase_evidence export never includes ref_id (a course-QR token''s own nonce hash, not the caller''s own data)'
);

-- ============================================================================
-- Access control: unchanged from the original version (no client role
-- reaches this function directly).
-- ============================================================================
SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok(
  $$ SELECT private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) $$,
  '42501',
  NULL,
  'authenticated cannot call private.export_my_data directly (permission denied)'
);

SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok(
  $$ SELECT private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) $$,
  '42501',
  NULL,
  'anon cannot call private.export_my_data directly (permission denied)'
);

SELECT * FROM finish();
ROLLBACK;
